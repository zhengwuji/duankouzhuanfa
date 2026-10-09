package webui

import (
	"net/http"
	"strings"

	"porttransit/internal/config"
)

// Mutating endpoints for relays, tunnels and forwards.
//
// All of them go through mutate, which is the single place that applies,
// validates and persists a change. Keeping that in one function is what
// guarantees the invariant the whole console depends on: a configuration on
// disk is always one that passed validation, so a restart can never fail
// because of an edit made through the GUI.

// mutate applies change to a copy of the live configuration, validates it and
// persists it. On any failure the live configuration is untouched.
func (s *Server) mutate(change func(*config.Config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Deep-copy through JSON so a partial edit cannot leave the live document
	// half-modified when validation rejects it.
	candidate, err := cloneConfig(s.cfg)
	if err != nil {
		return err
	}
	if err := change(candidate); err != nil {
		return err
	}
	if err := candidate.Validate(); err != nil {
		return err
	}
	if err := candidate.Save(s.path); err != nil {
		return err
	}
	s.cfg = candidate
	return nil
}

// cloneConfig deep-copies a configuration.
func cloneConfig(cfg *config.Config) (*config.Config, error) {
	raw, err := marshalConfig(cfg)
	if err != nil {
		return nil, err
	}
	return config.Parse(raw)
}

// handleServers lists, creates and replaces relay entries.
func (s *Server) handleServers(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Client == nil {
		writeError(w, http.StatusBadRequest, "client_disabled", "this process is not running a client")
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"servers": redactServers(s.cfg.Client.Servers)})

	case http.MethodPost:
		var entry config.ServerEntry
		if !decodeJSON(w, r, &entry) {
			return
		}
		if entry.ID == "" {
			entry.ID = newID("srv")
		}
		if err := s.mutate(func(cfg *config.Config) error {
			for _, existing := range cfg.Client.Servers {
				if existing.ID == entry.ID {
					return errAlreadyExists
				}
			}
			cfg.Client.Servers = append(cfg.Client.Servers, entry)
			return nil
		}); err != nil {
			writeMutateError(w, err)
			return
		}
		s.log.Info("relay added", "id", entry.ID, "address", entry.Address, "transport", entry.Transport)
		writeJSON(w, http.StatusCreated, map[string]any{
			"ok":              true,
			"id":              entry.ID,
			"restartRequired": false,
			"message":         "relay saved; it becomes usable immediately for new connections",
		})

	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "expected GET or POST")
	}
}

// handleServerByID reads, replaces or deletes one relay.
func (s *Server) handleServerByID(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Client == nil {
		writeError(w, http.StatusBadRequest, "client_disabled", "this process is not running a client")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/servers/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "a relay id is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		for _, entry := range s.cfg.Client.Servers {
			if entry.ID == id {
				writeJSON(w, http.StatusOK, map[string]any{"server": redactServer(entry)})
				return
			}
		}
		writeError(w, http.StatusNotFound, "not_found", "no relay with id %q", id)

	case http.MethodPut, http.MethodPatch:
		var entry config.ServerEntry
		if !decodeJSON(w, r, &entry) {
			return
		}
		entry.ID = id
		if err := s.mutate(func(cfg *config.Config) error {
			for i := range cfg.Client.Servers {
				if cfg.Client.Servers[i].ID == id {
					// Restore any secret the caller did not resend, so a
					// partial edit cannot wipe a credential.
					restoreSettings([]config.ServerEntry{entry}, []config.ServerEntry{cfg.Client.Servers[i]})
					cfg.Client.Servers[i] = entry
					return nil
				}
			}
			return errNotFound
		}); err != nil {
			writeMutateError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})

	case http.MethodDelete:
		if err := s.mutate(func(cfg *config.Config) error {
			out := cfg.Client.Servers[:0]
			found := false
			for _, entry := range cfg.Client.Servers {
				if entry.ID == id {
					found = true
					continue
				}
				out = append(out, entry)
			}
			if !found {
				return errNotFound
			}
			cfg.Client.Servers = out
			// A tunnel or proxy that still names the deleted relay would fail
			// validation, so the deletion is rejected rather than silently
			// breaking the client. The operator is told what to fix first.
			for _, t := range cfg.Client.Tunnels {
				if t.Server == id {
					return &inUseError{what: "tunnel " + t.Name}
				}
			}
			if cfg.Client.Proxy.Server == id {
				return &inUseError{what: "the local proxy"}
			}
			return nil
		}); err != nil {
			writeMutateError(w, err)
			return
		}
		s.log.Info("relay deleted", "id", id)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "expected GET, PUT, PATCH or DELETE")
	}
}

// handleTunnels lists and creates tunnels.
func (s *Server) handleTunnels(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Client == nil {
		writeError(w, http.StatusBadRequest, "client_disabled", "this process is not running a client")
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"tunnels": s.cfg.Client.Tunnels,
			"status":  s.tunnelStatus(),
		})

	case http.MethodPost:
		var t config.Tunnel
		if !decodeJSON(w, r, &t) {
			return
		}
		if t.Name == "" {
			t.Name = newID("tunnel")
		}
		if err := s.mutate(func(cfg *config.Config) error {
			for _, existing := range cfg.Client.Tunnels {
				if existing.Name == t.Name {
					return errAlreadyExists
				}
			}
			cfg.Client.Tunnels = append(cfg.Client.Tunnels, t)
			return nil
		}); err != nil {
			writeMutateError(w, err)
			return
		}
		s.log.Info("tunnel added", "name", t.Name, "listen", t.Listen, "target", t.Target)
		// A new local listener cannot be bound without rebinding, so the
		// operator is told a restart is needed rather than being left to
		// wonder why nothing is listening.
		writeJSON(w, http.StatusCreated, map[string]any{
			"ok":              true,
			"name":            t.Name,
			"restartRequired": true,
			"message":         "tunnel saved; restart the client to bind the new local port",
		})

	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "expected GET or POST")
	}
}

// handleTunnelByName reads, replaces or deletes one tunnel.
func (s *Server) handleTunnelByName(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Client == nil {
		writeError(w, http.StatusBadRequest, "client_disabled", "this process is not running a client")
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/tunnels/")
	if name == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "a tunnel name is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		for _, t := range s.cfg.Client.Tunnels {
			if t.Name == name {
				writeJSON(w, http.StatusOK, map[string]any{"tunnel": t})
				return
			}
		}
		writeError(w, http.StatusNotFound, "not_found", "no tunnel named %q", name)

	case http.MethodPut, http.MethodPatch:
		var t config.Tunnel
		if !decodeJSON(w, r, &t) {
			return
		}
		t.Name = name
		if err := s.mutate(func(cfg *config.Config) error {
			for i := range cfg.Client.Tunnels {
				if cfg.Client.Tunnels[i].Name == name {
					cfg.Client.Tunnels[i] = t
					return nil
				}
			}
			return errNotFound
		}); err != nil {
			writeMutateError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":              true,
			"name":            name,
			"restartRequired": true,
			"message":         "tunnel saved; restart the client for the change to take effect",
		})

	case http.MethodDelete:
		if err := s.mutate(func(cfg *config.Config) error {
			out := cfg.Client.Tunnels[:0]
			found := false
			for _, t := range cfg.Client.Tunnels {
				if t.Name == name {
					found = true
					continue
				}
				out = append(out, t)
			}
			if !found {
				return errNotFound
			}
			cfg.Client.Tunnels = out
			return nil
		}); err != nil {
			writeMutateError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		s.log.Info("tunnel deleted", "name", name)

	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "expected GET, PUT, PATCH or DELETE")
	}
}

// tunnelStatus returns the runtime status of every tunnel, tolerating a client
// that is not running.
func (s *Server) tunnelStatus() any {
	if s.cli == nil {
		return []any{}
	}
	return s.cli.TunnelStatuses()
}

// redactServers renders relay entries with their settings redacted.
func redactServers(entries []config.ServerEntry) []config.ServerEntry {
	out := make([]config.ServerEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, redactServer(e))
	}
	return out
}

// redactServer replaces the secret values in one relay's settings.
func redactServer(entry config.ServerEntry) config.ServerEntry {
	if len(entry.Settings) == 0 {
		return entry
	}
	clean := make(map[string]any, len(entry.Settings))
	for k, v := range entry.Settings {
		if isSecretKey(k) {
			if s, ok := v.(string); ok && s != "" {
				clean[k] = RedactedPlaceholder
				continue
			}
		}
		clean[k] = v
	}
	entry.Settings = clean
	return entry
}
