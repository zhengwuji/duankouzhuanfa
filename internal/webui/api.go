package webui

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"porttransit/internal/config"
	"porttransit/internal/cryptox"
)

// The management API.
//
// Every mutating endpoint follows the same shape: decode, apply to a copy of
// the configuration, validate the whole document, persist, and only then
// report success. Applying to a copy is what makes a rejected change a no-op
// rather than a half-applied edit that the operator has to unpick by hand.

// handleLogin authenticates an administrator and mints a session.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "login requires POST")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	// The username is compared first and the password always verified, so a
	// wrong username and a wrong password take the same time and neither
	// reveals whether the account exists.
	userOK := body.Username == s.cfg.WebUI.Username
	passOK := VerifyPassword(s.cfg.WebUI.PasswordHash, body.Password)

	if !userOK || !passOK {
		s.log.Warn("failed management login",
			"remote", clientIP(r, s.cfg.WebUI.TrustedProxies),
			"username", body.Username,
		)
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}

	token := s.sessions.create(clientIP(r, s.cfg.WebUI.TrustedProxies))
	ttl := s.cfg.WebUI.SessionTTL.Or(12 * time.Hour)
	setSessionCookie(w, r, token, ttl)

	s.log.Info("management login", "remote", clientIP(r, s.cfg.WebUI.TrustedProxies), "username", body.Username)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"username": s.cfg.WebUI.Username,
		"expires":  time.Now().Add(ttl).Format(time.RFC3339),
	})
}

// handleLogout destroys the caller's session.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := sessionToken(r)
	if token != "" {
		s.sessions.destroy(token)
	}
	clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleSession reports whether the caller holds a live session, so the front
// end can decide between the login form and the console without a failed
// request.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	token := sessionToken(r)
	authed := token != "" && s.sessions.valid(token)
	resp := map[string]any{
		"authenticated": authed,
		"username":      s.cfg.WebUI.Username,
		"version":       currentVersion(),
	}
	if authed {
		s.sessions.touch(token)
		resp["mode"] = string(s.cfg.Mode)
		resp["sessions"] = s.sessions.count()
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleStatus reports the process's overall state.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"version":  currentVersion(),
		"mode":     string(s.cfg.Mode),
		"uptime":   time.Since(startedAt).Seconds(),
		"webui":    map[string]any{"listen": s.Addr(), "url": s.URL(), "tls": s.cfg.WebUI.TLS},
		"sessions": s.sessions.count(),
	}

	if s.relay != nil {
		resp["server"] = map[string]any{
			"stats":     s.relay.Stats().Snapshot(),
			"listeners": s.relay.ListenerStatuses(),
			"forwards":  len(s.cfg.Server.Forwards),
			"clients":   len(s.cfg.Server.Clients),
		}
	}
	if s.cli != nil {
		resp["client"] = map[string]any{
			"stats":   s.cli.Stats().Snapshot(),
			"tunnels": s.cli.TunnelStatuses(),
			"proxy":   s.cli.ProxyStatus(),
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// startedAt anchors the uptime the status endpoint reports.
var startedAt = time.Now()

// handleConfig returns the configuration with secrets redacted.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	redacted := redactConfig(s.cfg)
	writeJSON(w, http.StatusOK, map[string]any{
		"config": redacted,
		"path":   s.path,
	})
}

// handleValidate checks a candidate configuration without persisting it, so
// the front end can show every problem before the operator commits.
func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "validation requires POST")
		return
	}
	var body struct {
		Config json.RawMessage `json:"config"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	// Validation runs against a parsed candidate so it exercises exactly the
	// same path a reload would.
	candidate, err := config.Parse(body.Config)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":  false,
			"errors": splitProblems(err.Error()),
		})
		return
	}
	if err := candidate.Validate(); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":  false,
			"errors": splitProblems(err.Error()),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "errors": []string{}})
}

// handleReload re-reads the configuration file from disk.
func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "reload requires POST")
		return
	}
	cfg, err := config.Load(s.path)
	if err != nil {
		writeError(w, http.StatusBadRequest, "reload_failed", "%v", err)
		return
	}

	// A reload changes the in-memory document but cannot rebind sockets, so
	// the operator is told explicitly that a restart is needed for listener
	// changes to take effect. Silently ignoring them would be worse.
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()

	s.log.Info("configuration reloaded from disk", "path", s.path)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"restartRequired": []string{
			"listeners",
			"webui.listen",
			"client.tunnels[].listen",
			"client.proxy",
		},
		"note": "listener and bind-address changes need a service restart",
	})
}

// handleLogs returns recent log records.
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 2000 {
		limit = 2000
	}

	if s.buffer == nil {
		writeJSON(w, http.StatusOK, map[string]any{"entries": []any{}})
		return
	}
	entries := s.buffer.Snapshot(limit)

	level := strings.ToLower(r.URL.Query().Get("level"))
	if level == "" || level == "debug" {
		writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
		return
	}

	// Filtering server-side keeps a chatty debug log from being sent in full
	// just for the browser to discard most of it.
	min := levelRank(level)
	filtered := make([]any, 0, len(entries))
	for _, e := range entries {
		if levelRank(strings.ToLower(e.Level)) >= min {
			filtered = append(filtered, e)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": filtered})
}

func levelRank(level string) int {
	switch level {
	case "debug":
		return 0
	case "info":
		return 1
	case "warn", "warning":
		return 2
	case "error":
		return 3
	default:
		return 0
	}
}

// handleTransports lists the registered schemes so the GUI can offer them.
func (s *Server) handleTransports(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"transports": transportList()})
}

// handleHealth reports every relay's health.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if s.cli == nil {
		writeJSON(w, http.StatusOK, map[string]any{"servers": []any{}})
		return
	}
	entries := s.cli.Pools().Entries()
	out := make([]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Health())
	}
	writeJSON(w, http.StatusOK, map[string]any{"servers": out})
}

// handleProbe probes one relay immediately, so an operator does not have to
// wait for the next scheduled check after editing a relay.
func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "probing requires POST")
		return
	}
	if s.cli == nil {
		writeError(w, http.StatusBadRequest, "client_disabled", "this process is not running a client")
		return
	}
	var body struct {
		ServerID string `json:"serverId"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	entries := s.cli.Pools().Entries()
	for _, e := range entries {
		if e.ID != body.ServerID {
			continue
		}
		if err := s.cli.ProbeNow(r.Context(), e.ID); err != nil {
			writeError(w, http.StatusBadGateway, "probe_failed", "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "server": e.Health()})
		return
	}
	writeError(w, http.StatusNotFound, "not_found", "no relay with id %q", body.ServerID)
}

// handlePassword changes the administrator password.
func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Current  string `json:"current"`
		Password string `json:"password"`
		Username string `json:"username"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	// The current password is required even though the caller already holds a
	// session: a session may have been left open on an unlocked machine, and
	// the password change is the operation that would lock the real owner out.
	if !VerifyPassword(s.cfg.WebUI.PasswordHash, body.Current) {
		s.log.Warn("password change rejected", "remote", clientIP(r, s.cfg.WebUI.TrustedProxies))
		writeError(w, http.StatusForbidden, "invalid_credentials", "the current password is not correct")
		return
	}
	if err := ValidatePassword(body.Password); err != nil {
		writeError(w, http.StatusBadRequest, "weak_password", "%v", err)
		return
	}

	hash, err := HashPassword(body.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hash_failed", "%v", err)
		return
	}

	if err := s.mutate(func(cfg *config.Config) error {
		cfg.WebUI.PasswordHash = hash
		if body.Username != "" {
			cfg.WebUI.Username = body.Username
		}
		return nil
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "save_failed", "%v", err)
		return
	}

	// Every other session is invalidated: a password change is the operator's
	// remedy for a suspected compromise, so leaving other sessions alive would
	// defeat it.
	s.sessions.destroyAll()
	clearSessionCookie(w, r)

	s.log.Info("administrator password changed", "remote", clientIP(r, s.cfg.WebUI.TrustedProxies))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "password changed; every session was signed out, please log in again",
	})
}

// splitProblems breaks a validation error into individual messages so the GUI
// can render them as a list rather than one long string.
func splitProblems(msg string) []string {
	msg = strings.TrimPrefix(msg, "config: ")
	parts := strings.Split(msg, "; ")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// newID returns a short random identifier for a newly created relay or tunnel.
func newID(prefix string) string {
	return prefix + "-" + cryptox.RandomHex(4)
}
