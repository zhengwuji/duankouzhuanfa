package webui

import (
	"encoding/json"
	"strings"

	"porttransit/internal/config"
)

// Redaction.
//
// The API never returns a stored secret. A management console that echoes a
// relay's PSK or a client's UUID into a browser turns every screenshot, every
// proxy log and every browser extension into a credential leak. Instead the
// API returns a placeholder and treats that placeholder as "unchanged" on the
// way back in, so the front end can round-trip a configuration it never saw.

// RedactedPlaceholder is what the API returns in place of a stored secret.
//
// It is deliberately not a valid value for any field, so an accidental
// round-trip without the "unchanged" handling would fail validation loudly
// rather than silently overwrite a credential with a literal.
const RedactedPlaceholder = "__redacted__"

// secretKeys lists the setting keys whose values are never returned.
var secretKeys = map[string]bool{
	"psk":          true,
	"password":     true,
	"passwordhash": true,
	"uuid":         true,
	"privatekey":   true,
	"key":          true,
	"token":        true,
	"secret":       true,
	"credentials":  true,
}

// isSecretKey reports whether a setting name holds a secret.
func isSecretKey(key string) bool {
	return secretKeys[strings.ToLower(strings.TrimSpace(key))]
}

// redactConfig renders a configuration safe to send to a browser.
func redactConfig(cfg *config.Config) *config.Config {
	if cfg == nil {
		return nil
	}
	// Marshal, redact, unmarshal: going through JSON guarantees the redacted
	// view has exactly the shape the API contract promises, with no field
	// missed because a new struct was added and this function was not.
	raw, err := json.Marshal(cfg)
	if err != nil {
		return cfg
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return cfg
	}
	redactValue(generic)

	out := &config.Config{}
	if err := json.Unmarshal(mustMarshal(generic), out); err != nil {
		return cfg
	}
	return out
}

// redactValue walks a decoded JSON tree and replaces secret values in place.
func redactValue(v any) {
	switch node := v.(type) {
	case map[string]any:
		for key, val := range node {
			if isSecretKey(key) {
				if s, ok := val.(string); ok && s != "" {
					node[key] = RedactedPlaceholder
					continue
				}
				if _, ok := val.(map[string]any); ok {
					// A credentials map is keyed by transport name, so every
					// value inside it is a secret regardless of its own key.
					node[key] = redactAllValues(val.(map[string]any))
					continue
				}
			}
			redactValue(val)
		}
	case []any:
		for _, item := range node {
			redactValue(item)
		}
	}
}

// redactAllValues replaces every non-empty string value in m.
func redactAllValues(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok && s != "" {
			out[k] = RedactedPlaceholder
			continue
		}
		out[k] = v
	}
	return out
}

// applyRedactionInPlace restores secrets the caller did not change.
//
// It runs against the incoming document before it is validated, replacing the
// placeholder with the value currently on disk. This is what makes the
// round-trip safe: the front end can submit the whole configuration it
// received, and every secret it never saw is preserved.
func applyRedactionInPlace(incoming, current *config.Config) {
	if incoming == nil || current == nil {
		return
	}

	// Web UI password.
	if incoming.WebUI.PasswordHash == RedactedPlaceholder || incoming.WebUI.PasswordHash == "" {
		incoming.WebUI.PasswordHash = current.WebUI.PasswordHash
	}

	if incoming.Server != nil && current.Server != nil {
		restoreSettings(incoming.Server.Listeners, current.Server.Listeners)
		restoreClientCredentials(incoming.Server.Clients, current.Server.Clients)
	}
	if incoming.Client != nil && current.Client != nil {
		restoreSettings(incoming.Client.Servers, current.Client.Servers)
		if incoming.Client.Proxy.PasswordHash == RedactedPlaceholder || incoming.Client.Proxy.PasswordHash == "" {
			incoming.Client.Proxy.PasswordHash = current.Client.Proxy.PasswordHash
		}
	}
}

// restoreSettings restores redacted values in matching listeners or relays.
func restoreSettings[T any](incoming, current []T) {
	cur := make(map[string]map[string]any, len(current))
	for _, item := range current {
		if id, settings, ok := settingsOf(item); ok {
			cur[id] = settings
		}
	}
	for _, item := range incoming {
		id, settings, ok := settingsOf(item)
		if !ok || settings == nil {
			continue
		}
		prev, found := cur[id]
		if !found {
			continue
		}
		for k, v := range settings {
			if s, ok := v.(string); ok && s == RedactedPlaceholder {
				if old, ok := prev[k]; ok {
					settings[k] = old
				}
			}
		}
	}
}

// settingsOf extracts the identifier and settings map from a listener or a
// relay entry, both of which expose Name or ID plus Settings.
func settingsOf(item any) (string, map[string]any, bool) {
	switch v := item.(type) {
	case config.Listener:
		return v.Name, v.Settings, true
	case config.ServerEntry:
		return v.ID, v.Settings, true
	default:
		return "", nil, false
	}
}

// restoreClientCredentials restores redacted per-transport credentials.
func restoreClientCredentials(incoming, current []config.ClientAccount) {
	cur := make(map[string]map[string]string, len(current))
	for _, a := range current {
		cur[a.ID] = a.Credentials
	}
	for i := range incoming {
		prev, ok := cur[incoming[i].ID]
		if !ok {
			continue
		}
		if incoming[i].Credentials == nil {
			incoming[i].Credentials = map[string]string{}
		}
		for k, v := range incoming[i].Credentials {
			if v == RedactedPlaceholder {
				if old, ok := prev[k]; ok {
					incoming[i].Credentials[k] = old
				}
			}
		}
	}
}

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}
