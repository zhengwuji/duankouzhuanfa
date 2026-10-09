package server

import (
	"porttransit/internal/config"
)

// maskingSettingKeys are the per-listener settings that the global
// server.masking block feeds.
//
// They are the same keys the transports already read, so masking is a way to
// state a fallback once instead of repeating it on every listener. A listener
// that sets a key explicitly always wins, which is what makes a global default
// safe to enable.
const (
	settingFallbackAddr       = "fallbackAddr"
	settingFallbackServerName = "fallbackServerName"
	settingFallbackHTTPHost   = "host"
	settingCertFile           = "certFile"
	settingKeyFile            = "keyFile"
	settingSniff              = "sniff"
)

// applyMasking merges the global masking configuration into one listener's
// settings.
//
// Masking exists because a relay that answers nothing, or answers wrongly, is
// trivially identifiable as a proxy: a TLS listener that cannot complete a
// handshake, or an HTTP listener that returns 404 for everything, looks nothing
// like the website it claims to be. The transports already know how to present
// a fallback — Trojan forwards unauthenticated traffic, the HTTP transports
// serve a real site — but each needs to be told where that site is. Without
// this merge the masking block was validated and then ignored, so an operator
// could configure it and get no effect at all.
//
// The listener's own settings take precedence: a listener that names its own
// fallback is being specific, and a global default must not override it.
func applyMasking(lc config.Listener, m config.MaskingConfig) config.Listener {
	// "none" is the default and means exactly that: do not touch anything, so
	// a listener that already configures a fallback by hand keeps working.
	if m.Mode == "" || m.Mode == "none" {
		return lc
	}

	// Copy before writing. The config may be shared with the caller (the GUI
	// holds a pointer to it), and mutating a listener's settings in place would
	// make the in-memory config differ from the file on disk.
	merged := make(map[string]any, len(lc.Settings)+4)
	for k, v := range lc.Settings {
		merged[k] = v
	}
	setIfAbsent := func(key string, value any) {
		if _, exists := merged[key]; exists {
			return
		}
		merged[key] = value
	}

	if m.FallbackAddr != "" {
		setIfAbsent(settingFallbackAddr, m.FallbackAddr)
	}
	if m.FallbackServerName != "" {
		setIfAbsent(settingFallbackServerName, m.FallbackServerName)
	}
	if m.FallbackHTTPHost != "" {
		setIfAbsent(settingFallbackHTTPHost, m.FallbackHTTPHost)
	}
	if m.CertFile != "" {
		setIfAbsent(settingCertFile, m.CertFile)
	}
	if m.KeyFile != "" {
		setIfAbsent(settingKeyFile, m.KeyFile)
	}
	if m.Sniff {
		setIfAbsent(settingSniff, true)
	}

	lc.Settings = merged
	return lc
}

// maskingAppliesTo reports whether a transport understands a fallback at all.
//
// Masking is only meaningful for the transports that have somewhere to send an
// unauthenticated connection. Silently injecting a fallback into a transport
// that ignores the key would leave the operator believing probing is handled
// when it is not, so the caller uses this to warn instead.
func maskingAppliesTo(transportName string) bool {
	switch transportName {
	case "trojan", "http", "httpupgrade", "ws":
		return true
	default:
		return false
	}
}

// describeMasking renders the effective masking for the log, so an operator can
// see that it took effect rather than inferring it from behaviour.
func describeMasking(m config.MaskingConfig) string {
	if m.Mode == "" || m.Mode == "none" {
		return "none"
	}
	out := m.Mode
	if m.FallbackAddr != "" {
		out += " → " + m.FallbackAddr
	}
	return out
}
