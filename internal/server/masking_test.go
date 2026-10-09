package server

import (
	"testing"

	"porttransit/internal/config"
)

func listenerWith(settings map[string]any) config.Listener {
	return config.Listener{
		Name:      "l1",
		Transport: "trojan",
		Listen:    "127.0.0.1:443",
		Enabled:   true,
		Settings:  settings,
	}
}

func TestMaskingNoneLeavesSettingsUntouched(t *testing.T) {
	lc := listenerWith(map[string]any{"psk": "keep"})

	for _, mode := range []string{"", "none"} {
		got := applyMasking(lc, config.MaskingConfig{Mode: mode, FallbackAddr: "example.com:443"})
		if got.Settings["fallbackAddr"] != nil {
			t.Errorf("mode %q injected a fallback anyway", mode)
		}
		if got.Settings["psk"] != "keep" {
			t.Errorf("mode %q dropped an existing setting", mode)
		}
	}
}

// This is the whole point of the feature: a fallback configured once in
// server.masking must reach the transport, because the transport is what
// actually forwards an unauthenticated connection.
func TestMaskingSuppliesTheFallbackToTheTransport(t *testing.T) {
	lc := listenerWith(nil)
	m := config.MaskingConfig{
		Mode:               "tls-fallback",
		FallbackAddr:       "www.bing.com:443",
		FallbackServerName: "www.bing.com",
		CertFile:           "/etc/porttransit/certs/relay.crt",
		KeyFile:            "/etc/porttransit/certs/relay.key",
		Sniff:              true,
	}

	got := applyMasking(lc, m)

	for key, want := range map[string]any{
		"fallbackAddr":       "www.bing.com:443",
		"fallbackServerName": "www.bing.com",
		"certFile":           "/etc/porttransit/certs/relay.crt",
		"keyFile":            "/etc/porttransit/certs/relay.key",
		"sniff":              true,
	} {
		if got.Settings[key] != want {
			t.Errorf("setting %q is %v, want %v", key, got.Settings[key], want)
		}
	}
}

// A listener that names its own fallback is being specific, so a global
// default must not override it. Otherwise enabling masking globally would
// silently redirect a listener an operator had already configured.
func TestListenerSettingsWinOverGlobalMasking(t *testing.T) {
	lc := listenerWith(map[string]any{
		"fallbackAddr":       "own.example.com:443",
		"fallbackServerName": "own.example.com",
	})
	m := config.MaskingConfig{
		Mode:               "tls-fallback",
		FallbackAddr:       "global.example.com:443",
		FallbackServerName: "global.example.com",
	}

	got := applyMasking(lc, m)

	if got.Settings["fallbackAddr"] != "own.example.com:443" {
		t.Errorf("the global fallback overwrote the listener's own: %v", got.Settings["fallbackAddr"])
	}
	if got.Settings["fallbackServerName"] != "own.example.com" {
		t.Errorf("the global SNI overwrote the listener's own: %v", got.Settings["fallbackServerName"])
	}
}

// The input config is often shared with the GUI, so merging must not mutate it:
// otherwise the in-memory config would drift from the file on disk and a save
// would persist settings the operator never wrote.
func TestMaskingDoesNotMutateTheInputListener(t *testing.T) {
	original := map[string]any{"psk": "keep"}
	lc := listenerWith(original)
	m := config.MaskingConfig{Mode: "tls-fallback", FallbackAddr: "example.com:443"}

	got := applyMasking(lc, m)

	if _, leaked := original["fallbackAddr"]; leaked {
		t.Fatal("the original settings map was mutated")
	}
	if lc.Settings["fallbackAddr"] != nil {
		t.Fatal("the original listener was mutated")
	}
	// The returned listener must have its own map, not an alias.
	if &got.Settings == &lc.Settings {
		t.Fatal("the returned settings alias the input")
	}
}

func TestMaskingWithOnlySomeFieldsSet(t *testing.T) {
	lc := listenerWith(nil)
	// A fallback address with no SNI is valid: the transport then uses the
	// address's own hostname, which is the common case.
	got := applyMasking(lc, config.MaskingConfig{Mode: "tls-fallback", FallbackAddr: "example.com:443"})

	if got.Settings["fallbackAddr"] != "example.com:443" {
		t.Error("the fallback address was not applied")
	}
	if _, set := got.Settings["fallbackServerName"]; set {
		t.Error("an empty SNI was written, which would override the transport's own default")
	}
}

func TestMaskingOnAListenerWithNilSettings(t *testing.T) {
	lc := listenerWith(nil)
	got := applyMasking(lc, config.MaskingConfig{Mode: "http-fallback", FallbackAddr: "site.example.com:80"})
	if got.Settings == nil {
		t.Fatal("a nil settings map was left in place")
	}
	if got.Settings["fallbackAddr"] != "site.example.com:80" {
		t.Errorf("fallbackAddr is %v", got.Settings["fallbackAddr"])
	}
}

func TestMaskingAppliesOnlyToTransportsThatCanForward(t *testing.T) {
	// Only these have somewhere to send an unauthenticated connection. Telling
	// an operator otherwise would leave them believing probing is handled.
	for _, name := range []string{"trojan", "http", "httpupgrade", "ws"} {
		if !maskingAppliesTo(name) {
			t.Errorf("masking should apply to %q", name)
		}
	}
	for _, name := range []string{"tls", "reality", "vless", "vmess", "shadowsocks", "socks5", "direct"} {
		if maskingAppliesTo(name) {
			t.Errorf("masking should not claim to apply to %q", name)
		}
	}
}

func TestDescribeMasking(t *testing.T) {
	for _, tc := range []struct {
		m    config.MaskingConfig
		want string
	}{
		{config.MaskingConfig{}, "none"},
		{config.MaskingConfig{Mode: "none"}, "none"},
		{config.MaskingConfig{Mode: "tls-fallback", FallbackAddr: "a.example:443"}, "tls-fallback → a.example:443"},
		{config.MaskingConfig{Mode: "http-fallback"}, "http-fallback"},
	} {
		if got := describeMasking(tc.m); got != tc.want {
			t.Errorf("describeMasking(%+v) = %q, want %q", tc.m, got, tc.want)
		}
	}
}
