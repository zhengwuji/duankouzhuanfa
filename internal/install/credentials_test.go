package install

import (
	"strings"
	"testing"

	"porttransit/internal/config"
)

// knownPrivateKey and knownPublicKey are a fixed X25519 pair.
//
// The public half was cross-checked against an independent implementation
// (Python's `cryptography` library, X25519PrivateKey → public_bytes) so this is
// a real known-answer vector rather than a value this code computed for
// itself. Without an external check, a test that recomputes the expected value
// with the function under test would pass even if the derivation were wrong.
const (
	knownPrivateKey = "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw"
	knownPublicKey  = "u1D_noKldM-_gg6X9g-5wUPsdBXPUU-M_Zjv9Z4FlhQ"
)

// TestListenerCredentialsRecoversTheRealityPublicKey is the regression test for
// a relay that could be installed but never used.
//
// A REALITY relay's configuration stores only its private key; the public key
// is printed once by `init` and then gone. `show-credentials` used to print
// whatever happened to be in the settings map, so it emitted no publicKey at
// all — which meant a relay installed by the one-click script could not be
// added to a client afterwards, because the one value the client authenticates
// with no longer existed anywhere on the host.
func TestListenerCredentialsRecoversTheRealityPublicKey(t *testing.T) {
	l := config.Listener{
		Name:      "relay-jp",
		Transport: "reality",
		Listen:    "0.0.0.0:8443",
		Enabled:   true,
		Settings: map[string]any{
			"privateKey":  knownPrivateKey,
			"psk":         "base64:AAAA",
			"shortId":     "710a2e0332e4ea36",
			"dest":        "www.bing.com:443",
			"serverNames": []any{"www.bing.com"},
		},
	}

	creds := ListenerCredentials(l)

	if creds["publicKey"] != knownPublicKey {
		t.Errorf("publicKey = %q, want %q (derived from the stored private key)", creds["publicKey"], knownPublicKey)
	}
	// serverNames is a list on the relay but a single name on the client, and a
	// JSON round-trip turns []string into []any — so both shapes must work.
	if creds["serverName"] != "www.bing.com" {
		t.Errorf("serverName = %q, want www.bing.com (from serverNames)", creds["serverName"])
	}
	if creds["shortId"] != "710a2e0332e4ea36" {
		t.Errorf("shortId = %q, want the configured value", creds["shortId"])
	}
}

// TestListenerCredentialsAcceptsBothServerNameShapes proves the single-string
// form works too, since an operator editing the config by hand may write it
// either way and REALITY only needs one name.
func TestListenerCredentialsAcceptsBothServerNameShapes(t *testing.T) {
	for name, settings := range map[string]map[string]any{
		"list of strings": {"privateKey": knownPrivateKey, "serverNames": []string{"a.example.com"}},
		"list of anys":    {"privateKey": knownPrivateKey, "serverNames": []any{"a.example.com"}},
		"single string":   {"privateKey": knownPrivateKey, "serverName": "a.example.com"},
	} {
		creds := ListenerCredentials(config.Listener{
			Name: "r", Transport: "reality", Listen: "0.0.0.0:8443", Enabled: true, Settings: settings,
		})
		if creds["serverName"] != "a.example.com" {
			t.Errorf("%s: serverName = %q, want a.example.com", name, creds["serverName"])
		}
	}
}

// TestListenerCredentialsSurvivesABrokenPrivateKey proves one unusable field
// does not hide the rest.
//
// The relay is still running and its PSK and short id are still correct; the
// only thing that cannot be derived is the public key. Refusing to print
// anything would make a working relay look entirely broken.
func TestListenerCredentialsSurvivesABrokenPrivateKey(t *testing.T) {
	creds := ListenerCredentials(config.Listener{
		Name: "r", Transport: "reality", Listen: "0.0.0.0:8443", Enabled: true,
		Settings: map[string]any{
			"privateKey": "not-a-key",
			"psk":        "base64:AAAA",
			"shortId":    "aabb",
		},
	})
	if creds["psk"] != "base64:AAAA" || creds["shortId"] != "aabb" {
		t.Errorf("the usable credentials were dropped: %v", creds)
	}
	if creds["publicKey"] != "" {
		t.Errorf("publicKey = %q for an invalid private key, want it omitted", creds["publicKey"])
	}
}

// TestListenerCredentialsNeverLeaksPrivateMaterial proves the relay's private
// key cannot reach a client through the credentials map.
//
// This is the whole reason the function is a filter rather than a copy: the
// console prints these credentials, and a client entry written from them is
// stored in a file the console displays.
func TestListenerCredentialsNeverLeaksPrivateMaterial(t *testing.T) {
	for _, transportName := range []string{"tls", "vless", "vmess", "trojan", "reality", "shadowsocks", "socks5", "ws", "httpupgrade", "direct", "http"} {
		l := config.Listener{
			Name:      "relay",
			Transport: transportName,
			Listen:    "0.0.0.0:8443",
			Enabled:   true,
			Settings: map[string]any{
				"psk":        "base64:AAAA",
				"privateKey": knownPrivateKey,
				"certFile":   "/etc/porttransit/certs/relay.crt",
				"keyFile":    "/etc/porttransit/certs/relay.key",
				"dest":       "www.bing.com:443",
			},
		}
		creds := ListenerCredentials(l)
		for _, forbidden := range []string{"privateKey", "certFile", "keyFile", "dest"} {
			if _, ok := creds[forbidden]; ok {
				t.Errorf("ListenerCredentials(%q) leaked the relay field %q", transportName, forbidden)
			}
		}
	}
}

// TestListenerCredentialsCarriesWhatEachSchemeNeeds proves each transport's
// client-relevant fields survive the filter.
//
// A field dropped here does not fail at configuration time; it fails at
// handshake time on the user's machine, which is far harder to diagnose.
func TestListenerCredentialsCarriesWhatEachSchemeNeeds(t *testing.T) {
	cases := []struct {
		transport string
		settings  map[string]any
		want      []string
	}{
		{"tls", map[string]any{"psk": "base64:AAAA"}, []string{"psk"}},
		{"direct", map[string]any{"psk": "base64:AAAA"}, []string{"psk"}},
		{"vless", map[string]any{"psk": "base64:A", "uuid": "u"}, []string{"psk", "uuid"}},
		{"vmess", map[string]any{"psk": "base64:A", "uuid": "u"}, []string{"psk", "uuid"}},
		{"trojan", map[string]any{"psk": "base64:A", "password": "p"}, []string{"psk", "password"}},
		{"shadowsocks", map[string]any{"method": "m", "password": "p"}, []string{"method", "password"}},
		{"socks5", map[string]any{"username": "u", "password": "p"}, []string{"username", "password"}},
		{"ws", map[string]any{"psk": "base64:A", "path": "/ws"}, []string{"psk", "path"}},
		{"httpupgrade", map[string]any{"psk": "base64:A", "path": "/up"}, []string{"psk", "path"}},
	}
	for _, tc := range cases {
		l := config.Listener{
			Name:      "relay",
			Transport: tc.transport,
			Listen:    "0.0.0.0:8443",
			Enabled:   true,
			Settings:  tc.settings,
		}
		creds := ListenerCredentials(l)
		for _, key := range tc.want {
			if creds[key] == "" {
				t.Errorf("ListenerCredentials(%q) is missing %q; the client would fail at handshake time", tc.transport, key)
			}
		}
	}
}

// TestClientSettingsForAddsTheFieldsTheRelayLacks proves the translation adds
// what a client needs but a relay never reports.
//
// This is the second half of the same defect: recording a relay's address and
// key correctly is not enough. A TLS-family entry also needs "insecure" (the
// certificate is self-signed and generated on first handshake), and the plain
// schemes need "tls": false or the client waits for a ServerHello that never
// comes.
func TestClientSettingsForAddsTheFieldsTheRelayLacks(t *testing.T) {
	base := map[string]string{"psk": "base64:AAAA"}

	for _, transportName := range []string{"tls", "vless", "vmess", "trojan"} {
		got := ClientSettingsFor(transportName, base)
		if v, ok := got["insecure"].(bool); !ok || !v {
			t.Errorf("ClientSettingsFor(%q) did not set insecure: %v", transportName, got["insecure"])
		}
	}
	for _, transportName := range []string{"ws", "httpupgrade"} {
		got := ClientSettingsFor(transportName, base)
		if v, ok := got["tls"].(bool); !ok || v {
			t.Errorf("ClientSettingsFor(%q) did not disable TLS: %v", transportName, got["tls"])
		}
	}
	// A pinned fingerprint is stronger than insecure, so it must not be
	// silently overridden by the automatic insecure flag.
	pinned := ClientSettingsFor("tls", map[string]string{
		"psk":             "base64:AAAA",
		"certFingerprint": strings.Repeat("ab", 32),
	})
	if pinned["insecure"] == true {
		t.Error("a pinned certificate fingerprint was overridden by insecure:true")
	}
	if pinned["certFingerprint"] == nil {
		t.Error("the pinned fingerprint was dropped")
	}
}

// TestClientSettingsForNeverLeaksPrivateMaterial proves the client translation
// cannot carry the relay's private material into a client entry.
func TestClientSettingsForNeverLeaksPrivateMaterial(t *testing.T) {
	creds := map[string]string{
		"psk":        "base64:AAAA",
		"privateKey": knownPrivateKey,
		"certFile":   "/etc/porttransit/certs/relay.crt",
		"keyFile":    "/etc/porttransit/certs/relay.key",
		"dest":       "www.bing.com:443",
		"listen":     "0.0.0.0:8443",
		"name":       "relay",
		"transport":  "tls",
	}
	for _, transportName := range []string{"tls", "vless", "vmess", "trojan", "reality", "shadowsocks", "socks5", "ws", "httpupgrade", "direct"} {
		got := ClientSettingsFor(transportName, creds)
		for _, forbidden := range []string{"privateKey", "certFile", "keyFile", "dest", "listen", "name", "transport"} {
			if _, ok := got[forbidden]; ok {
				t.Errorf("ClientSettingsFor(%q) leaked the relay field %q", transportName, forbidden)
			}
		}
	}
}

// TestListenerCredentialsFeedsClientSettings proves the two halves compose: a
// listener's credentials go in, and what comes out is exactly what a client
// entry needs, with nothing left for the operator to fill in.
func TestListenerCredentialsFeedsClientSettings(t *testing.T) {
	l := config.Listener{
		Name: "relay-jp", Transport: "reality", Listen: "0.0.0.0:8443", Enabled: true,
		Settings: map[string]any{
			"privateKey":  knownPrivateKey,
			"psk":         "base64:AAAA",
			"shortId":     "710a2e0332e4ea36",
			"serverNames": []any{"www.bing.com"},
		},
	}
	got := ClientSettingsFor(l.Transport, ListenerCredentials(l))
	for _, key := range []string{"psk", "publicKey", "shortId", "serverName"} {
		if got[key] == "" || got[key] == nil {
			t.Errorf("the composed client settings are missing %q: %v", key, got)
		}
	}
	if got["publicKey"] != knownPublicKey {
		t.Errorf("publicKey = %v, want %q", got["publicKey"], knownPublicKey)
	}
}
