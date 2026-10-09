package main

import (
	"net"
	"testing"
)

// TestClientAddressForRewritesAWildcardBind is the regression test for a
// configuration that looked complete but could never connect.
//
// "init --mode both" binds the relay to 0.0.0.0 by default and then writes the
// relay's address into the client section. 0.0.0.0 is a bind address, not a
// destination, so dialling it fails on every platform and the local proxy
// silently has no working relay.
func TestClientAddressForRewritesAWildcardBind(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:8443", ":8443", "[::]:8443", ":::"} {
		got := clientAddressFor(listen)
		host, port, err := net.SplitHostPort(got)
		if err != nil {
			// ":::" is not a valid address at all; passing it through
			// unchanged is the correct behaviour for input we cannot parse.
			if listen == ":::" {
				continue
			}
			t.Errorf("clientAddressFor(%q) returned %q, which does not parse: %v", listen, got, err)
			continue
		}
		if host == "0.0.0.0" || host == "::" || host == "" {
			t.Errorf("clientAddressFor(%q) returned %q, which is still a bind address", listen, got)
		}
		if port != "8443" {
			t.Errorf("clientAddressFor(%q) changed the port to %q", listen, port)
		}
	}
}

// TestClientAddressForKeepsASpecificBind proves an operator's explicit choice
// of interface survives.
//
// Rewriting a specific address to loopback would break the case where the relay
// and client are on different hosts, or where the relay is reached over a
// specific interface.
func TestClientAddressForKeepsASpecificBind(t *testing.T) {
	for _, listen := range []string{"127.0.0.1:8443", "10.0.0.5:8443", "[2001:db8::1]:8443"} {
		if got := clientAddressFor(listen); got != listen {
			t.Errorf("clientAddressFor(%q) = %q, want it unchanged", listen, got)
		}
	}
}

// TestClientSettingsForOmitsRelaySecrets is the most important assertion here.
//
// The relay's settings hold its private key material. Copying them wholesale
// into the client section would write the relay's private key into the client
// half of a file that the console displays, so the translation must be
// explicit rather than a copy.
func TestClientSettingsForOmitsRelaySecrets(t *testing.T) {
	creds := map[string]string{
		"psk":        "base64:AAAA",
		"uuid":       "b831381d-6324-4d53-ad4f-8cda48b30811",
		"password":   "hunter2",
		"method":     "2022-blake3-chacha20-poly1305",
		"publicKey":  "pub",
		"shortId":    "abcd",
		"serverName": "www.bing.com",
		"username":   "pt",
		"transport":  "tls",
		"listen":     "0.0.0.0:8443",
		"name":       "relay-tls",
	}
	for _, transport := range []string{"direct", "tls", "vless", "vmess", "trojan", "shadowsocks", "reality", "socks5", "ws", "httpupgrade"} {
		got := clientSettingsFor(transport, creds)
		for _, forbidden := range []string{"privateKey", "certFile", "keyFile", "transport", "listen", "name"} {
			if _, ok := got[forbidden]; ok {
				t.Errorf("clientSettingsFor(%q) leaked the relay field %q", transport, forbidden)
			}
		}
	}
}

// TestClientSettingsForCarriesWhatEachSchemeNeeds proves each transport gets
// the fields it actually authenticates with.
//
// A missing field here does not fail at configuration time; it fails at
// handshake time on the user's machine, which is far harder to diagnose.
func TestClientSettingsForCarriesWhatEachSchemeNeeds(t *testing.T) {
	creds := map[string]string{
		"psk":        "base64:AAAA",
		"uuid":       "b831381d-6324-4d53-ad4f-8cda48b30811",
		"password":   "hunter2",
		"method":     "2022-blake3-chacha20-poly1305",
		"publicKey":  "pub",
		"shortId":    "abcd",
		"serverName": "www.bing.com",
		"username":   "pt",
	}
	cases := []struct {
		transport string
		want      []string
	}{
		{"direct", []string{"psk"}},
		{"tls", []string{"psk", "insecure"}},
		{"vless", []string{"psk", "uuid", "insecure"}},
		{"vmess", []string{"psk", "uuid", "insecure"}},
		{"trojan", []string{"psk", "password", "insecure"}},
		{"shadowsocks", []string{"method", "password"}},
		{"reality", []string{"serverName", "publicKey", "shortId"}},
		{"socks5", []string{"username", "password"}},
		{"ws", []string{"psk", "tls"}},
		{"httpupgrade", []string{"psk", "tls"}},
	}
	for _, tc := range cases {
		got := clientSettingsFor(tc.transport, creds)
		for _, key := range tc.want {
			v, ok := got[key]
			if !ok {
				t.Errorf("clientSettingsFor(%q) is missing %q; the client would fail at handshake time", tc.transport, key)
				continue
			}
			if s, isStr := v.(string); isStr && s == "" {
				t.Errorf("clientSettingsFor(%q) set %q to an empty string", tc.transport, key)
			}
		}
	}
}

// TestClientSettingsForDisablesTLSOnPlainSchemes proves the schemes that the
// relay serves in the clear do not make the client attempt a TLS handshake.
//
// Both default to TLS on the client side, so leaving this unset makes the
// client wait for a ServerHello the relay never sends, and the failure is a
// handshake timeout rather than a clear configuration error.
func TestClientSettingsForDisablesTLSOnPlainSchemes(t *testing.T) {
	for _, transport := range []string{"ws", "httpupgrade"} {
		got := clientSettingsFor(transport, map[string]string{"psk": "base64:AAAA"})
		if v, ok := got["tls"].(bool); !ok || v {
			t.Errorf("clientSettingsFor(%q) did not disable TLS: %v", transport, got["tls"])
		}
	}
}
