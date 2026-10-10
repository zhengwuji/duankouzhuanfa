package reality

import (
	"crypto/ecdh"
	"encoding/base64"
	"testing"
)

// A fixed X25519 pair, cross-checked against an independent implementation
// (Python's `cryptography` library: X25519PrivateKey → public_bytes).
//
// The external check is what makes this a known-answer vector rather than a
// value this package computed for itself; a test that recomputes its expected
// value with the function under test passes even when the derivation is wrong.
const (
	knownRealityPrivate = "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw"
	knownRealityPublic  = "u1D_noKldM-_gg6X9g-5wUPsdBXPUU-M_Zjv9Z4FlhQ"
)

// TestPublicKeyFromPrivateMatchesAKnownVector proves the derivation is correct,
// not merely self-consistent.
func TestPublicKeyFromPrivateMatchesAKnownVector(t *testing.T) {
	got, err := PublicKeyFromPrivate(knownRealityPrivate)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate: %v", err)
	}
	if got != knownRealityPublic {
		t.Errorf("public key = %q, want %q", got, knownRealityPublic)
	}
}

// TestPublicKeyFromPrivateRoundTrips proves the derived key is the one the
// dialer would accept, which is what makes it usable as a client setting.
//
// This is the property that matters: the relay stores a private key, the client
// is configured with a public key, and nothing else checks that the two belong
// to each other until a handshake fails on the user's machine.
func TestPublicKeyFromPrivateRoundTrips(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	privB64 := base64.RawURLEncoding.EncodeToString(priv.Bytes())

	pub, err := PublicKeyFromPrivate(privB64)
	if err != nil {
		t.Fatalf("PublicKeyFromPrivate: %v", err)
	}
	raw, err := decodeKey(pub)
	if err != nil {
		t.Fatalf("the derived public key does not decode: %v", err)
	}
	parsed, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		t.Fatalf("the derived public key is not an X25519 key: %v", err)
	}
	if !parsed.Equal(priv.PublicKey()) {
		t.Error("the derived public key does not match the private key's own public half")
	}
}

// TestPublicKeyFromPrivateAcceptsEveryBase64Form proves an operator can paste a
// key in whichever encoding their other tool produced.
//
// The relay stores raw URL-safe base64, but a key copied out of Xray or a
// password manager often has padding or uses the standard alphabet. Rejecting
// those would surface as "authentication failed" rather than a configuration
// error.
func TestPublicKeyFromPrivateAcceptsEveryBase64Form(t *testing.T) {
	raw, err := decodeKey(knownRealityPrivate)
	if err != nil {
		t.Fatalf("decode the fixture: %v", err)
	}
	forms := map[string]string{
		"raw url":     base64.RawURLEncoding.EncodeToString(raw),
		"url padded":  base64.URLEncoding.EncodeToString(raw),
		"raw std":     base64.RawStdEncoding.EncodeToString(raw),
		"std padded":  base64.StdEncoding.EncodeToString(raw),
		"with spaces": "  " + base64.RawURLEncoding.EncodeToString(raw) + "  ",
	}
	for name, key := range forms {
		got, err := PublicKeyFromPrivate(key)
		if err != nil {
			t.Errorf("%s: PublicKeyFromPrivate(%q) failed: %v", name, key, err)
			continue
		}
		if got != knownRealityPublic {
			t.Errorf("%s: public key = %q, want %q", name, got, knownRealityPublic)
		}
	}
}

// TestPublicKeyFromPrivateRejectsBadInput proves a typo is reported as a
// configuration error rather than producing a plausible-looking wrong key.
func TestPublicKeyFromPrivateRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"empty":       "",
		"not base64":  "not a key!",
		"too short":   base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}),
		"too long":    base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
		"only spaces": "   ",
	}
	for name, key := range cases {
		if got, err := PublicKeyFromPrivate(key); err == nil {
			t.Errorf("%s: PublicKeyFromPrivate(%q) returned %q, want an error", name, key, got)
		}
	}
}
