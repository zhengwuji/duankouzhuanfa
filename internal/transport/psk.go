package transport

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
)

// randomBytes returns n cryptographically random bytes. It panics on failure
// because a relay that cannot obtain randomness must not keep serving.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("transport: entropy source failed: " + err.Error())
	}
	return b
}

// DecodePSK interprets a configured pre-shared key.
//
// Accepted forms, tried in order:
//
//   - empty string        → nil, meaning "no MAC on the preamble"
//   - "base64:<value>"    → explicit base64 (standard or URL alphabet)
//   - "hex:<value>"       → explicit hex
//   - otherwise           → the literal bytes of the string
//
// The literal fallback is what makes a hand-written config work without the
// author having to encode anything; the explicit prefixes exist because a
// passphrase can coincidentally look like valid base64.
func DecodePSK(s string) []byte {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if v, ok := strings.CutPrefix(s, "base64:"); ok {
		if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v)); err == nil {
			return b
		}
		if b, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(v)); err == nil {
			return b
		}
		if b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(v)); err == nil {
			return b
		}
		// A malformed explicit base64 is a config error, but falling back to
		// the literal keeps the relay reachable rather than dead. The GUI
		// reports the mismatch when a handshake fails.
		return []byte(v)
	}
	if v, ok := strings.CutPrefix(s, "hex:"); ok {
		if b, err := decodeHex(strings.TrimSpace(v)); err == nil {
			return b
		}
		return []byte(v)
	}
	return []byte(s)
}

// EncodePSK renders a key in the explicit base64 form so it survives a config
// round trip unambiguously.
func EncodePSK(key []byte) string {
	if len(key) == 0 {
		return ""
	}
	return "base64:" + base64.StdEncoding.EncodeToString(key)
}

// GeneratePSK returns n random bytes as a base64-prefixed config string.
func GeneratePSK(n int) string {
	if n <= 0 {
		n = 32
	}
	return EncodePSK(randomBytes(n))
}

func decodeHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		s = "0" + s
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, ok1 := hexVal(s[i*2])
		lo, ok2 := hexVal(s[i*2+1])
		if !ok1 || !ok2 {
			return nil, ErrBadAddress
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
