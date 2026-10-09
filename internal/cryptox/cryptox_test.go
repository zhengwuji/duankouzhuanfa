package cryptox

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// TestNewAEADKeySizes proves a key of the wrong length is refused rather than
// silently truncated, which would produce two suites that appear to work but
// derive different keys.
func TestNewAEADKeySizes(t *testing.T) {
	cases := []struct {
		cipher Cipher
		keyLen int
		wantOK bool
	}{
		{CipherAES128GCM, 16, true},
		{CipherAES128GCM, 32, false},
		{CipherAES256GCM, 32, true},
		{CipherAES256GCM, 16, false},
		{CipherChaCha20Poly1305, 32, true},
		{CipherChaCha20Poly1305, 16, false},
		{CipherNone, 0, false},
	}
	for _, tc := range cases {
		_, err := NewAEAD(tc.cipher, make([]byte, tc.keyLen))
		if tc.wantOK && err != nil {
			t.Errorf("NewAEAD(%s, %d bytes) failed: %v", tc.cipher, tc.keyLen, err)
		}
		if !tc.wantOK && err == nil {
			t.Errorf("NewAEAD(%s, %d bytes) succeeded but should have been refused", tc.cipher, tc.keyLen)
		}
	}
}

// TestAEADSealOpenRoundTrip proves each suite round-trips and that a tampered
// ciphertext is refused — the property every transport relies on.
func TestAEADSealOpenRoundTrip(t *testing.T) {
	suites := []Cipher{CipherAES128GCM, CipherAES256GCM, CipherChaCha20Poly1305}
	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	for _, c := range suites {
		t.Run(string(c), func(t *testing.T) {
			key := RandomBytes(c.KeySize())
			aead, err := NewAEAD(c, key)
			if err != nil {
				t.Fatalf("NewAEAD: %v", err)
			}
			nonce := make([]byte, aead.NonceSize())
			sealed := aead.Seal(nil, nonce, plaintext, nil)
			if len(sealed) != len(plaintext)+aead.Overhead() {
				t.Errorf("sealed length %d, want %d", len(sealed), len(plaintext)+aead.Overhead())
			}

			opened, err := aead.Open(nil, nonce, sealed, nil)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(opened, plaintext) {
				t.Errorf("round trip produced %q, want %q", opened, plaintext)
			}

			tampered := append([]byte(nil), sealed...)
			tampered[0] ^= 0x01
			if _, err := aead.Open(nil, nonce, tampered, nil); err == nil {
				t.Error("Open accepted a tampered ciphertext")
			}
		})
	}
}

// TestHKDFDeterministic proves key derivation is reproducible, which is what
// makes two independent implementations interoperate.
func TestHKDFDeterministic(t *testing.T) {
	secret := []byte("shared-secret")
	salt := []byte("a-salt-value")

	a := HKDF(secret, salt, "info", 32)
	b := HKDF(secret, salt, "info", 32)
	if !bytes.Equal(a, b) {
		t.Error("HKDF is not deterministic for identical inputs")
	}
	if len(a) != 32 {
		t.Errorf("HKDF returned %d bytes, want 32", len(a))
	}

	// A different info string must produce a different key, which is the whole
	// point of separating derivation contexts.
	c := HKDF(secret, salt, "other-info", 32)
	if bytes.Equal(a, c) {
		t.Error("HKDF produced the same key for two different info strings")
	}
	d := HKDF(secret, []byte("other-salt"), "info", 32)
	if bytes.Equal(a, d) {
		t.Error("HKDF produced the same key for two different salts")
	}
}

// TestHKDFKnownVector pins the derivation against RFC 5869 test case 1, so a
// future refactor that changes the hash or the info handling is caught rather
// than silently breaking interoperability with every other implementation.
func TestHKDFKnownVector(t *testing.T) {
	ikm := mustHex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := mustHex(t, "000102030405060708090a0b0c")
	// HKDF takes the info parameter as a string, so the RFC's raw octets are
	// passed through a byte-string conversion rather than as hex text.
	info := string(mustHex(t, "f0f1f2f3f4f5f6f7f8f9"))

	got := HKDF(ikm, salt, info, 42)
	want := mustHex(t, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
	if !bytes.Equal(got, want) {
		t.Errorf("HKDF = %x, want %x", got, want)
	}
}

// TestUUIDParseAndRender covers the accepted UUID forms. A parser that rejects
// a form a share link uses makes a relay unreachable for a reason that is
// invisible in the GUI.
func TestUUIDParseAndRender(t *testing.T) {
	const canonical = "de305d54-75b4-431b-adb2-eb6b9e546014"
	want := mustHex(t, "de305d5475b4431badb2eb6b9e546014")

	cases := []string{
		canonical,
		strings.ReplaceAll(canonical, "-", ""),
		"{" + canonical + "}",
	}
	for _, in := range cases {
		u, err := ParseUUID(in)
		if err != nil {
			t.Errorf("ParseUUID(%q): %v", in, err)
			continue
		}
		if !bytes.Equal(u[:], want) {
			t.Errorf("ParseUUID(%q) = %x, want %x", in, u[:], want)
		}
		if u.String() != canonical {
			t.Errorf("UUID.String() = %q, want %q", u.String(), canonical)
		}
	}

	bad := []string{"", "not-a-uuid", "de305d54-75b4-431b-adb2-eb6b9e54601", "zz305d54-75b4-431b-adb2-eb6b9e546014"}
	for _, in := range bad {
		if _, err := ParseUUID(in); err == nil {
			t.Errorf("ParseUUID(%q) succeeded but should have failed", in)
		}
	}
}

// TestNewUUIDVersion proves generated UUIDs carry the version-4 and variant
// bits, because a relay that emits a malformed UUID can be rejected by a
// stricter client.
func TestNewUUIDVersion(t *testing.T) {
	for i := 0; i < 50; i++ {
		u := NewUUID()
		if u.IsZero() {
			t.Fatal("NewUUID returned the zero UUID")
		}
		if u[6]>>4 != 0x4 {
			t.Fatalf("UUID %s has version nibble %x, want 4", u, u[6]>>4)
		}
		if u[8]>>6 != 0x2 {
			t.Fatalf("UUID %s has variant bits %02x, want 10xxxxxx", u, u[8])
		}
	}
}

// TestChacha20Nonce proves the Shadowsocks-2022 nonce layout is a big-endian
// counter followed by the session id, which is what makes two implementations
// agree on the nonce for a given chunk.
func TestChacha20Nonce(t *testing.T) {
	session := [8]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22}
	n := Chacha20Nonce(0x01020304, session)
	want := append([]byte{0x01, 0x02, 0x03, 0x04}, session[:]...)
	if !bytes.Equal(n, want) {
		t.Errorf("Chacha20Nonce = %x, want %x", n, want)
	}
	if len(n) != 12 {
		t.Errorf("nonce is %d bytes, want 12", len(n))
	}
}

// TestIncrementNonce proves the little-endian counter used by VLESS-Vision
// increments correctly, including the carry that a naive implementation drops.
func TestIncrementNonce(t *testing.T) {
	n := make([]byte, 12)
	IncrementNonce(n, 1)
	if n[0] != 1 {
		t.Errorf("after one increment the counter byte is %d, want 1", n[0])
	}
	IncrementNonce(n, 1)
	if n[0] != 2 {
		t.Errorf("after two increments the counter byte is %d, want 2", n[0])
	}

	// 0xff + 1 must carry into the next byte rather than wrapping to zero.
	c := []byte{0xff, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	IncrementNonce(c, 1)
	if c[0] != 0 || c[1] != 1 {
		t.Errorf("carry produced %x, want 00 01 …", c[:2])
	}
}

// TestEncodePasswordKey proves the password key derivation is deterministic
// and produces the requested length.
func TestEncodePasswordKey(t *testing.T) {
	a := EncodePasswordKey("hunter2", 32)
	b := EncodePasswordKey("hunter2", 32)
	if !bytes.Equal(a, b) {
		t.Error("EncodePasswordKey is not deterministic")
	}
	if len(a) != 32 {
		t.Errorf("EncodePasswordKey returned %d bytes, want 32", len(a))
	}
	c := EncodePasswordKey("hunter3", 32)
	if bytes.Equal(a, c) {
		t.Error("two different passwords produced the same key")
	}
}

// TestBase64DecodeLenient covers the forms a share link may use, because a
// strict decoder makes a valid link unusable.
func TestBase64DecodeLenient(t *testing.T) {
	raw := []byte{0xfb, 0xef, 0xbe}
	std := Base64Std(raw)
	url := Base64URL(raw)

	for _, in := range []string{std, url, strings.TrimRight(std, "=")} {
		got, err := Base64DecodeLenient(in)
		if err != nil {
			t.Errorf("Base64DecodeLenient(%q): %v", in, err)
			continue
		}
		if !bytes.Equal(got, raw) {
			t.Errorf("Base64DecodeLenient(%q) = %x, want %x", in, got, raw)
		}
	}
}

// TestConstantTimeEqual proves the comparison is correct; its timing property
// is not measurable in a unit test but its result must be.
func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqual([]byte("abc"), []byte("abc")) {
		t.Error("equal slices compared unequal")
	}
	if ConstantTimeEqual([]byte("abc"), []byte("abd")) {
		t.Error("different slices compared equal")
	}
	if ConstantTimeEqual([]byte("abc"), []byte("abcd")) {
		t.Error("slices of different lengths compared equal")
	}
}

// TestDefaultCipherIsUsable proves the advertised default can actually build
// an AEAD, so a configuration that omits a suite still works.
func TestDefaultCipherIsUsable(t *testing.T) {
	c := DefaultCipher()
	if !c.Valid() {
		t.Fatalf("DefaultCipher returned the invalid suite %q", c)
	}
	if _, err := NewAEAD(c, RandomBytes(c.KeySize())); err != nil {
		t.Fatalf("the default suite cannot build an AEAD: %v", err)
	}
}

// TestCipherSizes pins the per-suite parameters, because a wrong size silently
// breaks interoperability with every other implementation.
func TestCipherSizes(t *testing.T) {
	cases := []struct {
		cipher   Cipher
		key      int
		nonce    int
		tag      int
		overhead int
	}{
		{CipherAES128GCM, 16, 12, 16, 28},
		{CipherAES256GCM, 32, 12, 16, 28},
		{CipherChaCha20Poly1305, 32, 12, 16, 28},
		{CipherNone, 0, 0, 0, 0},
	}
	for _, tc := range cases {
		if got := tc.cipher.KeySize(); got != tc.key {
			t.Errorf("%s.KeySize() = %d, want %d", tc.cipher, got, tc.key)
		}
		if got := tc.cipher.NonceSize(); got != tc.nonce {
			t.Errorf("%s.NonceSize() = %d, want %d", tc.cipher, got, tc.nonce)
		}
		if got := tc.cipher.TagSize(); got != tc.tag {
			t.Errorf("%s.TagSize() = %d, want %d", tc.cipher, got, tc.tag)
		}
		if got := tc.cipher.Overhead(); got != tc.overhead {
			t.Errorf("%s.Overhead() = %d, want %d", tc.cipher, got, tc.overhead)
		}
	}
}

// TestMD5AndSHA256 pin the legacy digests VMess and Shadowsocks depend on.
func TestMD5AndSHA256(t *testing.T) {
	if got := hex.EncodeToString(MD5Sum([]byte("abc"))); got != "900150983cd24fb0d6963f7d28e17f72" {
		t.Errorf("MD5Sum(abc) = %s, want 900150983cd24fb0d6963f7d28e17f72", got)
	}
	if got := hex.EncodeToString(SHA256Sum([]byte("abc"))); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Errorf("SHA256Sum(abc) = %s", got)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in test data %q: %v", s, err)
	}
	return b
}
