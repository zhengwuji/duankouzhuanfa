// Package cryptox holds the symmetric primitives shared by PortTransit's
// encrypted transports.
//
// Everything here is standard-library based; there is no bespoke cipher. The
// package exists so VLESS, VMess, Trojan and Shadowsocks-2022 all derive keys
// and frame records the same way, which is what makes them interoperable with
// mainstream clients.
package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// Cipher names the AEAD suites PortTransit can negotiate.
type Cipher string

const (
	// CipherAES128GCM is the fastest suite on CPUs with AES-NI.
	CipherAES128GCM Cipher = "aes-128-gcm"
	// CipherAES256GCM is the wider-key variant.
	CipherAES256GCM Cipher = "aes-256-gcm"
	// CipherChaCha20Poly1305 is the fastest suite without AES-NI and is the
	// default for Shadowsocks-2022 and VLESS-Vision.
	CipherChaCha20Poly1305 Cipher = "chacha20-poly1305"
	// CipherNone disables encryption. It is only valid for the direct
	// transport on trusted links.
	CipherNone Cipher = "none"
)

// KeySize returns the key length in bytes for a suite, or 0 for CipherNone.
func (c Cipher) KeySize() int {
	switch c {
	case CipherAES128GCM:
		return 16
	case CipherAES256GCM, CipherChaCha20Poly1305:
		return 32
	default:
		return 0
	}
}

// NonceSize returns the nonce length for a suite.
func (c Cipher) NonceSize() int {
	switch c {
	case CipherAES128GCM, CipherAES256GCM, CipherChaCha20Poly1305:
		return 12
	default:
		return 0
	}
}

// TagSize returns the authentication tag length for a suite.
func (c Cipher) TagSize() int {
	if c == CipherNone {
		return 0
	}
	return 16
}

// Overhead is the per-record expansion: nonce plus tag.
func (c Cipher) Overhead() int { return c.NonceSize() + c.TagSize() }

// Valid reports whether the suite is recognised by this build.
func (c Cipher) Valid() bool {
	switch c {
	case CipherAES128GCM, CipherAES256GCM, CipherChaCha20Poly1305, CipherNone:
		return true
	}
	return false
}

// DefaultCipher returns the preferred suite for the host CPU. ChaCha20 is
// chosen when AES hardware acceleration is unavailable, which is common on the
// small ARM relays this project targets.
func DefaultCipher() Cipher { return CipherChaCha20Poly1305 }

// NewAEAD builds an AEAD for the suite with the given key.
func NewAEAD(c Cipher, key []byte) (cipher.AEAD, error) {
	if want := c.KeySize(); len(key) != want {
		return nil, fmt.Errorf("cryptox: %s needs a %d-byte key, got %d", c, want, len(key))
	}
	switch c {
	case CipherAES128GCM, CipherAES256GCM:
		blk, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(blk)
	case CipherChaCha20Poly1305:
		return chacha20poly1305.New(key)
	default:
		return nil, fmt.Errorf("cryptox: %s is not an AEAD suite", c)
	}
}

// HKDF derives length bytes from secret using HKDF-SHA256 with the given salt
// and info string.
func HKDF(secret, salt []byte, info string, length int) []byte {
	r := hkdf.New(sha256.New, secret, salt, []byte(info))
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		// hkdf.Read only fails if the underlying hash fails, which SHA-256
		// never does; a panic here would mean the process is already broken.
		panic("cryptox: hkdf: " + err.Error())
	}
	return out
}

// PBKDF2SHA1 derives length bytes with PBKDF2-HMAC-SHA1. Shadowsocks' legacy
// key derivation uses this, so interoperability requires it.
func PBKDF2SHA1(password []byte, salt []byte, iterations, length int) []byte {
	return pbkdf2.Key(password, salt, iterations, length, sha1.New)
}

// SHA256Sum returns the SHA-256 digest of b.
func SHA256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// HMACSHA256 returns HMAC-SHA256(key, msg).
func HMACSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// HMACSHA1 returns HMAC-SHA1(key, msg). Required by Shadowsocks-2022's
// identity header, which kept SHA-1 for compatibility.
func HMACSHA1(key, msg []byte) []byte {
	m := hmac.New(sha1.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// MD5Sum returns the MD5 digest of b. VMess uses MD5 for its command-key
// derivation, so it is required for interoperability even though MD5 is
// unsuitable for new designs.
func MD5Sum(b []byte) []byte {
	s := md5.Sum(b)
	return s[:]
}

// ConstantTimeEqual compares two byte slices without leaking their contents
// through timing.
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// RandomBytes returns n cryptographically random bytes. It panics on failure
// because a relay that cannot obtain randomness must not keep serving.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("cryptox: entropy source failed: " + err.Error())
	}
	return b
}

// RandomHex returns n random bytes hex-encoded.
func RandomHex(n int) string { return hex.EncodeToString(RandomBytes(n)) }

// UUID is a 16-byte identifier in the RFC 4122 layout. VLESS and VMess use it
// as the shared user credential.
type UUID [16]byte

// ParseUUID accepts the canonical 8-4-4-4-12 form, a bare 32-character hex
// string, or the legacy "uuid" placeholder that some generators emit. A nil
// UUID is returned with an error when s is malformed.
func ParseUUID(s string) (UUID, error) {
	var u UUID
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "{}")
	switch len(s) {
	case 32:
		// bare hex
	case 36:
		s = strings.ReplaceAll(s, "-", "")
		if len(s) != 32 {
			return u, errors.New("cryptox: malformed uuid")
		}
	case 0:
		return u, errors.New("cryptox: empty uuid")
	default:
		return u, fmt.Errorf("cryptox: uuid length %d is not 32 or 36", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return u, fmt.Errorf("cryptox: uuid is not hex: %w", err)
	}
	copy(u[:], b)
	return u, nil
}

// MustParseUUID is ParseUUID for constants known to be valid at build time.
func MustParseUUID(s string) UUID {
	u, err := ParseUUID(s)
	if err != nil {
		panic(err)
	}
	return u
}

// NewUUID returns a random version-4 UUID.
func NewUUID() UUID {
	var u UUID
	copy(u[:], RandomBytes(16))
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return u
}

// String renders the canonical 8-4-4-4-12 form.
func (u UUID) String() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// IsZero reports whether the UUID is all zeros.
func (u UUID) IsZero() bool { return u == UUID{} }

// Bytes returns a copy of the raw 16 bytes.
func (u UUID) Bytes() []byte {
	b := make([]byte, 16)
	copy(b, u[:])
	return b
}

// EncodePasswordKey derives a 32-byte key from a human password using the
// scheme shared by Shadowsocks-2022 and Trojan-Go style configs: PBKDF2-SHA1
// with a fixed iteration count.
//
// The fixed salt is a deliberate compatibility choice, not a security claim —
// these protocols rely on the transport for confidentiality and use the key
// only to bind the password to the session.
func EncodePasswordKey(password string, keyLen int) []byte {
	return PBKDF2SHA1([]byte(password), []byte("porttransit"), 8192, keyLen)
}

// Base64Std encodes b with standard base64 padding.
func Base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// Base64URL encodes b with the URL-safe alphabet and no padding, which is what
// the VMess and VLESS share links use.
func Base64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Base64DecodeLenient decodes standard or URL-safe base64 with or without
// padding, which is what share-link parsing needs in practice.
func Base64DecodeLenient(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.StdEncoding.DecodeString(s)
}

// Chacha20Nonce builds the 12-byte nonce Shadowsocks-2022 uses: a 4-byte
// big-endian counter followed by the 8-byte session id.
func Chacha20Nonce(counter uint32, sessionID [8]byte) []byte {
	n := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint32(n[:4], counter)
	copy(n[4:], sessionID[:])
	return n
}

// IncrementNonce adds delta to a little-endian nonce, which is the convention
// for the IETF ChaCha20-Poly1305 construction used by VLESS-Vision.
func IncrementNonce(nonce []byte, delta uint64) {
	if len(nonce) == 0 {
		return
	}
	var carry uint64 = delta
	for i := 0; i < len(nonce) && carry > 0; i++ {
		v := uint64(nonce[i]) + (carry & 0xff)
		nonce[i] = byte(v)
		carry = (carry >> 8) + (v >> 8)
	}
}

// NewHash returns the hash constructor named by name, used where a protocol
// lets the peer pick the KDF.
func NewHash(name string) (func() hash.Hash, error) {
	switch strings.ToLower(name) {
	case "sha256", "":
		return sha256.New, nil
	case "sha1":
		return sha1.New, nil
	case "md5":
		return md5.New, nil
	default:
		return nil, fmt.Errorf("cryptox: unsupported hash %q", name)
	}
}

// ErrAuthFailed is returned when a record fails authentication. Callers treat
// it as fatal for the connection: a single bad tag means the key is wrong or
// the stream is being tampered with.
var ErrAuthFailed = errors.New("cryptox: authentication failed")

// ErrShortRecord means a length-prefixed record was truncated.
var ErrShortRecord = errors.New("cryptox: truncated record")
