package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Credential generation for the init command.
//
// Every helper here is deliberately simple and uses only the standard library
// plus bcrypt, because the init path runs on a fresh host before anything else
// is installed and must not depend on the relay's own packages being
// initialised.

// randomPassword returns a URL-safe random password with enough entropy that
// an operator never needs to strengthen it.
//
// 24 bytes of base64 is 192 bits: far beyond what an offline attack against a
// bcrypt hash could reach, and short enough to type from a console.
func randomPassword() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic("porttransit: entropy source failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashPassword renders a password as a bcrypt hash, matching what the
// management console stores.
func hashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("generate password hash: %w", err)
	}
	return string(h), nil
}

// generatePSK returns a 32-byte pre-shared key in the transport package's
// `base64:` form, so the config round-trips unambiguously.
func generatePSK() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("porttransit: entropy source failed: " + err.Error())
	}
	return "base64:" + base64.StdEncoding.EncodeToString(b)
}

// newUUID returns a random version-4 UUID in canonical form.
func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("porttransit: entropy source failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// generateSSKey returns a base64 key of the length Shadowsocks-2022 requires
// for the configured method.
//
// The 2022 methods take a raw key rather than a passphrase, so the length is
// not cosmetic: a key of the wrong size is rejected at handshake time and the
// failure is hard to diagnose from the client side.
func generateSSKey(method string) string {
	n := 32
	if method == "shadowsocks-128" {
		n = 16
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("porttransit: entropy source failed: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(b)
}

// generateRealityKeyPair returns a base64 X25519 key pair for REALITY.
//
// X25519 rather than Ed25519 because REALITY derives its shared secret from an
// ECDH exchange with the client's ephemeral key; the signing key used for the
// temporary certificate is generated separately and per process.
func generateRealityKeyPair() (privateB64, publicB64 string) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic("porttransit: generate REALITY key: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(priv.Bytes()),
		base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
}

// generateShortID returns a random 8-byte REALITY short id in hex.
//
// REALITY's short id is exactly 8 bytes on the wire, so the hex form is
// exactly 16 characters; generating the full width avoids relying on the
// zero-padding path.
func generateShortID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("porttransit: entropy source failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// defaultPortFor returns the conventional port for a transport.
func defaultPortFor(transport string) int {
	switch transport {
	case "tls", "trojan", "vless", "vmess", "reality":
		return 8443
	case "shadowsocks":
		return 8388
	case "socks5":
		return 1080
	case "httpupgrade":
		return 80
	case "websocket", "ws", "http", "direct":
		return 8080
	default:
		return 8443
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// ed25519SeedLen documents the key size REALITY's temporary certificate uses,
// so a future change to the certificate path has a reference point.
const ed25519SeedLen = ed25519.SeedSize
