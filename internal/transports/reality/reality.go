// Package reality implements the PortTransit XTLS REALITY transport.
//
// REALITY is a TLS 1.3 camouflage: the relay is indistinguishable from the
// third-party site it fronts. A client performs an ordinary TLS 1.3 handshake
// whose ClientHello is byte-for-byte a real browser's, and smuggles an
// authenticated "auth block" into the ClientHello's legacy session_id field.
// The relay recognises that block; anyone else — a censor, a prober, a scanner
// — is spliced straight through to the fronted site and sees nothing but a
// normal port-forward.
//
// # Wire format
//
//	client → relay: [TLS 1.3 ClientHello + REALITY auth block][TLS 1.3 ...][PortTransit preamble]
//	relay  → client: [TLS 1.3 ServerHello ... with a forged certificate]
//	then:           encrypted bidirectional bytes
//
// NativeHeader is false: the final target travels in the PortTransit preamble
// inside the tunnel, exactly as the tls transport does.
//
// # What authenticates the relay to the client
//
// The relay's TLS certificate is deliberately unverifiable: a fresh Ed25519
// self-signed certificate with no CN and no SAN, generated once per process,
// which chains to nothing. Its authenticity comes instead from the last 64
// bytes of its DER — the X.509 signature field — which the relay overwrites
// with HMAC-SHA512(key = AuthKey, message = Ed25519 public key). Only a peer
// that already derived AuthKey from the shared X25519 secret can check it, so
// the client learns "this really is the relay" without any PKI, and a
// man-in-the-middle holding a genuine certificate for the fronted name is
// detected rather than trusted.
//
// # Resolving the session_id AAD circularity
//
// Xray's client seals the auth block with
//
//	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
//
// which looks circular: GCM's tag lives inside session_id, session_id is
// inside the AAD, and the tag depends on the AAD.
//
// There is no circularity, because at seal time the session_id region of
// hello.Raw holds 32 zero bytes. The client first detaches the field:
//
//	hello.SessionId = make([]byte, 32)     // a NEW slice; no longer aliases Raw
//	copy(hello.Raw[39:], hello.SessionId)  // zero the region inside Raw
//	// ... then write version/time/shortId into the detached hello.SessionId ...
//
// so the plaintext lives in a buffer that is not part of the AAD, while Raw
// still carries zeros where session_id will go. The AAD is therefore
// "the ClientHello with session_id zeroed", and it is fully determined before
// the tag exists. The 32-byte seal output is copied into Raw[39:71] afterwards.
//
// The server reconstructs precisely that AAD. From XTLS/REALITY tls.go:
//
//	copy(ciphertext, hs.clientHello.sessionId)
//	copy(hs.clientHello.sessionId, plainText) // hs.clientHello.sessionId points to hs.clientHello.raw[39:]
//	aead.Open(plainText[:0], hs.clientHello.random[20:], ciphertext, hs.clientHello.original)
//
// The trailing comment is the whole answer: on the server, sessionId *does*
// alias raw[39:], so zeroing it zeroes the AAD region, and
// hs.clientHello.original is that same raw buffer. Both sides therefore
// authenticate identical bytes, and the tag never has to authenticate itself.
//
// CONFIRMED by reading both sources, and reproduced end to end against a real
// uTLS Chrome ClientHello: client and server derive the same AuthKey, the
// server's Open succeeds, and a tampered AAD is rejected.
//
//   - client seal: https://raw.githubusercontent.com/XTLS/Xray-core/main/transport/internet/reality/reality.go
//   - server open: https://raw.githubusercontent.com/XTLS/REALITY/main/tls.go
//
// # Deliberate deviations from Xray
//
//   - Signature algorithms. REALITY's server is a crypto/tls fork that skips
//     signature-scheme negotiation and hard-codes Ed25519 (hs.sigAlg = Ed25519).
//     Stock crypto/tls cannot: it rejects an Ed25519 certificate when the
//     ClientHello's signature_algorithms does not list Ed25519, and uTLS's
//     Chrome presets do not list it. This package therefore appends Ed25519 to
//     the client's signature_algorithms extension before marshalling. A real
//     Xray/REALITY relay ignores signature_algorithms, so the client still
//     interoperates with it; a real Xray client cannot complete a handshake
//     with this relay. See the "## UNCONFIRMED" note in this comment.
//   - The relay terminates TLS locally with the forged certificate instead of
//     splicing dest's real ServerHello flight. See the TODO on the tls.Server
//     call in Handler.Handle.
//
// # UNCONFIRMED
//
//   - Whether an unmodified Xray client (upstream uTLS, unpatched
//     signature_algorithms) can complete a handshake with this relay's Ed25519
//     certificate. The pinned uTLS revision used by Xray-core
//     (v1.8.3-0.20260301010127-aa6edf4b11af) was inspected and its
//     HelloChrome_133 preset also omits Ed25519, which suggests it cannot —
//     but Xray's client may rely on fork behaviour not visible from the preset
//     tables. Treat relay→Xray-client interop as unverified.
//   - Whether REALITY's server-side strictness requiring an X25519MLKEM768
//     key share to be present is load-bearing for camouflage. This package
//     accepts a bare X25519 share as well, which is a superset of what a real
//     relay accepts; authentication still requires the HMAC over the auth
//     block, so the extra tolerance does not weaken it.
package reality

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	"porttransit/internal/logx"
	"porttransit/internal/transport"
	"porttransit/internal/version"
)

// Name is the registry key.
const Name = "reality"

// DefaultPort is the conventional listen port. REALITY must share 443 with a
// real site to be indistinguishable from it, so 443 is the only value that
// gives the camouflage its full value; the installer falls back to 8443 when
// 443 is taken.
const DefaultPort = 443

func init() {
	transport.Register(transport.Factory{
		Name:         Name,
		Description:  "XTLS REALITY: TLS 1.3 camouflaged as a real third-party site, with no certificate authority and no server-side certificate to steal.",
		NativeHeader: false,
		DefaultPort:  DefaultPort,
		Build:        func() (transport.Dialer, transport.Handler) { return Dialer{}, Handler{} },
	})
}

// Settings keys understood by this transport.
const (
	// SettingServerName is the SNI to present (client) and the name the relay
	// fronts. It must be one of the fronted site's real names, because the
	// relay dials that site and the whole disguise rests on the name matching.
	SettingServerName = "serverName"
	// SettingPublicKey is the relay's REALITY X25519 public key, base64. This
	// is how the client learns the relay's static key without any PKI: it is
	// the only secret-free value that lets the client derive AuthKey.
	SettingPublicKey = "publicKey"
	// SettingPrivateKey is the relay's REALITY X25519 private key, base64.
	// Anyone holding it can impersonate the relay, so it never leaves the
	// relay's config.
	SettingPrivateKey = "privateKey"
	// SettingShortID is the hex short id, at most 16 characters, right
	// zero-padded to 8 bytes. Empty is legal and means eight zero bytes; it
	// lets one relay serve several client groups and revoke one by removing
	// its entry.
	SettingShortID = "shortId"
	// SettingShortIDs is the relay-side allow-list of short ids. SettingShortID
	// is equivalent to a one-element list.
	SettingShortIDs = "shortIds"
	// SettingDest is the fronted site the relay dials on every connection,
	// e.g. "www.microsoft.com:443". Dialing it unconditionally is what makes a
	// probe indistinguishable from a real visit.
	SettingDest = "dest"
	// SettingServerNames is the relay-side allow-list of accepted SNI values.
	SettingServerNames = "serverNames"
	// SettingFingerprint selects the uTLS ClientHello profile. Default chrome.
	SettingFingerprint = "fingerprint"
	// SettingInsecure relaxes the relay's certificate check. It defaults to
	// false, which means the REALITY HMAC in the certificate's signature field
	// is required; setting it true accepts a certificate that merely chains to
	// a trusted root, for the rare deployment that fronts a site the client
	// already trusts. It is NOT the usual "skip verification" flag: skipping
	// verification outright would defeat the only authentication REALITY has.
	SettingInsecure = "insecure"
	// SettingPSK authenticates the PortTransit preamble inside the tunnel.
	SettingPSK = "psk"
	// SettingTimeout bounds the handshake.
	SettingTimeout = "timeout"
	// SettingXver selects the PROXY protocol version sent to dest: 0 none,
	// 1 v1 text, 2 v2 binary.
	SettingXver = "xver"
	// SettingMaxTimeDiff bounds the clock skew of the timestamp inside the
	// auth block. Zero selects DefaultMaxTimeDiff; a negative value disables
	// the check.
	SettingMaxTimeDiff = "maxTimeDiff"
	// SettingMinClientVer and SettingMaxClientVer bound the client version
	// range as "x.y.z".
	SettingMinClientVer = "minClientVer"
	SettingMaxClientVer = "maxClientVer"
	// SettingClientVer overrides the version the client reports. It defaults
	// to this build's version.
	SettingClientVer = "clientVer"
)

// Auth block geometry. These are wire-format constants fixed by XTLS REALITY
// and cannot be changed without breaking interoperability.
const (
	// sessionIDLen is the legacy session_id length REALITY requires. TLS 1.3
	// only treats session_id as a compatibility echo, which is exactly why it
	// is a safe place to hide an authenticated block.
	sessionIDLen = 32
	// sessionIDOffset is where session_id starts inside a marshalled
	// ClientHello: type(1) + uint24 length(3) + legacy_version(2) +
	// random(32) = 38 bytes, then the uint8 length prefix at 38.
	sessionIDOffset = 39
	// sessionIDPlainLen is the authenticated plaintext: version(3) + reserved(1)
	// + timestamp(4 BE) + shortId(8).
	sessionIDPlainLen = 16
	// sessionIDTagLen is the AES-GCM tag that fills the rest of the field.
	sessionIDTagLen = 16
	// shortIDLen is the on-wire short id width.
	shortIDLen = 8

	// authBlockReserved is the byte at session_id[3], reserved by REALITY and
	// required to be zero so future versions can extend the block.
	authBlockReserved = 0x00

	// clientVersionLen is the width of the version field in the auth block.
	clientVersionLen = 3
)

// TLS record and handshake framing constants used by the ClientHello peek.
const (
	recordTypeHandshake = 22
	handshakeTypeClient = 1
	recordHeaderLen     = 5
	handshakeHeaderLen  = 4
	// maxTLSRecordLen is the largest TLS record this package will read while
	// looking for a ClientHello. A hostile peer must not be able to make the
	// relay allocate without bound.
	maxTLSRecordLen = 1 << 14
	// maxClientHelloLen bounds the ClientHello we will buffer.
	maxClientHelloLen = 1 << 15
)

// DefaultMaxTimeDiff is the clock skew allowed by default between the client's
// timestamp and the relay's clock. REALITY's own default is 0 ("do not check"),
// which is unsafe for a relay with a wrong clock, so this package prefers an
// explicit default and lets an operator opt out with a negative value.
const DefaultMaxTimeDiff = 60 * time.Second

// hkdfInfo is the HKDF info string. It is a domain separator, not a secret:
// it keeps the REALITY key schedule from colliding with any other use of the
// same X25519 shared secret.
const hkdfInfo = "REALITY"

// ErrFallbackHandled reports that a connection failed REALITY authentication
// and was spliced through to the fronted site instead. It is not a failure:
// the relay did exactly what its camouflage requires. The message contains
// "forwarded to fallback" because internal/server classifies fallbacks by that
// phrase.
var ErrFallbackHandled = fmt.Errorf("reality: connection forwarded to fallback")

// ClientVersion is the version this build reports inside the auth block.
//
// The bytes are only meaningful to a relay that configured minClientVer or
// maxClientVer; a relay that did not check ignores them. Deriving it from the
// build version keeps a PortTransit client honest about itself while remaining
// inside any range an operator would plausibly configure.
func ClientVersion() [clientVersionLen]byte { return versionBytes(version.Version) }

// versionBytes renders a "x.y.z" version string as the three bytes REALITY
// puts at the start of the auth block. Unparsable components become zero.
func versionBytes(s string) [clientVersionLen]byte {
	var out [clientVersionLen]byte
	parts := strings.SplitN(strings.TrimSpace(s), ".", clientVersionLen)
	for i := 0; i < len(parts) && i < clientVersionLen; i++ {
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(parts[i]), "%d", &n); err != nil {
			continue
		}
		if n < 0 {
			n = 0
		}
		if n > 0xff {
			n = 0xff
		}
		out[i] = byte(n)
	}
	return out
}

// versionValue composes the three version bytes into one comparable integer.
// REALITY's Value() does the same big-endian fold, which is why the field is
// ordered most-significant byte first.
func versionValue(v [clientVersionLen]byte) uint32 {
	return uint32(v[0])<<16 | uint32(v[1])<<8 | uint32(v[2])
}

// ParseShortID converts a hex short id to its 8-byte wire form.
//
// Shorter strings are right zero-padded, which is what Xray's config parser
// does: it decodes into an already-zeroed 8-byte buffer. An empty string is
// therefore eight zero bytes and is explicitly legal, because a relay that
// accepts the zero short id is a valid configuration (it simply cannot
// distinguish client groups).
func ParseShortID(s string) ([shortIDLen]byte, error) {
	var out [shortIDLen]byte
	s = strings.TrimSpace(s)
	if s == "" {
		return out, nil
	}
	if len(s) > shortIDLen*2 {
		return out, fmt.Errorf("reality: short id %q is longer than %d hex characters", s, shortIDLen*2)
	}
	if len(s)%2 != 0 {
		return out, fmt.Errorf("reality: short id %q has an odd number of hex characters", s)
	}
	if _, err := hex.Decode(out[:], []byte(s)); err != nil {
		return out, fmt.Errorf("reality: short id %q is not hex: %w", s, err)
	}
	return out, nil
}

// EncodeShortID renders an 8-byte short id as the canonical 16-character hex.
func EncodeShortID(id [shortIDLen]byte) string { return hex.EncodeToString(id[:]) }

// authBlock is the 16-byte plaintext REALITY seals into session_id[0:16].
type authBlock struct {
	// Version is the client version, most significant byte first.
	Version [clientVersionLen]byte
	// Time is the client's clock at the moment the ClientHello was built.
	Time time.Time
	// ShortID selects the client group.
	ShortID [shortIDLen]byte
}

// marshal renders the block in REALITY's wire order. The reserved byte at
// offset 3 is written explicitly rather than left implicit so the layout is
// readable against the specification.
func (a authBlock) marshal() [sessionIDPlainLen]byte {
	var out [sessionIDPlainLen]byte
	out[0], out[1], out[2] = a.Version[0], a.Version[1], a.Version[2]
	out[3] = authBlockReserved
	binary.BigEndian.PutUint32(out[4:8], uint32(a.Time.Unix()))
	copy(out[8:16], a.ShortID[:])
	return out
}

// unmarshalAuthBlock decodes a recovered plaintext block.
func unmarshalAuthBlock(b []byte) (authBlock, error) {
	var a authBlock
	if len(b) < sessionIDPlainLen {
		return a, fmt.Errorf("%w: auth block is %d bytes, want %d", transport.ErrProtocol, len(b), sessionIDPlainLen)
	}
	copy(a.Version[:], b[0:3])
	a.Time = time.Unix(int64(binary.BigEndian.Uint32(b[4:8])), 0)
	copy(a.ShortID[:], b[8:16])
	return a, nil
}

// deriveAuthKey performs the REALITY key schedule.
//
// The X25519 shared secret is fed through HKDF-SHA256 with the *first 20 bytes
// of the ClientHello random* as salt and the literal "REALITY" as info. Salting
// with client-chosen bytes is what binds the key to this specific ClientHello:
// a replayed auth block is useless without the matching random, and an attacker
// cannot precompute AuthKey for a ClientHello it has not seen. The 32-byte
// output is an AES-256-GCM key.
func deriveAuthKey(sharedSecret, clientRandom []byte) ([]byte, error) {
	if len(clientRandom) < 32 {
		return nil, fmt.Errorf("%w: client random is %d bytes, want 32", transport.ErrProtocol, len(clientRandom))
	}
	// Salt is random[:20], not the whole random: REALITY reserves the last 12
	// bytes as the GCM nonce, so the two must not overlap.
	key, err := hkdf.Key(sha256.New, sharedSecret, clientRandom[:20], hkdfInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("reality: derive auth key: %w", err)
	}
	return key, nil
}

// newAuthAEAD builds the AES-256-GCM AEAD over authKey.
func newAuthAEAD(authKey []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, fmt.Errorf("reality: auth cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("reality: auth aead: %w", err)
	}
	return aead, nil
}

// authNonce returns the GCM nonce: the last 12 bytes of the ClientHello
// random. It is derived from the same random that salts HKDF but never
// overlaps it, so the nonce is unpredictable to anyone who cannot already
// reproduce the ClientHello.
func authNonce(clientRandom []byte) []byte { return clientRandom[20:32] }

// sessionRegion returns the [39:71] byte range of a marshalled ClientHello.
func sessionRegion(raw []byte) ([]byte, error) {
	if len(raw) < sessionIDOffset+sessionIDLen {
		return nil, fmt.Errorf("%w: ClientHello is %d bytes, too short for a session id", transport.ErrProtocol, len(raw))
	}
	return raw[sessionIDOffset : sessionIDOffset+sessionIDLen], nil
}

// sealAuthBlock writes the REALITY auth block into raw in place.
//
// raw must be a marshalled ClientHello whose session_id region is already zero
// (uTLS leaves it zeroed while the preset's session id lives in a detached
// slice). The AAD is a copy of raw with that region zeroed, which is why the
// tag can authenticate a buffer that is about to contain the tag itself: the
// authenticated image predates the ciphertext.
func sealAuthBlock(raw []byte, clientRandom []byte, authKey []byte, block authBlock) error {
	region, err := sessionRegion(raw)
	if err != nil {
		return err
	}
	aead, err := newAuthAEAD(authKey)
	if err != nil {
		return err
	}

	// The AAD is raw as it stands: session_id is zeros. Copying rather than
	// aliasing keeps the invariant explicit and makes the intent auditable —
	// the ciphertext we are about to produce must not be part of its own AAD.
	aad := make([]byte, len(raw))
	copy(aad, raw)
	aadRegion, _ := sessionRegion(aad)
	for i := range aadRegion {
		aadRegion[i] = 0
	}

	plain := block.marshal()
	// dst is nil: GCM's exact-overlap allowance is irrelevant here and a
	// detached output makes the AAD/ciphertext separation obvious.
	sealed := aead.Seal(nil, authNonce(clientRandom), plain[:], aad)
	if len(sealed) != sessionIDLen {
		return fmt.Errorf("%w: auth block sealed to %d bytes, want %d", transport.ErrProtocol, len(sealed), sessionIDLen)
	}
	copy(region, sealed)
	return nil
}

// openAuthBlock recovers the auth block from a received ClientHello.
//
// It reconstructs the AAD exactly as XTLS/REALITY does: the received bytes
// with session_id[0:32] zeroed. On the server the parsed session_id aliases
// that region, so REALITY achieves the same thing by overwriting the field
// with zeros before calling Open.
func openAuthBlock(raw []byte, clientRandom []byte, authKey []byte) (authBlock, error) {
	region, err := sessionRegion(raw)
	if err != nil {
		return authBlock{}, err
	}
	aead, err := newAuthAEAD(authKey)
	if err != nil {
		return authBlock{}, err
	}

	aad := make([]byte, len(raw))
	copy(aad, raw)
	aadRegion, _ := sessionRegion(aad)
	for i := range aadRegion {
		aadRegion[i] = 0
	}

	ciphertext := make([]byte, sessionIDLen)
	copy(ciphertext, region)

	plain, err := aead.Open(nil, authNonce(clientRandom), ciphertext, aad)
	if err != nil {
		return authBlock{}, fmt.Errorf("%w: auth block: %w", transport.ErrAuthFailed, err)
	}
	return unmarshalAuthBlock(plain)
}

// temporaryCertificate returns the process-global Ed25519 key pair and the
// DER of a self-signed certificate built from it.
//
// One key pair per process, not per connection, is deliberate: it makes the
// certificate stable for the process lifetime, so a client that connects twice
// sees the same public key, while still rotating on restart so a captured
// certificate is worthless afterwards. The template has no CN and no SAN —
// the certificate is never meant to pass a name check, only to carry the HMAC
// in its signature field.
var (
	temporaryCertOnce sync.Once
	temporaryCertKey  ed25519.PrivateKey
	temporaryCertDER  []byte
	temporaryCertErr  error
)

func temporaryCertificate() (ed25519.PrivateKey, []byte, error) {
	temporaryCertOnce.Do(func() {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			temporaryCertErr = fmt.Errorf("reality: generate certificate key: %w", err)
			return
		}
		// An empty template is exactly what REALITY uses. Adding a CN or SAN
		// would make the certificate look like a deliberate self-signed
		// certificate and would invite a name check that can only fail.
		tmpl := &x509.Certificate{SerialNumber: new(big.Int)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
		if err != nil {
			temporaryCertErr = fmt.Errorf("reality: create certificate: %w", err)
			return
		}
		if len(der) < sha512.Size {
			temporaryCertErr = fmt.Errorf("reality: certificate DER is %d bytes, too short to hold a signature", len(der))
			return
		}
		temporaryCertKey = priv
		temporaryCertDER = der
	})
	if temporaryCertErr != nil {
		return nil, nil, temporaryCertErr
	}
	// Callers must not mutate the cached DER, so hand out a copy.
	der := make([]byte, len(temporaryCertDER))
	copy(der, temporaryCertDER)
	key := make(ed25519.PrivateKey, len(temporaryCertKey))
	copy(key, temporaryCertKey)
	return key, der, nil
}

// forgeCertificate replaces the certificate's signature field with the REALITY
// authenticator.
//
// The Ed25519 public key is the HMAC message and AuthKey is the HMAC key, so
// only a peer that derived AuthKey can tell a forged certificate from a
// genuine one. The signature field is the last element of the DER-encoded
// Certificate sequence and, for Ed25519, is exactly 64 bytes — the size of an
// HMAC-SHA512 output, which is what makes the substitution byte-for-byte
// length-preserving.
func forgeCertificate(authKey []byte) (tls.Certificate, error) {
	priv, der, err := temporaryCertificate()
	if err != nil {
		return tls.Certificate{}, err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return tls.Certificate{}, errors.New("reality: certificate key is not Ed25519")
	}
	mac := hmac.New(sha512.New, authKey)
	mac.Write(pub)
	signature := mac.Sum(nil)
	if len(signature) != sha512.Size {
		return tls.Certificate{}, errors.New("reality: unexpected HMAC length")
	}
	forged := make([]byte, len(der))
	copy(forged, der)
	copy(forged[len(forged)-len(signature):], signature)
	return tls.Certificate{Certificate: [][]byte{forged}, PrivateKey: priv}, nil
}

// verifyForgedCertificate checks that a peer's certificate carries the REALITY
// authenticator for authKey.
//
// A genuine certificate from the fronted site — the outcome of a
// man-in-the-middle, or of a censor redirecting the ClientHello — will not
// match, which is the point: REALITY never trusts a certificate chain, only
// this tag.
func verifyForgedCertificate(cert *x509.Certificate, authKey []byte) bool {
	if cert == nil {
		return false
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return false
	}
	mac := hmac.New(sha512.New, authKey)
	mac.Write(pub)
	return hmac.Equal(mac.Sum(nil), cert.Signature)
}

// decodeKey decodes a base64 REALITY key.
//
// Several encodings are accepted because the installer emits raw URL-safe
// base64 while an operator copying a key out of another tool will often have
// standard base64 with padding; refusing either would produce a confusing
// "authentication failed" rather than a configuration error.
func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("reality: key is empty")
	}
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("reality: key %q is not valid base64", s)
}

// Dialer establishes client→relay REALITY streams.
type Dialer struct{}

// Name returns the registry key.
func (Dialer) Name() string { return Name }

// Dial performs the REALITY handshake and then exchanges the preamble.
func (d Dialer) Dial(ctx context.Context, req transport.DialRequest) (transport.Stream, error) {
	timeout := req.Settings.GetDuration(SettingTimeout, 10*time.Second)
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	host, _, err := transport.SplitHostPort(req.ServerAddr)
	if err != nil {
		return nil, err
	}
	sni := req.ServerName
	if sni == "" {
		sni = req.Settings.GetString(SettingServerName, host)
	}

	publicKey, err := decodeKey(req.Settings.GetString(SettingPublicKey, ""))
	if err != nil {
		return nil, fmt.Errorf("reality: %s: %w", SettingPublicKey, err)
	}
	serverPub, err := ecdh.X25519().NewPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("reality: %s is not an X25519 public key: %w", SettingPublicKey, err)
	}

	shortID, err := ParseShortID(req.Settings.GetString(SettingShortID, ""))
	if err != nil {
		return nil, err
	}

	raw, err := (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", req.ServerAddr)
	if err != nil {
		return nil, err
	}
	if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
		raw.Close()
		return nil, err
	}

	uconn, authKey, err := realityClientHello(raw, req, sni, serverPub, shortID)
	if err != nil {
		raw.Close()
		return nil, err
	}

	if err := uconn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("reality: handshake with %s (sni %s): %w", req.ServerAddr, sni, err)
	}

	// The certificate's HMAC is the only proof that the peer is the relay and
	// not the fronted site. Checking it after the handshake is what detects a
	// redirection or a man-in-the-middle holding a genuine certificate.
	if err := verifyRelayCertificate(uconn, authKey, req.Settings, sni); err != nil {
		raw.Close()
		return nil, err
	}

	if err := uconn.SetDeadline(time.Time{}); err != nil {
		uconn.Close()
		return nil, err
	}

	return transport.PreambleClientHandshake(uconn, req.Request, transport.ClientHandshakeConfig{
		PSK:           transport.DecodePSK(req.Settings.GetString(SettingPSK, "")),
		ClientID:      clientIDFrom(req),
		TransportName: Name,
		Timeout:       timeout,
		Logger:        loggerFor(req.Logger),
	})
}

// realityClientHello builds the uTLS ClientHello and installs the REALITY auth
// block into it, returning the connection and the derived AuthKey.
//
// Everything here happens between BuildHandshakeState and the handshake
// itself: the auth block has to be in place before the first flight leaves,
// and AuthKey has to be known before the certificate can be checked.
func realityClientHello(raw net.Conn, req transport.DialRequest, sni string, serverPub *ecdh.PublicKey, shortID [shortIDLen]byte) (*utls.UConn, []byte, error) {
	fingerprint, err := clientHelloID(req.Settings.GetString(SettingFingerprint, "chrome"))
	if err != nil {
		return nil, nil, err
	}

	cfg := &utls.Config{
		ServerName: sni,
		// The certificate chain can never verify: it is a fresh self-signed
		// certificate with no CN and no SAN. Authenticity comes from the HMAC
		// in its signature field instead, so verification is delegated to
		// verifyRelayCertificate rather than to a root store.
		InsecureSkipVerify: true,
		// REALITY's auth block is bound to one ClientHello, so a resumed
		// session would carry a stale block and a stale key.
		SessionTicketsDisabled: true,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
	}

	uconn := utls.UClient(raw, cfg, fingerprint)
	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, nil, fmt.Errorf("reality: build ClientHello: %w", err)
	}

	hello := uconn.HandshakeState.Hello
	// The preset must have produced a 32-byte session id, otherwise rewriting
	// the field would change the ClientHello length and every offset after it.
	// Fail loudly rather than silently corrupting the fingerprint.
	if _, err := sessionRegion(hello.Raw); err != nil {
		return nil, nil, err
	}
	if hello.Raw[sessionIDOffset-1] != sessionIDLen {
		return nil, nil, fmt.Errorf("%w: fingerprint %s produced a %d-byte session id, REALITY needs %d",
			transport.ErrProtocol, fingerprint.Client, hello.Raw[sessionIDOffset-1], sessionIDLen)
	}

	// Append Ed25519 to signature_algorithms. See the package comment: stock
	// crypto/tls refuses to send an Ed25519 certificate to a peer that did not
	// advertise Ed25519, and uTLS's browser presets do not advertise it. A real
	// REALITY relay ignores this list, so adding the entry costs nothing there.
	//
	// This re-marshals, so it must happen before the auth block is sealed:
	// sealing writes into hello.Raw, and a later re-marshal would overwrite it.
	if err := advertiseEd25519(uconn); err != nil {
		return nil, nil, err
	}
	hello = uconn.HandshakeState.Hello
	region, err := sessionRegion(hello.Raw)
	if err != nil {
		return nil, nil, err
	}

	// Zero the session id region and detach the field, exactly as Xray does:
	//
	//	hello.SessionId = make([]byte, 32)
	//	copy(hello.Raw[39:], hello.SessionId)
	//
	// This is the step that resolves the AAD circularity. uTLS's preset fills
	// session_id with random bytes, so it must be cleared; and because
	// hello.SessionId is a separate slice from hello.Raw, the plaintext we are
	// about to seal lives outside the AAD while the AAD still carries zeros
	// where the ciphertext will go.
	for i := range region {
		region[i] = 0
	}
	hello.SessionId = make([]byte, sessionIDLen)

	ephemeral := uconn.HandshakeState.State13.KeyShareKeys
	if ephemeral == nil {
		return nil, nil, fmt.Errorf("%w: fingerprint %s produced no TLS 1.3 key share", transport.ErrProtocol, fingerprint.Client)
	}
	// REALITY reuses the TLS 1.3 key_share ephemeral key rather than
	// generating its own: one key exchange serves both TLS and REALITY, and
	// the ClientHello carries no extra field that a fingerprinter could spot.
	ecdhe := ephemeral.Ecdhe
	if ecdhe == nil {
		// A hybrid-only fingerprint (X25519MLKEM768) still embeds a plain
		// X25519 key; REALITY's server reads the hybrid share's tail 32 bytes,
		// which is the same key.
		ecdhe = ephemeral.MlkemEcdhe
	}
	if ecdhe == nil {
		return nil, nil, fmt.Errorf("reality: fingerprint %s offers no X25519 key share, so REALITY cannot authenticate; use a TLS 1.3 fingerprint such as chrome",
			fingerprint.Client)
	}

	sharedSecret, err := ecdhe.ECDH(serverPub)
	if err != nil {
		return nil, nil, fmt.Errorf("reality: X25519: %w", err)
	}
	authKey, err := deriveAuthKey(sharedSecret, hello.Random)
	if err != nil {
		return nil, nil, err
	}

	clientVer := ClientVersion()
	if v := req.Settings.GetString(SettingClientVer, ""); v != "" {
		clientVer = versionBytes(v)
	}
	block := authBlock{Version: clientVer, Time: time.Now(), ShortID: shortID}
	if err := sealAuthBlock(hello.Raw, hello.Random, authKey, block); err != nil {
		return nil, nil, err
	}
	// Keep the detached field in step with the marshalled bytes. uTLS reuses
	// hello.Raw verbatim when it writes the ClientHello, so this is for
	// consistency rather than for the wire.
	copy(hello.SessionId, region)

	return uconn, authKey, nil
}

// advertiseEd25519 appends Ed25519 to the ClientHello's signature_algorithms
// and re-marshals.
//
// The re-marshal is safe because the extension list is unchanged in shape: one
// two-byte algorithm code is appended, and uTLS recomputes the lengths. The
// result is what uTLS will actually put on the wire, because writeHandshakeRecord
// reuses hello.Raw verbatim once it is set.
func advertiseEd25519(uconn *utls.UConn) error {
	for _, ext := range uconn.Extensions {
		sa, ok := ext.(*utls.SignatureAlgorithmsExtension)
		if !ok {
			continue
		}
		for _, alg := range sa.SupportedSignatureAlgorithms {
			if alg == utls.Ed25519 {
				return nil
			}
		}
		sa.SupportedSignatureAlgorithms = append(sa.SupportedSignatureAlgorithms, utls.Ed25519)
		if err := uconn.MarshalClientHelloNoECH(); err != nil {
			return fmt.Errorf("reality: re-marshal ClientHello: %w", err)
		}
		return nil
	}
	return fmt.Errorf("%w: fingerprint has no signature_algorithms extension", transport.ErrProtocol)
}

// verifyRelayCertificate enforces the REALITY certificate authenticator.
//
// With the default settings this is strict: only a certificate carrying the
// HMAC for this session's AuthKey is accepted. When SettingInsecure is set, a
// certificate that chains to a trusted root is accepted as a fallback, which
// is the only case where a genuine CA-issued certificate is the intended
// outcome rather than evidence of interception.
func verifyRelayCertificate(uconn *utls.UConn, authKey []byte, settings transport.Settings, sni string) error {
	state := uconn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("%w: relay sent no certificate", transport.ErrAuthFailed)
	}
	if verifyForgedCertificate(state.PeerCertificates[0], authKey) {
		return nil
	}
	if settings.GetBool(SettingInsecure, false) {
		// An operator who explicitly opted in accepts a real chain instead of
		// the HMAC. Verify it against the system roots and the configured SNI,
		// so this is a deliberate downgrade rather than no check at all.
		if _, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: sni}); err != nil {
			return fmt.Errorf("%w: relay certificate is neither REALITY nor a trusted chain: %w", transport.ErrAuthFailed, err)
		}
		return nil
	}
	// The peer presented a certificate we cannot authenticate. Either it is the
	// fronted site (the relay rejected us, or something redirected the
	// ClientHello) or it is an interceptor. Xray's client switches to "spider"
	// mode here to look like a browser; this build refuses instead, because
	// silently downgrading would hide a real attack.
	return fmt.Errorf("%w: relay certificate is not a REALITY certificate (fronted site or interception)", transport.ErrAuthFailed)
}

// clientHelloID maps a profile name to a uTLS ClientHelloID.
//
// The versions are pinned for the same reason the tls transport pins them:
// uTLS's "latest" aliases move with each release, which would silently change
// the wire fingerprint of an already-deployed client.
func clientHelloID(name string) (utls.ClientHelloID, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "chrome", "":
		return utls.HelloChrome_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "edge":
		return utls.HelloEdge_Auto, nil
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil
	case "random", "randomized":
		return utls.HelloRandomizedALPN, nil
	case "golang":
		return utls.HelloGolang, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("reality: unknown fingerprint profile %q", name)
	}
}

// Handler accepts relay-side REALITY streams.
type Handler struct{}

// Name returns the registry key.
func (Handler) Name() string { return Name }

// Handle performs the relay side of the REALITY handshake.
//
// The order matters and mirrors XTLS REALITY: dial the fronted site first,
// unconditionally, before looking at the client at all. A prober that
// completes a TCP connection and then does nothing, or sends garbage, still
// causes an outbound connection to dest — so the relay's behaviour is
// indistinguishable from a plain port-forward to that site.
func (h Handler) Handle(ctx context.Context, raw net.Conn, req transport.HandleRequest) (transport.Stream, error) {
	timeout := req.Settings.GetDuration(SettingTimeout, 10*time.Second)
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	dest := req.Settings.GetString(SettingDest, "")
	if dest == "" {
		// Without a fronted site the relay has nothing to look like, and the
		// fallback path has nowhere to send a prober. Refusing to start is
		// better than a relay that silently drops probes.
		raw.Close()
		return nil, fmt.Errorf("reality: %s is required", SettingDest)
	}

	upstream, err := h.dialDest(ctx, raw, dest, req)
	if err != nil {
		raw.Close()
		return nil, err
	}

	if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
		upstream.Close()
		raw.Close()
		return nil, err
	}

	// Read the ClientHello ourselves before any TLS state exists, because the
	// auth block inside it decides whether there will be a TLS session at all.
	hello, replay, err := readClientHello(raw)
	if err != nil {
		loggerFor(req.Logger).Debug("reality: ClientHello read failed", "remote", transport.RemoteAddrString(raw), "err", err)
		return h.fallback(raw, upstream, replay)
	}

	authKey, err := authenticateClient(hello, req.Settings)
	if err != nil {
		loggerFor(req.Logger).Debug("reality: authentication failed", "remote", transport.RemoteAddrString(raw), "err", err)
		return h.fallback(raw, upstream, replay)
	}

	cert, err := forgeCertificate(authKey)
	if err != nil {
		upstream.Close()
		raw.Close()
		return nil, err
	}

	// Replay every consumed byte, record headers included, so crypto/tls sees
	// an untouched stream.
	//
	// TODO: relay dest's real ServerHello flight instead of terminating TLS
	// here. A PortTransit client cannot tell the difference — it authenticates
	// the certificate's HMAC and never consults the chain — but a prober that
	// completes a TLS handshake receives an empty self-signed certificate
	// rather than the fronted site's real one, which is a weaker disguise than
	// REALITY's. Doing it properly also requires mirroring dest's
	// post-handshake record lengths, which needs a per-dest cache (Xray keeps
	// it in GlobalPostHandshakeRecordsLens, keyed by dest + SNI + ALPN).
	conn := &prefixConn{Conn: raw, prefix: replay}

	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		// ALPN must stay nil, exactly as Xray configures it: the fronted site
		// is not ours, so the relay must not claim to speak any protocol the
		// client might then use.
		NextProtos:             nil,
		SessionTicketsDisabled: true,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		upstream.Close()
		raw.Close()
		loggerFor(req.Logger).Debug("reality: TLS handshake failed", "remote", transport.RemoteAddrString(raw), "err", err)
		return nil, err
	}

	// Authentication succeeded, so the camouflage has done its job. The
	// connection to dest is no longer needed; leaving it open would leak a
	// connection per session to the fronted site.
	upstream.Close()

	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		tlsConn.Close()
		return nil, err
	}

	return transport.PreambleServerHandshake(tlsConn, transport.ServerHandshakeConfig{
		PSK:             transport.DecodePSK(req.Settings.GetString(SettingPSK, "")),
		Replay:          replayGuard(req.Settings),
		Timeout:         timeout,
		Logger:          loggerFor(req.Logger),
		RequireClientID: req.Settings.GetBool("requireClientID", false),
		AllowedClients:  req.Settings.GetStringSlice("allowedClients"),
		AllowPing:       req.Settings.GetBool("allowPing", true),
		TransportName:   Name,
	})
}

// dialDest connects to the fronted site and optionally prefixes the connection
// with a PROXY protocol header.
func (h Handler) dialDest(ctx context.Context, raw net.Conn, dest string, req transport.HandleRequest) (net.Conn, error) {
	timeout := req.Settings.GetDuration(SettingTimeout, 10*time.Second)
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	upstream, err := (&net.Dialer{Timeout: timeout}).DialContext(dialCtx, "tcp", dest)
	if err != nil {
		loggerFor(req.Logger).Debug("reality: dial dest failed", "dest", dest, "err", err)
		return nil, fmt.Errorf("reality: dial %s: %w", dest, err)
	}

	switch req.Settings.GetInt(SettingXver, 0) {
	case 1, 2:
		// PROXY protocol tells the fronted site the real client address. It is
		// only correct when dest is a server the operator also controls; on a
		// third-party site it is an anomaly, which is why 0 is the default.
		ver := req.Settings.GetInt(SettingXver, 0)
		if err := writeProxyHeader(upstream, raw, byte(ver)); err != nil {
			upstream.Close()
			return nil, fmt.Errorf("reality: PROXY protocol: %w", err)
		}
	}
	return upstream, nil
}

// fallback splices the client straight through to the fronted site.
//
// This is REALITY's "steal oneself" behaviour and the reason a failed
// authentication is not an error: a prober must be handed a real conversation
// with the fronted site, not a dropped connection. prelude holds the bytes
// already read from the client so they can be replayed to dest first.
func (h Handler) fallback(raw, upstream net.Conn, prelude []byte) (transport.Stream, error) {
	conn := &prefixConn{Conn: raw, prefix: prelude}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		upstream.Close()
		raw.Close()
		return nil, err
	}
	transport.CopyBidirectional(conn, upstream)
	return nil, ErrFallbackHandled
}

// authenticateClient validates a received ClientHello and returns the derived
// AuthKey.
//
// Every check is a reason to fall back rather than to fail loudly: a prober
// that gets a different answer for a bad SNI than for a bad short id learns
// something about the relay's configuration, so all rejections look identical
// from outside.
func authenticateClient(hello []byte, settings transport.Settings) ([]byte, error) {
	parsed := utls.UnmarshalClientHello(hello)
	if parsed == nil {
		return nil, fmt.Errorf("%w: ClientHello did not parse", transport.ErrProtocol)
	}

	// TLS 1.3 is required. The auth block lives in a field TLS 1.3 treats as a
	// compatibility echo; a 1.2 server would use it for resumption state.
	if !supportsTLS13(parsed) {
		return nil, fmt.Errorf("%w: client does not offer TLS 1.3", transport.ErrProtocol)
	}

	names := settings.GetStringSlice(SettingServerNames)
	if len(names) > 0 && !containsString(names, parsed.ServerName) {
		return nil, fmt.Errorf("%w: SNI %q is not accepted", transport.ErrAuthFailed, parsed.ServerName)
	}

	privKey, err := decodeKey(settings.GetString(SettingPrivateKey, ""))
	if err != nil {
		return nil, fmt.Errorf("reality: %s: %w", SettingPrivateKey, err)
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("reality: %s is not an X25519 private key: %w", SettingPrivateKey, err)
	}

	peerPub, err := peerX25519(parsed)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := privateKey.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("reality: X25519: %w", err)
	}
	authKey, err := deriveAuthKey(sharedSecret, parsed.Random)
	if err != nil {
		return nil, err
	}

	block, err := openAuthBlock(hello, parsed.Random, authKey)
	if err != nil {
		return nil, err
	}
	if err := checkAuthBlock(block, settings); err != nil {
		return nil, err
	}
	return authKey, nil
}

// checkAuthBlock enforces the post-decryption acceptance gate: version range,
// timestamp freshness and short id membership.
func checkAuthBlock(block authBlock, settings transport.Settings) error {
	if min := settings.GetString(SettingMinClientVer, ""); min != "" {
		if versionValue(block.Version) < versionValue(versionBytes(min)) {
			return fmt.Errorf("%w: client version %d.%d.%d is below the minimum",
				transport.ErrAuthFailed, block.Version[0], block.Version[1], block.Version[2])
		}
	}
	if max := settings.GetString(SettingMaxClientVer, ""); max != "" {
		if versionValue(block.Version) > versionValue(versionBytes(max)) {
			return fmt.Errorf("%w: client version %d.%d.%d is above the maximum",
				transport.ErrAuthFailed, block.Version[0], block.Version[1], block.Version[2])
		}
	}

	maxDiff := settings.GetDuration(SettingMaxTimeDiff, DefaultMaxTimeDiff)
	if maxDiff < 0 {
		// An operator who cannot guarantee NTP may disable the check. It is
		// the only defence against replaying a captured auth block, so the
		// negative value has to be explicit.
		maxDiff = 0
	} else if maxDiff == 0 {
		maxDiff = DefaultMaxTimeDiff
	}
	if maxDiff > 0 {
		skew := time.Since(block.Time)
		if skew < 0 {
			skew = -skew
		}
		if skew > maxDiff {
			return fmt.Errorf("%w: auth block is %s old, limit is %s", transport.ErrAuthFailed, skew, maxDiff)
		}
	}

	accepted, err := acceptedShortIDs(settings)
	if err != nil {
		return err
	}
	if len(accepted) == 0 {
		// No short ids configured means the relay cannot distinguish client
		// groups. Accepting only the zero short id keeps the behaviour
		// predictable instead of silently trusting any value.
		accepted = [][shortIDLen]byte{{}}
	}
	for _, id := range accepted {
		if id == block.ShortID {
			return nil
		}
	}
	return fmt.Errorf("%w: short id %s is not accepted", transport.ErrAuthFailed, EncodeShortID(block.ShortID))
}

// acceptedShortIDs collects the relay's configured short ids.
func acceptedShortIDs(settings transport.Settings) ([][shortIDLen]byte, error) {
	var out [][shortIDLen]byte
	for _, s := range settings.GetStringSlice(SettingShortIDs) {
		id, err := ParseShortID(s)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	if single := settings.GetString(SettingShortID, ""); single != "" {
		id, err := ParseShortID(single)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

// supportsTLS13 reports whether the ClientHello advertises TLS 1.3.
func supportsTLS13(hello *utls.PubClientHelloMsg) bool {
	for _, v := range hello.SupportedVersions {
		if v == tls.VersionTLS13 {
			return true
		}
	}
	return false
}

// peerX25519 extracts the client's ephemeral X25519 public key.
//
// REALITY reuses the TLS 1.3 key_share ephemeral key, so there is nothing
// extra to parse: the plain X25519 share is preferred, and a hybrid
// X25519MLKEM768 share is accepted by taking its trailing 32 bytes, which is
// the X25519 half. That tail is the same key uTLS exposes as MlkemEcdhe on the
// client, so both sides agree.
func peerX25519(hello *utls.PubClientHelloMsg) (*ecdh.PublicKey, error) {
	const x25519Len = 32
	for _, ks := range hello.KeyShares {
		if ks.Group == utls.X25519 && len(ks.Data) == x25519Len {
			return ecdh.X25519().NewPublicKey(ks.Data)
		}
	}
	for _, ks := range hello.KeyShares {
		if ks.Group == utls.X25519MLKEM768 && len(ks.Data) > x25519Len {
			// The hybrid share is mlkemEncapsulationKey || x25519PublicKey.
			if pub, err := ecdh.X25519().NewPublicKey(ks.Data[len(ks.Data)-x25519Len:]); err == nil {
				return pub, nil
			}
		}
	}
	return nil, fmt.Errorf("%w: client sent no X25519 key share", transport.ErrAuthFailed)
}

// readClientHello reads TLS records until a complete ClientHello is available.
//
// It returns two things because both outcomes of the caller's decision need
// different views of the same bytes:
//
//   - hello is the handshake message alone, which is what the auth block is
//     sealed over and what the AAD must be reconstructed from.
//   - replay is every byte consumed from r, record headers included. It is
//     what prefixConn must serve so that whoever consumes the connection next
//     — the TLS server on the authenticated path, or the fronted site on the
//     fallback path — sees a byte-for-byte intact stream.
//
// On error, replay still carries whatever was consumed, so a prober that sent
// a truncated or malformed handshake has its bytes forwarded rather than
// silently swallowed.
func readClientHello(r io.Reader) (hello, replay []byte, err error) {
	var payload []byte
	var consumed []byte
	for {
		var header [recordHeaderLen]byte
		head, err := io.ReadFull(r, header[:])
		consumed = append(consumed, header[:head]...)
		if err != nil {
			return nil, consumed, fmt.Errorf("reality: read record header: %w", err)
		}
		if header[0] != recordTypeHandshake {
			return nil, consumed, fmt.Errorf("%w: first record is type %d, not a handshake", transport.ErrProtocol, header[0])
		}
		n := int(header[3])<<8 | int(header[4])
		if n <= 0 || n > maxTLSRecordLen {
			return nil, consumed, fmt.Errorf("%w: record length %d out of range", transport.ErrProtocol, n)
		}
		// Read the body incrementally rather than with io.ReadFull so that a
		// truncated record still contributes its partial bytes to replay. A
		// prober that sends half a ClientHello and stops must have those bytes
		// forwarded to dest, not swallowed.
		body := make([]byte, 0, n)
		buf := make([]byte, n)
		for len(body) < n {
			read, err := r.Read(buf[:n-len(body)])
			if read > 0 {
				body = append(body, buf[:read]...)
				consumed = append(consumed, buf[:read]...)
			}
			if err != nil {
				return nil, consumed, fmt.Errorf("reality: read record body: %w", err)
			}
		}
		payload = append(payload, body...)

		if len(payload) < handshakeHeaderLen {
			continue
		}
		if payload[0] != handshakeTypeClient {
			return nil, consumed, fmt.Errorf("%w: handshake type %d is not a ClientHello", transport.ErrProtocol, payload[0])
		}
		msgLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
		if msgLen > maxClientHelloLen {
			return nil, consumed, fmt.Errorf("%w: ClientHello length %d out of range", transport.ErrProtocol, msgLen)
		}
		if total := handshakeHeaderLen + msgLen; len(payload) >= total {
			return payload[:total], consumed, nil
		}
	}
}

// prefixConn replays buffered bytes before reading from the underlying
// connection.
//
// It exists because the relay must inspect the ClientHello before deciding
// whether to authenticate or fall back, yet both outcomes need a stream that
// still begins with those bytes.
type prefixConn struct {
	net.Conn
	prefix []byte
}

// Read serves the replay buffer first, then delegates.
func (c *prefixConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

// CloseWrite forwards a half-close when the underlying connection supports it,
// so the fallback splice produces a clean EOF instead of a reset.
func (c *prefixConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// writeProxyHeader emits a PROXY protocol header to the fronted site.
//
// Implemented locally rather than by importing go-proxyproto because the
// module graph is fixed: adding a dependency for two small encodings would
// widen the supply-chain surface of a relay whose entire value is that it can
// be trusted.
func writeProxyHeader(w io.Writer, client net.Conn, version byte) error {
	src, ok := client.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("reality: client address %T is not TCP", client.RemoteAddr())
	}
	dst, ok := client.LocalAddr().(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("reality: local address %T is not TCP", client.LocalAddr())
	}

	switch version {
	case 1:
		family := "TCP4"
		if src.IP.To4() == nil {
			family = "TCP6"
		}
		_, err := fmt.Fprintf(w, "PROXY %s %s %s %d %d\r\n",
			family, src.IP.String(), dst.IP.String(), src.Port, dst.Port)
		return err
	case 2:
		// v2 signature is fixed by the specification; the version/command
		// byte 0x21 is "version 2, PROXY command".
		header := []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21}
		srcIP, dstIP := src.IP.To4(), dst.IP.To4()
		if srcIP != nil && dstIP != nil {
			header = append(header, 0x11, 0x00, 0x0c) // TCP over IPv4, 12 bytes
			header = append(header, srcIP...)
			header = append(header, dstIP...)
		} else {
			header = append(header, 0x21, 0x00, 0x24) // TCP over IPv6, 36 bytes
			header = append(header, src.IP.To16()...)
			header = append(header, dst.IP.To16()...)
		}
		header = binary.BigEndian.AppendUint16(header, uint16(src.Port))
		header = binary.BigEndian.AppendUint16(header, uint16(dst.Port))
		_, err := w.Write(header)
		return err
	default:
		return fmt.Errorf("reality: xver %d is not 1 or 2", version)
	}
}

func replayGuard(s transport.Settings) *transport.ReplayGuard {
	if s.GetBool("disableReplayGuard", false) {
		return nil
	}
	return transport.NewReplayGuard(s.GetInt("replayCacheSize", 65536), 0)
}

func clientIDFrom(req transport.DialRequest) string {
	if req.Request != nil && req.Request.ClientID != "" {
		return req.Request.ClientID
	}
	return req.Settings.GetString("clientID", "")
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// nopLogger absorbs diagnostics when the caller configured no logger.
//
// Returning a no-op rather than nil is deliberate: every logging call site in
// this package would otherwise panic on a nil interface, and the fallback path
// — the one that runs for every probe — is exactly where a relay without
// logging configured would hit it.
type nopLogger struct{}

func (nopLogger) Debug(string, ...any) {}
func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Warn(string, ...any)  {}
func (nopLogger) Error(string, ...any) {}

func loggerFor(l *logx.Logger) transport.Logger {
	if l == nil {
		return nopLogger{}
	}
	return l
}
