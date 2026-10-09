package reality

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"porttransit/internal/transport"
)

func TestParseShortID(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    [8]byte
		wantErr bool
	}{
		{name: "empty is eight zero bytes", in: "", want: [8]byte{}},
		{name: "one byte", in: "ab", want: [8]byte{0xab}},
		{
			name: "seven bytes right zero padded",
			in:   "01020304050607",
			want: [8]byte{1, 2, 3, 4, 5, 6, 7, 0},
		},
		{
			name: "full sixteen characters",
			in:   "0123456789abcdef",
			want: [8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
		},
		{name: "uppercase hex", in: "ABCDEF", want: [8]byte{0xab, 0xcd, 0xef, 0, 0, 0, 0, 0}},
		{name: "surrounding whitespace", in: "  abcd  ", want: [8]byte{0xab, 0xcd}},
		{name: "too long", in: "0123456789abcdef00", wantErr: true},
		{name: "odd length", in: "abc", wantErr: true},
		{name: "not hex", in: "zz", wantErr: true},
		{name: "not hex mixed", in: "12g4", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseShortID(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseShortID(%q) = %v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseShortID(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseShortID(%q) = %x, want %x", tc.in, got, tc.want)
			}
			// The wire form must always be exactly 8 bytes, because the auth
			// block reserves a fixed 8-byte slot for it.
			if EncodeShortID(got) != encodePadded(tc.want) {
				t.Fatalf("EncodeShortID round-trip mismatch for %q", tc.in)
			}
		})
	}
}

func encodePadded(id [8]byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, 16)
	for _, b := range id {
		out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
	}
	return string(out)
}

// syntheticClientHello builds a marshalled ClientHello skeleton: the 38-byte
// prefix (type, uint24 length, legacy_version, random) followed by a 32-byte
// session id and a tail, so offsets match a real one.
func syntheticClientHello(random []byte) []byte {
	raw := make([]byte, sessionIDOffset+sessionIDLen+64)
	raw[0] = handshakeTypeClient
	raw[1], raw[2], raw[3] = 0x00, 0x01, 0x2c
	raw[4], raw[5] = 0x03, 0x03
	copy(raw[6:38], random)
	raw[sessionIDOffset-1] = sessionIDLen
	// The session id region stays zero, as uTLS leaves it before sealing.
	for i := sessionIDOffset + sessionIDLen; i < len(raw); i++ {
		raw[i] = byte(i)
	}
	return raw
}

func fixedAuthKey(t *testing.T) []byte {
	t.Helper()
	key, err := deriveAuthKey(bytes.Repeat([]byte{0x5a}, 32), bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestSealOpenAuthBlockRoundTrip(t *testing.T) {
	authKey := fixedAuthKey(t)
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(0x40 + i)
	}
	shortID, err := ParseShortID("deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	want := authBlock{
		Version: [3]byte{1, 8, 2},
		Time:    time.Unix(1700000000, 0),
		ShortID: shortID,
	}

	raw := syntheticClientHello(random)
	if err := sealAuthBlock(raw, random, authKey, want); err != nil {
		t.Fatalf("sealAuthBlock: %v", err)
	}

	// The sealed region must be exactly 32 bytes and must not be all zeros,
	// which is what a relay checks before it bothers deriving a key.
	region, err := sessionRegion(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(region) != sessionIDLen {
		t.Fatalf("session id region is %d bytes, want %d", len(region), sessionIDLen)
	}
	if bytes.Equal(region, make([]byte, sessionIDLen)) {
		t.Fatal("sealed session id is all zeros")
	}

	got, err := openAuthBlock(raw, random, authKey)
	if err != nil {
		t.Fatalf("openAuthBlock: %v", err)
	}
	if got.Version != want.Version {
		t.Errorf("version = %v, want %v", got.Version, want.Version)
	}
	if !got.Time.Equal(want.Time) {
		t.Errorf("time = %v, want %v", got.Time, want.Time)
	}
	if got.ShortID != want.ShortID {
		t.Errorf("shortId = %x, want %x", got.ShortID, want.ShortID)
	}
}

// TestSealOpenIgnoresPreExistingSessionIDBytes proves the AAD is built from the
// zeroed session_id region rather than from whatever happened to be in raw.
// This is the property that makes the seal non-circular: the authenticated
// image cannot contain the ciphertext it authenticates.
func TestSealOpenIgnoresPreExistingSessionIDBytes(t *testing.T) {
	authKey := fixedAuthKey(t)
	random := bytes.Repeat([]byte{0x77}, 32)
	block := authBlock{Version: [3]byte{2, 0, 0}, Time: time.Unix(1700000001, 0)}

	clean := syntheticClientHello(random)
	if err := sealAuthBlock(clean, random, authKey, block); err != nil {
		t.Fatal(err)
	}

	// Same ClientHello, but the session_id region is pre-filled with garbage.
	dirty := syntheticClientHello(random)
	for i := sessionIDOffset; i < sessionIDOffset+sessionIDLen; i++ {
		dirty[i] = 0xff
	}
	if err := sealAuthBlock(dirty, random, authKey, block); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(clean, dirty) {
		t.Fatal("sealing must be independent of the pre-existing session_id bytes")
	}
}

func TestOpenAuthBlockRejectsTampering(t *testing.T) {
	authKey := fixedAuthKey(t)
	random := bytes.Repeat([]byte{0x33}, 32)
	block := authBlock{Version: [3]byte{1, 0, 0}, Time: time.Unix(1700000000, 0)}

	tests := []struct {
		name   string
		mutate func(raw []byte)
	}{
		{
			name: "flip a byte in the tail of the ClientHello",
			mutate: func(raw []byte) {
				raw[len(raw)-1] ^= 0x01
			},
		},
		{
			name: "flip a byte in the session id ciphertext",
			mutate: func(raw []byte) {
				raw[sessionIDOffset] ^= 0x01
			},
		},
		{
			name: "flip a byte in the session id tag",
			mutate: func(raw []byte) {
				raw[sessionIDOffset+sessionIDLen-1] ^= 0x01
			},
		},
		{
			name: "flip a byte in the random, which salts the key and nonce",
			mutate: func(raw []byte) {
				raw[6] ^= 0x01
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := syntheticClientHello(random)
			if err := sealAuthBlock(raw, random, authKey, block); err != nil {
				t.Fatal(err)
			}
			tc.mutate(raw)
			if _, err := openAuthBlock(raw, random, authKey); err == nil {
				t.Fatal("openAuthBlock accepted a tampered ClientHello")
			} else if !errors.Is(err, transport.ErrAuthFailed) {
				t.Fatalf("error = %v, want ErrAuthFailed", err)
			}
		})
	}
}

func TestOpenAuthBlockRejectsWrongKey(t *testing.T) {
	random := bytes.Repeat([]byte{0x22}, 32)
	block := authBlock{Version: [3]byte{1, 0, 0}, Time: time.Unix(1700000000, 0)}

	raw := syntheticClientHello(random)
	if err := sealAuthBlock(raw, random, fixedAuthKey(t), block); err != nil {
		t.Fatal(err)
	}

	other, err := deriveAuthKey(bytes.Repeat([]byte{0x5b}, 32), random)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openAuthBlock(raw, random, other); err == nil {
		t.Fatal("openAuthBlock accepted a ClientHello sealed under a different key")
	}
}

func TestDeriveAuthKeyIsDeterministicAnd32Bytes(t *testing.T) {
	shared := bytes.Repeat([]byte{0x01}, 32)
	random := bytes.Repeat([]byte{0x02}, 32)

	first, err := deriveAuthKey(shared, random)
	if err != nil {
		t.Fatal(err)
	}
	second, err := deriveAuthKey(shared, random)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 32 {
		t.Fatalf("AuthKey is %d bytes, want 32 (AES-256-GCM)", len(first))
	}
	if !bytes.Equal(first, second) {
		t.Fatal("deriveAuthKey is not deterministic for fixed inputs")
	}

	// The salt is random[:20] only, so a difference confined to the last 12
	// bytes (which REALITY uses as the GCM nonce) must not change the key.
	randomTailChanged := bytes.Clone(random)
	randomTailChanged[20] ^= 0xff
	sameKey, err := deriveAuthKey(shared, randomTailChanged)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, sameKey) {
		t.Fatal("AuthKey must not depend on the nonce half of the random")
	}

	// The salt half must change it.
	randomHeadChanged := bytes.Clone(random)
	randomHeadChanged[0] ^= 0xff
	differentKey, err := deriveAuthKey(shared, randomHeadChanged)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, differentKey) {
		t.Fatal("AuthKey must depend on random[:20]")
	}
}

func TestDeriveAuthKeyRejectsShortRandom(t *testing.T) {
	if _, err := deriveAuthKey(bytes.Repeat([]byte{1}, 32), make([]byte, 31)); err == nil {
		t.Fatal("deriveAuthKey accepted a 31-byte client random")
	}
}

func TestVersionBytes(t *testing.T) {
	tests := []struct {
		in   string
		want [3]byte
	}{
		{in: "1.8.2", want: [3]byte{1, 8, 2}},
		{in: "25.1.30", want: [3]byte{25, 1, 30}},
		{in: "1.8", want: [3]byte{1, 8, 0}},
		{in: "1", want: [3]byte{1, 0, 0}},
		{in: "", want: [3]byte{0, 0, 0}},
		{in: "dev", want: [3]byte{0, 0, 0}},
		{in: "1.8.2-rc1", want: [3]byte{1, 8, 2}},
	}
	for _, tc := range tests {
		if got := versionBytes(tc.in); got != tc.want {
			t.Errorf("versionBytes(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}

	// versionValue folds most-significant byte first, matching REALITY's
	// Value() helper, which is what makes range comparisons work.
	if versionValue([3]byte{1, 8, 2}) <= versionValue([3]byte{1, 7, 255}) {
		t.Fatal("versionValue must order 1.8.2 above 1.7.255")
	}
}

func TestForgedCertificateRoundTrip(t *testing.T) {
	authKey := fixedAuthKey(t)

	cert, err := forgeCertificate(authKey)
	if err != nil {
		t.Fatalf("forgeCertificate: %v", err)
	}
	parsed, err := parseLeaf(cert)
	if err != nil {
		t.Fatal(err)
	}

	// REALITY's temporary certificate carries no identity at all: it is never
	// meant to pass a name check, only to carry the HMAC.
	if parsed.Subject.CommonName != "" {
		t.Errorf("certificate has CN %q, want empty", parsed.Subject.CommonName)
	}
	if len(parsed.DNSNames) != 0 || len(parsed.IPAddresses) != 0 {
		t.Errorf("certificate has SANs %v / %v, want none", parsed.DNSNames, parsed.IPAddresses)
	}

	if !verifyForgedCertificate(parsed, authKey) {
		t.Fatal("verifyForgedCertificate rejected a certificate forged for this key")
	}

	other, err := deriveAuthKey(bytes.Repeat([]byte{0x99}, 32), bytes.Repeat([]byte{0x88}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if verifyForgedCertificate(parsed, other) {
		t.Fatal("verifyForgedCertificate accepted a certificate forged for a different key")
	}
	if verifyForgedCertificate(nil, authKey) {
		t.Fatal("verifyForgedCertificate accepted a nil certificate")
	}
}

// TestTemporaryCertificateIsProcessStable pins the once-per-process contract:
// the key must not rotate between connections, or a client that reconnects
// would see a different public key.
func TestTemporaryCertificateIsProcessStable(t *testing.T) {
	_, first, err := temporaryCertificate()
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := temporaryCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("temporaryCertificate returned different DER on successive calls")
	}
}

func TestDecodeKeyAcceptsCommonEncodings(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := key.PublicKey().Bytes()

	for _, enc := range []string{
		base64RawURL(raw), base64URL(raw), base64RawStd(raw), base64Std(raw),
	} {
		got, err := decodeKey(enc)
		if err != nil {
			t.Fatalf("decodeKey(%q): %v", enc, err)
		}
		if !bytes.Equal(got, raw) {
			t.Fatalf("decodeKey(%q) = %x, want %x", enc, got, raw)
		}
	}
	if _, err := decodeKey(""); err == nil {
		t.Fatal("decodeKey accepted an empty key")
	}
	if _, err := decodeKey("not base64!!"); err == nil {
		t.Fatal("decodeKey accepted a non-base64 key")
	}
}

func TestReadClientHelloSplitsLeftover(t *testing.T) {
	// A ClientHello message with a 4-byte header and a 5-byte body, followed
	// by 3 extra bytes that must be replayed along with the record header.
	msg := []byte{handshakeTypeClient, 0x00, 0x00, 0x05, 1, 2, 3, 4, 5}
	tail := []byte{9, 9, 9}
	record := append(append([]byte(nil), msg...), tail...)

	frame := []byte{recordTypeHandshake, 0x03, 0x03, byte(len(record) >> 8), byte(len(record))}
	frame = append(frame, record...)

	hello, replay, err := readClientHello(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("readClientHello: %v", err)
	}
	if !bytes.Equal(hello, msg) {
		t.Fatalf("hello = %x, want %x", hello, msg)
	}
	// replay must be the complete original stream, record header included,
	// because it is what gets handed to the TLS server or the fronted site.
	if !bytes.Equal(replay, frame) {
		t.Fatalf("replay = %x, want the whole frame %x", replay, frame)
	}
}

// TestReadClientHelloReplaysOnError pins the fallback invariant: even when the
// read fails, whatever was consumed must be reported so a prober's bytes are
// forwarded rather than swallowed.
func TestReadClientHelloReplaysOnError(t *testing.T) {
	frame := []byte{recordTypeHandshake, 0x03, 0x03, 0x00, 0x08, handshakeTypeClient, 0, 0, 5, 1}
	_, replay, err := readClientHello(bytes.NewReader(frame))
	if err == nil {
		t.Fatal("readClientHello accepted a truncated record")
	}
	if !bytes.Equal(replay, frame) {
		t.Fatalf("replay = %x, want the consumed prefix %x", replay, frame)
	}
}

func TestReadClientHelloRejectsBadFraming(t *testing.T) {
	tests := []struct {
		name  string
		frame []byte
	}{
		{
			name:  "not a handshake record",
			frame: []byte{23, 0x03, 0x03, 0x00, 0x01, 0x00},
		},
		{
			name:  "zero length record",
			frame: []byte{recordTypeHandshake, 0x03, 0x03, 0x00, 0x00},
		},
		{
			name:  "record length beyond the cap",
			frame: []byte{recordTypeHandshake, 0x03, 0x03, 0xff, 0xff},
		},
		{
			name:  "handshake type is not a ClientHello",
			frame: []byte{recordTypeHandshake, 0x03, 0x03, 0x00, 0x04, 2, 0, 0, 0},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := readClientHello(bytes.NewReader(tc.frame)); err == nil {
				t.Fatal("readClientHello accepted malformed input")
			}
		})
	}
}

func TestCheckAuthBlock(t *testing.T) {
	shortID, err := ParseShortID("cafe")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	tests := []struct {
		name     string
		block    authBlock
		settings transport.Settings
		wantErr  bool
	}{
		{
			name:     "fresh block with matching short id",
			block:    authBlock{Version: [3]byte{1, 8, 2}, Time: now, ShortID: shortID},
			settings: transport.Settings{SettingShortID: "cafe"},
		},
		{
			name:     "stale timestamp",
			block:    authBlock{Version: [3]byte{1, 8, 2}, Time: now.Add(-10 * time.Minute), ShortID: shortID},
			settings: transport.Settings{SettingShortID: "cafe"},
			wantErr:  true,
		},
		{
			name:     "future timestamp beyond skew",
			block:    authBlock{Version: [3]byte{1, 8, 2}, Time: now.Add(10 * time.Minute), ShortID: shortID},
			settings: transport.Settings{SettingShortID: "cafe"},
			wantErr:  true,
		},
		{
			name:     "skew within a widened limit",
			block:    authBlock{Version: [3]byte{1, 8, 2}, Time: now.Add(-10 * time.Minute), ShortID: shortID},
			settings: transport.Settings{SettingShortID: "cafe", SettingMaxTimeDiff: 20 * time.Minute},
		},
		{
			name:     "negative maxTimeDiff disables the check",
			block:    authBlock{Version: [3]byte{1, 8, 2}, Time: time.Unix(1, 0), ShortID: shortID},
			settings: transport.Settings{SettingShortID: "cafe", SettingMaxTimeDiff: -1 * time.Second},
		},
		{
			name:     "unknown short id",
			block:    authBlock{Version: [3]byte{1, 8, 2}, Time: now, ShortID: shortID},
			settings: transport.Settings{SettingShortID: "beef"},
			wantErr:  true,
		},
		{
			name:     "short id list membership",
			block:    authBlock{Version: [3]byte{1, 8, 2}, Time: now, ShortID: shortID},
			settings: transport.Settings{SettingShortIDs: []string{"beef", "cafe"}},
		},
		{
			name:     "client version below the minimum",
			block:    authBlock{Version: [3]byte{1, 7, 0}, Time: now, ShortID: shortID},
			settings: transport.Settings{SettingShortID: "cafe", SettingMinClientVer: "1.8.0"},
			wantErr:  true,
		},
		{
			name:     "client version above the maximum",
			block:    authBlock{Version: [3]byte{26, 0, 0}, Time: now, ShortID: shortID},
			settings: transport.Settings{SettingShortID: "cafe", SettingMaxClientVer: "25.1.30"},
			wantErr:  true,
		},
		{
			name:     "client version inside the range",
			block:    authBlock{Version: [3]byte{1, 8, 2}, Time: now, ShortID: shortID},
			settings: transport.Settings{SettingShortID: "cafe", SettingMinClientVer: "1.8.0", SettingMaxClientVer: "25.1.30"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkAuthBlock(tc.block, tc.settings)
			if tc.wantErr && err == nil {
				t.Fatal("checkAuthBlock accepted a block it should reject")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("checkAuthBlock: %v", err)
			}
		})
	}
}

// TestClientHelloAuthBlockOverRealFingerprint exercises the client-side sealing
// against a genuine uTLS Chrome ClientHello, which is the only way to prove
// that the session_id really does begin at offset 39 and that the preset leaves
// it zeroed.
func TestClientHelloAuthBlockOverRealFingerprint(t *testing.T) {
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shortID, err := ParseShortID("0102030405060708")
	if err != nil {
		t.Fatal(err)
	}

	uconn, authKey, err := realityClientHello(nil, transport.DialRequest{
		ServerName: "www.microsoft.com",
		Settings:   transport.Settings{},
	}, "www.microsoft.com", serverKey.PublicKey(), shortID)
	if err != nil {
		t.Fatalf("realityClientHello: %v", err)
	}

	raw := uconn.HandshakeState.Hello.Raw
	if len(authKey) != 32 {
		t.Fatalf("AuthKey is %d bytes, want 32", len(authKey))
	}
	if raw[sessionIDOffset-1] != sessionIDLen {
		t.Fatalf("session id length prefix = %d, want %d", raw[sessionIDOffset-1], sessionIDLen)
	}

	// The relay side must recover exactly what the client sealed.
	block, err := openAuthBlock(raw, uconn.HandshakeState.Hello.Random, authKey)
	if err != nil {
		t.Fatalf("openAuthBlock over a real ClientHello: %v", err)
	}
	if block.ShortID != shortID {
		t.Errorf("shortId = %x, want %x", block.ShortID, shortID)
	}
	if block.Version != ClientVersion() {
		t.Errorf("version = %v, want %v", block.Version, ClientVersion())
	}
	if skew := time.Since(block.Time); skew < 0 || skew > time.Minute {
		t.Errorf("timestamp skew = %s, want a fresh timestamp", skew)
	}

	// Ed25519 must have been added to signature_algorithms, otherwise
	// crypto/tls will refuse to send the relay's Ed25519 certificate.
	parsed := utls.UnmarshalClientHello(raw)
	if parsed == nil {
		t.Fatal("marshalled ClientHello did not parse")
	}
	found := false
	for _, alg := range parsed.SupportedSignatureAlgorithms {
		if alg == utls.Ed25519 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("signature_algorithms does not advertise Ed25519")
	}

	// The server must derive the same key from the advertised key share.
	privateKey, err := ecdh.X25519().NewPrivateKey(serverKey.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	peerPub, err := peerX25519(parsed)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := privateKey.ECDH(peerPub)
	if err != nil {
		t.Fatal(err)
	}
	serverAuthKey, err := deriveAuthKey(shared, parsed.Random)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(authKey, serverAuthKey) {
		t.Fatal("client and server derived different AuthKeys")
	}
}

func TestPeerX25519RejectsMissingKeyShare(t *testing.T) {
	hello := &utls.PubClientHelloMsg{KeyShares: []utls.KeyShare{{Group: utls.CurveP256, Data: make([]byte, 65)}}}
	if _, err := peerX25519(hello); err == nil {
		t.Fatal("peerX25519 accepted a ClientHello with no X25519 share")
	}
}

func TestHandlerRequiresDest(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	h := Handler{}
	_, err := h.Handle(context.Background(), server, transport.HandleRequest{
		Settings: transport.Settings{},
		Timeout:  time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), SettingDest) {
		t.Fatalf("Handle without %s: err = %v, want a %s error", SettingDest, err, SettingDest)
	}
}

func TestDialerRequiresPublicKey(t *testing.T) {
	d := Dialer{}
	_, err := d.Dial(context.Background(), transport.DialRequest{
		ServerAddr: "127.0.0.1:1",
		Settings:   transport.Settings{},
	})
	if err == nil || !strings.Contains(err.Error(), SettingPublicKey) {
		t.Fatalf("Dial without %s: err = %v, want a %s error", SettingPublicKey, err, SettingPublicKey)
	}
}

func TestClientHelloIDRejectsUnknownProfile(t *testing.T) {
	if _, err := clientHelloID("netscape"); err == nil {
		t.Fatal("clientHelloID accepted an unknown profile")
	}
	if _, err := clientHelloID(""); err != nil {
		t.Fatalf("clientHelloID(\"\") should default to chrome: %v", err)
	}
}

// TestRealityHandshakeOverPipe runs the full REALITY handshake end to end
// between this package's client and server halves over an in-memory
// connection, and asserts that the relay recovers the target the client asked
// for. The fronted site is a real loopback listener, because the relay dials
// dest on every connection by design.
func TestRealityHandshakeOverPipe(t *testing.T) {
	dest := newDestStub(t)
	defer dest.close()

	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shortID := "1122334455667788"

	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()

	handler := Handler{}
	streamCh := make(chan transport.Stream, 1)
	errCh := make(chan error, 1)
	go func() {
		s, err := handler.Handle(context.Background(), serverPipe, transport.HandleRequest{
			Timeout: 10 * time.Second,
			Settings: transport.Settings{
				SettingPrivateKey:  base64RawURL(serverKey.Bytes()),
				SettingDest:        dest.addr(),
				SettingServerNames: []string{"www.microsoft.com"},
				SettingShortID:     shortID,
				SettingPSK:         "test-psk",
			},
		})
		if err != nil {
			errCh <- err
			return
		}
		streamCh <- s
	}()

	uconn, authKey, err := realityClientHello(clientPipe, transport.DialRequest{
		ServerName: "www.microsoft.com",
		Settings:   transport.Settings{},
	}, "www.microsoft.com", serverKey.PublicKey(), mustShortID(t, shortID))
	if err != nil {
		t.Fatalf("realityClientHello: %v", err)
	}
	if err := uconn.Handshake(); err != nil {
		select {
		case rerr := <-errCh:
			t.Fatalf("client handshake: %v (relay: %v)", err, rerr)
		default:
			t.Fatalf("client handshake: %v", err)
		}
	}
	if err := verifyRelayCertificate(uconn, authKey, transport.Settings{}, "www.microsoft.com"); err != nil {
		t.Fatalf("verifyRelayCertificate: %v", err)
	}

	// The relay must have forged its certificate for the key we derived.
	state := uconn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("relay sent no certificate")
	}
	if !verifyForgedCertificate(state.PeerCertificates[0], authKey) {
		t.Fatal("relay certificate did not carry the REALITY authenticator")
	}

	// Now the PortTransit preamble travels inside the REALITY tunnel.
	wantTarget := "example.com:443"
	clientStream, err := transport.PreambleClientHandshake(uconn, &transport.Request{
		Command: transport.CmdConnectTCP,
		Target:  wantTarget,
	}, transport.ClientHandshakeConfig{
		PSK:           []byte("test-psk"),
		TransportName: Name,
		Timeout:       10 * time.Second,
	})
	if err != nil {
		t.Fatalf("PreambleClientHandshake: %v", err)
	}
	defer clientStream.Close()

	select {
	case err := <-errCh:
		t.Fatalf("relay Handle: %v", err)
	case stream := <-streamCh:
		if got := stream.Request().Target; got != wantTarget {
			t.Fatalf("relay recovered target %q, want %q", got, wantTarget)
		}
		if got := stream.Request().Transport; got != Name {
			t.Fatalf("relay stamped transport %q, want %q", got, Name)
		}
		stream.Close()
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the relay to authenticate")
	}

	// The relay must have dialled the fronted site exactly once, before it
	// looked at the client at all.
	if n := dest.accepted(); n != 1 {
		t.Fatalf("relay dialled dest %d times, want 1", n)
	}
}

// TestRealityHandlerFallsBackOnBadShortID proves the camouflage path: a client
// that fails authentication is spliced to the fronted site and the relay
// reports the fallback sentinel rather than a hard error.
func TestRealityHandlerFallsBackOnBadShortID(t *testing.T) {
	dest := newDestStub(t)
	defer dest.close()

	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	clientPipe, serverPipe := net.Pipe()

	handler := Handler{}
	errCh := make(chan error, 1)
	go func() {
		_, err := handler.Handle(context.Background(), serverPipe, transport.HandleRequest{
			Timeout: 5 * time.Second,
			Settings: transport.Settings{
				SettingPrivateKey:  base64RawURL(serverKey.Bytes()),
				SettingDest:        dest.addr(),
				SettingServerNames: []string{"www.microsoft.com"},
				SettingShortID:     "aabbccdd",
			},
		})
		errCh <- err
	}()

	// Authenticate correctly but present a short id the relay does not accept.
	uconn, _, err := realityClientHello(clientPipe, transport.DialRequest{
		ServerName: "www.microsoft.com",
		Settings:   transport.Settings{},
	}, "www.microsoft.com", serverKey.PublicKey(), mustShortID(t, "00112233"))
	if err != nil {
		t.Fatalf("realityClientHello: %v", err)
	}

	// The relay rejects the ClientHello and splices the raw stream to dest, so
	// no ServerHello ever arrives. The deadline is what lets the client give up
	// and close, which in turn lets the relay's splice finish.
	_ = clientPipe.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if err := uconn.Handshake(); err == nil {
		t.Fatal("client handshake succeeded against a relay that rejected the short id")
	}
	clientPipe.Close()

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrFallbackHandled) {
			t.Fatalf("Handle returned %v, want ErrFallbackHandled", err)
		}
		// internal/server classifies fallbacks by this phrase, so the message
		// must keep it.
		if !strings.Contains(err.Error(), "forwarded to fallback") {
			t.Fatalf("error %q must contain \"forwarded to fallback\"", err.Error())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the fallback")
	}

	serverPipe.Close()

	// The whole point of the fallback is that the prober's bytes reach the
	// fronted site, so dest must have received the ClientHello verbatim.
	if got := dest.received(); got == 0 {
		t.Fatal("dest received no bytes; the client was not spliced through")
	}
}

// destStub is a stand-in for the fronted site. The relay dials it on every
// connection, so the test needs a real listener to observe that behaviour.
type destStub struct {
	ln net.Listener

	mu    sync.Mutex
	count int
	bytes int
}

func newDestStub(t *testing.T) *destStub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &destStub{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			d.mu.Lock()
			d.count++
			d.mu.Unlock()
			// Record what arrives, standing in for a web server that answers.
			go func() {
				defer conn.Close()
				buf := make([]byte, 4096)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						d.mu.Lock()
						d.bytes += n
						d.mu.Unlock()
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return d
}

func (d *destStub) addr() string { return d.ln.Addr().String() }

func (d *destStub) accepted() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.count
}

func (d *destStub) received() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.bytes
}

func (d *destStub) close() { _ = d.ln.Close() }

func mustShortID(t *testing.T, s string) [shortIDLen]byte {
	t.Helper()
	id, err := ParseShortID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func parseLeaf(cert tls.Certificate) (*x509.Certificate, error) {
	if len(cert.Certificate) == 0 {
		return nil, errors.New("certificate has no DER")
	}
	return x509.ParseCertificate(cert.Certificate[0])
}

func base64RawURL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func base64URL(b []byte) string    { return base64.URLEncoding.EncodeToString(b) }
func base64RawStd(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }
func base64Std(b []byte) string    { return base64.StdEncoding.EncodeToString(b) }

// Compile-time assertions that the transport contract is satisfied.
var (
	_ transport.Dialer  = Dialer{}
	_ transport.Handler = Handler{}
)
