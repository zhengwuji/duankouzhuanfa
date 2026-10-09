package vmess

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"hash/crc32"
	"io"
	"net"
	"testing"
	"time"

	"porttransit/internal/cryptox"
	"porttransit/internal/transport"
)

// hash2 is the thin wrapper v2ray's KDF uses to hand a live HMAC to the next
// level. It exists only so the outer and inner hashes of the next HMAC are
// *different interface values* while sharing one underlying object, which is
// what satisfies crypto/hmac's uniqueness check.
type hash2 struct{ hash.Hash }

// referenceKDF is a literal transcription of v2ray's aead.KDF, including the
// shared-state trick.
func referenceKDF(key []byte, path ...string) []byte {
	hmacf := hmac.New(sha256.New, []byte(kdfRoot))
	for _, component := range path {
		first := true
		inner := hmacf
		hmacf = hmac.New(func() hash.Hash {
			if first {
				first = false
				return hash2{inner}
			}
			return inner
		}, []byte(component))
	}
	hmacf.Write(key)
	return hmacf.Sum(nil)
}

// TestKDFAgainstReferenceImplementation checks that the direct evaluation of
// the nested-HMAC chain matches the reference construction for every path
// length the protocol actually uses, plus a key longer than the block size.
func TestKDFAgainstReferenceImplementation(t *testing.T) {
	cmdKey := CmdKey(cryptox.MustParseUUID("b831381d-6324-4d53-ad4f-8cda48b30811"))

	cases := []struct {
		name string
		key  []byte
		path []string
	}{
		{"no path", cmdKey, nil},
		{"auth id", cmdKey, []string{kdfSaltAuthID}},
		{"header key", cmdKey, []string{kdfSaltHeaderKey, "0123456789abcdef", "fedcba9876543210"}},
		{"header length", cmdKey, []string{kdfSaltHeaderLengthKey, "0123456789abcdef", "fedcba9876543210"}},
		{"response header", []byte("0123456789abcdef"), []string{kdfSaltResponseHeaderKey}},
		{"long key", bytes.Repeat([]byte{0xab}, 100), []string{kdfSaltHeaderKey, "nonce"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := KDF(tc.key, tc.path...)
			want := referenceKDF(tc.key, tc.path...)
			if !bytes.Equal(got, want) {
				t.Fatalf("KDF mismatch\n got %x\nwant %x", got, want)
			}
			if len(KDF16(tc.key, tc.path...)) != 16 {
				t.Fatalf("KDF16 returned %d bytes, want 16", len(KDF16(tc.key, tc.path...)))
			}
		})
	}
}

// TestKDFKnownVector pins three derived values so a future refactor cannot
// quietly change the wire format while still matching the reference
// transcription (both would move together, and the cross-check above would stay
// green). The vectors were produced by this implementation and cross-checked
// against the transcription; they are regression pins, not independently
// published test vectors.
func TestKDFKnownVector(t *testing.T) {
	cmdKey, err := hex.DecodeString("b1c2d3e4f5061728394a5b6c7d8e9f00")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		path []string
		want string
	}{
		{"auth id", []string{kdfSaltAuthID}, "331e769169028e99a1aaac66bd2ba2f6"},
		{"header key", []string{kdfSaltHeaderKey, "0f1e2d3c4b5a6978", "8899aabbccddeeff"}, "b15a63d4c41201b6b21ff3f6ac27b98f"},
		{"response header key", []string{kdfSaltResponseHeaderKey}, "e0de464dd0ca8d9c54d5633da41e034e"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hex.EncodeToString(KDF16(cmdKey, tc.path...))
			if got != tc.want {
				t.Fatalf("KDF16 = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestCmdKey checks the MD5 domain separation.
func TestCmdKey(t *testing.T) {
	uuid := cryptox.MustParseUUID("b831381d-6324-4d53-ad4f-8cda48b30811")
	got := CmdKey(uuid)
	if len(got) != 16 {
		t.Fatalf("CmdKey returned %d bytes, want 16", len(got))
	}
	sum := cryptox.MD5Sum(append(uuid.Bytes(), []byte(cmdKeySuffix)...))
	if !bytes.Equal(got, sum) {
		t.Fatalf("CmdKey = %x, want %x", got, sum)
	}
	// A different UUID must not collide.
	other := CmdKey(cryptox.MustParseUUID("de305d54-75b4-431b-adb2-eb6b9e546014"))
	if bytes.Equal(got, other) {
		t.Fatal("two UUIDs produced the same CmdKey")
	}
}

// TestAuthIDRoundTrip checks that the ECB block encryption is invertible and
// that the CRC survives, which is the property the relay's user lookup relies
// on.
func TestAuthIDRoundTrip(t *testing.T) {
	cmdKey, err := hex.DecodeString("00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)

	authID, err := createAuthID(cmdKey, now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	got, err := openAuthID(cmdKey, authID)
	if err != nil {
		t.Fatalf("openAuthID: %v", err)
	}
	if !got.Equal(now) {
		t.Fatalf("timestamp round trip = %s, want %s", got, now)
	}

	// The plaintext layout is Timestamp|Rand|CRC32(IEEE) over the first 12
	// bytes, and the cipher is a single AES block, so decrypting by hand must
	// reproduce it.
	blk, err := aesBlockForTest(KDF16(cmdKey, kdfSaltAuthID))
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, 16)
	blk.Decrypt(plain, authID[:])
	if binary.BigEndian.Uint64(plain[:8]) != uint64(now.Unix()) {
		t.Fatalf("timestamp field = %d, want %d", binary.BigEndian.Uint64(plain[:8]), now.Unix())
	}
	if got, want := binary.BigEndian.Uint32(plain[12:16]), crc32.ChecksumIEEE(plain[:12]); got != want {
		t.Fatalf("CRC field = %08x, want %08x", got, want)
	}
}

// TestAuthIDRejectsWrongUser checks that a request encrypted for another user
// fails the CRC, which is the whole authentication of a VMess request.
func TestAuthIDRejectsWrongUser(t *testing.T) {
	good := cryptox.MD5Sum([]byte("good"))
	bad := cryptox.MD5Sum([]byte("bad"))

	authID, err := createAuthID(good, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openAuthID(bad, authID); err == nil {
		t.Fatal("openAuthID accepted an auth id belonging to another user")
	}
}

// TestAuthIDRejectsStaleTimestamp covers the replay window in both directions.
func TestAuthIDRejectsStaleTimestamp(t *testing.T) {
	cmdKey := cryptox.MD5Sum([]byte("user"))

	for _, tc := range []struct {
		name  string
		delta time.Duration
		ok    bool
	}{
		{"fresh", 0, true},
		{"just inside", maxSkew - 5*time.Second, true},
		{"just outside", maxSkew + 5*time.Second, false},
		{"far future", -(maxSkew + 5*time.Second), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authID, err := createAuthID(cmdKey, time.Now().Add(tc.delta).Unix())
			if err != nil {
				t.Fatal(err)
			}
			_, err = openAuthID(cmdKey, authID)
			if tc.ok && err != nil {
				t.Fatalf("openAuthID rejected a fresh id: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("openAuthID accepted a stale id")
			}
		})
	}
}

// TestInstructionRoundTrip covers the instruction section encode/decode pair
// across every address type and a range of padding lengths.
func TestInstructionRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		address string
		command byte
		pad     byte
	}{
		{"ipv4", "1.2.3.4:80", cmdTCP, 0},
		{"ipv4 padded", "1.2.3.4:80", cmdTCP, maxPadding},
		{"ipv6", "[2001:db8::1]:443", cmdTCP, 7},
		{"domain", "example.com:8080", cmdTCP, 3},
		{"domain udp", "very.long.subdomain.example.org:53", cmdUDP, 15},
		{"loopback", "127.0.0.1:1", cmdTCP, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := &requestHeader{
				Version:   instructionVersion,
				ResponseV: 0x5a,
				Option:    0,
				Padding:   tc.pad,
				Security:  SecurityChaCha20Poly1305,
				Command:   tc.command,
				Address:   tc.address,
			}
			copy(want.BodyIV[:], bytes.Repeat([]byte{0x11}, 16))
			copy(want.BodyKey[:], bytes.Repeat([]byte{0x22}, 16))

			encoded, err := want.encode()
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if got, wantSum := fnv1a32(encoded[:len(encoded)-checksumLen]), binary.BigEndian.Uint32(encoded[len(encoded)-checksumLen:]); got != wantSum {
				t.Fatalf("checksum = %08x, want %08x", got, wantSum)
			}

			got, err := decodeRequestHeader(encoded)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got.Address != want.Address {
				t.Fatalf("address = %q, want %q", got.Address, want.Address)
			}
			if got.Command != want.Command || got.Security != want.Security || got.Padding != want.Padding {
				t.Fatalf("header = %+v, want %+v", got, want)
			}
			if got.BodyIV != want.BodyIV || got.BodyKey != want.BodyKey || got.ResponseV != want.ResponseV {
				t.Fatal("body key material did not round trip")
			}
		})
	}
}

// TestInstructionRejectsTampering checks that the checksum catches a flipped
// bit anywhere in the instruction section.
func TestInstructionRejectsTampering(t *testing.T) {
	h := &requestHeader{
		Version:  instructionVersion,
		Security: SecurityAES128GCM,
		Command:  cmdTCP,
		Address:  "example.com:443",
	}
	encoded, err := h.encode()
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < len(encoded)-checksumLen; i++ {
		corrupt := append([]byte(nil), encoded...)
		corrupt[i] ^= 0x01
		if _, err := decodeRequestHeader(corrupt); err == nil {
			t.Fatalf("decode accepted a corrupt byte at offset %d", i)
		}
	}
	if _, err := decodeRequestHeader(encoded[:len(encoded)-1]); err == nil {
		t.Fatal("decode accepted a truncated instruction section")
	}
}

// TestInstructionRejectsBadFields covers the reserved byte, an unknown address
// type and an impossible padding length.
func TestInstructionRejectsBadFields(t *testing.T) {
	base := &requestHeader{Version: instructionVersion, Security: SecurityAES128GCM, Command: cmdTCP, Address: "example.com:443"}
	encoded, err := base.encode()
	if err != nil {
		t.Fatal(err)
	}

	corrupt := func(offset int, value byte) []byte {
		out := append([]byte(nil), encoded...)
		out[offset] = value
		// Re-checksum so the failure comes from the field, not the checksum.
		binary.BigEndian.PutUint32(out[len(out)-checksumLen:], fnv1a32(out[:len(out)-checksumLen]))
		return out
	}

	// Offsets within the instruction section, for a domain address:
	// 0 version, 1..16 IV, 17..32 key, 33 response V, 34 option,
	// 35 margin|security, 36 reserved, 37 command, 38..39 port, 40 address type.
	if _, err := decodeRequestHeader(corrupt(36, 0x01)); err == nil {
		t.Fatal("decode accepted a non-zero reserved byte")
	}
	if _, err := decodeRequestHeader(corrupt(40, 0x07)); err == nil {
		t.Fatal("decode accepted an unknown address type")
	}
	if _, err := decodeRequestHeader(corrupt(0, 0x02)); err != nil {
		t.Fatalf("decode rejected a bumped version byte, which is the caller's job: %v", err)
	}
}

// TestFNV1aKnownVector pins the checksum against the FNV-1a specification.
func TestFNV1aKnownVector(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
	}{
		{"", 0x811c9dc5},
		{"a", 0xe40c292c},
		{"foobar", 0xbf9cf968},
	}
	for _, tc := range cases {
		if got := fnv1a32([]byte(tc.in)); got != tc.want {
			t.Fatalf("fnv1a32(%q) = %08x, want %08x", tc.in, got, tc.want)
		}
	}
}

// TestChunkNonceLayout checks the nonce is a big-endian counter followed by ten
// bytes of the IV, and that the counter advances.
func TestChunkNonceLayout(t *testing.T) {
	iv := [16]byte{}
	for i := range iv {
		iv[i] = byte(i + 1)
	}
	b := &bodyConn{iv: iv}
	for count := uint16(0); count < 3; count++ {
		nonce := b.chunkNonce(count)
		if len(nonce) != aeadNonceLen {
			t.Fatalf("nonce length = %d, want %d", len(nonce), aeadNonceLen)
		}
		if binary.BigEndian.Uint16(nonce[:2]) != count {
			t.Fatalf("nonce counter = %d, want %d", binary.BigEndian.Uint16(nonce[:2]), count)
		}
		if !bytes.Equal(nonce[2:], iv[:chunkNonceIVLen]) {
			t.Fatalf("nonce IV tail = %x, want %x", nonce[2:], iv[:chunkNonceIVLen])
		}
	}
}

// TestResponseBodyKeys checks the SHA-256 truncation.
func TestResponseBodyKeys(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 16)
	iv := bytes.Repeat([]byte{0x02}, 16)
	gotKey, gotIV := responseBodyKeys(key, iv)
	if !bytes.Equal(gotKey, cryptox.SHA256Sum(key)[:16]) {
		t.Fatal("response key is not SHA256(request key)[:16]")
	}
	if !bytes.Equal(gotIV, cryptox.SHA256Sum(iv)[:16]) {
		t.Fatal("response IV is not SHA256(request IV)[:16]")
	}
}

// TestBodyConnRoundTrip pushes a payload larger than one chunk through a pipe
// and checks the framing survives, including the empty end-of-transmission
// packet.
func TestBodyConnRoundTrip(t *testing.T) {
	key := cryptox.RandomBytes(16)
	iv := [16]byte{}
	copy(iv[:], cryptox.RandomBytes(16))

	payload := cryptox.RandomBytes(maxChunkLength + 1234)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	aead, err := SecurityAES128GCM.bodyAEAD(key)
	if err != nil {
		t.Fatal(err)
	}

	writeErr := make(chan error, 1)
	go func() {
		w := newBodyConn(client, aead, iv)
		if _, err := w.Write(payload); err != nil {
			writeErr <- err
			return
		}
		writeErr <- w.closeWrite()
	}()

	r := newBodyConn(server, aead, iv)
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload round trip differs: got %d bytes, want %d", len(got), len(payload))
	}
}

// TestHandshakeOverPipe runs the full client↔relay handshake in memory and
// asserts the relay recovers the target address, then exchanges data in both
// directions.
func TestHandshakeOverPipe(t *testing.T) {
	uuid := cryptox.MustParseUUID("b831381d-6324-4d53-ad4f-8cda48b30811")
	settings := transport.Settings{
		SettingUUID:     uuid.String(),
		SettingTLS:      false,
		SettingSecurity: "chacha20-poly1305",
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	type result struct {
		stream transport.Stream
		err    error
	}
	handled := make(chan result, 1)
	go func() {
		s, err := Handler{}.Handle(context.Background(), server, transport.HandleRequest{Settings: settings})
		handled <- result{s, err}
	}()

	dialer := pipeDialer{conn: client}
	stream, err := dialer.Dial(context.Background(), transport.DialRequest{
		ServerAddr: "relay.example:443",
		Request:    &transport.Request{Command: transport.CmdConnectTCP, Target: "target.example:8443"},
		Settings:   settings,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	relaySide := <-handled
	if relaySide.err != nil {
		t.Fatalf("handle: %v", relaySide.err)
	}
	defer relaySide.stream.Close()

	got := relaySide.stream.Request()
	if got.Target != "target.example:8443" {
		t.Fatalf("relay recovered target %q, want %q", got.Target, "target.example:8443")
	}
	if got.Command != transport.CmdConnectTCP {
		t.Fatalf("relay recovered command %v, want tcp", got.Command)
	}
	if got.Transport != Name {
		t.Fatalf("relay recovered transport %q, want %q", got.Transport, Name)
	}
	if got.ClientID != uuid.String() {
		t.Fatalf("relay recovered client id %q, want %q", got.ClientID, uuid.String())
	}
	if got.Meta["security"] != "chacha20-poly1305" {
		t.Fatalf("relay recovered security %q", got.Meta["security"])
	}

	// Client → relay and relay → client, concurrently: net.Pipe is unbuffered,
	// so both directions must be driven at once.
	up := []byte("hello relay")
	down := []byte("hello client")

	go func() {
		_, _ = stream.Write(up)
		_ = stream.(*clientStream).CloseWrite()
	}()
	go func() {
		_, _ = relaySide.stream.Write(down)
		_ = relaySide.stream.(*tunnelStream).CloseWrite()
	}()

	gotUp := make([]byte, len(up))
	if _, err := io.ReadFull(relaySide.stream, gotUp); err != nil {
		t.Fatalf("relay read: %v", err)
	}
	if !bytes.Equal(gotUp, up) {
		t.Fatalf("uplink = %q, want %q", gotUp, up)
	}

	gotDown, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(gotDown, down) {
		t.Fatalf("downlink = %q, want %q", gotDown, down)
	}
}

// TestHandshakeRejectsWrongUser checks the relay refuses a client using another
// UUID.
func TestHandshakeRejectsWrongUser(t *testing.T) {
	server := transport.Settings{
		SettingUUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
		SettingTLS:  false,
	}
	client := transport.Settings{
		SettingUUID: "de305d54-75b4-431b-adb2-eb6b9e546014",
		SettingTLS:  false,
	}

	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := Handler{}.Handle(context.Background(), s, transport.HandleRequest{Settings: server})
		errCh <- err
	}()

	dialer := pipeDialer{conn: c}
	// The client's write races the relay's rejection on an unbuffered pipe, so
	// Dial may fail with a closed pipe instead of completing. The assertion is
	// about the relay, not about which side observes the closure first.
	_, _ = dialer.Dial(context.Background(), transport.DialRequest{
		ServerAddr: "relay.example:443",
		Request:    &transport.Request{Command: transport.CmdConnectTCP, Target: "target.example:443"},
		Settings:   client,
	})

	if err := <-errCh; err == nil {
		t.Fatal("relay accepted a request from the wrong user")
	}
}

// TestParseSecurity covers the settings mapping.
func TestParseSecurity(t *testing.T) {
	cases := []struct {
		in      string
		want    Security
		wantErr bool
	}{
		{"", SecurityChaCha20Poly1305, false},
		{"auto", SecurityChaCha20Poly1305, false},
		{"aes-128-gcm", SecurityAES128GCM, false},
		{"chacha20-poly1305", SecurityChaCha20Poly1305, false},
		{"none", SecurityNone, false},
		{"aes-128-cfb", 0, true},
		{"aes-256-gcm", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseSecurity(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseSecurity(%q) succeeded, want an error", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSecurity(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseSecurity(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// pipeDialer hands Dial an already-connected net.Conn so the handshake can be
// tested without a listener.
type pipeDialer struct {
	conn net.Conn
}

// Dial implements transport.Dialer against a pre-connected pipe.
func (p pipeDialer) Dial(ctx context.Context, req transport.DialRequest) (transport.Stream, error) {
	d := Dialer{}
	return d.dialOver(ctx, p.conn, req)
}

// aesBlockForTest builds the raw AES block used by the EAuID construction so a
// test can decrypt an auth id independently of openAuthID.
func aesBlockForTest(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}
