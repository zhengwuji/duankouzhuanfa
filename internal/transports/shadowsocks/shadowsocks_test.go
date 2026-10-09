package shadowsocks

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"porttransit/internal/cryptox"
	"porttransit/internal/transport"

	"lukechampine.com/blake3"
)

// testKey2022 returns a deterministic key of the method's length.
func testKey2022(t *testing.T, m method) []byte {
	t.Helper()
	key := make([]byte, m.keyLen)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

// testSettings renders settings that select m with a fixed key.
func testSettings(t *testing.T, m method, key []byte) transport.Settings {
	t.Helper()
	return transport.Settings{
		SettingMethod:   m.name,
		SettingPassword: base64.StdEncoding.EncodeToString(key),
	}
}

// mustMethod resolves a method or fails the test.
func mustMethod(t *testing.T, name string) method {
	t.Helper()
	m, err := resolveMethod(name)
	if err != nil {
		t.Fatalf("resolveMethod(%q): %v", name, err)
	}
	return m
}

// --- Subkey derivation ---------------------------------------------------

// TestSessionSubkey2022BLAKE3Vector pins the BLAKE3 key-derivation primitive
// against the official BLAKE3 test vector.
//
// The vector is the published one for input length 1 (the single byte 0x00)
// under the context string "BLAKE3 2019-12-27 16:29:52 test vectors context".
// Checking it here proves the library call is wired up the way the spec's
// `blake3::derive_key` is, rather than merely that the code compiles.
func TestSessionSubkey2022BLAKE3Vector(t *testing.T) {
	const want = "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c" +
		"5827b91bf889b6b97c5477f535361caefca0b5d8c4746441c5761711193315895" +
		"0670f9aa8a05d791daae10ac683cbef8faf897c84e6114a59d2173c3f417023a3" +
		"5d6983f2c7dfa57e7fc559ad751dbfb9ffab39c2ef8c4aafebc9ae973a64f0c76551"

	out := make([]byte, 131)
	// The derivation must use the same primitive the transport does. Routing it
	// through sessionSubkey2022 with a 131-byte key is not possible (the subkey
	// length equals the key length), so the primitive is exercised directly.
	deriveKeyBLAKE3(out, "BLAKE3 2019-12-27 16:29:52 test vectors context", []byte{0x00})

	if got := hex.EncodeToString(out); got != want {
		t.Fatalf("BLAKE3 derive_key vector mismatch:\n got %s\nwant %s", got, want)
	}
}

// TestSessionSubkey2022 pins the Shadowsocks-2022 subkey derivation itself.
//
// The expected value was produced by SIP022 section 2.2's construction:
// blake3::derive_key("shadowsocks 2022 session subkey", key || salt). The
// primitive underneath it is verified independently by
// TestSessionSubkey2022BLAKE3Vector, so this vector pins the two things that
// test cannot: the context string and the order of the key material.
func TestSessionSubkey2022(t *testing.T) {
	cases := []struct {
		name string
		key  []byte
		salt []byte
		want string
	}{
		{
			name: "32-byte key and salt",
			key:  seq(32, 0x00),
			salt: seq(32, 0xA0),
			want: "8a54bdc58e8c56998e5570a1903596333229fcba141429f380cceda6a647b700",
		},
		{
			name: "16-byte key and salt",
			key:  seq(16, 0x00),
			salt: seq(16, 0xA0),
			want: "4d0d7016c8028969edf2d6ca7fc30b93",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sessionSubkey2022(tc.key, tc.salt)
			if hex.EncodeToString(got) != tc.want {
				t.Fatalf("subkey mismatch:\n got %s\nwant %s", hex.EncodeToString(got), tc.want)
			}
			if len(got) != len(tc.key) {
				t.Fatalf("subkey is %d bytes, want the key length %d", len(got), len(tc.key))
			}
		})
	}
}

// TestSessionSubkey2022KeyMaterialOrder proves the key material is key||salt
// and not salt||key.
//
// The spec is explicit about the order, and BLAKE3's keyed mode is not
// commutative, so getting it backwards produces a value that a real peer would
// never compute — a bug that would otherwise look like a wrong password.
func TestSessionSubkey2022KeyMaterialOrder(t *testing.T) {
	key := seq(32, 0x11)
	salt := seq(32, 0x22)

	forward := sessionSubkey2022(key, salt)

	// The reversed construction, computed the same way a wrong implementation
	// would: salt first, then key.
	reversed := make([]byte, 32)
	deriveKeyBLAKE3(reversed, sessionSubkeyContext, append(append([]byte{}, salt...), key...))

	if bytes.Equal(forward, reversed) {
		t.Fatal("key||salt and salt||key derived the same subkey, so the order is not being honoured")
	}
}

// seq returns n bytes starting at start and incrementing.
func seq(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

// --- Wire format ---------------------------------------------------------

// buildRequest2022 renders a complete 2022 request header the way the client
// does, with the timestamp and salt supplied so a test can make them invalid.
//
// It deliberately re-implements the framing rather than calling
// clientHandshake2022: a test that reuses the code under test cannot detect a
// framing mistake in it.
func buildRequest2022(t *testing.T, m method, key, salt []byte, ts uint64, target string, padLen int) []byte {
	t.Helper()

	aead, err := cryptox.NewAEAD(m.aead, sessionSubkey2022(key, salt))
	if err != nil {
		t.Fatalf("build aead: %v", err)
	}
	addr, err := encodeTarget(target)
	if err != nil {
		t.Fatalf("encode target: %v", err)
	}

	variable := append([]byte{}, addr...)
	variable = binary.BigEndian.AppendUint16(variable, uint16(padLen))
	variable = append(variable, cryptox.RandomBytes(padLen)...)

	fixed := []byte{headerTypeClientStream}
	fixed = binary.BigEndian.AppendUint64(fixed, ts)
	fixed = binary.BigEndian.AppendUint16(fixed, uint16(len(variable)))

	out := append([]byte{}, salt...)
	out = append(out, aead.Seal(nil, nonceLE(0), fixed, nil)...)
	out = append(out, aead.Seal(nil, nonceLE(1), variable, nil)...)
	return out
}

// TestRequestHeaderLayout asserts the request stream's byte layout field by
// field, which is what makes the implementation interoperable rather than
// merely self-consistent.
func TestRequestHeaderLayout(t *testing.T) {
	m := mustMethod(t, Method2022ChaCha20Poly)
	key := testKey2022(t, m)
	salt := seq(m.saltLen, 0x5A)

	const target = "127.0.0.1:8080"
	blob := buildRequest2022(t, m, key, salt, uint64(time.Now().Unix()), target, 16)

	// The salt is the first thing on the wire, in the clear.
	if !bytes.Equal(blob[:m.saltLen], salt) {
		t.Fatal("the request does not start with the salt")
	}

	aead, err := cryptox.NewAEAD(m.aead, sessionSubkey2022(key, salt))
	if err != nil {
		t.Fatalf("aead: %v", err)
	}

	// The first header chunk is exactly 11 bytes of plaintext plus the tag.
	fixedRec := blob[m.saltLen : m.saltLen+requestFixedHeaderLen+aead.Overhead()]
	fixed, err := aead.Open(nil, nonceLE(0), fixedRec, nil)
	if err != nil {
		t.Fatalf("the first header chunk does not open with nonce 0: %v", err)
	}
	if len(fixed) != 11 {
		t.Fatalf("the fixed-length header is %d bytes, want 11", len(fixed))
	}
	if fixed[0] != headerTypeClientStream {
		t.Fatalf("header type is 0x%02x, want 0x%02x", fixed[0], headerTypeClientStream)
	}
	// The timestamp is big-endian Unix seconds.
	if got, want := int64(binary.BigEndian.Uint64(fixed[1:9])), time.Now().Unix(); got < want-5 || got > want+5 {
		t.Fatalf("timestamp field is %d, want about %d", got, want)
	}
	// The length field counts the plaintext of the *next* chunk, which is the
	// variable-length header: address + 2-byte padding length + padding.
	addr, err := encodeTarget(target)
	if err != nil {
		t.Fatalf("encode target: %v", err)
	}
	wantLen := len(addr) + 2 + 16
	if got := int(binary.BigEndian.Uint16(fixed[9:11])); got != wantLen {
		t.Fatalf("length field is %d, want %d", got, wantLen)
	}

	// The second header chunk is a standalone AEAD chunk on nonce 1.
	varRec := blob[m.saltLen+len(fixedRec):]
	variable, err := aead.Open(nil, nonceLE(1), varRec, nil)
	if err != nil {
		t.Fatalf("the second header chunk does not open with nonce 1: %v", err)
	}
	if len(variable) != wantLen {
		t.Fatalf("the variable-length header is %d bytes, want %d", len(variable), wantLen)
	}
	gotTarget, consumed, err := transport.DecodeAddrFrom(variable)
	if err != nil {
		t.Fatalf("decode address: %v", err)
	}
	if gotTarget != target {
		t.Fatalf("address decoded to %q, want %q", gotTarget, target)
	}
	// The address is followed by a big-endian padding length and the padding.
	if got := int(binary.BigEndian.Uint16(variable[consumed : consumed+2])); got != 16 {
		t.Fatalf("padding length is %d, want 16", got)
	}
	if len(variable) != consumed+2+16 {
		t.Fatalf("the variable header is %d bytes, want %d", len(variable), consumed+2+16)
	}
}

// TestNonceIsLittleEndian96 pins the 2022 nonce encoding.
//
// The spec's `u96le counter` is a 96-bit little-endian integer. The build's
// other nonce helper, cryptox.Chacha20Nonce, puts a big-endian counter in the
// first four bytes and zeroes the rest, which agrees only for the first value —
// so this is not a cosmetic difference.
func TestNonceIsLittleEndian96(t *testing.T) {
	cases := []struct {
		n    uint64
		want string
	}{
		{0, "000000000000000000000000"},
		{1, "010000000000000000000000"},
		{0x0102, "020100000000000000000000"},
		{0x0102030405060708, "080706050403020100000000"},
	}
	for _, tc := range cases {
		if got := hex.EncodeToString(nonceLE(tc.n)); got != tc.want {
			t.Errorf("nonceLE(%#x) = %s, want %s", tc.n, got, tc.want)
		}
	}
	if len(nonceLE(0)) != 12 {
		t.Fatalf("the nonce is %d bytes, want 12", len(nonceLE(0)))
	}

	// The two nonce helpers must disagree past zero; if they ever coincide the
	// 2022 path has silently inherited the legacy construction.
	if bytes.Equal(nonceLE(1), cryptox.Chacha20Nonce(1, [8]byte{})) {
		t.Fatal("the 2022 nonce matches the legacy construction at counter 1")
	}
}

// --- Round trips over net.Pipe -------------------------------------------

// TestRoundTrip2022 drives a full 2022 exchange through the real client and
// relay halves over an in-memory pipe.
func TestRoundTrip2022(t *testing.T) {
	for _, name := range []string{Method2022AES128GCM, Method2022AES256GCM, Method2022ChaCha20Poly} {
		t.Run(name, func(t *testing.T) {
			m := mustMethod(t, name)
			key := testKey2022(t, m)

			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			const payload = "shadowsocks 2022 payload"

			serverErr := make(chan error, 1)
			go func() {
				stream, err := serverHandshake2022(serverConn, m, key, transport.HandleRequest{})
				if err != nil {
					serverErr <- err
					return
				}
				defer stream.Close()
				if got := stream.Request().Target; got != "127.0.0.1:8080" {
					serverErr <- errors.New("relay decoded target " + got)
					return
				}
				buf := make([]byte, 1024)
				n, err := stream.Read(buf)
				if err != nil {
					serverErr <- err
					return
				}
				// Echo it back, which forces the relay to emit its salt, its
				// response header and the first payload chunk together.
				if _, err := stream.Write(buf[:n]); err != nil {
					serverErr <- err
					return
				}
				serverErr <- nil
			}()

			clientErr := make(chan error, 1)
			go func() {
				stream, err := clientHandshake2022(clientConn, m, key, "127.0.0.1:8080", &transport.Request{
					Command: transport.CmdConnectTCP,
					Target:  "127.0.0.1:8080",
				})
				if err != nil {
					clientErr <- err
					return
				}
				defer stream.Close()
				if _, err := stream.Write([]byte(payload)); err != nil {
					clientErr <- err
					return
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(stream, got); err != nil {
					clientErr <- err
					return
				}
				if string(got) != payload {
					clientErr <- errors.New("echoed " + string(got))
					return
				}
				clientErr <- nil
			}()

			done := make(chan struct{}, 2)
			for _, ch := range []chan error{serverErr, clientErr} {
				go func(ch chan error) {
					if err := <-ch; err != nil {
						t.Errorf("%s side: %v", name, err)
					}
					done <- struct{}{}
				}(ch)
			}
			for i := 0; i < 2; i++ {
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("the 2022 round trip did not finish")
				}
			}
		})
	}
}

// TestRoundTripLegacy proves the 2017 path still works, which is the check that
// the 2022 rewrite did not disturb the framing that is already in use.
func TestRoundTripLegacy(t *testing.T) {
	for _, name := range []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305} {
		t.Run(name, func(t *testing.T) {
			m := mustMethod(t, name)
			key := evpBytesToKey([]byte("a legacy passphrase"), m.keyLen)

			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			const payload = "shadowsocks 2017 payload"

			go func() {
				stream, err := serverHandshakeLegacy(serverConn, m, key, transport.HandleRequest{})
				if err != nil {
					return
				}
				defer stream.Close()
				buf := make([]byte, 1024)
				n, err := stream.Read(buf)
				if err != nil {
					return
				}
				_, _ = stream.Write(buf[:n])
			}()

			stream, err := clientHandshakeLegacy(clientConn, m, key, "127.0.0.1:8080", &transport.Request{
				Command: transport.CmdConnectTCP,
				Target:  "127.0.0.1:8080",
			})
			if err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			defer stream.Close()

			_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := stream.Write([]byte(payload)); err != nil {
				t.Fatalf("write: %v", err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(stream, got); err != nil {
				t.Fatalf("read echo: %v", err)
			}
			if string(got) != payload {
				t.Fatalf("echoed %q, want %q", got, payload)
			}
		})
	}
}

// TestLargePayloadChunking2022 proves a payload far larger than one chunk
// crosses intact, which catches a length/nonce desynchronisation that a short
// message would hide.
func TestLargePayloadChunking2022(t *testing.T) {
	m := mustMethod(t, Method2022ChaCha20Poly)
	key := testKey2022(t, m)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Larger than 0xFFFF so it must be split, and not a multiple of the chunk
	// size so the final short chunk is exercised too.
	payload := make([]byte, maxChunkPayload2022*2+1234)
	for i := range payload {
		payload[i] = byte(i * 7)
	}

	go func() {
		stream, err := serverHandshake2022(serverConn, m, key, transport.HandleRequest{})
		if err != nil {
			return
		}
		defer stream.Close()
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(stream, got); err != nil {
			return
		}
		_, _ = stream.Write(got)
	}()

	stream, err := clientHandshake2022(clientConn, m, key, "127.0.0.1:8080", &transport.Request{
		Command: transport.CmdConnectTCP,
		Target:  "127.0.0.1:8080",
	})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	defer stream.Close()
	_ = clientConn.SetDeadline(time.Now().Add(30 * time.Second))

	writeErr := make(chan error, 1)
	go func() {
		_, err := stream.Write(payload)
		writeErr <- err
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("read the large echo: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write the large payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the large payload came back different")
	}
}

// --- Rejection paths -----------------------------------------------------

// TestRejectsWrongKey proves a request encrypted under another key is refused
// before any response is produced.
func TestRejectsWrongKey(t *testing.T) {
	m := mustMethod(t, Method2022ChaCha20Poly)
	key := testKey2022(t, m)
	wrong := seq(m.keyLen, 0xEE)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Build the request with the wrong key, then feed it to a relay that holds
	// the right one.
	blob := buildRequest2022(t, m, wrong, seq(m.saltLen, 0x01), uint64(time.Now().Unix()), "127.0.0.1:8080", 16)
	go func() {
		_, _ = clientConn.Write(blob)
	}()

	_, err := serverHandshake2022(serverConn, m, key, transport.HandleRequest{})
	if err == nil {
		t.Fatal("a request encrypted under the wrong key was accepted")
	}
	if !errors.Is(err, transport.ErrAuthFailed) {
		t.Fatalf("error is %v, want it to wrap ErrAuthFailed", err)
	}
}

// TestRejectsStaleTimestamp proves the timestamp window is enforced, which is
// what makes a captured request useless once it is old.
func TestRejectsStaleTimestamp(t *testing.T) {
	m := mustMethod(t, Method2022ChaCha20Poly)
	key := testKey2022(t, m)

	cases := []struct {
		name string
		ts   uint64
		ok   bool
	}{
		{"now", uint64(time.Now().Unix()), true},
		{"29 seconds old", uint64(time.Now().Add(-29 * time.Second).Unix()), true},
		{"31 seconds old", uint64(time.Now().Add(-31 * time.Second).Unix()), false},
		{"an hour old", uint64(time.Now().Add(-time.Hour).Unix()), false},
		{"an hour in the future", uint64(time.Now().Add(time.Hour).Unix()), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			blob := buildRequest2022(t, m, key, cryptox.RandomBytes(m.saltLen), tc.ts, "127.0.0.1:8080", 16)
			go func() {
				_, _ = clientConn.Write(blob)
			}()

			stream, err := serverHandshake2022(serverConn, m, key, transport.HandleRequest{})
			if tc.ok {
				if err != nil {
					t.Fatalf("a fresh header was rejected: %v", err)
				}
				stream.Close()
				return
			}
			if err == nil {
				stream.Close()
				t.Fatal("a header outside the timestamp window was accepted")
			}
			if !errors.Is(err, transport.ErrAuthFailed) {
				t.Fatalf("error is %v, want it to wrap ErrAuthFailed", err)
			}
		})
	}
}

// TestRejectsReplayedSalt proves the same request cannot be used twice.
//
// The same byte-for-byte request is fed to the relay on two connections: the
// first must succeed, the second must be refused as a replay. This is the
// property the 2017 edition lacked, where a captured request stayed valid
// forever.
func TestRejectsReplayedSalt(t *testing.T) {
	m := mustMethod(t, Method2022ChaCha20Poly)
	key := testKey2022(t, m)

	// A fresh random salt, so the test does not collide with any other run.
	blob := buildRequest2022(t, m, key, cryptox.RandomBytes(m.saltLen), uint64(time.Now().Unix()), "127.0.0.1:8080", 16)

	first := func() error {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()
		go func() { _, _ = clientConn.Write(blob) }()
		stream, err := serverHandshake2022(serverConn, m, key, transport.HandleRequest{})
		if err == nil {
			stream.Close()
		}
		return err
	}

	if err := first(); err != nil {
		t.Fatalf("the first use of a fresh request was rejected: %v", err)
	}
	err := first()
	if err == nil {
		t.Fatal("the same request was accepted twice")
	}
	if !errors.Is(err, transport.ErrAuthFailed) {
		t.Fatalf("error is %v, want it to wrap ErrAuthFailed", err)
	}
	if !strings.Contains(err.Error(), "already used") {
		t.Fatalf("error is %v, want it to name the replay", err)
	}
}

// TestRejectsHeaderWithNeitherPayloadNorPadding enforces the spec's rule that a
// request header must carry initial payload or non-zero padding.
//
// A header with neither is the shape a truncated probe has, and answering it
// would hand a prober the confirmation the 2022 edition exists to deny.
func TestRejectsHeaderWithNeitherPayloadNorPadding(t *testing.T) {
	m := mustMethod(t, Method2022ChaCha20Poly)
	key := testKey2022(t, m)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	blob := buildRequest2022(t, m, key, cryptox.RandomBytes(m.saltLen), uint64(time.Now().Unix()), "127.0.0.1:8080", 0)
	go func() { _, _ = clientConn.Write(blob) }()

	_, err := serverHandshake2022(serverConn, m, key, transport.HandleRequest{})
	if err == nil {
		t.Fatal("a header with no payload and no padding was accepted")
	}
	if !errors.Is(err, transport.ErrProtocol) {
		t.Fatalf("error is %v, want it to wrap ErrProtocol", err)
	}
}

// TestRejectsOversizedPaddingLength proves a padding length that runs past the
// header chunk is refused rather than allowed to over-read.
func TestRejectsOversizedPaddingLength(t *testing.T) {
	m := mustMethod(t, Method2022ChaCha20Poly)
	key := testKey2022(t, m)
	salt := cryptox.RandomBytes(m.saltLen)

	aead, err := cryptox.NewAEAD(m.aead, sessionSubkey2022(key, salt))
	if err != nil {
		t.Fatalf("aead: %v", err)
	}
	addr, err := encodeTarget("127.0.0.1:8080")
	if err != nil {
		t.Fatalf("encode target: %v", err)
	}

	// A padding length far larger than the bytes actually present.
	variable := append([]byte{}, addr...)
	variable = binary.BigEndian.AppendUint16(variable, 900)

	fixed := []byte{headerTypeClientStream}
	fixed = binary.BigEndian.AppendUint64(fixed, uint64(time.Now().Unix()))
	fixed = binary.BigEndian.AppendUint16(fixed, uint16(len(variable)))

	blob := append([]byte{}, salt...)
	blob = append(blob, aead.Seal(nil, nonceLE(0), fixed, nil)...)
	blob = append(blob, aead.Seal(nil, nonceLE(1), variable, nil)...)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	go func() { _, _ = clientConn.Write(blob) }()

	_, err = serverHandshake2022(serverConn, m, key, transport.HandleRequest{})
	if err == nil {
		t.Fatal("an over-long padding length was accepted")
	}
	if !errors.Is(err, transport.ErrProtocol) {
		t.Fatalf("error is %v, want it to wrap ErrProtocol", err)
	}
}

// TestRejectsResponseWithWrongRequestSalt proves the client refuses a response
// that does not echo the salt it sent, which is what binds a response to its
// request.
func TestRejectsResponseWithWrongRequestSalt(t *testing.T) {
	m := mustMethod(t, Method2022ChaCha20Poly)
	key := testKey2022(t, m)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	stream := newSSConn(clientConn, m, key, true, nil)
	stream.requestSalt = seq(m.saltLen, 0x11)
	stream.read = nil

	// A well-formed response header that echoes a different salt. It is written
	// from the far end of the pipe, because a net.Pipe has no buffer: writing
	// on the same end this side reads from would deadlock rather than fail.
	go func() {
		salt := seq(m.saltLen, 0x22)
		aead, err := cryptox.NewAEAD(m.aead, sessionSubkey2022(key, salt))
		if err != nil {
			return
		}
		plain := []byte{headerTypeServerStream}
		plain = binary.BigEndian.AppendUint64(plain, uint64(time.Now().Unix()))
		plain = append(plain, seq(m.saltLen, 0x33)...)
		plain = binary.BigEndian.AppendUint16(plain, 4)

		out := append([]byte{}, salt...)
		out = append(out, aead.Seal(nil, nonceLE(0), plain, nil)...)
		_, _ = serverConn.Write(out)
	}()

	err := stream.readResponseHeader2022()
	if err == nil {
		t.Fatal("a response header echoing the wrong request salt was accepted")
	}
	if !errors.Is(err, transport.ErrAuthFailed) {
		t.Fatalf("error is %v, want it to wrap ErrAuthFailed", err)
	}
}

// TestClientAcceptsCorrectResponseHeader proves the check above does not reject
// a correct response, which is what keeps it from being a blanket refusal.
func TestClientAcceptsCorrectResponseHeader(t *testing.T) {
	m := mustMethod(t, Method2022ChaCha20Poly)
	key := testKey2022(t, m)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	requestSalt := seq(m.saltLen, 0x11)
	stream := newSSConn(clientConn, m, key, true, nil)
	stream.requestSalt = requestSalt

	go func() {
		salt := seq(m.saltLen, 0x22)
		aead, err := cryptox.NewAEAD(m.aead, sessionSubkey2022(key, salt))
		if err != nil {
			return
		}
		plain := []byte{headerTypeServerStream}
		plain = binary.BigEndian.AppendUint64(plain, uint64(time.Now().Unix()))
		plain = append(plain, requestSalt...)
		plain = binary.BigEndian.AppendUint16(plain, 4)

		out := append([]byte{}, salt...)
		out = append(out, aead.Seal(nil, nonceLE(0), plain, nil)...)
		// The payload chunk the header announced.
		out = append(out, aead.Seal(nil, nonceLE(1), []byte("pong"), nil)...)
		_, _ = serverConn.Write(out)
	}()

	if err := stream.readResponseHeader2022(); err != nil {
		t.Fatalf("a correct response header was rejected: %v", err)
	}
	if stream.pendingDataLen != 4 {
		t.Fatalf("the header announced %d payload bytes, want 4", stream.pendingDataLen)
	}

	buf := make([]byte, 4)
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("read the announced payload: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("payload is %q, want %q", buf, "pong")
	}
}

// --- Configuration -------------------------------------------------------

// TestResolveMethodLengths pins the key and salt lengths the spec's table gives,
// since a mismatch here would silently produce a wrong-length subkey.
func TestResolveMethodLengths(t *testing.T) {
	cases := []struct {
		name    string
		keyLen  int
		saltLen int
		is2022  bool
	}{
		{Method2022AES128GCM, 16, 16, true},
		{Method2022AES256GCM, 32, 32, true},
		{Method2022ChaCha20Poly, 32, 32, true},
		{MethodAES128GCM, 16, 16, false},
		{MethodAES256GCM, 32, 32, false},
		{MethodChaCha20Poly1305, 32, 32, false},
	}
	for _, tc := range cases {
		m := mustMethod(t, tc.name)
		if m.keyLen != tc.keyLen || m.saltLen != tc.saltLen {
			t.Errorf("%s: keyLen=%d saltLen=%d, want %d/%d", tc.name, m.keyLen, m.saltLen, tc.keyLen, tc.saltLen)
		}
		if m.is2022 != tc.is2022 {
			t.Errorf("%s: is2022=%v, want %v", tc.name, m.is2022, tc.is2022)
		}
		// The 2022 spec requires the salt to be the same length as the key.
		if m.is2022 && m.keyLen != m.saltLen {
			t.Errorf("%s: the salt must be the same length as the key", tc.name)
		}
	}
	if maxChunkPayload2022 != 0xFFFF {
		t.Errorf("the 2022 chunk cap is %#x, want 0xFFFF", maxChunkPayload2022)
	}
	if maxChunkPayloadLegacy != 0x3FFF {
		t.Errorf("the legacy chunk cap is %#x, want 0x3FFF", maxChunkPayloadLegacy)
	}
}

// TestRejectsWrongLengthKey proves a 2022 password that decodes to the wrong
// number of bytes is refused rather than truncated or padded.
func TestRejectsWrongLengthKey(t *testing.T) {
	_, _, err := resolveSettings(transport.Settings{
		SettingMethod:   Method2022AES256GCM,
		SettingPassword: base64.StdEncoding.EncodeToString(make([]byte, 16)),
	})
	if err == nil {
		t.Fatal("a 16-byte key was accepted for a 32-byte method")
	}
	if !strings.Contains(err.Error(), "32-byte key") {
		t.Fatalf("error is %v, want it to name the required length", err)
	}

	// A passphrase that is not base64 at all must also be refused: the 2022
	// methods take a raw key, not a password to stretch.
	if _, _, err := resolveSettings(transport.Settings{
		SettingMethod:   Method2022AES256GCM,
		SettingPassword: "not base64 at all!!",
	}); err == nil {
		t.Fatal("a non-base64 password was accepted for a 2022 method")
	}
}

// TestLegacyKeyIsPassphraseStretched confirms the legacy methods still derive
// their key from a passphrase, so the 2022 key handling did not leak into them.
func TestLegacyKeyIsPassphraseStretched(t *testing.T) {
	m := mustMethod(t, MethodAES256GCM)
	got, err := m.deriveKey("a passphrase")
	if err != nil {
		t.Fatalf("deriveKey: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("derived %d bytes, want 32", len(got))
	}
	if !bytes.Equal(got, evpBytesToKey([]byte("a passphrase"), 32)) {
		t.Fatal("the legacy key is not the EVP_BytesToKey result")
	}
}

// --- Replay guard --------------------------------------------------------

// TestReplayGuardExactness proves the guard is exact rather than probabilistic.
//
// The spec forbids a Bloom filter precisely because a false positive would lock
// out a legitimate client, so this checks that an unseen salt is always
// admitted and a seen one is always refused.
func TestReplayGuardExactness(t *testing.T) {
	g := newReplayGuard()
	now := time.Now()
	g.clock = func() time.Time { return now }

	const n = 2000
	salts := make([][]byte, n)
	for i := range salts {
		salts[i] = cryptox.RandomBytes(32)
	}
	for i, s := range salts {
		if !g.check(s) {
			t.Fatalf("salt %d was refused on first use", i)
		}
	}
	for i, s := range salts {
		if g.check(s) {
			t.Fatalf("salt %d was admitted a second time", i)
		}
	}
}

// TestReplayGuardExpires proves a salt is forgotten after the retention window,
// so the table cannot grow without bound.
func TestReplayGuardExpires(t *testing.T) {
	g := newReplayGuard()
	now := time.Now()
	g.clock = func() time.Time { return now }

	salt := cryptox.RandomBytes(32)
	if !g.check(salt) {
		t.Fatal("the first use was refused")
	}
	if g.check(salt) {
		t.Fatal("an immediate replay was admitted")
	}

	// Past the retention window the entry is swept and the salt is admissible
	// again, which is safe because the timestamp check has long since expired.
	now = now.Add(saltRetention + time.Second)
	if !g.check(salt) {
		t.Fatal("a salt was still remembered after the retention window")
	}
}

// TestRequestPaddingIsNonZeroAndInRange checks the padding the client puts in
// its request header.
//
// The spec requires either initial payload or non-zero padding, and caps the
// padding at 900 bytes. This client sends no payload with the header, so it must
// always pad, and a zero-length or over-long pad would make a real peer reject
// the request outright.
func TestRequestPaddingIsNonZeroAndInRange(t *testing.T) {
	m := mustMethod(t, Method2022ChaCha20Poly)
	key := testKey2022(t, m)

	seen := map[int]bool{}
	for i := 0; i < 200; i++ {
		clientConn, serverConn := net.Pipe()

		blob, err := captureClientHeader(t, clientConn, serverConn, m, key)
		clientConn.Close()
		serverConn.Close()
		if err != nil {
			t.Fatalf("capture: %v", err)
		}

		aead, err := cryptox.NewAEAD(m.aead, sessionSubkey2022(key, blob[:m.saltLen]))
		if err != nil {
			t.Fatalf("aead: %v", err)
		}
		varRec := blob[m.saltLen+requestFixedHeaderLen+aead.Overhead():]
		variable, err := aead.Open(nil, nonceLE(1), varRec, nil)
		if err != nil {
			t.Fatalf("open variable header: %v", err)
		}
		_, consumed, err := transport.DecodeAddrFrom(variable)
		if err != nil {
			t.Fatalf("decode address: %v", err)
		}
		padLen := int(binary.BigEndian.Uint16(variable[consumed : consumed+2]))

		if padLen == 0 {
			t.Fatal("the client sent no padding and no payload, which a server must reject")
		}
		if padLen > maxPaddingLength {
			t.Fatalf("padding is %d bytes, over the spec maximum of %d", padLen, maxPaddingLength)
		}
		// The padding is random, so a run of 200 headers should not all agree.
		seen[padLen] = true
	}
	if len(seen) < 10 {
		t.Fatalf("only %d distinct padding lengths in 200 headers, so the padding is not random", len(seen))
	}
}

// TestRelayAcceptsInitialPayloadInHeader proves the relay accepts a client that
// sends its first payload bytes inside the variable-length header.
//
// The reference client does exactly this, so a relay that only tolerated
// padding would interoperate with this build and with nothing else.
func TestRelayAcceptsInitialPayloadInHeader(t *testing.T) {
	m := mustMethod(t, Method2022ChaCha20Poly)
	key := testKey2022(t, m)
	salt := cryptox.RandomBytes(m.saltLen)

	aead, err := cryptox.NewAEAD(m.aead, sessionSubkey2022(key, salt))
	if err != nil {
		t.Fatalf("aead: %v", err)
	}
	addr, err := encodeTarget("127.0.0.1:8080")
	if err != nil {
		t.Fatalf("encode target: %v", err)
	}

	// Zero padding, but an initial payload riding along with the header.
	const initial = "GET / HTTP/1.0\r\n\r\n"
	variable := append([]byte{}, addr...)
	variable = binary.BigEndian.AppendUint16(variable, 0)
	variable = append(variable, initial...)

	fixed := []byte{headerTypeClientStream}
	fixed = binary.BigEndian.AppendUint64(fixed, uint64(time.Now().Unix()))
	fixed = binary.BigEndian.AppendUint16(fixed, uint16(len(variable)))

	blob := append([]byte{}, salt...)
	blob = append(blob, aead.Seal(nil, nonceLE(0), fixed, nil)...)
	blob = append(blob, aead.Seal(nil, nonceLE(1), variable, nil)...)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	go func() { _, _ = clientConn.Write(blob) }()

	stream, err := serverHandshake2022(serverConn, m, key, transport.HandleRequest{})
	if err != nil {
		t.Fatalf("a header carrying initial payload was rejected: %v", err)
	}
	defer stream.Close()

	if got := stream.Request().Target; got != "127.0.0.1:8080" {
		t.Fatalf("decoded target %q", got)
	}
	// The initial payload must be available on the stream, not discarded.
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(initial))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("read the initial payload: %v", err)
	}
	if string(got) != initial {
		t.Fatalf("initial payload is %q, want %q", got, initial)
	}
}

// captureClientHeader runs a client handshake and returns the bytes it wrote,
// which lets a test inspect the header without duplicating the framing.
//
// The reader must run concurrently: a net.Pipe is unbuffered, so the client's
// single Write blocks until the far end reads it.
func captureClientHeader(t *testing.T, clientConn, serverConn net.Conn, m method, key []byte) ([]byte, error) {
	t.Helper()

	ch := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, err := serverConn.Read(buf)
		if err != nil {
			ch <- nil
			return
		}
		ch <- append([]byte{}, buf[:n]...)
	}()

	if _, err := clientHandshake2022(clientConn, m, key, "127.0.0.1:8080", &transport.Request{
		Command: transport.CmdConnectTCP,
		Target:  "127.0.0.1:8080",
	}); err != nil {
		return nil, err
	}
	select {
	case out := <-ch:
		if out == nil {
			return nil, errors.New("the client wrote no header")
		}
		return out, nil
	case <-time.After(3 * time.Second):
		return nil, errors.New("timed out capturing the client header")
	}
}

// --- Helpers -------------------------------------------------------------

// deriveKeyBLAKE3 is the raw BLAKE3 key-derivation primitive.
//
// The vector test calls it directly rather than through sessionSubkey2022,
// because the vector's output is 131 bytes while a subkey is always as long as
// the key: routing it through the wrapper would mean asserting a length the
// wrapper does not produce.
func deriveKeyBLAKE3(dst []byte, ctx string, src []byte) {
	blake3.DeriveKey(dst, ctx, src)
}

// TestConcurrentRelaysDoNotShareState proves the guard is safe under parallel
// handshakes, which a single relay process does routinely.
func TestConcurrentRelaysDoNotShareState(t *testing.T) {
	m := mustMethod(t, Method2022ChaCha20Poly)
	key := testKey2022(t, m)

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			blob := buildRequest2022(t, m, key, cryptox.RandomBytes(m.saltLen), uint64(time.Now().Unix()), "127.0.0.1:8080", 16)
			go func() { _, _ = clientConn.Write(blob) }()

			stream, err := serverHandshake2022(serverConn, m, key, transport.HandleRequest{})
			if err != nil {
				errs <- err
				return
			}
			stream.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("a concurrent handshake failed: %v", err)
	}
}

// TestDialAndHandleOverTCP exercises the exported Dialer and Handler against
// each other over a real socket, which is the seam the unit tests above stub
// out.
func TestDialAndHandleOverTCP(t *testing.T) {
	m := mustMethod(t, Method2022ChaCha20Poly)
	key := testKey2022(t, m)
	settings := testSettings(t, m, key)

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind the echo target: %v", err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()

	relay, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind the relay: %v", err)
	}
	defer relay.Close()

	handler := Handler{}
	go func() {
		for {
			c, err := relay.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				stream, err := handler.Handle(context.Background(), c, transport.HandleRequest{Settings: settings})
				if err != nil {
					return
				}
				defer stream.Close()
				up, err := net.Dial("tcp", stream.Request().Target)
				if err != nil {
					return
				}
				defer up.Close()
				go func() { _, _ = io.Copy(up, stream) }()
				_, _ = io.Copy(stream, up)
			}(c)
		}
	}()

	stream, err := (Dialer{}).Dial(context.Background(), transport.DialRequest{
		ServerAddr: relay.Addr().String(),
		Request: &transport.Request{
			Command: transport.CmdConnectTCP,
			Target:  echo.Addr().String(),
		},
		Settings: settings,
		Timeout:  10 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))

	const payload = "shadowsocks payload"
	if _, err := stream.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("read the echo: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("echoed %q, want %q", got, payload)
	}
}
