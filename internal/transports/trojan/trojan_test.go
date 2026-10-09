package trojan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"porttransit/internal/logx"
	"porttransit/internal/transport"
)

// Trojan is a TLS transport, so every relay-side test has to complete a real
// TLS handshake before it can reach the protocol at all.
//
// net.Pipe is fully synchronous — a Write blocks until the peer reads every
// byte — so the relay half always runs in a goroutine and the test body plays
// the client. Writing a request inline from the test body while the relay half
// was writing (or refusing) would deadlock for the whole test timeout.

// pair returns a connected client/server socket pair for driving the protocol
// halves against each other without touching the network.
func pair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	c, s := net.Pipe()
	t.Cleanup(func() {
		c.Close()
		s.Close()
	})
	return c, s
}

// writeAsync sends a frame from a goroutine.
//
// A synchronous pipe blocks a Write until the peer consumes it, and several
// rejection paths close the connection after reading only part of a request.
// Writing inline would then deadlock the test: the test body would still be
// waiting to finish a write the relay half has already stopped reading.
func writeAsync(conn net.Conn, buf []byte) {
	go func() { _, _ = conn.Write(buf) }()
}

// readN reads exactly n bytes, failing the test on a short read.
//
// The deadline matters: without it a missing reply hangs the test binary until
// the package timeout instead of failing the one test that is broken.
func readN(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return buf
}

// drainAsync consumes everything the relay writes until the connection ends.
//
// This is required on every rejection path, and the reason is subtle: the relay
// closes a *tls.Conn*, and tls.Conn.Close writes a close_notify record before
// closing the socket. On a synchronous pipe that write blocks until the peer
// reads it, so a test body that merely waited for Handle to return would
// deadlock against a relay stuck inside Close. Draining in a goroutine lets the
// relay finish, which is exactly what a real client's read loop would do.
func drainAsync(conn net.Conn) {
	go func() {
		buf := make([]byte, 256)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}()
}

// dialTLSClient performs the client half of the TLS handshake on raw, which is
// what a Trojan client does before it writes its header.
func dialTLSClient(t *testing.T, raw net.Conn) *tls.Conn {
	t.Helper()
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	return tc
}

// handleResult carries the relay half's outcome back to the test body.
type handleResult struct {
	stream transport.Stream
	err    error
}

// runHandle drives Handler.Handle in a goroutine.
func runHandle(conn net.Conn, req transport.HandleRequest) <-chan handleResult {
	out := make(chan handleResult, 1)
	go func() {
		st, err := Handler{}.Handle(context.Background(), conn, req)
		out <- handleResult{st, err}
	}()
	return out
}

// domainAddr encodes a SOCKS5 domain address, built here rather than by the
// product's encoder so the wire assertions are not self-referential.
func domainAddr(host string, port uint16) []byte {
	buf := []byte{transport.AddrTypeDomain, byte(len(host))}
	buf = append(buf, host...)
	return binary.BigEndian.AppendUint16(buf, port)
}

// ipv4Addr encodes a SOCKS5 IPv4 literal address.
func ipv4Addr(ip [4]byte, port uint16) []byte {
	buf := append([]byte{transport.AddrTypeIPv4}, ip[:]...)
	return binary.BigEndian.AppendUint16(buf, port)
}

// trojanFrame assembles the exact byte sequence a Trojan client writes:
// hex(SHA224(password)) CRLF command address CRLF.
func trojanFrame(password string, command byte, addr []byte) []byte {
	buf := []byte(PasswordHash(password))
	buf = append(buf, '\r', '\n', command)
	buf = append(buf, addr...)
	return append(buf, '\r', '\n')
}

// TestPasswordHashKnownVector pins the exact digest Trojan puts on the wire.
//
// The hard-coded value is the whole point: a test that only re-derives the hash
// from the same primitive cannot catch the wrong digest being chosen (SHA-256
// instead of SHA-224, say), and that mistake makes the relay silently reject
// every genuine Trojan client with no diagnostic beyond "authentication
// failed".
func TestPasswordHashKnownVector(t *testing.T) {
	const (
		password = "hunter2"
		want     = "84ca85078d6fa3a9b01dae0242938a9b71c9c6920f8d790505cad7a7"
	)

	got := PasswordHash(password)

	if len(got) != hashLen {
		t.Fatalf("the hash is %d characters, want %d (SHA-224 renders as 56 hex characters)", len(got), hashLen)
	}
	if got != want {
		t.Errorf("PasswordHash(%q) = %q, want %q", password, got, want)
	}

	// Independently re-derive it so the literal above is not the only witness.
	sum := sha256.Sum224([]byte(password))
	if hex.EncodeToString(sum[:]) != got {
		t.Error("the hash is not hex(SHA224(password))")
	}

	// Trojan clients send lowercase hex. An uppercase rendering would still be
	// 56 bytes and would never match the relay's constant-time comparison, so
	// the case is load-bearing rather than cosmetic.
	for i := 0; i < len(got); i++ {
		c := got[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		t.Fatalf("character %d of the hash is %q, which is not lowercase hex", i, c)
	}
}

// TestPasswordHashIsStableAndDistinct proves the hash is a pure function of the
// password: a client and a relay that derive it independently must agree, and
// two different passwords must not collide into the same wire prefix, which
// would let one user authenticate as another.
func TestPasswordHashIsStableAndDistinct(t *testing.T) {
	first := PasswordHash("correct horse battery staple")
	if again := PasswordHash("correct horse battery staple"); again != first {
		t.Errorf("the hash of one password is not stable: %q vs %q", first, again)
	}

	other := PasswordHash("correct horse battery stapl")
	if other == first {
		t.Error("two different passwords produced the same hash")
	}

	// The empty password is not special-cased by the hash, only by the caller,
	// which refuses it; the hash itself must still be a full 56 characters so
	// no short prefix can ever be compared.
	if len(PasswordHash("")) != hashLen {
		t.Errorf("the hash of the empty password is %d characters, want %d", len(PasswordHash("")), hashLen)
	}
}

// TestCommandByteValues pins the two command bytes Trojan defines. They are
// inherited from SOCKS5 rather than VLESS, and a swapped value would send a UDP
// request as a TCP connect with no error anywhere.
func TestCommandByteValues(t *testing.T) {
	if commandConnect != 0x01 {
		t.Errorf("commandConnect = 0x%02x, want 0x01", commandConnect)
	}
	if commandUDP != 0x03 {
		t.Errorf("commandUDP = 0x%02x, want 0x03", commandUDP)
	}
	if commandConnect == commandUDP {
		t.Fatal("the CONNECT and UDP command bytes are identical")
	}
}

// selfSigned returns a certificate for the relay half of a loopback test.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	cert, err := transport.GenerateSelfSigned(transport.SelfSignedOptions{})
	if err != nil {
		t.Fatalf("generate the relay certificate: %v", err)
	}
	return cert
}

// captureDialHeader runs a TLS relay on a loopback listener, lets Dialer.Dial
// complete, and returns the raw bytes the client wrote after the handshake.
//
// A real listener is used rather than a pipe because Dial opens its own TCP
// connection: there is no seam to inject a pipe, and the exact byte layout is
// precisely what has to be proven. The port is ephemeral, so nothing here
// depends on a fixed port being free.
func captureDialHeader(t *testing.T, want int, req transport.DialRequest) []byte {
	t.Helper()

	cert := selfSigned(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	got := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer conn.Close()
		tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tc.Handshake(); err != nil {
			got <- nil
			return
		}
		_ = tc.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, want)
		if _, err := io.ReadFull(tc, buf); err != nil {
			got <- nil
			return
		}
		got <- buf
	}()

	req.ServerAddr = ln.Addr().String()
	req.Timeout = 5 * time.Second
	stream, err := Dialer{}.Dial(context.Background(), req)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { stream.Close() })

	select {
	case buf := <-got:
		if buf == nil {
			t.Fatalf("the relay did not receive a %d-byte header", want)
		}
		return buf
	case <-time.After(5 * time.Second):
		t.Fatal("the relay never received the header")
		return nil
	}
}

// TestDialWritesExactHeaderForDomain asserts the whole client frame byte for
// byte against a domain target.
//
// A silent off-by-one in this header is the class of bug this repository has
// already suffered: a transport that consumed one byte too many left every
// request misaligned and stalled. The two CRLF pairs in particular are easy to
// drop without any test failing except one that compares raw bytes.
func TestDialWritesExactHeaderForDomain(t *testing.T) {
	const password = "hunter2"

	addr := domainAddr("example.com", 443)
	got := captureDialHeader(t, hashLen+2+1+len(addr)+2, transport.DialRequest{
		Request:  &transport.Request{Command: transport.CmdConnectTCP, Target: "example.com:443"},
		Settings: transport.Settings{SettingPassword: password},
	})

	// Assembled from the published test vector rather than from PasswordHash,
	// so the hash bytes are checked here too.
	want := []byte("84ca85078d6fa3a9b01dae0242938a9b71c9c6920f8d790505cad7a7")
	want = append(want, '\r', '\n')
	want = append(want, commandConnect)
	want = append(want, addr...)
	want = append(want, '\r', '\n')

	if !bytes.Equal(got, want) {
		t.Fatalf("the header is\n  % x\nwant\n  % x", got, want)
	}
	// Spell the layout out so a failure above is readable without decoding hex.
	if got[hashLen] != '\r' || got[hashLen+1] != '\n' {
		t.Errorf("the CRLF after the hash is %q, want \\r\\n", got[hashLen:hashLen+2])
	}
	if got[hashLen+2] != commandConnect {
		t.Errorf("the command byte is 0x%02x, want 0x%02x", got[hashLen+2], commandConnect)
	}
	if got[len(got)-2] != '\r' || got[len(got)-1] != '\n' {
		t.Errorf("the trailing CRLF is %q, want \\r\\n", got[len(got)-2:])
	}
}

// TestDialWritesExactHeaderForIPv4 asserts the IPv4 literal encoding, which is
// a different address type and a different length from the domain form.
func TestDialWritesExactHeaderForIPv4(t *testing.T) {
	const password = "hunter2"

	addr := ipv4Addr([4]byte{93, 184, 216, 34}, 443)
	got := captureDialHeader(t, hashLen+2+1+len(addr)+2, transport.DialRequest{
		Request:  &transport.Request{Command: transport.CmdConnectTCP, Target: "93.184.216.34:443"},
		Settings: transport.Settings{SettingPassword: password},
	})

	want := []byte(PasswordHash(password))
	want = append(want, '\r', '\n', commandConnect)
	want = append(want, addr...)
	want = append(want, '\r', '\n')

	if !bytes.Equal(got, want) {
		t.Fatalf("the header is\n  % x\nwant\n  % x", got, want)
	}
	// The literal must go on the wire as four binary bytes with the address
	// type 0x01, not as a dotted-quad string: a relay that received the text
	// form would read the first character as the port's high byte.
	if got[hashLen+3] != transport.AddrTypeIPv4 {
		t.Errorf("the address type is 0x%02x, want 0x%02x (IPv4)", got[hashLen+3], transport.AddrTypeIPv4)
	}
	if !bytes.Equal(got[hashLen+4:hashLen+8], []byte{93, 184, 216, 34}) {
		t.Errorf("the address bytes are % x, want 5d b8 d8 22", got[hashLen+4:hashLen+8])
	}
	if !bytes.Equal(got[hashLen+8:hashLen+10], []byte{0x01, 0xBB}) {
		t.Errorf("the port bytes are % x, want 01 bb (443, big endian)", got[hashLen+8:hashLen+10])
	}
}

// TestDialWritesUDPCommandByte proves a UDP association request is marked as
// such on the wire, because the relay routes on that byte: sending 0x01 instead
// would open a TCP connection to the target and never carry a datagram.
func TestDialWritesUDPCommandByte(t *testing.T) {
	addr := domainAddr("dns.example.com", 53)
	got := captureDialHeader(t, hashLen+2+1+len(addr)+2, transport.DialRequest{
		Request:  &transport.Request{Command: transport.CmdUDPAssociate, Target: "dns.example.com:53"},
		Settings: transport.Settings{SettingPassword: "hunter2"},
	})

	if got[hashLen+2] != commandUDP {
		t.Errorf("the command byte is 0x%02x, want 0x%02x (UDP ASSOCIATE)", got[hashLen+2], commandUDP)
	}
	if !bytes.Equal(got[hashLen+3:len(got)-2], addr) {
		t.Errorf("the address is % x, want % x", got[hashLen+3:len(got)-2], addr)
	}
}

// TestDialRequiresPassword proves the client refuses to open a connection with
// no password rather than sending a header the relay would treat as a probe and
// forward to the fallback site.
func TestDialRequiresPassword(t *testing.T) {
	_, err := Dialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: "relay.example:443",
		Request:    &transport.Request{Command: transport.CmdConnectTCP, Target: "example.com:443"},
	})
	if err == nil {
		t.Fatal("Dial accepted an empty password")
	}
	if !strings.Contains(err.Error(), SettingPassword) {
		t.Errorf("the error does not name the missing setting: %v", err)
	}
}

// TestDialWithNilRequestIsTreatedAsPing proves a nil Request is a liveness
// probe rather than a crash.
//
// The relay's own health checker and the Web GUI latency test dial with a
// request that carries no target, so the transport must substitute the relay's
// address instead of dereferencing a nil pointer inside the handshake.
func TestDialWithNilRequestIsTreatedAsPing(t *testing.T) {
	cert := selfSigned(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	// The probe target is the relay's own listening address, so the expected
	// address bytes are built from the listener rather than hard-coded.
	wantAddr, err := transport.EncodeAddr(nil, ln.Addr().String())
	if err != nil {
		t.Fatalf("encode the relay address: %v", err)
	}

	got := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer conn.Close()
		tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tc.Handshake(); err != nil {
			got <- nil
			return
		}
		_ = tc.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, hashLen+2+1+len(wantAddr)+2)
		if _, err := io.ReadFull(tc, buf); err != nil {
			got <- nil
			return
		}
		got <- buf
	}()

	stream, err := Dialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: ln.Addr().String(),
		Request:    nil,
		Settings:   transport.Settings{SettingPassword: "hunter2"},
		Timeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial with a nil request: %v", err)
	}
	defer stream.Close()

	if got := stream.Request(); got == nil || got.Command != transport.CmdConnectTCP {
		t.Fatalf("the probe stream reports %+v, want a TCP connect", got)
	}
	if got := stream.Request().Meta["ping"]; got != "true" {
		t.Errorf("the probe is not marked as a ping: Meta = %v", stream.Request().Meta)
	}

	buf := <-got
	if buf == nil {
		t.Fatal("the relay did not receive the probe header")
	}
	// The probe must name the relay's own listening address: that is what makes
	// the round trip measure the full handshake instead of a third party.
	if !bytes.Equal(buf[hashLen+3:], append(append([]byte(nil), wantAddr...), '\r', '\n')) {
		t.Errorf("the probe header names % x, want the relay address % x", buf[hashLen+3:], wantAddr)
	}
}

// TestHandlerParsesTCPHandshake proves the relay half reaches the point where
// it hands back a stream naming the target, which is the whole contract of the
// transport.
func TestHandlerParsesTCPHandshake(t *testing.T) {
	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: transport.Settings{SettingPassword: "hunter2"},
		Timeout:  5 * time.Second,
		Logger:   logx.Discard(),
	})

	tc := dialTLSClient(t, client)
	writeAsync(tc, trojanFrame("hunter2", commandConnect, domainAddr("example.com", 443)))

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Handle: %v", r.err)
		}
		defer r.stream.Close()
		if r.stream == nil {
			t.Fatal("Handle returned no error but also no stream")
		}
		if got := r.stream.Request().Target; got != "example.com:443" {
			t.Errorf("the stream target is %q, want example.com:443", got)
		}
		if got := r.stream.TransportName(); got != Name {
			t.Errorf("the stream transport is %q, want %q", got, Name)
		}
		if got := r.stream.Request().Command; got != transport.CmdConnectTCP {
			t.Errorf("the stream command is %v, want a TCP connect", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestHandlerParsesUDPHandshake proves the UDP command byte is translated into
// the relay's own command, since the two enumerations are not the same numbers.
func TestHandlerParsesUDPHandshake(t *testing.T) {
	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: transport.Settings{SettingPassword: "hunter2"},
		Timeout:  5 * time.Second,
	})

	tc := dialTLSClient(t, client)
	writeAsync(tc, trojanFrame("hunter2", commandUDP, ipv4Addr([4]byte{1, 2, 3, 4}, 53)))

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Handle: %v", r.err)
		}
		defer r.stream.Close()
		if got := r.stream.Request().Command; got != transport.CmdUDPAssociate {
			t.Errorf("the stream command is %v, want a UDP associate", got)
		}
		if got := r.stream.Request().Target; got != "1.2.3.4:53" {
			t.Errorf("the stream target is %q, want 1.2.3.4:53", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestHandlerTreatsAnyOtherCommandAsConnect documents the lenient mapping: only
// 0x03 is treated as UDP and every other byte falls back to CONNECT.
//
// This is worth pinning because the password has already authenticated the
// peer, so an unknown command byte cannot be an attack; but a future refactor
// that started rejecting unknown commands would break clients that send a
// non-standard value, and the change would otherwise be invisible.
func TestHandlerTreatsAnyOtherCommandAsConnect(t *testing.T) {
	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: transport.Settings{SettingPassword: "hunter2"},
		Timeout:  5 * time.Second,
	})

	tc := dialTLSClient(t, client)
	writeAsync(tc, trojanFrame("hunter2", 0x02, ipv4Addr([4]byte{1, 2, 3, 4}, 80)))

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Handle: %v", r.err)
		}
		defer r.stream.Close()
		if got := r.stream.Request().Command; got != transport.CmdConnectTCP {
			t.Errorf("an unknown command byte produced %v, want a TCP connect", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestHandlerForwardsWrongPasswordToFallback proves the camouflage works: a
// client that fails authentication is piped to a real website, bytes and all,
// rather than being rejected.
//
// This is the property that makes a Trojan relay indistinguishable from the
// HTTPS site it imitates, and it is also what internal/server counts as a
// fallback, which it recognises by the literal text "forwarded to fallback".
func TestHandlerForwardsWrongPasswordToFallback(t *testing.T) {
	fallback, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for the fallback site: %v", err)
	}
	t.Cleanup(func() { fallback.Close() })

	// A probe's request is not a Trojan header at all; the fallback must see it
	// verbatim, including the part the relay had already read as the prelude.
	frame := trojanFrame("a-wrong-password", commandConnect, domainAddr("example.com", 443))
	received := make(chan []byte, 1)
	go func() {
		conn, err := fallback.Accept()
		if err != nil {
			received <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, len(frame))
		if _, err := io.ReadFull(conn, buf); err != nil {
			received <- nil
			return
		}
		received <- buf
		// Keep draining so the relay's copy loop can finish once the client
		// half goes away.
		_, _ = io.Copy(io.Discard, conn)
	}()

	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: transport.Settings{
			SettingPassword:     "hunter2",
			SettingFallbackAddr: fallback.Addr().String(),
		},
		Timeout: 5 * time.Second,
		Logger:  logx.Discard(),
	})

	tc := dialTLSClient(t, client)
	writeAsync(tc, frame)

	select {
	case got := <-received:
		if got == nil {
			t.Fatal("the fallback site received fewer bytes than the client sent")
		}
		if !bytes.Equal(got, frame) {
			t.Errorf("the fallback received\n  % x\nwant the client's bytes verbatim\n  % x", got, frame)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the fallback site was never contacted")
	}

	// Closing the client half lets the relay's copy loop finish and report.
	_ = client.Close()

	select {
	case r := <-done:
		if r.stream != nil {
			t.Error("a failed authentication still produced a stream")
		}
		if !errors.Is(r.err, ErrFallbackHandled) {
			t.Fatalf("Handle returned %v, want ErrFallbackHandled", r.err)
		}
		// The relay's statistics classify a fallback by this exact substring, so
		// rewording the sentinel would silently start counting camouflage as a
		// failure.
		if !strings.Contains(r.err.Error(), "forwarded to fallback") {
			t.Errorf("the error %q must contain \"forwarded to fallback\"", r.err.Error())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return after the fallback finished")
	}
}

// TestHandlerRejectsWrongPasswordWithoutFallback proves a relay with no
// fallback configured refuses the connection and says so, rather than serving
// an unauthenticated client.
func TestHandlerRejectsWrongPasswordWithoutFallback(t *testing.T) {
	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: transport.Settings{SettingPassword: "hunter2"},
		Timeout:  5 * time.Second,
	})

	tc := dialTLSClient(t, client)
	writeAsync(tc, trojanFrame("a-wrong-password", commandConnect, domainAddr("example.com", 443)))
	drainAsync(tc)

	select {
	case r := <-done:
		if r.stream != nil {
			t.Error("an unauthenticated client was handed a stream")
		}
		if !errors.Is(r.err, transport.ErrAuthFailed) {
			t.Fatalf("Handle returned %v, want ErrAuthFailed", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestHandlerRejectsMissingTrailingCRLF proves a header that is otherwise
// correct but lacks its final CRLF is refused as a protocol violation.
//
// Without the check the parser would accept a truncated frame and then treat
// the first two payload bytes as the terminator, which shifts the entire stream
// by two bytes — the exact failure mode this repository has already shipped.
func TestHandlerRejectsMissingTrailingCRLF(t *testing.T) {
	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: transport.Settings{SettingPassword: "hunter2"},
		Timeout:  5 * time.Second,
	})

	tc := dialTLSClient(t, client)
	frame := trojanFrame("hunter2", commandConnect, domainAddr("example.com", 443))
	// Keep the length but corrupt the terminator.
	frame[len(frame)-2], frame[len(frame)-1] = '\n', '\n'
	writeAsync(tc, frame)
	drainAsync(tc)

	select {
	case r := <-done:
		if r.stream != nil {
			t.Error("a header without its trailing CRLF was accepted")
		}
		if !errors.Is(r.err, transport.ErrProtocol) {
			t.Fatalf("Handle returned %v, want ErrProtocol", r.err)
		}
		if !strings.Contains(r.err.Error(), "CRLF") {
			t.Errorf("the error does not name the missing CRLF: %v", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestHandlerRejectsBadAddressType proves an address type the relay cannot
// parse is refused rather than guessed at.
func TestHandlerRejectsBadAddressType(t *testing.T) {
	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: transport.Settings{SettingPassword: "hunter2"},
		Timeout:  5 * time.Second,
	})

	tc := dialTLSClient(t, client)
	// 0x09 is not a SOCKS5 address type. The frame is otherwise well formed, so
	// only the type byte can be what the relay objects to.
	addr := append([]byte{0x09}, []byte{0, 0, 0, 0, 0, 80}...)
	writeAsync(tc, trojanFrame("hunter2", commandConnect, addr))
	drainAsync(tc)

	select {
	case r := <-done:
		if r.stream != nil {
			t.Error("an undefined address type was accepted")
		}
		if r.err == nil {
			t.Fatal("Handle accepted an undefined address type")
		}
		if !errors.Is(r.err, transport.ErrBadAddress) {
			t.Errorf("Handle returned %v, want ErrBadAddress", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestHandlerRejectsZeroLengthDomain proves a domain with no name is refused,
// since a zero-length name would otherwise decode to a target of ":port" and
// the relay would dial its own host.
func TestHandlerRejectsZeroLengthDomain(t *testing.T) {
	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: transport.Settings{SettingPassword: "hunter2"},
		Timeout:  5 * time.Second,
	})

	tc := dialTLSClient(t, client)
	writeAsync(tc, trojanFrame("hunter2", commandConnect, []byte{transport.AddrTypeDomain, 0x00, 0x00, 0x50}))
	drainAsync(tc)

	select {
	case r := <-done:
		if r.stream != nil {
			t.Error("a zero-length domain was accepted")
		}
		if r.err == nil {
			t.Fatal("Handle accepted a zero-length domain")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestHandlerTreatsATruncatedPreludeAsNotTrojan proves a client that vanishes
// mid-hash is never mistaken for an authenticated one.
//
// A short read is the normal shape of a prober's traffic — an HTTP request is
// shorter than the 56-byte hash — so the important property is that it yields
// no stream, whichever error path it takes.
func TestHandlerTreatsATruncatedPreludeAsNotTrojan(t *testing.T) {
	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: transport.Settings{SettingPassword: "hunter2"},
		Timeout:  5 * time.Second,
	})

	tc := dialTLSClient(t, client)
	// 30 bytes is fewer than hashLen+2, so the relay cannot have a full hash.
	// The write is inline because the relay is guaranteed to consume it while
	// it waits for the rest of the fixed-length prelude.
	if _, err := tc.Write([]byte("GET / HTTP/1.1\r\nHost: probe.exam")); err != nil {
		t.Fatalf("write the truncated prelude: %v", err)
	}
	_ = client.Close()

	select {
	case r := <-done:
		if r.stream != nil {
			t.Fatal("a truncated prelude produced a stream")
		}
		if r.err == nil {
			t.Fatal("a truncated prelude was accepted")
		}
		// The relay either forwards the fragment to a fallback (there is none
		// configured here, so that becomes ErrAuthFailed) or reports the read
		// failure. Both are refusals; a successful parse would not be.
		if !errors.Is(r.err, transport.ErrAuthFailed) {
			t.Logf("note: the truncated prelude failed with %v rather than ErrAuthFailed", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestHandlerRejectsMissingPassword proves a relay with no password configured
// refuses every connection instead of authenticating everyone.
func TestHandlerRejectsMissingPassword(t *testing.T) {
	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{Timeout: 2 * time.Second})

	_ = client.Close()

	select {
	case r := <-done:
		if r.stream != nil {
			t.Fatal("a relay with no password handed out a stream")
		}
		if r.err == nil || !strings.Contains(r.err.Error(), SettingPassword) {
			t.Fatalf("Handle returned %v, want an error naming the missing password", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestNilLoggerHandshake proves a handshake with no logger configured does not
// panic.
//
// This was a real panic in this repository: a loggerFor helper returned a nil
// interface, and the first method call on it took down the whole relay from
// inside the handshake path.
func TestNilLoggerHandshake(t *testing.T) {
	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: transport.Settings{SettingPassword: "hunter2"},
		Timeout:  5 * time.Second,
		Logger:   nil,
	})

	tc := dialTLSClient(t, client)
	writeAsync(tc, trojanFrame("hunter2", commandConnect, domainAddr("example.com", 443)))

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Handle with a nil logger: %v", r.err)
		}
		defer r.stream.Close()
		if got := r.stream.Request().Target; got != "example.com:443" {
			t.Errorf("the stream target is %q, want example.com:443", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestNilLoggerOnFallbackFailurePath proves the logging inside the fallback
// path is nil-safe too, because that is where a misconfigured fallback is
// reported and where a panic would be hardest to attribute.
func TestNilLoggerOnFallbackFailurePath(t *testing.T) {
	// An address that is bound and then released: dialling it is refused
	// immediately, without depending on any fixed port being free.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()

	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: transport.Settings{
			SettingPassword:     "hunter2",
			SettingFallbackAddr: deadAddr,
		},
		Timeout: 5 * time.Second,
		Logger:  nil,
	})

	tc := dialTLSClient(t, client)
	writeAsync(tc, trojanFrame("a-wrong-password", commandConnect, domainAddr("example.com", 443)))
	drainAsync(tc)

	select {
	case r := <-done:
		if r.stream != nil {
			t.Fatal("a failed fallback dial produced a stream")
		}
		if r.err == nil {
			t.Fatal("a failed fallback dial was reported as success")
		}
		if errors.Is(r.err, ErrFallbackHandled) {
			t.Errorf("Handle claimed the connection was forwarded although the dial failed: %v", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestLoggerForNilIsUsable proves the adapter returns a working logger rather
// than a nil interface, which is the fix for the panic described above.
func TestLoggerForNilIsUsable(t *testing.T) {
	log := loggerFor(nil)
	if log == nil {
		t.Fatal("loggerFor(nil) returned a nil interface, which panics on first use")
	}
	// Every method the transports call must be safe on the substitute.
	log.Debug("trojan: test", "key", "value")
	log.Info("trojan: test", "key", "value")
	log.Warn("trojan: test", "key", "value")
	log.Error("trojan: test", "key", "value")

	// A real logger must be passed through unchanged so diagnostics are not
	// silently swallowed.
	if got := loggerFor(logx.Discard()); got == nil {
		t.Error("loggerFor returned nil for a non-nil logger")
	}
}

// TestRegistrationAndMetadata proves the transport is discoverable under the
// name a configuration file would use, with the conventional port.
func TestRegistrationAndMetadata(t *testing.T) {
	if Name != "trojan" {
		t.Errorf("Name = %q, want \"trojan\"", Name)
	}

	f, ok := transport.Lookup(Name)
	if !ok {
		t.Fatalf("transport.Lookup(%q) found nothing", Name)
	}
	if f.DefaultPort != DefaultPort {
		t.Errorf("DefaultPort = %d, want %d", f.DefaultPort, DefaultPort)
	}
	if DefaultPort != 443 {
		t.Errorf("DefaultPort = %d, want 443 (Trojan is presented as HTTPS)", DefaultPort)
	}
	// Trojan carries the target inside its own header rather than exchanging a
	// PortTransit preamble, which is what tells the GUI not to wrap it.
	if !f.NativeHeader {
		t.Error("the factory does not declare a native header")
	}

	d, h := f.Build()
	if d == nil || h == nil {
		t.Fatal("Build returned a nil dialer or handler")
	}
	if d.Name() != Name {
		t.Errorf("the dialer is registered as %q, want %q", d.Name(), Name)
	}
	if h.Name() != Name {
		t.Errorf("the handler is registered as %q, want %q", h.Name(), Name)
	}
}

// TestSettingsKeysAreStable pins the configuration keys, because a renamed key
// is silently ignored: the relay would fall back to the default value and a
// working configuration would start behaving differently with no error.
func TestSettingsKeysAreStable(t *testing.T) {
	want := map[string]string{
		SettingPassword:           "password",
		SettingServerName:         "serverName",
		SettingInsecureSkipVerify: "insecure",
		SettingCertFingerprint:    "certFingerprint",
		SettingCertFile:           "certFile",
		SettingKeyFile:            "keyFile",
		SettingFallbackAddr:       "fallbackAddr",
		SettingFallbackSNI:        "fallbackServerName",
		SettingTimeout:            "timeout",
		SettingMinVersion:         "minVersion",
	}
	for got, expected := range want {
		if got != expected {
			t.Errorf("a settings key is %q, want %q", got, expected)
		}
	}
}

// TestMinVersionPinsTLS proves the TLS floor is honoured, since a relay that
// silently accepted TLS 1.0 would be trivially downgraded.
func TestMinVersionPinsTLS(t *testing.T) {
	if got := minVersion("1.3"); got != tls.VersionTLS13 {
		t.Errorf("minVersion(\"1.3\") = %d, want TLS 1.3", got)
	}
	// Anything unrecognised must land on the safe default rather than 1.0.
	for _, in := range []string{"", "1.2", "garbage", "1.0", "ssl3"} {
		if got := minVersion(in); got != tls.VersionTLS12 {
			t.Errorf("minVersion(%q) = %d, want TLS 1.2", in, got)
		}
	}
}
