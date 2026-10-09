package socks5

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"porttransit/internal/transport"
)

// pair returns a connected client/server socket pair for driving the protocol
// halves against each other without touching the network.
//
// net.Pipe is fully synchronous: a Write blocks until the peer reads every
// byte. The tests therefore always run the server half in a goroutine and let
// the test body act as the client, because a server half that writes a reply
// while the test body waits for its return value would deadlock.
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
// protocol paths write a refusal after reading only the fixed part of a
// request. Writing inline would therefore deadlock the test: the server would
// be waiting to write its reply while the test body was still waiting to
// finish writing the request the server has already stopped reading.
func writeAsync(conn net.Conn, buf []byte) {
	go func() { _, _ = conn.Write(buf) }()
}

// readN reads exactly n bytes, failing the test on a short read.
func readN(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return buf
}

// requestBytes builds a SOCKS5 request frame for a CONNECT to an IPv4 literal.
func requestBytes(command byte, atyp byte, addr []byte) []byte {
	buf := []byte{version5, command, 0x00, atyp}
	buf = append(buf, addr...)
	return buf
}

// runServerRequest drives serverRequest in a goroutine and returns its result.
func runServerRequest(conn net.Conn) <-chan struct {
	command byte
	target  string
	err     error
} {
	out := make(chan struct {
		command byte
		target  string
		err     error
	}, 1)
	go func() {
		command, target, err := serverRequest(conn)
		out <- struct {
			command byte
			target  string
			err     error
		}{command, target, err}
	}()
	return out
}

// TestServerRequestParsesConnect proves the relay decodes a CONNECT request and
// its target, which is the whole point of the transport.
func TestServerRequestParsesConnect(t *testing.T) {
	client, server := pair(t)
	done := runServerRequest(server)

	// 93.184.216.34:443
	_, _ = client.Write(requestBytes(cmdConnect, transport.AddrTypeIPv4, []byte{93, 184, 216, 34, 0x01, 0xBB}))

	got := <-done
	if got.err != nil {
		t.Fatalf("serverRequest: %v", got.err)
	}
	if got.command != cmdConnect {
		t.Errorf("command = 0x%02x, want CONNECT", got.command)
	}
	if got.target != "93.184.216.34:443" {
		t.Errorf("target = %q, want 93.184.216.34:443", got.target)
	}
}

// TestServerRequestParsesDomain proves a domain target is decoded, which is
// what a client sends when it has not resolved the name itself.
func TestServerRequestParsesDomain(t *testing.T) {
	client, server := pair(t)
	done := runServerRequest(server)

	host := "example.com"
	addr := append([]byte{byte(len(host))}, host...)
	addr = append(addr, 0x00, 0x50) // port 80
	_, _ = client.Write(requestBytes(cmdConnect, transport.AddrTypeDomain, addr))

	got := <-done
	if got.err != nil {
		t.Fatalf("serverRequest: %v", got.err)
	}
	if got.target != "example.com:80" {
		t.Errorf("target = %q, want example.com:80", got.target)
	}
}

// TestServerRequestParsesUDPAssociate proves the UDP command is recognised, so
// the relay can route it to its datagram path.
func TestServerRequestParsesUDPAssociate(t *testing.T) {
	client, server := pair(t)
	done := runServerRequest(server)

	_, _ = client.Write(requestBytes(cmdUDP, transport.AddrTypeIPv4, []byte{0, 0, 0, 0, 0, 0}))

	got := <-done
	if got.err != nil {
		t.Fatalf("serverRequest: %v", got.err)
	}
	if got.command != cmdUDP {
		t.Errorf("command = 0x%02x, want UDP ASSOCIATE", got.command)
	}
}

// TestServerRequestRejectsUnsupportedCommand proves BIND is refused with the
// proper reply code rather than being misread as CONNECT.
func TestServerRequestRejectsUnsupportedCommand(t *testing.T) {
	client, server := pair(t)
	done := runServerRequest(server)

	writeAsync(client, requestBytes(0x02 /* BIND */, transport.AddrTypeIPv4, []byte{0, 0, 0, 0, 0, 0}))

	// The refusal reply must be drained or the server half blocks on its write.
	reply := readN(t, client, 10)
	if reply[1] != replyCommandNotSupp {
		t.Errorf("the reply code is 0x%02x, want 0x%02x (command not supported)", reply[1], replyCommandNotSupp)
	}

	got := <-done
	if got.err == nil {
		t.Fatal("serverRequest accepted a BIND command")
	}
	if !strings.Contains(got.err.Error(), "not supported") {
		t.Errorf("the error does not name the problem: %v", got.err)
	}
}

// TestServerRequestRejectsBadVersion proves a non-SOCKS5 first byte is refused
// rather than parsed as a request, which is what stops an unrelated protocol's
// traffic from being misinterpreted.
func TestServerRequestRejectsBadVersion(t *testing.T) {
	client, server := pair(t)
	done := runServerRequest(server)

	writeAsync(client, append([]byte{0x04}, requestBytes(cmdConnect, transport.AddrTypeIPv4, []byte{1, 2, 3, 4, 0, 80})...))

	if got := <-done; got.err == nil {
		t.Fatal("serverRequest accepted a SOCKS4 request")
	}
}

// TestServerRequestRejectsNonZeroReserved proves the reserved byte is checked,
// since a non-zero value indicates a client that is not speaking RFC 1928.
func TestServerRequestRejectsNonZeroReserved(t *testing.T) {
	client, server := pair(t)
	done := runServerRequest(server)

	buf := requestBytes(cmdConnect, transport.AddrTypeIPv4, []byte{1, 2, 3, 4, 0, 80})
	buf[2] = 0xFF
	writeAsync(client, buf)

	if got := <-done; got.err == nil {
		t.Fatal("serverRequest accepted a non-zero reserved byte")
	}
}

// TestServerGreetingSelectsNoAuth proves the relay offers no-authentication
// when it is not configured with credentials.
func TestServerGreetingSelectsNoAuth(t *testing.T) {
	client, server := pair(t)

	done := make(chan error, 1)
	go func() { done <- serverGreeting(server, false) }()

	_, _ = client.Write([]byte{version5, 1, methodNoAuth})
	reply := readN(t, client, 2)

	if reply[0] != version5 || reply[1] != methodNoAuth {
		t.Errorf("the selection is %v, want version 5 with no-auth", reply)
	}
	if err := <-done; err != nil {
		t.Fatalf("serverGreeting: %v", err)
	}
}

// TestServerGreetingSelectsUserPass proves the relay requires authentication
// when it is configured with credentials, so an unauthenticated client is not
// silently admitted.
func TestServerGreetingSelectsUserPass(t *testing.T) {
	client, server := pair(t)

	done := make(chan error, 1)
	go func() { done <- serverGreeting(server, true) }()

	_, _ = client.Write([]byte{version5, 2, methodNoAuth, methodUserPass})
	reply := readN(t, client, 2)

	if reply[1] != methodUserPass {
		t.Errorf("the selection is 0x%02x, want 0x%02x (username/password)", reply[1], methodUserPass)
	}
	if err := <-done; err != nil {
		t.Fatalf("serverGreeting: %v", err)
	}
}

// TestServerGreetingRejectsWhenNoMethodMatches proves a client offering only a
// method the relay does not accept is refused with the 0xFF reply, as RFC 1928
// requires, rather than the connection being silently left open.
func TestServerGreetingRejectsWhenNoMethodMatches(t *testing.T) {
	client, server := pair(t)

	done := make(chan error, 1)
	go func() { done <- serverGreeting(server, false) }()

	_, _ = client.Write([]byte{version5, 1, methodUserPass})
	reply := readN(t, client, 2)

	if reply[1] != methodNone {
		t.Errorf("the refusal reply is 0x%02x, want 0xFF", reply[1])
	}
	if err := <-done; err == nil {
		t.Fatal("serverGreeting accepted an unsupported method")
	}
}

// authFrame builds an RFC 1929 username/password frame.
func authFrame(user, pass string) []byte {
	buf := []byte{authVersion, byte(len(user))}
	buf = append(buf, user...)
	buf = append(buf, byte(len(pass)))
	buf = append(buf, pass...)
	return buf
}

// TestServerAuthAcceptsCorrectCredentials proves the RFC 1929 exchange accepts
// a matching username and password.
func TestServerAuthAcceptsCorrectCredentials(t *testing.T) {
	client, server := pair(t)

	done := make(chan error, 1)
	go func() { done <- serverAuth(server, "alice", "s3cret") }()

	_, _ = client.Write(authFrame("alice", "s3cret"))
	reply := readN(t, client, 2)

	if reply[1] != authOK {
		t.Errorf("the auth reply is 0x%02x, want 0x%02x (success)", reply[1], authOK)
	}
	if err := <-done; err != nil {
		t.Fatalf("serverAuth: %v", err)
	}
}

// TestServerAuthRejectsWrongCredentials proves a wrong password is refused,
// because the relay must not forward for an unauthenticated client.
func TestServerAuthRejectsWrongCredentials(t *testing.T) {
	client, server := pair(t)

	done := make(chan error, 1)
	go func() { done <- serverAuth(server, "alice", "s3cret") }()

	_, _ = client.Write(authFrame("alice", "wrong"))
	reply := readN(t, client, 2)

	if reply[1] != authFail {
		t.Errorf("the auth reply is 0x%02x, want 0x%02x (failure)", reply[1], authFail)
	}
	if err := <-done; err == nil {
		t.Fatal("serverAuth accepted a wrong password")
	}
}

// TestWriteSuccessReply proves the success reply has the exact ten-byte shape a
// SOCKS5 client expects, since a client that cannot parse it will report a
// working tunnel as broken.
func TestWriteSuccessReply(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSuccessReply(&buf); err != nil {
		t.Fatalf("WriteSuccessReply: %v", err)
	}

	got := buf.Bytes()
	want := []byte{version5, replySuccess, 0x00, transport.AddrTypeIPv4, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(got, want) {
		t.Errorf("the reply is %v, want %v", got, want)
	}
	// The bound address must be zeroed rather than naming the relay, which
	// would leak its position in the path.
	if got[4] != 0 || got[5] != 0 || got[6] != 0 || got[7] != 0 {
		t.Error("the reply exposes a bound address")
	}
}

// TestWriteFailureReplyCarriesTheCode proves the failure reply reports the code
// it was given, which is how a client distinguishes "refused" from "unreachable".
func TestWriteFailureReplyCarriesTheCode(t *testing.T) {
	for _, code := range []byte{replyGeneralFailure, replyHostUnreachable, replyCommandNotSupp} {
		var buf bytes.Buffer
		if err := WriteFailureReply(&buf, code); err != nil {
			t.Fatalf("WriteFailureReply(0x%02x): %v", code, err)
		}
		got := buf.Bytes()
		if len(got) != 10 {
			t.Fatalf("the reply is %d bytes, want 10", len(got))
		}
		if got[1] != code {
			t.Errorf("the reply code is 0x%02x, want 0x%02x", got[1], code)
		}
	}
}

// TestReplyTextCoversEveryCode proves every defined reply code has a
// description, since an operator reading a log needs to know what 0x06 means.
func TestReplyTextCoversEveryCode(t *testing.T) {
	for code := 0; code <= 0x08; code++ {
		text := replyText(byte(code))
		if text == "" {
			t.Errorf("reply 0x%02x has no description", code)
		}
		if strings.HasPrefix(text, "unknown reply") {
			t.Errorf("reply 0x%02x is described as unknown", code)
		}
	}
	// An undefined code must still produce something readable.
	if got := replyText(0x42); !strings.Contains(got, "0x42") {
		t.Errorf("an undefined reply code renders as %q", got)
	}
}

// TestClientRequestReadsTheReplyAndAddress is the regression test for a bug
// where the client consumed four reply bytes and then asked DecodeAddr to read
// the address type, which was already gone.
//
// The consequence was severe and silent: the address type byte was swallowed,
// so the parser read the address from one byte too late and the stream never
// aligned. Every SOCKS5 request stalled until its timeout.
func TestClientRequestReadsTheReplyAndAddress(t *testing.T) {
	client, server := pair(t)

	// The relay answers, then immediately sends a payload byte. If the client
	// consumes one byte too many, that payload byte is lost and the following
	// read returns the wrong data.
	go func() {
		req := make([]byte, 10)
		_, _ = io.ReadFull(server, req)

		reply := []byte{version5, replySuccess, 0x00, transport.AddrTypeIPv4, 0, 0, 0, 0, 0, 0}
		reply = append(reply, 'X')
		_, _ = server.Write(reply)
	}()

	if err := clientRequest(client, cmdConnect, "93.184.216.34:443"); err != nil {
		t.Fatalf("clientRequest: %v", err)
	}

	// Exactly the payload byte must remain. Reading more would mean the client
	// ate into the stream; reading less would mean it left part of the reply
	// behind.
	buf := readN(t, client, 1)
	if buf[0] != 'X' {
		t.Fatalf("after the reply the stream holds %q, want \"X\"", buf)
	}
}

// TestClientRequestRejectsARefusal proves a relay error reply surfaces as an
// error naming the reason, rather than being treated as success.
func TestClientRequestRejectsARefusal(t *testing.T) {
	client, server := pair(t)

	go func() {
		req := make([]byte, 10)
		_, _ = io.ReadFull(server, req)
		_, _ = server.Write([]byte{version5, 0x05, 0x00, transport.AddrTypeIPv4, 0, 0, 0, 0, 0, 0})
	}()

	err := clientRequest(client, cmdConnect, "93.184.216.34:443")
	if err == nil {
		t.Fatal("clientRequest accepted a refusal")
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Errorf("the error does not report the refusal: %v", err)
	}
}

// TestClientRequestRejectsABadVersion proves a reply that is not SOCKS5 is
// refused, which catches a relay that answered with something else entirely.
func TestClientRequestRejectsABadVersion(t *testing.T) {
	client, server := pair(t)

	go func() {
		req := make([]byte, 10)
		_, _ = io.ReadFull(server, req)
		_, _ = server.Write([]byte{0x04, 0x00, 0x00, transport.AddrTypeIPv4, 0, 0, 0, 0, 0, 0})
	}()

	if err := clientRequest(client, cmdConnect, "93.184.216.34:443"); err == nil {
		t.Fatal("clientRequest accepted a non-SOCKS5 reply")
	}
}

// TestClientRequestSendsTheAddressType proves the request carries the SOCKS5
// address type for a domain, which is the encoding the relay parses.
func TestClientRequestSendsTheAddressType(t *testing.T) {
	client, server := pair(t)

	sent := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := server.Read(buf)
		if err != nil {
			close(sent)
			return
		}
		sent <- append([]byte(nil), buf[:n]...)
		_, _ = server.Write([]byte{version5, replySuccess, 0x00, transport.AddrTypeIPv4, 0, 0, 0, 0, 0, 0})
	}()

	if err := clientRequest(client, cmdConnect, "example.com:443"); err != nil {
		t.Fatalf("clientRequest: %v", err)
	}

	got := <-sent
	if len(got) == 0 {
		t.Fatal("the client sent nothing")
	}
	if got[0] != version5 || got[1] != cmdConnect {
		t.Errorf("the request starts with %v, want version 5 and CONNECT", got[:2])
	}
	if got[3] != transport.AddrTypeDomain {
		t.Errorf("the address type is 0x%02x, want 0x%02x (domain)", got[3], transport.AddrTypeDomain)
	}
	if int(got[4]) != len("example.com") {
		t.Errorf("the host length is %d, want %d", got[4], len("example.com"))
	}
}

// TestOneShotReaderYieldsExactlyOneByte proves the replay helper used to
// re-present an already-consumed address type terminates after its byte.
//
// A helper that kept yielding would make the caller's io.MultiReader loop
// forever, which is the bug it was written to fix.
func TestOneShotReaderYieldsExactlyOneByte(t *testing.T) {
	r := newOneShotReader(0x01)

	buf := make([]byte, 4)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatalf("the first read failed: %v", err)
	}
	if n != 1 || buf[0] != 0x01 {
		t.Fatalf("the first read returned (%d, 0x%02x), want (1, 0x01)", n, buf[0])
	}

	if _, err := r.Read(buf); err != io.EOF {
		t.Fatalf("the second read returned %v, want io.EOF", err)
	}
}

// TestHandlerRejectsUnknownAddressType proves a request naming an address type
// the relay cannot parse is refused with the proper reply code.
func TestHandlerRejectsUnknownAddressType(t *testing.T) {
	client, server := pair(t)

	done := make(chan error, 1)
	go func() {
		_, err := Handler{}.Handle(context.Background(), server, transport.HandleRequest{
			Timeout: 2 * time.Second,
		})
		done <- err
	}()

	_, _ = client.Write([]byte{version5, 1, methodNoAuth})
	readN(t, client, 2)

	// Address type 0x09 is not defined by RFC 1928.
	writeAsync(client, requestBytes(cmdConnect, 0x09, []byte{0, 0, 0, 0, 0, 0}))

	reply := readN(t, client, 10)
	if reply[1] != replyAddrTypeNotSupp {
		t.Errorf("the reply code is 0x%02x, want 0x%02x (address type not supported)", reply[1], replyAddrTypeNotSupp)
	}

	if err := <-done; err == nil {
		t.Fatal("the handler accepted an undefined address type")
	}
}

// TestHandlerCompletesAHandshake proves the relay half reaches the point where
// it hands back a stream carrying the requested target.
func TestHandlerCompletesAHandshake(t *testing.T) {
	client, server := pair(t)

	type result struct {
		stream transport.Stream
		err    error
	}
	done := make(chan result, 1)
	go func() {
		st, err := Handler{}.Handle(context.Background(), server, transport.HandleRequest{
			Timeout: 2 * time.Second,
		})
		done <- result{st, err}
	}()

	_, _ = client.Write([]byte{version5, 1, methodNoAuth})
	readN(t, client, 2)

	_, _ = client.Write(requestBytes(cmdConnect, transport.AddrTypeIPv4, []byte{93, 184, 216, 34, 0x01, 0xBB}))

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Handle: %v", r.err)
		}
		defer r.stream.Close()
		if got := r.stream.Request().Target; got != "93.184.216.34:443" {
			t.Errorf("the stream target is %q, want 93.184.216.34:443", got)
		}
		if r.stream.TransportName() != Name {
			t.Errorf("the stream transport is %q, want %q", r.stream.TransportName(), Name)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}
