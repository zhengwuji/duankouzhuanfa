package http

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"porttransit/internal/logx"
	"porttransit/internal/transport"
)

// testTimeout bounds every handshake in this file.
//
// A handshake that never completes must fail its assertion quickly: the
// transport's default timeout is ten seconds, and a suite of tests each waiting
// that long turns one regression into what looks like a hung binary.
const testTimeout = 3 * time.Second

// readN reads exactly n bytes, failing the test on a short read.
//
// The read deadline is what converts "the peer never answered" into a fast,
// attributable failure instead of a stall that takes the whole test binary down
// with it.
func readN(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return buf
}

// writeAsync sends bytes from a goroutine.
//
// net.Pipe is fully synchronous — a Write blocks until the peer reads every
// byte — so a helper that wrote inline while the peer might write a reply would
// deadlock the test. Writing from a goroutine keeps the test body free to drain
// the peer's reply.
func writeAsync(conn net.Conn, buf []byte) {
	go func() { _, _ = conn.Write(buf) }()
}

// connectReq is the intent the client conveys to the relay.
func connectReq(target string) *transport.Request {
	return &transport.Request{Command: transport.CmdConnectTCP, Target: target}
}

// ---------------------------------------------------------------------------
// A raw-socket relay harness
// ---------------------------------------------------------------------------

// relayResult is one accepted connection's outcome.
type relayResult struct {
	stream transport.Stream
	err    error
}

// relayHarness runs a transport's Handler over bare TCP sockets, which is
// exactly how the relay's own accept loop uses it.
//
// A harness built on net/http would exercise a different code path and could not
// observe what actually appears on the wire, which is where this package's bugs
// have lived.
type relayHarness struct {
	addr    string
	results chan relayResult

	mu   sync.Mutex
	held []transport.Stream
}

func startRelay(t *testing.T, handler transport.Handler, settings transport.Settings, logger *logx.Logger) *relayHarness {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	h := &relayHarness{addr: ln.Addr().String(), results: make(chan relayResult, 4)}
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				st, err := handler.Handle(ctx, c, transport.HandleRequest{
					Timeout:  testTimeout,
					Logger:   logger,
					Settings: settings,
				})
				if err == nil {
					h.mu.Lock()
					h.held = append(h.held, st)
					h.mu.Unlock()
				}
				select {
				case h.results <- relayResult{stream: st, err: err}:
				case <-ctx.Done():
					if st != nil {
						st.Close()
					}
				}
			}(conn)
		}
	}()

	t.Cleanup(func() {
		cancel()
		ln.Close()
		h.mu.Lock()
		defer h.mu.Unlock()
		for _, st := range h.held {
			st.Close()
		}
	})
	return h
}

// waitStream returns the relay side of the next accepted connection.
func (h *relayHarness) waitStream(t *testing.T) transport.Stream {
	t.Helper()
	select {
	case r := <-h.results:
		if r.err != nil {
			t.Fatalf("the relay side of the handshake failed: %v", r.err)
		}
		return r.stream
	case <-time.After(10 * time.Second):
		t.Fatal("the relay never produced a stream")
	}
	return nil
}

// waitErr returns the error the relay side reported.
func (h *relayHarness) waitErr(t *testing.T) error {
	t.Helper()
	select {
	case r := <-h.results:
		if r.err == nil {
			r.stream.Close()
			t.Fatal("the relay accepted a connection it should have refused")
		}
		return r.err
	case <-time.After(10 * time.Second):
		t.Fatal("the relay never reported a result")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Registration and naming
// ---------------------------------------------------------------------------

// TestRegistrationOfBothSchemes proves both transports are reachable under the
// exact scheme names the config and the GUI use, with their conventional ports.
//
// A mismatch is not a compile error: the relay would simply fail to resolve the
// scheme at start time, or the GUI would offer a port the relay never binds.
func TestRegistrationOfBothSchemes(t *testing.T) {
	if NameConnect != "http" {
		t.Errorf("NameConnect = %q, want \"http\"", NameConnect)
	}
	if NameUpgrade != "httpupgrade" {
		t.Errorf("NameUpgrade = %q, want \"httpupgrade\"", NameUpgrade)
	}
	if DefaultPortConnect != 8080 {
		t.Errorf("DefaultPortConnect = %d, want 8080", DefaultPortConnect)
	}
	if DefaultPortUpgrade != 80 {
		t.Errorf("DefaultPortUpgrade = %d, want 80", DefaultPortUpgrade)
	}

	cases := []struct {
		name       string
		port       int
		native     bool
		wantDialer transport.Dialer
	}{
		{NameConnect, DefaultPortConnect, true, ConnectDialer{}},
		{NameUpgrade, DefaultPortUpgrade, false, UpgradeDialer{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, ok := transport.Lookup(tc.name)
			if !ok {
				t.Fatalf("transport.Lookup(%q) did not find the transport", tc.name)
			}
			if f.DefaultPort != tc.port {
				t.Errorf("the registered factory reports port %d, want %d", f.DefaultPort, tc.port)
			}
			// NativeHeader drives the GUI's hint about where the target address
			// travels. CONNECT carries it in the request line; httpupgrade
			// carries it in the PortTransit preamble, so the two must differ.
			if f.NativeHeader != tc.native {
				t.Errorf("NativeHeader = %v, want %v", f.NativeHeader, tc.native)
			}
			if f.Description == "" {
				t.Error("the factory has no description for the GUI protocol picker")
			}

			d, h := f.Build()
			if d == nil || h == nil {
				t.Fatal("the factory did not build both a dialer and a handler")
			}
			if d.Name() != tc.name || h.Name() != tc.name {
				t.Errorf("the built halves report %q and %q, want %q", d.Name(), h.Name(), tc.name)
			}
			// The registry is what the relay resolves a listener through.
			if _, err := transport.NewHandler(tc.name); err != nil {
				t.Errorf("transport.NewHandler(%q): %v", tc.name, err)
			}
			if _, err := transport.NewDialer(tc.name); err != nil {
				t.Errorf("transport.NewDialer(%q): %v", tc.name, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The Sec-WebSocket-Accept computation
// ---------------------------------------------------------------------------

// TestWSGUIDIsTheRFC6455Constant proves the magic GUID is the canonical value.
//
// The GUID is the only thing that distinguishes this handshake from any other
// SHA-1 token, and a single wrong character would produce an accept value that
// every conforming client rejects — with no hint as to why.
func TestWSGUIDIsTheRFC6455Constant(t *testing.T) {
	const want = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	if wsGUID != want {
		t.Errorf("wsGUID = %q, want %q", wsGUID, want)
	}
}

// TestWSAcceptMatchesTheRFC6455Example pins the accept computation against the
// worked example published in RFC 6455 section 1.3.
//
// The expected string is hard-coded rather than recomputed. A test that derived
// it the same way the implementation does would agree with the implementation
// even if both were wrong — for instance if the GUID were mistyped — and would
// then prove nothing at all.
func TestWSAcceptMatchesTheRFC6455Example(t *testing.T) {
	const (
		key  = "dGhlIHNhbXBsZSBub25jZQ=="
		want = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	)
	if got := wsAccept(key); got != want {
		t.Errorf("wsAccept(%q) = %q, want %q", key, got, want)
	}

	// The key must be used verbatim, with no trimming or case folding: a client
	// that sent this exact key must receive this exact accept value.
	if got := wsAccept(" " + key + " "); got == want {
		t.Error("wsAccept ignores surrounding whitespace, so it would accept a key the client never sent")
	}
}

// ---------------------------------------------------------------------------
// HTTP CONNECT
// ---------------------------------------------------------------------------

// TestConnectHandlerCompletesADomainHandshake proves a domain target survives the
// round trip and is reported on the relay's stream.
//
// This is the whole purpose of the CONNECT transport: the request line names the
// final destination, so the relay never has to decode a preamble.
func TestConnectHandlerCompletesADomainHandshake(t *testing.T) {
	h := startRelay(t, ConnectHandler{}, transport.Settings{}, logx.Discard())

	client, err := ConnectDialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: h.addr,
		Request:    connectReq("example.com:443"),
		Timeout:    testTimeout,
		Logger:     logx.Discard(),
		Settings:   transport.Settings{},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	server := h.waitStream(t)
	t.Cleanup(func() { server.Close() })

	if got := server.Request().Target; got != "example.com:443" {
		t.Errorf("the relay decoded target %q, want example.com:443", got)
	}
	if got := server.TransportName(); got != NameConnect {
		t.Errorf("the stream reports transport %q, want %q", got, NameConnect)
	}
	if got := server.Request().Command; got != transport.CmdConnectTCP {
		t.Errorf("the stream reports command %v, want tcp", got)
	}

	// The tunnel must actually carry bytes in both directions.
	const payload = "connect payload"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if got := string(readN(t, server, len(payload))); got != payload {
		t.Errorf("the relay read %q, want %q", got, payload)
	}

	const reply = "connect reply"
	if _, err := server.Write([]byte(reply)); err != nil {
		t.Fatalf("relay write: %v", err)
	}
	if got := string(readN(t, client, len(reply))); got != reply {
		t.Errorf("the client read %q, want %q", got, reply)
	}
}

// TestConnectHandlerCompletesAnIPv4LiteralHandshake proves an IP literal target
// is decoded as an address rather than as a hostname.
//
// A literal must not be resolved client-side or mangled into a domain: the
// relay's ACL and its dial path treat the two forms differently, so a
// mis-decoded literal would be routed by the wrong rule.
func TestConnectHandlerCompletesAnIPv4LiteralHandshake(t *testing.T) {
	h := startRelay(t, ConnectHandler{}, transport.Settings{}, logx.Discard())

	client, err := ConnectDialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: h.addr,
		Request:    connectReq("93.184.216.34:8443"),
		Timeout:    testTimeout,
		Logger:     logx.Discard(),
		Settings:   transport.Settings{},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	server := h.waitStream(t)
	t.Cleanup(func() { server.Close() })

	if got := server.Request().Target; got != "93.184.216.34:8443" {
		t.Errorf("the relay decoded target %q, want 93.184.216.34:8443", got)
	}

	const payload = "literal"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := string(readN(t, server, len(payload))); got != payload {
		t.Errorf("the relay read %q, want %q", got, payload)
	}
}

// TestConnectDialerSendsAWellFormedRequestLine proves the exact bytes the client
// puts on the wire.
//
// The request line is the entire protocol: a proxy that receives a malformed
// CONNECT cannot route it, and the failure surfaces at the far end of the
// internet rather than in the client's logs.
func TestConnectDialerSendsAWellFormedRequestLine(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	raw := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		// Read the remainder of the header block so the observation is complete.
		var sb strings.Builder
		sb.WriteString(req.Method + " " + req.RequestURI + " " + req.Proto + "\r\n")
		for k, vs := range req.Header {
			for _, v := range vs {
				sb.WriteString(k + ": " + v + "\r\n")
			}
		}
		sb.WriteString("Host: " + req.Host + "\r\n")
		raw <- sb.String()

		// Answer so the dial completes; the observation is already captured.
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}()

	_, _ = ConnectDialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: ln.Addr().String(),
		Request:    connectReq("example.com:443"),
		Timeout:    testTimeout,
		Logger:     logx.Discard(),
		Settings:   transport.Settings{},
	})

	var got string
	select {
	case got = <-raw:
	case <-time.After(5 * time.Second):
		t.Fatal("the listener never received a request")
	}

	// The authority in the request line is the final destination, not the relay.
	// Sending the relay's own address would turn every tunnel into a loop.
	if !strings.HasPrefix(got, "CONNECT example.com:443 HTTP/1.1\r\n") {
		t.Errorf("the request line is not a CONNECT to the final destination:\n%s", got)
	}
	if !strings.Contains(got, "Proxy-Connection: Keep-Alive") {
		t.Errorf("the request omits Proxy-Connection, so a proxy would not keep the tunnel open:\n%s", got)
	}
}

// TestConnectHandlerReplyIsTheExactEstablishedLine proves the 200 reply is the
// canonical CONNECT response.
//
// Go's client tolerates a short reason phrase, but other HTTP proxies and
// command-line tools match on the established line, so the exact bytes are the
// contract.
func TestConnectHandlerReplyIsTheExactEstablishedLine(t *testing.T) {
	h := startRelay(t, ConnectHandler{}, transport.Settings{}, logx.Discard())

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	if _, err := conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	const want = "HTTP/1.1 200 Connection Established\r\n\r\n"
	got := string(readN(t, conn, len(want)))
	if got != want {
		t.Errorf("the reply is %q, want %q", got, want)
	}

	if st := h.waitStream(t); st.Request().Target != "example.com:443" {
		t.Errorf("the relay decoded target %q, want example.com:443", st.Request().Target)
	}
}

// TestConnectHandlerRejectsARequestWithoutAnAuthority proves a CONNECT that
// names nothing is refused rather than producing a stream with an empty target.
//
// An empty target would be handed to the relay's dial path and its ACL, where
// "connect to nothing" is not a case either was written for.
//
// The request deliberately carries no Host header: Go's parser falls back to
// Host when the request line has no authority, so a request with a Host would
// have a target and would not exercise this branch at all.
func TestConnectHandlerRejectsARequestWithoutAnAuthority(t *testing.T) {
	h := startRelay(t, ConnectHandler{}, transport.Settings{}, logx.Discard())

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	writeAsync(conn, []byte("CONNECT /rpc HTTP/1.1\r\n\r\n"))

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read the refusal: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("the relay answered %d, want 400", resp.StatusCode)
	}

	if err := h.waitErr(t); !errors.Is(err, transport.ErrProtocol) {
		t.Errorf("the relay error is %v, want ErrProtocol", err)
	}
}

// TestConnectHandlerRejectsAMalformedFirstLine proves garbage is refused instead
// of being parsed into a request with surprising fields.
//
// The relay sits on a public port, so the first thing any scanner sends is
// something that is not HTTP at all.
func TestConnectHandlerRejectsAMalformedFirstLine(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"not HTTP at all", "garbage\r\n\r\n"},
		{"empty request", "\r\n\r\n"},
		{"a method but no version", "CONNECT example.com:443\r\n\r\n"},
		{"an unparsable authority", "CONNECT bad:port HTTP/1.1\r\nHost: bad:port\r\n\r\n"},
		{"an invalid method token", "CONNECT\x01bad example.com:443 HTTP/1.1\r\n\r\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := startRelay(t, ConnectHandler{}, transport.Settings{}, logx.Discard())

			conn, err := net.Dial("tcp", h.addr)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			t.Cleanup(func() { conn.Close() })

			writeAsync(conn, []byte(tc.raw))

			if err := h.waitErr(t); err == nil {
				t.Fatal("the relay accepted a malformed request")
			}
		})
	}
}

// TestUnsupportedHTTPVersionIsRefused proves a request claiming an HTTP version
// this build does not implement is refused instead of being served.
//
// RFC 9112 section 2.3 requires a server that receives a major version it does
// not support to answer 505, and Go's own net/http Server does exactly that.
// Go's request parser accepts any HTTP/X.Y, so the version has to be checked
// explicitly: without the check both schemes treated an HTTP/9.9 request as if
// it were understood, answering 200 Connection Established or 101 Switching
// Protocols. The request was still routed by its parsed authority rather than
// by the version, so this was a conformance and disguise gap rather than a
// routing bypass — but the disguise the httpupgrade transport depends on is
// weakened by answering a handshake no real server would accept.
func TestUnsupportedHTTPVersionIsRefused(t *testing.T) {
	cases := []struct {
		name    string
		handler transport.Handler
		raw     string
		method  string
	}{
		{
			name:    "CONNECT claiming HTTP/9.9",
			handler: ConnectHandler{},
			raw:     "CONNECT example.com:443 HTTP/9.9\r\nHost: example.com:443\r\n\r\n",
			method:  http.MethodConnect,
		},
		{
			name:    "CONNECT claiming HTTP/2.0",
			handler: ConnectHandler{},
			raw:     "CONNECT example.com:443 HTTP/2.0\r\nHost: example.com:443\r\n\r\n",
			method:  http.MethodConnect,
		},
		{
			name:    "an upgrade claiming HTTP/9.9",
			handler: UpgradeHandler{},
			raw: "GET / HTTP/9.9\r\nHost: relay.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
			method: http.MethodGet,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := startRelay(t, tc.handler, transport.Settings{}, logx.Discard())

			conn, err := net.Dial("tcp", h.addr)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			t.Cleanup(func() { conn.Close() })

			writeAsync(conn, []byte(tc.raw))

			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: tc.method})
			if err != nil {
				// A refusal that closes without a response is also a refusal.
				return
			}

			if resp.StatusCode != http.StatusHTTPVersionNotSupported {
				t.Errorf("the relay answered %s to a request claiming an unsupported HTTP version, "+
					"want 505 HTTP Version Not Supported", resp.Status)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// HTTP Basic authentication on CONNECT
// ---------------------------------------------------------------------------

// TestConnectHandlerRequiresBasicAuthWhenConfigured proves the relay refuses a
// CONNECT that carries no credentials when a username is configured.
//
// A CONNECT proxy normally requires authentication; a relay that ignored the
// setting would be an open proxy for anyone who found the port.
func TestConnectHandlerRequiresBasicAuthWhenConfigured(t *testing.T) {
	settings := transport.Settings{"username": "alice", "password": "s3cret"}
	h := startRelay(t, ConnectHandler{}, settings, logx.Discard())

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	writeAsync(conn, []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read the refusal: %v", err)
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("the relay answered %d, want 407", resp.StatusCode)
	}

	if err := h.waitErr(t); !errors.Is(err, transport.ErrAuthFailed) {
		t.Errorf("the relay error is %v, want ErrAuthFailed", err)
	}
}

// TestConnectHandlerAcceptsCorrectBasicAuth proves the credential check admits a
// matching username and password, so the refusal above is a gate rather than a
// blanket denial.
func TestConnectHandlerAcceptsCorrectBasicAuth(t *testing.T) {
	settings := transport.Settings{"username": "alice", "password": "s3cret"}
	h := startRelay(t, ConnectHandler{}, settings, logx.Discard())

	client, err := ConnectDialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: h.addr,
		Request:    connectReq("example.com:443"),
		Timeout:    testTimeout,
		Logger:     logx.Discard(),
		Settings:   transport.Settings{"username": "alice", "password": "s3cret"},
	})
	if err != nil {
		t.Fatalf("dial with correct credentials: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	if got := h.waitStream(t).Request().Target; got != "example.com:443" {
		t.Errorf("the relay decoded target %q, want example.com:443", got)
	}
}

// TestCheckBasicAuth pins the credential comparison, including the cases that
// must be refused.
//
// The negative cases are the security-relevant ones: a comparison that accepted
// a prefix, ignored case, or tolerated a missing separator would let a prober
// through with a credential the operator never configured.
func TestCheckBasicAuth(t *testing.T) {
	settings := transport.Settings{"username": "alice", "password": "s3cret"}
	basic := func(user, pass string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	}

	cases := []struct {
		name   string
		header string
		wantOK bool
	}{
		{"exact credentials", basic("alice", "s3cret"), true},
		{"wrong password", basic("alice", "wrong"), false},
		{"wrong username", basic("bob", "s3cret"), false},
		{"a username prefix", basic("ali", "s3cret"), false},
		{"a password prefix", basic("alice", "s3cre"), false},
		{"case differs", basic("Alice", "s3cret"), false},
		{"no colon in the decoded pair", "Basic " + base64.StdEncoding.EncodeToString([]byte("alice")), false},
		{"not base64", "Basic !!!not-base64!!!", false},
		{"the wrong scheme", "Bearer " + base64.StdEncoding.EncodeToString([]byte("alice:s3cret")), false},
		{"empty", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodConnect, "http://relay.local", nil)
			if err != nil {
				t.Fatalf("build the request: %v", err)
			}
			if tc.header != "" {
				req.Header.Set("Proxy-Authorization", tc.header)
			}

			err = checkBasicAuth(req, settings)
			if tc.wantOK && err != nil {
				t.Errorf("checkBasicAuth rejected valid credentials: %v", err)
			}
			if !tc.wantOK {
				if err == nil {
					t.Fatal("checkBasicAuth accepted credentials it must refuse")
				}
				if !errors.Is(err, transport.ErrAuthFailed) {
					t.Errorf("the error is %v, want ErrAuthFailed", err)
				}
			}
		})
	}
}

// TestCheckBasicAuthAcceptsTheAuthorizationHeader proves the upgrade path can
// authenticate with the ordinary Authorization header.
//
// CONNECT uses Proxy-Authorization while an upgrade uses Authorization, and one
// helper serves both. A helper that only looked at one of them would leave one
// scheme unauthenticated.
func TestCheckBasicAuthAcceptsTheAuthorizationHeader(t *testing.T) {
	settings := transport.Settings{"username": "alice", "password": "s3cret"}
	cred := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))

	req, err := http.NewRequest(http.MethodGet, "http://relay.local/", nil)
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}
	req.Header.Set("Authorization", cred)

	if err := checkBasicAuth(req, settings); err != nil {
		t.Errorf("checkBasicAuth rejected Authorization: %v", err)
	}
}

// TestCheckBasicAuthIsSkippedWhenNoUsernameIsConfigured proves an unconfigured
// relay accepts anything, which is the documented behaviour.
//
// A relay already protected by TLS plus the preamble MAC must not become
// unreachable just because no proxy password was set.
func TestCheckBasicAuthIsSkippedWhenNoUsernameIsConfigured(t *testing.T) {
	req, err := http.NewRequest(http.MethodConnect, "http://relay.local", nil)
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}
	if err := checkBasicAuth(req, transport.Settings{"password": "ignored"}); err != nil {
		t.Errorf("checkBasicAuth refused a request with no username configured: %v", err)
	}
}

// ---------------------------------------------------------------------------
// HTTPUpgrade
// ---------------------------------------------------------------------------

// TestUpgradeHandlerReplyIsTheExact101 proves the 101 response is byte-for-byte
// the WebSocket handshake a middlebox expects to validate.
//
// The whole point of this transport is that the first exchange is
// indistinguishable from a WebSocket upgrade, so a missing or reordered header
// is not a cosmetic difference — it is the transport failing at its only job.
func TestUpgradeHandlerReplyIsTheExact101(t *testing.T) {
	h := startRelay(t, UpgradeHandler{}, transport.Settings{}, logx.Discard())

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	const key = "dGhlIHNhbXBsZSBub25jZQ=="
	req := "GET / HTTP/1.1\r\nHost: relay.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write the upgrade request: %v", err)
	}

	want := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
	got := string(readN(t, conn, len(want)))
	if got != want {
		t.Errorf("the 101 reply is\n%q\nwant\n%q", got, want)
	}
}

// TestUpgradeHandlerCompletesTheHandshakeAndPassesBytesUnframed is the core
// assertion of this transport: the payload is passed through verbatim, with no
// WebSocket framing.
//
// The raw client is deliberate. Driving this through the real dialer would only
// prove the two halves agree with each other; writing the preamble and payload
// straight onto the socket proves that what crosses the wire is exactly the
// bytes the application produced. If the transport applied framing, the relay
// would try to read "PTRF" as a frame header and fail.
func TestUpgradeHandlerCompletesTheHandshakeAndPassesBytesUnframed(t *testing.T) {
	h := startRelay(t, UpgradeHandler{}, transport.Settings{}, logx.Discard())

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	req := "GET / HTTP/1.1\r\nHost: relay.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write the upgrade request: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read the 101: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("the relay answered %s, want 101", resp.Status)
	}

	// The preamble goes on the wire with no frame header at all.
	preamble, err := transport.EncodePreamble(&transport.Preamble{
		Command: transport.CmdConnectTCP,
		Target:  "example.com:443",
	}, nil)
	if err != nil {
		t.Fatalf("EncodePreamble: %v", err)
	}
	if _, err := conn.Write(preamble); err != nil {
		t.Fatalf("write the preamble: %v", err)
	}

	server := h.waitStream(t)
	t.Cleanup(func() { server.Close() })

	if got := server.Request().Target; got != "example.com:443" {
		t.Fatalf("the relay decoded target %q, want example.com:443", got)
	}
	if got := server.TransportName(); got != NameUpgrade {
		t.Errorf("the stream reports transport %q, want %q", got, NameUpgrade)
	}

	// Client to relay: exactly the payload bytes, nothing prepended.
	const payload = "unframed payload"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write the payload: %v", err)
	}
	if got := string(readN(t, server, len(payload))); got != payload {
		t.Errorf("the relay read %q, want %q", got, payload)
	}

	// Relay to client: exactly the reply bytes. A WebSocket transport would have
	// prefixed these with a two-byte frame header, so an exact-length read of
	// the raw socket is what proves the absence of framing.
	const reply = "unframed reply"
	if _, err := server.Write([]byte(reply)); err != nil {
		t.Fatalf("relay write: %v", err)
	}
	if got := string(readN(t, conn, len(reply))); got != reply {
		t.Errorf("the client read %q, want %q", got, reply)
	}
}

// TestUpgradeHandlerAcceptsAnOmittedWebSocketKey proves the handshake still
// completes when the client sends no Sec-WebSocket-Key.
//
// A middlebox that validates the token is the only consumer of it, and this
// transport's real clients are not browsers. Refusing a keyless handshake would
// break a client that had no reason to send one.
func TestUpgradeHandlerAcceptsAnOmittedWebSocketKey(t *testing.T) {
	h := startRelay(t, UpgradeHandler{}, transport.Settings{}, logx.Discard())

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	req := "GET / HTTP/1.1\r\nHost: relay.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write the upgrade request: %v", err)
	}

	want := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	got := string(readN(t, conn, len(want)))
	if got != want {
		t.Errorf("the 101 reply is\n%q\nwant\n%q", got, want)
	}
}

// TestUpgradeHandlerRejectsTheWrongPath proves the relay refuses an upgrade whose
// request path is not the configured one.
//
// THIS TEST FAILS against the current code and documents a genuine defect. See
// the note at the end of the test body for the root cause and the suggested fix.
//
// The path is the only URL-level discriminator the listener has: it is what lets
// the client's upgrade look like a request for a real resource. A relay that
// answers 101 on any path is trivially separable from the web server it is
// pretending to be, because a real server answers 404 for a path it does not
// serve — which defeats the disguise this transport exists to provide.
//
// The websocket transport already enforces its path setting (see its
// pathAllowed helper), so this package is the remaining outlier: its two schemes
// apply the path only on the dialer side.
func TestUpgradeHandlerRejectsTheWrongPath(t *testing.T) {
	h := startRelay(t, UpgradeHandler{}, transport.Settings{"path": "/secret"}, logx.Discard())

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	req := "GET /totally-different HTTP/1.1\r\nHost: relay.local\r\nUpgrade: websocket\r\n" +
		"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	writeAsync(conn, []byte(req))

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		// Closing without a response is also a refusal.
		return
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Errorf("the relay answered %s to an upgrade for a path other than the configured one, "+
			"want a refusal (404).\n"+
			"root cause: UpgradeHandler.Handle calls isUpgradeRequest and checkBasicAuth but never "+
			"compares httpReq.URL.Path against settings.GetString(SettingPath, \"/\"), so the path "+
			"setting is applied only by the dialer and is never enforced by the relay. "+
			"ConnectHandler.Handle has the same gap.\n"+
			"suggested fix: mirror websocket.pathAllowed, which the websocket transport added for "+
			"this same defect. Add an equivalent helper here and, after the isUpgradeRequest check "+
			"in UpgradeHandler.Handle, on a mismatch either writeHTTPError(raw, http.StatusNotFound, "+
			"\"Not Found\") and close, or route to the configured fallback so the relay still looks "+
			"like an ordinary web server.", resp.Status)
	}
}

// TestIsUpgradeRequest pins the recognition rules, including the cases that must
// NOT be treated as an upgrade.
//
// A loose check would let an ordinary browser request be answered with a 101 and
// then interpreted as a byte stream, which both breaks the disguise and hands an
// unauthenticated peer a raw tunnel.
func TestIsUpgradeRequest(t *testing.T) {
	build := func(upgrade, connection string) *http.Request {
		req, err := http.NewRequest(http.MethodGet, "http://relay.local/", nil)
		if err != nil {
			panic(err)
		}
		if upgrade != "" {
			req.Header.Set("Upgrade", upgrade)
		}
		if connection != "" {
			req.Header.Set("Connection", connection)
		}
		return req
	}

	cases := []struct {
		name       string
		upgrade    string
		connection string
		want       bool
	}{
		{"the canonical pair", "websocket", "Upgrade", true},
		{"lowercase upgrade", "websocket", "upgrade", true},
		{"mixed case upgrade token", "WebSocket", "Upgrade", true},
		{"a connection list", "websocket", "keep-alive, Upgrade", true},
		{"upgrade without connection", "websocket", "", false},
		{"connection without upgrade", "", "Upgrade", false},
		{"a different protocol", "h2c", "Upgrade", false},
		{"neither header", "", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isUpgradeRequest(build(tc.upgrade, tc.connection)); got != tc.want {
				t.Errorf("isUpgradeRequest(Upgrade=%q, Connection=%q) = %v, want %v",
					tc.upgrade, tc.connection, got, tc.want)
			}
		})
	}
}

// TestUpgradeDialerAppliesPathAndQuery proves the client's path and query
// settings reach the request line.
//
// The path is what lets the client look like it is fetching a real resource, and
// the default "/" must be applied when the setting is absent.
func TestUpgradeDialerAppliesPathAndQuery(t *testing.T) {
	cases := []struct {
		name  string
		set   transport.Settings
		want  string
		query string
	}{
		{"default", transport.Settings{}, "/", ""},
		{"explicit path", transport.Settings{"path": "/assets/app.js"}, "/assets/app.js", ""},
		{"path without a leading slash", transport.Settings{"path": "assets/app.js"}, "/assets/app.js", ""},
		{"with a query", transport.Settings{"path": "/x", "query": "?v=3"}, "/x", "v=3"},
		{"a query given without the question mark", transport.Settings{"path": "/x", "query": "v=3"}, "/x", "v=3"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			t.Cleanup(func() { ln.Close() })

			got := make(chan *http.Request, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				got <- req
			}()

			_, _ = UpgradeDialer{}.Dial(context.Background(), transport.DialRequest{
				ServerAddr: ln.Addr().String(),
				Request:    connectReq("example.com:443"),
				Timeout:    testTimeout,
				Logger:     logx.Discard(),
				Settings:   tc.set,
			})

			select {
			case req := <-got:
				if req.URL.Path != tc.want {
					t.Errorf("the path is %q, want %q", req.URL.Path, tc.want)
				}
				if req.URL.RawQuery != tc.query {
					t.Errorf("the query is %q, want %q", req.URL.RawQuery, tc.query)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the listener never received a request")
			}
		})
	}
}

// TestUpgradeDialerSendsBrowserShapedHeaders proves the upgrade request carries
// the headers a middlebox expects to see.
//
// A Go-http-client User-Agent on an upgrade is one of the easiest proxy tells to
// detect, which would defeat the disguise the transport exists to provide.
func TestUpgradeDialerSendsBrowserShapedHeaders(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	got := make(chan *http.Request, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		got <- req
	}()

	_, _ = UpgradeDialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: ln.Addr().String(),
		Request:    connectReq("example.com:443"),
		Timeout:    testTimeout,
		Logger:     logx.Discard(),
		Settings:   transport.Settings{"userAgent": "CustomAgent/9"},
	})

	select {
	case req := <-got:
		if ua := req.Header.Get("User-Agent"); ua != "CustomAgent/9" {
			t.Errorf("User-Agent = %q, want CustomAgent/9", ua)
		}
		if v := req.Header.Get("Sec-WebSocket-Version"); v != "13" {
			t.Errorf("Sec-WebSocket-Version = %q, want 13", v)
		}
		if req.Header.Get("Sec-WebSocket-Key") == "" {
			t.Error("the request carries no Sec-WebSocket-Key")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the listener never received a request")
	}
}

// TestUpgradeDialerValidatesTheAcceptToken proves the client rejects a relay that
// answered 101 with a wrong accept value.
//
// A CDN or middlebox that terminated the upgrade itself would answer 101 with
// its own token, and a client that ignored it would then speak this protocol to
// something that is not this relay — reporting a working tunnel for a connection
// that cannot carry data.
func TestUpgradeDialerValidatesTheAcceptToken(t *testing.T) {
	cases := []struct {
		name    string
		accept  string
		wantErr bool
	}{
		{"a correct token", "correct", false},
		{"a wrong token", "d3JvbmcgdG9rZW4=", true},
		{"an absent token", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			t.Cleanup(func() { ln.Close() })

			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				accept := tc.accept
				if accept == "correct" {
					accept = wsAccept(req.Header.Get("Sec-WebSocket-Key"))
				}
				resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
				if accept != "" {
					resp += "Sec-WebSocket-Accept: " + accept + "\r\n"
				}
				resp += "\r\n"
				_, _ = conn.Write([]byte(resp))

				// Keep the connection open so a client that accepted the reply
				// proceeds to its preamble write rather than seeing EOF.
				time.Sleep(500 * time.Millisecond)
			}()

			_, err = UpgradeDialer{}.Dial(context.Background(), transport.DialRequest{
				ServerAddr: ln.Addr().String(),
				Request:    connectReq("example.com:443"),
				Timeout:    testTimeout,
				Logger:     logx.Discard(),
				Settings:   transport.Settings{},
			})
			if tc.wantErr && err == nil {
				t.Fatal("the client accepted a mismatched Sec-WebSocket-Accept")
			}
			if tc.wantErr && !errors.Is(err, transport.ErrProtocol) {
				t.Errorf("the error is %v, want ErrProtocol", err)
			}
			if !tc.wantErr && err != nil && errors.Is(err, transport.ErrProtocol) {
				t.Errorf("the client rejected a valid handshake: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// bufferedConn: the bytes already read must not be lost
// ---------------------------------------------------------------------------

// TestBufferedConnDrainsTheBufferBeforeTheSocket proves the wrapper yields the
// buffered bytes first and only then reads the socket.
//
// This is the single most important property in the package. When the handshake
// leaves bytes in a bufio.Reader and the wrapper ignores it, the first request of
// every tunnel is truncated: the client's first write is silently swallowed, and
// the symptom is a hang or a corrupt payload rather than an error.
func TestBufferedConnDrainsTheBufferBeforeTheSocket(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })

	// A write on one end of a pipe is read on the other, so the data that a
	// later read of `server` sees must be written to `client`.
	go func() {
		_, _ = client.Write([]byte("SOCKET"))
	}()

	br := bufio.NewReader(bytes.NewReader([]byte("BUFFERED")))
	// The reader must be primed: Buffered() reports 0 until a read has actually
	// pulled bytes into the buffer, and the wrapper only consults the buffer when
	// it is non-empty. Peeking is exactly what http.ReadRequest does to this same
	// reader before the wrapper is built, so this reproduces the real state.
	if _, err := br.Peek(len("BUFFERED")); err != nil {
		t.Fatalf("prime the reader: %v", err)
	}
	wrapped := &bufferedConn{Conn: server, r: br}

	// The buffered bytes must come out first, in order, before any socket byte.
	got := readN(t, wrapped, len("BUFFERED"))
	if string(got) != "BUFFERED" {
		t.Fatalf("the first read returned %q, want the buffered bytes", got)
	}
	if got := readN(t, wrapped, len("SOCKET")); string(got) != "SOCKET" {
		t.Fatalf("the second read returned %q, want the socket bytes", got)
	}
}

// TestBufferedConnPreservesBytesPipelinedAfterAConnect proves the bytes a client
// pipelines behind its CONNECT request reach the relay's stream.
//
// A client that sends its request and its first payload in one write is the
// normal case, not a corner case: the two writes coalesce into one segment, the
// request parse consumes only the header block, and everything after it is
// already sitting in the bufio.Reader. Losing those bytes truncates exactly the
// first request of the tunnel — the classic "first request hangs" report.
func TestBufferedConnPreservesBytesPipelinedAfterAConnect(t *testing.T) {
	h := startRelay(t, ConnectHandler{}, transport.Settings{}, logx.Discard())

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	const pipelined = "FIRST-REQUEST-BYTES"

	// One write: the request line, the headers, and the payload together.
	blob := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n" + pipelined
	if _, err := conn.Write([]byte(blob)); err != nil {
		t.Fatalf("write the pipelined handshake: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect}); err != nil {
		t.Fatalf("read the 200: %v", err)
	}

	server := h.waitStream(t)
	t.Cleanup(func() { server.Close() })

	// Every pipelined byte must arrive, in order, before anything else.
	got := readN(t, server, len(pipelined))
	if string(got) != pipelined {
		t.Fatalf("the relay read %q, want %q: the pipelined bytes were dropped or reordered", got, pipelined)
	}

	// And the stream must continue to work normally afterwards.
	const more = "SECOND"
	if _, err := conn.Write([]byte(more)); err != nil {
		t.Fatalf("write the follow-up: %v", err)
	}
	if got := string(readN(t, server, len(more))); got != more {
		t.Errorf("the follow-up read %q, want %q", got, more)
	}
}

// TestBufferedConnPreservesBytesPipelinedAfterAnUpgrade is the same assertion for
// the httpupgrade path, which has its own independent wrapper.
//
// The two handlers build their bufferedConn separately, so a fix or a regression
// in one says nothing about the other.
func TestBufferedConnPreservesBytesPipelinedAfterAnUpgrade(t *testing.T) {
	h := startRelay(t, UpgradeHandler{}, transport.Settings{}, logx.Discard())

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	preamble, err := transport.EncodePreamble(&transport.Preamble{
		Command: transport.CmdConnectTCP,
		Target:  "example.com:443",
	}, nil)
	if err != nil {
		t.Fatalf("EncodePreamble: %v", err)
	}
	const pipelined = "PIPELINED-AFTER-UPGRADE"

	req := "GET / HTTP/1.1\r\nHost: relay.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"

	// One write: request, preamble and first payload together.
	blob := append([]byte(req), preamble...)
	blob = append(blob, []byte(pipelined)...)
	if _, err := conn.Write(blob); err != nil {
		t.Fatalf("write the pipelined handshake: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet}); err != nil {
		t.Fatalf("read the 101: %v", err)
	}

	server := h.waitStream(t)
	t.Cleanup(func() { server.Close() })

	if got := server.Request().Target; got != "example.com:443" {
		t.Fatalf("the relay decoded target %q, want example.com:443", got)
	}
	if got := string(readN(t, server, len(pipelined))); got != pipelined {
		t.Fatalf("the relay read %q, want %q: the pipelined bytes were dropped", got, pipelined)
	}
}

// TestUpgradeDialerPreservesBytesPipelinedAfterThe101 is the client-side mirror
// of the tests above.
//
// The relay answers the upgrade and starts writing the tunnel's first bytes
// immediately, so both arrive in one segment. A client that discarded its
// bufio.Reader's contents would drop the head of the very first response — the
// same truncation bug, in the other direction.
func TestUpgradeDialerPreservesBytesPipelinedAfterThe101(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	const pipelined = "RELAY-FIRST-BYTES"

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		accept := wsAccept(req.Header.Get("Sec-WebSocket-Key"))

		// The 101 and the tunnel's first bytes go out together.
		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n" + pipelined
		if _, err := conn.Write([]byte(resp)); err != nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}()

	client, err := UpgradeDialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: ln.Addr().String(),
		Request:    connectReq("example.com:443"),
		Timeout:    testTimeout,
		Logger:     logx.Discard(),
		Settings:   transport.Settings{},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	if got := string(readN(t, client, len(pipelined))); got != pipelined {
		t.Fatalf("the client read %q, want %q: the bytes pipelined after the 101 were dropped", got, pipelined)
	}
}

// ---------------------------------------------------------------------------
// The fallback site
// ---------------------------------------------------------------------------

// fallbackSink is a listener standing in for the real website a relay forwards
// probes to.
type fallbackSink struct {
	addr string

	mu        sync.Mutex
	requests  []*http.Request
	pipelined []byte
}

// startFallbackSink accepts one connection, records what it received, answers it,
// and closes so the relay's copy loop terminates.
func startFallbackSink(t *testing.T, pipelinedLen int) *fallbackSink {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	sink := &fallbackSink{addr: ln.Addr().String()}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}

		var pipelined []byte
		if pipelinedLen > 0 {
			pipelined = make([]byte, pipelinedLen)
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.ReadFull(br, pipelined); err != nil {
				pipelined = nil
			}
		}

		sink.mu.Lock()
		sink.requests = append(sink.requests, req)
		sink.pipelined = pipelined
		sink.mu.Unlock()

		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi"))
	}()

	return sink
}

// first returns the request the sink received.
func (s *fallbackSink) first(t *testing.T) *http.Request {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		if len(s.requests) > 0 {
			req := s.requests[0]
			s.mu.Unlock()
			return req
		}
		s.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the fallback site never received the forwarded request")
	return nil
}

// TestFallbackForwardsANonConnectRequest proves a plain GET is forwarded to the
// configured site rather than refused.
//
// This is the disguise: a relay that answers a browser's GET with a 404 is
// trivially identifiable as a proxy, while one that serves the site it claims to
// be is indistinguishable from that site.
func TestFallbackForwardsANonConnectRequest(t *testing.T) {
	sink := startFallbackSink(t, 0)
	h := startRelay(t, ConnectHandler{}, transport.Settings{"fallbackAddr": sink.addr}, logx.Discard())

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	writeAsync(conn, []byte("GET /index.html?x=1 HTTP/1.1\r\nHost: www.example.com\r\nX-Test: 1\r\n\r\n"))

	req := sink.first(t)
	if req.Method != http.MethodGet {
		t.Errorf("the fallback site saw method %q, want GET", req.Method)
	}
	if req.URL.RequestURI() != "/index.html?x=1" {
		t.Errorf("the fallback site saw path %q, want /index.html?x=1", req.URL.RequestURI())
	}
	if req.Host != "www.example.com" {
		t.Errorf("the fallback site saw Host %q, want www.example.com", req.Host)
	}
	if got := req.Header.Get("X-Test"); got != "1" {
		t.Errorf("the fallback site saw X-Test %q, want 1: the original headers must survive", got)
	}

	// The relay reports this as a handled fallback, not a failure. The server
	// classifies it by this exact substring, so a reworded message would turn
	// every masked probe into a logged handshake failure.
	err = h.waitErr(t)
	if !errors.Is(err, ErrFallbackHandled) {
		t.Errorf("the relay error is %v, want ErrFallbackHandled", err)
	}
	if err == nil || !strings.Contains(err.Error(), "forwarded to fallback") {
		t.Errorf("the error %q does not contain the substring the server classifies on", err)
	}
}

// TestFallbackForwardsPipelinedBytes proves the bytes buffered behind the
// forwarded request are replayed to the fallback site.
//
// A browser may pipeline its next request or a form body into the same segment.
// Dropping those bytes would make the fallback site see a truncated request,
// which is both a broken disguise and a visible error at the far end.
func TestFallbackForwardsPipelinedBytes(t *testing.T) {
	const pipelined = "PIPELINED-BODY"

	sink := startFallbackSink(t, len(pipelined))
	h := startRelay(t, ConnectHandler{}, transport.Settings{"fallbackAddr": sink.addr}, logx.Discard())

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	blob := "GET /a HTTP/1.1\r\nHost: www.example.com\r\n\r\n" + pipelined
	writeAsync(conn, []byte(blob))

	sink.first(t)

	sink.mu.Lock()
	got := string(sink.pipelined)
	sink.mu.Unlock()
	if got != pipelined {
		t.Errorf("the fallback site received %q of pipelined data, want %q", got, pipelined)
	}
}

// TestNoFallbackConfiguredRefusesTheRequest proves a GET is refused when no
// fallback site is configured, and that the refusal is NOT reported as a handled
// fallback.
//
// The distinction is operational: a fallback is counted as success while a
// refusal is counted as an authentication failure, so misreporting one as the
// other would hide a flood of probes or invent a fault that is not there.
func TestNoFallbackConfiguredRefusesTheRequest(t *testing.T) {
	h := startRelay(t, ConnectHandler{}, transport.Settings{}, logx.Discard())

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	writeAsync(conn, []byte("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"))

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read the refusal: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("the relay answered %d, want 404", resp.StatusCode)
	}

	err = h.waitErr(t)
	if errors.Is(err, ErrFallbackHandled) {
		t.Error("a refusal was reported as a handled fallback, so the server would count it as success")
	}
	if !errors.Is(err, transport.ErrAuthFailed) {
		t.Errorf("the relay error is %v, want ErrAuthFailed", err)
	}
}

// TestFallbackForTheUpgradeHandler proves the httpupgrade transport masks a
// non-upgrade request the same way, through its own independent code path.
func TestFallbackForTheUpgradeHandler(t *testing.T) {
	sink := startFallbackSink(t, 0)
	h := startRelay(t, UpgradeHandler{}, transport.Settings{"fallbackAddr": sink.addr}, logx.Discard())

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	writeAsync(conn, []byte("GET /shop HTTP/1.1\r\nHost: www.example.com\r\n\r\n"))

	req := sink.first(t)
	if req.URL.RequestURI() != "/shop" {
		t.Errorf("the fallback site saw path %q, want /shop", req.URL.RequestURI())
	}

	err = h.waitErr(t)
	if !errors.Is(err, ErrFallbackHandled) {
		t.Errorf("the relay error is %v, want ErrFallbackHandled", err)
	}
	if err == nil || !strings.Contains(err.Error(), "forwarded to fallback") {
		t.Errorf("the error %q does not contain the classified substring", err)
	}
}

// TestNoFallbackConfiguredRefusesTheUpgradeRequest proves the httpupgrade path
// refuses a non-upgrade request when there is no fallback site.
func TestNoFallbackConfiguredRefusesTheUpgradeRequest(t *testing.T) {
	h := startRelay(t, UpgradeHandler{}, transport.Settings{}, logx.Discard())

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	writeAsync(conn, []byte("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"))

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read the refusal: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("the relay answered %d, want 404", resp.StatusCode)
	}

	err = h.waitErr(t)
	if errors.Is(err, ErrFallbackHandled) {
		t.Error("a refusal was reported as a handled fallback")
	}
	if !errors.Is(err, transport.ErrAuthFailed) {
		t.Errorf("the relay error is %v, want ErrAuthFailed", err)
	}
}

// TestFallbackErrorIsClassifiedByTheServersSubstring pins the exact wording the
// server's classifier matches on.
//
// internal/server/stats.go decides whether a failed handshake was a masked
// fallback by searching the error text for "forwarded to fallback". The string
// is therefore load-bearing API, not a log message, and a copy-edit would
// silently reclassify every probe as a failure.
func TestFallbackErrorIsClassifiedByTheServersSubstring(t *testing.T) {
	const classified = "forwarded to fallback"
	if !strings.Contains(ErrFallbackHandled.Error(), classified) {
		t.Errorf("ErrFallbackHandled is %q, which does not contain %q, so the server would count "+
			"every masked probe as a handshake failure", ErrFallbackHandled.Error(), classified)
	}
}

// ---------------------------------------------------------------------------
// Pre-shared key authentication
// ---------------------------------------------------------------------------

// TestUpgradeCorrectPSKIsAccepted proves a matching key completes the httpupgrade
// handshake and carries data.
//
// httpupgrade carries the target in the PortTransit preamble, so unlike CONNECT
// it really does authenticate with the key.
func TestUpgradeCorrectPSKIsAccepted(t *testing.T) {
	settings := transport.Settings{"psk": "base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}
	h := startRelay(t, UpgradeHandler{}, settings, logx.Discard())

	client, err := UpgradeDialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: h.addr,
		Request:    connectReq("example.com:443"),
		Timeout:    testTimeout,
		Logger:     logx.Discard(),
		Settings:   settings,
	})
	if err != nil {
		t.Fatalf("dial with a matching key: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	server := h.waitStream(t)
	t.Cleanup(func() { server.Close() })

	if got := server.Request().Target; got != "example.com:443" {
		t.Errorf("the relay decoded target %q, want example.com:443", got)
	}

	const payload = "authenticated"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := string(readN(t, server, len(payload))); got != payload {
		t.Errorf("the relay read %q, want %q", got, payload)
	}
}

// TestUpgradeWrongPSKIsRefused proves a mismatched key cannot establish a tunnel.
//
// The relay's own error is the assertion, because the client writes its preamble
// and does not wait for a verdict: only the relay's side observes the failed MAC.
func TestUpgradeWrongPSKIsRefused(t *testing.T) {
	h := startRelay(t, UpgradeHandler{}, transport.Settings{
		"psk": "base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
	}, logx.Discard())

	client, err := UpgradeDialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: h.addr,
		Request:    connectReq("example.com:443"),
		Timeout:    testTimeout,
		Logger:     logx.Discard(),
		Settings:   transport.Settings{"psk": "base64:ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="},
	})
	if err == nil {
		t.Cleanup(func() { client.Close() })
	}

	serverErr := h.waitErr(t)
	if !errors.Is(serverErr, transport.ErrAuthFailed) {
		t.Errorf("the relay error is %v, want ErrAuthFailed", serverErr)
	}
	if !strings.Contains(serverErr.Error(), "MAC") {
		t.Errorf("the relay error does not name the failed MAC: %v", serverErr)
	}
}

// TestUpgradeRequiresABasicCredentialWhenConfigured proves the upgrade path
// enforces HTTP Basic auth when a username is set.
//
// An operator who configures a username on an httpupgrade listener expects it to
// gate the handshake; a relay that ignored it would be reachable by anyone.
func TestUpgradeRequiresABasicCredentialWhenConfigured(t *testing.T) {
	h := startRelay(t, UpgradeHandler{}, transport.Settings{"username": "alice", "password": "s3cret"}, logx.Discard())

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	req := "GET / HTTP/1.1\r\nHost: relay.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	writeAsync(conn, []byte(req))

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read the refusal: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the relay answered %d, want 401", resp.StatusCode)
	}

	if err := h.waitErr(t); !errors.Is(err, transport.ErrAuthFailed) {
		t.Errorf("the relay error is %v, want ErrAuthFailed", err)
	}
}

// TestConnectSchemeDoesNotVerifyThePreamble documents that the "http" scheme
// authenticates with HTTP Basic only: the psk setting has no effect there.
//
// CONNECT is a native-header transport — the request line carries the target and
// the relay returns the stream without ever reading a PortTransit preamble — so
// there is no MAC for a key to verify. The behaviour is recorded here because the
// setting is accepted silently: an operator who configures only `psk` on an
// `http` listener believes the relay is authenticated when it is not.
func TestConnectSchemeDoesNotVerifyThePreamble(t *testing.T) {
	h := startRelay(t, ConnectHandler{}, transport.Settings{
		"psk": "base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
	}, logx.Discard())

	// A client with a completely different key still completes the handshake,
	// because no preamble is exchanged on this scheme.
	client, err := ConnectDialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: h.addr,
		Request:    connectReq("example.com:443"),
		Timeout:    testTimeout,
		Logger:     logx.Discard(),
		Settings:   transport.Settings{"psk": "an-entirely-different-key"},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	server := h.waitStream(t)
	t.Cleanup(func() { server.Close() })

	// The stream carries the client's payload directly: no preamble is in front
	// of it, which is the mechanical reason the key is not checked.
	const payload = "no preamble here"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := readN(t, server, len(payload))
	if string(got) != payload {
		t.Fatalf("the relay read %q, want %q: a preamble was unexpectedly placed in the stream", got, payload)
	}
}

// ---------------------------------------------------------------------------
// Nil-logger safety
// ---------------------------------------------------------------------------

// TestNilLoggerDoesNotPanic proves a full handshake with no logger configured
// succeeds on both schemes.
//
// This was a real panic: a loggerFor helper that returned a nil interface
// panicked on the first method call, and the transports log from inside the
// handshake path, so a relay started without a logger died on its first
// connection.
func TestNilLoggerDoesNotPanic(t *testing.T) {
	cases := []struct {
		name    string
		handler transport.Handler
		dial    func(addr string) (transport.Stream, error)
	}{
		{
			name:    "http CONNECT",
			handler: ConnectHandler{},
			dial: func(addr string) (transport.Stream, error) {
				return ConnectDialer{}.Dial(context.Background(), transport.DialRequest{
					ServerAddr: addr,
					Request:    connectReq("example.com:443"),
					Timeout:    testTimeout,
					Logger:     nil,
					Settings:   transport.Settings{},
				})
			},
		},
		{
			name:    "httpupgrade",
			handler: UpgradeHandler{},
			dial: func(addr string) (transport.Stream, error) {
				return UpgradeDialer{}.Dial(context.Background(), transport.DialRequest{
					ServerAddr: addr,
					Request:    connectReq("example.com:443"),
					Timeout:    testTimeout,
					Logger:     nil,
					Settings:   transport.Settings{},
				})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := startRelay(t, tc.handler, transport.Settings{}, nil)

			client, err := tc.dial(h.addr)
			if err != nil {
				t.Fatalf("dial with a nil logger: %v", err)
			}
			t.Cleanup(func() { client.Close() })

			server := h.waitStream(t)
			t.Cleanup(func() { server.Close() })

			const payload = "no logger"
			if _, err := client.Write([]byte(payload)); err != nil {
				t.Fatalf("write: %v", err)
			}
			if got := string(readN(t, server, len(payload))); got != payload {
				t.Errorf("the relay read %q, want %q", got, payload)
			}
		})
	}
}

// TestNilLoggerDoesNotPanicOnRejectedHandshakes proves the failure paths log
// through the same nil-safe wrapper.
//
// A no-op logger installed only on the success path would still panic whenever a
// prober or a misconfigured client was refused — which on a public port is the
// common case, not the rare one.
func TestNilLoggerDoesNotPanicOnRejectedHandshakes(t *testing.T) {
	cases := []struct {
		name     string
		handler  transport.Handler
		settings transport.Settings
		raw      string
	}{
		{
			name:     "CONNECT with no authority",
			handler:  ConnectHandler{},
			settings: transport.Settings{},
			raw:      "CONNECT /rpc HTTP/1.1\r\n\r\n",
		},
		{
			name:     "CONNECT with missing credentials",
			handler:  ConnectHandler{},
			settings: transport.Settings{"username": "alice", "password": "s3cret"},
			raw:      "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
		},
		{
			name:     "a malformed first line",
			handler:  ConnectHandler{},
			settings: transport.Settings{},
			raw:      "garbage\r\n\r\n",
		},
		{
			name:     "an upgrade without credentials",
			handler:  UpgradeHandler{},
			settings: transport.Settings{"username": "alice", "password": "s3cret"},
			raw: "GET / HTTP/1.1\r\nHost: relay.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := startRelay(t, tc.handler, tc.settings, nil)

			conn, err := net.Dial("tcp", h.addr)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			t.Cleanup(func() { conn.Close() })

			writeAsync(conn, []byte(tc.raw))

			if err := h.waitErr(t); err == nil {
				t.Fatal("the relay accepted a request it should have refused")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TLS on the client
// ---------------------------------------------------------------------------

// TestHTTPTransportsDoNotUseTLSByDefault proves both HTTP transports speak
// plaintext unless tls is explicitly enabled.
//
// This is the opposite of the websocket transport's default, and the difference
// is deliberate: an HTTP proxy is normally reached over a plaintext connection,
// and a client that silently wrapped CONNECT in TLS would fail against every
// ordinary proxy. The assertion is behavioural — the first byte on the wire is
// what reveals which protocol was actually spoken.
func TestHTTPTransportsDoNotUseTLSByDefault(t *testing.T) {
	cases := []struct {
		name     string
		settings transport.Settings
		want     byte
		what     string
	}{
		{"CONNECT unset", transport.Settings{}, 'C', "a plaintext CONNECT"},
		{"CONNECT explicitly off", transport.Settings{"tls": false}, 'C', "a plaintext CONNECT"},
		{"CONNECT explicitly on", transport.Settings{"tls": true}, 0x16, "a TLS ClientHello"},
		{"upgrade unset", transport.Settings{}, 'G', "a plaintext GET"},
		{"upgrade explicitly off", transport.Settings{"tls": false}, 'G', "a plaintext GET"},
		{"upgrade explicitly on", transport.Settings{"tls": true}, 0x16, "a TLS ClientHello"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			t.Cleanup(func() { ln.Close() })

			first := make(chan byte, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				buf := make([]byte, 1)
				if _, err := io.ReadFull(conn, buf); err != nil {
					return
				}
				first <- buf[0]
			}()

			dial := ConnectDialer{}.Dial
			if strings.Contains(tc.name, "upgrade") {
				dial = UpgradeDialer{}.Dial
			}
			// The dial cannot complete against this stub; the first byte is the
			// observation under test.
			_, _ = dial(context.Background(), transport.DialRequest{
				ServerAddr: ln.Addr().String(),
				Request:    connectReq("example.com:443"),
				Timeout:    testTimeout,
				Logger:     logx.Discard(),
				Settings:   tc.settings,
			})

			select {
			case b := <-first:
				if b != tc.want {
					t.Errorf("the first byte is 0x%02x, want 0x%02x (%s)", b, tc.want, tc.what)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the listener never received a byte")
			}
		})
	}
}

// TestConnectDialerOverTLS proves the tls path completes against a self-signed
// relay.
//
// The certificate is generated by the shared helper so the test is
// self-contained, and the TLS listener is built by the test because the
// transport itself has no server-side certificate handling.
func TestConnectDialerOverTLS(t *testing.T) {
	cert, err := transport.GenerateSelfSigned(transport.SelfSignedOptions{CommonName: "porttransit-test"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})

	results := make(chan relayResult, 1)
	go func() {
		conn, err := tlsLn.Accept()
		if err != nil {
			results <- relayResult{err: err}
			return
		}
		st, err := ConnectHandler{}.Handle(context.Background(), conn, transport.HandleRequest{
			Timeout:  testTimeout,
			Logger:   logx.Discard(),
			Settings: transport.Settings{},
		})
		results <- relayResult{stream: st, err: err}
	}()

	client, err := ConnectDialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: ln.Addr().String(),
		Request:    connectReq("example.com:443"),
		Timeout:    testTimeout,
		Logger:     logx.Discard(),
		Settings:   transport.Settings{"tls": true, "insecure": true},
	})
	if err != nil {
		t.Fatalf("CONNECT over TLS: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	var server transport.Stream
	select {
	case r := <-results:
		if r.err != nil {
			t.Fatalf("the TLS relay side failed: %v", r.err)
		}
		server = r.stream
	case <-time.After(10 * time.Second):
		t.Fatal("the TLS relay never produced a stream")
	}
	t.Cleanup(func() { server.Close() })

	const payload = "over tls"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := string(readN(t, server, len(payload))); got != payload {
		t.Errorf("the TLS relay read %q, want %q", got, payload)
	}
}
