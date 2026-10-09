package websocket

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"porttransit/internal/logx"
	"porttransit/internal/transport"
)

// testTimeout bounds every handshake in this file.
//
// A handshake that never completes must fail the test quickly: the default
// ten-second transport timeout multiplied by a handful of tests would make a
// single regression look like a hung suite rather than a failing assertion.
const testTimeout = 3 * time.Second

// readN reads exactly n bytes, failing the test on a short read.
//
// The read deadline is what turns "the peer never answered" into a fast
// failure: without it a dropped reply would stall until the whole test binary
// times out, hiding which assertion actually broke.
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
// byte — so any helper that writes inline while the peer may write a reply
// deadlocks the test. Writing from a goroutine keeps the test body free to
// drain the peer's reply.
func writeAsync(conn net.Conn, buf []byte) {
	go func() { _, _ = conn.Write(buf) }()
}

// connectReq is the request the client conveys to the relay.
func connectReq(target string) *transport.Request {
	return &transport.Request{Command: transport.CmdConnectTCP, Target: target}
}

// ---------------------------------------------------------------------------
// A raw-socket relay harness
// ---------------------------------------------------------------------------

// relayHarness is a listener whose accept loop hands bare TCP sockets to
// Handler.Handle, which is exactly what the relay's own accept loop does.
//
// The distinction matters: Handle must drive the HTTP upgrade itself, because
// nothing in the relay has parsed the request for it. A harness built on
// http.Server would silently exercise the other deployment shape instead and
// could not catch the regression this harness exists to prevent.
type relayHarness struct {
	addr string

	streams chan transport.Stream
	errs    chan error

	mu   sync.Mutex
	held []transport.Stream
}

func startWSRelay(t *testing.T, settings transport.Settings, logger *logx.Logger) *relayHarness {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	h := &relayHarness{
		addr:    ln.Addr().String(),
		streams: make(chan transport.Stream, 4),
		errs:    make(chan error, 4),
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				st, err := Handler{}.Handle(ctx, c, transport.HandleRequest{
					Timeout:  testTimeout,
					Logger:   logger,
					Settings: settings,
				})
				if err != nil {
					select {
					case h.errs <- err:
					case <-ctx.Done():
					}
					return
				}
				h.mu.Lock()
				h.held = append(h.held, st)
				h.mu.Unlock()
				select {
				case h.streams <- st:
				case <-ctx.Done():
					st.Close()
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
	case st := <-h.streams:
		return st
	case err := <-h.errs:
		t.Fatalf("relay side of the handshake failed: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the relay never produced a stream")
	}
	return nil
}

// waitErr returns the error the relay side reported.
func (h *relayHarness) waitErr(t *testing.T) error {
	t.Helper()
	select {
	case err := <-h.errs:
		return err
	case st := <-h.streams:
		st.Close()
		t.Fatal("the relay accepted a connection it should have refused")
	case <-time.After(10 * time.Second):
		t.Fatal("the relay never reported a result")
	}
	return nil
}

// dialWS performs the client half against addr.
func dialWS(ctx context.Context, addr string, settings transport.Settings, req *transport.Request, logger *logx.Logger) (transport.Stream, error) {
	return Dialer{}.Dial(ctx, transport.DialRequest{
		ServerAddr: addr,
		Request:    req,
		Timeout:    testTimeout,
		Logger:     logger,
		Settings:   settings,
	})
}

// openWSPair completes one handshake end to end and returns both halves.
func openWSPair(t *testing.T, serverSettings, clientSettings transport.Settings) (client, server transport.Stream) {
	t.Helper()

	h := startWSRelay(t, serverSettings, logx.Discard())
	client, err := dialWS(context.Background(), h.addr, clientSettings, connectReq("example.com:443"), logx.Discard())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	server = h.waitStream(t)
	t.Cleanup(func() { server.Close() })
	return client, server
}

// ---------------------------------------------------------------------------
// A frame-level WebSocket pair
// ---------------------------------------------------------------------------

// wsRawPair returns both ends of a real WebSocket handshake as raw gorilla
// connections, so a test can inspect individual frames.
//
// The server half is upgraded through the transport's own hijackWriter, which
// is the adapter that lets gorilla's Upgrader run without an http.Server.
func wsRawPair(t *testing.T) (client, server *websocket.Conn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	accepted := make(chan *websocket.Conn, 1)
	failed := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			failed <- err
			return
		}
		br := bufio.NewReader(conn)
		httpReq, err := http.ReadRequest(br)
		if err != nil {
			failed <- err
			return
		}
		_ = httpReq.Body.Close()

		up := websocket.Upgrader{
			ReadBufferSize:  32 * 1024,
			WriteBufferSize: 32 * 1024,
			CheckOrigin:     func(*http.Request) bool { return true },
		}
		ws, err := up.Upgrade(&hijackWriter{conn: conn, br: br}, httpReq, nil)
		if err != nil {
			failed <- err
			return
		}
		accepted <- ws
	}()

	d := websocket.Dialer{HandshakeTimeout: testTimeout}
	client, resp, err := d.Dial("ws://"+ln.Addr().String()+"/ws", nil)
	if err != nil {
		t.Fatalf("client upgrade: %v (resp %v)", err, resp)
	}
	t.Cleanup(func() { client.Close() })

	var serverConn *websocket.Conn
	select {
	case serverConn = <-accepted:
	case err := <-failed:
		t.Fatalf("server upgrade: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the server half never completed the upgrade")
	}
	t.Cleanup(func() { serverConn.Close() })
	return client, serverConn
}

// halfCloser is the optional method a Stream exposes so a caller can signal
// end-of-stream without tearing down the read direction.
//
// Stream embeds net.Conn, whose method set has no CloseWrite, so the method is
// only reachable through an assertion. That is deliberate in the product — the
// relay's copy loop tests for it exactly this way — so the tests do too.
type halfCloser interface{ CloseWrite() error }

// closeWrite half-closes a stream, failing the test when the stream does not
// support it.
//
// A stream that silently lacked CloseWrite would make every half-close a no-op,
// which is the defect these tests exist to catch, so the assertion is part of
// the assertion under test rather than a convenience.
func closeWrite(t *testing.T, st transport.Stream) {
	t.Helper()
	cw, ok := st.(halfCloser)
	if !ok {
		t.Fatalf("the %T stream exposes no CloseWrite, so a half-close cannot reach the peer", st)
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Registration and naming
// ---------------------------------------------------------------------------

// TestRegistration proves the transport is reachable under the exact scheme
// name the config and the GUI use, and that the conventional port matches.
//
// A mismatch here is not a compile error: the client would simply fail to find
// the scheme at dial time, which is why the literal is asserted rather than
// compared against the same constant.
func TestRegistration(t *testing.T) {
	if Name != "ws" {
		t.Errorf("Name = %q, want \"ws\"", Name)
	}
	if DefaultPort != 8080 {
		t.Errorf("DefaultPort = %d, want 8080", DefaultPort)
	}

	f, ok := transport.Lookup(Name)
	if !ok {
		t.Fatalf("transport.Lookup(%q) did not find the websocket transport", Name)
	}
	if f.DefaultPort != 8080 {
		t.Errorf("the registered factory reports port %d, want 8080", f.DefaultPort)
	}
	if f.Build == nil {
		t.Fatal("the registered factory has no Build function")
	}

	d, h := f.Build()
	if d == nil || h == nil {
		t.Fatal("the factory did not build both a dialer and a handler")
	}
	if d.Name() != Name || h.Name() != Name {
		t.Errorf("the built halves report %q and %q, want %q", d.Name(), h.Name(), Name)
	}

	// The registry is what the relay resolves a configured listener through, so
	// the same lookup the relay performs must succeed.
	if _, err := transport.NewHandler(Name); err != nil {
		t.Errorf("transport.NewHandler(%q): %v", Name, err)
	}
	if _, err := transport.NewDialer(Name); err != nil {
		t.Errorf("transport.NewDialer(%q): %v", Name, err)
	}
}

// ---------------------------------------------------------------------------
// The wsConn adapter: a message-framed protocol behind a byte-stream interface
// ---------------------------------------------------------------------------

// TestWSConnRoundTrip proves bytes written to the adapter arrive intact on the
// peer, which is the only property the relay's copy loop depends on.
func TestWSConnRoundTrip(t *testing.T) {
	client, server := wsRawPair(t)
	wc := newWSConn(client)

	const payload = "the quick brown fox jumps over the lazy dog"
	if n, err := wc.Write([]byte(payload)); err != nil || n != len(payload) {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(payload))
	}

	typ, data, err := server.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if typ != websocket.BinaryMessage {
		t.Errorf("the frame type is %d, want BinaryMessage", typ)
	}
	if string(data) != payload {
		t.Errorf("the peer received %q, want %q", data, payload)
	}
}

// TestWSConnLargePayloadSurvives proves a payload far larger than any single
// socket buffer is delivered byte for byte.
//
// WebSocket is message-framed while net.Conn is a byte stream, so the adapter
// must split a large frame across many Reads without losing or duplicating a
// byte. A silent off-by-one there would corrupt every transfer that crosses a
// buffer boundary, which is most of them.
func TestWSConnLargePayloadSurvives(t *testing.T) {
	client, server := wsRawPair(t)
	write := newWSConn(client)
	read := newWSConn(server)

	const size = 1 << 20 // 1 MiB
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i * 7)
	}

	done := make(chan error, 1)
	go func() {
		_, err := write.Write(payload)
		done <- err
	}()

	_ = read.SetReadDeadline(time.Now().Add(10 * time.Second))
	got := make([]byte, size)
	if _, err := io.ReadFull(read, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the 1 MiB payload did not survive the adapter intact")
	}
}

// TestWSConnReadReturnsEOFOnEmptyFrame proves the end-of-stream marker is
// recognised as a clean finish rather than as a zero-length payload.
//
// Before this was fixed Read looped on an empty frame, so a peer that had
// finished writing looked exactly like a peer that was merely quiet.
func TestWSConnReadReturnsEOFOnEmptyFrame(t *testing.T) {
	client, server := wsRawPair(t)

	if err := server.WriteMessage(websocket.BinaryMessage, nil); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	wc := newWSConn(client)
	_ = wc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8)
	n, err := wc.Read(buf)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("Read of an empty frame = (%d, %v), want (0, io.EOF)", n, err)
	}
}

// TestCloseWriteSendsExactlyOneMarker proves CloseWrite is idempotent and that
// the marker is a single empty binary frame.
//
// The idempotence is not cosmetic: the relay's copy loop and the client's pipe
// both half-close when one direction ends, and a second marker would be read
// by the peer as a second end-of-stream — or, worse, as a payload frame in a
// stream that had already been torn down.
func TestCloseWriteSendsExactlyOneMarker(t *testing.T) {
	client, server := wsRawPair(t)
	wc := newWSConn(client)

	if err := wc.CloseWrite(); err != nil {
		t.Fatalf("the first CloseWrite returned %v, want nil", err)
	}
	if err := wc.CloseWrite(); err != nil {
		t.Fatalf("the second CloseWrite returned %v, want nil", err)
	}

	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, data, err := server.ReadMessage()
	if err != nil {
		t.Fatalf("the peer did not receive the marker: %v", err)
	}
	if typ != websocket.BinaryMessage || len(data) != 0 {
		t.Fatalf("the marker is (type %d, %d bytes), want an empty binary frame", typ, len(data))
	}

	// Nothing else may follow. A second marker would surface here as another
	// empty binary frame; a timeout is the correct outcome.
	_ = server.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if typ, data, err := server.ReadMessage(); err == nil {
		t.Fatalf("a second CloseWrite sent another frame: (type %d, %d bytes)", typ, len(data))
	}
}

// TestCloseWriteReachesThePeerAsEOF proves the marker crosses a real relay
// handshake and is observed as io.EOF, which is the contract the relay's copy
// loop relies on to release a finished tunnel immediately.
//
// Without it every WebSocket tunnel lingers until its idle timeout, which
// presents as a healthy relay that slowly runs out of connections.
func TestCloseWriteReachesThePeerAsEOF(t *testing.T) {
	client, server := openWSPair(t, transport.Settings{"tls": false}, transport.Settings{"tls": false})

	start := time.Now()
	closeWrite(t, client)

	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := server.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("the peer saw (%d, %v), want (0, io.EOF)", n, err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("the end-of-stream marker took %v to arrive; it must be prompt", elapsed)
	}
}

// TestHalfCloseLeavesTheOtherDirectionOpen proves CloseWrite is a true
// half-close: the peer still receives data after the marker.
//
// A CloseWrite implemented as a full Close would pass the EOF test above while
// silently truncating every response that is still in flight — the classic
// half-close mistake.
func TestHalfCloseLeavesTheOtherDirectionOpen(t *testing.T) {
	client, server := openWSPair(t, transport.Settings{"tls": false}, transport.Settings{"tls": false})

	closeWrite(t, client)

	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := server.Read(make([]byte, 4)); !errors.Is(err, io.EOF) {
		t.Fatalf("the peer saw %v, want io.EOF", err)
	}

	// The server's write direction must still be usable.
	const reply = "reply after half-close"
	if _, err := server.Write([]byte(reply)); err != nil {
		t.Fatalf("the relay could not write after its peer half-closed: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(reply))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("the client could not read after half-closing: %v", err)
	}
	if string(got) != reply {
		t.Errorf("the client read %q, want %q", got, reply)
	}
}

// TestPayloadsThatLookLikeTheMarkerAreNotTreatedAsOne proves the marker is
// unambiguous: an all-zero payload and a maximum-size payload are ordinary
// data.
//
// The marker is an empty frame precisely because a payload frame is never
// empty. If the implementation ever grew a length-based or content-based
// shortcut, an all-zero buffer would truncate the stream instead of being
// delivered.
func TestPayloadsThatLookLikeTheMarkerAreNotTreatedAsOne(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{"all zeros", make([]byte, 4096)},
		{"single zero byte", []byte{0x00}},
		{"four mebibytes minus one", bytes.Repeat([]byte{0xAB}, (4<<20)-1)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := wsRawPair(t)
			write := newWSConn(client)
			read := newWSConn(server)

			done := make(chan error, 1)
			go func() {
				_, err := write.Write(tc.payload)
				done <- err
			}()

			_ = read.SetReadDeadline(time.Now().Add(20 * time.Second))
			got := make([]byte, len(tc.payload))
			if _, err := io.ReadFull(read, got); err != nil {
				t.Fatalf("ReadFull: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatalf("Write: %v", err)
			}
			if !bytes.Equal(got, tc.payload) {
				t.Fatalf("a %d-byte payload was not delivered intact", len(tc.payload))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Error translation: "the peer finished" must not look like "the peer broke"
// ---------------------------------------------------------------------------

// TestTranslateWSErrorMapsACleanCloseToEOF proves a peer that closed normally
// is reported as a finished stream.
//
// A caller that cannot tell a clean close from a broken connection reports
// healthy tunnels as failures, which turns every ordinary disconnect into an
// alert.
func TestTranslateWSErrorMapsACleanCloseToEOF(t *testing.T) {
	cases := []struct {
		name string
		code int
	}{
		{"normal closure", websocket.CloseNormalClosure},
		{"going away", websocket.CloseGoingAway},
		{"no status received", websocket.CloseNoStatusReceived},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := translateWSError(&websocket.CloseError{Code: tc.code, Text: "bye"})
			if !errors.Is(err, io.EOF) {
				t.Errorf("close code %d translated to %v, want io.EOF", tc.code, err)
			}
		})
	}
}

// TestTranslateWSErrorKeepsRealFailuresVisible proves a protocol violation or
// an abrupt TCP reset is NOT laundered into io.EOF.
//
// The distinction is the whole point of the mapping: treating every close as a
// clean finish would hide a peer that died mid-frame, and the relay would
// report a truncated transfer as complete.
func TestTranslateWSErrorKeepsRealFailuresVisible(t *testing.T) {
	abrupt := &websocket.CloseError{Code: websocket.CloseAbnormalClosure, Text: io.ErrUnexpectedEOF.Error()}
	if errors.Is(translateWSError(abrupt), io.EOF) {
		t.Error("an abnormal closure was translated to io.EOF, hiding a broken connection")
	}

	violation := &websocket.CloseError{Code: websocket.CloseProtocolError, Text: "bad opcode"}
	if errors.Is(translateWSError(violation), io.EOF) {
		t.Error("a protocol violation was translated to io.EOF")
	}

	sentinel := errors.New("disk on fire")
	if got := translateWSError(sentinel); !errors.Is(got, sentinel) {
		t.Errorf("an unrelated error was rewritten to %v", got)
	}

	if got := translateWSError(nil); got != nil {
		t.Errorf("translateWSError(nil) = %v, want nil", got)
	}
}

// TestTranslateWSErrorMapsErrCloseSentToNetClosed proves a write to a
// connection whose close frame has already gone out reports net.ErrClosed.
//
// net.ErrClosed is the vocabulary callers already use to mean "this side is
// finished", so mapping gorilla's private sentinel onto it lets the relay stop
// treating a normal shutdown as an unexpected error.
func TestTranslateWSErrorMapsErrCloseSentToNetClosed(t *testing.T) {
	if got := translateWSError(websocket.ErrCloseSent); !errors.Is(got, net.ErrClosed) {
		t.Errorf("ErrCloseSent translated to %v, want net.ErrClosed", got)
	}
}

// TestPeerCloseIsObservedAsEOF proves the translation happens on a real close,
// not merely in the helper: the peer sends a normal close frame and the
// adapter reports io.EOF.
func TestPeerCloseIsObservedAsEOF(t *testing.T) {
	client, server := wsRawPair(t)

	if err := server.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(time.Second)); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	wc := newWSConn(client)
	_ = wc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := wc.Read(make([]byte, 8)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read after a normal close = %v, want io.EOF", err)
	}
}

// TestAbruptSocketCloseIsNotReportedAsEOF proves a peer that vanished without a
// close frame is reported as a failure.
//
// This is the mirror of the test above, and it is the one that catches an
// over-eager translation: a tunnel that dies mid-transfer must not look
// identical to one that ended cleanly.
func TestAbruptSocketCloseIsNotReportedAsEOF(t *testing.T) {
	client, server := wsRawPair(t)

	// Drop the TCP connection with no close handshake at all.
	if err := server.UnderlyingConn().Close(); err != nil {
		t.Fatalf("close the peer socket: %v", err)
	}

	wc := newWSConn(client)
	_ = wc.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := wc.Read(make([]byte, 8))
	if err == nil {
		t.Fatal("Read returned no error after the peer vanished")
	}
	if errors.Is(err, io.EOF) {
		t.Fatal("an abrupt TCP close was reported as a clean end of stream")
	}
}

// ---------------------------------------------------------------------------
// The relay-side HTTP handshake (the regression that stalled every connection)
// ---------------------------------------------------------------------------

// TestHandleCompletesTheUpgradeOnARawSocket is the regression test for the
// defect where the relay never completed the WebSocket upgrade.
//
// Handle used to assume the connection had already been upgraded, because only
// ServeHTTP performed the upgrade. The relay's accept loop, however, hands
// Handle a bare TCP socket, so the client's HTTP upgrade request was parsed as
// a PortTransit preamble and rejected — every WebSocket connection failed. The
// test therefore drives Handle over a real TCP socket with no http.Server
// anywhere in the picture.
func TestHandleCompletesTheUpgradeOnARawSocket(t *testing.T) {
	client, server := openWSPair(t, transport.Settings{"tls": false}, transport.Settings{"tls": false})

	if got := server.TransportName(); got != Name {
		t.Errorf("the relay stream reports transport %q, want %q", got, Name)
	}
	if got := server.Request().Target; got != "example.com:443" {
		t.Errorf("the relay decoded target %q, want example.com:443", got)
	}
	if got := client.Request().Target; got != "example.com:443" {
		t.Errorf("the client stream reports target %q, want example.com:443", got)
	}

	// The upgrade alone is not enough: the framed payload must round-trip
	// through the stream Handle returned.
	const payload = "payload after a raw-socket upgrade"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := readN(t, server, len(payload))
	if string(got) != payload {
		t.Errorf("the relay read %q, want %q", got, payload)
	}
}

// TestHandleUpgradeReplyIsAWellFormed101 proves the relay answers the upgrade
// itself, rather than merely tolerating the request.
//
// A relay that parsed the request but replied with something other than a 101
// would pass a naive "did Handle return a stream" check while failing against
// every real WebSocket client.
func TestHandleUpgradeReplyIsAWellFormed101(t *testing.T) {
	h := startWSRelay(t, transport.Settings{"tls": false}, logx.Discard())

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	key := "dGhlIHNhbXBsZSBub25jZQ=="
	req := "GET /ws HTTP/1.1\r\nHost: " + h.addr + "\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write the upgrade request: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read the upgrade reply: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("the relay answered %s, want 101", resp.Status)
	}
	if got := resp.Header.Get("Upgrade"); !strings.EqualFold(got, "websocket") {
		t.Errorf("the reply advertises Upgrade: %q, want websocket", got)
	}
	// The accept token is what a real client validates, and RFC 6455 pins it
	// for this exact key.
	if got, want := resp.Header.Get("Sec-WebSocket-Accept"), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="; got != want {
		t.Errorf("Sec-WebSocket-Accept = %q, want %q", got, want)
	}

	// The 101 is only half the handshake: the relay must then accept a framed
	// preamble and produce a usable stream, which proves the upgrade left the
	// connection in a state the adapter can actually read from.
	preamble, err := transport.EncodePreamble(&transport.Preamble{
		Command: transport.CmdConnectTCP,
		Target:  "example.com:443",
	}, nil)
	if err != nil {
		t.Fatalf("EncodePreamble: %v", err)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(maskedBinaryFrame(preamble)); err != nil {
		t.Fatalf("write the preamble: %v", err)
	}

	st := h.waitStream(t)
	t.Cleanup(func() { st.Close() })
	if got := st.Request().Target; got != "example.com:443" {
		t.Errorf("the relay decoded target %q, want example.com:443", got)
	}
}

// TestServeHTTPCompletesTheUpgrade proves the mounted deployment shape still
// works, so a relay fronted by its own http.Server is not broken by the fix to
// Handle.
//
// Both paths must remain valid: Handle covers the bare accept loop, ServeHTTP
// covers mounting the transport next to the management GUI on one port.
func TestServeHTTPCompletesTheUpgrade(t *testing.T) {
	settings := transport.Settings{"tls": false}

	streams := make(chan transport.Stream, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Handler{}.ServeHTTP(w, r, settings, func(conn net.Conn) error {
			st, err := transport.PreambleServerHandshake(conn, transport.ServerHandshakeConfig{
				Timeout:       testTimeout,
				Logger:        logx.Discard(),
				TransportName: Name,
			})
			if err != nil {
				return err
			}
			streams <- st
			return nil
		})
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: testTimeout}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })

	client, err := dialWS(context.Background(), ln.Addr().String(), settings, connectReq("example.com:443"), logx.Discard())
	if err != nil {
		t.Fatalf("dial through ServeHTTP: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	var server transport.Stream
	select {
	case server = <-streams:
	case <-time.After(10 * time.Second):
		t.Fatal("ServeHTTP never handed a stream to its callback")
	}
	t.Cleanup(func() { server.Close() })

	if got := server.Request().Target; got != "example.com:443" {
		t.Errorf("the mounted relay decoded target %q, want example.com:443", got)
	}
	if got := server.TransportName(); got != Name {
		t.Errorf("the mounted stream reports transport %q, want %q", got, Name)
	}

	const payload = "payload through a mounted handler"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if got := string(readN(t, server, len(payload))); got != payload {
		t.Errorf("the mounted relay read %q, want %q", got, payload)
	}
}

// TestServeHTTPRejectsADisallowedHost proves the hosts allow-list is enforced
// on the mounted path too, so one deployment shape cannot be used to bypass the
// other's policy.
func TestServeHTTPRejectsADisallowedHost(t *testing.T) {
	settings := transport.Settings{"hosts": []string{"allowed.example.com"}}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Handler{}.ServeHTTP(w, r, settings, func(net.Conn) error { return nil })
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: testTimeout}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })

	client := &http.Client{Timeout: 5 * time.Second}
	url := "http://" + ln.Addr().String() + "/ws"

	// A plain GET carrying a Host outside the list must be refused before any
	// upgrade is attempted.
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}
	req.Host = "evil.example.com"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request with a disallowed host: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("a disallowed host was answered %d, want 404", resp.StatusCode)
	}

	// A Host inside the list must get past the check. It then fails the
	// WebSocket handshake, which is the point: the status must not be 404.
	req2, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}
	req2.Host = "allowed.example.com"
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("request with an allowed host: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusNotFound {
		t.Error("an allowed host was refused with 404")
	}
}

// ---------------------------------------------------------------------------
// The hosts allow-list
// ---------------------------------------------------------------------------

// TestHostsSettingRefusesAnUnlistedHost proves the allow-list actually gates the
// relay.
//
// A relay that is reachable under any Host header is trivially discoverable by
// a prober that sweeps names at the relay's address, which defeats the point of
// restricting the list at all.
func TestHostsSettingRefusesAnUnlistedHost(t *testing.T) {
	h := startWSRelay(t, transport.Settings{
		"tls":   false,
		"hosts": []string{"allowed.example.com"},
	}, logx.Discard())

	_, err := dialWS(context.Background(), h.addr, transport.Settings{
		"tls":  false,
		"host": "evil.example.com",
	}, connectReq("example.com:443"), logx.Discard())
	if err == nil {
		t.Fatal("the client completed a handshake with a host outside the allow-list")
	}

	serverErr := h.waitErr(t)
	if !errors.Is(serverErr, transport.ErrAuthFailed) {
		t.Errorf("the relay error is %v, want ErrAuthFailed", serverErr)
	}
	if !strings.Contains(serverErr.Error(), "not allowed") {
		t.Errorf("the relay error does not name the reason: %v", serverErr)
	}
}

// TestHostsSettingAcceptsAListedHost proves the allow-list is a gate rather
// than a blanket refusal, which a broken comparison would otherwise look like.
func TestHostsSettingAcceptsAListedHost(t *testing.T) {
	client, server := openWSPair(t,
		transport.Settings{"tls": false, "hosts": []string{"allowed.example.com"}},
		transport.Settings{"tls": false, "host": "allowed.example.com"},
	)

	if got := server.Request().Target; got != "example.com:443" {
		t.Errorf("the relay decoded target %q, want example.com:443", got)
	}
	if _, err := client.Write([]byte("ok")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := string(readN(t, server, 2)); got != "ok" {
		t.Errorf("the relay read %q, want \"ok\"", got)
	}
}

// TestHostAllowedMatching pins the comparison rules, including the cases that
// must NOT match.
//
// The negative cases carry the security weight: a suffix rule that matched
// "notexample.com" or "example.com.evil.com" would hand an attacker a valid
// Host for a relay that believes it is restricted.
func TestHostAllowedMatching(t *testing.T) {
	cases := []struct {
		name    string
		host    string
		allowed []string
		want    bool
	}{
		{"exact", "example.com", []string{"example.com"}, true},
		{"case insensitive host", "EXAMPLE.com", []string{"example.com"}, true},
		{"case insensitive entry", "example.com", []string{"EXAMPLE.COM"}, true},
		{"the port is ignored", "example.com:8443", []string{"example.com"}, true},
		{"surrounding whitespace in the entry", "example.com", []string{"  example.com  "}, true},
		{"wildcard", "anything.example.net", []string{"*"}, true},
		{"suffix form", "a.example.com", []string{".example.com"}, true},
		{"suffix form does not match the apex", "example.com", []string{".example.com"}, false},
		{"suffix form rejects a lookalike", "notexample.com", []string{".example.com"}, false},
		{"suffix form rejects a prefixed domain", "example.com.evil.com", []string{".example.com"}, false},
		{"a different host", "evil.com", []string{"example.com"}, false},
		{"an empty list entry does not match everything", "example.com", []string{""}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hostAllowed(tc.host, tc.allowed); got != tc.want {
				t.Errorf("hostAllowed(%q, %v) = %v, want %v", tc.host, tc.allowed, got, tc.want)
			}
		})
	}
}

// TestHandleRejectsADisallowedHostOnTheRawPath proves the same policy applies
// to the bare-socket deployment, so an operator cannot be protected on one path
// and exposed on the other.
func TestHandleRejectsADisallowedHostOnTheRawPath(t *testing.T) {
	h := startWSRelay(t, transport.Settings{
		"tls":   false,
		"hosts": []string{"allowed.example.com"},
	}, logx.Discard())

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	req := "GET /ws HTTP/1.1\r\nHost: evil.example.com\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	writeAsync(conn, []byte(req))

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read the refusal: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("the relay answered %d for a disallowed host, want 404", resp.StatusCode)
	}

	if err := h.waitErr(t); !errors.Is(err, transport.ErrAuthFailed) {
		t.Errorf("the relay error is %v, want ErrAuthFailed", err)
	}
}

// TestHandleRejectsARequestForTheWrongPath proves the relay refuses an upgrade
// whose request path is not the configured one.
//
// This is a regression test for a defect where the path was honoured only by the
// client and never enforced by the relay: Handler.upgrade and ServeHTTP parsed
// the request and checked the hosts allow-list but never compared the request
// path against SettingPath, so the relay answered 101 on any path. The path is
// the relay's only per-listener URL-level discriminator, and answering an
// unknown path with a successful upgrade is both a discovery aid for a prober
// that guessed the host but not the path and a broken disguise — a real web
// server answers 404 for a path it does not serve.
func TestHandleRejectsARequestForTheWrongPath(t *testing.T) {
	h := startWSRelay(t, transport.Settings{"tls": false, "path": "/secret"}, logx.Discard())

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	req := "GET /totally-different HTTP/1.1\r\nHost: " + h.addr + "\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	writeAsync(conn, []byte(req))

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		// Closing without a response is also a refusal.
		return
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatal("the relay upgraded a request for a path other than the configured one")
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("the relay answered %d, want 404 so it looks like an ordinary web server", resp.StatusCode)
	}

	if err := h.waitErr(t); !errors.Is(err, transport.ErrAuthFailed) {
		t.Errorf("the relay error is %v, want ErrAuthFailed", err)
	}
}

// TestPathAllowedMatching pins the path comparison, including the cases that must
// NOT match.
//
// Unlike the host allow-list there is no wildcard here, and that asymmetry is
// deliberate: the path is a shared secret between one client and one relay rather
// than a set of names. A prefix or suffix rule would let a prober walk the path
// space, which is the discovery the setting exists to prevent.
func TestPathAllowedMatching(t *testing.T) {
	cases := []struct {
		name     string
		got      string
		settings transport.Settings
		want     bool
	}{
		{"the default path", "/ws", transport.Settings{}, true},
		{"the default rejects another path", "/other", transport.Settings{}, false},
		{"the default rejects the root", "/", transport.Settings{}, false},
		{"an explicit path", "/secret", transport.Settings{"path": "/secret"}, true},
		{"an explicit path rejects the default", "/ws", transport.Settings{"path": "/secret"}, false},
		{"a configured path without a leading slash", "/secret", transport.Settings{"path": "secret"}, true},
		{"a nested path", "/a/b/c", transport.Settings{"path": "/a/b/c"}, true},
		{"a prefix does not match", "/a/b", transport.Settings{"path": "/a/b/c"}, false},
		{"a longer path does not match", "/a/b/c/d", transport.Settings{"path": "/a/b/c"}, false},
		{"an empty request path normalises to the root", "", transport.Settings{"path": "/"}, true},
		{"an empty request path is not the default", "", transport.Settings{}, false},
		{"case matters", "/WS", transport.Settings{"path": "/ws"}, false},
		{"a query is not part of the path", "/ws", transport.Settings{"path": "/ws"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pathAllowed(tc.got, tc.settings); got != tc.want {
				t.Errorf("pathAllowed(%q, %v) = %v, want %v", tc.got, tc.settings, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Client-side request shaping
// ---------------------------------------------------------------------------

// capturedRequest is the HTTP upgrade request a bare listener observed.
type capturedRequest struct {
	req *http.Request
	raw string
}

// captureUpgradeRequest dials with the given settings and returns the upgrade
// request a bare listener received.
//
// The listener deliberately does not complete the handshake: the point is to
// observe exactly what the client puts on the wire, and a failed Dial is the
// expected outcome.
func captureUpgradeRequest(t *testing.T, clientSettings transport.Settings) capturedRequest {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	got := make(chan capturedRequest, 1)
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
		got <- capturedRequest{req: req, raw: req.Method + " " + req.RequestURI + " " + req.Proto}
	}()

	// The dial cannot succeed; the captured request is what matters.
	_, _ = dialWS(context.Background(), ln.Addr().String(), clientSettings, connectReq("example.com:443"), logx.Discard())

	select {
	case c := <-got:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("the listener never received an upgrade request")
	}
	return capturedRequest{}
}

// TestDialerUsesTheDefaultPath proves the unset path is "/ws".
//
// The default is what a one-click deployment relies on: if it did not match the
// relay's expectation the client would request a path the relay does not serve
// and every connection would fail with a confusing 404.
func TestDialerUsesTheDefaultPath(t *testing.T) {
	got := captureUpgradeRequest(t, transport.Settings{"tls": false})

	if got.req.URL.Path != "/ws" {
		t.Errorf("the default path is %q, want /ws", got.req.URL.Path)
	}
	if got.req.Method != http.MethodGet {
		t.Errorf("the upgrade uses %s, want GET", got.req.Method)
	}
	if !strings.EqualFold(got.req.Header.Get("Upgrade"), "websocket") {
		t.Errorf("the request advertises Upgrade: %q, want websocket", got.req.Header.Get("Upgrade"))
	}
	if got.req.Header.Get("Sec-WebSocket-Key") == "" {
		t.Error("the request carries no Sec-WebSocket-Key")
	}
}

// TestDialerAppliesPathAndQuery proves the path and query settings reach the
// wire, including a path written without a leading slash.
//
// The query is what lets a client look like an ordinary application request
// (`?token=...`, `?v=3`), and a path missing its slash would produce a request
// line no server accepts.
func TestDialerAppliesPathAndQuery(t *testing.T) {
	got := captureUpgradeRequest(t, transport.Settings{
		"tls":   false,
		"path":  "chat/room", // deliberately without the leading slash
		"query": "?token=abc&v=3",
	})

	if got.req.URL.Path != "/chat/room" {
		t.Errorf("the path is %q, want /chat/room", got.req.URL.Path)
	}
	if got.req.URL.RawQuery != "token=abc&v=3" {
		t.Errorf("the query is %q, want token=abc&v=3", got.req.URL.RawQuery)
	}
}

// TestDialerSendsUserAgentAndExtraHeaders proves the disguise settings reach the
// wire.
//
// A Go-http-client User-Agent on a WebSocket upgrade is one of the easiest
// proxy tells to detect, and the headers map exists so the client matches the
// header set a real application sends. Neither is observable anywhere else, so
// this is the only test that can catch a regression in it.
func TestDialerSendsUserAgentAndExtraHeaders(t *testing.T) {
	got := captureUpgradeRequest(t, transport.Settings{
		"tls":       false,
		"userAgent": "CustomAgent/1.0",
		"headers": map[string]any{
			"X-PortTransit-Test": "present",
			"Accept-Language":    "en-US",
		},
	})

	if ua := got.req.Header.Get("User-Agent"); ua != "CustomAgent/1.0" {
		t.Errorf("User-Agent = %q, want CustomAgent/1.0", ua)
	}
	if v := got.req.Header.Get("X-PortTransit-Test"); v != "present" {
		t.Errorf("X-PortTransit-Test = %q, want present", v)
	}
	if v := got.req.Header.Get("Accept-Language"); v != "en-US" {
		t.Errorf("Accept-Language = %q, want en-US", v)
	}

	// The default must still look like a browser rather than like Go.
	fallback := captureUpgradeRequest(t, transport.Settings{"tls": false})
	if ua := fallback.req.Header.Get("User-Agent"); !strings.HasPrefix(ua, "Mozilla/5.0") {
		t.Errorf("the default User-Agent is %q, want a browser-shaped one", ua)
	}
}

// TestDialerSendsTheConfiguredHostHeader proves the host setting reaches the
// Host header, which is what a relay restricted with `hosts` matches against.
func TestDialerSendsTheConfiguredHostHeader(t *testing.T) {
	got := captureUpgradeRequest(t, transport.Settings{"tls": false, "host": "front.example.com"})

	if got.req.Host != "front.example.com" {
		t.Errorf("Host = %q, want front.example.com", got.req.Host)
	}
}

// TestDialerHonoursServerNameAsTheDefaultHost proves ServerName is used when no
// explicit host is configured, because that is how a client reaches a
// CDN-fronted relay whose address is not its name.
func TestDialerHonoursServerNameAsTheDefaultHost(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	got := make(chan string, 1)
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
		got <- req.Host
	}()

	_, _ = Dialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: ln.Addr().String(),
		ServerName: "cdn.example.com",
		Request:    connectReq("example.com:443"),
		Timeout:    testTimeout,
		Settings:   transport.Settings{"tls": false},
		Logger:     logx.Discard(),
	})

	select {
	case host := <-got:
		if host != "cdn.example.com" {
			t.Errorf("Host = %q, want cdn.example.com", host)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the listener never received a request")
	}
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

// TestTLSDefaultsToTrue proves the transport wraps the WebSocket in TLS unless
// it is explicitly disabled.
//
// The default is asserted behaviourally rather than by reading the source: a
// client that silently fell back to a plaintext handshake would still connect
// to a plaintext relay, so only the first byte on the wire reveals which
// protocol was actually spoken.
func TestTLSDefaultsToTrue(t *testing.T) {
	cases := []struct {
		name     string
		settings transport.Settings
		want     byte
		what     string
	}{
		{"unset defaults to TLS", transport.Settings{}, 0x16, "a TLS ClientHello"},
		{"explicitly disabled", transport.Settings{"tls": false}, 'G', "a plain HTTP request"},
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

			// The dial cannot complete against this stub listener; the first
			// byte is the observation under test.
			_, _ = dialWS(context.Background(), ln.Addr().String(), tc.settings, connectReq("example.com:443"), logx.Discard())

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

// TestTLSHandshakeAgainstASelfSignedRelay proves the wss path completes against
// a relay presenting a generated self-signed certificate.
//
// The certificate is generated by the shared helper rather than loaded from
// disk so the test is self-contained, and the TLS listener is built by the test
// because the websocket transport itself has no server-side certificate
// handling at all — it reads no certFile/keyFile setting and never calls
// GenerateSelfSigned. Only the client half of the TLS path is therefore under
// test here.
func TestTLSHandshakeAgainstASelfSignedRelay(t *testing.T) {
	cert, err := transport.GenerateSelfSigned(transport.SelfSignedOptions{CommonName: "porttransit-test"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})

	streams := make(chan transport.Stream, 1)
	errs := make(chan error, 1)
	go func() {
		conn, err := tlsLn.Accept()
		if err != nil {
			errs <- err
			return
		}
		st, err := Handler{}.Handle(context.Background(), conn, transport.HandleRequest{
			Timeout:  testTimeout,
			Logger:   logx.Discard(),
			Settings: transport.Settings{"tls": true},
		})
		if err != nil {
			errs <- err
			return
		}
		streams <- st
	}()

	client, err := dialWS(context.Background(), ln.Addr().String(), transport.Settings{
		"tls":      true,
		"insecure": true,
	}, connectReq("example.com:443"), logx.Discard())
	if err != nil {
		t.Fatalf("wss dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	var server transport.Stream
	select {
	case server = <-streams:
	case err := <-errs:
		t.Fatalf("the TLS relay side failed: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the TLS relay never produced a stream")
	}
	t.Cleanup(func() { server.Close() })

	const payload = "payload over wss"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatalf("write over TLS: %v", err)
	}
	if got := string(readN(t, server, len(payload))); got != payload {
		t.Errorf("the TLS relay read %q, want %q", got, payload)
	}
}

// TestTLSCertificateValidationIsEnforced proves that turning verification off
// is what makes a self-signed relay reachable, rather than the client ignoring
// certificates unconditionally.
//
// Without this, a regression that hard-coded InsecureSkipVerify would be
// invisible: the insecure test above would keep passing.
func TestTLSCertificateValidationIsEnforced(t *testing.T) {
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
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	_, err = dialWS(context.Background(), ln.Addr().String(), transport.Settings{
		"tls":      true,
		"insecure": false,
	}, connectReq("example.com:443"), logx.Discard())
	if err == nil {
		t.Fatal("the client accepted an untrusted self-signed certificate")
	}
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

// TestCorrectPSKIsAccepted proves a matching pre-shared key completes the
// handshake and carries data.
func TestCorrectPSKIsAccepted(t *testing.T) {
	settings := transport.Settings{"tls": false, "psk": "base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}

	client, server := openWSPair(t, settings, settings)

	const payload = "authenticated payload"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := string(readN(t, server, len(payload))); got != payload {
		t.Errorf("the relay read %q, want %q", got, payload)
	}
}

// TestWrongPSKIsRefused proves a client with the wrong key cannot establish a
// tunnel, which is the property that keeps the relay from being an open proxy.
//
// The client's Dial is not itself the proof: the preamble is written and
// verified in one direction, so a client cannot learn the verdict from its own
// handshake. The assertion is therefore that the RELAY refused and that the
// stream carried no data — a client that only checked its own Dial would report
// a working tunnel here.
func TestWrongPSKIsRefused(t *testing.T) {
	h := startWSRelay(t, transport.Settings{
		"tls": false,
		"psk": "base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
	}, logx.Discard())

	client, err := dialWS(context.Background(), h.addr, transport.Settings{
		"tls": false,
		"psk": "base64:ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=",
	}, connectReq("example.com:443"), logx.Discard())
	if err == nil {
		// The handshake may appear to succeed locally, but the relay must have
		// dropped the connection, so no data can flow.
		t.Cleanup(func() { client.Close() })
		_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _ = client.Write([]byte("should never arrive"))
		if n, rerr := client.Read(make([]byte, 8)); rerr == nil && n > 0 {
			t.Fatalf("the relay carried %d bytes despite a wrong pre-shared key", n)
		}
	}

	serverErr := h.waitErr(t)
	if !errors.Is(serverErr, transport.ErrAuthFailed) {
		t.Errorf("the relay error is %v, want ErrAuthFailed", serverErr)
	}
	if !strings.Contains(serverErr.Error(), "MAC") {
		t.Errorf("the relay error does not name the failed MAC: %v", serverErr)
	}
}

// TestNoPSKOnEitherSideIsAccepted proves the deliberately unauthenticated mode
// still works.
//
// PSK is optional, so a relay relying on TLS plus the preamble MAC alone — or
// one behind a CDN that already authenticated the client — must remain usable.
// A regression that required a key would break those deployments outright.
func TestNoPSKOnEitherSideIsAccepted(t *testing.T) {
	client, server := openWSPair(t, transport.Settings{"tls": false}, transport.Settings{"tls": false})

	if got := server.Request().Target; got != "example.com:443" {
		t.Errorf("the relay decoded target %q, want example.com:443", got)
	}
	if _, err := client.Write([]byte("no psk")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := string(readN(t, server, 6)); got != "no psk" {
		t.Errorf("the relay read %q, want \"no psk\"", got)
	}
}

// TestAMACedFrameIsRefusedByAnUnkeyedRelay proves the unauthenticated mode is
// not a silent downgrade.
//
// A relay configured without a key accepts only a zero MAC, so a client that
// thinks it is authenticating cannot have its frame quietly accepted as
// anonymous. As with the wrong-key case the client cannot observe the verdict,
// so the relay's own error is the assertion.
func TestAMACedFrameIsRefusedByAnUnkeyedRelay(t *testing.T) {
	h := startWSRelay(t, transport.Settings{"tls": false}, logx.Discard())

	client, err := dialWS(context.Background(), h.addr, transport.Settings{
		"tls": false,
		"psk": "a-key-the-relay-does-not-know",
	}, connectReq("example.com:443"), logx.Discard())
	if err == nil {
		t.Cleanup(func() { client.Close() })
	}

	serverErr := h.waitErr(t)
	if !errors.Is(serverErr, transport.ErrAuthFailed) {
		t.Errorf("the relay error is %v, want ErrAuthFailed", serverErr)
	}
	if !strings.Contains(serverErr.Error(), "no key") {
		t.Errorf("the relay error does not explain that no key is configured: %v", serverErr)
	}
}

// ---------------------------------------------------------------------------
// Nil-logger safety
// ---------------------------------------------------------------------------

// TestNilLoggerDoesNotPanic proves a handshake with no logger configured
// succeeds on both sides.
//
// This was a real panic: a loggerFor helper that returned a nil interface
// panicked on the first method call, and the transports log from inside the
// handshake path — so a relay started without a logger died on its first
// connection rather than merely losing diagnostics.
func TestNilLoggerDoesNotPanic(t *testing.T) {
	h := startWSRelay(t, transport.Settings{"tls": false}, nil)

	client, err := dialWS(context.Background(), h.addr, transport.Settings{"tls": false}, connectReq("example.com:443"), nil)
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
}

// TestNilLoggerDoesNotPanicOnARejectedHandshake proves the failure paths log
// through the same nil-safe wrapper.
//
// A no-op logger that is only installed on the success path would still panic
// whenever a prober or a misconfigured client was refused — which is the
// common case on a public port, not the rare one.
func TestNilLoggerDoesNotPanicOnARejectedHandshake(t *testing.T) {
	h := startWSRelay(t, transport.Settings{
		"tls":   false,
		"hosts": []string{"allowed.example.com"},
	}, nil)

	_, err := dialWS(context.Background(), h.addr, transport.Settings{
		"tls":  false,
		"host": "evil.example.com",
	}, connectReq("example.com:443"), nil)
	if err == nil {
		t.Fatal("the relay accepted a disallowed host")
	}
	if serverErr := h.waitErr(t); serverErr == nil {
		t.Fatal("the relay reported no error for a disallowed host")
	}
}

// TestNilLoggerPreambleRejectionDoesNotPanic proves a malformed preamble is
// logged safely when no logger is configured.
func TestNilLoggerPreambleRejectionDoesNotPanic(t *testing.T) {
	h := startWSRelay(t, transport.Settings{"tls": false}, nil)

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	req := "GET /ws HTTP/1.1\r\nHost: " + h.addr + "\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write the upgrade request: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet}); err != nil {
		t.Fatalf("read the upgrade reply: %v", err)
	}

	// A garbage preamble: correct WebSocket framing, wrong PortTransit magic.
	writeAsync(conn, maskedBinaryFrame([]byte("not a PortTransit preamble")))

	if err := h.waitErr(t); err == nil {
		t.Fatal("the relay accepted a garbage preamble")
	}
}

// maskedBinaryFrame encodes a masked binary WebSocket frame, which is the shape
// a client must send.
//
// The length field is written in all three RFC 6455 encodings, not just the
// 7-bit form. A frame builder that OR-ed the length into one byte would silently
// corrupt every frame longer than 125 bytes, and because a preamble's padding
// length is random that failure would be intermittent — the worst kind of test
// bug, and one that would look like a product defect.
func maskedBinaryFrame(payload []byte) []byte {
	const maskBit = 0x80

	mask := [4]byte{0x11, 0x22, 0x33, 0x44}
	buf := []byte{0x82} // FIN + binary opcode

	switch n := len(payload); {
	case n < 126:
		buf = append(buf, maskBit|byte(n))
	case n <= 0xFFFF:
		buf = append(buf, maskBit|126, byte(n>>8), byte(n))
	default:
		buf = append(buf, maskBit|127)
		for shift := 56; shift >= 0; shift -= 8 {
			buf = append(buf, byte(n>>uint(shift)))
		}
	}
	buf = append(buf, mask[:]...)
	for i, b := range payload {
		buf = append(buf, b^mask[i%4])
	}
	return buf
}

// ---------------------------------------------------------------------------
// Address reporting
// ---------------------------------------------------------------------------

// TestWSConnReportsAddresses proves the adapter reports the peer addresses and
// falls back to a placeholder rather than a nil, because the relay logs the
// remote address on every handshake and a nil would panic the log call.
func TestWSConnReportsAddresses(t *testing.T) {
	client, _ := wsRawPair(t)
	wc := newWSConn(client)

	if wc.LocalAddr() == nil || wc.RemoteAddr() == nil {
		t.Fatal("the adapter reported a nil address")
	}
	if wc.LocalAddr().Network() != "tcp" {
		t.Errorf("LocalAddr network = %q, want tcp", wc.LocalAddr().Network())
	}

	var d dummyAddr = "ws-fallback"
	if d.Network() != "ws" {
		t.Errorf("dummyAddr.Network() = %q, want ws", d.Network())
	}
	if d.String() != "ws-fallback" {
		t.Errorf("dummyAddr.String() = %q, want ws-fallback", d.String())
	}
}

// TestSetDeadlinesReachTheUnderlyingSocket proves the deadline setters are not
// silently dropped.
//
// A no-op deadline setter would leave a stalled peer holding a relay slot until
// the process was restarted, which is exactly the failure the idle timeout
// exists to prevent.
func TestSetDeadlinesReachTheUnderlyingSocket(t *testing.T) {
	client, _ := wsRawPair(t)
	wc := newWSConn(client)

	past := time.Now().Add(-time.Second)
	if err := wc.SetReadDeadline(past); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := wc.Read(make([]byte, 4)); err == nil {
		t.Error("a read past the deadline succeeded, so the deadline never reached the socket")
	}

	if err := wc.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := wc.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The upgrade's pipelined-byte handling
// ---------------------------------------------------------------------------

// TestUpgradeReattachesPipelinedBytes proves the bytes a client pipelines behind
// its upgrade request are not dropped.
//
// hijackWriter.Hijack re-chains those bytes through an io.MultiReader, and the
// comment there states they are "re-chained rather than dropped". This is the
// only assertion in the file that exercises that path: a client which sends its
// upgrade request and its first payload in one write must have both honoured,
// because a real client that optimises the two writes into one segment would
// otherwise stall until the handshake timeout.
func TestUpgradeReattachesPipelinedBytes(t *testing.T) {
	h := startWSRelay(t, transport.Settings{"tls": false}, logx.Discard())

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

	const payload = "pipelined-payload"
	req := "GET /ws HTTP/1.1\r\nHost: " + h.addr + "\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"

	blob := append([]byte(req), maskedBinaryFrame(preamble)...)
	blob = append(blob, maskedBinaryFrame([]byte(payload))...)
	if _, err := conn.Write(blob); err != nil {
		t.Fatalf("write the pipelined handshake: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet}); err != nil {
		t.Fatalf("read the upgrade reply: %v", err)
	}

	// The relay must now hand back a stream decoded from the pipelined frame.
	var server transport.Stream
	select {
	case server = <-h.streams:
	case err := <-h.errs:
		t.Fatalf("the relay could not read the pipelined handshake: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the relay never produced a stream from the pipelined handshake")
	}
	t.Cleanup(func() { server.Close() })

	if got := server.Request().Target; got != "example.com:443" {
		t.Fatalf("the relay decoded target %q, want example.com:443", got)
	}
	if got := string(readN(t, server, len(payload))); got != payload {
		t.Errorf("the relay read %q from the pipelined bytes, want %q", got, payload)
	}
}

// TestHandleRejectsANonWebSocketRequest proves a request that is not an upgrade
// is refused rather than being parsed as a preamble.
//
// The relay is on a public port: an ordinary HTTP probe must not be able to
// reach the preamble parser at all, and the refusal must be a clean error
// rather than a hang.
func TestHandleRejectsANonWebSocketRequest(t *testing.T) {
	h := startWSRelay(t, transport.Settings{"tls": false}, logx.Discard())

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	writeAsync(conn, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read the refusal: %v", err)
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatal("the relay upgraded a request that was not a WebSocket upgrade")
	}

	if err := h.waitErr(t); err == nil {
		t.Fatal("the relay reported no error for a non-upgrade request")
	}
}
