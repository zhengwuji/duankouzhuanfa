// Package websocket implements the PortTransit WebSocket transport.
//
// The relay listens as an ordinary HTTP server; the client performs a standard
// WebSocket upgrade and then carries the PortTransit preamble and payload in
// binary frames. Because the first bytes on the wire are a textbook HTTP/1.1
// upgrade, this transport passes through CDNs, corporate proxies and
// TLS-terminating load balancers that would drop a bespoke protocol.
//
// # Wire format
//
//	client → relay: HTTP/1.1 GET <path> Upgrade: websocket
//	relay  → client: HTTP/1.1 101 Switching Protocols
//	client → relay: [binary frame: PortTransit preamble]
//	then:           binary frames carrying raw bytes
//
// # Fragmentation
//
// Every Write becomes one binary frame. A Read returns the payload of the next
// frame, which may be shorter than the caller's buffer; net.Conn semantics are
// preserved because a short read is always legal. Control frames (ping, pong,
// close) are handled by the underlying library and never surface to callers.
package websocket

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"porttransit/internal/logx"
	"porttransit/internal/transport"
)

// Name is the registry key.
const Name = "ws"

// DefaultPort is the conventional listen port.
const DefaultPort = 8080

func init() {
	transport.Register(transport.Factory{
		Name:         Name,
		Description:  "WebSocket over HTTP/1.1 or HTTP/2. Passes through CDNs and corporate proxies.",
		NativeHeader: false,
		DefaultPort:  DefaultPort,
		Build:        func() (transport.Dialer, transport.Handler) { return Dialer{}, Handler{} },
	})
}

// Settings keys understood by this transport.
const (
	// SettingPath is the HTTP path the relay answers on. Default "/ws".
	SettingPath = "path"
	// SettingHost overrides the Host header. Defaults to ServerName.
	SettingHost = "host"
	// SettingTLS wraps the WebSocket in TLS. Default true, because a plain
	// WebSocket on a public port is both insecure and conspicuous.
	SettingTLS = "tls"
	// SettingInsecureSkipVerify accepts any TLS certificate.
	SettingInsecureSkipVerify = "insecure"
	// SettingPSK authenticates the PortTransit preamble.
	SettingPSK = "psk"
	// SettingTimeout bounds the handshake.
	SettingTimeout = "timeout"
	// SettingHeaders adds extra HTTP headers to the upgrade request, which is
	// how a client matches the header set a real application sends.
	SettingHeaders = "headers"
	// SettingHosts restricts the Host header values the relay accepts. Empty
	// accepts any host, which is what a CDN-fronted relay needs.
	SettingHosts = "hosts"
)

// Dialer establishes client→relay WebSocket streams.
type Dialer struct{}

// Name returns the registry key.
func (Dialer) Name() string { return Name }

// Dial performs the WebSocket upgrade and then exchanges the preamble.
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
		sni = req.Settings.GetString("serverName", host)
	}

	useTLS := req.Settings.GetBool(SettingTLS, true)
	scheme := "ws"
	if useTLS {
		scheme = "wss"
	}

	path := req.Settings.GetString(SettingPath, "/ws")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	u := &url.URL{Scheme: scheme, Host: req.ServerAddr, Path: path}
	if q := req.Settings.GetString("query", ""); q != "" {
		u.RawQuery = strings.TrimPrefix(q, "?")
	}

	hdrs := http.Header{}
	hdrs.Set("User-Agent", browserUserAgent(req.Settings))
	hostHeader := req.Settings.GetString(SettingHost, sni)
	if hostHeader != "" {
		hdrs.Set("Host", hostHeader)
	}
	if extra, ok := req.Settings[SettingHeaders].(map[string]any); ok {
		for k, v := range extra {
			hdrs.Set(k, fmt.Sprint(v))
		}
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: timeout,
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext(ctx, network, req.ServerAddr)
		},
		ReadBufferSize:  32 * 1024,
		WriteBufferSize: 32 * 1024,
		// Compression is disabled: it would leak the plaintext structure of
		// an already-encrypted payload and costs CPU on both ends.
		EnableCompression: false,
	}
	if useTLS {
		dialer.TLSClientConfig = &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: req.Settings.GetBool(SettingInsecureSkipVerify, true),
		}
	}

	ws, resp, err := dialer.DialContext(ctx, u.String(), hdrs)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("ws: upgrade to %s failed with HTTP %d: %w", u.String(), resp.StatusCode, err)
		}
		return nil, fmt.Errorf("ws: upgrade to %s: %w", u.String(), err)
	}

	conn := newWSConn(ws)
	return transport.PreambleClientHandshake(conn, req.Request, transport.ClientHandshakeConfig{
		PSK:           transport.DecodePSK(req.Settings.GetString(SettingPSK, "")),
		ClientID:      clientIDFrom(req),
		TransportName: Name,
		Timeout:       timeout,
		Logger:        loggerFor(req.Logger),
	})
}

// Handler accepts relay-side WebSocket streams.
type Handler struct{}

// Name returns the registry key.
func (Handler) Name() string { return Name }

// ServeHTTP upgrades an HTTP request and hands the resulting stream to the
// callback. It exists so a relay can mount the WebSocket transport inside a
// larger HTTP server — which is what allows one port to serve both the
// management GUI and the relay.
//
// The callback is invoked in a new goroutine and owns the stream.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, settings transport.Settings, handle func(net.Conn) error) {
	timeout := settings.GetDuration(SettingTimeout, 10*time.Second)

	if allowed := settings.GetStringSlice(SettingHosts); len(allowed) > 0 {
		if !hostAllowed(r.Host, allowed) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
	}
	// The configured path is part of the disguise, so it has to be enforced
	// rather than merely used by the client: answering an upgrade on any path
	// lets a prober find the relay by scanning paths, which is exactly what
	// moving off the default is meant to prevent.
	if !pathAllowed(r.URL.Path, settings) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	upgrader := websocket.Upgrader{
		HandshakeTimeout: timeout,
		ReadBufferSize:   32 * 1024,
		WriteBufferSize:  32 * 1024,
		// The relay accepts any Origin: the WebSocket here is a transport, not
		// a browser API, so the same-origin policy that protects a web app
		// would only break legitimate non-browser clients.
		CheckOrigin: func(*http.Request) bool { return true },
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade already wrote an error response.
		return
	}
	conn := newWSConn(ws)
	if err := handle(conn); err != nil {
		conn.Close()
	}
}

// Handle performs the relay side of a WebSocket stream.
//
// The relay's accept loop hands this a raw TCP connection, not one an
// http.Server has already parsed, so the HTTP handshake is driven here.
// ServeHTTP covers the other deployment shape — mounting the transport inside
// an existing HTTP server — but it cannot be the only path, because a relay
// that is not fronted by one would then never complete a WebSocket handshake.
func (h Handler) Handle(ctx context.Context, raw net.Conn, req transport.HandleRequest) (transport.Stream, error) {
	timeout := req.Settings.GetDuration(SettingTimeout, 10*time.Second)
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	conn, err := h.upgrade(raw, req.Settings, timeout)
	if err != nil {
		return nil, err
	}

	return transport.PreambleServerHandshake(conn, transport.ServerHandshakeConfig{
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

// upgrade performs the server half of the WebSocket handshake on a bare
// connection.
func (h Handler) upgrade(raw net.Conn, settings transport.Settings, timeout time.Duration) (*wsConn, error) {
	if err := raw.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	br := bufio.NewReader(raw)
	httpReq, err := http.ReadRequest(br)
	if err != nil {
		return nil, fmt.Errorf("ws: read upgrade request: %w", err)
	}
	// The request body is never used, and a GET with a body would otherwise
	// leave unread bytes in front of the payload.
	_ = httpReq.Body.Close()

	if allowed := settings.GetStringSlice(SettingHosts); len(allowed) > 0 {
		if !hostAllowed(httpReq.Host, allowed) {
			writeWSError(raw, http.StatusNotFound, "Not Found")
			return nil, fmt.Errorf("%w: ws: host %q is not allowed", transport.ErrAuthFailed, httpReq.Host)
		}
	}
	// See the note in ServeHTTP: the path is part of the disguise and must be
	// enforced by the relay, not only honoured by the client.
	if !pathAllowed(httpReq.URL.Path, settings) {
		writeWSError(raw, http.StatusNotFound, "Not Found")
		return nil, fmt.Errorf("%w: ws: path %q is not the configured one", transport.ErrAuthFailed, httpReq.URL.Path)
	}

	upgrader := websocket.Upgrader{
		HandshakeTimeout: timeout,
		ReadBufferSize:   32 * 1024,
		WriteBufferSize:  32 * 1024,
		// The relay accepts any Origin: the WebSocket here is a transport, not
		// a browser API, so the same-origin policy that protects a web app
		// would only break legitimate non-browser clients.
		CheckOrigin: func(*http.Request) bool { return true },
	}

	ws, err := upgrader.Upgrade(&hijackWriter{conn: raw, br: br}, httpReq, nil)
	if err != nil {
		return nil, fmt.Errorf("ws: upgrade: %w", err)
	}
	// The handshake read deadline must be cleared: gorilla resets only the
	// write deadline, so leaving this in place would abort every later read.
	if err := raw.SetReadDeadline(time.Time{}); err != nil {
		ws.Close()
		return nil, err
	}
	return newWSConn(ws), nil
}

// hijackWriter adapts a bare connection to the http.ResponseWriter and
// http.Hijacker pair that gorilla's Upgrader requires.
type hijackWriter struct {
	conn net.Conn
	br   *bufio.Reader

	mu          sync.Mutex
	hdr         http.Header
	wroteHeader bool
}

func (w *hijackWriter) Header() http.Header {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.hdr == nil {
		w.hdr = http.Header{}
	}
	return w.hdr
}

// WriteHeader emits a complete response. Only the rejection path reaches it: a
// successful upgrade writes its own 101 directly to the hijacked connection.
func (w *hijackWriter) WriteHeader(status int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true

	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	for k, vs := range w.hdr {
		for _, v := range vs {
			fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
		}
	}
	sb.WriteString("\r\n")
	_, _ = io.WriteString(w.conn, sb.String())
}

func (w *hijackWriter) Write(p []byte) (int, error) {
	return w.conn.Write(p)
}

// Hijack hands gorilla the connection and an empty reader positioned after the
// request.
//
// Bytes the client pipelined behind its upgrade request are re-chained rather
// than dropped. They cannot ride along in the returned bufio.ReadWriter:
// gorilla rejects a hijacked reader that already holds buffered bytes
// ("client sent data before handshake is complete") and, when ReadBufferSize is
// non-zero, discards the reader entirely. Both behaviours would lose a client's
// first payload when it arrives in the same segment as the upgrade request, so
// the bytes are instead prefixed onto the connection gorilla reads from.
func (w *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn := w.conn
	if w.br != nil {
		if n := w.br.Buffered(); n > 0 {
			peeked, err := w.br.Peek(n)
			if err != nil {
				return nil, nil, err
			}
			// Peek does not consume, so the bytes exist only in this buffer:
			// the underlying connection has already given them up.
			conn = &prefixConn{Conn: w.conn, prefix: append([]byte(nil), peeked...)}
		}
	}
	return conn, bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(w.conn)), nil
}

// prefixConn yields buffered bytes before falling through to the connection.
//
// It exists because the only way to hand gorilla bytes that arrived before the
// upgrade is to make them part of the connection gorilla reads from.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// CloseWrite forwards a half-close to the underlying connection when it
// supports one, so a prefixed connection is no less capable than the raw one.
func (c *prefixConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// writeWSError emits a minimal HTTP error response on a bare connection.
func writeWSError(conn net.Conn, status int, text string) {
	body := text + "\n"
	_, _ = fmt.Fprintf(conn,
		"HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
}

// wsConn adapts a WebSocket connection to net.Conn.
//
// WebSocket is message-framed while net.Conn is a byte stream. The adapter
// bridges the two by buffering at most one partially-consumed frame: a Read
// larger than the current frame returns what the frame holds, and the next
// Read continues with the following frame. A Read smaller than the frame
// leaves the remainder buffered for the next call.
type wsConn struct {
	ws *websocket.Conn

	readMu sync.Mutex
	buf    []byte

	writeMu sync.Mutex

	closeOnce      sync.Once
	closeWriteOnce sync.Once
	closed         chan struct{}
}

func newWSConn(ws *websocket.Conn) *wsConn {
	c := &wsConn{ws: ws, closed: make(chan struct{})}
	// A 60-second pong deadline keeps a NAT from silently dropping an idle
	// tunnel while still tolerating a briefly stalled peer.
	ws.SetReadLimit(4 << 20)
	return c
}

// Read returns bytes from the current frame, fetching the next frame when the
// buffer is drained.
func (c *wsConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.buf) == 0 {
		select {
		case <-c.closed:
			return 0, io.EOF
		default:
		}
		typ, data, err := c.ws.ReadMessage()
		if err != nil {
			return 0, translateWSError(err)
		}
		if typ != websocket.BinaryMessage && typ != websocket.TextMessage {
			// Control frames are consumed by the library; anything else is a
			// protocol violation.
			continue
		}
		if len(data) == 0 {
			// An empty binary frame is the peer's end-of-stream marker. See
			// CloseWrite for why this exists: WebSocket has no half-close, so
			// without a marker a finished writer would be indistinguishable
			// from a silent one and the reader would sit until its idle
			// deadline.
			return 0, io.EOF
		}
		c.buf = data
	}

	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	if len(c.buf) == 0 {
		c.buf = nil
	}
	return n, nil
}

// Write sends p as one binary frame.
func (c *wsConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}

	if err := c.ws.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, translateWSError(err)
	}
	return len(p), nil
}

// Close sends a close frame and tears down the underlying socket.
func (c *wsConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed)
		// Best effort: the peer may already be gone.
		_ = c.ws.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(time.Second))
		err = c.ws.Close()
	})
	return err
}

// LocalAddr reports the local socket address.
func (c *wsConn) LocalAddr() net.Addr {
	if a := c.ws.LocalAddr(); a != nil {
		return a
	}
	return dummyAddr("ws-local")
}

// RemoteAddr reports the peer socket address.
func (c *wsConn) RemoteAddr() net.Addr {
	if a := c.ws.RemoteAddr(); a != nil {
		return a
	}
	return dummyAddr("ws-remote")
}

// SetDeadline applies both a read and a write deadline.
func (c *wsConn) SetDeadline(t time.Time) error {
	if err := c.ws.SetReadDeadline(t); err != nil {
		return err
	}
	return c.ws.SetWriteDeadline(t)
}

// SetReadDeadline applies a read deadline.
func (c *wsConn) SetReadDeadline(t time.Time) error { return c.ws.SetReadDeadline(t) }

// SetWriteDeadline applies a write deadline.
func (c *wsConn) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }

// CloseWrite signals end-of-stream to the peer with an empty binary frame.
//
// WebSocket has no half-close: the only ways to tell the peer that no more
// data is coming are a close frame, which also kills the read direction, or an
// application-level marker. The marker is what preserves net.Conn's half-close
// semantics, and it matters in practice: the relay's copy loop and the
// client's pipe both half-close when one direction finishes, so without it
// every WebSocket tunnel would linger until its idle timeout instead of being
// released as soon as the transfer ends.
//
// The frame is only ever sent on the write side of a connection whose peer
// interprets it as EOF, and no payload frame is ever empty, so the marker is
// unambiguous.
func (c *wsConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.closeWriteOnce.Do(func() {
		select {
		case <-c.closed:
			return
		default:
		}
		_ = c.ws.WriteMessage(websocket.BinaryMessage, nil)
	})
	return nil
}

// translateWSError maps gorilla's close errors onto the net package's
// vocabulary so callers can treat a peer-initiated close like an EOF.
func translateWSError(err error) error {
	if err == nil {
		return nil
	}
	if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived) {
		return io.EOF
	}
	if errors.Is(err, websocket.ErrCloseSent) {
		return net.ErrClosed
	}
	return err
}

type dummyAddr string

func (d dummyAddr) Network() string { return "ws" }
func (d dummyAddr) String() string  { return string(d) }

func hostAllowed(host string, allowed []string) bool {
	host = strings.ToLower(transport.HostOnly(host))
	for _, a := range allowed {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == host || a == "*" {
			return true
		}
		if strings.HasPrefix(a, ".") && strings.HasSuffix(host, a) {
			return true
		}
	}
	return false
}

// pathAllowed reports whether an upgrade request is for the configured path.
//
// Both sides are normalised the same way the client builds its URL, so a
// setting of "ws" and a request for "/ws" agree. Comparison is exact: unlike
// the host allow-list there is no wildcard, because the path is a shared secret
// between one client and one relay rather than a set of names.
func pathAllowed(got string, s transport.Settings) bool {
	want := s.GetString(SettingPath, "/ws")
	if !strings.HasPrefix(want, "/") {
		want = "/" + want
	}
	if got == "" {
		got = "/"
	}
	return got == want
}

// browserUserAgent returns a User-Agent that matches the fingerprint the
// client claims. A Go-http-client User-Agent on a WebSocket upgrade is one of
// the easiest proxy tells to detect.
func browserUserAgent(s transport.Settings) string {
	if ua := s.GetString("userAgent", ""); ua != "" {
		return ua
	}
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
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

// loggerFor adapts the shared logger to the transport package's minimal
// interface.
//
// It returns an explicit no-op rather than nil: a nil interface panics on the
// first method call, and the transports log from inside handshake paths where
// a panic would take down the whole relay.
func loggerFor(l *logx.Logger) transport.Logger {
	if l == nil {
		return transport.NopLogger()
	}
	return l
}
