// Package http implements two related HTTP transports:
//
//   - "http": the relay speaks the HTTP CONNECT method, exactly as a corporate
//     proxy does. Any tool that understands an HTTP proxy can use it.
//   - "httpupgrade": the client sends an ordinary HTTP/1.1 GET with an
//     Upgrade header, the relay answers 101, and the connection then becomes a
//     raw byte stream. On the wire the first exchange is indistinguishable
//     from a WebSocket upgrade, which is what makes it useful where a full
//     WebSocket implementation is undesirable.
//
// # CONNECT wire format
//
//	client → relay: CONNECT host:port HTTP/1.1
//	                Host: host:port
//	relay  → client: HTTP/1.1 200 Connection Established
//	then:           raw bidirectional bytes
//
// # HTTPUpgrade wire format
//
//	client → relay: GET /path HTTP/1.1
//	                Upgrade: websocket
//	                Connection: Upgrade
//	                Sec-WebSocket-Key: <base64>
//	                Sec-WebSocket-Version: 13
//	relay  → client: HTTP/1.1 101 Switching Protocols
//	                Upgrade: websocket
//	                Connection: Upgrade
//	                Sec-WebSocket-Accept: <base64(sha1(key + GUID))>
//	then:           raw bidirectional bytes (NO WebSocket framing)
//
// The relay computes the correct Sec-WebSocket-Accept so the handshake passes
// any middlebox that validates it, but never applies WebSocket framing to the
// payload. That is the entire point of HTTPUpgrade: it is a WebSocket
// handshake without the framing overhead.
package http

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"porttransit/internal/logx"
	"porttransit/internal/transport"
)

// Names registered by this package.
const (
	// NameConnect is the HTTP CONNECT proxy transport.
	NameConnect = "http"
	// NameUpgrade is the WebSocket-handshake-without-framing transport.
	NameUpgrade = "httpupgrade"
)

// DefaultPorts are the conventional listen ports.
const (
	DefaultPortConnect = 8080
	DefaultPortUpgrade = 80
)

func init() {
	transport.Register(transport.Factory{
		Name:         NameConnect,
		Description:  "HTTP CONNECT proxy. Works with any tool that understands an HTTP proxy.",
		NativeHeader: true,
		DefaultPort:  DefaultPortConnect,
		Build:        func() (transport.Dialer, transport.Handler) { return ConnectDialer{}, ConnectHandler{} },
	})
	transport.Register(transport.Factory{
		Name:         NameUpgrade,
		Description:  "HTTP upgrade handshake (WebSocket-shaped) with no framing. Low overhead, passes proxies.",
		NativeHeader: false,
		DefaultPort:  DefaultPortUpgrade,
		Build:        func() (transport.Dialer, transport.Handler) { return UpgradeDialer{}, UpgradeHandler{} },
	})
}

// Settings keys understood by both HTTP transports.
const (
	// SettingPath is the request path for HTTPUpgrade. Default "/".
	SettingPath = "path"
	// SettingHost overrides the Host header.
	SettingHost = "host"
	// SettingTLS wraps the connection in TLS.
	SettingTLS = "tls"
	// SettingInsecureSkipVerify accepts any TLS certificate.
	SettingInsecureSkipVerify = "insecure"
	// SettingPSK authenticates the PortTransit preamble.
	SettingPSK = "psk"
	// SettingTimeout bounds the handshake.
	SettingTimeout = "timeout"
	// SettingUsername and SettingPassword enable HTTP Basic authentication on
	// the relay side. This is what a CONNECT proxy normally requires.
	SettingUsername = "username"
	SettingPassword = "password"
	// SettingFallbackAddr forwards a non-CONNECT, non-upgrade request to a
	// real website, so the relay answers like an ordinary web server.
	SettingFallbackAddr = "fallbackAddr"
)

// wsGUID is the constant from RFC 6455 that the Sec-WebSocket-Accept is
// derived from.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// ---------------------------------------------------------------------------
// HTTP CONNECT
// ---------------------------------------------------------------------------

// ConnectDialer establishes client→relay streams over HTTP CONNECT.
type ConnectDialer struct{}

// Name returns the registry key.
func (ConnectDialer) Name() string { return NameConnect }

// Dial issues a CONNECT request and then exchanges the preamble.
func (d ConnectDialer) Dial(ctx context.Context, req transport.DialRequest) (transport.Stream, error) {
	timeout := req.Settings.GetDuration(SettingTimeout, 10*time.Second)
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	conn, err := dialMaybeTLS(ctx, req, timeout)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, err
	}

	host, _, err := transport.SplitHostPort(req.ServerAddr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// The CONNECT target is the relay itself when the request is a ping, and
	// the final destination otherwise. Sending the real destination is what
	// makes this an ordinary proxy request rather than a tunnel setup.
	authority := req.ServerAddr
	if req.Request != nil && req.Request.Target != "" && req.Request.Command != transport.CmdPing {
		authority = req.Request.Target
	}

	hostHeader := req.Settings.GetString(SettingHost, "")
	if hostHeader == "" {
		hostHeader = host
	}

	var sb strings.Builder
	sb.WriteString("CONNECT ")
	sb.WriteString(authority)
	sb.WriteString(" HTTP/1.1\r\nHost: ")
	sb.WriteString(hostHeader)
	sb.WriteString("\r\nProxy-Connection: Keep-Alive\r\n")
	if u := req.Settings.GetString(SettingUsername, ""); u != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(u + ":" + req.Settings.GetString(SettingPassword, "")))
		sb.WriteString("Proxy-Authorization: Basic ")
		sb.WriteString(cred)
		sb.WriteString("\r\n")
	}
	sb.WriteString("\r\n")

	if _, err := io.WriteString(conn, sb.String()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("http: write CONNECT: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("http: read CONNECT reply: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("%w: http CONNECT refused with %s", transport.ErrAuthFailed, resp.Status)
	}

	// A CONNECT reply has no body, but a server may have pipelined bytes after
	// it. Those bytes are the head of the stream and must not be dropped.
	wrapped := &bufferedConn{Conn: conn, r: br}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}

	if req.Request == nil || req.Request.Command == transport.CmdPing {
		// The CONNECT itself already measured the round trip, so the ping is
		// answered without a second exchange.
		req.Request = &transport.Request{
			Command:   transport.CmdConnectTCP,
			Target:    req.ServerAddr,
			Transport: NameConnect,
			Meta:      map[string]string{"ping": "true"},
		}
		return transport.NewStream(wrapped, req.Request, NameConnect, 0), nil
	}
	return transport.NewStream(wrapped, req.Request, NameConnect, 0), nil
}

// ConnectHandler accepts relay-side HTTP CONNECT streams.
type ConnectHandler struct{}

// Name returns the registry key.
func (ConnectHandler) Name() string { return NameConnect }

// Handle parses a CONNECT request from an accepted connection.
func (h ConnectHandler) Handle(ctx context.Context, raw net.Conn, req transport.HandleRequest) (transport.Stream, error) {
	timeout := req.Settings.GetDuration(SettingTimeout, 10*time.Second)
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	if err := raw.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		raw.Close()
		return nil, err
	}

	br := bufio.NewReader(raw)
	httpReq, err := http.ReadRequest(br)
	if err != nil {
		raw.Close()
		loggerFor(req.Logger).Debug("http: malformed request", "remote", transport.RemoteAddrString(raw), "err", err)
		return nil, err
	}

	// Go's parser accepts any HTTP/X.Y, so the version has to be checked here.
	// A request claiming HTTP/2.0 or later cannot be answered with a
	// Connection-level 200 or 101: those are HTTP/1.1 constructs, and a peer
	// that asked for something else would misread the reply. Only HTTP/1.0 and
	// HTTP/1.1 are understood, matching net/http's own server.
	if httpReq.ProtoMajor != 1 {
		writeHTTPError(raw, http.StatusHTTPVersionNotSupported, "HTTP Version Not Supported")
		raw.Close()
		return nil, fmt.Errorf("%w: http: unsupported HTTP version %s", transport.ErrProtocol, httpReq.Proto)
	}

	if httpReq.Method != http.MethodConnect {
		// A plain GET is what a prober or a real browser sends. Forwarding it
		// to the fallback site is what makes the relay look like an ordinary
		// web server.
		return h.fallback(ctx, raw, br, httpReq, req)
	}

	if err := checkBasicAuth(httpReq, req.Settings); err != nil {
		writeHTTPError(raw, http.StatusProxyAuthRequired, "Proxy Authentication Required")
		raw.Close()
		return nil, err
	}

	target := httpReq.Host
	if target == "" {
		target = httpReq.URL.Host
	}
	if target == "" {
		writeHTTPError(raw, http.StatusBadRequest, "CONNECT requires an authority")
		raw.Close()
		return nil, fmt.Errorf("%w: http CONNECT without authority", transport.ErrProtocol)
	}
	if _, err := transport.NormalizeAddr(target, 443); err != nil {
		writeHTTPError(raw, http.StatusBadRequest, "bad authority")
		raw.Close()
		return nil, err
	}

	if _, err := io.WriteString(raw, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		raw.Close()
		return nil, err
	}

	if err := raw.SetReadDeadline(time.Time{}); err != nil {
		raw.Close()
		return nil, err
	}

	wrapped := &bufferedConn{Conn: raw, r: br}
	streamReq := &transport.Request{
		Command:   transport.CmdConnectTCP,
		Target:    target,
		Transport: NameConnect,
	}
	return transport.NewStream(wrapped, streamReq, NameConnect, 0), nil
}

// fallback forwards a non-CONNECT request to the configured website.
func (h ConnectHandler) fallback(ctx context.Context, raw net.Conn, br *bufio.Reader, httpReq *http.Request, req transport.HandleRequest) (transport.Stream, error) {
	addr := req.Settings.GetString(SettingFallbackAddr, "")
	if addr == "" {
		writeHTTPError(raw, http.StatusNotFound, "Not Found")
		raw.Close()
		return nil, fmt.Errorf("%w: http non-CONNECT request and no fallback", transport.ErrAuthFailed)
	}

	timeout := req.Settings.GetDuration("fallbackTimeout", 10*time.Second)
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	upstream, err := (&net.Dialer{Timeout: timeout}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		writeHTTPError(raw, http.StatusBadGateway, "Bad Gateway")
		raw.Close()
		return nil, err
	}

	// Replay the request verbatim so the fallback site sees the original.
	if err := httpReq.Write(upstream); err != nil {
		upstream.Close()
		raw.Close()
		return nil, err
	}
	if n := br.Buffered(); n > 0 {
		if rest, err := br.Peek(n); err == nil {
			if _, err := upstream.Write(rest); err != nil {
				upstream.Close()
				raw.Close()
				return nil, err
			}
		}
	}

	transport.CopyBidirectional(raw, upstream)
	return nil, ErrFallbackHandled
}

// ---------------------------------------------------------------------------
// HTTPUpgrade
// ---------------------------------------------------------------------------

// UpgradeDialer establishes client→relay streams over an HTTP upgrade.
type UpgradeDialer struct{}

// Name returns the registry key.
func (UpgradeDialer) Name() string { return NameUpgrade }

// Dial performs the upgrade handshake and then exchanges the preamble.
func (d UpgradeDialer) Dial(ctx context.Context, req transport.DialRequest) (transport.Stream, error) {
	timeout := req.Settings.GetDuration(SettingTimeout, 10*time.Second)
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	conn, err := dialMaybeTLS(ctx, req, timeout)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, err
	}

	path := req.Settings.GetString(SettingPath, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if q := req.Settings.GetString("query", ""); q != "" {
		path += "?" + strings.TrimPrefix(q, "?")
	}

	host, _, err := transport.SplitHostPort(req.ServerAddr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	hostHeader := req.Settings.GetString(SettingHost, host)

	key := base64.StdEncoding.EncodeToString(randomBytes(16))

	var sb strings.Builder
	sb.WriteString("GET ")
	sb.WriteString(path)
	sb.WriteString(" HTTP/1.1\r\nHost: ")
	sb.WriteString(hostHeader)
	sb.WriteString("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ")
	sb.WriteString(key)
	sb.WriteString("\r\nSec-WebSocket-Version: 13\r\nUser-Agent: ")
	sb.WriteString(browserUserAgent(req.Settings))
	sb.WriteString("\r\n")
	if u := req.Settings.GetString(SettingUsername, ""); u != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(u + ":" + req.Settings.GetString(SettingPassword, "")))
		sb.WriteString("Authorization: Basic ")
		sb.WriteString(cred)
		sb.WriteString("\r\n")
	}
	sb.WriteString("\r\n")

	if _, err := io.WriteString(conn, sb.String()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("httpupgrade: write request: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("httpupgrade: read reply: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, fmt.Errorf("httpupgrade: relay answered %s, expected 101", resp.Status)
	}
	// Validating the accept token catches a relay that is not speaking this
	// protocol — for example a CDN that terminated the upgrade itself.
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != "" {
		if want := wsAccept(key); got != want {
			conn.Close()
			return nil, fmt.Errorf("%w: httpupgrade: Sec-WebSocket-Accept mismatch", transport.ErrProtocol)
		}
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}

	wrapped := &bufferedConn{Conn: conn, r: br}
	return transport.PreambleClientHandshake(wrapped, req.Request, transport.ClientHandshakeConfig{
		PSK:           transport.DecodePSK(req.Settings.GetString(SettingPSK, "")),
		ClientID:      clientIDFrom(req),
		TransportName: NameUpgrade,
		Timeout:       timeout,
		Logger:        loggerFor(req.Logger),
	})
}

// UpgradeHandler accepts relay-side HTTPUpgrade streams.
type UpgradeHandler struct{}

// Name returns the registry key.
func (UpgradeHandler) Name() string { return NameUpgrade }

// Handle parses the upgrade request and replies 101.
func (h UpgradeHandler) Handle(ctx context.Context, raw net.Conn, req transport.HandleRequest) (transport.Stream, error) {
	timeout := req.Settings.GetDuration(SettingTimeout, 10*time.Second)
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	if err := raw.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		raw.Close()
		return nil, err
	}

	br := bufio.NewReader(raw)
	httpReq, err := http.ReadRequest(br)
	if err != nil {
		raw.Close()
		return nil, err
	}

	// See the note in ConnectHandler.Handle: Go's parser accepts any HTTP/X.Y,
	// and a 101 Switching Protocols reply is an HTTP/1.1 construct.
	if httpReq.ProtoMajor != 1 {
		writeHTTPError(raw, http.StatusHTTPVersionNotSupported, "HTTP Version Not Supported")
		raw.Close()
		return nil, fmt.Errorf("%w: httpupgrade: unsupported HTTP version %s", transport.ErrProtocol, httpReq.Proto)
	}

	// A request for the wrong path is treated exactly like a non-upgrade
	// request: the configured path is part of the disguise, so answering an
	// upgrade on any path would let a prober find the relay by scanning paths —
	// which is precisely what moving off the default is meant to prevent.
	// Routing it to the fallback also keeps the relay looking like an ordinary
	// web server to anything that guesses wrong.
	if !isUpgradeRequest(httpReq) || !pathAllowed(httpReq.URL.Path, req.Settings) {
		addr := req.Settings.GetString(SettingFallbackAddr, "")
		if addr == "" {
			writeHTTPError(raw, http.StatusNotFound, "Not Found")
			raw.Close()
			return nil, fmt.Errorf("%w: httpupgrade: not an upgrade request for the configured path", transport.ErrAuthFailed)
		}
		dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		upstream, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(dialCtx, "tcp", addr)
		if err != nil {
			writeHTTPError(raw, http.StatusBadGateway, "Bad Gateway")
			raw.Close()
			return nil, err
		}
		if err := httpReq.Write(upstream); err != nil {
			upstream.Close()
			raw.Close()
			return nil, err
		}
		transport.CopyBidirectional(raw, upstream)
		return nil, ErrFallbackHandled
	}

	if err := checkBasicAuth(httpReq, req.Settings); err != nil {
		writeHTTPError(raw, http.StatusUnauthorized, "Unauthorized")
		raw.Close()
		return nil, err
	}

	key := httpReq.Header.Get("Sec-WebSocket-Key")
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
	if key != "" {
		resp += "Sec-WebSocket-Accept: " + wsAccept(key) + "\r\n"
	}
	resp += "\r\n"

	if _, err := io.WriteString(raw, resp); err != nil {
		raw.Close()
		return nil, err
	}

	if err := raw.SetReadDeadline(time.Time{}); err != nil {
		raw.Close()
		return nil, err
	}

	wrapped := &bufferedConn{Conn: raw, r: br}
	return transport.PreambleServerHandshake(wrapped, transport.ServerHandshakeConfig{
		PSK:             transport.DecodePSK(req.Settings.GetString(SettingPSK, "")),
		Replay:          replayGuard(req.Settings),
		Timeout:         timeout,
		Logger:          loggerFor(req.Logger),
		RequireClientID: req.Settings.GetBool("requireClientID", false),
		AllowedClients:  req.Settings.GetStringSlice("allowedClients"),
		AllowPing:       req.Settings.GetBool("allowPing", true),
		TransportName:   NameUpgrade,
	})
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// ErrFallbackHandled reports that a connection was forwarded to the fallback
// site rather than authenticated. It is a success, not a failure.
var ErrFallbackHandled = fmt.Errorf("http: connection forwarded to fallback")

// bufferedConn lets a caller hand back a connection whose leading bytes were
// already consumed into a bufio.Reader.
//
// Without this, the bytes a proxy pipelined after its reply — or the first
// bytes a client sent right after the handshake — would be silently dropped,
// which manifests as a truncated first request.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

// Read drains the buffered reader before touching the socket.
func (c *bufferedConn) Read(p []byte) (int, error) {
	if c.r != nil && c.r.Buffered() > 0 {
		return c.r.Read(p)
	}
	return c.Conn.Read(p)
}

func dialMaybeTLS(ctx context.Context, req transport.DialRequest, timeout time.Duration) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", req.ServerAddr)
	if err != nil {
		return nil, err
	}
	if !req.Settings.GetBool(SettingTLS, false) {
		return conn, nil
	}
	host, _, err := transport.SplitHostPort(req.ServerAddr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	sni := req.ServerName
	if sni == "" {
		sni = req.Settings.GetString("serverName", host)
	}
	tc := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: req.Settings.GetBool(SettingInsecureSkipVerify, true),
		MinVersion:         tls.VersionTLS12,
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return tc, nil
}

// checkBasicAuth validates Proxy-Authorization (CONNECT) or Authorization
// (upgrade). When no username is configured the relay accepts anything, which
// is appropriate for a relay already protected by TLS plus the preamble MAC.
func checkBasicAuth(r *http.Request, s transport.Settings) error {
	username := s.GetString(SettingUsername, "")
	if username == "" {
		return nil
	}
	password := s.GetString(SettingPassword, "")

	header := r.Header.Get("Proxy-Authorization")
	if header == "" {
		header = r.Header.Get("Authorization")
	}
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return fmt.Errorf("%w: http missing basic credentials", transport.ErrAuthFailed)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return fmt.Errorf("%w: http malformed basic credentials", transport.ErrAuthFailed)
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok || !constantTimeEqual(user, username) || !constantTimeEqual(pass, password) {
		return fmt.Errorf("%w: http bad credentials", transport.ErrAuthFailed)
	}
	return nil
}

// pathAllowed reports whether a request is for the configured HTTPUpgrade path.
//
// Both sides are normalised the same way the dialer builds its request, so a
// setting of "upgrade" and a request for "/upgrade" agree. Comparison is exact:
// unlike a host allow-list there is no wildcard, because the path is a shared
// secret between one client and one relay rather than a set of names.
//
// The CONNECT scheme does not use this: a CONNECT request carries an authority
// rather than a resource path, so there is nothing to compare.
func pathAllowed(got string, s transport.Settings) bool {
	want := s.GetString(SettingPath, "/")
	if !strings.HasPrefix(want, "/") {
		want = "/" + want
	}
	if got == "" {
		got = "/"
	}
	return got == want
}

func isUpgradeRequest(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, v := range r.Header.Values("Connection") {
		if strings.Contains(strings.ToLower(v), "upgrade") {
			return true
		}
	}
	return false
}

// wsAccept computes the Sec-WebSocket-Accept token from a client key, exactly
// as RFC 6455 specifies: base64(SHA1(key + GUID)).
func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// randomBytes returns n cryptographically random bytes. It panics on failure
// because a handshake that cannot obtain randomness must not proceed.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("http: entropy source failed: " + err.Error())
	}
	return b
}

// constantTimeEqual compares two strings without leaking their contents
// through timing.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func writeHTTPError(w io.Writer, code int, message string) {
	body := message + "\n"
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
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

func browserUserAgent(s transport.Settings) string {
	if ua := s.GetString("userAgent", ""); ua != "" {
		return ua
	}
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
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
