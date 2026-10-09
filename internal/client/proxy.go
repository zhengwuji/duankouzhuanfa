package client

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"porttransit/internal/transport"
)

// The client's local proxy endpoints.
//
// A client exposes SOCKS5 and/or HTTP CONNECT on loopback so ordinary
// applications can use the relay without knowing anything about it. This is
// the "browse through the relay" mode, as opposed to a tunnel's "one local
// port maps to one target" mode.
//
// # Destination policy
//
// Three rule lists are applied in order: block, direct, proxy. A blocked
// destination is refused; a direct destination is dialed without the relay;
// everything else goes through the relay (or, when ProxyRules is non-empty,
// only the destinations in that list do). The direct list is what lets an
// operator send local traffic straight out while still routing a specific
// service through the relay — which is the common case for a user who wants a
// foreign endpoint accelerated but does not want every request to take the
// extra hop.

// startProxy binds the configured local proxy listeners.
func (c *Client) startProxy() error {
	cfg := c.cfg.Proxy
	h := &proxyHandle{}

	if cfg.SOCKS5Listen != "" {
		ln, err := net.Listen("tcp", cfg.SOCKS5Listen)
		if err != nil {
			return fmt.Errorf("bind socks5 %s: %w", cfg.SOCKS5Listen, err)
		}
		h.socks5 = ln
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.acceptProxy(ln, "socks5")
		}()
		c.log.Info("socks5 proxy listening", "listen", ln.Addr().String())
	}

	if cfg.HTTPListen != "" {
		ln, err := net.Listen("tcp", cfg.HTTPListen)
		if err != nil {
			if h.socks5 != nil {
				_ = h.socks5.Close()
			}
			return fmt.Errorf("bind http %s: %w", cfg.HTTPListen, err)
		}
		h.http = ln
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.acceptProxy(ln, "http")
		}()
		c.log.Info("http proxy listening", "listen", ln.Addr().String())
	}

	c.mu.Lock()
	c.proxy = h
	c.mu.Unlock()
	return nil
}

// acceptProxy accepts connections on a local proxy listener.
func (c *Client) acceptProxy(ln net.Listener, kind string) {
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else if delay < time.Second {
				delay *= 2
			}
			c.log.Warn("proxy accept failed, backing off", "kind", kind, "err", err, "backoff", delay)
			select {
			case <-time.After(delay):
				continue
			case <-c.ctx.Done():
				return
			}
		}
		delay = 0
		c.stats.ProxyRequests.Add(1)
		c.stats.TotalConnections.Add(1)

		c.wg.Add(1)
		go func(conn net.Conn) {
			defer c.wg.Done()
			c.stats.ActiveConnections.Add(1)
			defer c.stats.ActiveConnections.Add(-1)
			if kind == "socks5" {
				c.serveSOCKS5(conn)
			} else {
				c.serveHTTP(conn)
			}
		}(conn)
	}
}

// serveSOCKS5 handles one local SOCKS5 session.
func (c *Client) serveSOCKS5(conn net.Conn) {
	defer conn.Close()

	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	// The local proxy is a user-facing endpoint, so a stalled client must not
	// hold a goroutine forever.
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return
	}

	// Greeting.
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return
	}
	if head[0] != 0x05 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	wantMethod := byte(0x00)
	if c.cfg.Proxy.Username != "" {
		wantMethod = 0x02
	}
	accepted := false
	for _, m := range methods {
		if m == wantMethod {
			accepted = true
			break
		}
	}
	if !accepted {
		_, _ = conn.Write([]byte{0x05, 0xFF})
		return
	}
	if _, err := conn.Write([]byte{0x05, wantMethod}); err != nil {
		return
	}

	if wantMethod == 0x02 {
		if !c.socks5Auth(conn) {
			return
		}
	}

	// Request.
	var reqHead [4]byte
	if _, err := io.ReadFull(conn, reqHead[:]); err != nil {
		return
	}
	if reqHead[0] != 0x05 {
		return
	}
	command := reqHead[1]
	if command == 0x03 {
		// UDP ASSOCIATE. The address in the request is where the client says
		// it will send its datagrams from; RFC 1928 allows it to be all zeroes
		// and browsers almost always send that, so it is consumed and
		// discarded. The association is pinned to the control connection's peer
		// instead, which is the only binding that is actually enforceable.
		if _, err := transport.DecodeAddr(io.MultiReader(newOneShot(reqHead[3]), conn)); err != nil {
			writeSocksReply(conn, 0x08)
			return
		}
		if !c.cfg.Proxy.UDP {
			// The operator has not enabled the datagram path. Refusing is the
			// honest answer: silently accepting and then dropping datagrams
			// would look like a broken network to the user.
			c.log.Debug("socks5 udp associate refused: udp is disabled in the local proxy config")
			writeSocksReply(conn, 0x07)
			return
		}
		c.serveUDPAssociate(conn)
		return
	}
	if command != 0x01 {
		// BIND (0x02) is not implemented: it needs a second listener and is
		// obsolete in practice, since every client that wants inbound traffic
		// today uses a tunnel's fixed local port instead.
		writeSocksReply(conn, 0x07)
		return
	}
	target, err := transport.DecodeAddr(io.MultiReader(newOneShot(reqHead[3]), conn))
	if err != nil {
		writeSocksReply(conn, 0x08)
		return
	}

	decision := c.decide(target)
	switch decision {
	case decisionBlock:
		c.log.Debug("local proxy blocked a destination", "target", target)
		writeSocksReply(conn, 0x02)
		return
	case decisionDirect:
		if err := c.serveDirect(conn, target, true); err != nil {
			c.log.Debug("direct connection failed", "target", target, "err", err)
		}
		return
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return
	}
	c.relayThroughServer(conn, target, true)
}

// socks5Auth validates the local proxy's username/password.
func (c *Client) socks5Auth(conn net.Conn) bool {
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return false
	}
	if head[0] != 0x01 {
		return false
	}
	user := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return false
	}
	var plen [1]byte
	if _, err := io.ReadFull(conn, plen[:]); err != nil {
		return false
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return false
	}

	// The hash comparison uses bcrypt when a hash is configured, and a
	// constant-time plaintext comparison otherwise, because the local proxy
	// password is optional and often unset.
	ok := subtle.ConstantTimeCompare(user, []byte(c.cfg.Proxy.Username)) == 1
	if ok {
		if c.cfg.Proxy.PasswordHash != "" {
			ok = verifyPassword(c.cfg.Proxy.PasswordHash, string(pass))
		} else {
			ok = true
		}
	}
	status := byte(0x00)
	if !ok {
		status = 0x01
	}
	_, _ = conn.Write([]byte{0x01, status})
	return ok
}

// serveHTTP handles one local HTTP proxy session.
func (c *Client) serveHTTP(conn net.Conn) {
	defer conn.Close()

	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return
	}

	br := newBufReader(conn)
	req, err := readHTTPRequest(br)
	if err != nil {
		return
	}

	if req.method == "CONNECT" {
		target := req.target
		if !strings.Contains(target, ":") {
			target = net.JoinHostPort(target, "443")
		}
		decision := c.decide(target)
		if decision == decisionBlock {
			writeSimpleResponse(conn, 403, "Forbidden")
			return
		}
		if decision == decisionDirect {
			if err := c.serveDirect(conn, target, false); err != nil {
				c.log.Debug("direct CONNECT failed", "target", target, "err", err)
			}
			return
		}
		if err := conn.SetDeadline(time.Time{}); err != nil {
			return
		}
		c.relayThroughServerCONNECT(conn, target)
		return
	}

	// A plain HTTP request: the absolute URI carries the destination.
	target := req.host
	if target == "" {
		writeSimpleResponse(conn, 400, "Bad Request")
		return
	}
	if !strings.Contains(target, ":") {
		target = net.JoinHostPort(target, "80")
	}

	decision := c.decide(target)
	if decision == decisionBlock {
		writeSimpleResponse(conn, 403, "Forbidden")
		return
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return
	}

	var upstream net.Conn
	if decision == decisionDirect {
		upstream, err = net.DialTimeout("tcp", target, 10*time.Second)
	} else {
		upstream, err = c.dialThroughServer(target)
	}
	if err != nil {
		writeSimpleResponse(conn, 502, "Bad Gateway")
		return
	}
	defer upstream.Close()

	// Rewrite the request line to origin form, which is what an origin server
	// expects, and strip hop-by-hop headers.
	rewritten := req.originForm()
	if _, err := upstream.Write(rewritten); err != nil {
		return
	}
	// Any body bytes already buffered must be forwarded before streaming.
	if n := br.Buffered(); n > 0 {
		if head, err := br.Peek(n); err == nil {
			if _, err := upstream.Write(head); err != nil {
				return
			}
			_, _ = br.Discard(n)
		}
	}

	c.stats.BytesUp.Add(int64(len(rewritten)))
	c.pipeBoth(conn, upstream, br)
}

// relayThroughServer forwards a local connection through a relay, replying to
// the local SOCKS5 client once the relay accepted the request.
func (c *Client) relayThroughServer(local net.Conn, target string, socks5 bool) {
	stream, err := c.dialThroughServer(target)
	if err != nil {
		if socks5 {
			writeSocksReply(local, 0x05)
		}
		c.log.Debug("relay request failed", "target", target, "err", err)
		return
	}
	defer stream.Close()

	if socks5 {
		// The reply is written only now, so the local application learns the
		// real outcome rather than an optimistic success.
		if err := writeSocksReply(local, 0x00); err != nil {
			return
		}
	}
	c.log.Debug("proxy request relayed", "target", target, "transport", stream.TransportName())
	c.pipe(local, stream)
}

// relayThroughServerCONNECT answers an HTTP CONNECT once the relay accepted.
func (c *Client) relayThroughServerCONNECT(local net.Conn, target string) {
	stream, err := c.dialThroughServer(target)
	if err != nil {
		writeSimpleResponse(local, 502, "Bad Gateway")
		c.log.Debug("relay CONNECT failed", "target", target, "err", err)
		return
	}
	defer stream.Close()

	if _, err := local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	c.log.Debug("proxy CONNECT relayed", "target", target, "transport", stream.TransportName())
	c.pipe(local, stream)
}

// dialThroughServer opens a tunnel stream to target via the configured relay.
func (c *Client) dialThroughServer(target string) (transport.Stream, error) {
	req := &transport.Request{
		Command: transport.CmdConnectTCP,
		Target:  target,
	}
	stream, _, err := c.openStream(c.cfg.Proxy.Server, c.cfg.Proxy.Group, c.cfg.Proxy.Balance, req)
	return stream, err
}

// serveDirect dials the target without the relay.
func (c *Client) serveDirect(local net.Conn, target string, socks5 bool) error {
	upstream, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		if socks5 {
			writeSocksReply(local, 0x05)
		} else {
			writeSimpleResponse(local, 502, "Bad Gateway")
		}
		return err
	}
	defer upstream.Close()

	if socks5 {
		if err := writeSocksReply(local, 0x00); err != nil {
			return err
		}
	} else {
		if _, err := local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return err
		}
	}
	c.log.Debug("direct connection established", "target", target)
	c.pipeBoth(local, upstream, nil)
	return nil
}

// pipeBoth copies between two raw connections with no traffic accounting
// beyond the byte counts, used by the direct path.
func (c *Client) pipeBoth(a, b net.Conn, pre *bufReader) {
	done := make(chan int64, 2)
	go func() {
		var n int64
		if pre != nil {
			n += copyBuffered(b, pre)
		}
		n += copyStream(b, a)
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- n
	}()
	go func() {
		n := copyStream(a, b)
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- n
	}()
	c.stats.BytesUp.Add(<-done)
	c.stats.BytesDown.Add(<-done)
}

// decision is the routing verdict for a destination.
type decision int

const (
	decisionProxy decision = iota
	decisionDirect
	decisionBlock
)

// decide applies the block, direct and proxy rule lists.
func (c *Client) decide(target string) decision {
	host := transport.HostOnly(target)
	cfg := c.cfg.Proxy

	for _, pattern := range cfg.BlockRules {
		if matchRule(pattern, target, host) {
			return decisionBlock
		}
	}
	for _, pattern := range cfg.DirectRules {
		if matchRule(pattern, target, host) {
			return decisionDirect
		}
	}
	if len(cfg.ProxyRules) > 0 {
		for _, pattern := range cfg.ProxyRules {
			if matchRule(pattern, target, host) {
				return decisionProxy
			}
		}
		// A non-empty proxy list is an allow-list: anything not on it is
		// dialed directly rather than silently dropped, because dropping would
		// look like a network outage to the user.
		return decisionDirect
	}
	return decisionProxy
}

// matchRule applies one routing pattern. The syntax matches the relay's ACL so
// an operator learns one form.
func matchRule(pattern, target, host string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if strings.HasPrefix(pattern, ".") {
		suffix := strings.ToLower(pattern)
		h := strings.ToLower(host)
		return h == suffix[1:] || strings.HasSuffix(h, suffix)
	}
	if strings.Contains(pattern, ":") {
		return strings.EqualFold(pattern, target)
	}
	return strings.EqualFold(pattern, host)
}

// writeSocksReply sends a SOCKS5 reply with a zeroed bound address.
func writeSocksReply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// newOneShot yields its byte once then reports EOF, so a reader can replay a
// byte that was already consumed.
type oneShot struct {
	b   byte
	got bool
}

func newOneShot(b byte) *oneShot { return &oneShot{b: b} }

func (r *oneShot) Read(p []byte) (int, error) {
	if r.got || len(p) == 0 {
		return 0, io.EOF
	}
	r.got = true
	p[0] = r.b
	return 1, nil
}

// verifyPassword checks a password against a bcrypt hash, falling back to a
// plaintext comparison when the stored value is not a bcrypt hash.
func verifyPassword(hash, password string) bool {
	if strings.HasPrefix(hash, "$2") {
		return bcryptCompare(hash, password)
	}
	return subtle.ConstantTimeCompare([]byte(hash), []byte(password)) == 1
}

// ErrProxyAuthFailed reports a rejected local proxy credential.
var ErrProxyAuthFailed = errors.New("client: local proxy authentication failed")
