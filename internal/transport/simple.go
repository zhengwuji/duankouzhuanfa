package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// This file holds the machinery shared by every "simple" transport: the ones
// that complete their own handshake and then exchange a PortTransit preamble to
// name the final target.
//
// A simple transport only has to supply two things:
//
//   - ClientSide: wrap the raw connection (TLS, REALITY, WebSocket, ...)
//   - ServerSide: accept on the raw connection and wrap it the same way
//
// PreambleClientHandshake and PreambleServerHandshake then take care of
// authentication, anti-replay, target addressing and the ping fast path.

// ServerHandshakeConfig parameterises the relay side of a preamble exchange.
type ServerHandshakeConfig struct {
	// PSK authenticates the client. Empty disables MAC verification.
	PSK []byte
	// Replay guards against captured frames being reused. Optional.
	Replay *ReplayGuard
	// Timeout bounds the whole preamble read.
	Timeout time.Duration
	// Logger receives diagnostics.
	Logger Logger
	// RequireClientID rejects frames that omit a client identifier. The relay
	// enables this when it is configured with per-client allow-lists.
	RequireClientID bool
	// AllowedClients restricts accepted client ids when non-empty.
	AllowedClients []string
	// AllowPing permits CmdPing frames to be answered without dialing.
	AllowPing bool
	// TransportName is stamped onto the resulting Request.
	TransportName string
}

// Logger is the minimal logging surface the transport package needs. It keeps
// this package free of a hard dependency on the concrete logger.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Debug(string, ...any) {}
func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Warn(string, ...any)  {}
func (nopLogger) Error(string, ...any) {}

// orNop returns l, or a no-op logger when l is nil.
func orNop(l Logger) Logger {
	if l == nil {
		return nopLogger{}
	}
	return l
}

// NopLogger returns a logger that discards everything.
//
// Transport implementations must use this rather than returning a nil
// interface: a nil interface panics the moment a method is called on it, and
// the transports log from deep inside handshake paths where a panic would take
// down the whole relay. A nil *logx.Logger would be safe only by accident, so
// the no-op value makes the intent explicit.
func NopLogger() Logger { return nopLogger{} }

// PreambleServerHandshake performs the relay side of a simple transport.
//
// On success the returned stream owns conn. On failure conn is closed and an
// error is returned.
func PreambleServerHandshake(conn net.Conn, cfg ServerHandshakeConfig) (Stream, error) {
	log := orNop(cfg.Logger)
	name := cfg.TransportName

	if cfg.Timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(cfg.Timeout)); err != nil {
			conn.Close()
			return nil, err
		}
	}

	pre, err := DecodePreamble(conn)
	if err != nil {
		conn.Close()
		// A bad magic byte is the normal outcome of a port scan or a
		// misconfigured client, so it is logged at debug, not error.
		if errors.Is(err, ErrProtocol) {
			log.Debug("preamble rejected", "transport", name, "remote", remoteAddr(conn), "err", err)
		} else {
			log.Debug("preamble read failed", "transport", name, "remote", remoteAddr(conn), "err", err)
		}
		return nil, err
	}

	// Verify the MAC before anything else so an unauthenticated prober learns
	// nothing about the relay's configuration.
	if err := pre.Verify(cfg.PSK); err != nil {
		conn.Close()
		log.Warn("preamble authentication failed", "transport", name, "remote", remoteAddr(conn))
		return nil, err
	}
	if err := pre.Freshness(PreambleSkew); err != nil {
		conn.Close()
		log.Warn("preamble stale", "transport", name, "remote", remoteAddr(conn), "err", err)
		return nil, err
	}
	if cfg.Replay != nil && !cfg.Replay.Check(pre.Nonce) {
		conn.Close()
		log.Warn("preamble replay detected", "transport", name, "remote", remoteAddr(conn))
		return nil, fmt.Errorf("%w: replayed nonce", ErrAuthFailed)
	}

	if cfg.RequireClientID && pre.ClientID == "" {
		conn.Close()
		log.Warn("client id required but absent", "transport", name, "remote", remoteAddr(conn))
		return nil, fmt.Errorf("%w: client id required", ErrAuthFailed)
	}
	if len(cfg.AllowedClients) > 0 && !containsString(cfg.AllowedClients, pre.ClientID) {
		conn.Close()
		log.Warn("client id not allowed", "transport", name, "client", pre.ClientID)
		return nil, fmt.Errorf("%w: client id not allowed", ErrAuthFailed)
	}

	if pre.Command == CmdPing {
		if !cfg.AllowPing {
			conn.Close()
			return nil, fmt.Errorf("%w: ping disabled", ErrProtocol)
		}
		// Answer with a single byte and close. The client measures RTT from
		// the time it wrote the preamble.
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write([]byte{0x01})
		conn.Close()
		return nil, errPingAnswered
	}

	// Clearing the deadline is best effort: the frame has already been read
	// and verified, so a failure here (the peer having closed immediately
	// after sending) must not discard a usable stream.
	_ = conn.SetReadDeadline(time.Time{})

	req := &Request{
		Command:   pre.Command,
		Target:    pre.Target,
		Transport: name,
		ClientID:  pre.ClientID,
	}
	return NewStream(conn, req, name, 0), nil
}

// errPingAnswered is an internal sentinel: the preamble was a ping and has been
// answered, so the caller must not treat the closed connection as a failure.
var errPingAnswered = errors.New("transport: ping answered")

// IsPingAnswered reports whether err is the internal ping-completion sentinel.
// Callers should treat it as success, not failure.
func IsPingAnswered(err error) bool { return errors.Is(err, errPingAnswered) }

// ClientHandshakeConfig parameterises the client side of a preamble exchange.
type ClientHandshakeConfig struct {
	// PSK authenticates this client to the relay. Empty sends a zero MAC.
	PSK []byte
	// ClientID is reported to the relay and used for per-client policy.
	ClientID string
	// TransportName is stamped onto the resulting Request.
	TransportName string
	// Timeout bounds the round trip.
	Timeout time.Duration
	// Logger receives diagnostics.
	Logger Logger
}

// PreambleClientHandshake writes the preamble for req and, for a ping, waits
// for the relay's acknowledgement so the caller can measure round-trip time.
//
// On success the returned stream owns conn.
func PreambleClientHandshake(conn net.Conn, req *Request, cfg ClientHandshakeConfig) (Stream, error) {
	log := orNop(cfg.Logger)
	name := cfg.TransportName
	if name == "" {
		name = req.Transport
	}

	pre := &Preamble{
		Command:  req.Command,
		ClientID: cfg.ClientID,
		Target:   req.Target,
	}
	frame, err := EncodePreamble(pre, cfg.PSK)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if cfg.Timeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(cfg.Timeout)); err != nil {
			conn.Close()
			return nil, err
		}
	}

	start := time.Now()
	if _, err := conn.Write(frame); err != nil {
		conn.Close()
		log.Debug("preamble write failed", "transport", name, "err", err)
		return nil, err
	}

	if req.Command == CmdPing {
		var ack [1]byte
		if _, err := io.ReadFull(conn, ack[:]); err != nil {
			conn.Close()
			return nil, fmt.Errorf("ping: %w", err)
		}
		rtt := time.Since(start)
		// Clearing the deadline is best effort. The relay closes its side as
		// soon as it has written the acknowledgement, so on a connection type
		// that reports the peer's close immediately — net.Pipe, or a transport
		// whose CloseWrite propagates — this call can legitimately fail even
		// though the ping itself succeeded. Failing here would turn a
		// successful health check into a reported outage.
		_ = conn.SetDeadline(time.Time{})
		log.Debug("ping ok", "transport", name, "rtt", rtt)
		return NewStream(conn, req, name, rtt), nil
	}

	// Clearing the handshake deadline is best effort, for the same reason as
	// the ping path above: the frame is already on the wire, so the handshake
	// succeeded. A relay that closes immediately after accepting — a failed
	// target dial, or a policy refusal that races the close — makes this call
	// fail on a connection type that reports the peer's close at once. Failing
	// here would report the handshake as broken and hide the real reason, which
	// the caller then sees on its first read or write of the stream.
	_ = conn.SetDeadline(time.Time{})
	return NewStream(conn, req, name, 0), nil
}

// RemoteAddrString renders the peer address of conn for logging, tolerating a
// nil or already-closed connection.
func remoteAddr(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return "?"
	}
	return conn.RemoteAddr().String()
}

// RemoteAddrString is the exported form used by transport implementations.
func RemoteAddrString(conn net.Conn) string { return remoteAddr(conn) }

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// DeadlineDialer dials TCP with a bounded timeout and optional bind address.
type DeadlineDialer struct {
	// Timeout bounds the dial.
	Timeout time.Duration
	// LocalAddr optionally binds the outgoing socket.
	LocalAddr string
	// KeepAlive enables TCP keepalive on the resulting connection.
	KeepAlive bool
}

// Dial connects to addr, honouring the configured timeout and bind address.
func (d DeadlineDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	nd := net.Dialer{
		Timeout:   d.Timeout,
		KeepAlive: keepAliveInterval(d.KeepAlive),
	}
	if d.LocalAddr != "" {
		if la, err := net.ResolveTCPAddr("tcp", d.LocalAddr); err == nil {
			nd.LocalAddr = la
		}
	}
	return nd.DialContext(ctx, network, addr)
}

func keepAliveInterval(on bool) time.Duration {
	if !on {
		return -1
	}
	return 30 * time.Second
}

// CopyBidirectional pipes bytes between a and b until either side fails, then
// closes both. It is the core of both the relay and the local proxy.
//
// It returns the number of bytes copied in each direction for accounting.
func CopyBidirectional(a, b net.Conn) (aToB, bToA int64) {
	type result struct {
		n   int64
		err error
	}
	done := make(chan result, 2)

	pipe := func(dst, src net.Conn) {
		n, err := io.Copy(dst, src)
		// Half-close so the peer observes a clean EOF rather than a reset.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- result{n: n, err: err}
	}

	go pipe(a, b)
	go pipe(b, a)

	r1 := <-done
	r2 := <-done
	_ = a.Close()
	_ = b.Close()

	// r1 and r2 arrive in completion order, not direction order; report the
	// totals which is what accounting cares about.
	return r1.n, r2.n
}
