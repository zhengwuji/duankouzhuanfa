package server

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"

	"porttransit/internal/transport"
)

// This file implements the relay side of multiplexing: one accepted TCP
// connection carries a yamux session, and every stream inside it is served as
// if it were a connection of its own.
//
// # Where the per-stream request comes from
//
// Each stream begins with an ordinary PortTransit preamble, decoded with the
// transport's own PreambleServerHandshake. That is the whole point of the
// design: the request framing, its MAC, its freshness check, its replay guard
// and its client-id rules are the ones the transports already implement, so a
// multiplexed stream cannot reach the forwarding path by a route that skips
// them. Re-implementing the request inside the session would have meant a
// second parser to keep in step with the first, and the day the two drifted the
// session would have become the way around authentication.
//
// # What is deliberately *not* shared with the connection
//
// The transport handshake, the per-IP handshake throttle and the global
// connection semaphore apply once per session, because those exist to bound
// connections. Everything that bounds a *request* — the account's concurrency
// slot, the forward rules, the ACL, the per-stream rate limit and quota, the
// idle timeout — is applied per stream, by re-entering serveRequest. A session
// therefore cannot buy a client more than the policy allows; it only avoids
// paying the handshake repeatedly.

// serveMuxSession runs a multiplexed session on conn until it ends.
//
// stream is the connection-level preamble's stream. It is not forwarded
// anywhere: it exists so the transport handler could accept and authenticate
// the connection, and it is closed on the way out because the session owns the
// same underlying connection.
func (s *Server) serveMuxSession(h *listenerHandle, conn net.Conn, stream transport.Stream, req *transport.Request) {
	defer stream.Close()

	if !transport.SupportsMux(h.cfg.Transport) {
		// A client asking for multiplexing on a scheme that cannot express it
		// is a configuration mismatch, not an attack. Refusing without the
		// acknowledgement byte makes the client fall back to a dedicated
		// connection immediately rather than after a keepalive timeout.
		s.stats.HandshakeFailures.Add(1)
		s.log.Warn("multiplexing requested on a transport that cannot carry it",
			"listener", h.cfg.Name,
			"transport", h.cfg.Transport,
			"client", req.ClientID,
		)
		return
	}
	if !transport.MuxEnabled(h.cfg.Settings) {
		// The listener was not configured for it. Failing cleanly is the whole
		// reason the acknowledgement byte exists: without it the client would
		// start a session on a connection this side is about to close and would
		// only discover the mismatch when the keepalive gave up.
		s.stats.HandshakeFailures.Add(1)
		s.log.Info("multiplexing refused: this listener has multiplexing disabled",
			"listener", h.cfg.Name,
			"transport", h.cfg.Transport,
			"client", req.ClientID,
		)
		return
	}

	cfg, err := transport.MuxSessionConfig(h.cfg.Settings, s.log)
	if err != nil {
		s.stats.HandshakeFailures.Add(1)
		s.log.Warn("multiplexing refused: bad session parameters",
			"listener", h.cfg.Name,
			"err", err,
		)
		return
	}

	// The session is created before the acknowledgement is written, so a
	// failure to build it cannot leave the client believing the relay accepted.
	// The stream's own deadlines are cleared first: a deadline left over from
	// the preamble read would be inherited by the session's read loop and would
	// tear the session down when it expired.
	_ = stream.SetDeadline(time.Time{})
	sess, err := yamux.Server(stream, cfg)
	if err != nil {
		s.stats.HandshakeFailures.Add(1)
		s.log.Warn("could not start a multiplexed session", "listener", h.cfg.Name, "err", err)
		return
	}
	defer sess.Close()

	timeout := s.limits.HandshakeTimeout.Or(10 * time.Second)
	if err := transport.AcknowledgeMux(stream, timeout); err != nil {
		s.log.Debug("could not acknowledge a multiplexed session", "listener", h.cfg.Name, "err", err)
		return
	}

	s.log.Debug("multiplexed session established",
		"listener", h.cfg.Name,
		"transport", h.cfg.Transport,
		"client", req.ClientID,
		"remote", transport.RemoteAddrString(conn),
		"maxStreams", transport.MuxMaxStreams(h.cfg.Settings),
	)

	ms := &muxSession{
		srv:      s,
		h:        h,
		sess:     sess,
		clientID: req.ClientID,
		timeout:  timeout,
	}
	// The session is closed explicitly on the way out rather than only by the
	// deferred sess.Close above, so an idle close and a shutdown cannot race:
	// close is idempotent, and doing it here also stops the idle timer before
	// the deferred close runs.
	defer ms.close()
	ms.run(s.ctx)
}

// muxSession tracks one live multiplexed session.
type muxSession struct {
	srv  *Server
	h    *listenerHandle
	sess *yamux.Session
	// clientID is the id from the connection-level preamble. It is carried only
	// for logging: the identity each stream is policed by is the one in that
	// stream's own preamble, so a client cannot present one id to open the
	// session and another to use it.
	clientID string
	timeout  time.Duration

	// open counts streams that are being set up or served, and limit is the
	// cap. They exist because yamux itself has no notion of a maximum stream
	// count: without this a session could open streams until the relay ran out
	// of memory or file descriptors.
	open  atomic.Int64
	limit int64

	// idleMu guards the idle timer, and closed records that the session is on
	// its way down so a stream finishing during shutdown cannot arm a new
	// timer on a session that no longer exists.
	idleMu    sync.Mutex
	idle      *time.Timer
	idleFor   time.Duration
	closed    bool
	closeOnce sync.Once
}

// run accepts streams until the session ends.
//
// The accept loop and the idle watchdog both run here, in the connection's own
// goroutine, so the session's whole lifetime is one goroutine and one deferred
// Close.
func (ms *muxSession) run(ctx context.Context) {
	ms.limit = int64(transport.MuxMaxStreams(ms.h.cfg.Settings))
	ms.idleFor = transport.MuxIdleTimeout(ms.h.cfg.Settings, transport.ServerMuxIdleTimeout)

	// The idle timer starts armed. A session that never carries a stream is
	// exactly the case it is for — a client that opened one and then went away
	// without closing anything — and arming it only when a stream finishes
	// would leave that session held open for as long as the peer kept the
	// connection alive.
	if ms.idleFor > 0 {
		ms.startIdleTimer()
	}

	// The accept goroutine feeds a channel so the select below can watch the
	// server's shutdown alongside it. AcceptStream is not interruptible by
	// anything but the session dying, and the session only dies when the
	// connection does — which a relay shutdown does not guarantee, because a
	// client may simply hold the connection open.
	accepts := make(chan net.Conn)
	go func() {
		defer close(accepts)
		for {
			st, err := ms.sess.AcceptStream()
			if err != nil {
				return
			}
			// The stream is wrapped before it goes anywhere: a raw yamux
			// stream has no CloseWrite, so every half-close probe further down
			// — the relay's own copy loop included — would silently fail and
			// the half-close would never reach the client.
			conn := transport.NewMuxStream(st)
			select {
			case accepts <- conn:
			case <-ms.sess.CloseChan():
				_ = st.Close()
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case conn, ok := <-accepts:
			if !ok {
				return
			}
			if !ms.admitStream() {
				// The cap is a resource bound, not a policy: the stream is
				// half-closed with no preamble reply, which the client sees as
				// EOF on its first read and treats as a failed stream.
				//
				// yamux has no way to force a stream shut from outside — Close
				// on an already half-closed stream is a no-op, and the only
				// other teardown is the library's own StreamCloseTimeout — so a
				// refused stream that a client keeps writing to holds up to one
				// stream window of unread data until that timer fires. It is
				// bounded (muxMaxWindowSize, 256 KiB by default, and reclaimed
				// sooner as soon as the client closes its side, which our own
				// client does immediately) and it is not a way past the cap,
				// because a refused stream never occupies a slot.
				ms.srv.stats.RejectedLimit.Add(1)
				_ = conn.Close()
				continue
			}
			ms.srv.wg.Add(1)
			go func(conn net.Conn) {
				defer ms.srv.wg.Done()
				defer ms.releaseStream()
				ms.serveStream(conn)
			}(conn)
		}
	}
}

// admitStream reserves one of the session's stream slots.
func (ms *muxSession) admitStream() bool {
	for {
		cur := ms.open.Load()
		if cur >= ms.limit {
			return false
		}
		if ms.open.CompareAndSwap(cur, cur+1) {
			ms.stopIdleTimer()
			return true
		}
	}
}

// releaseStream gives a slot back and, when the session has gone quiet, starts
// the idle timer that retires it.
func (ms *muxSession) releaseStream() {
	if ms.open.Add(-1) <= 0 && ms.idleFor > 0 {
		ms.startIdleTimer()
	}
}

// stopIdleTimer cancels a pending idle close, because a new stream means the
// session is in use again.
func (ms *muxSession) stopIdleTimer() {
	ms.idleMu.Lock()
	defer ms.idleMu.Unlock()
	if ms.idle != nil {
		ms.idle.Stop()
		ms.idle = nil
	}
}

// startIdleTimer arms the idle close.
//
// Without this the relay would hold a connection open for as long as the client
// keeps it alive, and a client that crashed without closing anything — a
// machine that lost power, a laptop that slept — would leave a session, its
// buffers and its file descriptor allocated until the keepalive eventually
// noticed. The timer is the backstop for exactly that case.
func (ms *muxSession) startIdleTimer() {
	ms.idleMu.Lock()
	defer ms.idleMu.Unlock()
	if ms.closed {
		// The session is already being torn down, so arming a timer here would
		// only produce a callback on a dead session.
		return
	}
	if ms.idle != nil {
		ms.idle.Stop()
	}
	ms.idle = time.AfterFunc(ms.idleFor, func() {
		if ms.open.Load() > 0 {
			// A stream arrived between the timer firing and this callback, so
			// the session is not idle after all.
			return
		}
		ms.srv.log.Debug("closing an idle multiplexed session",
			"listener", ms.h.cfg.Name,
			"idle", ms.idleFor,
		)
		ms.close()
	})
}

// close tears the session down once.
func (ms *muxSession) close() {
	ms.closeOnce.Do(func() {
		ms.idleMu.Lock()
		ms.closed = true
		if ms.idle != nil {
			ms.idle.Stop()
			ms.idle = nil
		}
		ms.idleMu.Unlock()
		_ = ms.sess.Close()
	})
}

// serveStream decodes one stream's preamble and serves the request it names.
//
// conn is a yamux stream wrapped by transport.NewMuxStream, so it is a net.Conn
// the transport's own preamble handshake can run on unchanged — and it carries
// CloseWrite, which is what lets the half-close propagate back to the client.
//
// A failure here — a bad MAC, a stale frame, a replayed nonce, a client id the
// relay does not know — closes the stream and nothing else: the session and its
// sibling streams are unaffected, which is what makes one misconfigured request
// cost one connection rather than all of them.
func (ms *muxSession) serveStream(conn net.Conn) {
	defer conn.Close()

	// The stream's deadlines start clear. yamux inherits nothing from the
	// session, but a deadline set here by a previous handshake would persist
	// into the copy loop, so it is cleared rather than merely overwritten.
	_ = conn.SetDeadline(time.Time{})

	cfg := transport.ServerStreamConfig(
		ms.h.cfg.Settings,
		ms.h.cfg.Transport,
		ms.timeout,
		ms.h.muxReplay,
		ms.srv.log,
	)
	stream, err := transport.PreambleServerHandshake(conn, cfg)
	if err != nil {
		if isPingAnswered(err) {
			// A ping inside a session is answered and the stream closed. It is
			// how a client measures the session's health without opening a
			// real connection through it.
			ms.srv.stats.Pings.Add(1)
			return
		}
		ms.srv.stats.HandshakeFailures.Add(1)
		ms.srv.log.Debug("multiplexed stream rejected",
			"listener", ms.h.cfg.Name,
			"client", ms.clientID,
			"err", err,
		)
		return
	}
	// PreambleServerHandshake returns a stream that owns conn, so the wrapper
	// is what gets closed. The deferred conn.Close above is then a no-op: the
	// wrapper's Close is yamux's own Close, which on an already half-closed
	// stream does nothing at all, and neither call is an error.
	defer stream.Close()

	req := stream.Request()
	if req == nil {
		ms.srv.stats.HandshakeFailures.Add(1)
		return
	}

	ms.srv.serveRequest(ms.h, stream, req)
}
