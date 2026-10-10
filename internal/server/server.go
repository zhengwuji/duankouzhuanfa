// Package server implements the PortTransit relay: the 中转 side that accepts
// encrypted tunnel streams from clients and forwards them to their final
// destination.
//
// # Request lifecycle
//
//	accept TCP
//	  → per-IP handshake throttle
//	  → per-IP and global connection caps
//	  → transport handler decodes the stream and yields a Request
//	  → ACL check (destination policy)
//	  → forward-rule match (which may override the destination)
//	  → dial the target (with balance across upstreams)
//	  → optional PROXY protocol header
//	  → bidirectional copy with idle timeout and rate limit
//	  → traffic accounting
//
// # Why forwards exist alongside the generic tunnel
//
// The generic path lets a client name any destination the ACL permits. That is
// what makes the relay a general-purpose 中转. A forward rule is the narrower,
// more common case: "this listener always sends to this one target". Rules are
// evaluated first, so a relay can expose a fixed service on a fixed port
// without giving the client any say in the destination.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"porttransit/internal/config"
	"porttransit/internal/logx"
	"porttransit/internal/transport"
)

// Server is a running relay.
type Server struct {
	cfg      *config.ServerConfig
	log      *logx.Logger
	stats    *Stats
	acl      *ACL
	guard    *handshakeGuard
	sem      *semaphore
	limits   config.LimitConfig
	accounts *accountTable
	resolver *resolver

	mu        sync.Mutex
	listeners map[string]*listenerHandle
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	started   atomic.Bool
}

// listenerHandle is one bound inbound endpoint.
type listenerHandle struct {
	cfg     config.Listener
	ln      net.Listener
	handler transport.Handler
	// identityCapable is resolved once, at bind time, from the transport's
	// factory. Doing it here rather than per request is both cheaper and more
	// reliable: the factory is known to be registered because the handler was
	// just built from it, whereas a per-request lookup depends on the registry
	// still being populated.
	identityCapable bool
	conns           atomic.Int64
	accepted        atomic.Int64
	rejected        atomic.Int64
	// muxReplay guards the nonces of the per-stream preambles carried by this
	// listener's multiplexed sessions. It is built once and shared by every
	// stream of every session on this listener.
	//
	// Sharing is what makes it useful. A transport builds its own guard per
	// connection, which is correct when a connection carries exactly one
	// request; a session carries hundreds, so a guard built per stream would
	// start empty each time and accept a nonce it had already seen on a sibling
	// stream — exactly the replay the guard exists to stop. It is nil when
	// multiplexing is off or replay protection is disabled.
	muxReplay *transport.ReplayGuard
	// err records why a listener is not serving, so the console can report it
	// rather than showing a port that silently accepts nothing.
	err error
	// failLog holds the unix-nano time of the last rate-limited handshake
	// failure warning for this listener, and failCount the number of failures
	// seen since that warning. Together they turn a per-connection Debug line
	// into an occasional Warn that a default-level operator can actually see.
	failLog   atomic.Int64
	failCount atomic.Int64
}

// New builds a relay from configuration.
func New(cfg *config.ServerConfig, log *logx.Logger) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("server: config is nil")
	}
	if log == nil {
		log = logx.Discard()
	}

	acl, err := NewACL(cfg.ACL)
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:       cfg,
		log:       log.Component("server"),
		stats:     NewStats(),
		acl:       acl,
		guard:     newHandshakeGuard(cfg.Limits.MaxHandshakesPerSecondPerIP),
		limits:    cfg.Limits,
		accounts:  newAccountTable(cfg),
		resolver:  newResolver(cfg.Resolver),
		listeners: map[string]*listenerHandle{},
	}
	if cfg.Limits.MaxConnections > 0 {
		s.sem = newSemaphore(cfg.Limits.MaxConnections)
	}
	return s, nil
}

// Stats returns the relay's traffic and connection counters.
func (s *Server) Stats() *Stats { return s.stats }

// Start binds every enabled listener and begins serving. It returns once the
// sockets are bound, not once the relays finish.
func (s *Server) Start(ctx context.Context) error {
	if !s.started.CompareAndSwap(false, true) {
		return errors.New("server: already started")
	}
	s.ctx, s.cancel = context.WithCancel(ctx)

	var started int
	for _, lc := range s.cfg.Listeners {
		if !lc.Enabled {
			s.log.Info("listener disabled, skipping", "listener", lc.Name)
			continue
		}
		if err := s.startListener(lc); err != nil {
			// A partially bound relay is worse than none: the operator would
			// believe a port is serving when it is not. Roll back and report.
			s.Stop()
			return fmt.Errorf("server: listener %s: %w", lc.Name, err)
		}
		started++
	}
	if started == 0 {
		s.log.Warn("no listeners were started; the relay is running but accepts nothing")
	}
	if n := len(s.accounts.snapshot()); n > 0 {
		// Announcing this makes the strictness visible: an operator who
		// configured accounts should know that an unknown client id is now
		// refused, because that is a behaviour change from having none.
		s.log.Info("client accounts configured; unknown client ids will be refused", "accounts", n)

		// And it should equally know which listeners the accounts cannot apply
		// to. Those transports authenticate with a shared secret rather than a
		// client id, so a per-client policy is impossible on them — saying so
		// is the difference between a documented limitation and a hole the
		// operator believes is covered.
		var unmanaged []string
		for _, lc := range s.cfg.Listeners {
			if lc.Enabled && !identityCapable(lc.Transport) {
				unmanaged = append(unmanaged, lc.Name+"("+lc.Transport+")")
			}
		}
		if len(unmanaged) > 0 {
			s.log.Warn("these listeners authenticate with a shared secret, so per-client accounts cannot apply to them",
				"listeners", strings.Join(unmanaged, ", "))
		}
	}
	if d := s.resolver.describe(); d != "system" {
		s.log.Info("using a custom DNS resolver", "servers", d)
	}
	if !socketOptionsSupported {
		// Saying so once is better than an operator wondering why enabling
		// tcpFastOpen changed nothing on this platform.
		for _, lc := range s.cfg.Listeners {
			if lc.TCPFastOpen || lc.MPTCP {
				s.log.Warn("tcpFastOpen/mptcp are Linux-only; ignored on this platform",
					"listener", lc.Name)
			}
		}
	}
	s.log.Info("relay started", "listeners", started)
	return nil
}

// startListener binds one endpoint and spawns its accept loop.
func (s *Server) startListener(lc config.Listener) error {
	// Merge the global masking block into this listener before the handler is
	// built, so a fallback configured once applies everywhere. A listener that
	// names its own fallback keeps it.
	lc = applyMasking(lc, s.cfg.Masking)
	if lc.Settings[settingFallbackAddr] != nil && !maskingAppliesTo(lc.Transport) {
		// Saying so is better than silently ignoring it: an operator who
		// configured masking expects probing to be handled, and only these
		// transports can forward an unauthenticated connection anywhere.
		s.log.Warn("masking is configured but this transport cannot forward unauthenticated traffic",
			"listener", lc.Name,
			"transport", lc.Transport,
		)
	}

	handler, err := transport.NewHandler(lc.Transport)
	if err != nil {
		return err
	}

	network := lc.Network
	if network == "" {
		network = "tcp"
	}

	// UDP listeners take the plain path; the socket options are TCP-specific.
	var ln net.Listener
	if network == "tcp" {
		ln, err = listenTCP(s.ctx, lc)
	} else {
		ln, err = net.Listen(network, lc.Listen)
	}
	if err != nil {
		return fmt.Errorf("bind %s: %w", lc.Listen, err)
	}

	h := &listenerHandle{cfg: lc, ln: ln, handler: handler, identityCapable: identityCapable(lc.Transport)}
	if transport.MuxEnabled(lc.Settings) {
		h.muxReplay = transport.NewStreamReplayGuard(lc.Settings)
	}
	s.mu.Lock()
	s.listeners[lc.Name] = h
	s.mu.Unlock()

	s.wg.Add(1)
	go s.acceptLoop(h)

	s.log.Info("listener bound",
		"listener", lc.Name,
		"transport", lc.Transport,
		"listen", ln.Addr().String(),
	)
	if m := describeMasking(s.cfg.Masking); m != "none" {
		s.log.Info("masking active", "listener", lc.Name, "masking", m)
	}
	if transport.MuxEnabled(lc.Settings) {
		if !transport.SupportsMux(lc.Transport) {
			// Saying so at bind time is the difference between "multiplexing is
			// on" and "multiplexing is on but cannot work here". A scheme that
			// carries the target inside its own wire protocol has no
			// connection-level command to accept, so a client configured for
			// mux will fall back to dedicated connections on every request —
			// silently, unless this is said once.
			s.log.Warn("multiplexing is enabled but this transport cannot carry a multiplexed session; clients will fall back to one connection per stream",
				"listener", lc.Name,
				"transport", lc.Transport,
			)
		} else {
			s.log.Info("multiplexing enabled",
				"listener", lc.Name,
				"maxStreams", transport.MuxMaxStreams(lc.Settings),
			)
		}
	}
	return nil
}

// acceptLoop accepts connections until the listener closes.
func (s *Server) acceptLoop(h *listenerHandle) {
	defer s.wg.Done()

	var delay time.Duration
	for {
		conn, err := h.ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			// A closed listener outside a shutdown is terminal: retrying would
			// spin forever on an error that never clears. Recording it makes
			// the console able to say why the port stopped serving.
			if errors.Is(err, net.ErrClosed) {
				s.mu.Lock()
				h.err = err
				s.mu.Unlock()
				s.log.Error("listener closed unexpectedly", "listener", h.cfg.Name, "err", err)
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			// A transient accept failure (EMFILE, ENFILE) would otherwise spin
			// the CPU at 100%. Back off exponentially up to a second.
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else if delay < time.Second {
				delay *= 2
			}
			s.log.Warn("accept failed, backing off", "listener", h.cfg.Name, "err", err, "backoff", delay)
			select {
			case <-time.After(delay):
				continue
			case <-s.ctx.Done():
				return
			}
		}
		delay = 0
		h.accepted.Add(1)

		// Per-IP throttling happens before any goroutine is spawned, so a
		// connection flood cannot exhaust memory by creating goroutines.
		if !s.guard.allow(remoteIP(conn)) {
			h.rejected.Add(1)
			s.stats.RejectedThrottled.Add(1)
			_ = conn.Close()
			continue
		}
		if s.sem != nil && !s.sem.tryAcquire() {
			h.rejected.Add(1)
			s.stats.RejectedLimit.Add(1)
			s.log.Debug("global connection cap reached, dropping", "remote", transport.RemoteAddrString(conn))
			_ = conn.Close()
			continue
		}

		h.conns.Add(1)
		s.stats.ActiveConnections.Add(1)
		s.stats.TotalConnections.Add(1)

		s.wg.Add(1)
		go func(conn net.Conn, h *listenerHandle) {
			defer s.wg.Done()
			defer h.conns.Add(-1)
			defer s.stats.ActiveConnections.Add(-1)
			if s.sem != nil {
				defer s.sem.release()
			}
			s.serve(h, conn)
		}(conn, h)
	}
}

// serve handles one accepted connection through its whole lifecycle.
func (s *Server) serve(h *listenerHandle, conn net.Conn) {
	defer conn.Close()

	if tc, ok := conn.(*net.TCPConn); ok {
		// Disable Nagle: a relay is latency-sensitive and the protocol already
		// batches at the transport layer.
		_ = tc.SetNoDelay(true)
		// Enable keepalive so a dead peer is detected without waiting for the
		// idle timeout on a stream that never writes.
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}

	// An inbound PROXY protocol header must be consumed before anything else
	// reads from the socket, and only when the listener says to expect one:
	// reading it unconditionally would eat the first bytes of a normal
	// connection. The header carries the real client address, which matters
	// because the per-IP throttle in the accept loop necessarily saw the load
	// balancer's address instead. It is used to correct the address the log and
	// the policy see; the throttle cannot be re-run after the fact.
	if h.cfg.ProxyProtocol {
		timeout := s.limits.HandshakeTimeout.Or(10 * time.Second)
		wrapped, realAddr, err := ReadProxyHeader(conn, timeout)
		if err != nil {
			s.stats.HandshakeFailures.Add(1)
			s.log.Debug("proxy protocol header rejected",
				"listener", h.cfg.Name,
				"remote", transport.RemoteAddrString(conn),
				"err", err,
			)
			return
		}
		conn = wrapped
		if realAddr != nil {
			conn = &addressedConn{Conn: conn, remote: realAddr}
		}
	}

	handshakeTimeout := s.limits.HandshakeTimeout.Or(10 * time.Second)
	ctx, cancel := context.WithTimeout(s.ctx, handshakeTimeout)
	defer cancel()

	stream, err := h.handler.Handle(ctx, conn, transport.HandleRequest{
		Timeout:  handshakeTimeout,
		Logger:   s.log,
		Settings: h.cfg.Settings,
	})
	if err != nil {
		if isPingAnswered(err) {
			s.stats.Pings.Add(1)
			return
		}
		// Trojan and the HTTP transports consume a failed handshake by
		// forwarding it to the fallback site; that is success, not failure.
		if isFallbackHandled(err) {
			s.stats.Fallbacks.Add(1)
			return
		}
		s.stats.HandshakeFailures.Add(1)
		// Logged at Debug per connection because a scanner or a flood would
		// otherwise fill the log. The rate-limited Warn below is what makes the
		// failure visible at the default level: without it a relay whose
		// clients cannot complete a handshake — a path being interfered with, a
		// wrong PSK after a rotation — logged nothing at all while its failure
		// counter climbed, and the only symptom an operator had was a client
		// that could not connect.
		s.log.Debug("handshake failed",
			"listener", h.cfg.Name,
			"transport", h.cfg.Transport,
			"remote", transport.RemoteAddrString(conn),
			"err", err,
		)
		s.noteHandshakeFailure(h, conn, err)
		return
	}
	defer stream.Close()

	req := stream.Request()
	if req == nil {
		s.stats.HandshakeFailures.Add(1)
		return
	}

	// A connection-level request to multiplex. The transport has already
	// decoded and authenticated the preamble, so this decision is made on a
	// verified frame — a client cannot reach the session path without the
	// listener's credentials.
	if req.Command == transport.CmdMux {
		s.serveMuxSession(h, conn, stream, req)
		return
	}

	s.serveRequest(h, stream, req)
}

// handshakeFailureWarnInterval is how often at most one handshake-failure
// warning is emitted per listener. Long enough that a flood cannot fill the
// log, short enough that an operator watching a broken line sees it promptly.
const handshakeFailureWarnInterval = 30 * time.Second

// noteHandshakeFailure emits an occasional Warn summarising handshake failures
// on one listener, and returns the number of failures folded into that warning.
//
// The first failure on a listener always warns, because a relay that has never
// served a successful handshake and is now refusing them is the case an
// operator most needs to see, and waiting out an interval would hide it.
func (s *Server) noteHandshakeFailure(h *listenerHandle, conn net.Conn, err error) int64 {
	now := time.Now()
	prev := h.failLog.Load()
	if prev != 0 && now.UnixNano()-prev < int64(handshakeFailureWarnInterval) {
		h.failCount.Add(1)
		return 0
	}
	if !h.failLog.CompareAndSwap(prev, now.UnixNano()) {
		// Another goroutine warned concurrently; let it own this window.
		h.failCount.Add(1)
		return 0
	}
	folded := h.failCount.Swap(0) + 1
	s.log.Warn("handshake failed",
		"listener", h.cfg.Name,
		"transport", h.cfg.Transport,
		"remote", transport.RemoteAddrString(conn),
		"failures", folded,
		"err", err,
	)
	return folded
}

// serveRequest handles one already-decoded request: admission, policy, and the
// forwarding itself.
//
// It is separated from serve so that a stream inside a multiplexed session
// takes exactly the same path as a whole connection. Anything checked here —
// the account's concurrency slot, the forward rules, the ACL — therefore
// applies to a multiplexed stream identically, and a policy cannot be bypassed
// by multiplexing.
func (s *Server) serveRequest(h *listenerHandle, stream transport.Stream, req *transport.Request) {
	// A ping that a transport expressed as a TCP connect to the relay itself
	// must not be dialed: that would loop back into this listener.
	if req.Meta != nil && req.Meta["ping"] == "true" {
		s.stats.Pings.Add(1)
		return
	}

	// Admit against the client's account before any work is done. Checking
	// here rather than at handshake time is deliberate: the client id is
	// carried in the transport's request frame, which several transports only
	// produce after their own authentication succeeds, so this is the earliest
	// point where the identity is trustworthy.
	acct, err := s.accounts.admit(req.ClientID, h.identityCapable)
	if err != nil {
		s.stats.ACLDenied.Add(1)
		s.log.Info("request refused",
			"listener", h.cfg.Name,
			"transport", req.Transport,
			"client", req.ClientID,
			"err", err,
		)
		// A SOCKS5 client should learn this from the reply code rather than a
		// bare close, so it can distinguish "denied" from "server is down".
		writeDialFailure(stream, err)
		return
	}
	defer acct.release()

	target, rule, err := s.resolveTarget(h, stream, req)
	if err != nil {
		s.stats.ACLDenied.Add(1)
		s.log.Info("request refused",
			"listener", h.cfg.Name,
			"transport", req.Transport,
			"target", req.Target,
			"client", req.ClientID,
			"err", err,
		)
		return
	}

	switch req.Command {
	case transport.CmdUDPAssociate:
		s.serveUDP(h, stream, target, rule, acct)
	default:
		s.serveTCP(h, stream, target, rule, req, acct)
	}
}

// resolveTarget applies the forward rules and the ACL to decide the real
// destination, and returns the matching rule (which may be nil).
func (s *Server) resolveTarget(h *listenerHandle, stream transport.Stream, req *transport.Request) (string, *config.Forward, error) {
	rule := s.matchForward(h.cfg.Name, req)
	if rule == nil {
		return "", nil, fmt.Errorf("no forward rule matches transport %q on listener %q", req.Transport, h.cfg.Name)
	}

	target := req.Target
	if rule.Target != "" {
		// A rule with a fixed target overrides whatever the client asked for.
		// That is the point of such a rule: the client cannot redirect it.
		target = pickUpstream(rule.Target, rule.Balance, req.Target)
	} else if !targetAllowedByRule(rule, target) {
		return "", nil, fmt.Errorf("target %q is not in the rule's allowedTargets", target)
	}

	normalized, err := transport.NormalizeAddr(target, 0)
	if err != nil {
		return "", nil, err
	}

	if err := s.acl.Check(normalized, clientPolicy(s.cfg, req.ClientID)); err != nil {
		return "", nil, err
	}
	return normalized, rule, nil
}

// matchForward finds the first enabled rule that applies.
//
// Rule specificity is deliberate: a rule naming both a listener and a
// transport wins over one naming only a listener, which wins over one naming
// neither. Without that ordering an operator could not add a general rule
// without shadowing a specific one.
func (s *Server) matchForward(listenerName string, req *transport.Request) *config.Forward {
	var best *config.Forward
	bestScore := -1

	for i := range s.cfg.Forwards {
		f := &s.cfg.Forwards[i]
		if !f.Enabled {
			continue
		}
		if f.Listener != "" && f.Listener != listenerName {
			continue
		}
		if f.Transport != "" && f.Transport != req.Transport {
			continue
		}
		if f.Client != "" && f.Client != req.ClientID {
			continue
		}

		score := 0
		if f.Listener != "" {
			score += 2
		}
		if f.Transport != "" {
			score++
		}
		if f.Client != "" {
			score++
		}
		if score > bestScore {
			best, bestScore = f, score
		}
	}

	// A relay with no configured rules behaves as a general-purpose tunnel:
	// every authenticated request is forwarded, subject to the ACL. This is
	// the common case for a 中转 hop.
	if best == nil && len(s.cfg.Forwards) == 0 {
		return &config.Forward{Enabled: true}
	}
	return best
}

// serveTCP dials the target and pipes bytes in both directions.
func (s *Server) serveTCP(h *listenerHandle, stream transport.Stream, target string, rule *config.Forward, req *transport.Request, acct *accountRuntime) {
	dialTimeout := s.limits.DialTimeout.Or(10 * time.Second)
	ctx, cancel := context.WithTimeout(s.ctx, dialTimeout)
	defer cancel()

	start := time.Now()
	upstream, err := s.dialTarget(ctx, target, rule)
	if err != nil {
		s.stats.DialFailures.Add(1)
		s.log.Info("dial target failed",
			"listener", h.cfg.Name,
			"target", target,
			"client", req.ClientID,
			"err", err,
		)
		// A SOCKS5 client learns the failure from the reply code; every other
		// transport learns it from the close.
		writeDialFailure(stream, err)
		return
	}
	defer upstream.Close()

	if rule != nil && rule.ProxyProtocolOut {
		if err := writeProxyProtocolV1(upstream, stream.RemoteAddr(), target); err != nil {
			s.log.Debug("proxy protocol header failed", "target", target, "err", err)
			return
		}
	}

	// Both counters must move together: Snapshot divides the accumulated
	// latency by this count, so incrementing only the latency would leave the
	// average reading as a permanent zero.
	s.stats.DialLatencyMs.Add(time.Since(start).Milliseconds())
	s.stats.DialCount.Add(1)
	s.stats.ActiveForwards.Add(1)
	defer s.stats.ActiveForwards.Add(-1)

	// A SOCKS5 relay reports success only now, once the target is genuinely
	// reachable, so the client can attribute a failure correctly.
	writeDialSuccess(stream)

	s.log.Debug("relay established",
		"listener", h.cfg.Name,
		"transport", req.Transport,
		"target", target,
		"client", req.ClientID,
		"dialMs", time.Since(start).Milliseconds(),
	)

	copyWithLimits(stream, upstream, s.limits, s.stats, req.ClientID, target, acct)
	s.accounts.markDirty()
}

// dialTarget connects to the chosen upstream.
func (s *Server) dialTarget(ctx context.Context, target string, rule *config.Forward) (net.Conn, error) {
	nd := net.Dialer{
		Timeout:   s.limits.DialTimeout.Or(10 * time.Second),
		KeepAlive: 30 * time.Second,
	}
	if s.cfg.Resolver.Strategy == "prefer_ipv4" || s.cfg.Resolver.Strategy == "prefer_ipv6" {
		// Happy-eyeballs with an explicit address family preference: dial the
		// preferred family first and fall back to the other. This matters for
		// a relay whose IPv6 path is faster but not always available.
		preferV6 := s.cfg.Resolver.Strategy == "prefer_ipv6"
		if conn, err := dialPreferred(ctx, nd, target, preferV6, s.resolver); err == nil {
			return conn, nil
		}
	}
	return nd.DialContext(ctx, "tcp", target)
}

// dialPreferred tries one address family, then the other.
func dialPreferred(ctx context.Context, nd net.Dialer, target string, preferV6 bool, rv *resolver) (net.Conn, error) {
	host, port, err := transport.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	// An IP literal has no alternative family to try.
	if transport.IsIPLiteral(host) {
		return nd.DialContext(ctx, "tcp", target)
	}

	addrs, err := rv.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	primary := make([]string, 0, len(addrs))
	secondary := make([]string, 0, len(addrs))
	for _, a := range addrs {
		s := net.JoinHostPort(a.IP.String(), port)
		isV6 := a.IP.To4() == nil
		if isV6 == preferV6 {
			primary = append(primary, s)
		} else {
			secondary = append(secondary, s)
		}
	}

	var lastErr error
	for _, group := range [][]string{primary, secondary} {
		for _, addr := range group {
			conn, err := nd.DialContext(ctx, "tcp", addr)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("server: %s resolved to no usable address", host)
	}
	return nil, lastErr
}

// serveUDP relays a UDP association.
func (s *Server) serveUDP(h *listenerHandle, stream transport.Stream, target string, rule *config.Forward, acct *accountRuntime) {
	// UDP over the tunnel is framed by the transport as length-prefixed
	// datagrams; the relay opens a connected UDP socket to the target and
	// relays each datagram, tracking the reply address so a target that
	// answers from a different port still works.
	s.log.Debug("udp association requested", "target", target, "listener", h.cfg.Name)

	// A SOCKS5 client blocks on the reply to its UDP ASSOCIATE request before
	// it sends any datagram, so the reply must be written even though the
	// association is already usable. Without it the client would hang until
	// its handshake deadline and report a failure for a working tunnel.
	writeDialSuccess(stream)

	s.stats.ActiveForwards.Add(1)
	defer s.stats.ActiveForwards.Add(-1)

	if err := relayUDP(s.ctx, stream, target, s.limits.UDPTimeout.Or(120*time.Second), s.stats, acct); err != nil {
		s.log.Debug("udp association ended", "target", target, "err", err)
	}
	s.accounts.markDirty()
}

// Stop closes every listener and waits for in-flight relays to finish.
func (s *Server) Stop() {
	if !s.started.CompareAndSwap(true, false) {
		return
	}
	if s.cancel != nil {
		s.cancel()
	}

	s.mu.Lock()
	handles := make([]*listenerHandle, 0, len(s.listeners))
	for _, h := range s.listeners {
		handles = append(handles, h)
	}
	s.listeners = map[string]*listenerHandle{}
	s.mu.Unlock()

	for _, h := range handles {
		_ = h.ln.Close()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		s.log.Warn("relay shutdown timed out waiting for in-flight connections")
	}

	// Persist accumulated quota usage on the way out. Without this a restart
	// would silently reset every client's counter, which turns a quota into
	// something a client can clear by waiting for a deploy.
	if err := s.accounts.saveUsage(); err != nil {
		s.log.Warn("could not persist client quota usage", "err", err)
	}
	s.log.Info("relay stopped")
}

// AccountUsage reports per-client usage for the Web GUI.
func (s *Server) AccountUsage() []AccountUsage { return s.accounts.snapshot() }

// ResetAccountUsage clears accumulated quota usage for one client, or for all
// when id is empty. It returns how many accounts were cleared.
func (s *Server) ResetAccountUsage(id string) int {
	n := s.accounts.resetUsage(id)
	if err := s.accounts.saveUsage(); err != nil {
		s.log.Warn("could not persist client quota reset", "err", err)
	}
	return n
}

// ListenerStatus describes one listener for the Web GUI.
type ListenerStatus struct {
	Name      string `json:"name"`
	Transport string `json:"transport"`
	Listen    string `json:"listen"`
	Enabled   bool   `json:"enabled"`
	// Listening reports whether the socket is actually bound. A configured
	// listener that is not bound is the difference between "the port is open"
	// and "the configuration says it should be", which is the first thing an
	// operator needs to know when a client cannot connect.
	Listening bool `json:"listening"`
	// Reason explains a listener that is configured but not bound: it is
	// disabled, or it failed to bind.
	Reason string `json:"reason,omitempty"`
	Active int64  `json:"active"`
	// Accepted counts connections accepted since start.
	Accepted int64 `json:"accepted"`
	// Rejected counts connections refused before a handshake, which rising
	// numbers point at a credential or throttling problem.
	Rejected int64 `json:"rejected"`
}

// ListenerStatuses reports the state of every configured listener, including
// ones that are not bound so the GUI can show why.
func (s *Server) ListenerStatuses() []ListenerStatus {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]ListenerStatus, 0, len(s.cfg.Listeners))
	for _, lc := range s.cfg.Listeners {
		st := ListenerStatus{
			Name:      lc.Name,
			Transport: lc.Transport,
			Listen:    lc.Listen,
			Enabled:   lc.Enabled,
		}
		if h, ok := s.listeners[lc.Name]; ok {
			st.Listening = h.ln != nil
			st.Active = h.conns.Load()
			st.Accepted = h.accepted.Load()
			st.Rejected = h.rejected.Load()
			if h.ln != nil {
				st.Listen = h.ln.Addr().String()
			}
			if h.err != nil {
				st.Reason = h.err.Error()
			}
		} else if !lc.Enabled {
			st.Reason = "listener is disabled"
		} else {
			st.Reason = "listener is not running"
		}
		out = append(out, st)
	}
	return out
}

// remoteIP extracts the peer IP from a connection.
func remoteIP(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

// clientPolicy returns the per-client override for an ACL check, or nil.
func clientPolicy(cfg *config.ServerConfig, clientID string) *config.ClientAccount {
	if clientID == "" {
		return nil
	}
	for i := range cfg.Clients {
		if cfg.Clients[i].ID == clientID {
			return &cfg.Clients[i]
		}
	}
	return nil
}

// targetAllowedByRule reports whether a client-chosen target satisfies a rule
// that has no fixed target.
func targetAllowedByRule(rule *config.Forward, target string) bool {
	if len(rule.AllowedTargets) == 0 {
		// A rule with neither a target nor an allow-list would be an open
		// proxy. Config validation rejects it, so reaching here means the
		// synthesized catch-all rule is in play: allow the ACL to decide.
		return rule.Target == ""
	}
	host := transport.HostOnly(target)
	for _, pattern := range rule.AllowedTargets {
		if matchTarget(pattern, target, host) {
			return true
		}
	}
	return false
}

// matchTarget applies one allow-list pattern.
//
// Supported forms:
//
//	"example.com:443"  exact host and port
//	"example.com"      any port on that host
//	"192.168.1.1"      any port on that address
//	".example.com"     any host in that domain suffix
func matchTarget(pattern, target, host string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if strings.Contains(pattern, ":") && !strings.HasPrefix(pattern, ".") {
		return strings.EqualFold(pattern, target)
	}
	if strings.HasPrefix(pattern, ".") {
		suffix := strings.ToLower(pattern)
		h := strings.ToLower(host)
		// ".example.com" matches "a.example.com" and "example.com" itself,
		// which is what an operator writing a suffix rule intends.
		return h == suffix[1:] || strings.HasSuffix(h, suffix)
	}
	return strings.EqualFold(pattern, host)
}

// pickUpstream selects among comma-separated upstreams.
func pickUpstream(spec, strategy, seed string) string {
	parts := strings.Split(spec, ",")
	if len(parts) == 1 {
		return strings.TrimSpace(parts[0])
	}
	candidates := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			candidates = append(candidates, p)
		}
	}
	if len(candidates) == 0 {
		return strings.TrimSpace(spec)
	}

	switch strategy {
	case "round-robin", "random", "least-conn", "least-latency":
		// A per-rule counter would need shared state; hashing the seed (the
		// client-chosen target, or the client id) spreads load across
		// upstreams deterministically without it, which also keeps a given
		// destination pinned to one upstream — important for targets that
		// keep server-side session state.
		var h uint32 = 2166136261
		for i := 0; i < len(seed); i++ {
			h ^= uint32(seed[i])
			h *= 16777619
		}
		return candidates[int(h%uint32(len(candidates)))]
	default:
		return candidates[0]
	}
}

// writeProxyProtocolV1 emits a HAProxy PROXY protocol v1 header so the target
// can recover the original client address.
func writeProxyProtocolV1(w net.Conn, src net.Addr, dst string) error {
	srcHost, srcPort := splitAddr(src)
	dstHost, dstPort, err := transport.SplitHostPort(dst)
	if err != nil {
		return err
	}

	family := "TCP4"
	if strings.Contains(srcHost, ":") || strings.Contains(dstHost, ":") {
		family = "TCP6"
	}
	header := fmt.Sprintf("PROXY %s %s %s %s %s\r\n", family, srcHost, dstHost, srcPort, dstPort)
	_, err = w.Write([]byte(header))
	return err
}

func splitAddr(a net.Addr) (host, port string) {
	if a == nil {
		return "0.0.0.0", "0"
	}
	h, p, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String(), "0"
	}
	return h, p
}
