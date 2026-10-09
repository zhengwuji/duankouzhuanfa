package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"

	"porttransit/internal/logx"
	"porttransit/internal/transport"
)

// This file implements the client's multiplexed session pool.
//
// # Why a pool
//
// Every proxied connection used to cost a full transport handshake against the
// relay: a TCP connection plus, on the encrypted schemes, a TLS or REALITY
// handshake. Browsing a page opens dozens of short connections, so that cost
// was paid dozens of times, to a relay that may be on another continent. It was
// the single largest latency term in the system.
//
// A multiplexed session pays it once. One session per relay carries many
// proxied connections as streams inside it, so later connections start
// immediately, and all of them share one congestion window — which behaves
// better on a lossy long-haul path than dozens of windows competing.
//
// # The race this file exists to get right
//
// The pool is read and written by every goroutine that serves a local
// connection, so a session must never be closed while another goroutine is
// about to open a stream on it. Three rules make that true, and all of them are
// load bearing:
//
//   - A goroutine that is about to open a stream takes a reference on the
//     session first, under the pool's mutex. The reference is what marks the
//     session as in use.
//   - The idle reaper only retires a session with no references, and it checks
//     that under the same mutex. A session is therefore never closed between
//     the moment a caller picks it and the moment it opens a stream on it.
//   - A session is removed from the pool before it is closed. The close happens
//     outside the lock, but by then no new caller can reach the pointer, so the
//     worst case is a caller that already held a reference — and that caller
//     handles the failure by discarding the session and retrying once.
//
// # What a dead session costs
//
// A session that dies is dropped and replaced inside the same call, so a broken
// session surfaces as one slow connection rather than a permanent outage. If
// the replacement cannot be built either, the failure is reported like a dial
// failure and the caller's existing retry-across-relays logic takes over
// unchanged.

// errMuxRefused reports that the relay answered the session request by refusing
// it: the connection was accepted and then closed without the acknowledgement
// byte. It is a configuration mismatch rather than a fault — the client asked
// for multiplexing and the relay was not configured for it.
//
// It is deliberately distinct from a dial error so the caller can fall back to
// a dedicated connection on the same relay instead of moving to the next one:
// the relay is working, it simply does not multiplex.
var errMuxRefused = errors.New("client: the relay refused a multiplexed session")

// errMuxUnsupported reports that a multiplexed session was requested on a
// transport scheme that cannot carry one. It should be unreachable — the
// decision is taken from transport.SupportsMux when the relay entry is built —
// but it is checked rather than assumed, because reaching the session path on a
// native-header transport would send a connection-level request with no target
// at all.
var errMuxUnsupported = errors.New("client: this transport cannot carry a multiplexed session")

// errMuxFull reports that every session to this relay is at its stream cap and
// the client is already at its session cap. It is a capacity signal, not a
// failure: the caller falls back to a dedicated connection, which is exactly
// what the client did before multiplexing existed.
var errMuxFull = errors.New("client: every multiplexed session to this relay is full")

// errSessionStale reports that the session that was picked could not carry a
// stream, so it has been discarded and a fresh attempt is worth making.
var errSessionStale = errors.New("client: the multiplexed session is stale")

// sessionPool keeps the multiplexed sessions for every relay.
//
// Sessions are held per relay rather than per tunnel because the handshake is
// against the relay: every tunnel, the local proxy and its UDP flows that use
// that relay share its sessions, so the saving is multiplied by however many
// ways the client uses the relay.
type sessionPool struct {
	cli *Client

	mu     sync.Mutex
	byID   map[string]*relayPool
	closed bool
}

func newSessionPool(c *Client) *sessionPool {
	return &sessionPool{cli: c, byID: map[string]*relayPool{}}
}

// relay returns this relay's pool, creating it on first use.
//
// The relay pool outlives any individual session: it is the thing that survives
// a session dying, so the next caller finds the same bookkeeping rather than a
// second, competing entry for the same relay.
func (p *sessionPool) relay(e *serverEntry) (*relayPool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, errors.New("client: the session pool is closed")
	}
	rp, ok := p.byID[e.ID]
	if !ok {
		rp = &relayPool{
			pool:        p,
			entry:       e,
			log:         p.cli.log,
			maxStreams:  int64(transport.MuxMaxStreams(e.settings())),
			maxSessions: transport.MuxMaxSessions(e.settings()),
		}
		p.byID[e.ID] = rp
	}
	return rp, nil
}

// anyEnabled reports whether any configured relay uses multiplexing, so the
// reaper is only started when there is something for it to do.
func (p *sessionPool) anyEnabled() bool {
	for _, e := range p.cli.pools.Entries() {
		if e.muxOK {
			return true
		}
	}
	return false
}

// reapInterval returns how often idle sessions are examined.
//
// It is derived from the shortest configured idle timeout and halved, so a
// session is retired reasonably close to its deadline rather than up to a whole
// extra tick late. It is clamped at both ends: below five seconds the reaper
// would wake constantly for no benefit, and above a minute a short configured
// timeout would be overshot by so much that it no longer means what it says.
func (p *sessionPool) reapInterval() time.Duration {
	shortest := time.Duration(0)
	for _, e := range p.cli.pools.Entries() {
		if !e.muxOK {
			continue
		}
		d := e.muxIdle
		if d <= 0 {
			continue
		}
		if shortest == 0 || d < shortest {
			shortest = d
		}
	}
	if shortest == 0 {
		return 15 * time.Second
	}
	interval := shortest / 2
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	if interval > time.Minute {
		interval = time.Minute
	}
	return interval
}

// reapLoop retires idle sessions until the context ends.
func (p *sessionPool) reapLoop(ctx context.Context) {
	ticker := time.NewTicker(p.reapInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.reap(time.Now())
		}
	}
}

// reap examines every pooled session, dropping the dead ones and retiring the
// ones that have been idle for their configured timeout.
func (p *sessionPool) reap(now time.Time) {
	p.mu.Lock()
	relays := make([]*relayPool, 0, len(p.byID))
	for _, rp := range p.byID {
		relays = append(relays, rp)
	}
	p.mu.Unlock()

	for _, rp := range relays {
		rp.reap(now)
	}
}

// closeAll closes every pooled session. It is called on client shutdown, so a
// relay does not keep a connection, its buffers and its file descriptors alive
// for a client that has gone.
func (p *sessionPool) closeAll() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	relays := make([]*relayPool, 0, len(p.byID))
	for _, rp := range p.byID {
		relays = append(relays, rp)
	}
	p.byID = map[string]*relayPool{}
	p.mu.Unlock()

	for _, rp := range relays {
		rp.closeAll()
	}
}

// relayPool holds every multiplexed session the client has to one relay.
type relayPool struct {
	pool  *sessionPool
	entry *serverEntry
	log   *logx.Logger

	// maxStreams and maxSessions are resolved once, when the relay pool is
	// built. Reading them from the settings on every acquire would allocate a
	// copy of the settings map on the hot path of every proxied connection.
	maxStreams  int64
	maxSessions int

	// dialMu serialises creating a session for this relay.
	//
	// Without it a burst of cold connections would each dial their own session
	// and all but one would be thrown away: N handshakes to end up with one
	// session, which is the exact cost multiplexing exists to remove. Holding
	// it across the dial means the first connection pays the handshake and the
	// rest wait for it and then share the result.
	dialMu sync.Mutex

	// refused records that this relay answered a session request by refusing
	// it. Once it has, every later request goes straight to a dedicated
	// connection.
	//
	// Without this the mismatch would be rediscovered per connection: each one
	// would open a connection, wait for an acknowledgement that never comes,
	// close it, and then open the connection it should have opened in the first
	// place — doubling the handshakes on exactly the configuration that is
	// already the slow one. The flag is deliberately never cleared: a refusal
	// is a statement about how the relay is configured, and retrying it forever
	// would be a slow-motion denial of service against a relay the operator has
	// not upgraded.
	refused atomic.Bool

	// mu guards sessions and every field of the sessions in it. It is never
	// held across a network operation: a reference is taken under it and the
	// stream is opened outside, so the lock is held for nanoseconds even while
	// a wedged session blocks an opener.
	mu       sync.Mutex
	sessions []*pooledSession
}

// markRefused records that the relay does not serve multiplexed sessions.
func (p *relayPool) markRefused() {
	if p.refused.CompareAndSwap(false, true) {
		p.log.Warn("this relay does not serve multiplexed sessions; falling back to one connection per stream",
			"server", p.entry.Name,
			"transport", p.entry.Transport,
		)
	}
}

// isRefused reports whether the relay has already refused a session.
func (p *relayPool) isRefused() bool { return p.refused.Load() }

// pooledSession is one live multiplexed session. Its fields are guarded by the
// enclosing relayPool's mutex.
type pooledSession struct {
	sess *yamux.Session

	// refs counts goroutines that have picked this session and are about to
	// open a stream on it. It is what keeps the reaper away from a session in
	// use, and it is included in the occupancy estimate so that a burst of
	// simultaneous opens cannot all see the same free slot.
	refs int

	// idleSince is when the session was first observed with no streams and no
	// references. A zero value means it is not currently idle.
	idleSince time.Time
}

// open builds one multiplexed stream carrying req.
//
// It retries once with a fresh session when the pooled one turns out to be
// dead. That single internal retry is what turns a dead session into "one slow
// connection" rather than a failed one: the connection that discovers the
// corpse pays one extra handshake and then works, instead of surfacing an error
// the operator would have to explain.
func (p *relayPool) open(ctx context.Context, req *transport.Request) (transport.Stream, error) {
	if !p.entry.muxOK {
		return nil, errMuxUnsupported
	}
	if p.isRefused() {
		// The relay has already said it does not multiplex. Answering with a
		// dedicated connection is cheaper than asking again and being refused,
		// and it is what the caller would have done anyway.
		return nil, errMuxRefused
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		ps, err := p.acquire(ctx)
		if err != nil {
			return nil, err
		}
		stream, err := p.openOn(ps, req)
		if err == nil {
			return stream, nil
		}
		lastErr = err
		if !errors.Is(err, errSessionStale) {
			// A refusal or a genuine dial failure is not something a second
			// attempt on the same relay would fix; the caller's fallback to a
			// dedicated connection, or its retry across relays, is the right
			// response.
			return nil, err
		}
	}
	return nil, lastErr
}

// isMuxRefusal reports whether an acknowledgement failure means the relay
// declined to multiplex, as opposed to failing to answer at all.
//
// The distinction is what decides whether the client may latch the refusal. A
// clean EOF is a relay that read the request and closed the connection without
// answering — a listener whose multiplexing is off, or a relay too old to know the
// command. A reset or a timeout is a relay that is unreachable, restarting, or
// merely slow, and none of those say anything about whether it multiplexes, so
// the client must be willing to ask again.
func isMuxRefusal(err error) bool {
	if err == nil {
		return false
	}
	// A protocol violation is a refusal: the relay answered, so it understands
	// the request, and the answer was not the one expected.
	if errors.Is(err, transport.ErrProtocol) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	// Anything wrapping a network error is a transport-level failure rather
	// than a decision by the relay.
	var ne net.Error
	if errors.As(err, &ne) {
		return false
	}
	// A reset is a net.OpError and is caught above; a bare syscall error on a
	// platform that does not wrap one is treated as transient, which is the
	// safe direction: the cost of asking again is one failed handshake, while
	// the cost of wrongly latching is that multiplexing never turns on.
	return false
}

// acquire returns a session with room, taking a reference on it, and dials a
// new one when every existing session is full.
func (p *relayPool) acquire(ctx context.Context) (*pooledSession, error) {
	if ps := p.pick(); ps != nil {
		return ps, nil
	}

	// Serialise dialing, then re-check: the goroutine ahead in this queue has
	// almost certainly just installed a session, and dialing a second one to
	// throw it away would pay the handshake twice.
	p.dialMu.Lock()
	defer p.dialMu.Unlock()

	if ps := p.pick(); ps != nil {
		return ps, nil
	}

	p.mu.Lock()
	count := len(p.sessions)
	p.mu.Unlock()
	if count >= p.maxSessions {
		// Every session is full and the client is at its own session cap. The
		// caller falls back to a dedicated connection, which is the honest
		// answer: refusing the connection outright would turn a busy moment
		// into a visible outage.
		return nil, errMuxFull
	}

	sess, err := p.dial(ctx)
	if err != nil {
		if errors.Is(err, errMuxRefused) {
			p.markRefused()
		}
		return nil, err
	}

	ps := &pooledSession{sess: sess, refs: 1}
	p.mu.Lock()
	p.sessions = append(p.sessions, ps)
	p.mu.Unlock()
	return ps, nil
}

// pick returns a live session with room, taking a reference on it.
//
// Occupancy is measured as the session's own stream count plus the references
// in flight, because a stream that is being opened is not yet in the session's
// count. Without the references, a burst of simultaneous opens would all read
// the same count and all pass the cap, which is precisely the burst a stream
// cap exists to bound.
func (p *relayPool) pick() *pooledSession {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, ps := range p.sessions {
		if ps.sess == nil || ps.sess.IsClosed() {
			continue
		}
		if int64(ps.sess.NumStreams())+int64(ps.refs) >= p.maxStreams {
			continue
		}
		ps.refs++
		// A session that has just been handed out is not idle, whatever it was
		// a moment ago. Clearing this is what stops the reaper from closing a
		// session in the window between the reference being taken and the
		// stream appearing in the session's stream count.
		ps.idleSince = time.Time{}
		return ps
	}
	return nil
}

// isPreambleEncodingError reports whether a failed per-stream handshake was
// caused by the request itself rather than by the session.
//
// The distinction decides whether the session may be discarded. The preamble is
// encoded locally before a single byte is written, so a malformed target or an
// over-long client id fails identically on every session: discarding a healthy
// session over one of those would cost a handshake and fix nothing. Every other
// failure in that handshake happens on the wire, on a stream that was opened
// moments earlier on a session that was alive at the time — which leaves the
// session itself as the only thing that can have gone wrong.
func isPreambleEncodingError(err error) bool {
	return errors.Is(err, transport.ErrProtocol) || errors.Is(err, transport.ErrBadAddress)
}

// openOn opens one stream on ps and releases the reference acquire took.
func (p *relayPool) openOn(ps *pooledSession, req *transport.Request) (transport.Stream, error) {
	st, err := ps.sess.OpenStream()
	p.release(ps)
	if err != nil {
		// The session was alive when it was handed out and is not now, so the
		// pool's copy is a corpse. Dropping it here is what stops every later
		// connection from paying for the same discovery.
		p.discard(ps)
		return nil, fmt.Errorf("%w: %v", errSessionStale, err)
	}

	// The request must be a fresh copy: the preamble handshake records the
	// transport on it, and the caller's request is reused across relay
	// attempts.
	attemptReq := req.Clone()
	attemptReq.Transport = p.entry.Transport
	if p.entry.ClientID != "" {
		attemptReq.ClientID = p.entry.ClientID
	}

	stream, err := transport.PreambleClientHandshake(
		transport.NewMuxStream(st),
		attemptReq,
		transport.ClientStreamConfig(
			p.entry.settings(),
			p.entry.Transport,
			p.entry.ClientID,
			p.pool.cli.dialTimeout(),
			p.log,
		))
	if err != nil {
		// The wrapper's Close is a half-close, so the whole stream is torn
		// down explicitly here: a preamble that failed leaves nothing worth
		// reading, and a half-closed stream would linger until yamux's
		// StreamCloseTimeout reclaimed it.
		_ = st.Close()

		if isPreambleEncodingError(err) {
			// The request is at fault, not the session. Reporting it as-is
			// keeps a healthy session in the pool and keeps the error
			// recognisable, rather than spending a handshake on a retry that
			// would fail in exactly the same way.
			return nil, err
		}

		// The session died between OpenStream returning and the preamble
		// reaching the wire — the relay was restarted or the connection was
		// reset underneath us. The session is discarded and the failure is
		// reported as stale so the caller's single retry builds a fresh one.
		//
		// This is checked rather than inferred from Session.IsClosed, because
		// the two are not ordered: yamux hands the writer its error from the
		// send loop before that loop tears the session down, so a write can
		// fail while IsClosed still reads false. Trusting IsClosed here left
		// the failure escaping as a plain dial error, which is exactly the
		// "dead session becomes a permanent outage" case the retry exists to
		// prevent.
		p.discard(ps)
		return nil, fmt.Errorf("%w: %v", errSessionStale, err)
	}
	return stream, nil
}

// release gives back a reference taken by pick or by acquire's dial path.
func (p *relayPool) release(ps *pooledSession) {
	p.mu.Lock()
	if ps.refs > 0 {
		ps.refs--
	}
	p.mu.Unlock()
}

// discard removes ps from the pool and closes it.
//
// The removal happens before the close, so by the time the close runs no new
// caller can reach the pointer: pick can only see the remaining sessions, and
// acquire will dial a replacement.
func (p *relayPool) discard(ps *pooledSession) {
	p.mu.Lock()
	kept := p.sessions[:0]
	for _, s := range p.sessions {
		if s != ps {
			kept = append(kept, s)
		}
	}
	p.sessions = kept
	p.mu.Unlock()
	_ = ps.sess.Close()
}

// reap drops dead sessions and retires sessions that have been idle for their
// configured timeout.
//
// The order of the checks matters. A session with a reference outstanding is
// skipped first, because an opener is inside OpenStream and would be racing the
// close. A session that is already closed is dropped without being counted as
// an idle retirement — it is a corpse, not a policy decision. Only then is
// idleness judged, and it is judged from the session's own stream count rather
// than from a counter we maintain, because the stream count is the truth about
// whether anything is using the session.
func (p *relayPool) reap(now time.Time) {
	idleFor := p.entry.muxIdle

	p.mu.Lock()
	kept := p.sessions[:0]
	var retire []*pooledSession
	for _, ps := range p.sessions {
		if ps.sess.IsClosed() {
			retire = append(retire, ps)
			continue
		}
		if ps.refs > 0 || ps.sess.NumStreams() > 0 {
			ps.idleSince = time.Time{}
			kept = append(kept, ps)
			continue
		}
		if idleFor <= 0 {
			// Idle expiry is switched off for this relay. The session is left
			// alone; the relay's own idle timeout is then the only thing that
			// retires it, which is why the client's default is a finite value.
			kept = append(kept, ps)
			continue
		}
		if ps.idleSince.IsZero() {
			ps.idleSince = now
			kept = append(kept, ps)
			continue
		}
		if now.Sub(ps.idleSince) < idleFor {
			kept = append(kept, ps)
			continue
		}
		retire = append(retire, ps)
	}
	p.sessions = kept
	p.mu.Unlock()

	for _, ps := range retire {
		_ = ps.sess.Close()
		if idleFor > 0 {
			p.log.Debug("retired an idle multiplexed session",
				"server", p.entry.Name,
				"transport", p.entry.Transport,
				"idle", idleFor,
			)
		}
	}
}

// closeAll tears every session down.
func (p *relayPool) closeAll() {
	p.mu.Lock()
	sessions := p.sessions
	p.sessions = nil
	p.mu.Unlock()

	for _, ps := range sessions {
		_ = ps.sess.Close()
	}
}

// dial performs one transport handshake and turns the resulting connection into
// a multiplexed session.
//
// The connection-level preamble carries CmdMux and no target: it exists so the
// relay's ordinary transport handler can accept and authenticate the connection
// with the code it already has, and so the relay can tell "multiplex this"
// apart from "forward this".
func (p *relayPool) dial(ctx context.Context) (*yamux.Session, error) {
	e := p.entry
	dialer, err := transport.NewDialer(e.Transport)
	if err != nil {
		return nil, err
	}

	timeout := p.pool.cli.dialTimeout()
	req := &transport.Request{
		Command:   transport.CmdMux,
		Transport: e.Transport,
	}
	if e.ClientID != "" {
		req.ClientID = e.ClientID
	}

	start := time.Now()
	stream, err := dialer.Dial(ctx, transport.DialRequest{
		ServerAddr: e.Address,
		ServerName: e.ServerName,
		Request:    req,
		Timeout:    timeout,
		Logger:     p.log,
		Settings:   e.settings(),
	})
	if err != nil {
		return nil, err
	}
	e.observeLatency(time.Since(start))

	// The relay answers with one byte once it has agreed to serve a session.
	// Waiting for it is what turns "the relay does not multiplex" from a
	// connection that hangs until the session keepalive gives up into an
	// immediate, classifiable failure the caller can fall back from.
	if err := transport.AwaitMuxAck(stream, timeout); err != nil {
		_ = stream.Close()
		if isMuxRefusal(err) {
			return nil, fmt.Errorf("%w: %v", errMuxRefused, err)
		}
		// Anything else is a failure to reach a working relay — a timeout, a
		// reset while the relay was restarting, an I/O error. Reporting it as a
		// dial failure lets the caller's existing retry move to the next relay,
		// and it deliberately does not latch the refusal: a relay that was
		// restarting at this moment will multiplex perfectly well a second
		// later, and remembering otherwise would silently disable the feature
		// for the life of the process.
		return nil, fmt.Errorf("client: no multiplexing acknowledgement from %s: %w", e.Name, err)
	}

	cfg, err := transport.MuxSessionConfig(e.settings(), p.log)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	sess, err := yamux.Client(stream, cfg)
	if err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("client: could not start a multiplexed session with %s: %w", e.Name, err)
	}

	p.log.Debug("multiplexed session established",
		"server", e.Name,
		"transport", e.Transport,
		"handshakeMs", time.Since(start).Milliseconds(),
		"maxStreams", p.maxStreams,
	)
	return sess, nil
}
