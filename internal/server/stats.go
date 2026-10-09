package server

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"porttransit/internal/config"
	"porttransit/internal/transport"
)

// Stats holds the relay's counters. Every field is atomic because the relay
// updates them from many goroutines and the Web GUI reads them concurrently.
type Stats struct {
	ActiveConnections atomic.Int64
	TotalConnections  atomic.Int64
	ActiveForwards    atomic.Int64

	HandshakeFailures atomic.Int64
	RejectedThrottled atomic.Int64
	RejectedLimit     atomic.Int64
	ACLDenied         atomic.Int64
	DialFailures      atomic.Int64
	Pings             atomic.Int64
	Fallbacks         atomic.Int64

	BytesUp   atomic.Int64
	BytesDown atomic.Int64

	// DialLatencyMs accumulates the sum of dial durations so an average can be
	// derived without keeping a histogram.
	DialLatencyMs atomic.Int64
	DialCount     atomic.Int64

	startedAt time.Time
}

// NewStats returns a zeroed Stats stamped with its creation time.
func NewStats() *Stats { return &Stats{startedAt: time.Now()} }

// Snapshot is the JSON view of the counters.
type Snapshot struct {
	ActiveConnections int64   `json:"activeConnections"`
	TotalConnections  int64   `json:"totalConnections"`
	ActiveForwards    int64   `json:"activeForwards"`
	HandshakeFailures int64   `json:"handshakeFailures"`
	RejectedThrottled int64   `json:"rejectedThrottled"`
	RejectedLimit     int64   `json:"rejectedLimit"`
	ACLDenied         int64   `json:"aclDenied"`
	DialFailures      int64   `json:"dialFailures"`
	Pings             int64   `json:"pings"`
	Fallbacks         int64   `json:"fallbacks"`
	BytesUp           int64   `json:"bytesUp"`
	BytesDown         int64   `json:"bytesDown"`
	AvgDialMs         float64 `json:"avgDialMs"`
	UptimeSeconds     int64   `json:"uptimeSeconds"`
}

// Snapshot reads every counter consistently enough for display.
func (s *Stats) Snapshot() Snapshot {
	dials := s.DialCount.Load()
	var avg float64
	if dials > 0 {
		avg = float64(s.DialLatencyMs.Load()) / float64(dials)
	}
	return Snapshot{
		ActiveConnections: s.ActiveConnections.Load(),
		TotalConnections:  s.TotalConnections.Load(),
		ActiveForwards:    s.ActiveForwards.Load(),
		HandshakeFailures: s.HandshakeFailures.Load(),
		RejectedThrottled: s.RejectedThrottled.Load(),
		RejectedLimit:     s.RejectedLimit.Load(),
		ACLDenied:         s.ACLDenied.Load(),
		DialFailures:      s.DialFailures.Load(),
		Pings:             s.Pings.Load(),
		Fallbacks:         s.Fallbacks.Load(),
		BytesUp:           s.BytesUp.Load(),
		BytesDown:         s.BytesDown.Load(),
		AvgDialMs:         avg,
		UptimeSeconds:     int64(time.Since(s.startedAt).Seconds()),
	}
}

// Reset zeroes the counters, keeping the uptime anchor.
func (s *Stats) Reset() {
	s.ActiveConnections.Store(0)
	s.TotalConnections.Store(0)
	s.ActiveForwards.Store(0)
	s.HandshakeFailures.Store(0)
	s.RejectedThrottled.Store(0)
	s.RejectedLimit.Store(0)
	s.ACLDenied.Store(0)
	s.DialFailures.Store(0)
	s.Pings.Store(0)
	s.Fallbacks.Store(0)
	s.BytesUp.Store(0)
	s.BytesDown.Store(0)
	s.DialLatencyMs.Store(0)
	s.DialCount.Store(0)
	s.startedAt = time.Now()
}

// semaphore is a counting semaphore with a non-blocking acquire, used to cap
// concurrent relays without ever blocking the accept loop.
type semaphore struct {
	ch chan struct{}
}

func newSemaphore(n int) *semaphore {
	if n <= 0 {
		return nil
	}
	return &semaphore{ch: make(chan struct{}, n)}
}

func (s *semaphore) tryAcquire() bool {
	select {
	case s.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *semaphore) release() {
	select {
	case <-s.ch:
	default:
	}
}

// handshakeGuard throttles handshake attempts per source IP.
//
// A relay is a natural target for connection floods, and the cheapest defence
// is to drop attempts before allocating a goroutine or a transport handshake.
// A token bucket per IP with a bounded map is enough: a real client opens a
// handful of connections per second at most, while a scanner opens thousands.
type handshakeGuard struct {
	rate    int
	mu      sync.Mutex
	buckets map[string]*bucket
	lastGC  time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// handshakeGuardMaxIPs bounds the bucket map so a spoofed-source flood cannot
// grow it without limit. When the cap is hit the oldest entries are evicted.
const handshakeGuardMaxIPs = 65536

func newHandshakeGuard(ratePerSecond int) *handshakeGuard {
	if ratePerSecond <= 0 {
		// A zero rate means "no throttle", which is the default because a
		// legitimate client behind CGNAT shares one source IP with many
		// users and a low limit would break it.
		return &handshakeGuard{}
	}
	return &handshakeGuard{
		rate:    ratePerSecond,
		buckets: make(map[string]*bucket, 1024),
		lastGC:  time.Now(),
	}
}

// allow reports whether one more handshake from ip may proceed.
func (g *handshakeGuard) allow(ip string) bool {
	if g == nil || g.rate <= 0 {
		return true
	}
	if ip == "" {
		return true
	}

	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()

	// Opportunistic garbage collection: drop buckets idle for a minute, at
	// most once per minute, so the map does not accumulate dead entries.
	if now.Sub(g.lastGC) > time.Minute {
		for k, b := range g.buckets {
			if now.Sub(b.last) > time.Minute {
				delete(g.buckets, k)
			}
		}
		g.lastGC = now
	}
	if len(g.buckets) >= handshakeGuardMaxIPs {
		for k := range g.buckets {
			delete(g.buckets, k)
			if len(g.buckets) < handshakeGuardMaxIPs/2 {
				break
			}
		}
	}

	b, ok := g.buckets[ip]
	if !ok {
		g.buckets[ip] = &bucket{tokens: float64(g.rate) - 1, last: now}
		return true
	}

	// Refill at rate tokens per second, capped at the burst size.
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * float64(g.rate)
	if b.tokens > float64(g.rate) {
		b.tokens = float64(g.rate)
	}
	b.last = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// copyWithLimits pipes bytes between the tunnel and the target, applying an
// idle timeout and a throughput cap, and recording traffic.
//
// Direction naming follows the client's perspective: "up" is client → target,
// "down" is target → client. That is what an operator expects to see when
// diagnosing an asymmetric path, which is the whole point of a 中转.
//
// acct may be nil, which means the relay has no client accounts configured and
// only the global limits apply.
func copyWithLimits(tunnel, target net.Conn, limits config.LimitConfig, stats *Stats, clientID, targetAddr string, acct *accountRuntime) {
	bufSize := limits.BufferSize
	if bufSize <= 0 {
		bufSize = 32 * 1024
	}
	idle := limits.IdleTimeout.Or(300 * time.Second)

	var upLimiter, downLimiter *rateLimiter
	if limits.RateLimitKBps > 0 {
		upLimiter = newRateLimiter(limits.RateLimitKBps)
		downLimiter = newRateLimiter(limits.RateLimitKBps)
	}

	// A per-account limit is additional to the global one, not a replacement:
	// the global limit protects the relay as a whole, while the account limit
	// is a policy about one client. Applying whichever is tighter is the only
	// reading that honours both, so each direction uses the stricter limiter.
	//
	// The account's limiter object is shared across all of that client's
	// streams so its token bucket is global to the client; a per-stream bucket
	// would let the client multiply its rate by opening more streams.
	if acctLimiter := acct.rateLimiter(); acctLimiter != nil {
		upLimiter = stricterLimiter(upLimiter, acctLimiter)
		downLimiter = stricterLimiter(downLimiter, acctLimiter)
	}

	type result struct {
		up bool
		n  int64
	}
	done := make(chan result, 2)

	pipe := func(dst, src net.Conn, up bool, limiter *rateLimiter) {
		n := copyWithIdle(dst, src, bufSize, idle, limiter)
		// Half-close so the peer sees a clean EOF rather than a reset, which
		// matters for protocols that treat a reset as an error.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- result{up: up, n: n}
	}

	go pipe(target, tunnel, true, upLimiter)
	go pipe(tunnel, target, false, downLimiter)

	for i := 0; i < 2; i++ {
		r := <-done
		if r.up {
			stats.BytesUp.Add(r.n)
		} else {
			stats.BytesDown.Add(r.n)
		}
		// Quota accounting counts both directions, because an operator setting
		// a quota is limiting cost, and cost is traffic in either direction.
		acct.addBytes(r.n)
	}
}

// stricterLimiter picks the lower of two throughput caps.
//
// A nil limiter means unlimited, so nil is only returned when both are nil.
func stricterLimiter(a, b *rateLimiter) *rateLimiter {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case b.rate < a.rate:
		return b
	default:
		return a
	}
}

// copyWithIdle copies until EOF or until neither direction has moved for the
// idle timeout.
func copyWithIdle(dst, src net.Conn, bufSize int, idle time.Duration, limiter *rateLimiter) int64 {
	buf := make([]byte, bufSize)
	var total int64

	for {
		if idle > 0 {
			if err := src.SetReadDeadline(time.Now().Add(idle)); err != nil {
				return total
			}
		}
		n, err := src.Read(buf)
		if n > 0 {
			if limiter != nil {
				limiter.wait(n)
			}
			written, werr := dst.Write(buf[:n])
			total += int64(written)
			if werr != nil {
				return total
			}
		}
		if err != nil {
			return total
		}
	}
}

// rateLimiter is a token bucket that throttles throughput.
type rateLimiter struct {
	mu       sync.Mutex
	capacity float64
	tokens   float64
	rate     float64 // tokens (bytes) per second
	last     time.Time
}

func newRateLimiter(kbps int) *rateLimiter {
	if kbps <= 0 {
		return nil
	}
	rate := float64(kbps) * 1024
	return &rateLimiter{
		// A quarter-second burst smooths out the sawtooth a strict per-byte
		// limiter would produce on a bursty transfer.
		capacity: rate / 4,
		tokens:   rate / 4,
		rate:     rate,
		last:     time.Now(),
	}
}

// wait blocks until n bytes may be sent.
func (r *rateLimiter) wait(n int) {
	if r == nil || r.rate <= 0 {
		return
	}
	remaining := float64(n)
	for remaining > 0 {
		r.mu.Lock()
		now := time.Now()
		r.tokens += now.Sub(r.last).Seconds() * r.rate
		if r.tokens > r.capacity {
			r.tokens = r.capacity
		}
		r.last = now

		if r.tokens >= remaining {
			r.tokens -= remaining
			r.mu.Unlock()
			return
		}
		deficit := remaining - r.tokens
		r.tokens = 0
		r.mu.Unlock()

		sleep := time.Duration(deficit / r.rate * float64(time.Second))
		if sleep < time.Millisecond {
			sleep = time.Millisecond
		}
		if sleep > time.Second {
			sleep = time.Second
		}
		time.Sleep(sleep)
		remaining = deficit
	}
}

// writeDialSuccess tells a SOCKS5 client that the target is reachable. Other
// transports have no success reply, so this is a no-op for them.
func writeDialSuccess(stream transport.Stream) {
	if stream.TransportName() != "socks5" {
		return
	}
	_ = socks5Success(stream)
}

// writeDialFailure tells a SOCKS5 client why the dial failed.
func writeDialFailure(stream transport.Stream, err error) {
	if stream.TransportName() != "socks5" {
		return
	}
	_ = socks5Failure(stream, err)
}

// socks5Success and socks5Failure are indirection points so the server package
// does not import the socks5 transport directly, which would create a cycle
// once the socks5 package needs server-side helpers.
var (
	socks5Success = func(w interface{ Write([]byte) (int, error) }) error {
		_, err := w.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return err
	}
	socks5Failure = func(w interface{ Write([]byte) (int, error) }, err error) error {
		code := byte(0x01)
		msg := strings.ToLower(err.Error())
		switch {
		case strings.Contains(msg, "refused"):
			code = 0x05
		case strings.Contains(msg, "unreachable") && strings.Contains(msg, "network"):
			code = 0x03
		case strings.Contains(msg, "unreachable"):
			code = 0x04
		case strings.Contains(msg, "timeout"):
			code = 0x06
		case strings.Contains(msg, "not allowed"):
			code = 0x02
		}
		_, werr := w.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return werr
	}
)

// isPingAnswered reports whether the transport answered a ping and closed.
func isPingAnswered(err error) bool {
	return transport.IsPingAnswered(err)
}

// isFallbackHandled reports whether a failed handshake was forwarded to a
// masking fallback instead of being dropped.
func isFallbackHandled(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "forwarded to fallback")
}

// String renders the relay's state for logs.
func (s *Server) String() string {
	st := s.stats.Snapshot()
	return fmt.Sprintf("relay{listeners=%d active=%d total=%d up=%d down=%d}",
		len(s.ListenerStatuses()), st.ActiveConnections, st.TotalConnections, st.BytesUp, st.BytesDown)
}
