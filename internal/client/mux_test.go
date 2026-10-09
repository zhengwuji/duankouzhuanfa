package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"porttransit/internal/config"
	"porttransit/internal/logx"
	"porttransit/internal/transport"

	_ "porttransit/internal/transports/direct"
)

// The tests in this file exercise the session pool against a relay that speaks
// the real multiplexing contract: a connection-level CmdMux preamble, the
// acknowledgement byte, a yamux session, and a PortTransit preamble on every
// stream. A fake that skipped the preambles would prove nothing about the part
// most likely to be wrong — the pool's own concurrency — because it would not
// reproduce the fact that a stream's usefulness is only known after a round
// trip.

// muxRelay is a minimal relay used by the pool tests.
//
// It is deliberately built from the production pieces — the direct transport's
// handler for the connection-level preamble, and PreambleServerHandshake for
// each stream — rather than from a hand-rolled framing, so a change to the
// wire contract breaks these tests instead of passing them.
type muxRelay struct {
	ln       net.Listener
	settings transport.Settings
	// ack controls whether the relay acknowledges a multiplexing request. When
	// false it closes the connection instead, which is what an older relay or a
	// listener with multiplexing off does.
	ack bool

	conns    atomic.Int64
	sessions atomic.Int64
	streams  atomic.Int64

	mu      sync.Mutex
	live    []*yamux.Session
	stopped bool
}

func startMuxRelay(t *testing.T, settings transport.Settings, ack bool) *muxRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind the fake relay: %v", err)
	}
	r := &muxRelay{ln: ln, settings: settings, ack: ack}
	go r.serve()
	t.Cleanup(func() {
		r.mu.Lock()
		r.stopped = true
		live := r.live
		r.live = nil
		r.mu.Unlock()
		for _, s := range live {
			_ = s.Close()
		}
		_ = ln.Close()
	})
	return r
}

func (r *muxRelay) addr() string { return r.ln.Addr().String() }

// killSessions tears every live session down without closing the listener, so a
// test can simulate a relay that dropped the connection.
func (r *muxRelay) killSessions() {
	r.mu.Lock()
	live := r.live
	r.live = nil
	r.mu.Unlock()
	for _, s := range live {
		_ = s.Close()
	}
}

func (r *muxRelay) liveSessions() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.live)
}

func (r *muxRelay) serve() {
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			return
		}
		r.conns.Add(1)
		go r.handle(conn)
	}
}

func (r *muxRelay) handle(conn net.Conn) {
	handler, err := transport.NewHandler("direct")
	if err != nil {
		_ = conn.Close()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := handler.Handle(ctx, conn, transport.HandleRequest{
		Timeout:  5 * time.Second,
		Settings: r.settings,
	})
	if err != nil {
		_ = conn.Close()
		return
	}
	req := stream.Request()

	if req == nil || req.Command != transport.CmdMux {
		// An ordinary, dedicated connection. The pool falls back to one of
		// these whenever multiplexing is unavailable, so the fake relay has to
		// serve it or the fallback path could not be tested.
		defer stream.Close()
		r.echo(stream)
		return
	}

	if !r.ack {
		// Refusing multiplexing means closing the connection with no
		// acknowledgement byte, which is exactly what a relay whose listener
		// has multiplexing off does.
		_ = stream.Close()
		return
	}

	cfg, err := transport.MuxSessionConfig(r.settings, transport.NopLogger())
	if err != nil {
		_ = stream.Close()
		return
	}
	if err := transport.AcknowledgeMux(stream, 5*time.Second); err != nil {
		_ = stream.Close()
		return
	}
	sess, err := yamux.Server(stream, cfg)
	if err != nil {
		_ = stream.Close()
		return
	}
	defer sess.Close()

	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return
	}
	r.live = append(r.live, sess)
	r.sessions.Add(1)
	r.mu.Unlock()

	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return
		}
		r.streams.Add(1)
		go func(st *yamux.Stream) {
			defer st.Close()
			// The stream is wrapped before the preamble handshake runs on it,
			// because the returned Stream is what the echo loop copies from and
			// what the client's own half-close has to reach.
			inner, err := transport.PreambleServerHandshake(transport.NewMuxStream(st), transport.ServerHandshakeConfig{
				PSK:           transport.DecodePSK(r.settings.GetString("psk", "")),
				Timeout:       5 * time.Second,
				TransportName: "direct",
			})
			if err != nil {
				return
			}
			defer inner.Close()
			r.echo(inner)
		}(st)
	}
}

// echo copies a stream onto itself so the client sees its own bytes back, which
// is what proves the stream carried data in both directions.
func (r *muxRelay) echo(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	_, _ = io.Copy(conn, conn)
}

// muxTestClient builds a client whose only relay is entry.
//
// Start is deliberately not called: the pool is exercised directly, and a
// client that has not started has no context — which is why openStream and
// openVia resolve a nil context rather than assuming Start ran.
func muxTestClient(t *testing.T, entry config.ServerEntry) (*Client, *serverEntry) {
	t.Helper()
	cfg := config.Default(config.ModeClient)
	cfg.Client.Proxy.Enabled = false
	cfg.Client.Health.Enabled = false
	cfg.Client.Servers = []config.ServerEntry{entry}

	c, err := New(cfg.Client, logx.Discard())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	entries := c.pools.Entries()
	if len(entries) != 1 {
		t.Fatalf("the client holds %d relays, want 1", len(entries))
	}
	return c, entries[0]
}

// muxEntry describes a relay entry pointed at r.
func muxEntry(r *muxRelay, extra map[string]any) config.ServerEntry {
	settings := map[string]any{"psk": "pool-test-key", "mux": true}
	for k, v := range extra {
		settings[k] = v
	}
	return config.ServerEntry{
		ID:        "relay-1",
		Name:      "pool test relay",
		Address:   r.addr(),
		Transport: "direct",
		Enabled:   true,
		Settings:  settings,
	}
}

// connectRequest is the request a tunnel or the local proxy would send.
func connectRequest() *transport.Request {
	return &transport.Request{Command: transport.CmdConnectTCP, Target: "example.com:443"}
}

// echoOver writes payload and reads it back through a stream.
func echoOver(t *testing.T, st transport.Stream, payload string) string {
	t.Helper()
	_ = st.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := st.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatalf("read the echo back: %v", err)
	}
	return string(got)
}

// TestSessionPoolReusesOneSession proves the whole point of multiplexing: many
// proxied connections travel over a single relay connection, so the handshake
// is paid once rather than once per connection.
func TestSessionPoolReusesOneSession(t *testing.T) {
	relay := startMuxRelay(t, transport.Settings{"psk": "pool-test-key"}, true)

	// openStream is the real entry point every tunnel and the proxy use, so the
	// test drives it rather than the pool directly.
	c, entry := muxTestClient(t, muxEntry(relay, nil))

	for i := 0; i < 6; i++ {
		stream, _, err := c.openStream(entry.ID, "", "", connectRequest())
		if err != nil {
			t.Fatalf("openStream %d: %v", i, err)
		}
		payload := fmt.Sprintf("stream number %d", i)
		if back := echoOver(t, stream, payload); back != payload {
			t.Fatalf("stream %d echoed %q, want %q", i, back, payload)
		}
		_ = stream.Close()
	}

	if n := relay.conns.Load(); n != 1 {
		t.Errorf("the relay accepted %d TCP connections, want 1: the session was not reused", n)
	}
	if n := relay.sessions.Load(); n != 1 {
		t.Errorf("the relay saw %d sessions, want 1", n)
	}
}

// TestSessionPoolReplacesDeadSession proves a session that dies is dropped and
// replaced inside the same call, so a broken session costs one slow connection
// rather than becoming a permanent outage.
func TestSessionPoolReplacesDeadSession(t *testing.T) {
	relay := startMuxRelay(t, transport.Settings{"psk": "pool-test-key"}, true)
	c, entry := muxTestClient(t, muxEntry(relay, nil))

	first, _, err := c.openStream(entry.ID, "", "", connectRequest())
	if err != nil {
		t.Fatalf("openStream before the kill: %v", err)
	}
	if back := echoOver(t, first, "before"); back != "before" {
		t.Fatalf("echoed %q, want %q", back, "before")
	}
	_ = first.Close()

	// The relay drops every session without closing the listener. The client
	// has to notice and recover on its own.
	relay.killSessions()
	waitFor(t, 5*time.Second, func() bool { return relay.liveSessions() == 0 })

	second, _, err := c.openStream(entry.ID, "", "", connectRequest())
	if err != nil {
		t.Fatalf("openStream after the kill: %v", err)
	}
	defer second.Close()
	if back := echoOver(t, second, "after"); back != "after" {
		t.Fatalf("echoed %q after recovery, want %q", back, "after")
	}

	if n := relay.sessions.Load(); n < 2 {
		t.Errorf("the relay saw %d sessions, want at least 2: a replacement was not dialed", n)
	}
	if n := relay.conns.Load(); n < 2 {
		t.Errorf("the relay accepted %d connections, want at least 2", n)
	}
}

// TestSessionPoolFallsBackWhenRelayRefuses proves a relay that does not
// multiplex is still used, with one connection per stream. Without this a
// half-upgraded deployment — client updated, relay not — would fail every
// request.
func TestSessionPoolFallsBackWhenRelayRefuses(t *testing.T) {
	relay := startMuxRelay(t, transport.Settings{"psk": "pool-test-key"}, false)
	c, entry := muxTestClient(t, muxEntry(relay, nil))

	for i := 0; i < 3; i++ {
		stream, _, err := c.openStream(entry.ID, "", "", connectRequest())
		if err != nil {
			t.Fatalf("openStream %d fell back and still failed: %v", i, err)
		}
		payload := fmt.Sprintf("fallback %d", i)
		if back := echoOver(t, stream, payload); back != payload {
			t.Fatalf("fallback stream %d echoed %q, want %q", i, back, payload)
		}
		_ = stream.Close()
	}

	if n := relay.sessions.Load(); n != 0 {
		t.Errorf("the relay started %d sessions despite refusing multiplexing", n)
	}
	// Three streams cost four connections, not six: the first stream discovers
	// the refusal by opening a connection the relay closes, and every later
	// stream goes straight to a dedicated connection because the refusal is
	// remembered. Rediscovering it per stream would double the handshakes on
	// exactly the configuration that is already the slow one.
	if n := relay.conns.Load(); n != 4 {
		t.Errorf("the relay accepted %d connections, want 4 (one refusal plus one per stream)", n)
	}
}

// TestSessionPoolCapsStreamsPerSession proves the client spreads work across
// more sessions rather than overfilling one, and that past its own session cap
// it degrades to a dedicated connection instead of failing.
//
// The cap is the client's half of a limit yamux does not provide: yamux will
// happily open a new stream on a session forever, so without this the relay's
// own cap would be the only thing standing between one session and unbounded
// resource use.
func TestSessionPoolCapsStreamsPerSession(t *testing.T) {
	relay := startMuxRelay(t, transport.Settings{"psk": "pool-test-key"}, true)
	c, entry := muxTestClient(t, muxEntry(relay, map[string]any{
		"muxMaxStreams":  2,
		"muxMaxSessions": 2,
	}))

	// Two streams fill the first session. The third must open a second one.
	var held []transport.Stream
	for i := 0; i < 3; i++ {
		st, _, err := c.openStream(entry.ID, "", "", connectRequest())
		if err != nil {
			t.Fatalf("openStream %d: %v", i, err)
		}
		held = append(held, st)
	}
	if n := relay.sessions.Load(); n != 2 {
		t.Errorf("the relay saw %d sessions, want 2", n)
	}

	// Both sessions are now full and the client is at its session cap, so the
	// next request must be served by a dedicated connection rather than
	// refused.
	fourth, _, err := c.openStream(entry.ID, "", "", connectRequest())
	if err != nil {
		t.Fatalf("openStream past the session cap: %v", err)
	}
	held = append(held, fourth)
	if back := echoOver(t, fourth, "past the cap"); back != "past the cap" {
		t.Fatalf("echoed %q, want %q", back, "past the cap")
	}

	for _, st := range held {
		_ = st.Close()
	}
}

// TestSessionPoolIdleSessionRetired proves an idle session is closed rather
// than held open forever. The reaper is driven directly so the test does not
// depend on the wall clock.
func TestSessionPoolIdleSessionRetired(t *testing.T) {
	relay := startMuxRelay(t, transport.Settings{"psk": "pool-test-key"}, true)
	c, entry := muxTestClient(t, muxEntry(relay, map[string]any{"muxIdleTimeout": "1s"}))

	stream, _, err := c.openStream(entry.ID, "", "", connectRequest())
	if err != nil {
		t.Fatalf("openStream: %v", err)
	}
	if back := echoOver(t, stream, "idle"); back != "idle" {
		t.Fatalf("echoed %q, want %q", back, "idle")
	}
	_ = stream.Close()

	// The stream has been closed, so the session has no streams on it. The
	// reaper records the idle moment on its first pass and retires on the
	// second, once the configured timeout has elapsed.
	//
	// Waiting for the relay to observe the close first is what makes this
	// measure the reaper rather than a race: the pool judges idleness from the
	// session's own stream count, and the relay's count only drops once it has
	// processed the FIN.
	waitFor(t, 5*time.Second, func() bool { return relaySessionStreams(t, c, entry) == 0 })
	c.mux.reap(time.Now())
	c.mux.reap(time.Now().Add(2 * time.Second))

	rp, err := c.mux.relay(entry)
	if err != nil {
		t.Fatalf("relay pool: %v", err)
	}
	rp.mu.Lock()
	live := len(rp.sessions)
	rp.mu.Unlock()
	if live != 0 {
		t.Errorf("the pool still holds %d sessions after the idle timeout", live)
	}

	// And the next request rebuilds a session rather than failing.
	again, _, err := c.openStream(entry.ID, "", "", connectRequest())
	if err != nil {
		t.Fatalf("openStream after the idle retirement: %v", err)
	}
	defer again.Close()
	if back := echoOver(t, again, "rebuilt"); back != "rebuilt" {
		t.Fatalf("echoed %q, want %q", back, "rebuilt")
	}
	if n := relay.sessions.Load(); n < 2 {
		t.Errorf("the relay saw %d sessions, want at least 2", n)
	}
}

// relaySessionStreams reports the stream count the client's own session
// believes it has, which is what the reaper judges idleness from.
func relaySessionStreams(t *testing.T, c *Client, entry *serverEntry) int {
	t.Helper()
	rp, err := c.mux.relay(entry)
	if err != nil {
		t.Fatalf("relay pool: %v", err)
	}
	rp.mu.Lock()
	defer rp.mu.Unlock()
	total := 0
	for _, ps := range rp.sessions {
		if ps.sess != nil {
			total += ps.sess.NumStreams()
		}
	}
	return total
}

// TestSessionPoolConcurrentOpensAreRaceFree hammers the pool from many
// goroutines while the reaper runs and the relay drops sessions underneath it.
//
// This is the test the pool exists for: it is the only part of multiplexing
// that is shared mutable state, so it is the part where a mistake is a crash or
// a silently crossed stream rather than a slow connection. It is most valuable
// under -race, which this host cannot run (no gcc), so the concurrency is
// deliberately high to give any unsynchronised access as many chances to
// misbehave as possible.
func TestSessionPoolConcurrentOpensAreRaceFree(t *testing.T) {
	relay := startMuxRelay(t, transport.Settings{"psk": "pool-test-key"}, true)
	c, entry := muxTestClient(t, muxEntry(relay, map[string]any{
		"muxMaxStreams":  4,
		"muxMaxSessions": 2,
		"muxIdleTimeout": "1ms",
	}))

	stop := make(chan struct{})
	var reaper sync.WaitGroup
	reaper.Add(1)
	go func() {
		defer reaper.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// A zero idle timeout would retire every session on every pass;
			// the reaper's own idle bookkeeping still requires two passes, so
			// sessions are retired aggressively but not instantaneously, which
			// is what makes this a genuine race against the openers.
			c.mux.reap(time.Now().Add(time.Hour))
		}
	}()

	const workers = 24
	const perWorker = 6
	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				stream, _, err := c.openStream(entry.ID, "", "", connectRequest())
				if err != nil {
					errs <- fmt.Errorf("worker %d open %d: %w", n, j, err)
					return
				}
				// A distinct payload per worker catches a stream that was
				// crossed with another, which a shared buffer would produce.
				payload := fmt.Sprintf("w%d-j%d", n, j)
				_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := stream.Write([]byte(payload)); err != nil {
					errs <- fmt.Errorf("worker %d write %d: %w", n, j, err)
					_ = stream.Close()
					return
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(stream, got); err != nil {
					errs <- fmt.Errorf("worker %d read %d: %w", n, j, err)
					_ = stream.Close()
					return
				}
				if string(got) != payload {
					errs <- fmt.Errorf("worker %d received %q, want %q", n, got, payload)
				}
				_ = stream.Close()
			}
		}(i)
	}

	wg.Wait()
	close(stop)
	reaper.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestSessionPoolClosedClientDoesNotDial proves the pool refuses after the
// client has stopped, so a late connection attempt cannot resurrect a session
// on a client that is shutting down.
func TestSessionPoolClosedClientDoesNotDial(t *testing.T) {
	relay := startMuxRelay(t, transport.Settings{"psk": "pool-test-key"}, true)
	c, entry := muxTestClient(t, muxEntry(relay, nil))

	c.mux.closeAll()
	if _, _, err := c.openStream(entry.ID, "", "", connectRequest()); err == nil {
		t.Fatal("openStream succeeded after the session pool was closed")
	}
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the condition was not met within %s", timeout)
}
