package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"porttransit/internal/client"
	"porttransit/internal/config"
	"porttransit/internal/logx"
	"porttransit/internal/server"

	_ "porttransit/internal/transports/direct"
	_ "porttransit/internal/transports/tls"
)

// The tests in this file prove the multiplexed path end to end: a real client,
// a real relay and a real target, with the relay's listener and the client's
// relay entry both configured for multiplexing.
//
// The unit tests in the client package cover the session pool's own logic with
// a stand-in relay. These tests exist because the pool is only useful if the
// relay actually serves what it opens: the connection-level request has to be
// accepted, the acknowledgement has to arrive, each stream's preamble has to be
// read by the relay's own handshake code, and the bytes have to survive the
// round trip. A defect at any of those seams passes every unit test and fails
// the moment a browser opens a second connection.

// muxSettings returns the settings both sides need for a multiplexed direct
// tunnel, with extra keys layered on top.
func muxSettings(t *testing.T, extra map[string]any) map[string]any {
	t.Helper()
	s := map[string]any{"psk": randomPSK(t), "mux": true}
	for k, v := range extra {
		s[k] = v
	}
	return s
}

// relayConnections reports how many TCP connections the relay has accepted
// since it started.
//
// For a multiplexed client this is the number of sessions, which is the whole
// claim being tested: many proxied connections, one relay connection.
func relayConnections(h *harness) int64 {
	return h.relay.Stats().Snapshot().TotalConnections
}

// TestMuxManyStreamsOverOneConnection proves the point of multiplexing: many
// proxied connections travel over a single relay connection, so the transport
// handshake is paid once instead of once per connection.
//
// It is the multiplexed counterpart of TestMultipleConnectionsThroughOneTunnel
// and asserts the same thing about the payload — every connection still
// carries its own bytes to the target — plus the property that makes it worth
// doing: the relay saw one connection, not one per request.
func TestMuxManyStreamsOverOneConnection(t *testing.T) {
	h := startHarness(t, "direct", muxSettings(t, nil), nil)

	const rounds = 8
	for i := 0; i < rounds; i++ {
		payload := fmt.Sprintf("multiplexed message %d", i)
		if got := h.roundTrip(t, payload); got != payload {
			t.Fatalf("stream %d echoed %q, want %q", i, got, payload)
		}
	}

	if n := relayConnections(h); n != 1 {
		t.Errorf("the relay accepted %d connections for %d streams, want 1", n, rounds)
	}
	// The target is dialed per stream even though the relay connection is
	// shared, because a stream is a separate destination connection. A relay
	// that reused one target connection would be sending different clients'
	// traffic down the same socket.
	if n := h.target.connections(); n < rounds {
		t.Errorf("the target saw %d connections, want at least %d", n, rounds)
	}
}

// TestMuxConcurrentStreamsAreIsolated proves parallel streams inside one
// session do not mix their bytes, which is the failure a shared buffer or a
// mis-keyed stream produces.
//
// Each worker sends a payload that identifies it, so a crossed stream is
// detected rather than merely tolerated.
func TestMuxConcurrentStreamsAreIsolated(t *testing.T) {
	h := startHarness(t, "direct", muxSettings(t, nil), nil)

	const workers = 16
	var wg sync.WaitGroup
	errs := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			payload := strings.Repeat(fmt.Sprintf("worker-%d-", n), 400)

			conn, err := net.DialTimeout("tcp", h.tunnel, 10*time.Second)
			if err != nil {
				errs <- fmt.Errorf("worker %d dial: %w", n, err)
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

			if _, err := conn.Write([]byte(payload)); err != nil {
				errs <- fmt.Errorf("worker %d write: %w", n, err)
				return
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				errs <- fmt.Errorf("worker %d read: %w", n, err)
				return
			}
			if string(got) != payload {
				errs <- fmt.Errorf("worker %d received a different stream", n)
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	if n := relayConnections(h); n != 1 {
		t.Errorf("the relay accepted %d connections for %d concurrent streams, want 1", n, workers)
	}
}

// TestMuxLargeTransferPreservesBytes proves a payload larger than one buffer
// crosses a multiplexed stream intact.
//
// It matters more here than for a plain connection: the payload is split into
// yamux frames, so a framing bug — a lost window update, a stream that stops
// reading because flow control never releases — truncates or stalls a large
// transfer while a short message passes.
func TestMuxLargeTransferPreservesBytes(t *testing.T) {
	h := startHarness(t, "direct", muxSettings(t, nil), nil)

	const size = 512 * 1024
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	conn, err := net.DialTimeout("tcp", h.tunnel, 10*time.Second)
	if err != nil {
		t.Fatalf("dial the tunnel: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	// The write and the read have to be concurrent: the echo target will not
	// drain 512 KiB while the sender is still blocked writing it if the session
	// window fills.
	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		writeErr <- err
	}()

	got := make([]byte, size)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read the large echo back: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write the large payload: %v", err)
	}

	for i := range got {
		if got[i] != payload[i] {
			t.Fatalf("the payload differs at byte %d of %d", i, size)
		}
	}
	if n := relayConnections(h); n != 1 {
		t.Errorf("the relay accepted %d connections, want 1", n)
	}
}

// TestMuxSessionIsReplacedAfterIdleClose proves a session that dies is replaced
// rather than wedging the client.
//
// The relay is given a very short idle timeout, so it closes the session while
// the client still holds it. The client's next connection must notice the dead
// session, dial a replacement and succeed. Without that recovery the client
// would keep a corpse in its pool and every later connection would fail, which
// is the failure mode that makes a multiplexing implementation worse than no
// multiplexing at all.
func TestMuxSessionIsReplacedAfterIdleClose(t *testing.T) {
	// The idle timeout is applied to both sides through the shared settings, so
	// the client's reaper would also retire the session — but its reaper runs
	// on a five-second floor, while the relay's timer fires in half a second.
	// The relay therefore closes it first, which is exactly the case this test
	// is about: a session that died underneath the client.
	h := startHarness(t, "direct", muxSettings(t, map[string]any{"muxIdleTimeout": "500ms"}), nil)

	const first = "before the session died"
	if got := h.roundTrip(t, first); got != first {
		t.Fatalf("echoed %q, want %q", got, first)
	}
	if n := relayConnections(h); n != 1 {
		t.Fatalf("the relay accepted %d connections before the idle close, want 1", n)
	}

	// Wait past the relay's idle timeout so the session it holds is closed,
	// then connect again.
	time.Sleep(1200 * time.Millisecond)

	const second = "after the session was replaced"
	if got := h.roundTrip(t, second); got != second {
		t.Fatalf("the client did not recover from a dead session: echoed %q, want %q", got, second)
	}
	if n := relayConnections(h); n < 2 {
		t.Errorf("the relay accepted %d connections, want at least 2: no replacement session was dialed", n)
	}
}

// TestMuxStreamCapIsEnforced proves the relay bounds how many streams one
// session may carry.
//
// The cap is the relay's protection against a session being used to exhaust its
// memory and file descriptors, so it has to be enforced on the relay rather
// than trusted to the client. The client is given a much higher cap here so
// that it genuinely tries to exceed the relay's.
func TestMuxStreamCapIsEnforced(t *testing.T) {
	const relayCap = 2

	h := startHarness(t, "direct",
		muxSettings(t, map[string]any{"muxMaxStreams": relayCap}),
		func(cc *config.ClientConfig) {
			// The client's own cap is raised so it does not simply open a
			// second session: the request under test is the one that exceeds
			// the relay's limit.
			cc.Servers[0].Settings["muxMaxStreams"] = 64
			cc.Servers[0].Settings["muxMaxSessions"] = 1
		})

	// Fill the session. Each connection stays open because the local socket is
	// held, and a held stream counts against the cap.
	held := make([]net.Conn, 0, relayCap)
	for i := 0; i < relayCap; i++ {
		conn, err := net.DialTimeout("tcp", h.tunnel, 10*time.Second)
		if err != nil {
			t.Fatalf("dial the tunnel for stream %d: %v", i, err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

		payload := fmt.Sprintf("held %d", i)
		if _, err := conn.Write([]byte(payload)); err != nil {
			t.Fatalf("write on stream %d: %v", i, err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("stream %d was not established: %v", i, err)
		}
		held = append(held, conn)
	}

	if n := relayConnections(h); n != 1 {
		t.Fatalf("the relay accepted %d connections, want 1", n)
	}

	// The next stream must be refused by the relay. The client writes its
	// preamble and payload, then reads; the read must fail rather than return
	// the echo, because the relay closed the stream instead of serving it.
	over, err := net.DialTimeout("tcp", h.tunnel, 10*time.Second)
	if err != nil {
		t.Fatalf("dial the tunnel past the cap: %v", err)
	}
	defer over.Close()
	_ = over.SetDeadline(time.Now().Add(10 * time.Second))

	_, _ = over.Write([]byte("past the cap"))
	buf := make([]byte, 32)
	if n, err := over.Read(buf); err == nil && n > 0 {
		t.Fatalf("the relay served stream %d past its cap of %d and echoed %q", relayCap+1, relayCap, buf[:n])
	}

	// A stream that was already open must be unaffected: the cap rejects new
	// streams, it does not tear down the session.
	for i, conn := range held {
		payload := fmt.Sprintf("still alive %d", i)
		if _, err := conn.Write([]byte(payload)); err != nil {
			t.Errorf("held stream %d failed after the cap rejection: %v", i, err)
			continue
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Errorf("held stream %d did not echo after the cap rejection: %v", i, err)
			continue
		}
		if string(got) != payload {
			t.Errorf("held stream %d echoed %q, want %q", i, got, payload)
		}
	}
}

// TestMuxDisabledByDefault proves a configuration that does not ask for
// multiplexing keeps the one-connection-per-stream behaviour, so an existing
// deployment is unaffected by this feature existing.
func TestMuxDisabledByDefault(t *testing.T) {
	// No "mux" key at all, which is what every configuration written before
	// this feature looks like.
	h := startHarness(t, "direct", map[string]any{"psk": randomPSK(t)}, nil)

	const rounds = 3
	for i := 0; i < rounds; i++ {
		payload := fmt.Sprintf("dedicated %d", i)
		if got := h.roundTrip(t, payload); got != payload {
			t.Fatalf("connection %d echoed %q, want %q", i, got, payload)
		}
	}

	if n := relayConnections(h); n != rounds {
		t.Errorf("the relay accepted %d connections for %d requests, want %d: multiplexing is on by default", n, rounds, rounds)
	}
}

// TestMuxOverTLS proves multiplexing works through an encrypted transport, not
// only over the plain one.
//
// The direct transport is a bare TCP connection followed by a preamble, so it
// would pass even if the session were somehow started on the raw socket. TLS is
// where the layering matters: the session must ride the encrypted
// connection, and each stream's preamble must be readable inside it.
func TestMuxOverTLS(t *testing.T) {
	settings := muxSettings(t, map[string]any{"insecure": true})
	h := startHarness(t, "tls", settings, nil)

	const rounds = 5
	for i := 0; i < rounds; i++ {
		payload := fmt.Sprintf("encrypted multiplexed %d", i)
		if got := h.roundTrip(t, payload); got != payload {
			t.Fatalf("stream %d echoed %q, want %q", i, got, payload)
		}
	}

	if n := relayConnections(h); n != 1 {
		t.Errorf("the relay accepted %d TLS connections for %d streams, want 1", n, rounds)
	}
}

// TestMuxClientFallsBackWhenRelayHasMuxOff proves a client configured for
// multiplexing still works against a relay that is not.
//
// This is the half-upgraded deployment: the operator has updated the client but
// not yet the relay, or has forgotten to add the setting to the listener. The
// client must keep working with one connection per stream. Without the
// acknowledgement byte this is the case that would hang for a keepalive
// timeout on every connection and look like an outage.
func TestMuxClientFallsBackWhenRelayHasMuxOff(t *testing.T) {
	psk := randomPSK(t)

	// The relay listener has no mux setting; the client asks for it.
	h := startHarness(t, "direct", map[string]any{"psk": psk}, func(cc *config.ClientConfig) {
		cc.Servers[0].Settings["mux"] = true
	})

	const rounds = 3
	for i := 0; i < rounds; i++ {
		payload := fmt.Sprintf("fallback over a plain relay %d", i)
		if got := h.roundTrip(t, payload); got != payload {
			t.Fatalf("connection %d echoed %q, want %q", i, got, payload)
		}
	}

	// The first request pays one extra connection to discover the refusal; the
	// rest go straight to dedicated connections because the refusal is
	// remembered per relay.
	if n := relayConnections(h); n != rounds+1 {
		t.Errorf("the relay accepted %d connections for %d requests, want %d (one refusal plus one per request)",
			n, rounds, rounds+1)
	}
}

// TestMuxStreamsRespectTheACL proves multiplexing is not a way around the
// relay's destination policy.
//
// A stream inside a session carries its own preamble, and the relay runs the
// same ACL check on it as on a whole connection. Without this test the
// implementation could plausibly have applied policy once per session and let
// every stream inside it go anywhere — which would be a policy bypass that only
// appears in the multiplexed path.
func TestMuxStreamsRespectTheACL(t *testing.T) {
	target := startEcho(t)

	serverCfg := config.Default(config.ModeServer)
	serverCfg.WebUI.Enabled = false
	serverCfg.Log.Level = "error"
	serverCfg.Log.File = ""
	serverCfg.Server.DataDir = t.TempDir()
	serverCfg.Server.Forwards = nil
	// The target lives on loopback, which the default policy blocks. Enabling
	// the block explicitly makes the test's intent clear rather than depending
	// on the default.
	block := true
	serverCfg.Server.ACL.BlockPrivate = &block
	settings := muxSettings(t, nil)
	serverCfg.Server.Listeners = []config.Listener{{
		Name:      "mux-acl-relay",
		Transport: "direct",
		Listen:    "127.0.0.1:0",
		Enabled:   true,
		Settings:  cloneSettings(settings),
	}}

	relay, err := server.New(serverCfg.Server, logx.Discard())
	if err != nil {
		t.Fatalf("create the relay: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := relay.Start(ctx); err != nil {
		t.Fatalf("start the relay: %v", err)
	}
	defer relay.Stop()

	relayAt := waitForListener(t, relay)

	clientCfg := config.Default(config.ModeClient)
	clientCfg.WebUI.Enabled = false
	clientCfg.Log.Level = "error"
	clientCfg.Log.File = ""
	clientCfg.Client.DataDir = t.TempDir()
	clientCfg.Client.Health.Enabled = false
	clientCfg.Client.Proxy.Enabled = false
	clientCfg.Client.Servers = []config.ServerEntry{{
		ID:        "relay-1",
		Address:   relayAt,
		Transport: "direct",
		Enabled:   true,
		Settings:  cloneSettings(settings),
	}}
	clientCfg.Client.Tunnels = []config.Tunnel{{
		Name:    "blocked-mux-tunnel",
		Enabled: true,
		Listen:  "127.0.0.1:0",
		Target:  target.addr(),
		Server:  "relay-1",
	}}

	cli, err := client.New(clientCfg.Client, logx.Discard())
	if err != nil {
		t.Fatalf("create the client: %v", err)
	}
	if err := cli.Start(ctx); err != nil {
		t.Fatalf("start the client: %v", err)
	}
	defer cli.Stop()

	tunnelAt := waitForTunnel(t, cli)

	// Two attempts: the first establishes the session, and the second proves
	// the check is applied to a stream inside an already-accepted session
	// rather than only to the connection that created it.
	for i := 0; i < 2; i++ {
		conn, err := net.DialTimeout("tcp", tunnelAt, 10*time.Second)
		if err != nil {
			t.Fatalf("dial the tunnel: %v", err)
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = conn.Write([]byte("blocked"))

		buf := make([]byte, 32)
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			_ = conn.Close()
			t.Fatalf("attempt %d: the relay reached a blocked private target and echoed %q", i, buf[:n])
		}
		_ = conn.Close()
	}

	if target.connections() != 0 {
		t.Error("the blocked target was contacted through a multiplexed stream, so the ACL was not enforced")
	}
	// The session itself was established: the refusal is per stream, not a
	// refusal to multiplex at all.
	if n := relay.Stats().Snapshot().TotalConnections; n != 1 {
		t.Errorf("the relay accepted %d connections, want 1: the ACL check should not have closed the session", n)
	}
}

// TestMuxProxyServesSOCKS5 proves the local proxy's connections are
// multiplexed too, which is the path a browser actually uses.
//
// It is worth a test of its own because the proxy opens its streams through a
// different call site from a tunnel's, so a change that only wired multiplexing
// into the tunnel path would pass every tunnel test and leave the browser
// paying a handshake per connection.
func TestMuxProxyServesSOCKS5(t *testing.T) {
	target := startEcho(t)

	serverCfg := config.Default(config.ModeServer)
	serverCfg.WebUI.Enabled = false
	serverCfg.Log.Level = "error"
	serverCfg.Log.File = ""
	serverCfg.Server.DataDir = t.TempDir()
	serverCfg.Server.Forwards = nil
	allowPrivate := false
	serverCfg.Server.ACL.BlockPrivate = &allowPrivate
	settings := muxSettings(t, nil)
	serverCfg.Server.Listeners = []config.Listener{{
		Name:      "mux-proxy-relay",
		Transport: "direct",
		Listen:    "127.0.0.1:0",
		Enabled:   true,
		Settings:  cloneSettings(settings),
	}}

	relay, err := server.New(serverCfg.Server, logx.Discard())
	if err != nil {
		t.Fatalf("create the relay: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := relay.Start(ctx); err != nil {
		t.Fatalf("start the relay: %v", err)
	}
	defer relay.Stop()

	relayAt := waitForListener(t, relay)

	clientCfg := config.Default(config.ModeClient)
	clientCfg.WebUI.Enabled = false
	clientCfg.Log.Level = "error"
	clientCfg.Log.File = ""
	clientCfg.Client.DataDir = t.TempDir()
	clientCfg.Client.Health.Enabled = false
	clientCfg.Client.Servers = []config.ServerEntry{{
		ID:        "relay-1",
		Address:   relayAt,
		Transport: "direct",
		Enabled:   true,
		Settings:  cloneSettings(settings),
	}}
	clientCfg.Client.Proxy = config.LocalProxyConfig{
		Enabled:      true,
		SOCKS5Listen: "127.0.0.1:0",
	}

	cli, err := client.New(clientCfg.Client, logx.Discard())
	if err != nil {
		t.Fatalf("create the client: %v", err)
	}
	if err := cli.Start(ctx); err != nil {
		t.Fatalf("start the client: %v", err)
	}
	defer cli.Stop()

	proxyAt := waitForProxy(t, cli)

	// Three separate SOCKS5 conversations, which is what a page load looks
	// like: several short connections in a row.
	for i := 0; i < 3; i++ {
		payload := fmt.Sprintf("proxied over a session %d", i)
		if got := socks5RoundTrip(t, proxyAt, target.addr(), payload); got != payload {
			t.Fatalf("proxy conversation %d echoed %q, want %q", i, got, payload)
		}
	}

	if n := relay.Stats().Snapshot().TotalConnections; n != 1 {
		t.Errorf("the relay accepted %d connections for 3 proxied conversations, want 1", n)
	}
	if n := target.connections(); n < 3 {
		t.Errorf("the target saw %d connections, want at least 3", n)
	}
}

// TestMuxStreamsAreAdmittedAndReleasedPerStream proves account policy is
// applied to each stream inside a session, and — the part that is easy to get
// wrong — that the concurrency slot a stream reserves is given back.
//
// The account is limited to one concurrent connection. If the multiplexed path
// admitted a stream without releasing the slot, the counter would leak: the
// first stream would work, and every later stream on the same session would be
// refused forever. That is not a hypothetical failure mode — it is exactly what
// an admit path that forgets its release produces, and it looks like the relay
// silently going deaf.
//
// Because the limit is one and the streams are sequential, this test passes
// only if every stream releases before the next one is admitted.
func TestMuxStreamsAreAdmittedAndReleasedPerStream(t *testing.T) {
	limited := enabledAcct("alice")
	limited.MaxConnections = 1

	settings := map[string]any{"psk": "acct-key", "mux": true}
	h := startAccountHarnessTransport(t, t.TempDir(), []config.ClientAccount{limited}, "alice", "direct", settings)

	const rounds = 5
	for i := 0; i < rounds; i++ {
		// The relay releases the slot when its copy loop finishes, which is
		// asynchronous relative to the client observing the echo. Waiting for
		// the count to return to zero makes this test measure whether the slot
		// is released at all, rather than whether it is released before the
		// next line of the test runs.
		waitForAccountIdle(t, h, 5*time.Second)

		payload := fmt.Sprintf("accounted stream %d", i)
		if err := h.attempt(payload); err != nil {
			t.Fatalf("stream %d was refused: the account slot from an earlier stream was not released: %v", i, err)
		}
	}

	// Every stream travelled over the same relay connection, so the release
	// being tested is the multiplexed one rather than the connection path's.
	if n := h.relay.Stats().Snapshot().TotalConnections; n != 1 {
		t.Errorf("the relay accepted %d connections for %d streams, want 1", n, rounds)
	}
}

// waitForAccountIdle waits until the relay reports no active stream for the
// harness's single account.
func waitForAccountIdle(t *testing.T, h *accountHarness, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		usage := h.relay.AccountUsage()
		if len(usage) == 1 && usage[0].Active == 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	usage := h.relay.AccountUsage()
	t.Fatalf("the account never returned to idle: %+v", usage)
}

// TestMuxStreamsAreRefusedForAnUnknownClient proves the account check runs on
// each multiplexed stream rather than once per session.
//
// Without it, a client could open a session with a listed id and then send
// streams under a different one — the connection-level identity would be
// checked and the streams would not.
func TestMuxStreamsAreRefusedForAnUnknownClient(t *testing.T) {
	settings := map[string]any{"psk": "acct-key", "mux": true}
	h := startAccountHarnessTransport(t, t.TempDir(), []config.ClientAccount{enabledAcct("alice")}, "mallory", "direct", settings)

	if err := h.attempt("mallory payload"); err == nil {
		t.Fatal("a multiplexed stream from an unknown client was served")
	}
}

// TestMuxUDPTunnelRoundTrip proves the datagram path works over a session too.
//
// A UDP tunnel opens one stream per flow through the same openStream call the
// TCP tunnels use, so multiplexing changes how a datagram flow is carried
// without changing anything above it. It is worth proving rather than assuming,
// because UDP framing is length-prefixed and read with io.ReadFull: a stream
// that returns short reads — which is a real difference between a raw TCP
// connection and a multiplexed one — would desynchronise the framing and
// corrupt every datagram after the first.
func TestMuxUDPTunnelRoundTrip(t *testing.T) {
	runUDPTunnelRoundTrip(t, "direct", muxSettings(t, nil))
}

// halfCloseTarget answers only after the peer half-closes, which is the
// request/response shape a half-close exists for: the client is done sending
// but is still waiting to read. A relay that treated the half-close as a full
// close would tear the connection down before the reply, and the target would
// never see the request complete.
//
// # Why the target replies, and why that is safe here
//
// Replying after the FIN means the reply is written into a stream whose other
// end has already half-closed — the exact sequence that used to lose data.
// yamux keeps a closed stream's receive buffer until the reader has drained it,
// so the reply is delivered; TestMuxHalfCloseDeliversTheReply in the transport
// package pins that property directly. The reply is asserted here because it is
// the strongest form of the property: not merely "the half-close arrived", but
// "the half-close arrived and the answer came back".
type halfCloseTarget struct {
	ln net.Listener
	// bodies receives one entry per accepted connection: the bytes read before
	// the peer half-closed.
	bodies chan string
}

func startHalfCloseTarget(t *testing.T) *halfCloseTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind the half-close target: %v", err)
	}
	h := &halfCloseTarget{ln: ln, bodies: make(chan string, 8)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))

				// io.ReadAll returns only when the peer half-closes or the
				// connection ends, so reaching the write below proves the
				// half-close travelled the whole way to the target.
				body, err := io.ReadAll(c)
				if err != nil {
					return
				}
				if _, err := c.Write([]byte(halfCloseReplyPrefix + string(body))); err != nil {
					return
				}
				select {
				case h.bodies <- string(body):
				default:
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return h
}

// halfCloseReplyPrefix marks the target's answer, so the client can tell the
// reply from its own request echoed back.
const halfCloseReplyPrefix = "answered:"

// waitForBody returns the next body the target read, or fails the test.
func (h *halfCloseTarget) waitForBody(t *testing.T, timeout time.Duration) string {
	t.Helper()
	select {
	case body := <-h.bodies:
		return body
	case <-time.After(timeout):
		t.Fatal("the target never saw the request complete, so the half-close did not reach it")
		return ""
	}
}

func (h *halfCloseTarget) addr() string { return h.ln.Addr().String() }

// TestMuxStreamHalfClosePropagates proves a half-close on a multiplexed stream
// reaches the target and leaves the other direction usable.
//
// It is the trap this codebase has hit before: a stream wrapper that embeds a
// net.Conn as an *interface* does not expose CloseWrite unless the method is
// written out explicitly, and every caller that probes for it then silently
// takes the "not supported" branch. The symptom is not an error but a
// connection that lingers until its idle timeout, or — as here — a reply that
// never arrives because the whole connection was closed when the request side
// finished.
//
// The test uses a target that answers only after it sees EOF, so it fails
// unless the half-close genuinely propagates through the session and the
// relay's copy loop — and, just as importantly, unless the reply written after
// the peer's FIN is still delivered. That second half is the property the
// session library has to get right: the smux version this layer used to depend
// on discarded a stream's unread receive buffer once both ends had half-closed,
// so the answer arrived as a bare EOF. See TestMuxHalfCloseDeliversTheReply in
// the transport package, which pins it directly and loops it, because the old
// defect was probabilistic.
func TestMuxStreamHalfClosePropagates(t *testing.T) {
	target := startHalfCloseTarget(t)

	serverCfg := config.Default(config.ModeServer)
	serverCfg.WebUI.Enabled = false
	serverCfg.Log.Level = "error"
	serverCfg.Log.File = ""
	serverCfg.Server.DataDir = t.TempDir()
	serverCfg.Server.Forwards = nil
	allowPrivate := false
	serverCfg.Server.ACL.BlockPrivate = &allowPrivate
	settings := muxSettings(t, nil)
	serverCfg.Server.Listeners = []config.Listener{{
		Name:      "mux-halfclose-relay",
		Transport: "direct",
		Listen:    "127.0.0.1:0",
		Enabled:   true,
		Settings:  cloneSettings(settings),
	}}

	relay, err := server.New(serverCfg.Server, logx.Discard())
	if err != nil {
		t.Fatalf("create the relay: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := relay.Start(ctx); err != nil {
		t.Fatalf("start the relay: %v", err)
	}
	defer relay.Stop()

	relayAt := waitForListener(t, relay)

	clientCfg := config.Default(config.ModeClient)
	clientCfg.WebUI.Enabled = false
	clientCfg.Log.Level = "error"
	clientCfg.Log.File = ""
	clientCfg.Client.DataDir = t.TempDir()
	clientCfg.Client.Health.Enabled = false
	clientCfg.Client.Proxy.Enabled = false
	clientCfg.Client.Servers = []config.ServerEntry{{
		ID:        "relay-1",
		Address:   relayAt,
		Transport: "direct",
		Enabled:   true,
		Settings:  cloneSettings(settings),
	}}
	clientCfg.Client.Tunnels = []config.Tunnel{{
		Name:    "halfclose-tunnel",
		Enabled: true,
		Listen:  "127.0.0.1:0",
		Target:  target.addr(),
		Server:  "relay-1",
	}}

	cli, err := client.New(clientCfg.Client, logx.Discard())
	if err != nil {
		t.Fatalf("create the client: %v", err)
	}
	if err := cli.Start(ctx); err != nil {
		t.Fatalf("start the client: %v", err)
	}
	defer cli.Stop()

	tunnelAt := waitForTunnel(t, cli)

	// Two rounds so the half-close is proven on a session that is already
	// established, not only on the one that created it.
	for i := 0; i < 2; i++ {
		conn, err := net.DialTimeout("tcp", tunnelAt, 10*time.Second)
		if err != nil {
			t.Fatalf("round %d: dial the tunnel: %v", i, err)
		}
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

		request := fmt.Sprintf("request %d", i)
		if _, err := conn.Write([]byte(request)); err != nil {
			_ = conn.Close()
			t.Fatalf("round %d: write: %v", i, err)
		}

		// The half-close. Everything above is sent, and the target is expected
		// to observe it as EOF on its side of the relay.
		tcp, ok := conn.(*net.TCPConn)
		if !ok {
			_ = conn.Close()
			t.Fatalf("round %d: the tunnel connection is not a *net.TCPConn", i)
		}
		if err := tcp.CloseWrite(); err != nil {
			_ = conn.Close()
			t.Fatalf("round %d: half-close: %v", i, err)
		}

		if got := target.waitForBody(t, 15*time.Second); got != request {
			_ = conn.Close()
			t.Fatalf("round %d: the target read %q after the half-close, want %q", i, got, request)
		}

		// The answer was written after this side half-closed, so reading it is
		// the assertion that the reply survived the FIN.
		want := halfCloseReplyPrefix + request
		got := make([]byte, len(want))
		if _, err := io.ReadFull(conn, got); err != nil {
			_ = conn.Close()
			t.Fatalf("round %d: the reply written after the half-close was not delivered: %v", i, err)
		}
		if string(got) != want {
			_ = conn.Close()
			t.Fatalf("round %d: read %q, want %q", i, got, want)
		}
		_ = conn.Close()
	}

	if n := relay.Stats().Snapshot().TotalConnections; n != 1 {
		t.Errorf("the relay accepted %d connections, want 1", n)
	}
}

// socks5RoundTrip runs one complete SOCKS5 CONNECT conversation through the
// local proxy and returns what the target echoed back.
func socks5RoundTrip(t *testing.T, proxyAt, target, payload string) string {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAt, 10*time.Second)
	if err != nil {
		t.Fatalf("dial the proxy at %s: %v", proxyAt, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write the SOCKS5 greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read the SOCKS5 method selection: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("the proxy selected %v, want version 5 with no authentication", reply)
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("split the target address: %v", err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("the target address %q is not an IPv4 literal", host)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse the target port: %v", err)
	}

	req := []byte{0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write the SOCKS5 CONNECT request: %v", err)
	}
	connectReply := make([]byte, 10)
	if _, err := io.ReadFull(conn, connectReply); err != nil {
		t.Fatalf("read the SOCKS5 CONNECT reply: %v", err)
	}
	if connectReply[1] != 0x00 {
		t.Fatalf("the proxy refused the connection with code 0x%02x", connectReply[1])
	}

	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write through the proxy: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read the echo back through the proxy: %v", err)
	}
	return string(got)
}
