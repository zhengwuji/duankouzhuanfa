// Package e2e exercises a complete relay path: a local client tunnel, a
// transport handshake against a real listening relay, and a real target
// server — all in one process but over real TCP sockets.
//
// The unit tests elsewhere prove each piece in isolation with net.Pipe. This
// package exists because a relay is only correct when the pieces are wired
// together: the transport has to agree with the relay's handshake, the relay's
// dial has to reach the target, and the client has to route the stream back.
// A defect that only appears at that seam is exactly the one that would ship.
//
// Each test imports the transports it needs directly rather than the aggregate
// package, so a single broken transport cannot make the whole suite
// uncompilable.
package e2e

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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
	_ "porttransit/internal/transports/shadowsocks"
	_ "porttransit/internal/transports/socks5"
	_ "porttransit/internal/transports/tls"
	_ "porttransit/internal/transports/trojan"
	_ "porttransit/internal/transports/vless"
	_ "porttransit/internal/transports/vmess"
	_ "porttransit/internal/transports/websocket"
)

// echoServer is a target that echoes everything it receives.
//
// An echo target is used rather than a file or an HTTP server because it
// proves the stream works in both directions and preserves bytes, which is
// what a relay is for.
type echoServer struct {
	ln     net.Listener
	mu     sync.Mutex
	conns  int
	closed bool
}

func startEcho(t *testing.T) *echoServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind the echo target: %v", err)
	}
	e := &echoServer{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			e.mu.Lock()
			e.conns++
			e.mu.Unlock()
			go func(c net.Conn) {
				defer c.Close()
				// A short deadline keeps a leaked connection from hanging the
				// test binary after it finishes.
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	t.Cleanup(func() {
		e.mu.Lock()
		e.closed = true
		e.mu.Unlock()
		ln.Close()
	})
	return e
}

func (e *echoServer) addr() string { return e.ln.Addr().String() }

func (e *echoServer) connections() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.conns
}

// randomPSK returns a fresh base64 pre-shared key.
func randomPSK(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generate a pre-shared key: %v", err)
	}
	return "base64:" + base64.StdEncoding.EncodeToString(b)
}

// harness is a running relay plus client pair.
type harness struct {
	relay   *server.Server
	client  *client.Client
	target  *echoServer
	tunnel  string // the local address the tunnel listens on
	relayAt string // the relay's bound address
}

// startHarness brings up a relay and a client connected to it.
//
// transport is the scheme both sides use; transportSettings are applied to the
// relay listener and the client's relay entry alike, so a test states a
// transport's parameters once.
func startHarness(t *testing.T, transport string, settings map[string]any, clientOverrides func(*config.ClientConfig)) *harness {
	t.Helper()

	target := startEcho(t)

	serverCfg := config.Default(config.ModeServer)
	serverCfg.WebUI.Enabled = false
	serverCfg.Log.Level = "error"
	serverCfg.Log.File = ""
	serverCfg.Server.DataDir = t.TempDir()
	// The echo target lives on the loopback interface, which the default
	// policy blocks. This is the one setting every test here has to change,
	// and TestRelayDeniesTargetOutsidePolicy exists to prove the block works.
	allowPrivate := false
	serverCfg.Server.ACL.BlockPrivate = &allowPrivate
	serverCfg.Server.Listeners = []config.Listener{{
		Name:      "test-relay",
		Transport: transport,
		Listen:    "127.0.0.1:0",
		Enabled:   true,
		Settings:  cloneSettings(settings),
	}}
	// The default certificate paths point at /etc, which a test must not
	// touch; a TLS listener generates a self-signed certificate into its data
	// directory when none is configured.
	serverCfg.Server.Forwards = nil

	relay, err := server.New(serverCfg.Server, logx.Discard())
	if err != nil {
		t.Fatalf("create the relay: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := relay.Start(ctx); err != nil {
		cancel()
		t.Fatalf("start the relay: %v", err)
	}

	// Wait for the listener to report its bound address, because the client
	// needs the real port and port zero means the kernel chose it.
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
		Name:      "test relay",
		Address:   relayAt,
		Transport: transport,
		Enabled:   true,
		Settings:  cloneSettings(settings),
	}}
	clientCfg.Client.Tunnels = []config.Tunnel{{
		Name:    "test-tunnel",
		Enabled: true,
		Listen:  "127.0.0.1:0",
		Target:  target.addr(),
		Server:  "relay-1",
	}}
	if clientOverrides != nil {
		clientOverrides(clientCfg.Client)
	}

	cli, err := client.New(clientCfg.Client, logx.Discard())
	if err != nil {
		cancel()
		relay.Stop()
		t.Fatalf("create the client: %v", err)
	}
	if err := cli.Start(ctx); err != nil {
		cancel()
		relay.Stop()
		t.Fatalf("start the client: %v", err)
	}

	tunnelAt := waitForTunnel(t, cli)

	h := &harness{relay: relay, client: cli, target: target, tunnel: tunnelAt, relayAt: relayAt}
	t.Cleanup(func() {
		cli.Stop()
		relay.Stop()
		cancel()
	})
	return h
}

func cloneSettings(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func waitForListener(t *testing.T, srv *server.Server) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, st := range srv.ListenerStatuses() {
			if st.Listening {
				return st.Listen
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the relay never bound its listener")
	return ""
}

func waitForTunnel(t *testing.T, c *client.Client) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, st := range c.TunnelStatuses() {
			if st.Listen != "" && !strings.HasSuffix(st.Listen, ":0") {
				return st.Listen
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the client never bound its tunnel")
	return ""
}

// roundTrip connects to the tunnel, sends payload, and returns what came back.
func (h *harness) roundTrip(t *testing.T, payload string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.tunnel, 10*time.Second)
	if err != nil {
		t.Fatalf("dial the tunnel at %s: %v", h.tunnel, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write to the tunnel: %v", err)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read the echo back: %v", err)
	}
	return string(got)
}

// TestRelayRoundTripDirect proves the simplest complete path works: a local
// tunnel forwards through a relay to a target and back.
func TestRelayRoundTripDirect(t *testing.T) {
	psk := randomPSK(t)
	h := startHarness(t, "direct", map[string]any{"psk": psk}, nil)

	const payload = "hello through the relay"
	if got := h.roundTrip(t, payload); got != payload {
		t.Fatalf("echoed %q, want %q", got, payload)
	}

	if h.target.connections() == 0 {
		t.Error("the target server was never contacted, so the relay did not dial it")
	}
}

// TestRelayRoundTripTLS proves the encrypted default path works end to end,
// including the relay's self-signed certificate and the client's decision to
// accept it.
func TestRelayRoundTripTLS(t *testing.T) {
	psk := randomPSK(t)
	// insecure is required because the relay generates a self-signed
	// certificate that no CA has signed. The pre-shared key is what
	// authenticates the peer; the certificate only provides confidentiality.
	h := startHarness(t, "tls", map[string]any{
		"psk":      psk,
		"insecure": true,
	}, nil)

	const payload = "encrypted end to end"
	if got := h.roundTrip(t, payload); got != payload {
		t.Fatalf("echoed %q, want %q", got, payload)
	}
}

// TestRelayRoundTripTrojan proves the trojan transport carries a stream, since
// its framing is the most unlike the others.
func TestRelayRoundTripTrojan(t *testing.T) {
	h := startHarness(t, "trojan", map[string]any{
		"password": "test-password",
		"insecure": true,
	}, nil)

	const payload = "trojan payload"
	if got := h.roundTrip(t, payload); got != payload {
		t.Fatalf("echoed %q, want %q", got, payload)
	}
}

// TestRelayRoundTripShadowsocks proves the Shadowsocks-2022 path works,
// including the salt exchange and the encrypted length framing.
func TestRelayRoundTripShadowsocks(t *testing.T) {
	// The 2022 methods derive the key from a base64 PSK of an exact length, so
	// the password must be a base64 key rather than a passphrase.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate the key: %v", err)
	}
	h := startHarness(t, "shadowsocks", map[string]any{
		"method":   "2022-blake3-chacha20-poly1305",
		"password": base64.StdEncoding.EncodeToString(key),
	}, nil)

	const payload = "shadowsocks payload"
	if got := h.roundTrip(t, payload); got != payload {
		t.Fatalf("echoed %q, want %q", got, payload)
	}
}

// TestRelayRoundTripVLESS proves the VLESS path works, including its
// non-SOCKS address type numbering.
func TestRelayRoundTripVLESS(t *testing.T) {
	h := startHarness(t, "vless", map[string]any{
		"uuid":     "b831381d-6324-4d53-ad4f-8cda48b30811",
		"insecure": true,
	}, nil)

	const payload = "vless payload"
	if got := h.roundTrip(t, payload); got != payload {
		t.Fatalf("echoed %q, want %q", got, payload)
	}
}

// TestRelayRoundTripVMess proves the VMess AEAD path works, including its
// response header that the client must consume before the payload.
func TestRelayRoundTripVMess(t *testing.T) {
	h := startHarness(t, "vmess", map[string]any{
		"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
	}, nil)

	const payload = "vmess payload"
	if got := h.roundTrip(t, payload); got != payload {
		t.Fatalf("echoed %q, want %q", got, payload)
	}
}

// TestRelayRoundTripWebSocket proves the WebSocket framing carries a stream.
func TestRelayRoundTripWebSocket(t *testing.T) {
	h := startHarness(t, "ws", map[string]any{
		"tls":      false,
		"psk":      randomPSK(t),
		"insecure": true,
	}, nil)

	const payload = "websocket payload"
	if got := h.roundTrip(t, payload); got != payload {
		t.Fatalf("echoed %q, want %q", got, payload)
	}
}

// TestWrongPSKIsRefused proves a client with the wrong key cannot reach the
// target, which is the property that makes the relay not an open proxy.
func TestWrongPSKIsRefused(t *testing.T) {
	good := randomPSK(t)
	bad := randomPSK(t)

	// The relay is configured with one key and the client with another, so the
	// handshake must fail and the tunnel must not carry data.
	h := startHarness(t, "direct", map[string]any{"psk": good}, func(cc *config.ClientConfig) {
		cc.Servers[0].Settings["psk"] = bad
	})

	conn, err := net.DialTimeout("tcp", h.tunnel, 10*time.Second)
	if err != nil {
		t.Fatalf("dial the tunnel: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// The write may succeed locally because the failure surfaces as a close
	// rather than an error; the read must not return the echoed payload.
	_, _ = conn.Write([]byte("should not arrive"))

	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		t.Fatalf("the relay echoed %q despite a wrong key", buf[:n])
	}

	if h.target.connections() != 0 {
		t.Error("the target was contacted despite a failed handshake")
	}
}

// TestMultipleConnectionsThroughOneTunnel proves the tunnel serves repeated
// connections, which is what a real browser or application does.
//
// A relay that only handles the first connection would pass a single-shot test
// and fail immediately in use.
func TestMultipleConnectionsThroughOneTunnel(t *testing.T) {
	h := startHarness(t, "direct", map[string]any{"psk": randomPSK(t)}, nil)

	for i := 0; i < 5; i++ {
		payload := fmt.Sprintf("message number %d", i)
		if got := h.roundTrip(t, payload); got != payload {
			t.Fatalf("connection %d echoed %q, want %q", i, got, payload)
		}
	}

	if n := h.target.connections(); n < 5 {
		t.Errorf("the target saw %d connections, want at least 5", n)
	}
}

// TestRelayStatsReportDialLatency proves the relay's average dial latency is
// actually computable. DialLatencyMs was accumulated on every successful dial
// while DialCount — the divisor Snapshot uses — was never incremented, so the
// console's "average dial" figure read as a permanent zero no matter how much
// traffic passed through.
func TestRelayStatsReportDialLatency(t *testing.T) {
	h := startHarness(t, "direct", map[string]any{"psk": randomPSK(t)}, nil)

	const payload = "measure the dial"
	if got := h.roundTrip(t, payload); got != payload {
		t.Fatalf("echoed %q, want %q", got, payload)
	}

	snap := h.relay.Stats().Snapshot()
	if snap.TotalConnections == 0 {
		t.Fatal("the relay recorded no connections, so the harness did not exercise it")
	}
	// The count is asserted rather than the average: a loopback dial can round
	// down to zero milliseconds, so a latency assertion here would be flaky
	// while proving nothing about the bug, which was the missing divisor.
	if snap.DialCount == 0 {
		t.Error("dialCount = 0 after a successful relayed connection, so avgDialMs can never be computed")
	}
}

// TestConcurrentConnectionsThroughOneTunnel proves the tunnel handles parallel
// connections without mixing their streams, which is the failure mode a
// shared-buffer bug produces.
func TestConcurrentConnectionsThroughOneTunnel(t *testing.T) {
	h := startHarness(t, "direct", map[string]any{"psk": randomPSK(t)}, nil)

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			// Each worker sends a distinct payload so a crossed stream is
			// detected rather than merely tolerated.
			payload := strings.Repeat(fmt.Sprintf("worker-%d-", n), 200)
			conn, err := net.DialTimeout("tcp", h.tunnel, 10*time.Second)
			if err != nil {
				errs <- fmt.Errorf("worker %d dial: %w", n, err)
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

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
}

// TestLargeTransferThroughTunnel proves a payload larger than one buffer
// crosses intact, which catches a framing or flush bug that a short message
// would hide.
func TestLargeTransferThroughTunnel(t *testing.T) {
	h := startHarness(t, "direct", map[string]any{"psk": randomPSK(t)}, nil)

	// 512 KiB is comfortably larger than the relay's default 32 KiB copy
	// buffer, so the copy loop must iterate many times.
	const size = 512 * 1024
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("generate the payload: %v", err)
	}

	conn, err := net.DialTimeout("tcp", h.tunnel, 10*time.Second)
	if err != nil {
		t.Fatalf("dial the tunnel: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	// The write and read must be concurrent: the echo target will not drain a
	// 512 KiB payload while the sender is still blocked writing it if the
	// relay's buffers fill.
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
}

// TestRelayDeniesTargetOutsidePolicy proves the relay's ACL is enforced on the
// real path, not just in the unit test: a client asking for a blocked
// destination must not reach it.
func TestRelayDeniesTargetOutsidePolicy(t *testing.T) {
	target := startEcho(t)

	serverCfg := config.Default(config.ModeServer)
	serverCfg.WebUI.Enabled = false
	serverCfg.Log.Level = "error"
	serverCfg.Log.File = ""
	serverCfg.Server.DataDir = t.TempDir()
	serverCfg.Server.Listeners = []config.Listener{{
		Name:      "test-relay",
		Transport: "direct",
		Listen:    "127.0.0.1:0",
		Enabled:   true,
		Settings:  map[string]any{"psk": randomPSK(t)},
	}}
	// The target lives on the loopback interface, which the default policy
	// blocks. Enabling the block explicitly makes the test's intent clear
	// rather than depending on the default.
	block := true
	serverCfg.Server.ACL.BlockPrivate = &block

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
		Settings:  serverCfg.Server.Listeners[0].Settings,
	}}
	clientCfg.Client.Tunnels = []config.Tunnel{{
		Name:    "blocked-tunnel",
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

	conn, err := net.DialTimeout("tcp", tunnelAt, 10*time.Second)
	if err != nil {
		t.Fatalf("dial the tunnel: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	_, _ = conn.Write([]byte("blocked"))

	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		t.Fatalf("the relay reached a blocked private target and echoed %q", buf[:n])
	}

	if target.connections() != 0 {
		t.Error("the blocked target was contacted, so the ACL was not enforced on the real path")
	}
}

// TestProxyServesSOCKS5 proves the local proxy carries a real SOCKS5
// conversation through the relay, which is the path a browser uses.
func TestProxyServesSOCKS5(t *testing.T) {
	target := startEcho(t)

	serverCfg := config.Default(config.ModeServer)
	serverCfg.WebUI.Enabled = false
	serverCfg.Log.Level = "error"
	serverCfg.Log.File = ""
	serverCfg.Server.DataDir = t.TempDir()
	// The echo target is on loopback, which the default policy blocks.
	allowPrivate := false
	serverCfg.Server.ACL.BlockPrivate = &allowPrivate
	serverCfg.Server.Listeners = []config.Listener{{
		Name:      "test-relay",
		Transport: "direct",
		Listen:    "127.0.0.1:0",
		Enabled:   true,
		Settings:  map[string]any{"psk": randomPSK(t)},
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
		Settings:  serverCfg.Server.Listeners[0].Settings,
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

	conn, err := net.DialTimeout("tcp", proxyAt, 10*time.Second)
	if err != nil {
		t.Fatalf("dial the proxy at %s: %v", proxyAt, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	// Greeting: version 5, one method, no authentication.
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

	// CONNECT to the target by IPv4 literal, which avoids a DNS dependency.
	host, portStr, err := net.SplitHostPort(target.addr())
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

	// The reply is ten bytes for an IPv4 bound address.
	connectReply := make([]byte, 10)
	if _, err := io.ReadFull(conn, connectReply); err != nil {
		t.Fatalf("read the SOCKS5 CONNECT reply: %v", err)
	}
	if connectReply[1] != 0x00 {
		t.Fatalf("the proxy refused the connection with code 0x%02x", connectReply[1])
	}

	const payload = "through the socks5 proxy"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write through the proxy: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read the echo back through the proxy: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("echoed %q, want %q", got, payload)
	}

	if target.connections() == 0 {
		t.Error("the target was never contacted through the proxy")
	}
}

func waitForProxy(t *testing.T, c *client.Client) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if st := c.ProxyStatus(); st.SOCKS5 != "" && !strings.HasSuffix(st.SOCKS5, ":0") {
			return st.SOCKS5
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the client never bound its SOCKS5 proxy")
	return ""
}

// TestUDPTunnelRoundTrip proves a UDP tunnel carries datagrams through the
// relay, since UDP has a completely separate framing path from TCP.
func TestUDPTunnelRoundTrip(t *testing.T) {
	runUDPTunnelRoundTrip(t, "socks5", map[string]any{})
}

// TestUDPTunnelRoundTripDirect proves the datagram path also works over a
// transport that carries the command in its own preamble rather than in a
// SOCKS5 request.
//
// This matters because it is easy to assume UDP is a SOCKS5-only feature: the
// relay's UDP handling is transport-independent, and only the SOCKS5 transport
// additionally needs a success reply. Testing a second transport is what keeps
// that assumption honest.
func TestUDPTunnelRoundTripDirect(t *testing.T) {
	runUDPTunnelRoundTrip(t, "direct", map[string]any{"psk": randomPSK(t)})
}

func runUDPTunnelRoundTrip(t *testing.T, transportName string, settings map[string]any) {
	t.Helper()

	// A UDP echo target.
	echoConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind the UDP echo target: %v", err)
	}
	defer echoConn.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echoConn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = echoConn.WriteTo(buf[:n], from)
		}
	}()

	serverCfg := config.Default(config.ModeServer)
	serverCfg.WebUI.Enabled = false
	serverCfg.Log.Level = "error"
	serverCfg.Log.File = ""
	serverCfg.Server.DataDir = t.TempDir()
	// The UDP echo target is on loopback, which the default policy blocks.
	allowPrivateUDP := false
	serverCfg.Server.ACL.BlockPrivate = &allowPrivateUDP
	serverCfg.Server.Listeners = []config.Listener{{
		Name:      "test-relay",
		Transport: transportName,
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

	// The client asks the relay for a UDP association, which every transport
	// expresses through the request command.
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
		Transport: transportName,
		Enabled:   true,
		Settings:  cloneSettings(settings),
	}}
	clientCfg.Client.Tunnels = []config.Tunnel{{
		Name:    "udp-tunnel",
		Enabled: true,
		Listen:  "127.0.0.1:0",
		Network: "udp",
		Target:  echoConn.LocalAddr().String(),
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

	conn, err := net.Dial("udp", tunnelAt)
	if err != nil {
		t.Fatalf("dial the UDP tunnel: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	const payload = "udp datagram"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write the datagram: %v", err)
	}

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read the datagram echo: %v", err)
	}
	if string(buf[:n]) != payload {
		t.Fatalf("echoed %q, want %q", buf[:n], payload)
	}
}
