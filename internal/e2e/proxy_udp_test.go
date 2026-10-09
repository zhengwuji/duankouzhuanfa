package e2e

import (
	"bytes"
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
	"porttransit/internal/transport"
)

// SOCKS5 UDP ASSOCIATE end to end.
//
// These tests exist because the datagram path is the one a browser uses for
// DNS and QUIC/HTTP3, and it is assembled from three separately-tested pieces:
// the local SOCKS5 header codec, the relay's UDP framing, and the routing
// decision. A defect at any seam leaves a browser silently falling back to TCP
// and the system resolver, which is exactly the leak the relay exists to
// prevent — and it looks like nothing more than a slow page load.

// udpEcho is a target that echoes every datagram it receives.
//
// A datagram echo is used rather than a DNS stub because it proves the payload
// crosses unmodified in both directions, and it keeps the test independent of
// any particular application protocol.
type udpEcho struct {
	pc net.PacketConn

	mu    sync.Mutex
	count int
}

func startUDPEcho(t *testing.T) *udpEcho {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind the UDP echo target: %v", err)
	}
	e := &udpEcho{pc: pc}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			e.mu.Lock()
			e.count++
			e.mu.Unlock()
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return e
}

func (e *udpEcho) addr() string { return e.pc.LocalAddr().String() }

func (e *udpEcho) received() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.count
}

// socks5Harness is a relay plus a client whose local SOCKS5 proxy is bound,
// which is the arrangement a browser actually sees.
type socks5Harness struct {
	proxyAt string
	echo    *udpEcho
	// cli is kept so a test can read the client's counters, which is the only
	// way to observe how many relay streams an association actually opened.
	cli *client.Client
}

// startSOCKSHarness brings up a relay and a client with the local SOCKS5 proxy
// enabled.
//
// overrides may replace the client configuration entirely, which the tests that
// only exercise the local decision path (routing rules, authentication) use to
// avoid depending on a working relay.
func startSOCKSHarness(t *testing.T, udp bool, overrides func(*config.Config)) *socks5Harness {
	t.Helper()

	echo := startUDPEcho(t)

	serverCfg := config.Default(config.ModeServer)
	serverCfg.WebUI.Enabled = false
	serverCfg.Log.Level = "error"
	serverCfg.Log.File = ""
	serverCfg.Server.DataDir = t.TempDir()
	// The echo target lives on loopback, which the default policy blocks.
	allowPrivate := false
	serverCfg.Server.ACL.BlockPrivate = &allowPrivate
	serverCfg.Server.Forwards = nil
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
	if err := relay.Start(ctx); err != nil {
		cancel()
		t.Fatalf("start the relay: %v", err)
	}
	relayAt := waitForListener(t, relay)

	clientCfg := config.Default(config.ModeClient)
	clientCfg.WebUI.Enabled = false
	clientCfg.Log.Level = "error"
	clientCfg.Log.File = ""
	clientCfg.Client.DataDir = t.TempDir()
	clientCfg.Client.Health.Enabled = false
	clientCfg.Client.Tunnels = nil
	clientCfg.Client.Servers = []config.ServerEntry{{
		ID:        "relay-1",
		Name:      "test relay",
		Address:   relayAt,
		Transport: "direct",
		Enabled:   true,
		Settings:  serverCfg.Server.Listeners[0].Settings,
	}}
	clientCfg.Client.Proxy = config.LocalProxyConfig{
		Enabled:      true,
		SOCKS5Listen: "127.0.0.1:0",
		UDP:          udp,
	}
	if overrides != nil {
		overrides(clientCfg)
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

	t.Cleanup(func() {
		cli.Stop()
		relay.Stop()
		cancel()
	})

	return &socks5Harness{proxyAt: waitForProxy(t, cli), echo: echo, cli: cli}
}

// socks5Handshake opens a control connection and completes the SOCKS5 greeting
// and, when credentials are given, the username/password exchange.
func socks5Handshake(t *testing.T, proxyAt, user, pass string) net.Conn {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAt, 10*time.Second)
	if err != nil {
		t.Fatalf("dial the proxy at %s: %v", proxyAt, err)
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	method := byte(0x00)
	if user != "" {
		method = 0x02
	}
	if _, err := conn.Write([]byte{0x05, 0x01, method}); err != nil {
		conn.Close()
		t.Fatalf("write the SOCKS5 greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		t.Fatalf("read the SOCKS5 method selection: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != method {
		conn.Close()
		t.Fatalf("the proxy selected %v, want version 5 with method 0x%02x", reply, method)
	}

	if method == 0x02 {
		auth := []byte{0x01, byte(len(user))}
		auth = append(auth, user...)
		auth = append(auth, byte(len(pass)))
		auth = append(auth, pass...)
		if _, err := conn.Write(auth); err != nil {
			conn.Close()
			t.Fatalf("write the SOCKS5 credentials: %v", err)
		}
		if _, err := io.ReadFull(conn, reply); err != nil {
			conn.Close()
			t.Fatalf("read the SOCKS5 auth reply: %v", err)
		}
		if reply[1] != 0x00 {
			conn.Close()
			t.Fatalf("the proxy rejected the credentials with status 0x%02x", reply[1])
		}
	}
	return conn
}

// readSocksReply reads one SOCKS5 reply and returns its code and bound address.
func readSocksReply(t *testing.T, conn net.Conn) (byte, string) {
	t.Helper()

	var head [3]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		t.Fatalf("read the SOCKS5 reply header: %v", err)
	}
	if head[0] != 0x05 {
		t.Fatalf("the SOCKS5 reply has version 0x%02x, want 0x05", head[0])
	}
	bound, err := transport.DecodeAddr(conn)
	if err != nil {
		t.Fatalf("read the SOCKS5 reply address: %v", err)
	}
	return head[1], bound
}

// udpAssociate sends UDP ASSOCIATE on an established control connection and
// returns the datagram address the client should use.
func udpAssociate(t *testing.T, ctrl net.Conn) string {
	t.Helper()

	// DST.ADDR 0.0.0.0:0 is what a browser sends: the address it will send from
	// is not known yet and RFC 1928 requires the proxy to ignore it.
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := ctrl.Write(req); err != nil {
		t.Fatalf("write the UDP ASSOCIATE request: %v", err)
	}
	code, bound := readSocksReply(t, ctrl)
	if code != 0x00 {
		t.Fatalf("the proxy refused UDP ASSOCIATE with code 0x%02x", code)
	}
	if bound == "" || strings.HasSuffix(bound, ":0") {
		t.Fatalf("the proxy replied with an unusable datagram address %q", bound)
	}
	return bound
}

// udpDatagram builds a SOCKS5 UDP request for dest.
func udpDatagram(t *testing.T, dest string, frag byte, payload []byte) []byte {
	t.Helper()

	pkt := []byte{0x00, 0x00, frag}
	var err error
	pkt, err = transport.EncodeAddr(pkt, dest)
	if err != nil {
		t.Fatalf("encode the destination %q: %v", dest, err)
	}
	return append(pkt, payload...)
}

// parseUDPReply splits a SOCKS5 UDP reply into its destination and payload.
func parseUDPReply(t *testing.T, pkt []byte) (string, []byte) {
	t.Helper()

	if len(pkt) < 4 {
		t.Fatalf("the reply is %d bytes, too short to hold a header", len(pkt))
	}
	if pkt[0] != 0 || pkt[1] != 0 || pkt[2] != 0 {
		t.Fatalf("the reply header is % x, want a zeroed RSV and FRAG", pkt[:3])
	}
	dest, n, err := transport.DecodeAddrFrom(pkt[3:])
	if err != nil {
		t.Fatalf("decode the reply destination: %v", err)
	}
	return dest, pkt[3+n:]
}

// TestProxyUDPAssociateRoundTrip is the whole point of this work: a real SOCKS5
// UDP ASSOCIATE through a real relay to a real UDP target and back.
//
// Nothing shorter proves it. A unit test of the header codec would pass while
// the relay's framing was wrong, and a test that only checked the association
// reply would pass while every datagram was silently dropped.
func TestProxyUDPAssociateRoundTrip(t *testing.T) {
	h := startSOCKSHarness(t, true, nil)

	ctrl := socks5Handshake(t, h.proxyAt, "", "")
	defer ctrl.Close()

	bound := udpAssociate(t, ctrl)

	conn, err := net.Dial("udp", bound)
	if err != nil {
		t.Fatalf("dial the datagram relay at %s: %v", bound, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	const payload = "a dns question through the relay"
	if _, err := conn.Write(udpDatagram(t, h.echo.addr(), 0, []byte(payload))); err != nil {
		t.Fatalf("send the datagram: %v", err)
	}

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read the datagram reply: %v", err)
	}
	dest, got := parseUDPReply(t, buf[:n])
	if dest != h.echo.addr() {
		t.Errorf("the reply names %q, want the requested destination %q", dest, h.echo.addr())
	}
	if string(got) != payload {
		t.Fatalf("echoed %q, want %q", got, payload)
	}

	if h.echo.received() == 0 {
		t.Error("the UDP target was never contacted, so the relay did not forward the datagram")
	}
}

// TestProxyUDPAssociateReusesOneFlowPerDestination proves a burst to one
// destination shares a single relay stream.
//
// This is not an optimisation detail: a per-datagram handshake would add a full
// round trip to every DNS query and to every QUIC packet, which is what makes a
// naive implementation unusable. The client's own successful-dial counter is
// the observable — it increments once per relay stream opened — so the
// assertion is that twelve datagrams cost exactly one dial, not twelve.
func TestProxyUDPAssociateReusesOneFlowPerDestination(t *testing.T) {
	h := startSOCKSHarness(t, true, nil)

	ctrl := socks5Handshake(t, h.proxyAt, "", "")
	defer ctrl.Close()
	bound := udpAssociate(t, ctrl)

	conn, err := net.Dial("udp", bound)
	if err != nil {
		t.Fatalf("dial the datagram relay: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	before := h.cli.Stats().Snapshot().SuccessfulDials

	const rounds = 12
	buf := make([]byte, 2048)
	for i := 0; i < rounds; i++ {
		payload := fmt.Sprintf("query-%02d", i)
		if _, err := conn.Write(udpDatagram(t, h.echo.addr(), 0, []byte(payload))); err != nil {
			t.Fatalf("round %d: send: %v", i, err)
		}
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("round %d: read: %v", i, err)
		}
		if _, got := parseUDPReply(t, buf[:n]); string(got) != payload {
			t.Fatalf("round %d: echoed %q, want %q", i, got, payload)
		}
	}

	if n := h.echo.received(); n < rounds {
		t.Errorf("the target saw %d datagrams, want at least %d", n, rounds)
	}

	dials := h.cli.Stats().Snapshot().SuccessfulDials - before
	if dials != 1 {
		t.Errorf("%d datagrams to one destination opened %d relay streams, want exactly 1", rounds, dials)
	}
}

// TestProxyUDPAssociateDropsFragments proves a datagram with FRAG != 0 is
// dropped rather than reassembled.
//
// Reassembly is optional in RFC 1928 and is a memory-exhaustion vector: it
// means holding attacker-supplied partial datagrams per association until a
// timeout. The observable contract is that nothing comes back.
func TestProxyUDPAssociateDropsFragments(t *testing.T) {
	h := startSOCKSHarness(t, true, nil)

	ctrl := socks5Handshake(t, h.proxyAt, "", "")
	defer ctrl.Close()
	bound := udpAssociate(t, ctrl)

	conn, err := net.Dial("udp", bound)
	if err != nil {
		t.Fatalf("dial the datagram relay: %v", err)
	}
	defer conn.Close()

	for _, frag := range []byte{0x01, 0x02, 0xff} {
		if _, err := conn.Write(udpDatagram(t, h.echo.addr(), frag, []byte("fragment"))); err != nil {
			t.Fatalf("FRAG=0x%02x: send: %v", frag, err)
		}
	}

	// A fragment must produce no reply. The deadline is short because the
	// datagram is dropped, never queued.
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("a fragmented datagram was answered with % x", buf[:n])
	}

	if n := h.echo.received(); n != 0 {
		t.Errorf("the target saw %d datagrams, want none: fragments must not be relayed", n)
	}
}

// TestProxyUDPAssociateDropsBlockedDestination proves the client's block list is
// enforced on the datagram path, not only on TCP.
//
// A block list that only covers TCP is worse than none: it looks like a policy
// while a browser reaches the same destination over QUIC.
func TestProxyUDPAssociateDropsBlockedDestination(t *testing.T) {
	h := startSOCKSHarness(t, true, func(cfg *config.Config) {
		// The UDP echo target is always bound on 127.0.0.1, so blocking the
		// loopback host is a deterministic way to block exactly it.
		cfg.Client.Proxy.BlockRules = []string{"127.0.0.1"}
	})

	ctrl := socks5Handshake(t, h.proxyAt, "", "")
	defer ctrl.Close()
	bound := udpAssociate(t, ctrl)

	conn, err := net.Dial("udp", bound)
	if err != nil {
		t.Fatalf("dial the datagram relay: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(udpDatagram(t, h.echo.addr(), 0, []byte("blocked"))); err != nil {
		t.Fatalf("send the datagram: %v", err)
	}

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("a blocked destination answered with % x", buf[:n])
	}
	if n := h.echo.received(); n != 0 {
		t.Errorf("the blocked target saw %d datagrams, want none", n)
	}
}

// TestProxyUDPAssociateHonoursDirectRules proves a direct-listed destination is
// dialed without the relay.
//
// The relay address is deliberately unreachable, so a datagram that came back
// could only have travelled directly. Without this the direct route could be
// silently ignored and every test would still pass.
func TestProxyUDPAssociateHonoursDirectRules(t *testing.T) {
	echo := startUDPEcho(t)

	clientCfg := config.Default(config.ModeClient)
	clientCfg.WebUI.Enabled = false
	clientCfg.Log.Level = "error"
	clientCfg.Log.File = ""
	clientCfg.Client.DataDir = t.TempDir()
	clientCfg.Client.Health.Enabled = false
	clientCfg.Client.Tunnels = nil
	clientCfg.Client.Servers = []config.ServerEntry{{
		ID: "dead-relay",
		// Nothing listens here: any attempt to reach the relay fails, so a
		// successful round trip proves the direct path was taken.
		Address:   "127.0.0.1:1",
		Transport: "direct",
		Enabled:   true,
		Settings:  map[string]any{"psk": randomPSK(t)},
	}}
	clientCfg.Client.Proxy = config.LocalProxyConfig{
		Enabled:      true,
		SOCKS5Listen: "127.0.0.1:0",
		UDP:          true,
		DirectRules:  []string{echo.addr()},
	}

	cli, err := client.New(clientCfg.Client, logx.Discard())
	if err != nil {
		t.Fatalf("create the client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := cli.Start(ctx); err != nil {
		t.Fatalf("start the client: %v", err)
	}
	defer cli.Stop()

	proxyAt := waitForProxy(t, cli)

	ctrl := socks5Handshake(t, proxyAt, "", "")
	defer ctrl.Close()
	bound := udpAssociate(t, ctrl)

	conn, err := net.Dial("udp", bound)
	if err != nil {
		t.Fatalf("dial the datagram relay: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	const payload = "direct datagram"
	if _, err := conn.Write(udpDatagram(t, echo.addr(), 0, []byte(payload))); err != nil {
		t.Fatalf("send the datagram: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read the direct reply (the relay is unreachable, so this proves the direct route was not taken): %v", err)
	}
	_, got := parseUDPReply(t, buf[:n])
	if string(got) != payload {
		t.Fatalf("echoed %q, want %q", got, payload)
	}
}

// TestProxyUDPAssociateRequiresAuthentication proves the datagram path is
// gated by the same credentials as CONNECT.
//
// A UDP association that skipped the username/password exchange would be a hole
// wide enough to make the local proxy's authentication worthless: any local
// process could relay through the tunnel by opening a datagram socket.
func TestProxyUDPAssociateRequiresAuthentication(t *testing.T) {
	const user, pass = "alice", "hunter2"
	withAuth := func(cfg *config.Config) {
		cfg.Client.Proxy.Username = user
		// A value without the bcrypt prefix is compared in constant time as
		// plaintext, which is the form the local proxy uses by default.
		cfg.Client.Proxy.PasswordHash = pass
	}

	t.Run("correct credentials reach the relay", func(t *testing.T) {
		h := startSOCKSHarness(t, true, withAuth)

		ctrl := socks5Handshake(t, h.proxyAt, user, pass)
		defer ctrl.Close()
		bound := udpAssociate(t, ctrl)

		conn, err := net.Dial("udp", bound)
		if err != nil {
			t.Fatalf("dial the datagram relay: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

		const payload = "authenticated datagram"
		if _, err := conn.Write(udpDatagram(t, h.echo.addr(), 0, []byte(payload))); err != nil {
			t.Fatalf("send the datagram: %v", err)
		}
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read the datagram reply: %v", err)
		}
		if _, got := parseUDPReply(t, buf[:n]); string(got) != payload {
			t.Fatalf("echoed %q, want %q", got, payload)
		}
	})

	t.Run("no credentials cannot associate", func(t *testing.T) {
		h := startSOCKSHarness(t, true, withAuth)

		conn, err := net.DialTimeout("tcp", h.proxyAt, 10*time.Second)
		if err != nil {
			t.Fatalf("dial the proxy: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		// Offering only "no authentication" against a proxy that requires a
		// credential must be refused at the greeting, before any request.
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			t.Fatalf("write the greeting: %v", err)
		}
		reply := make([]byte, 2)
		if _, err := io.ReadFull(conn, reply); err != nil {
			t.Fatalf("read the method selection: %v", err)
		}
		if reply[0] != 0x05 || reply[1] != 0xFF {
			t.Fatalf("the proxy selected %v, want 0xFF (no acceptable method)", reply)
		}
	})
}

// TestProxyUDPAssociateRefusedWhenDisabled pins the configuration gate.
//
// This deliberately replaces the older behaviour, where *every* UDP ASSOCIATE
// was answered with 0x07 because the command was unimplemented. Now 0x07 means
// only "the operator has not enabled the datagram path", which is a different
// statement — and a browser that receives it correctly concludes that it must
// use CONNECT.
func TestProxyUDPAssociateRefusedWhenDisabled(t *testing.T) {
	h := startSOCKSHarness(t, false, nil)

	ctrl := socks5Handshake(t, h.proxyAt, "", "")
	defer ctrl.Close()

	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := ctrl.Write(req); err != nil {
		t.Fatalf("write the UDP ASSOCIATE request: %v", err)
	}
	code, _ := readSocksReply(t, ctrl)
	if code != 0x07 {
		t.Fatalf("the proxy replied 0x%02x with udp disabled, want 0x07 (command not supported)", code)
	}
}

// TestProxyUDPAssociateReleasesOnControlClose proves the control connection
// defines the association's lifetime, as RFC 1928 requires.
//
// A relay socket that outlived its control connection would leak a descriptor
// per browser restart, and would keep accepting datagrams from a client that
// believes it has finished.
func TestProxyUDPAssociateReleasesOnControlClose(t *testing.T) {
	h := startSOCKSHarness(t, true, nil)

	ctrl := socks5Handshake(t, h.proxyAt, "", "")
	bound := udpAssociate(t, ctrl)

	conn, err := net.Dial("udp", bound)
	if err != nil {
		t.Fatalf("dial the datagram relay: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	// Prove the association works before tearing the control connection down,
	// so a failure below cannot be blamed on the setup.
	if _, err := conn.Write(udpDatagram(t, h.echo.addr(), 0, []byte("before"))); err != nil {
		t.Fatalf("send before closing the control connection: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read before closing the control connection: %v", err)
	}
	if _, got := parseUDPReply(t, buf[:n]); !bytes.Equal(got, []byte("before")) {
		t.Fatalf("echoed %q, want %q", got, "before")
	}

	if err := ctrl.Close(); err != nil {
		t.Fatalf("close the control connection: %v", err)
	}

	// The relay socket is closed asynchronously, so the assertion is polled:
	// either the datagram is refused outright or it is simply never answered.
	// What must never happen is another echo.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := conn.Write(udpDatagram(t, h.echo.addr(), 0, []byte("after"))); err != nil {
			return
		}
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if _, got := parseUDPReply(t, buf[:n]); bytes.Equal(got, []byte("after")) {
			t.Fatal("the association answered after its control connection was closed")
		}
	}
	t.Fatal("the association never stopped answering after its control connection was closed")
}

// TestProxyUDPAssociateBindsLoopbackOnly proves the datagram relay is never
// reachable from outside the machine.
//
// The relay socket carries no authentication of its own — a SOCKS5 datagram has
// nowhere to put a credential — so its only defence is that it is bound on a
// loopback address. Binding the control connection's own local address instead
// would hand back a LAN address whenever the proxy listens on 0.0.0.0, turning
// the client into an open UDP relay for the whole network.
//
// The per-datagram source check (that only the control connection's peer may
// use the association) is covered by TestSameIPBindsToTheControlPeer in the
// client package. It cannot be exercised here: this platform delivers loopback
// datagrams only from 127.0.0.1 to 127.0.0.1, so a genuinely foreign source
// address cannot be produced.
func TestProxyUDPAssociateBindsLoopbackOnly(t *testing.T) {
	h := startSOCKSHarness(t, true, nil)

	ctrl := socks5Handshake(t, h.proxyAt, "", "")
	defer ctrl.Close()
	bound := udpAssociate(t, ctrl)

	host, port, err := net.SplitHostPort(bound)
	if err != nil {
		t.Fatalf("split the bound address %q: %v", bound, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("the relay bound %q, which is not an IP literal", bound)
	}
	if !ip.IsLoopback() {
		t.Fatalf("the relay bound %q, which is not a loopback address", bound)
	}
	if port == "0" {
		t.Fatalf("the relay bound %q, which names no port", bound)
	}

	// The association must not share the TCP port: the client sends datagrams
	// to this address, and sharing it would mix them into the control stream.
	if _, tcpPort, _ := net.SplitHostPort(h.proxyAt); port == tcpPort {
		t.Fatalf("the relay bound %q, which reuses the SOCKS5 TCP port", bound)
	}
}

// TestProxyUDPAssociateRejectsMalformedDatagrams proves a hostile datagram
// cannot panic the read loop or be relayed.
//
// The parser is the only code that sees attacker-controlled bytes on this path,
// so a malformed datagram must be a dropped datagram and nothing more.
func TestProxyUDPAssociateRejectsMalformedDatagrams(t *testing.T) {
	h := startSOCKSHarness(t, true, nil)

	ctrl := socks5Handshake(t, h.proxyAt, "", "")
	defer ctrl.Close()
	bound := udpAssociate(t, ctrl)

	conn, err := net.Dial("udp", bound)
	if err != nil {
		t.Fatalf("dial the datagram relay: %v", err)
	}
	defer conn.Close()

	malformed := [][]byte{
		nil,
		{0x00},
		{0x00, 0x00, 0x00},
		// RSV must be zero.
		{0x01, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0, 53, 'x'},
		// An unknown address type.
		{0x00, 0x00, 0x00, 0x09, 1, 2, 3, 4, 0, 53, 'x'},
		// A truncated IPv4 address.
		{0x00, 0x00, 0x00, 0x01, 1, 2, 3},
		// A zero-length domain.
		{0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x35, 'x'},
		// A domain longer than the datagram.
		{0x00, 0x00, 0x00, 0x03, 0x0a, 'a', 'b'},
		// A valid header with no payload: the relay's framing reserves a
		// zero-length frame for end-of-stream, so this must not be forwarded.
		{0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0, 53},
	}
	for _, pkt := range malformed {
		if _, err := conn.Write(pkt); err != nil {
			t.Fatalf("send % x: %v", pkt, err)
		}
	}

	// The association must still be alive and usable afterwards: a malformed
	// datagram must not have killed the read loop.
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	const payload = "still alive"
	if _, err := conn.Write(udpDatagram(t, h.echo.addr(), 0, []byte(payload))); err != nil {
		t.Fatalf("send the follow-up datagram: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("the association did not survive malformed datagrams: %v", err)
	}
	if _, got := parseUDPReply(t, buf[:n]); string(got) != payload {
		t.Fatalf("echoed %q, want %q", got, payload)
	}
}

// TestProxyUDPAssociateLargeDatagram proves a datagram near the protocol's
// maximum crosses intact.
//
// The framing uses a two-byte length prefix, so a payload that does not fit in
// one read would be silently truncated rather than reported — the kind of bug
// that only shows up with real QUIC traffic.
func TestProxyUDPAssociateLargeDatagram(t *testing.T) {
	h := startSOCKSHarness(t, true, nil)

	ctrl := socks5Handshake(t, h.proxyAt, "", "")
	defer ctrl.Close()
	bound := udpAssociate(t, ctrl)

	conn, err := net.Dial("udp", bound)
	if err != nil {
		t.Fatalf("dial the datagram relay: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	// 1400 bytes is the practical QUIC payload, and it is larger than a single
	// loopback MTU, so it exercises the reassembly the kernel does on the way
	// in and the framing on the way out.
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if _, err := conn.Write(udpDatagram(t, h.echo.addr(), 0, payload)); err != nil {
		t.Fatalf("send the large datagram: %v", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read the large datagram reply: %v", err)
	}
	_, got := parseUDPReply(t, buf[:n])
	if !bytes.Equal(got, payload) {
		t.Fatalf("the payload came back as %d bytes, want %d", len(got), len(payload))
	}
}

// TestProxyUDPAssociateReplyHeaderNamesTheRequestedDestination pins the reply
// header, because a client matches an answer against the query it sent.
//
// A reply naming the address the answer arrived from would break any client
// that resolved a name: the source address of a DNS answer is not the name that
// was queried.
func TestProxyUDPAssociateReplyHeaderNamesTheRequestedDestination(t *testing.T) {
	h := startSOCKSHarness(t, true, nil)

	ctrl := socks5Handshake(t, h.proxyAt, "", "")
	defer ctrl.Close()
	bound := udpAssociate(t, ctrl)

	conn, err := net.Dial("udp", bound)
	if err != nil {
		t.Fatalf("dial the datagram relay: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	// A domain destination: the relay resolves it, and the reply must still
	// carry the name rather than the resolved address.
	_, port, err := net.SplitHostPort(h.echo.addr())
	if err != nil {
		t.Fatalf("split the echo address: %v", err)
	}
	dest := net.JoinHostPort("localhost", port)

	if _, err := conn.Write(udpDatagram(t, dest, 0, []byte("named"))); err != nil {
		t.Fatalf("send the datagram: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read the reply: %v", err)
	}
	gotDest, got := parseUDPReply(t, buf[:n])
	if gotDest != dest {
		t.Fatalf("the reply names %q, want the requested destination %q", gotDest, dest)
	}
	if !bytes.Equal(got, []byte("named")) {
		t.Fatalf("echoed %q, want %q", got, "named")
	}

	// The reply must be encoded as a domain, not as the address the relay
	// resolved: a client that asked for a name cannot match an address answer.
	if buf[3] != transport.AddrTypeDomain {
		t.Errorf("the reply address type is 0x%02x, want 0x%02x (domain)", buf[3], transport.AddrTypeDomain)
	}
}
