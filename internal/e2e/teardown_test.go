package e2e

import (
	"context"
	"net"
	"testing"
	"time"

	"porttransit/internal/client"
	"porttransit/internal/config"
	"porttransit/internal/logx"
	"porttransit/internal/server"

	_ "porttransit/internal/transports/direct"
)

// TestTunnelTeardownIsPrompt measures how long it takes for the relay and the
// client to shut down after a single short-lived connection has been closed.
//
// This is a resource question rather than a correctness one: a relay that
// holds a goroutine and a file descriptor for the full idle timeout after the
// peer has gone would accumulate state on a busy relay, and it would also make
// every restart take minutes.
func TestTunnelTeardownIsPrompt(t *testing.T) {
	target := startEcho(t)

	serverCfg := config.Default(config.ModeServer)
	serverCfg.WebUI.Enabled = false
	serverCfg.Log.Level = "error"
	serverCfg.Log.File = ""
	serverCfg.Server.DataDir = t.TempDir()
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
		Name:    "teardown-tunnel",
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
	tunnelAt := waitForTunnel(t, cli)

	// One short-lived connection, closed by the application.
	conn, err := net.DialTimeout("tcp", tunnelAt, 5*time.Second)
	if err != nil {
		t.Fatalf("dial the tunnel: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = conn.Close()

	// The relay should notice the closed tunnel quickly. Poll its active
	// connection counter rather than guessing at a fixed delay.
	deadline := time.Now().Add(25 * time.Second)
	var lastActive int64 = -1
	for time.Now().Before(deadline) {
		snap := relay.Stats().Snapshot()
		if snap.ActiveConnections == 0 && snap.ActiveForwards == 0 {
			t.Logf("relay released the connection after %v", time.Since(deadline.Add(-25*time.Second)))
			break
		}
		lastActive = snap.ActiveConnections
		time.Sleep(50 * time.Millisecond)
	}
	if lastActive != -1 {
		snap := relay.Stats().Snapshot()
		if snap.ActiveConnections != 0 || snap.ActiveForwards != 0 {
			t.Errorf("the relay still holds active=%d forwards=%d 25s after the client closed",
				snap.ActiveConnections, snap.ActiveForwards)
		}
	}

	stopStart := time.Now()
	cli.Stop()
	clientStop := time.Since(stopStart)

	stopStart = time.Now()
	relay.Stop()
	relayStop := time.Since(stopStart)

	t.Logf("client stop took %v, relay stop took %v", clientStop, relayStop)

	// A stop that takes seconds means goroutines are parked on long deadlines.
	// One second is generous for an idle process.
	if clientStop > 3*time.Second {
		t.Errorf("client shutdown took %v, which means a goroutine is parked on a long deadline", clientStop)
	}
	if relayStop > 3*time.Second {
		t.Errorf("relay shutdown took %v, which means a goroutine is parked on a long deadline", relayStop)
	}
}
