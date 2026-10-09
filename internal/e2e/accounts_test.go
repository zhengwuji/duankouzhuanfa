package e2e

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"porttransit/internal/client"
	"porttransit/internal/config"
	"porttransit/internal/logx"
	"porttransit/internal/server"

	_ "porttransit/internal/transports/direct"
	_ "porttransit/internal/transports/trojan"
	_ "porttransit/internal/transports/vmess"
)

// accountHarness is a relay with client accounts configured, plus a client that
// presents a chosen id. It exists because account enforcement is decided in the
// relay's serving path from the client id carried inside the transport's
// request frame — a wiring that unit tests of the account table cannot prove.
type accountHarness struct {
	relay   *server.Server
	client  *client.Client
	target  *echoServer
	tunnel  string
	relayAt string
}

// startAccountHarness brings up a relay that requires client accounts.
//
// clientID is what the client presents; empty means it presents nothing.
func startAccountHarness(t *testing.T, accounts []config.ClientAccount, clientID string) *accountHarness {
	t.Helper()
	return startAccountHarnessIn(t, t.TempDir(), accounts, clientID)
}

// startAccountHarnessIn is startAccountHarness with an explicit data directory,
// so a test can pre-seed the persisted usage file that the relay reads at
// startup.
func startAccountHarnessIn(t *testing.T, dataDir string, accounts []config.ClientAccount, clientID string) *accountHarness {
	t.Helper()
	return startAccountHarnessTransport(t, dataDir, accounts, clientID, "direct",
		map[string]any{"psk": "acct-key"})
}

// startAccountHarnessTransport brings up the harness on a chosen transport, so
// the difference between a preamble transport and a native-header one can be
// exercised against a real relay rather than only in a unit test.
func startAccountHarnessTransport(t *testing.T, dataDir string, accounts []config.ClientAccount, clientID, transportName string, settings map[string]any) *accountHarness {
	t.Helper()

	target := startEcho(t)

	serverCfg := config.Default(config.ModeServer)
	serverCfg.WebUI.Enabled = false
	serverCfg.Log.Level = "error"
	serverCfg.Log.File = ""
	serverCfg.Server.DataDir = dataDir
	allowPrivate := false
	serverCfg.Server.ACL.BlockPrivate = &allowPrivate
	serverCfg.Server.Clients = accounts
	serverCfg.Server.Forwards = nil
	serverCfg.Server.Listeners = []config.Listener{{
		Name:      "acct-relay",
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
	clientCfg.Client.Proxy.Enabled = false
	clientCfg.Client.Servers = []config.ServerEntry{{
		ID:        "relay-1",
		Name:      "acct relay",
		Address:   relayAt,
		Transport: transportName,
		Enabled:   true,
		ClientID:  clientID,
		Settings:  cloneSettings(settings),
	}}
	clientCfg.Client.Tunnels = []config.Tunnel{{
		Name:    "acct-tunnel",
		Enabled: true,
		Listen:  "127.0.0.1:0",
		Target:  target.addr(),
		Server:  "relay-1",
	}}

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

	h := &accountHarness{relay: relay, client: cli, target: target, tunnel: tunnelAt, relayAt: relayAt}
	t.Cleanup(func() {
		cli.Stop()
		relay.Stop()
		cancel()
	})
	return h
}

// attempt opens the tunnel and reports whether the payload came back.
//
// It returns an error rather than calling t.Fatal because a refusal is the
// expected outcome in most of these tests, and the assertion belongs to the
// caller.
func (h *accountHarness) attempt(payload string) error {
	conn, err := net.DialTimeout("tcp", h.tunnel, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte(payload)); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := readFull(conn, got); err != nil {
		return err
	}
	if string(got) != payload {
		return &mismatchError{got: string(got), want: payload}
	}
	return nil
}

type mismatchError struct{ got, want string }

func (e *mismatchError) Error() string {
	return "echoed " + e.got + ", want " + e.want
}

// readFull is io.ReadFull, kept local so this file's imports stay obvious.
func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func enabledAcct(id string) config.ClientAccount {
	return config.ClientAccount{
		ID:          id,
		Name:        id,
		Enabled:     true,
		Credentials: map[string]string{"direct": "acct-key"},
	}
}

// writeQuotaFile seeds the relay's persisted usage file.
//
// It writes the documented on-disk shape directly rather than exporting a
// helper from the server package, because the file format is the interface the
// relay promises to read back and a test that used the writer would not notice
// the reader drifting from it.
func writeQuotaFile(dataDir, clientID string, used int64) error {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return err
	}
	body := fmt.Sprintf(
		`{"version":1,"saved":"2024-01-01T00:00:00Z","used":{%q:%d}}`,
		clientID, used)
	return os.WriteFile(filepath.Join(dataDir, "quota.json"), []byte(body), 0o600)
}

// The baseline: with no accounts configured, a client that presents no id must
// still work. Every existing deployment looks like this, so this test is what
// keeps the accounts feature from breaking them.
func TestRelayWithoutAccountsServesAnonymousClients(t *testing.T) {
	h := startAccountHarness(t, nil, "")
	if err := h.attempt("anonymous"); err != nil {
		t.Fatalf("a relay with no accounts refused a client: %v", err)
	}
}

// With accounts configured, a listed and enabled client works.
func TestRelayServesAConfiguredClient(t *testing.T) {
	h := startAccountHarness(t, []config.ClientAccount{enabledAcct("alice")}, "alice")
	if err := h.attempt("alice payload"); err != nil {
		t.Fatalf("a configured client was refused: %v", err)
	}
}

// A client id the relay does not know must be refused. Without this, per-client
// policy is bypassed by simply claiming a different id.
func TestRelayRefusesAnUnknownClientID(t *testing.T) {
	h := startAccountHarness(t, []config.ClientAccount{enabledAcct("alice")}, "mallory")
	if err := h.attempt("mallory payload"); err == nil {
		t.Fatal("a client with an unknown id was served")
	}
}

// A client that presents nothing must be refused once accounts exist.
func TestRelayRefusesAClientWithNoID(t *testing.T) {
	h := startAccountHarness(t, []config.ClientAccount{enabledAcct("alice")}, "")
	if err := h.attempt("anonymous payload"); err == nil {
		t.Fatal("a client that presented no id was served")
	}
}

// A disabled account must stop working without being deleted.
func TestRelayRefusesADisabledClient(t *testing.T) {
	disabled := enabledAcct("alice")
	disabled.Enabled = false
	h := startAccountHarness(t, []config.ClientAccount{disabled}, "alice")
	if err := h.attempt("disabled payload"); err == nil {
		t.Fatal("a disabled account was served")
	}
}

// An expired account must stop working.
func TestRelayRefusesAnExpiredClient(t *testing.T) {
	expired := enabledAcct("alice")
	expired.ExpiresAt = time.Now().Add(-time.Hour)
	h := startAccountHarness(t, []config.ClientAccount{expired}, "alice")
	if err := h.attempt("expired payload"); err == nil {
		t.Fatal("an expired account was served")
	}
}

// The refusal must be recorded, otherwise an operator diagnosing "my client
// stopped working" has nothing to look at.
func TestRefusedAccountIsCounted(t *testing.T) {
	h := startAccountHarness(t, []config.ClientAccount{enabledAcct("alice")}, "mallory")

	before := h.relay.Stats().Snapshot().ACLDenied
	if err := h.attempt("mallory payload"); err == nil {
		t.Fatal("an unknown client was served")
	}
	// The relay serves each connection in its own goroutine, so the counter
	// may lag the client's failure by a moment.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.relay.Stats().Snapshot().ACLDenied > before {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the refusal was not counted in the relay's statistics")
}

// The console needs to see per-account usage, and a served stream must show up
// against the right account.
func TestAccountUsageIsVisibleAndCountsTraffic(t *testing.T) {
	h := startAccountHarness(t, []config.ClientAccount{enabledAcct("alice")}, "alice")

	usage := h.relay.AccountUsage()
	if len(usage) != 1 {
		t.Fatalf("usage has %d entries, want 1", len(usage))
	}
	if usage[0].ID != "alice" {
		t.Fatalf("usage is for %q, want alice", usage[0].ID)
	}
	if !usage[0].Enabled {
		t.Error("an enabled account is reported as disabled")
	}

	payload := "traffic that must be counted"
	if err := h.attempt(payload); err != nil {
		t.Fatalf("a configured client was refused: %v", err)
	}

	// The echo target returns the payload, so a full round trip is 2x its
	// length. Accounting is asynchronous relative to the client's read, so poll.
	want := int64(len(payload) * 2)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := h.relay.AccountUsage()[0].UsedBytes; got >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("usage is %d bytes, want at least %d", h.relay.AccountUsage()[0].UsedBytes, want)
}

// Resetting usage must be reflected in the console and must not disturb the
// account's ability to serve.
func TestResettingUsageKeepsTheAccountUsable(t *testing.T) {
	h := startAccountHarness(t, []config.ClientAccount{enabledAcct("alice")}, "alice")

	if err := h.attempt("first"); err != nil {
		t.Fatalf("the configured client was refused: %v", err)
	}
	// The relay accounts for each direction as that direction's copy finishes,
	// and the two finish independently. Wait for the full round trip before
	// resetting, otherwise the reset is overwritten by the second direction's
	// bookkeeping and the test measures a race rather than the reset.
	waitForUsage(t, h, int64(len("first")*2))

	if n := h.relay.ResetAccountUsage("alice"); n != 1 {
		t.Fatalf("reset cleared %d accounts, want 1", n)
	}
	if got := h.relay.AccountUsage()[0].UsedBytes; got != 0 {
		t.Fatalf("usage is %d after a reset, want 0", got)
	}
	// The reset must not have disabled anything.
	if err := h.attempt("second"); err != nil {
		t.Fatalf("the account stopped working after a usage reset: %v", err)
	}
}

// waitForUsage polls until the account has recorded at least n bytes, so a test
// does not race the relay's post-stream accounting.
func waitForUsage(t *testing.T, h *accountHarness, n int64) int64 {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := h.relay.AccountUsage()[0].UsedBytes; got >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("usage never reached %d bytes (stuck at %d)",
		n, h.relay.AccountUsage()[0].UsedBytes)
	return 0
}

// A quota is checked before a stream starts, so a client is refused only once
// it has already spent the allowance. That means a small quota is exceeded by
// the stream that spends it and the *next* connection is the one refused —
// which is the documented behaviour, because stopping mid-stream would corrupt
// a protocol that has no way to signal a partial failure.
func TestExhaustedQuotaRefusesTheNextConnection(t *testing.T) {
	limited := enabledAcct("alice")
	limited.QuotaBytes = 1
	h := startAccountHarness(t, []config.ClientAccount{limited}, "alice")

	// The first connection is admitted (nothing spent yet) and overshoots.
	if err := h.attempt("spends the quota"); err != nil {
		t.Fatalf("the first connection should have been admitted: %v", err)
	}
	used := waitForUsage(t, h, 1)
	if used < 1 {
		t.Fatalf("usage is %d, the quota was never charged", used)
	}

	// The second must be refused.
	if err := h.attempt("over quota"); err == nil {
		t.Fatal("a client over its quota was served")
	}
}

// An account whose quota is already spent from a previous run — restored from
// the persisted usage file — must be refused immediately, without serving even
// one more connection.
func TestQuotaRestoredFromDiskRefusesImmediately(t *testing.T) {
	dir := t.TempDir()
	// Pre-seed the usage file the relay reads at startup.
	if err := writeQuotaFile(dir, "alice", 1<<20); err != nil {
		t.Fatal(err)
	}

	limited := enabledAcct("alice")
	limited.QuotaBytes = 1000
	h := startAccountHarnessIn(t, dir, []config.ClientAccount{limited}, "alice")

	if err := h.attempt("already over quota"); err == nil {
		t.Fatal("an account whose restored usage exceeds its quota was served")
	}
}

// A concurrency limit of one means a second simultaneous stream is refused,
// while the first keeps working.
func TestMaxConnectionsRefusesTheExcess(t *testing.T) {
	limited := enabledAcct("alice")
	limited.MaxConnections = 1
	h := startAccountHarness(t, []config.ClientAccount{limited}, "alice")

	// Hold one stream open on the target side by connecting to the tunnel and
	// not finishing the exchange.
	first, err := net.DialTimeout("tcp", h.tunnel, 5*time.Second)
	if err != nil {
		t.Fatalf("dial the tunnel: %v", err)
	}
	defer first.Close()
	_ = first.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := first.Write([]byte("hold")); err != nil {
		t.Fatalf("write to the first stream: %v", err)
	}

	// Wait until the relay reports the stream as active, so the second attempt
	// genuinely races an admitted connection rather than the accept itself.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.relay.AccountUsage()[0].Active >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := h.relay.AccountUsage()[0].Active; got < 1 {
		t.Fatalf("the first stream never became active (active=%d)", got)
	}

	// The second connection must be refused. It may fail either at connect or
	// on the first read, because the relay closes rather than replying.
	second, err := net.DialTimeout("tcp", h.tunnel, 5*time.Second)
	if err != nil {
		return // refused at accept time, which is a valid refusal
	}
	defer second.Close()
	_ = second.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := second.Write([]byte("excess")); err != nil {
		return // refused on write, also valid
	}
	buf := make([]byte, 6)
	if _, err := readFull(second, buf); err == nil {
		t.Fatalf("a second concurrent stream was served despite a limit of 1: %q", buf)
	}
}

// The regression, proven against a real relay: configuring client accounts must
// not break a native-header transport, because none of them can report a
// client-chosen identity.
//
// Trojan is used because it authenticates with a password hash in its own
// header and never exchanges the PortTransit preamble. Before the fix, adding a
// single account refused every such connection — an outage caused by a policy
// feature, which is the worst possible failure mode for a security control.
func TestAccountsDoNotBreakANativeHeaderTransport(t *testing.T) {
	settings := map[string]any{"password": "acct-password", "insecure": true}
	h := startAccountHarnessTransport(t, t.TempDir(),
		[]config.ClientAccount{enabledAcct("alice")}, "", "trojan", settings)

	if err := h.attempt("trojan with accounts configured"); err != nil {
		t.Fatalf("a native-header transport was refused because accounts exist: %v", err)
	}
}

// And the same must hold for a transport that reports the listener's own shared
// secret as its identity, which is what VMess does. That value will not equal
// an account id, so a strict lookup would refuse it.
func TestAccountsDoNotBreakATransportReportingASharedSecret(t *testing.T) {
	// The account id is deliberately unrelated to the UUID below, so the
	// reported value cannot match by accident.
	settings := map[string]any{
		"uuid":     "b831381d-6324-4d53-ad4f-8cda48b30811",
		"insecure": true,
	}
	h := startAccountHarnessTransport(t, t.TempDir(),
		[]config.ClientAccount{enabledAcct("alice")}, "", "vmess", settings)

	if err := h.attempt("vmess with accounts configured"); err != nil {
		t.Fatalf("vmess was refused although its reported id is a shared secret: %v", err)
	}
}

// The counterpart: a preamble transport must still be policed, or the account
// list would be decorative on exactly the transports it can govern.
func TestAccountsStillGovernAPreambleTransport(t *testing.T) {
	// An unknown id on a preamble transport is refused...
	unknown := startAccountHarness(t, []config.ClientAccount{enabledAcct("alice")}, "mallory")
	if err := unknown.attempt("mallory"); err == nil {
		t.Fatal("a preamble transport with an unknown id was served")
	}

	// ...and a listed one is served.
	known := startAccountHarness(t, []config.ClientAccount{enabledAcct("alice")}, "alice")
	if err := known.attempt("alice"); err != nil {
		t.Fatalf("a listed client was refused: %v", err)
	}
}
