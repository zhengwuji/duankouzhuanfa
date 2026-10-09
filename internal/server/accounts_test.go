package server

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"porttransit/internal/config"
)

// serverConfig builds a ServerConfig with no listeners, so the account table
// can be exercised without binding anything.
func serverConfig(clients ...config.ClientAccount) *config.ServerConfig {
	cfg := config.Default(config.ModeServer).Server
	cfg.Clients = clients
	return cfg
}

func enabledAccount(id string) config.ClientAccount {
	return config.ClientAccount{ID: id, Enabled: true, Credentials: map[string]string{"psk": "x"}}
}

// With no accounts configured the relay must behave exactly as it did before
// accounts existed: any client id is served, because the operator has not asked
// for per-client policy.
func TestAccountTableIsOpenWhenNothingIsConfigured(t *testing.T) {
	tbl := newAccountTable(serverConfig())

	acct, err := tbl.admit("anyone", true)
	if err != nil {
		t.Fatalf("an unconfigured relay refused a client: %v", err)
	}
	if acct != nil {
		t.Fatal("a nil account was expected when no accounts exist")
	}
	// release and addBytes must be safe on a nil account, because the serving
	// path calls them unconditionally.
	acct.release()
	acct.addBytes(1024)
	if acct.rateLimiter() != nil {
		t.Fatal("a nil account reported a rate limiter")
	}
}

// Once accounts exist, an unknown id must be refused. Otherwise per-client
// policy is trivially bypassed by presenting an id the relay has never heard
// of, and the whole accounts feature is decorative.
func TestAccountTableRefusesUnknownClientIDs(t *testing.T) {
	tbl := newAccountTable(serverConfig(enabledAccount("alice")))

	if _, err := tbl.admit("mallory", true); err == nil {
		t.Fatal("an unknown client id was admitted")
	} else if !errors.Is(err, ErrAccountDisabled) {
		t.Errorf("the refusal is %v, want it to wrap ErrAccountDisabled", err)
	}

	// A missing id is the same failure mode and must be named as such, since
	// "you did not identify yourself" is a different fix from "wrong id".
	_, err := tbl.admit("", true)
	if err == nil {
		t.Fatal("an empty client id was admitted")
	}
	if !strings.Contains(err.Error(), "clientId") {
		t.Errorf("error %q does not mention the missing client id", err)
	}
}

func TestAccountTableAdmitsAKnownClient(t *testing.T) {
	tbl := newAccountTable(serverConfig(enabledAccount("alice")))

	acct, err := tbl.admit("alice", true)
	if err != nil {
		t.Fatalf("a configured, enabled client was refused: %v", err)
	}
	if acct == nil {
		t.Fatal("a nil account was returned for a configured client")
	}
	if got := acct.active.Load(); got != 1 {
		t.Errorf("active is %d, want 1 after admit", got)
	}
	acct.release()
	if got := acct.active.Load(); got != 0 {
		t.Errorf("active is %d, want 0 after release", got)
	}
}

// A disabled account is the feature's whole point: turning a client off must
// actually stop it, without deleting its configuration.
func TestAccountTableRefusesDisabledAccount(t *testing.T) {
	disabled := enabledAccount("alice")
	disabled.Enabled = false
	tbl := newAccountTable(serverConfig(disabled))

	_, err := tbl.admit("alice", true)
	if err == nil {
		t.Fatal("a disabled account was admitted")
	}
	if !errors.Is(err, ErrAccountDisabled) {
		t.Errorf("the refusal is %v, want it to wrap ErrAccountDisabled", err)
	}
	if !strings.Contains(err.Error(), "停用") {
		t.Errorf("error %q does not say the account is disabled", err)
	}
}

func TestAccountTableRefusesExpiredAccount(t *testing.T) {
	expired := enabledAccount("alice")
	expired.ExpiresAt = time.Now().Add(-time.Minute)
	tbl := newAccountTable(serverConfig(expired))

	_, err := tbl.admit("alice", true)
	if err == nil {
		t.Fatal("an expired account was admitted")
	}
	if !errors.Is(err, ErrAccountDisabled) {
		t.Errorf("the refusal is %v, want ErrAccountDisabled", err)
	}
	if !strings.Contains(err.Error(), "到期") {
		t.Errorf("error %q does not say the account expired", err)
	}
}

func TestAccountTableAdmitsAccountExpiringInTheFuture(t *testing.T) {
	future := enabledAccount("alice")
	future.ExpiresAt = time.Now().Add(time.Hour)
	tbl := newAccountTable(serverConfig(future))

	if _, err := tbl.admit("alice", true); err != nil {
		t.Fatalf("an account that has not expired was refused: %v", err)
	}
}

func TestAccountTableRefusesExhaustedQuota(t *testing.T) {
	limited := enabledAccount("alice")
	limited.QuotaBytes = 1000
	tbl := newAccountTable(serverConfig(limited))

	acct, err := tbl.admit("alice", true)
	if err != nil {
		t.Fatal(err)
	}
	// Under quota: still admitted.
	acct.addBytes(999)
	acct.release()
	if _, err := tbl.admit("alice", true); err != nil {
		t.Fatalf("an account under its quota was refused: %v", err)
	}

	// At quota: refused.
	acct.addBytes(1)
	_, err = tbl.admit("alice", true)
	if err == nil {
		t.Fatal("an account at its quota was admitted")
	}
	if !strings.Contains(err.Error(), "配额") {
		t.Errorf("error %q does not mention the quota", err)
	}
}

func TestAccountTableEnforcesMaxConnections(t *testing.T) {
	limited := enabledAccount("alice")
	limited.MaxConnections = 2
	tbl := newAccountTable(serverConfig(limited))

	a1, err := tbl.admit("alice", true)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := tbl.admit("alice", true)
	if err != nil {
		t.Fatalf("the second of two allowed connections was refused: %v", err)
	}
	if _, err := tbl.admit("alice", true); err == nil {
		t.Fatal("a third connection exceeded the limit of two but was admitted")
	} else if !strings.Contains(err.Error(), "并发连接") {
		t.Errorf("error %q does not mention the concurrency limit", err)
	}

	// Releasing one slot must let the next connection through, or the limit
	// would be a one-way ratchet.
	a1.release()
	if _, err := tbl.admit("alice", true); err != nil {
		t.Fatalf("a freed slot was not reusable: %v", err)
	}
	a2.release()
}

// The concurrency check must be atomic: two goroutines that both read "one slot
// left" and both take it would let a client exceed its limit under load, which
// is exactly when a limit matters.
//
// Admission is deliberately non-blocking — a relay refuses the excess rather
// than queueing it, because a queued connection has already consumed its
// handshake and would occupy a slot while waiting. So the assertion is that the
// number admitted *at any instant* never exceeds the limit, not that every
// attempt eventually succeeds.
func TestAccountTableConcurrencyLimitIsRaceFree(t *testing.T) {
	const limit = 8
	const attempts = 64

	limited := enabledAccount("alice")
	limited.MaxConnections = limit
	tbl := newAccountTable(serverConfig(limited))

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		admitted int
		refused  int
		peak     int64
	)
	start := make(chan struct{})

	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			acct, err := tbl.admit("alice", true)
			if err != nil {
				mu.Lock()
				refused++
				mu.Unlock()
				return
			}
			// Sample the concurrency while holding the slot: this is the
			// measurement that would catch a broken compare-and-swap.
			cur := acct.active.Load()
			mu.Lock()
			admitted++
			if cur > peak {
				peak = cur
			}
			mu.Unlock()

			time.Sleep(2 * time.Millisecond)
			acct.release()
		}()
	}
	close(start)
	wg.Wait()

	mu.Lock()
	gotAdmitted, gotRefused, gotPeak := admitted, refused, peak
	mu.Unlock()

	if gotAdmitted+gotRefused != attempts {
		t.Fatalf("%d admitted + %d refused != %d attempts", gotAdmitted, gotRefused, attempts)
	}
	if gotPeak > limit {
		t.Errorf("concurrency peaked at %d, above the limit of %d", gotPeak, limit)
	}
	if gotAdmitted == 0 {
		t.Error("nothing was admitted at all")
	}
	// Everyone releases in the end, so the counter must return to zero; a leak
	// here would permanently shrink the account's capacity.
	if got := tbl.lookup("alice").active.Load(); got != 0 {
		t.Errorf("active is %d after everyone released, want 0", got)
	}
}

func TestAccountTableSharesOneRateLimiterPerClient(t *testing.T) {
	limited := enabledAccount("alice")
	limited.RateLimitKBps = 100
	tbl := newAccountTable(serverConfig(limited))

	a1, err := tbl.admit("alice", true)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := tbl.admit("alice", true)
	if err != nil {
		t.Fatal(err)
	}
	// A limiter built per stream would let the client multiply its rate by
	// opening more streams, so the two must be the same object.
	if a1.rateLimiter() == nil {
		t.Fatal("no limiter was built for an account with a rate limit")
	}
	if a1.rateLimiter() != a2.rateLimiter() {
		t.Fatal("each stream got its own limiter, so the rate limit is per-stream and not per-client")
	}
	a1.release()
	a2.release()
}

func TestAccountTableSnapshotReportsUsage(t *testing.T) {
	limited := enabledAccount("alice")
	limited.Name = "Alice"
	limited.QuotaBytes = 5000
	limited.MaxConnections = 3
	limited.RateLimitKBps = 200
	limited.ExpiresAt = time.Now().Add(time.Hour)
	tbl := newAccountTable(serverConfig(limited))

	acct, err := tbl.admit("alice", true)
	if err != nil {
		t.Fatal(err)
	}
	acct.addBytes(1234)

	got := tbl.snapshot()
	if len(got) != 1 {
		t.Fatalf("snapshot has %d entries, want 1", len(got))
	}
	u := got[0]
	if u.ID != "alice" || u.Name != "Alice" {
		t.Errorf("snapshot identity is %+v", u)
	}
	if !u.Enabled {
		t.Error("an enabled account is reported as disabled")
	}
	if u.Active != 1 {
		t.Errorf("Active is %d, want 1", u.Active)
	}
	if u.UsedBytes != 1234 {
		t.Errorf("UsedBytes is %d, want 1234", u.UsedBytes)
	}
	if u.QuotaBytes != 5000 || u.MaxConnections != 3 || u.RateLimitKBps != 200 {
		t.Errorf("limits were not reported: %+v", u)
	}
	if u.ExpiresAt.IsZero() {
		t.Error("ExpiresAt was dropped")
	}
	acct.release()
}

func TestAccountTableSnapshotIsEmptyWithoutAccounts(t *testing.T) {
	if got := newAccountTable(serverConfig()).snapshot(); len(got) != 0 {
		t.Fatalf("got %v, want nothing", got)
	}
}

func TestResetUsageClearsOneOrAll(t *testing.T) {
	tbl := newAccountTable(serverConfig(enabledAccount("alice"), enabledAccount("bob")))
	for _, id := range []string{"alice", "bob"} {
		a, err := tbl.admit(id, true)
		if err != nil {
			t.Fatal(err)
		}
		a.addBytes(500)
		a.release()
	}

	if n := tbl.resetUsage("alice"); n != 1 {
		t.Fatalf("resetUsage(alice) cleared %d accounts, want 1", n)
	}
	if got := tbl.lookup("alice").used.Load(); got != 0 {
		t.Errorf("alice still shows %d bytes", got)
	}
	if got := tbl.lookup("bob").used.Load(); got != 500 {
		t.Errorf("bob was cleared too (%d bytes), but only alice was asked for", got)
	}

	if n := tbl.resetUsage(""); n != 2 {
		t.Fatalf("resetUsage(\"\") cleared %d accounts, want 2", n)
	}
	if got := tbl.lookup("bob").used.Load(); got != 0 {
		t.Errorf("bob still shows %d bytes after a full reset", got)
	}
}

// Usage must survive a restart, or a quota is something a client can clear by
// waiting for the operator to redeploy.
func TestUsageSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	cfg := serverConfig(enabledAccount("alice"))
	cfg.DataDir = dir

	tbl := newAccountTable(cfg)
	acct, err := tbl.admit("alice", true)
	if err != nil {
		t.Fatal(err)
	}
	acct.addBytes(4096)
	acct.release()
	if err := tbl.saveUsage(); err != nil {
		t.Fatal(err)
	}

	reloaded := newAccountTable(cfg)
	if got := reloaded.lookup("alice").used.Load(); got != 4096 {
		t.Fatalf("usage after reload is %d, want 4096", got)
	}
}

func TestUsageFileIsPrivateAndAtomic(t *testing.T) {
	dir := t.TempDir()
	cfg := serverConfig(enabledAccount("alice"))
	cfg.DataDir = dir

	tbl := newAccountTable(cfg)
	acct, _ := tbl.admit("alice", true)
	acct.addBytes(10)
	acct.release()
	if err := tbl.saveUsage(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "quota.json")
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// The file names which clients exist, so it must not be world-readable.
	// Windows does not model POSIX permission bits — Go reports 0666 for any
	// writable file there — so the assertion only means something elsewhere.
	if runtime.GOOS != "windows" {
		if perm := st.Mode().Perm(); perm != 0o600 {
			t.Errorf("quota file mode is %o, want 600", perm)
		}
	}
	// The temporary file must be gone after a successful rename.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("the temporary file was left behind")
	}
	// And the content must be valid JSON of the documented shape.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f quotaFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("quota file is not valid JSON: %v", err)
	}
	if f.Version != quotaFileVersion {
		t.Errorf("version is %d, want %d", f.Version, quotaFileVersion)
	}
	if f.Used["alice"] != 10 {
		t.Errorf("usage recorded as %d, want 10", f.Used["alice"])
	}
}

// A corrupt bookkeeping file must not take the relay down: refusing to start
// over a usage counter would turn a minor problem into an outage.
func TestCorruptUsageFileIsIgnored(t *testing.T) {
	dir := t.TempDir()
	cfg := serverConfig(enabledAccount("alice"))
	cfg.DataDir = dir

	if err := os.WriteFile(filepath.Join(dir, "quota.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	tbl := newAccountTable(cfg)
	if got := tbl.lookup("alice").used.Load(); got != 0 {
		t.Errorf("usage is %d, want 0 from a corrupt file", got)
	}
	// And it must still be usable.
	if _, err := tbl.admit("alice", true); err != nil {
		t.Fatalf("a corrupt quota file made the account unusable: %v", err)
	}
}

// A future format must not be misread as the current one.
func TestUnknownUsageFileVersionIsIgnored(t *testing.T) {
	dir := t.TempDir()
	cfg := serverConfig(enabledAccount("alice"))
	cfg.DataDir = dir

	b, _ := json.Marshal(quotaFile{Version: 99, Used: map[string]int64{"alice": 999}})
	if err := os.WriteFile(filepath.Join(dir, "quota.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	tbl := newAccountTable(cfg)
	if got := tbl.lookup("alice").used.Load(); got != 0 {
		t.Errorf("usage is %d, want 0 for an unknown file version", got)
	}
}

func TestUsageIsNotPersistedWithoutADataDir(t *testing.T) {
	cfg := serverConfig(enabledAccount("alice"))
	cfg.DataDir = ""
	tbl := newAccountTable(cfg)
	if tbl.quotaPath != "" {
		t.Fatalf("quota path is %q without a data dir", tbl.quotaPath)
	}
	if err := tbl.saveUsage(); err != nil {
		t.Fatalf("saving without a data dir should be a no-op: %v", err)
	}
	if err := tbl.flushIfDirty(); err != nil {
		t.Fatalf("flushing without a data dir should be a no-op: %v", err)
	}
}

func TestFlushOnlyWritesWhenDirty(t *testing.T) {
	dir := t.TempDir()
	cfg := serverConfig(enabledAccount("alice"))
	cfg.DataDir = dir
	tbl := newAccountTable(cfg)
	path := filepath.Join(dir, "quota.json")

	// Not dirty: no file should appear.
	if err := tbl.flushIfDirty(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("a flush with nothing dirty still wrote the file")
	}

	tbl.markDirty()
	if err := tbl.flushIfDirty(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("a dirty flush did not write the file: %v", err)
	}
	// The dirty flag must be cleared, or every subsequent flush would rewrite.
	if tbl.dirty.Load() {
		t.Error("the dirty flag was not cleared")
	}
}

func TestAccountTableHandlesNilConfig(t *testing.T) {
	tbl := newAccountTable(nil)
	if acct, err := tbl.admit("anyone", true); err != nil || acct != nil {
		t.Fatalf("a nil config produced %v / %v", acct, err)
	}
}

func TestLookupOfMissingClientReturnsNil(t *testing.T) {
	tbl := newAccountTable(serverConfig(enabledAccount("alice")))
	if got := tbl.lookup("nobody"); got != nil {
		t.Fatalf("got %v, want nil", got)
	}
	if got := tbl.lookup(""); got != nil {
		t.Fatalf("an empty id returned %v, want nil", got)
	}
	var nilTable *accountTable
	if got := nilTable.lookup("alice"); got != nil {
		t.Fatalf("a nil table returned %v, want nil", got)
	}
}

// identityCapable decides whether "no client id" is a client failing to
// identify itself or a transport that simply cannot.
//
// This distinction is load-bearing. The PortTransit preamble carries a client
// id, but a native-header transport authenticates with a shared secret in its
// own header and never exchanges the preamble. If those were treated as
// unidentified clients, configuring a single account would refuse every VLESS,
// Trojan, Shadowsocks, SOCKS5 and HTTP CONNECT connection — turning a policy
// feature into a total outage.
func TestIdentityCapableMatchesTheTransportShape(t *testing.T) {
	// Preamble transports: the client id travels in the frame, so a missing one
	// is the client's fault and must be refused.
	for _, name := range []string{"direct", "tls", "ws", "reality"} {
		if !identityCapable(name) {
			t.Errorf("%s carries a client id in its preamble but is treated as unable to", name)
		}
	}
	// Native-header transports: no preamble, so no client id exists to check.
	for _, name := range []string{"vless", "trojan", "shadowsocks", "socks5", "vmess", "http"} {
		if identityCapable(name) {
			t.Errorf("%s has no way to report a client id but is expected to", name)
		}
	}
	// An unknown transport must fail closed rather than silently weakening the
	// policy, because we cannot know whether it carries an identity.
	if !identityCapable("no-such-transport") {
		t.Error("an unknown transport was treated as identity-incapable, weakening the policy")
	}
}

// The regression this guards against: with accounts configured, a native-header
// transport must keep working. Before the fix this refused every such
// connection, because none of them can report a client-chosen identity.
func TestNativeHeaderTransportsAreServedWithoutAMatchingID(t *testing.T) {
	tbl := newAccountTable(serverConfig(enabledAccount("alice")))

	// "" is SOCKS5/Trojan/VLESS/Shadowsocks/HTTP CONNECT; the second value is
	// what VMess reports, which is the listener's own UUID rather than a
	// client-chosen id.
	for _, reported := range []string{"", "some-listener-uuid"} {
		acct, err := tbl.admit(reported, false)
		if err != nil {
			t.Errorf("a native-header transport reporting %q was refused: %v", reported, err)
			continue
		}
		if acct != nil {
			t.Errorf("reporting %q unexpectedly matched an account", reported)
			acct.release()
		}
	}
}

// A preamble transport that stays silent must still be refused, because it
// could have identified itself and did not.
func TestPreambleTransportWithoutAClientIDIsStillRefused(t *testing.T) {
	tbl := newAccountTable(serverConfig(enabledAccount("alice")))

	for _, name := range []string{"direct", "tls", "ws", "reality"} {
		if _, err := tbl.admit("", identityCapable(name)); err == nil {
			t.Errorf("%s connected without an id but was served", name)
		} else if !strings.Contains(err.Error(), "clientId") {
			t.Errorf("%s: error %q does not mention the missing client id", name, err)
		}
	}
}

// An id the relay does not know is refused on a preamble transport: the
// operator listed the ids they expect, so an unlisted one is a mismatch. This
// is what makes the account list meaningful rather than decorative.
func TestUnknownClientIDIsRefusedOnPreambleTransports(t *testing.T) {
	tbl := newAccountTable(serverConfig(enabledAccount("alice")))

	for _, name := range []string{"direct", "tls", "ws", "reality"} {
		if _, err := tbl.admit("mallory", identityCapable(name)); err == nil {
			t.Errorf("%s with an unknown id was served", name)
		}
	}
}

// A native-header transport must still get an account's limits when the value
// it reports happens to match one, so the policy is not simply skipped.
func TestNativeHeaderTransportWithAMatchingIDGetsItsAccount(t *testing.T) {
	tbl := newAccountTable(serverConfig(enabledAccount("alice")))

	acct, err := tbl.admit("alice", false)
	if err != nil {
		t.Fatalf("a native-header transport matching an account was refused: %v", err)
	}
	if acct == nil {
		t.Fatal("no account was returned for a matching id")
	}
	acct.release()
}

// Limits on a native-header transport must still apply when an id is reported,
// so the policy is not simply skipped for those transports.
func TestNativeHeaderTransportHonoursAccountLimits(t *testing.T) {
	limited := enabledAccount("alice")
	limited.MaxConnections = 1
	tbl := newAccountTable(serverConfig(limited))

	a1, err := tbl.admit("alice", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tbl.admit("alice", false); err == nil {
		t.Fatal("the concurrency limit was not applied on a native-header transport")
	}
	a1.release()

	// A disabled account must be refused there too.
	disabled := enabledAccount("bob")
	disabled.Enabled = false
	tbl2 := newAccountTable(serverConfig(disabled))
	if _, err := tbl2.admit("bob", false); err == nil {
		t.Fatal("a disabled account was served on a native-header transport")
	}
}

// The rate limiter comparison picks the tighter of the global and per-account
// caps, because both are policy and honouring only one silently ignores the
// other.
func TestStricterLimiterPicksTheLowerRate(t *testing.T) {
	slow := newRateLimiter(100)
	fast := newRateLimiter(1000)

	if got := stricterLimiter(slow, fast); got != slow {
		t.Error("the slower limiter was not chosen")
	}
	if got := stricterLimiter(fast, slow); got != slow {
		t.Error("the slower limiter was not chosen regardless of argument order")
	}
	// nil means unlimited, so the non-nil one wins.
	if got := stricterLimiter(nil, slow); got != slow {
		t.Error("a nil (unlimited) limiter beat a real one")
	}
	if got := stricterLimiter(slow, nil); got != slow {
		t.Error("a nil (unlimited) limiter beat a real one")
	}
	if got := stricterLimiter(nil, nil); got != nil {
		t.Error("two unlimited limiters should stay unlimited")
	}
}
