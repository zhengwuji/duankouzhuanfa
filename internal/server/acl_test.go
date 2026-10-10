package server

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"porttransit/internal/config"
	"porttransit/internal/logx"
	"porttransit/internal/transport"
)

// TestACLBlocksPrivateByDefault proves the relay refuses to reach its own
// host's private network, which is the single most valuable thing an attacker
// gains from a stolen relay credential.
func TestACLBlocksPrivateByDefault(t *testing.T) {
	acl, err := NewACL(config.ACLConfig{})
	if err != nil {
		t.Fatalf("NewACL: %v", err)
	}

	blocked := []string{
		"127.0.0.1:80",
		"10.0.0.1:22",
		"192.168.1.1:443",
		"172.16.0.1:3306",
		"169.254.169.254:80",
		"100.64.0.1:80",
		"0.0.0.0:80",
		"[::1]:80",
		"[fe80::1]:80",
		"[fc00::1]:80",
		"240.0.0.1:80",
		"198.18.0.1:80",
		"192.0.0.1:80",
	}
	for _, target := range blocked {
		if err := acl.Check(target, nil); !errors.Is(err, ErrDestinationDenied) {
			t.Errorf("ACL allowed %s, want it denied (%v)", target, err)
		}
	}
}

// TestACLAllowsPublicDestinations proves the default policy is not so strict
// that the relay is useless.
func TestACLAllowsPublicDestinations(t *testing.T) {
	acl, err := NewACL(config.ACLConfig{})
	if err != nil {
		t.Fatalf("NewACL: %v", err)
	}

	allowed := []string{
		"93.184.216.34:443",
		"example.com:443",
		"8.8.8.8:53",
		"[2606:2800:220:1:248:1893:25c8:1946]:443",
	}
	for _, target := range allowed {
		if err := acl.Check(target, nil); err != nil {
			t.Errorf("ACL denied %s: %v", target, err)
		}
	}
}

// TestACLBlockPrivateCanBeDisabled proves the operator can opt out, because a
// relay whose whole purpose is reaching an internal service must be able to.
func TestACLBlockPrivateCanBeDisabled(t *testing.T) {
	no := false
	acl, err := NewACL(config.ACLConfig{BlockPrivate: &no})
	if err != nil {
		t.Fatalf("NewACL: %v", err)
	}
	if err := acl.Check("192.168.1.1:80", nil); err != nil {
		t.Errorf("ACL denied a private destination after blockPrivate was disabled: %v", err)
	}
}

// TestACLDenyWinsOverAllow proves the deny list is authoritative. An operator
// who adds a deny entry expects it to take effect even when a broad allow rule
// already matches, otherwise the deny list cannot be trusted.
func TestACLDenyWinsOverAllow(t *testing.T) {
	acl, err := NewACL(config.ACLConfig{
		Allow: []string{"example.com"},
		Deny:  []string{"bad.example.com"},
	})
	if err != nil {
		t.Fatalf("NewACL: %v", err)
	}

	if err := acl.Check("example.com:443", nil); err != nil {
		t.Errorf("an allowed destination was denied: %v", err)
	}
	if err := acl.Check("bad.example.com:443", nil); !errors.Is(err, ErrDestinationDenied) {
		t.Errorf("a denied destination was allowed: %v", err)
	}
}

// TestACLPortPolicy proves port allow and block lists behave.
func TestACLPortPolicy(t *testing.T) {
	acl, err := NewACL(config.ACLConfig{BlockPorts: []int{25, 23}})
	if err != nil {
		t.Fatalf("NewACL: %v", err)
	}
	if err := acl.Check("example.com:25", nil); !errors.Is(err, ErrDestinationDenied) {
		t.Errorf("a blocked port was allowed: %v", err)
	}
	if err := acl.Check("example.com:443", nil); err != nil {
		t.Errorf("an unblocked port was denied: %v", err)
	}

	restricted, err := NewACL(config.ACLConfig{AllowPorts: []int{443, 8443}})
	if err != nil {
		t.Fatalf("NewACL: %v", err)
	}
	if err := restricted.Check("example.com:80", nil); !errors.Is(err, ErrDestinationDenied) {
		t.Errorf("a port outside the allow list was permitted: %v", err)
	}
	if err := restricted.Check("example.com:443", nil); err != nil {
		t.Errorf("a port inside the allow list was denied: %v", err)
	}
}

// TestACLPerClientPolicy proves a client's own lists narrow the global policy
// rather than replacing it, so an operator can grant a subset safely.
func TestACLPerClientPolicy(t *testing.T) {
	acl, err := NewACL(config.ACLConfig{})
	if err != nil {
		t.Fatalf("NewACL: %v", err)
	}

	client := &config.ClientAccount{
		ID:             "c1",
		AllowedTargets: []string{"api.example.com"},
		DeniedTargets:  []string{"secret.example.com"},
	}

	if err := acl.Check("api.example.com:443", client); err != nil {
		t.Errorf("a client-allowed destination was denied: %v", err)
	}
	if err := acl.Check("other.example.com:443", client); !errors.Is(err, ErrDestinationDenied) {
		t.Errorf("a destination outside the client's allow list was permitted: %v", err)
	}
	// A per-client deny must win even against a per-client allow, which is the
	// only ordering that makes a deny entry meaningful.
	client.AllowedTargets = append(client.AllowedTargets, "secret.example.com")
	if err := acl.Check("secret.example.com:443", client); !errors.Is(err, ErrDestinationDenied) {
		t.Errorf("a client-denied destination was permitted: %v", err)
	}
}

// TestACLMatchTargetForms proves the three supported pattern forms behave,
// because an operator writing ".example.com" and getting exact matching would
// silently expose more than they intended.
func TestACLMatchTargetForms(t *testing.T) {
	cases := []struct {
		pattern string
		target  string
		want    bool
	}{
		{"example.com:443", "example.com:443", true},
		{"example.com:443", "example.com:80", false},
		{"example.com", "example.com:80", true},
		{"example.com", "example.com:443", true},
		{"example.com", "other.com:443", false},
		{".example.com", "a.example.com:443", true},
		{".example.com", "a.b.example.com:443", true},
		{".example.com", "example.com:443", true},
		{".example.com", "notexample.com:443", false},
		{"", "example.com:443", false},
	}
	for _, tc := range cases {
		host := targetHost(tc.target)
		if got := matchTarget(tc.pattern, tc.target, host); got != tc.want {
			t.Errorf("matchTarget(%q, %q) = %v, want %v", tc.pattern, tc.target, got, tc.want)
		}
	}
}

// TestACLCheckResolvedCatchesRebinding proves a domain that resolves to a
// private address is refused, which closes the DNS-rebinding path around the
// literal-address check.
func TestACLCheckResolvedCatchesRebinding(t *testing.T) {
	acl, err := NewACL(config.ACLConfig{})
	if err != nil {
		t.Fatalf("NewACL: %v", err)
	}

	// The name itself passes, because resolving at check time would add a
	// lookup to every request.
	if err := acl.Check("evil.example.com:80", nil); err != nil {
		t.Fatalf("the domain form was denied before resolution: %v", err)
	}
	// After resolution the private address must be caught.
	if err := acl.CheckResolved("evil.example.com:80", net.ParseIP("127.0.0.1")); !errors.Is(err, ErrDestinationDenied) {
		t.Errorf("a name resolving to loopback was permitted: %v", err)
	}
	if err := acl.CheckResolved("evil.example.com:80", net.ParseIP("169.254.169.254")); !errors.Is(err, ErrDestinationDenied) {
		t.Errorf("a name resolving to the metadata endpoint was permitted: %v", err)
	}
	if err := acl.CheckResolved("ok.example.com:80", net.ParseIP("93.184.216.34")); err != nil {
		t.Errorf("a name resolving to a public address was denied: %v", err)
	}
}

// TestACLRejectsInvalidPorts proves a malformed target is refused rather than
// treated as port zero.
func TestACLRejectsInvalidPorts(t *testing.T) {
	acl, err := NewACL(config.ACLConfig{})
	if err != nil {
		t.Fatalf("NewACL: %v", err)
	}
	for _, target := range []string{"example.com:0", "example.com:70000", "example.com:abc"} {
		if err := acl.Check(target, nil); err == nil {
			t.Errorf("ACL accepted the malformed target %q", target)
		}
	}
}

// TestNewACLRejectsInvalidPortConfig proves a bad port in the configuration is
// reported at construction rather than silently ignored.
func TestNewACLRejectsInvalidPortConfig(t *testing.T) {
	if _, err := NewACL(config.ACLConfig{BlockPorts: []int{0}}); err == nil {
		t.Error("NewACL accepted port 0 in blockPorts")
	}
	if _, err := NewACL(config.ACLConfig{AllowPorts: []int{99999}}); err == nil {
		t.Error("NewACL accepted port 99999 in allowPorts")
	}
}

// TestIsNonRoutableIP covers the address classes directly, because the relay's
// SSRF protection rests entirely on this predicate.
func TestIsNonRoutableIP(t *testing.T) {
	nonRoutable := []string{
		"127.0.0.1", "::1",
		"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.0.1",
		"169.254.1.1", "169.254.169.254",
		"100.64.0.1", "100.127.255.255",
		"0.0.0.0",
		"fe80::1", "fc00::1", "fd00::1",
		"192.0.0.1", "198.18.0.1", "198.19.255.255", "240.0.0.1", "255.255.255.255",
	}
	for _, s := range nonRoutable {
		if !isNonRoutableIP(net.ParseIP(s)) {
			t.Errorf("isNonRoutableIP(%s) = false, want true", s)
		}
	}

	routable := []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34", "172.32.0.1", "172.15.255.255",
		"100.63.255.255", "100.128.0.0", "198.20.0.1", "2606:4700::1111",
	}
	for _, s := range routable {
		if isNonRoutableIP(net.ParseIP(s)) {
			t.Errorf("isNonRoutableIP(%s) = true, want false", s)
		}
	}
}

// TestPickUpstream proves the balance strategies are deterministic per seed,
// which is what keeps a stateful target pinned to one upstream.
func TestPickUpstream(t *testing.T) {
	spec := "a.example.com:1,b.example.com:2,c.example.com:3"

	// "first" always returns the first entry.
	if got := pickUpstream(spec, "first", "seed"); got != "a.example.com:1" {
		t.Errorf("pickUpstream(first) = %q", got)
	}
	// Any of the balancing strategies must be stable for a given seed.
	for _, strategy := range []string{"round-robin", "random", "least-conn", "least-latency"} {
		first := pickUpstream(spec, strategy, "same-seed")
		for i := 0; i < 20; i++ {
			if got := pickUpstream(spec, strategy, "same-seed"); got != first {
				t.Fatalf("pickUpstream(%s) is not deterministic: %q vs %q", strategy, got, first)
			}
		}
		// A single-host spec must return that host regardless of strategy.
		if got := pickUpstream("only.example.com:9", strategy, "seed"); got != "only.example.com:9" {
			t.Errorf("pickUpstream(%s) on a single host = %q", strategy, got)
		}
	}
	// Whitespace around entries must not leak into the result.
	if got := pickUpstream(" a:1 , b:2 ", "first", "s"); got != "a:1" {
		t.Errorf("pickUpstream did not trim whitespace: %q", got)
	}
}

// TestMatchForwardSpecificity proves a rule naming a listener beats a general
// rule, because otherwise an operator could not add a catch-all without
// shadowing every specific rule they had already written.
func TestMatchForwardSpecificity(t *testing.T) {
	s := &Server{cfg: &config.ServerConfig{
		Forwards: []config.Forward{
			{Name: "general", Enabled: true, Target: "general.example.com:1"},
			{Name: "by-listener", Enabled: true, Listener: "l1", Target: "listener.example.com:2"},
			{Name: "by-both", Enabled: true, Listener: "l1", Transport: "tls", Target: "both.example.com:3"},
			{Name: "disabled", Enabled: false, Listener: "l1", Transport: "tls", Client: "c1", Target: "never:1"},
		},
	}}

	got := s.matchForward("l1", reqFor("tls", ""))
	if got == nil || got.Name != "by-both" {
		t.Errorf("matchForward chose %v, want by-both", nameOf(got))
	}

	got = s.matchForward("l1", reqFor("vless", ""))
	if got == nil || got.Name != "by-listener" {
		t.Errorf("matchForward chose %v, want by-listener", nameOf(got))
	}

	got = s.matchForward("l2", reqFor("vless", ""))
	if got == nil || got.Name != "general" {
		t.Errorf("matchForward chose %v, want general", nameOf(got))
	}
}

// TestMatchForwardSynthesisesCatchAll proves a relay with no rules forwards
// every authenticated request, which is the common 中转 configuration.
func TestMatchForwardSynthesisesCatchAll(t *testing.T) {
	s := &Server{cfg: &config.ServerConfig{}}
	got := s.matchForward("any", reqFor("tls", ""))
	if got == nil {
		t.Fatal("a relay with no forward rules rejected every request")
	}
	if !got.Enabled {
		t.Error("the synthesised catch-all rule is disabled")
	}
}

// TestTargetAllowedByRule proves the allow-list forms used by a target-less
// forward rule.
func TestTargetAllowedByRule(t *testing.T) {
	rule := &config.Forward{
		Enabled:        true,
		AllowedTargets: []string{"example.com:443", "api.example.com", ".trusted.com"},
	}
	cases := []struct {
		target string
		want   bool
	}{
		{"example.com:443", true},
		{"example.com:80", false},
		{"api.example.com:8080", true},
		{"a.trusted.com:443", true},
		{"trusted.com:443", true},
		{"evil.com:443", false},
	}
	for _, tc := range cases {
		if got := targetAllowedByRule(rule, tc.target); got != tc.want {
			t.Errorf("targetAllowedByRule(%q) = %v, want %v", tc.target, got, tc.want)
		}
	}
}

// TestHandshakeGuardThrottles proves the per-IP throttle eventually refuses,
// which is what stops a connection flood from allocating a goroutine per
// attempt.
func TestHandshakeGuardThrottles(t *testing.T) {
	g := newHandshakeGuard(10)

	// The burst allowance is the configured rate, so the first ten attempts
	// must succeed.
	for i := 0; i < 10; i++ {
		if !g.allow("1.2.3.4") {
			t.Fatalf("attempt %d was throttled inside the burst allowance", i+1)
		}
	}
	if g.allow("1.2.3.4") {
		t.Error("an attempt beyond the burst allowance was permitted")
	}
	// A different source must be unaffected: the throttle is per IP, not
	// global, so one noisy client cannot deny service to everyone else.
	if !g.allow("5.6.7.8") {
		t.Error("a different source IP was throttled")
	}
}

// TestHandshakeGuardDisabled proves a zero rate disables throttling, which is
// the default because a legitimate client behind CGNAT shares one source IP.
func TestHandshakeGuardDisabled(t *testing.T) {
	g := newHandshakeGuard(0)
	for i := 0; i < 1000; i++ {
		if !g.allow("1.2.3.4") {
			t.Fatal("a disabled guard throttled an attempt")
		}
	}
	var nilGuard *handshakeGuard
	if !nilGuard.allow("1.2.3.4") {
		t.Error("a nil guard throttled an attempt")
	}
}

// TestNoteHandshakeFailureWarnsOncePerWindow proves a failed handshake is
// visible at the default log level without letting a flood fill the log.
//
// The failure this guards against is diagnosability, not correctness: every
// handshake failure was logged only at Debug, so a relay whose clients could
// not complete a handshake — a path being interfered with, a PSK rotated on one
// side only — wrote nothing at all while its failure counter climbed. An
// operator watching a broken line had no log evidence to look at.
func TestNoteHandshakeFailureWarnsOncePerWindow(t *testing.T) {
	buf := logx.NewBuffer(64)
	log, err := logx.New(logx.Options{Level: slog.LevelInfo, Buffer: buf})
	if err != nil {
		t.Fatalf("logx.New: %v", err)
	}
	defer log.Close()

	s := &Server{log: log}
	h := &listenerHandle{cfg: config.Listener{Name: "relay-test", Transport: "tls"}}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// The first failure must warn immediately: waiting out an interval would
	// hide the very first sign of trouble.
	if n := s.noteHandshakeFailure(h, server, errors.New("boom")); n != 1 {
		t.Errorf("first failure reported %d folded failures, want 1", n)
	}
	// Further failures inside the window must be counted, not logged.
	for i := 0; i < 5; i++ {
		if n := s.noteHandshakeFailure(h, server, errors.New("boom")); n != 0 {
			t.Errorf("failure %d inside the window was logged (folded=%d), want it suppressed", i+2, n)
		}
	}
	warnings := 0
	for _, e := range buf.Snapshot(0) {
		if e.Level == "warn" && e.Message == "handshake failed" {
			warnings++
		}
	}
	if warnings != 1 {
		t.Errorf("emitted %d handshake-failure warnings for 6 failures, want exactly 1", warnings)
	}
	// The suppressed failures must not be lost: once the window elapses the
	// next warning reports how many were folded in.
	h.failLog.Store(time.Now().Add(-2 * handshakeFailureWarnInterval).UnixNano())
	if n := s.noteHandshakeFailure(h, server, errors.New("boom")); n != 6 {
		t.Errorf("warning after the window reported %d folded failures, want 6", n)
	}
}

// TestSemaphoreTryAcquire proves the connection cap refuses rather than blocks,
// because blocking the accept loop would stall the whole relay.
func TestSemaphoreTryAcquire(t *testing.T) {
	s := newSemaphore(2)
	if !s.tryAcquire() || !s.tryAcquire() {
		t.Fatal("the semaphore refused within its capacity")
	}
	if s.tryAcquire() {
		t.Error("the semaphore exceeded its capacity")
	}
	s.release()
	if !s.tryAcquire() {
		t.Error("the semaphore did not free a slot on release")
	}
	// Releasing more than was acquired must not panic or corrupt the count.
	s.release()
	s.release()
	s.release()
	if !s.tryAcquire() || !s.tryAcquire() {
		t.Error("the semaphore is inconsistent after over-release")
	}
}

// TestRateLimiterAllowsBurst proves the limiter permits a burst up to its
// capacity, because a strict per-byte limiter would cripple a bursty transfer.
func TestRateLimiterAllowsBurst(t *testing.T) {
	r := newRateLimiter(1024) // 1 MB/s
	if r == nil {
		t.Fatal("newRateLimiter returned nil for a positive rate")
	}
	// A quarter-second of capacity must be available immediately.
	start := nowMs()
	r.wait(256 * 1024)
	elapsed := nowMs() - start
	if elapsed > 100 {
		t.Errorf("a burst within the capacity took %d ms, expected no delay", elapsed)
	}
	if newRateLimiter(0) != nil {
		t.Error("a zero rate produced a limiter instead of nil")
	}
	// A nil limiter must be a no-op, which is how an unlimited relay is
	// configured.
	var nilLimiter *rateLimiter
	nilLimiter.wait(1 << 20)
}

// TestRateLimiterSustainsTheConfiguredRate proves a block larger than the
// bucket capacity is still delivered at the configured rate.
//
// The limiter clamps the bucket to a quarter-second of credit so an idle
// bucket cannot bank an unbounded burst. Applying that clamp to the refill
// earned *while the caller was already blocked* discarded the tokens it had
// waited for, so a write larger than the capacity advanced by only capacity
// bytes per second — a quarter of the configured rate. With the relay's 32 KiB
// copy buffer and a typical 8 KB/s account that turned a 14.6 s transfer into
// 57 s.
func TestRateLimiterSustainsTheConfiguredRate(t *testing.T) {
	const kbps = 8
	const chunk = 32768 // the relay's default copy buffer
	const total = 120000

	r := newRateLimiter(kbps)
	if r == nil {
		t.Fatal("newRateLimiter returned nil for a positive rate")
	}

	start := time.Now()
	for sent := 0; sent < total; sent += chunk {
		r.wait(chunk)
	}
	elapsed := time.Since(start)

	ideal := time.Duration(float64(total) / (float64(kbps) * 1024) * float64(time.Second))
	// Generous upper bound: the point is to catch a 4x throttle, not to pin
	// scheduler noise. Anything under 1.6x of ideal means the bucket is not
	// throwing away the credit earned during a wait.
	if limit := ideal * 16 / 10; elapsed > limit {
		t.Errorf("throttling %d bytes in %d-byte blocks at %d KB/s took %v, want about %v "+
			"(the refill earned while blocked is being clamped to the bucket capacity)",
			total, chunk, kbps, elapsed.Round(time.Millisecond), ideal.Round(time.Millisecond))
	}
}

// TestIsBenignNetErr proves ordinary shutdown errors are not logged as faults,
// so a relay's log stays readable.
func TestIsBenignNetErr(t *testing.T) {
	if !isBenignNetErr(nil) {
		t.Error("nil was not treated as benign")
	}
	if !isBenignNetErr(io.EOF) {
		t.Error("io.EOF was not treated as benign")
	}
	if !isBenignNetErr(net.ErrClosed) {
		t.Error("net.ErrClosed was not treated as benign")
	}
	if isBenignNetErr(errors.New("connection refused")) {
		t.Error("a real error was treated as benign")
	}
}

// --- helpers ---

func targetHost(target string) string {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return target
	}
	return host
}

// reqFor builds the minimal Request the forward matcher inspects.
func reqFor(transportName, clientID string) *transport.Request {
	return &transport.Request{Transport: transportName, ClientID: clientID}
}

func nameOf(f *config.Forward) string {
	if f == nil {
		return "<nil>"
	}
	return f.Name
}

// nowMs returns the current monotonic time in milliseconds, used to assert
// that a burst within the limiter's capacity is not delayed.
func nowMs() int64 { return time.Now().UnixMilli() }
