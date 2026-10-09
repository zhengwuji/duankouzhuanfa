package client

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"porttransit/internal/config"
	"porttransit/internal/logx"
)

// TestPoolSetIndexesGroups proves relays are indexed by id and by group, which
// is what the tunnel and proxy selectors depend on.
func TestPoolSetIndexesGroups(t *testing.T) {
	p := newPoolSet([]config.ServerEntry{
		{ID: "a", Name: "A", Address: "a:1", Transport: "tls", Enabled: true, Group: "primary"},
		{ID: "b", Name: "B", Address: "b:1", Transport: "tls", Enabled: true, Group: "primary"},
		{ID: "c", Name: "C", Address: "c:1", Transport: "tls", Enabled: true, Group: "backup"},
		{ID: "d", Name: "D", Address: "d:1", Transport: "tls", Enabled: true},
	})

	if len(p.Entries()) != 4 {
		t.Fatalf("pool holds %d entries, want 4", len(p.Entries()))
	}
	if _, ok := p.ByID("a"); !ok {
		t.Error("relay a was not indexed by id")
	}
	if _, ok := p.ByID("missing"); ok {
		t.Error("ByID returned an entry for an unknown id")
	}
	if got := len(p.groups["primary"]); got != 2 {
		t.Errorf("group primary holds %d relays, want 2", got)
	}
	if got := len(p.groups["backup"]); got != 1 {
		t.Errorf("group backup holds %d relays, want 1", got)
	}
	// A relay with no group must not appear in any group.
	for _, e := range p.groups[""] {
		if e.ID == "d" {
			t.Error("a relay with an empty group was indexed into the empty group")
		}
	}
}

// TestCandidatesPinsToNamedServer proves a tunnel naming one relay uses only
// that relay, because an operator who pins a relay expects it to be used.
func TestCandidatesPinsToNamedServer(t *testing.T) {
	p := newPoolSet([]config.ServerEntry{
		{ID: "a", Address: "a:1", Transport: "tls", Enabled: true, Group: "g"},
		{ID: "b", Address: "b:1", Transport: "tls", Enabled: true, Group: "g"},
	})

	got, err := p.candidates("b", "", "")
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	if len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("candidates returned %d relays, want only b", len(got))
	}

	// A disabled named relay must be refused rather than silently substituted,
	// because using a different relay than the operator asked for could route
	// traffic through a country they did not intend.
	p.byID["b"].Enabled = false
	if _, err := p.candidates("b", "", ""); err == nil {
		t.Error("a disabled named relay was accepted")
	}
	if _, err := p.candidates("nope", "", ""); err == nil {
		t.Error("an unknown named relay was accepted")
	}
}

// TestCandidatesPrefersHealthy proves unhealthy relays are avoided while at
// least one healthy relay exists, which is the whole point of health checking.
func TestCandidatesPrefersHealthy(t *testing.T) {
	p := newPoolSet([]config.ServerEntry{
		{ID: "a", Address: "a:1", Transport: "tls", Enabled: true, Group: "g"},
		{ID: "b", Address: "b:1", Transport: "tls", Enabled: true, Group: "g"},
	})

	p.byID["a"].mu.Lock()
	p.byID["a"].healthy = false
	p.byID["a"].mu.Unlock()

	got, err := p.candidates("", "g", "first")
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	if len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("candidates returned %v, want only the healthy relay b", idsOf(got))
	}
}

// TestCandidatesFallsBackToUnhealthy proves a stale health verdict cannot make
// a tunnel unusable: when every relay in a group is marked down they are all
// offered anyway, because the operator can see the relay is up.
func TestCandidatesFallsBackToUnhealthy(t *testing.T) {
	p := newPoolSet([]config.ServerEntry{
		{ID: "a", Address: "a:1", Transport: "tls", Enabled: true, Group: "g"},
		{ID: "b", Address: "b:1", Transport: "tls", Enabled: true, Group: "g"},
	})
	for _, e := range p.Entries() {
		e.mu.Lock()
		e.healthy = false
		e.mu.Unlock()
	}

	got, err := p.candidates("", "g", "first")
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("candidates returned %d relays, want both even though unhealthy", len(got))
	}
}

// TestCandidatesRejectsEmptyGroup proves a tunnel naming a group that does not
// exist is reported rather than silently using every relay.
func TestCandidatesRejectsEmptyGroup(t *testing.T) {
	p := newPoolSet([]config.ServerEntry{
		{ID: "a", Address: "a:1", Transport: "tls", Enabled: true},
	})
	if _, err := p.candidates("", "nope", ""); err == nil {
		t.Error("an unknown group was accepted")
	}
}

// TestOrderByBalanceLeastLatency proves an unmeasured relay sorts last, so the
// first connection uses a relay known to be fast rather than gambling.
func TestOrderByBalanceLeastLatency(t *testing.T) {
	mk := func(id string, ms int64, valid bool) *serverEntry {
		e := newServerEntry(config.ServerEntry{ID: id, Address: id + ":1", Transport: "tls", Enabled: true})
		if valid {
			e.observeLatency(time.Duration(ms) * time.Millisecond)
		}
		return e
	}
	entries := []*serverEntry{
		mk("unmeasured", 0, false),
		mk("slow", 300, true),
		mk("fast", 20, true),
	}

	got := orderByBalance(entries, "least-latency")
	if got[0].ID != "fast" {
		t.Errorf("the fastest relay is %q, want fast", got[0].ID)
	}
	if got[1].ID != "slow" {
		t.Errorf("the second relay is %q, want slow", got[1].ID)
	}
	if got[2].ID != "unmeasured" {
		t.Errorf("the last relay is %q, want the unmeasured one", got[2].ID)
	}
}

// TestOrderByBalanceDefaultKeepsOrder proves the default strategy preserves
// configuration order, which is what an operator expects when they list a
// primary then a backup.
func TestOrderByBalanceDefaultKeepsOrder(t *testing.T) {
	entries := []*serverEntry{
		newServerEntry(config.ServerEntry{ID: "first", Address: "a:1", Transport: "tls", Enabled: true}),
		newServerEntry(config.ServerEntry{ID: "second", Address: "b:1", Transport: "tls", Enabled: true}),
		newServerEntry(config.ServerEntry{ID: "third", Address: "c:1", Transport: "tls", Enabled: true}),
	}
	for _, strategy := range []string{"", "first", "unknown-strategy"} {
		got := orderByBalance(entries, strategy)
		if got[0].ID != "first" || got[1].ID != "second" || got[2].ID != "third" {
			t.Errorf("strategy %q reordered the relays: %v", strategy, idsOf(got))
		}
	}
}

// TestOrderByBalanceDoesNotMutateInput proves the ordering works on a copy, so
// a balance strategy cannot permanently reorder the configured pool.
func TestOrderByBalanceDoesNotMutateInput(t *testing.T) {
	entries := []*serverEntry{
		newServerEntry(config.ServerEntry{ID: "a", Address: "a:1", Transport: "tls", Enabled: true}),
		newServerEntry(config.ServerEntry{ID: "b", Address: "b:1", Transport: "tls", Enabled: true}),
		newServerEntry(config.ServerEntry{ID: "c", Address: "c:1", Transport: "tls", Enabled: true}),
	}
	before := idsOf(entries)

	_ = orderByBalance(entries, "random")
	_ = orderByBalance(entries, "least-latency")

	if after := idsOf(entries); after != before {
		t.Errorf("the input slice was reordered: %v -> %v", before, after)
	}
}

// TestOrderByBalanceRandomPermutesAllEntries proves shuffling never drops or
// duplicates a relay, which a buggy index would do.
func TestOrderByBalanceRandomPermutesAllEntries(t *testing.T) {
	entries := []*serverEntry{
		newServerEntry(config.ServerEntry{ID: "a", Address: "a:1", Transport: "tls", Enabled: true}),
		newServerEntry(config.ServerEntry{ID: "b", Address: "b:1", Transport: "tls", Enabled: true}),
		newServerEntry(config.ServerEntry{ID: "c", Address: "c:1", Transport: "tls", Enabled: true}),
		newServerEntry(config.ServerEntry{ID: "d", Address: "d:1", Transport: "tls", Enabled: true}),
	}
	for i := 0; i < 50; i++ {
		got := orderByBalance(entries, "random")
		if len(got) != 4 {
			t.Fatalf("shuffle produced %d entries, want 4", len(got))
		}
		seen := map[string]bool{}
		for _, e := range got {
			if seen[e.ID] {
				t.Fatalf("shuffle duplicated %q", e.ID)
			}
			seen[e.ID] = true
		}
	}
}

// TestRecordProbeHysteresis proves a single failure does not retire a relay
// and a single success does not restore it, which is what stops a flapping
// link from oscillating the active relay.
func TestRecordProbeHysteresis(t *testing.T) {
	e := newServerEntry(config.ServerEntry{ID: "a", Address: "a:1", Transport: "tls", Enabled: true})
	e.failThreshold = 3
	e.successThreshold = 2

	// A relay starts optimistic.
	if !e.isHealthy() {
		t.Fatal("a new relay starts unhealthy, which would block traffic at startup")
	}

	// One failure is noise.
	e.recordProbe(false, errors.New("timeout"), 0)
	if !e.isHealthy() {
		t.Error("one failure retired the relay")
	}
	e.recordProbe(false, errors.New("timeout"), 0)
	if !e.isHealthy() {
		t.Error("two failures retired the relay before the threshold of three")
	}
	e.recordProbe(false, errors.New("timeout"), 0)
	if e.isHealthy() {
		t.Error("three failures did not retire the relay")
	}

	// One success is not enough to restore it.
	e.recordProbe(true, nil, 10*time.Millisecond)
	if e.isHealthy() {
		t.Error("one success restored a retired relay before the threshold of two")
	}
	e.recordProbe(true, nil, 10*time.Millisecond)
	if !e.isHealthy() {
		t.Error("two successes did not restore the relay")
	}
}

// TestRecordProbeResetsFailureCount proves a success clears the failure run,
// so intermittent failures do not accumulate into a false retirement.
func TestRecordProbeResetsFailureCount(t *testing.T) {
	e := newServerEntry(config.ServerEntry{ID: "a", Address: "a:1", Transport: "tls", Enabled: true})
	e.failThreshold = 3

	e.recordProbe(false, errors.New("x"), 0)
	e.recordProbe(false, errors.New("x"), 0)
	e.recordProbe(true, nil, time.Millisecond)
	e.recordProbe(false, errors.New("x"), 0)
	e.recordProbe(false, errors.New("x"), 0)

	if !e.isHealthy() {
		t.Error("two failures after a success retired the relay, so the failure run was not reset")
	}
}

// TestRecordProbeLatency proves a successful probe records its round trip and
// a failure does not overwrite the last known value with a bogus one.
func TestRecordProbeLatency(t *testing.T) {
	e := newServerEntry(config.ServerEntry{ID: "a", Address: "a:1", Transport: "tls", Enabled: true})
	e.failThreshold = 1

	e.recordProbe(true, nil, 42*time.Millisecond)
	if got := e.latencyMs.Load(); got != 42 {
		t.Errorf("recorded latency = %d ms, want 42", got)
	}
	if !e.latencyValid.Load() {
		t.Error("the latency was not marked valid")
	}

	e.recordProbe(false, errors.New("boom"), 0)
	if got := e.latencyMs.Load(); got != 42 {
		t.Errorf("a failed probe overwrote the last latency with %d ms", got)
	}
}

// TestServerEntrySettingsFillsStandardKeys proves the server name and client id
// are injected into the transport settings, which is what makes the generic
// transport code work without every transport knowing about them.
func TestServerEntrySettingsFillsStandardKeys(t *testing.T) {
	e := newServerEntry(config.ServerEntry{
		ID:         "a",
		Address:    "a:1",
		Transport:  "tls",
		Enabled:    true,
		ServerName: "sni.example.com",
		ClientID:   "client-1",
		Settings:   map[string]any{"insecure": true},
	})

	s := e.settings()
	if s["serverName"] != "sni.example.com" {
		t.Errorf("serverName = %v, want sni.example.com", s["serverName"])
	}
	if s["clientID"] != "client-1" {
		t.Errorf("clientID = %v, want client-1", s["clientID"])
	}
	if s["insecure"] != true {
		t.Errorf("the configured setting was lost: %v", s["insecure"])
	}

	// An explicit setting must win over the derived one, so an operator can
	// override the default without editing the entry fields.
	e.Settings["serverName"] = "explicit.example.com"
	s2 := e.settings()
	if s2["serverName"] != "explicit.example.com" {
		t.Errorf("serverName = %v, want the explicit value to win", s2["serverName"])
	}
}

// TestPoolValidateRejectsUnknownTransport proves a typo in a transport name is
// caught at startup rather than surfacing as a per-request error much later.
func TestPoolValidateRejectsUnknownTransport(t *testing.T) {
	p := newPoolSet([]config.ServerEntry{
		{ID: "a", Address: "a:1", Transport: "not-a-real-transport", Enabled: true},
	})
	if err := p.validate(); err == nil {
		t.Error("an unknown transport name was accepted")
	}

	p2 := newPoolSet([]config.ServerEntry{
		{ID: "a", Address: "", Transport: "tls", Enabled: true},
	})
	if err := p2.validate(); err == nil {
		t.Error("a relay with no address was accepted")
	}

	// A disabled relay must not block startup, because an operator disables a
	// relay precisely to take it out of service.
	p3 := newPoolSet([]config.ServerEntry{
		{ID: "a", Address: "a:1", Transport: "not-a-real-transport", Enabled: false},
	})
	if err := p3.validate(); err != nil {
		t.Errorf("a disabled relay blocked validation: %v", err)
	}
}

// TestDecideRoutingRules proves the block, direct and proxy lists are applied
// in the documented order, because a wrong order would leak traffic that the
// operator intended to route differently.
func TestDecideRoutingRules(t *testing.T) {
	c := &Client{cfg: &config.ClientConfig{
		Proxy: config.LocalProxyConfig{
			Enabled:     true,
			BlockRules:  []string{"ads.example.com"},
			DirectRules: []string{".cn", "localhost"},
		},
	}}

	cases := []struct {
		target string
		want   decision
	}{
		{"ads.example.com:443", decisionBlock},
		{"www.example.cn:443", decisionDirect},
		{"localhost:8080", decisionDirect},
		{"example.com:443", decisionProxy},
		{"8.8.8.8:53", decisionProxy},
	}
	for _, tc := range cases {
		if got := c.decide(tc.target); got != tc.want {
			t.Errorf("decide(%q) = %v, want %v", tc.target, got, tc.want)
		}
	}

	// A block rule must win over a direct rule for the same host, since an
	// operator who blocks a host expects it blocked.
	c.cfg.Proxy.DirectRules = append(c.cfg.Proxy.DirectRules, "ads.example.com")
	if got := c.decide("ads.example.com:443"); got != decisionBlock {
		t.Errorf("decide on a host in both lists = %v, want block", got)
	}
}

// TestDecideProxyRulesAreAllowList proves a non-empty proxy list routes
// everything not on it directly rather than dropping it, because dropping
// would look like a network outage to the user.
func TestDecideProxyRulesAreAllowList(t *testing.T) {
	c := &Client{cfg: &config.ClientConfig{
		Proxy: config.LocalProxyConfig{
			Enabled:    true,
			ProxyRules: []string{"only.example.com"},
		},
	}}

	if got := c.decide("only.example.com:443"); got != decisionProxy {
		t.Errorf("decide on a listed host = %v, want proxy", got)
	}
	if got := c.decide("other.example.com:443"); got != decisionDirect {
		t.Errorf("decide on an unlisted host = %v, want direct", got)
	}
}

// TestMatchRuleForms proves the routing pattern syntax matches the relay's ACL
// syntax, so an operator learns one form.
func TestMatchRuleForms(t *testing.T) {
	cases := []struct {
		pattern string
		target  string
		want    bool
	}{
		{"example.com:443", "example.com:443", true},
		{"example.com:443", "example.com:80", false},
		{"example.com", "example.com:80", true},
		{".example.com", "a.example.com:443", true},
		{".example.com", "example.com:443", true},
		{".example.com", "notexample.com:443", false},
		{"", "example.com:443", false},
	}
	for _, tc := range cases {
		host := tc.target
		if h, _, err := net.SplitHostPort(tc.target); err == nil {
			host = h
		}
		if got := matchRule(tc.pattern, tc.target, host); got != tc.want {
			t.Errorf("matchRule(%q, %q) = %v, want %v", tc.pattern, tc.target, got, tc.want)
		}
	}
}

// TestTunnelStatusesTolerateUnstartedClient proves the status API works before
// Start, which the console calls on a client whose listener has not bound yet.
func TestTunnelStatusesTolerateUnstartedClient(t *testing.T) {
	cfg := config.Default(config.ModeClient)
	cfg.Client.Tunnels = []config.Tunnel{
		{Name: "t1", Enabled: true, Listen: "127.0.0.1:1", Target: "x:1"},
		{Name: "t2", Enabled: false, Listen: "127.0.0.1:2", Target: "y:2"},
	}

	c, err := New(cfg.Client, logx.Discard())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	statuses := c.TunnelStatuses()
	if len(statuses) != 2 {
		t.Fatalf("reported %d tunnels, want 2", len(statuses))
	}
	for _, st := range statuses {
		if st.Active != 0 || st.Accepted != 0 {
			t.Errorf("tunnel %s reports traffic before it started: %+v", st.Name, st)
		}
		if st.Listen == "" {
			t.Errorf("tunnel %s reports no listen address", st.Name)
		}
	}

	// The proxy status must also be safe before Start.
	ps := c.ProxyStatus()
	if ps.SOCKS5 != "" || ps.HTTP != "" {
		t.Errorf("proxy status reports endpoints before Start: %+v", ps)
	}
}

// TestStartRejectsUnknownTransport proves a client with a typo in a transport
// name fails at Start rather than accepting connections it cannot serve.
func TestStartRejectsUnknownTransport(t *testing.T) {
	cfg := config.Default(config.ModeClient)
	cfg.Client.Servers = []config.ServerEntry{
		{ID: "a", Address: "127.0.0.1:1", Transport: "definitely-not-real", Enabled: true},
	}
	cfg.Client.Proxy.Enabled = false
	cfg.Client.Health.Enabled = false

	c, err := New(cfg.Client, logx.Discard())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("Start accepted a client with an unknown transport")
	}
	c.Stop()
}

// TestStopIsIdempotent proves Stop can be called twice, because both the
// signal handler and a deferred call may run it.
func TestStopIsIdempotent(t *testing.T) {
	cfg := config.Default(config.ModeClient)
	cfg.Client.Proxy.Enabled = false
	cfg.Client.Health.Enabled = false

	c, err := New(cfg.Client, logx.Discard())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Stop()
		}()
	}
	wg.Wait()
}

// TestShuffleIsNotIdentity proves the shuffle actually permutes, since a
// no-op shuffle would silently pin every request to one relay.
func TestShuffleIsNotIdentity(t *testing.T) {
	entries := make([]*serverEntry, 8)
	for i := range entries {
		id := string(rune('a' + i))
		entries[i] = newServerEntry(config.ServerEntry{ID: id, Address: id + ":1", Transport: "tls", Enabled: true})
	}
	before := idsOf(entries)

	changed := false
	for i := 0; i < 20; i++ {
		shuffle(entries)
		if idsOf(entries) != before {
			changed = true
			break
		}
	}
	if !changed {
		t.Error("shuffle produced the same order twenty times, so it is not permuting")
	}
}

// idsOf renders a relay slice as a comparable string for assertions.
func idsOf(entries []*serverEntry) string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.ID
	}
	return joinIDs(out)
}

func joinIDs(ids []string) string {
	s := ""
	for i, id := range ids {
		if i > 0 {
			s += ","
		}
		s += id
	}
	return s
}
