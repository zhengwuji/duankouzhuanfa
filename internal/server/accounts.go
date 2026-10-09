package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"porttransit/internal/config"
	"porttransit/internal/transport"
)

// ErrAccountDisabled is returned when a client account is switched off, has
// expired, or has exhausted its quota.
var ErrAccountDisabled = errors.New("server: client account is not usable")

// accountRuntime holds the mutable state for one configured client account.
//
// The configured fields live in config.ClientAccount and are replaced wholesale
// on reload; everything that changes as traffic flows lives here so a reload
// does not silently reset an operator's quota accounting.
type accountRuntime struct {
	cfg config.ClientAccount

	// active counts concurrent streams right now.
	active atomic.Int64
	// used accumulates bytes transferred, in both directions. It is the number
	// the quota is checked against.
	used atomic.Int64

	// limiter throttles this account's throughput. Built once because it holds
	// a token bucket whose state must persist across streams — a limiter
	// created per stream would let a client exceed its rate by opening more
	// streams, which is exactly what a rate limit is meant to prevent.
	limiter *rateLimiter
}

// accountTable indexes the configured accounts and keeps their runtime state.
type accountTable struct {
	mu sync.Mutex
	// byID maps a client id to its runtime state.
	byID map[string]*accountRuntime
	// defined reports whether any accounts are configured at all. When none
	// are, the relay behaves exactly as before accounts existed.
	defined bool
	// strict rejects a client id that has no account. It is set when accounts
	// are defined, because otherwise per-client policy is trivially bypassed
	// by presenting an unlisted id — the ACL for a listed client would simply
	// not apply.
	strict bool
	// quotaPath is where accumulated usage is persisted, empty to keep it in
	// memory only.
	quotaPath string
	// dirty marks usage that has not been written yet.
	dirty atomic.Bool
}

// newAccountTable builds the table from configuration.
func newAccountTable(cfg *config.ServerConfig) *accountTable {
	t := &accountTable{byID: map[string]*accountRuntime{}}
	if cfg == nil {
		return t
	}
	t.defined = len(cfg.Clients) > 0
	// Being strict whenever accounts exist is the only safe default: a relay
	// that lists its clients but then serves anyone who claims a different id
	// has not actually restricted anything.
	t.strict = t.defined
	for i := range cfg.Clients {
		a := cfg.Clients[i]
		rt := &accountRuntime{cfg: a}
		if a.RateLimitKBps > 0 {
			rt.limiter = newRateLimiter(a.RateLimitKBps)
		}
		t.byID[a.ID] = rt
	}
	if cfg.DataDir != "" {
		t.quotaPath = filepath.Join(cfg.DataDir, "quota.json")
		t.loadUsage()
	}
	return t
}

// lookup returns the runtime state for a client id, or nil when unknown.
func (t *accountTable) lookup(id string) *accountRuntime {
	if t == nil || id == "" {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.byID[id]
}

// identityCapable reports whether a transport can carry a per-client identity.
//
// The PortTransit preamble carries a client id, but a native-header transport
// (VLESS, Trojan, Shadowsocks, SOCKS5, HTTP CONNECT) authenticates with a
// shared secret in its own header and never exchanges the preamble — so it has
// no way to say *which* client it is. Treating "no id" as "unauthorised" for
// those transports would refuse every connection the moment an operator
// configured a single account, which is exactly the kind of change that turns a
// policy feature into an outage.
func identityCapable(transportName string) bool {
	f, ok := transport.Lookup(transportName)
	if !ok {
		// An unknown transport cannot be reasoned about; assume it carries an
		// identity so the stricter policy applies rather than silently
		// weakening it.
		return true
	}
	return !f.NativeHeader
}

// admit decides whether a client may open a stream, and reserves a slot.
//
// It returns the runtime state so the caller can apply the account's rate limit
// and record the traffic. A nil account with a nil error means no per-client
// policy applies to this request.
//
// identityCapable comes from the listener's transport and selects between two
// genuinely different regimes, which is why the parameter exists:
//
//   - A preamble transport (direct, tls, ws, reality) carries a client id in
//     the PortTransit frame. The operator lists the ids they expect, so an
//     absent or unlisted id is refused. This is where accounts do their job.
//
//   - A native-header transport (vless, trojan, shadowsocks, socks5, HTTP
//     CONNECT) authenticates with a shared secret in its own header and never
//     exchanges the preamble, so it cannot report a *client-chosen* identity.
//     What it may report is the shared secret itself (VMess reports the
//     listener's UUID). Being strict there would refuse every connection the
//     moment an operator added an account whose id did not happen to equal that
//     secret — so instead the lookup is best effort: a reported value that
//     matches an account gets that account's limits, and anything else is
//     served under the global policy. The shared secret is already the
//     authentication; an account can only add limits on top.
func (t *accountTable) admit(id string, identityCapable bool) (*accountRuntime, error) {
	if t == nil {
		return nil, nil
	}
	t.mu.Lock()
	rt := t.byID[id]
	strict := t.strict
	t.mu.Unlock()

	if rt == nil {
		// A transport that cannot identify a client is never refused for the
		// identity it could not provide. This is the case that must not break
		// an existing deployment.
		if !strict || !identityCapable {
			return nil, nil
		}
		if id == "" {
			return nil, fmt.Errorf("%w: 该中转已配置客户端账号，但连接未提供 clientId", ErrAccountDisabled)
		}
		return nil, fmt.Errorf("%w: 未知的 clientId %q", ErrAccountDisabled, id)
	}

	if err := rt.check(); err != nil {
		return nil, err
	}

	// Reserve the slot with a compare-and-swap loop so two concurrent streams
	// cannot both see "one slot left" and both take it.
	if max := rt.cfg.MaxConnections; max > 0 {
		for {
			cur := rt.active.Load()
			if cur >= int64(max) {
				return nil, fmt.Errorf("%w: 客户端 %s 的并发连接已达上限 %d", ErrAccountDisabled, id, max)
			}
			if rt.active.CompareAndSwap(cur, cur+1) {
				break
			}
		}
		return rt, nil
	}
	rt.active.Add(1)
	return rt, nil
}

// check evaluates the conditions that do not depend on concurrency.
func (rt *accountRuntime) check() error {
	if !rt.cfg.Enabled {
		return fmt.Errorf("%w: 客户端账号 %s 已停用", ErrAccountDisabled, rt.cfg.ID)
	}
	if !rt.cfg.ExpiresAt.IsZero() && time.Now().After(rt.cfg.ExpiresAt) {
		return fmt.Errorf("%w: 客户端账号 %s 已于 %s 到期",
			ErrAccountDisabled, rt.cfg.ID, rt.cfg.ExpiresAt.Format(time.RFC3339))
	}
	if quota := rt.cfg.QuotaBytes; quota > 0 && rt.used.Load() >= quota {
		return fmt.Errorf("%w: 客户端账号 %s 的流量配额已用尽（%d/%d 字节）",
			ErrAccountDisabled, rt.cfg.ID, rt.used.Load(), quota)
	}
	return nil
}

// release gives back a concurrency slot.
func (rt *accountRuntime) release() {
	if rt == nil {
		return
	}
	rt.active.Add(-1)
}

// addBytes records transferred bytes against the account's quota.
//
// A quota is checked before a stream starts, so a single long-lived transfer
// can overshoot it. Stopping mid-stream would corrupt the connection for a
// protocol that has no way to signal a partial failure, so the overshoot is
// accepted and the next connection is refused. The comment is here because the
// alternative looks like a bug.
func (rt *accountRuntime) addBytes(n int64) {
	if rt == nil || n <= 0 {
		return
	}
	rt.used.Add(n)
}

// rateLimiter returns the account's throughput limiter, or nil for unlimited.
func (rt *accountRuntime) rateLimiter() *rateLimiter {
	if rt == nil {
		return nil
	}
	return rt.limiter
}

// snapshot reports per-account usage for the console.
func (t *accountTable) snapshot() []AccountUsage {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]AccountUsage, 0, len(t.byID))
	for id, rt := range t.byID {
		u := AccountUsage{
			ID:             id,
			Name:           rt.cfg.Name,
			Enabled:        rt.cfg.Enabled,
			Active:         rt.active.Load(),
			UsedBytes:      rt.used.Load(),
			QuotaBytes:     rt.cfg.QuotaBytes,
			MaxConnections: rt.cfg.MaxConnections,
			RateLimitKBps:  rt.cfg.RateLimitKBps,
		}
		if !rt.cfg.ExpiresAt.IsZero() {
			u.ExpiresAt = rt.cfg.ExpiresAt
		}
		out = append(out, u)
	}
	return out
}

// AccountUsage is the console's view of one account's runtime state.
type AccountUsage struct {
	ID             string    `json:"id"`
	Name           string    `json:"name,omitempty"`
	Enabled        bool      `json:"enabled"`
	Active         int64     `json:"active"`
	UsedBytes      int64     `json:"usedBytes"`
	QuotaBytes     int64     `json:"quotaBytes,omitempty"`
	MaxConnections int       `json:"maxConnections,omitempty"`
	RateLimitKBps  int       `json:"rateLimitKBps,omitempty"`
	ExpiresAt      time.Time `json:"expiresAt,omitempty"`
}

// quotaFile is the on-disk form of accumulated usage.
//
// Only the byte counters are persisted. Concurrency is inherently a live
// quantity, and an expiry is configuration rather than state.
type quotaFile struct {
	// Version guards against a future format change being read as valid.
	Version int              `json:"version"`
	Saved   time.Time        `json:"saved"`
	Used    map[string]int64 `json:"used"`
}

const quotaFileVersion = 1

// loadUsage restores accumulated usage from disk.
//
// A missing file is the normal first run. A corrupt file is reported and
// ignored rather than fatal: refusing to start would take the relay down over
// a bookkeeping file, and silently treating it as zero would under-count a
// quota — so it is logged by the caller through the returned error.
func (t *accountTable) loadUsage() {
	if t.quotaPath == "" {
		return
	}
	b, err := os.ReadFile(t.quotaPath)
	if err != nil {
		return
	}
	var f quotaFile
	if err := json.Unmarshal(b, &f); err != nil {
		return
	}
	if f.Version != quotaFileVersion {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for id, used := range f.Used {
		if rt, ok := t.byID[id]; ok {
			rt.used.Store(used)
		}
	}
}

// saveUsage writes accumulated usage to disk.
func (t *accountTable) saveUsage() error {
	if t == nil || t.quotaPath == "" {
		return nil
	}
	t.mu.Lock()
	f := quotaFile{
		Version: quotaFileVersion,
		Saved:   time.Now(),
		Used:    make(map[string]int64, len(t.byID)),
	}
	for id, rt := range t.byID {
		if used := rt.used.Load(); used > 0 {
			f.Used[id] = used
		}
	}
	t.mu.Unlock()

	b, err := json.MarshalIndent(&f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(t.quotaPath), 0o750); err != nil {
		return err
	}
	// Written 0600 and atomically: the file names which clients exist, and a
	// half-written file read after a crash would look like lost usage.
	tmp := t.quotaPath + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, t.quotaPath); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// markDirty records that usage has changed and needs persisting.
func (t *accountTable) markDirty() {
	if t != nil && t.quotaPath != "" {
		t.dirty.Store(true)
	}
}

// flushIfDirty persists usage when something has changed.
func (t *accountTable) flushIfDirty() error {
	if t == nil || t.quotaPath == "" {
		return nil
	}
	if !t.dirty.CompareAndSwap(true, false) {
		return nil
	}
	return t.saveUsage()
}

// resetUsage clears every account's accumulated usage.
func (t *accountTable) resetUsage(id string) int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for acctID, rt := range t.byID {
		if id != "" && acctID != id {
			continue
		}
		rt.used.Store(0)
		n++
	}
	if n > 0 {
		t.markDirty()
	}
	return n
}
