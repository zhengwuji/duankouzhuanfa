// Package client implements the PortTransit client: the 客户端 side that opens
// encrypted tunnels to a relay and exposes them locally.
//
// # What the client does
//
//	local app ──▶ [local listener] ──▶ [transport] ──▶ relay ──▶ final target
//
// Two kinds of local listener are provided:
//
//   - A tunnel: a fixed local port that always forwards to one target through
//     one relay. This is the "port forwarding" case and is what an operator
//     configures when they want, for example, a Japanese endpoint reached
//     through a Shanghai relay.
//   - A proxy: a local SOCKS5 and/or HTTP proxy that accepts any destination
//     and forwards it through the relay. This is the "browse through the
//     relay" case.
//
// # Relay selection
//
// Relays may be grouped. Within a group the client applies a balance strategy
// and, when health checking is on, automatically avoids relays that have
// failed. That is what makes a multi-hop path resilient: if the Shanghai relay
// goes down, traffic moves to the backup without the operator touching
// anything.
package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"porttransit/internal/config"
	"porttransit/internal/logx"
	"porttransit/internal/transport"
)

// Client is a running PortTransit client.
type Client struct {
	cfg   *config.ClientConfig
	log   *logx.Logger
	stats *Stats
	pools *poolSet

	mu      sync.Mutex
	tunnels map[string]*tunnelHandle
	proxy   *proxyHandle
	health  *healthChecker
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	started atomic.Bool
}

// tunnelHandle is one bound local forwarding listener.
//
// Exactly one of ln and pc is set: a TCP tunnel has a listener, a UDP tunnel
// has a packet connection. Keeping both on one handle means the status API,
// the counters and the shutdown path do not have to special-case UDP.
type tunnelHandle struct {
	cfg      config.Tunnel
	ln       net.Listener
	pc       net.PacketConn
	conns    atomic.Int64
	accepted atomic.Int64
	failed   atomic.Int64
}

// close releases whichever socket the tunnel bound.
func (h *tunnelHandle) close() {
	if h.ln != nil {
		_ = h.ln.Close()
	}
	if h.pc != nil {
		_ = h.pc.Close()
	}
}

// listenAddr reports the bound address, or an empty string before binding.
func (h *tunnelHandle) listenAddr() string {
	if h.ln != nil {
		return h.ln.Addr().String()
	}
	if h.pc != nil {
		return h.pc.LocalAddr().String()
	}
	return ""
}

// proxyHandle is the local SOCKS5/HTTP proxy pair.
type proxyHandle struct {
	socks5 net.Listener
	http   net.Listener
}

// New builds a client from configuration.
func New(cfg *config.ClientConfig, log *logx.Logger) (*Client, error) {
	if cfg == nil {
		return nil, errors.New("client: config is nil")
	}
	if log == nil {
		log = logx.Discard()
	}

	c := &Client{
		cfg:     cfg,
		log:     log.Component("client"),
		stats:   NewStats(),
		pools:   newPoolSet(cfg.Servers),
		tunnels: map[string]*tunnelHandle{},
	}
	return c, nil
}

// Stats returns the client's counters.
func (c *Client) Stats() *Stats { return c.stats }

// Pools exposes the relay pools so the Web GUI can display health and latency.
func (c *Client) Pools() *poolSet { return c.pools }

// Start binds every enabled tunnel and the local proxy, then begins health
// checking.
func (c *Client) Start(ctx context.Context) error {
	if !c.started.CompareAndSwap(false, true) {
		return errors.New("client: already started")
	}
	c.ctx, c.cancel = context.WithCancel(ctx)

	// Validate every enabled relay can be built before binding anything, so a
	// typo in a transport name fails fast instead of surfacing as a per-request
	// error much later.
	if err := c.pools.validate(); err != nil {
		c.started.Store(false)
		return err
	}

	var started int
	for _, t := range c.cfg.Tunnels {
		if !t.Enabled {
			continue
		}
		if err := c.startTunnel(t); err != nil {
			c.Stop()
			return fmt.Errorf("client: tunnel %s: %w", t.Name, err)
		}
		started++
	}

	if c.cfg.Proxy.Enabled {
		if err := c.startProxy(); err != nil {
			c.Stop()
			return fmt.Errorf("client: local proxy: %w", err)
		}
	}

	if c.cfg.Health.Enabled && len(c.cfg.Servers) > 0 {
		c.pools.setHealthThresholds(c.cfg.Health)
		c.health = newHealthChecker(c.cfg.Health, c.pools, c.log)
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.health.run(c.ctx)
		}()
	}

	c.log.Info("client started", "tunnels", started, "servers", len(c.cfg.Servers))
	return nil
}

// startTunnel binds one local forwarding listener.
func (c *Client) startTunnel(t config.Tunnel) error {
	// A UDP tunnel is a datagram path, not a stream: it needs a packet
	// connection and a per-source flow table rather than an accept loop.
	// Binding it with net.Listen would fail outright, so the two cases are
	// separated here rather than deeper in the call chain.
	if t.Network == "udp" {
		return c.startUDPTunnel(t)
	}

	network := t.Network
	if network == "" || network == "both" {
		network = "tcp"
	}
	ln, err := net.Listen(network, t.Listen)
	if err != nil {
		return fmt.Errorf("bind %s: %w", t.Listen, err)
	}

	h := &tunnelHandle{cfg: t, ln: ln}
	c.mu.Lock()
	c.tunnels[t.Name] = h
	c.mu.Unlock()

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.acceptTunnel(h)
	}()

	c.log.Info("tunnel listening",
		"tunnel", t.Name,
		"listen", ln.Addr().String(),
		"target", t.Target,
		"server", t.Server,
		"group", t.Group,
	)
	return nil
}

// startUDPTunnel binds a local UDP socket and relays every datagram it
// receives through the relay.
//
// "both" is deliberately treated as TCP: a single socket cannot be both, and
// an operator who writes "both" for a port that needs UDP forwarding would
// otherwise silently get no datagram path at all. The two networks are
// configured as two tunnels instead, which is what the status view then shows.
func (c *Client) startUDPTunnel(t config.Tunnel) error {
	pc, err := net.ListenPacket("udp", t.Listen)
	if err != nil {
		return fmt.Errorf("bind udp %s: %w", t.Listen, err)
	}

	h := &tunnelHandle{cfg: t, pc: pc}
	c.mu.Lock()
	c.tunnels[t.Name] = h
	c.mu.Unlock()

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.acceptUDPTunnel(h)
	}()

	c.log.Info("udp tunnel listening",
		"tunnel", t.Name,
		"listen", pc.LocalAddr().String(),
		"target", t.Target,
		"server", t.Server,
		"group", t.Group,
	)
	return nil
}

// acceptTunnel accepts local connections and forwards each through a relay.
func (c *Client) acceptTunnel(h *tunnelHandle) {
	var delay time.Duration
	for {
		conn, err := h.ln.Accept()
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else if delay < time.Second {
				delay *= 2
			}
			c.log.Warn("tunnel accept failed, backing off", "tunnel", h.cfg.Name, "err", err, "backoff", delay)
			select {
			case <-time.After(delay):
				continue
			case <-c.ctx.Done():
				return
			}
		}
		delay = 0
		h.accepted.Add(1)
		c.stats.TotalConnections.Add(1)

		c.wg.Add(1)
		go func(conn net.Conn) {
			defer c.wg.Done()
			h.conns.Add(1)
			c.stats.ActiveConnections.Add(1)
			defer h.conns.Add(-1)
			defer c.stats.ActiveConnections.Add(-1)
			c.serveTunnel(h, conn)
		}(conn)
	}
}

// serveTunnel forwards one local connection to the tunnel's target.
func (c *Client) serveTunnel(h *tunnelHandle, local net.Conn) {
	defer local.Close()

	if tc, ok := local.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	req := &transport.Request{
		Command:   transport.CmdConnectTCP,
		Target:    h.cfg.Target,
		Transport: "",
	}

	stream, entry, err := c.openStream(h.cfg.Server, h.cfg.Group, h.cfg.Balance, req)
	if err != nil {
		h.failed.Add(1)
		c.stats.TunnelFailures.Add(1)
		c.log.Warn("tunnel could not reach the relay",
			"tunnel", h.cfg.Name,
			"target", h.cfg.Target,
			"err", err,
		)
		return
	}
	defer stream.Close()

	req.Transport = stream.TransportName()
	c.log.Debug("tunnel established",
		"tunnel", h.cfg.Name,
		"target", h.cfg.Target,
		"server", entry.Name,
		"transport", stream.TransportName(),
	)

	c.pipe(local, stream)
}

// openStream picks a relay from the appropriate pool and dials it, retrying
// across relays when the first choice fails.
//
// Retrying is what makes a grouped configuration useful: a single dead relay
// must not surface as an application error when a healthy one is available.
// The retry budget is bounded so a client with every relay down fails in a
// predictable time rather than hanging.
func (c *Client) openStream(serverID, group, balance string, req *transport.Request) (transport.Stream, *serverEntry, error) {
	candidates, err := c.pools.candidates(serverID, group, balance)
	if err != nil {
		return nil, nil, err
	}
	if len(candidates) == 0 {
		return nil, nil, errors.New("client: no enabled relay matches this tunnel")
	}

	// At most three attempts: enough to ride out one bad relay, few enough
	// that a total outage is reported quickly.
	attempts := len(candidates)
	if attempts > 3 {
		attempts = 3
	}

	var lastErr error
	for i := 0; i < attempts; i++ {
		entry := candidates[i]

		ctx, cancel := context.WithTimeout(c.ctx, c.dialTimeout())
		stream, err := c.dialRelay(ctx, entry, req)
		cancel()
		if err == nil {
			entry.markSuccess()
			c.stats.SuccessfulDials.Add(1)
			return stream, entry, nil
		}
		lastErr = err
		entry.markFailure(err)
		c.stats.FailedDials.Add(1)
		c.log.Debug("relay dial failed, trying the next candidate",
			"server", entry.Name,
			"transport", entry.Transport,
			"attempt", i+1,
			"err", err,
		)
	}
	return nil, nil, fmt.Errorf("client: every candidate relay failed, last error: %w", lastErr)
}

// dialRelay performs one transport handshake against one relay.
func (c *Client) dialRelay(ctx context.Context, entry *serverEntry, req *transport.Request) (transport.Stream, error) {
	dialer, err := transport.NewDialer(entry.Transport)
	if err != nil {
		return nil, err
	}

	// The request must be a fresh copy per attempt: a transport may fill in
	// Meta, and sharing it would leak state between attempts.
	attemptReq := req.Clone()
	attemptReq.Transport = entry.Transport
	if entry.ClientID != "" {
		attemptReq.ClientID = entry.ClientID
	}

	start := time.Now()
	stream, err := dialer.Dial(ctx, transport.DialRequest{
		ServerAddr: entry.Address,
		ServerName: entry.ServerName,
		Request:    attemptReq,
		Timeout:    c.dialTimeout(),
		Logger:     c.log,
		Settings:   entry.settings(),
	})
	if err != nil {
		return nil, err
	}
	entry.observeLatency(time.Since(start))
	return stream, nil
}

// dialTimeout returns the client's handshake budget.
func (c *Client) dialTimeout() time.Duration {
	if d := c.cfg.Health.Timeout.Or(0); d > 0 {
		return d
	}
	return 10 * time.Second
}

// pipe copies bytes between the local application and the relay, recording
// traffic in both directions.
func (c *Client) pipe(local net.Conn, stream transport.Stream) {
	done := make(chan struct {
		up bool
		n  int64
	}, 2)

	go func() {
		n := copyStream(stream, local)
		if cw, ok := stream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct {
			up bool
			n  int64
		}{true, n}
	}()
	go func() {
		n := copyStream(local, stream)
		if cw, ok := local.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct {
			up bool
			n  int64
		}{false, n}
	}()

	for i := 0; i < 2; i++ {
		r := <-done
		if r.up {
			c.stats.BytesUp.Add(r.n)
		} else {
			c.stats.BytesDown.Add(r.n)
		}
	}
}

// copyStream copies until EOF, returning the byte count.
func copyStream(dst net.Conn, src net.Conn) int64 {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			written, werr := dst.Write(buf[:n])
			total += int64(written)
			if werr != nil {
				return total
			}
		}
		if err != nil {
			return total
		}
	}
}

// TunnelStatus describes one tunnel for the Web GUI.
type TunnelStatus struct {
	Name     string `json:"name"`
	Listen   string `json:"listen"`
	Target   string `json:"target"`
	Server   string `json:"server,omitempty"`
	Group    string `json:"group,omitempty"`
	Enabled  bool   `json:"enabled"`
	Active   int64  `json:"active"`
	Accepted int64  `json:"accepted"`
	Failed   int64  `json:"failed"`
}

// TunnelStatuses reports the state of every configured tunnel.
func (c *Client) TunnelStatuses() []TunnelStatus {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([]TunnelStatus, 0, len(c.cfg.Tunnels))
	for _, t := range c.cfg.Tunnels {
		st := TunnelStatus{
			Name:    t.Name,
			Listen:  t.Listen,
			Target:  t.Target,
			Server:  t.Server,
			Group:   t.Group,
			Enabled: t.Enabled,
		}
		if h, ok := c.tunnels[t.Name]; ok {
			st.Active = h.conns.Load()
			st.Accepted = h.accepted.Load()
			st.Failed = h.failed.Load()
			if addr := h.listenAddr(); addr != "" {
				st.Listen = addr
			}
		}
		out = append(out, st)
	}
	return out
}

// ProxyStatus reports the local proxy's endpoints.
type ProxyStatus struct {
	Enabled bool   `json:"enabled"`
	SOCKS5  string `json:"socks5,omitempty"`
	HTTP    string `json:"http,omitempty"`
}

// ProxyStatus returns the local proxy's bound addresses.
func (c *Client) ProxyStatus() ProxyStatus {
	c.mu.Lock()
	defer c.mu.Unlock()

	st := ProxyStatus{Enabled: c.cfg.Proxy.Enabled}
	if c.proxy == nil {
		return st
	}
	if c.proxy.socks5 != nil {
		st.SOCKS5 = c.proxy.socks5.Addr().String()
	}
	if c.proxy.http != nil {
		st.HTTP = c.proxy.http.Addr().String()
	}
	return st
}

// ProbeNow runs one health probe against a single relay immediately.
//
// The console exposes this as a "test" button: waiting for the next scheduled
// check after editing a relay would make an operator believe their fix did not
// work.
func (c *Client) ProbeNow(ctx context.Context, serverID string) error {
	entry, ok := c.pools.ByID(serverID)
	if !ok {
		return fmt.Errorf("client: relay %q is not configured", serverID)
	}
	checker := newHealthChecker(c.cfg.Health, c.pools, c.log)
	checker.probe(ctx, entry)
	return nil
}

// Stop closes every listener and waits for in-flight relays to finish.
func (c *Client) Stop() {
	if !c.started.CompareAndSwap(true, false) {
		return
	}
	if c.cancel != nil {
		c.cancel()
	}

	c.mu.Lock()
	handles := make([]*tunnelHandle, 0, len(c.tunnels))
	for _, h := range c.tunnels {
		handles = append(handles, h)
	}
	c.tunnels = map[string]*tunnelHandle{}
	proxy := c.proxy
	c.proxy = nil
	c.mu.Unlock()

	for _, h := range handles {
		h.close()
	}
	if proxy != nil {
		if proxy.socks5 != nil {
			_ = proxy.socks5.Close()
		}
		if proxy.http != nil {
			_ = proxy.http.Close()
		}
	}

	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		c.log.Warn("client shutdown timed out waiting for in-flight connections")
	}
	c.log.Info("client stopped")
}

// serverEntry is the runtime view of one configured relay.
//
// It wraps the configuration with the mutable health state, so the
// configuration itself stays immutable and can be persisted without racing a
// health check.
type serverEntry struct {
	config.ServerEntry

	// failThreshold and successThreshold implement the health hysteresis. They
	// are copied from the health configuration when the entry is built, so a
	// probe never has to reach back into the config while holding the lock.
	failThreshold    int
	successThreshold int

	mu           sync.Mutex
	healthy      bool
	consecFail   int
	consecOK     int
	lastErr      string
	lastCheck    time.Time
	latencyMs    atomic.Int64
	latencyValid atomic.Bool
}

func newServerEntry(cfg config.ServerEntry) *serverEntry {
	return &serverEntry{
		ServerEntry: cfg,
		// A relay starts optimistic: blocking traffic until the first health
		// check completes would add a full check interval to startup.
		healthy: true,
	}
}

// settings returns the transport settings for this relay, with the standard
// server-name and client-id keys filled in from the entry.
func (e *serverEntry) settings() transport.Settings {
	s := make(transport.Settings, len(e.Settings)+4)
	for k, v := range e.Settings {
		s[k] = v
	}
	if e.ServerName != "" {
		if _, ok := s["serverName"]; !ok {
			s["serverName"] = e.ServerName
		}
	}
	if e.ClientID != "" {
		if _, ok := s["clientID"]; !ok {
			s["clientID"] = e.ClientID
		}
	}
	return s
}

func (e *serverEntry) isHealthy() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.healthy
}

func (e *serverEntry) markSuccess() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.consecFail = 0
	e.consecOK++
	e.healthy = true
	e.lastErr = ""
}

func (e *serverEntry) markFailure(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.consecOK = 0
	e.consecFail++
	e.lastCheck = time.Now()
	if err != nil {
		e.lastErr = err.Error()
	}
}

func (e *serverEntry) observeLatency(d time.Duration) {
	e.latencyMs.Store(d.Milliseconds())
	e.latencyValid.Store(true)
}

// HealthSnapshot is the JSON view of one relay's health.
type HealthSnapshot struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Address     string `json:"address"`
	Transport   string `json:"transport"`
	Group       string `json:"group,omitempty"`
	LatencyTag  string `json:"latencyTag,omitempty"`
	Enabled     bool   `json:"enabled"`
	Healthy     bool   `json:"healthy"`
	LatencyMs   int64  `json:"latencyMs"`
	LatencyOK   bool   `json:"latencyOk"`
	LastCheck   string `json:"lastCheck,omitempty"`
	LastError   string `json:"lastError,omitempty"`
	ConsecFails int    `json:"consecutiveFailures"`
}

// snapshot renders this relay's health for the API.
func (e *serverEntry) snapshot() HealthSnapshot {
	return e.Health()
}

// Health renders this relay's health for the API.
func (e *serverEntry) Health() HealthSnapshot {
	e.mu.Lock()
	defer e.mu.Unlock()

	s := HealthSnapshot{
		ID:          e.ID,
		Name:        e.Name,
		Address:     e.Address,
		Transport:   e.Transport,
		Group:       e.Group,
		LatencyTag:  e.LatencyTag,
		Enabled:     e.Enabled,
		Healthy:     e.healthy,
		LatencyMs:   e.latencyMs.Load(),
		LatencyOK:   e.latencyValid.Load(),
		LastError:   e.lastErr,
		ConsecFails: e.consecFail,
	}
	if !e.lastCheck.IsZero() {
		s.LastCheck = e.lastCheck.Format(time.RFC3339)
	}
	return s
}

// poolSet indexes relays by id and by group.
type poolSet struct {
	all    []*serverEntry
	byID   map[string]*serverEntry
	groups map[string][]*serverEntry
}

func newPoolSet(servers []config.ServerEntry) *poolSet {
	p := &poolSet{
		byID:   make(map[string]*serverEntry, len(servers)),
		groups: map[string][]*serverEntry{},
	}
	for _, s := range servers {
		e := newServerEntry(s)
		p.all = append(p.all, e)
		p.byID[s.ID] = e
		if s.Group != "" {
			p.groups[s.Group] = append(p.groups[s.Group], e)
		}
	}
	return p
}

// setHealthThresholds applies the health configuration's hysteresis to every
// relay. It must be called before the health checker starts.
func (p *poolSet) setHealthThresholds(cfg config.HealthConfig) {
	for _, e := range p.all {
		e.failThreshold = cfg.Failures
		e.successThreshold = cfg.Successes
	}
}

// validate builds every enabled relay's transport once, so a bad transport
// name is reported at startup rather than on the first request.
func (p *poolSet) validate() error {
	var problems []string
	for _, e := range p.all {
		if !e.Enabled {
			continue
		}
		if e.Address == "" {
			problems = append(problems, fmt.Sprintf("relay %q has no address", e.ID))
			continue
		}
		if _, err := transport.NewDialer(e.Transport); err != nil {
			problems = append(problems, fmt.Sprintf("relay %q: %v", e.ID, err))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("client: %s", strings.Join(problems, "; "))
	}
	return nil
}

// Entries returns every relay.
func (p *poolSet) Entries() []*serverEntry { return p.all }

// ByID looks up one relay.
func (p *poolSet) ByID(id string) (*serverEntry, bool) {
	e, ok := p.byID[id]
	return e, ok
}

// candidates returns the relays to try, in preference order.
//
// Selection rules, in order:
//
//  1. An explicit server id wins over everything; a tunnel that names one
//     relay is pinned to it and the group is ignored.
//  2. Otherwise the group's healthy members are used.
//  3. If the group has no healthy member, its unhealthy members are used
//     anyway: a stale health verdict must never make a tunnel unusable when
//     the operator can see the relay is up.
//  4. A tunnel with neither server nor group uses every enabled relay.
func (p *poolSet) candidates(serverID, group, balance string) ([]*serverEntry, error) {
	if serverID != "" {
		e, ok := p.byID[serverID]
		if !ok {
			return nil, fmt.Errorf("client: relay %q is not configured", serverID)
		}
		if !e.Enabled {
			return nil, fmt.Errorf("client: relay %q is disabled", serverID)
		}
		return []*serverEntry{e}, nil
	}

	var pool []*serverEntry
	if group != "" {
		pool = p.groups[group]
		if len(pool) == 0 {
			return nil, fmt.Errorf("client: group %q has no relays", group)
		}
	} else {
		pool = p.all
	}

	enabled := make([]*serverEntry, 0, len(pool))
	for _, e := range pool {
		if e.Enabled {
			enabled = append(enabled, e)
		}
	}
	if len(enabled) == 0 {
		return nil, fmt.Errorf("client: no enabled relay is available")
	}

	healthy := make([]*serverEntry, 0, len(enabled))
	for _, e := range enabled {
		if e.isHealthy() {
			healthy = append(healthy, e)
		}
	}
	if len(healthy) > 0 {
		return orderByBalance(healthy, balance), nil
	}
	return orderByBalance(enabled, balance), nil
}

// orderByBalance arranges candidates according to the strategy.
func orderByBalance(entries []*serverEntry, balance string) []*serverEntry {
	out := make([]*serverEntry, len(entries))
	copy(out, entries)

	switch balance {
	case "least-latency":
		// A relay that has never been measured sorts last, so the first
		// connection probes the ones known to be fast rather than gambling.
		sort.SliceStable(out, func(i, j int) bool {
			ai, aok := out[i].latencyMs.Load(), out[i].latencyValid.Load()
			bj, bok := out[j].latencyMs.Load(), out[j].latencyValid.Load()
			if aok != bok {
				return aok
			}
			if !aok && !bok {
				return false
			}
			return ai < bj
		})
	case "round-robin":
		// A deterministic rotation seeded by the current second spreads load
		// without shared mutable state, and keeps a given second's connections
		// on one relay so a burst does not fan out across every upstream.
		rotate := int(time.Now().Unix() % int64(len(out)))
		out = append(out[rotate:], out[:rotate]...)
	case "random":
		shuffle(out)
	default:
		// "first" and any unknown value keep configuration order, which is
		// what an operator expects when they list a primary then a backup.
	}
	return out
}

// shuffle permutes entries in place using a time-seeded xorshift.
func shuffle(entries []*serverEntry) {
	seed := uint64(time.Now().UnixNano()) | 1
	next := func() uint64 {
		seed ^= seed << 13
		seed ^= seed >> 7
		seed ^= seed << 17
		return seed
	}
	for i := len(entries) - 1; i > 0; i-- {
		j := int(next() % uint64(i+1))
		entries[i], entries[j] = entries[j], entries[i]
	}
}
