package client

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"porttransit/internal/config"
	"porttransit/internal/logx"
	"porttransit/internal/transport"
)

// Stats holds the client's counters.
type Stats struct {
	ActiveConnections atomic.Int64
	TotalConnections  atomic.Int64
	TunnelFailures    atomic.Int64
	ProxyRequests     atomic.Int64
	SuccessfulDials   atomic.Int64
	FailedDials       atomic.Int64
	HealthChecks      atomic.Int64
	HealthFailures    atomic.Int64
	BytesUp           atomic.Int64
	BytesDown         atomic.Int64

	startedAt time.Time
}

// NewStats returns a zeroed Stats stamped with its creation time.
func NewStats() *Stats { return &Stats{startedAt: time.Now()} }

// Snapshot is the JSON view of the counters.
type Snapshot struct {
	ActiveConnections int64 `json:"activeConnections"`
	TotalConnections  int64 `json:"totalConnections"`
	TunnelFailures    int64 `json:"tunnelFailures"`
	ProxyRequests     int64 `json:"proxyRequests"`
	SuccessfulDials   int64 `json:"successfulDials"`
	FailedDials       int64 `json:"failedDials"`
	HealthChecks      int64 `json:"healthChecks"`
	HealthFailures    int64 `json:"healthFailures"`
	BytesUp           int64 `json:"bytesUp"`
	BytesDown         int64 `json:"bytesDown"`
	UptimeSeconds     int64 `json:"uptimeSeconds"`
}

// Snapshot reads every counter.
func (s *Stats) Snapshot() Snapshot {
	return Snapshot{
		ActiveConnections: s.ActiveConnections.Load(),
		TotalConnections:  s.TotalConnections.Load(),
		TunnelFailures:    s.TunnelFailures.Load(),
		ProxyRequests:     s.ProxyRequests.Load(),
		SuccessfulDials:   s.SuccessfulDials.Load(),
		FailedDials:       s.FailedDials.Load(),
		HealthChecks:      s.HealthChecks.Load(),
		HealthFailures:    s.HealthFailures.Load(),
		BytesUp:           s.BytesUp.Load(),
		BytesDown:         s.BytesDown.Load(),
		UptimeSeconds:     int64(time.Since(s.startedAt).Seconds()),
	}
}

// Reset zeroes the counters.
func (s *Stats) Reset() {
	s.ActiveConnections.Store(0)
	s.TotalConnections.Store(0)
	s.TunnelFailures.Store(0)
	s.ProxyRequests.Store(0)
	s.SuccessfulDials.Store(0)
	s.FailedDials.Store(0)
	s.HealthChecks.Store(0)
	s.HealthFailures.Store(0)
	s.BytesUp.Store(0)
	s.BytesDown.Store(0)
	s.startedAt = time.Now()
}

// healthChecker probes relays periodically and flips their health.
//
// # Why probe at all
//
// A relay can be reachable at the TCP level while its transport handshake
// fails — a rotated credential, a firewall that now resets mid-handshake, a
// relay process that died leaving the socket in the kernel's backlog. Probing
// exercises the full handshake, which is the only way to learn that.
//
// # Why hysteresis
//
// A single failure is noise: a lost packet, a momentary CPU spike. A relay is
// only retired after Failures consecutive failures and restored after
// Successes consecutive successes, so a flapping link does not oscillate the
// active relay and interrupt every in-flight connection.
type healthChecker struct {
	cfg   config.HealthConfig
	pools *poolSet
	log   *logx.Logger

	mu     sync.Mutex
	probes map[string]int64
}

func newHealthChecker(cfg config.HealthConfig, pools *poolSet, log *logx.Logger) *healthChecker {
	return &healthChecker{
		cfg:    cfg,
		pools:  pools,
		log:    log,
		probes: map[string]int64{},
	}
}

// run probes every relay on the configured interval until the context ends.
func (h *healthChecker) run(ctx context.Context) {
	interval := h.cfg.Interval.Or(30 * time.Second)

	// Probe once immediately: waiting a full interval before the first check
	// would leave a client with a dead primary relay serving errors for that
	// whole window.
	h.probeAll(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.probeAll(ctx)
		}
	}
}

// probeAll probes every enabled relay concurrently.
func (h *healthChecker) probeAll(ctx context.Context) {
	var wg sync.WaitGroup
	for _, e := range h.pools.Entries() {
		if !e.Enabled {
			continue
		}
		wg.Add(1)
		go func(e *serverEntry) {
			defer wg.Done()
			h.probe(ctx, e)
		}(e)
	}
	wg.Wait()
}

// probe runs one liveness check against one relay.
func (h *healthChecker) probe(ctx context.Context, e *serverEntry) {
	timeout := h.cfg.Timeout.Or(5 * time.Second)
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer, err := transport.NewDialer(e.Transport)
	if err != nil {
		e.recordProbe(false, err, 0)
		return
	}

	req := &transport.Request{
		Command:   transport.CmdPing,
		Transport: e.Transport,
	}
	if h.cfg.ProbeTarget != "" {
		// A configured probe target turns the check into an end-to-end test:
		// the relay is asked to reach that address, so a failure can mean the
		// relay's own upstream is broken, not just the relay itself.
		req.Command = transport.CmdConnectTCP
		req.Target = h.cfg.ProbeTarget
	}

	start := time.Now()
	stream, err := dialer.Dial(probeCtx, transport.DialRequest{
		ServerAddr: e.Address,
		ServerName: e.ServerName,
		Request:    req,
		Timeout:    timeout,
		Logger:     h.log,
		Settings:   e.settings(),
	})
	rtt := time.Since(start)
	if err != nil {
		e.recordProbe(false, err, 0)
		return
	}
	// A ping stream is answered and closed by the relay; a probe-target stream
	// is a real connection and must be closed here.
	_ = stream.Close()
	e.recordProbe(true, nil, rtt)
}

// recordProbe applies a probe result, including the hysteresis thresholds.
func (e *serverEntry) recordProbe(ok bool, err error, rtt time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.lastCheck = time.Now()
	if ok {
		e.consecFail = 0
		e.consecOK++
		e.lastErr = ""
		if rtt > 0 {
			e.latencyMs.Store(rtt.Milliseconds())
			e.latencyValid.Store(true)
		}
		// A relay is restored only after the configured number of consecutive
		// successes, so a link that is up but flapping does not oscillate the
		// active relay.
		if e.successThreshold > 0 && e.consecOK < e.successThreshold && !e.healthy {
			return
		}
		e.healthy = true
		return
	}

	e.consecOK = 0
	e.consecFail++
	if err != nil {
		e.lastErr = err.Error()
	}
	// A single failure is noise; only a run of them retires the relay.
	if e.failThreshold > 0 && e.consecFail >= e.failThreshold {
		e.healthy = false
	}
}
