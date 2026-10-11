// Package hostmon samples the resources of the machine the management console
// runs on: CPU, memory, load, disks, network throughput, temperatures and the
// host's own outbound network quality.
//
// A relay operator's first question about a misbehaving tunnel is whether the
// machine itself is the problem, and the console could previously answer only
// about the relay. Everything here is read from /proc and /sys, which is why
// there is no third-party metrics dependency: the values are cheap, always
// present on the platform this program is installed on, and a dependency for
// reading a handful of kernel files would be out of proportion.
//
// Nothing in this package may fail the process. A kernel that does not expose a
// value reports it as absent, and the console shows what it has while saying
// what it does not.
package hostmon

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"porttransit/internal/logx"
)

// Sampling defaults. They are deliberately conservative: the console is a
// management surface, and a monitor that costs measurable CPU on a small VPS
// would be worse than no monitor at all.
const (
	DefaultInterval     = 5 * time.Second
	DefaultPingInterval = 30 * time.Second
	DefaultPingCount    = 3
	DefaultPingTimeout  = 1500 * time.Millisecond

	// cpuWindow is how long the sampler waits before taking its second
	// /proc/stat reading. CPU usage is a delta and a cumulative counter has no
	// meaning on its own, so the first snapshot is measured over a short window
	// rather than reporting a fabricated zero.
	cpuWindow = 300 * time.Millisecond

	// The floor each period is clamped to. Config validation reports a too-short
	// interval but does not reject it, because a status panel must not stop the
	// relay from starting — so the sampler enforces its own bound. Without this
	// a mistyped "1ms" would turn a display into a busy loop on the machine the
	// relay is trying to serve.
	minInterval     = time.Second
	minPingInterval = 5 * time.Second
	minPingTimeout  = 100 * time.Millisecond
	maxPingCount    = 20
)

// DefaultPingTargets are probed when the configuration names none.
//
// They mix anycast resolvers that are reachable from most networks, because the
// question the card answers is "can this host reach the public internet at
// all", and a host that reaches none of them has a real problem.
var DefaultPingTargets = []string{"1.1.1.1:443", "8.8.8.8:443", "223.5.5.5:443"}

// Options parameterise New.
type Options struct {
	// Interval is the resource sampling period.
	Interval time.Duration
	// PingInterval is the delay between outbound probe rounds.
	PingInterval time.Duration
	// PingTargets are the addresses the outbound probe measures. An empty
	// slice disables probing; nil selects DefaultPingTargets.
	PingTargets []string
	// PingCount is how many probes one target receives per round.
	PingCount int
	// PingTimeout bounds a single probe.
	PingTimeout time.Duration
	// Logger receives the one warning emitted when the host cannot be sampled.
	Logger *logx.Logger
}

/* ------------------------------------------------------------------- types */

// Snapshot is one reading of the host. Every field is a plain value so the
// structure can be handed straight to the console as JSON.
type Snapshot struct {
	// Supported is false on a platform with no collector, and Reason then says
	// why. The console shows the panel as unavailable rather than as zeroes.
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
	// Ready is true once a reading has been taken.
	Ready     bool      `json:"ready"`
	SampledAt time.Time `json:"sampledAt"`
	// Interval is the sampling period in seconds, so the console can say how
	// fresh the numbers are.
	Interval float64 `json:"intervalSeconds"`

	// Uptime is the host's uptime in seconds, not the process's.
	Uptime  float64       `json:"uptimeSeconds"`
	CPU     CPUInfo       `json:"cpu"`
	Memory  MemInfo       `json:"memory"`
	Swap    MemInfo       `json:"swap"`
	Load    LoadInfo      `json:"load"`
	Disks   []DiskInfo    `json:"disks"`
	Network NetworkInfo   `json:"network"`
	Thermal []ThermalInfo `json:"thermal"`
	System  SystemInfo    `json:"system"`
	Ping    PingInfo      `json:"ping"`
}

// CPUInfo describes the processor and its recent utilisation.
type CPUInfo struct {
	Model   string  `json:"model,omitempty"`
	Arch    string  `json:"arch,omitempty"`
	Cores   int     `json:"cores"`
	Sockets int     `json:"sockets"`
	MHz     float64 `json:"mhz,omitempty"`

	// The percentages are computed from the delta between two /proc/stat
	// readings and always sum to roughly 100.
	UsagePct   float64   `json:"usagePct"`
	UserPct    float64   `json:"userPct"`
	SystemPct  float64   `json:"systemPct"`
	IOWaitPct  float64   `json:"iowaitPct"`
	StealPct   float64   `json:"stealPct"`
	IdlePct    float64   `json:"idlePct"`
	PerCorePct []float64 `json:"perCorePct,omitempty"`

	// TempC is the hottest thermal zone, when the kernel exposes one. A virtual
	// machine usually does not.
	TempC float64 `json:"tempC,omitempty"`
}

// MemInfo describes memory or swap.
type MemInfo struct {
	TotalBytes     uint64  `json:"totalBytes"`
	UsedBytes      uint64  `json:"usedBytes"`
	FreeBytes      uint64  `json:"freeBytes"`
	AvailableBytes uint64  `json:"availableBytes"`
	CachedBytes    uint64  `json:"cachedBytes"`
	BuffersBytes   uint64  `json:"buffersBytes"`
	UsagePct       float64 `json:"usagePct"`
}

// LoadInfo describes the run queue.
type LoadInfo struct {
	One     float64 `json:"one"`
	Five    float64 `json:"five"`
	Fifteen float64 `json:"fifteen"`
	Running int     `json:"running"`
	Total   int     `json:"total"`
	// PerCore is the one-minute load divided by the logical core count. It is
	// the number that actually says whether the box is busy: a load of 4 is
	// idle on a 16-core host and saturated on a 2-core one.
	PerCore float64 `json:"perCore"`
}

// DiskInfo describes one mounted filesystem.
type DiskInfo struct {
	Device     string  `json:"device"`
	Mount      string  `json:"mount"`
	FSType     string  `json:"fstype,omitempty"`
	TotalBytes uint64  `json:"totalBytes"`
	UsedBytes  uint64  `json:"usedBytes"`
	FreeBytes  uint64  `json:"freeBytes"`
	UsagePct   float64 `json:"usagePct"`
	ReadOnly   bool    `json:"readOnly,omitempty"`
}

// NetworkInfo aggregates every non-loopback interface.
type NetworkInfo struct {
	RxBytes uint64  `json:"rxBytes"`
	TxBytes uint64  `json:"txBytes"`
	RxRate  float64 `json:"rxBytesPerSecond"`
	TxRate  float64 `json:"txBytesPerSecond"`
	RxPPS   float64 `json:"rxPacketsPerSecond"`
	TxPPS   float64 `json:"txPacketsPerSecond"`

	RxErrors  uint64 `json:"rxErrors"`
	TxErrors  uint64 `json:"txErrors"`
	RxDropped uint64 `json:"rxDropped"`
	TxDropped uint64 `json:"txDropped"`

	// TCPConns and TCPListeners are read from the kernel's socket tables, so
	// they count every socket on the host, not only the relay's.
	TCPConns  int `json:"tcpConnections"`
	TCPListen int `json:"tcpListeners"`

	Interfaces []NetIface `json:"interfaces,omitempty"`
}

// NetIface is one network interface.
type NetIface struct {
	Name      string   `json:"name"`
	Up        bool     `json:"up"`
	Loopback  bool     `json:"loopback,omitempty"`
	MTU       int      `json:"mtu,omitempty"`
	SpeedMbps int      `json:"speedMbps,omitempty"`
	Addrs     []string `json:"addrs,omitempty"`

	RxBytes uint64  `json:"rxBytes"`
	TxBytes uint64  `json:"txBytes"`
	RxRate  float64 `json:"rxBytesPerSecond"`
	TxRate  float64 `json:"txBytesPerSecond"`

	RxErrors  uint64 `json:"rxErrors,omitempty"`
	TxErrors  uint64 `json:"txErrors,omitempty"`
	RxDropped uint64 `json:"rxDropped,omitempty"`
	TxDropped uint64 `json:"txDropped,omitempty"`
}

// ThermalInfo is one thermal zone.
type ThermalInfo struct {
	Zone  string  `json:"zone"`
	Label string  `json:"label,omitempty"`
	TempC float64 `json:"tempC"`
}

// SystemInfo is the static identity of the host.
type SystemInfo struct {
	Hostname     string `json:"hostname,omitempty"`
	OS           string `json:"os,omitempty"`
	Distro       string `json:"distro,omitempty"`
	Kernel       string `json:"kernel,omitempty"`
	Arch         string `json:"arch,omitempty"`
	Virtualized  string `json:"virtualization,omitempty"`
	CPUGovernor  string `json:"cpuGovernor,omitempty"`
	ProcessCount int    `json:"processCount"`
	NumCPU       int    `json:"numCpu"`
}

// PingInfo is the host's own outbound network quality.
//
// This is not the latency of any tunnel: it is what the machine measures when
// it reaches for the public internet, which is the second half of the answer an
// operator needs when a tunnel is slow.
type PingInfo struct {
	Enabled bool         `json:"enabled"`
	Method  string       `json:"method,omitempty"`
	Targets []PingTarget `json:"targets,omitempty"`
	AvgMs   float64      `json:"avgMs"`
	MinMs   float64      `json:"minMs"`
	MaxMs   float64      `json:"maxMs"`
	LossPct float64      `json:"lossPct"`
	LastAt  time.Time    `json:"lastAt"`
	Error   string       `json:"error,omitempty"`
}

// PingTarget is one probed address.
type PingTarget struct {
	Address string  `json:"address"`
	Method  string  `json:"method,omitempty"`
	Sent    int     `json:"sent"`
	Recv    int     `json:"recv"`
	AvgMs   float64 `json:"avgMs"`
	MinMs   float64 `json:"minMs"`
	MaxMs   float64 `json:"maxMs"`
	LossPct float64 `json:"lossPct"`
	Error   string  `json:"error,omitempty"`
}

/* ---------------------------------------------------------- delta inputs */

// cpuTimes is one line of /proc/stat, in USER_HZ jiffies.
type cpuTimes struct {
	user, nice, system, idle, iowait, irq, softirq, steal uint64
}

func (c cpuTimes) total() uint64 {
	return c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.softirq + c.steal
}

// busy excludes idle and iowait, so a process waiting on the disk is not
// counted as consuming the CPU.
func (c cpuTimes) busy() uint64 {
	return c.total() - c.idle - c.iowait
}

// netCounters is one line of /proc/net/dev.
type netCounters struct {
	rxBytes, rxPackets, rxErrs, rxDrop uint64
	txBytes, txPackets, txErrs, txDrop uint64
}

// rawSample is one reading of the kernel files. The delta-derived fields are
// computed against the previous sample, which is why they are not stored here.
type rawSample struct {
	at   time.Time
	cpu  []cpuTimes
	net  map[string]netCounters
	snap Snapshot
}

/* ---------------------------------------------------------------- monitor */

// Monitor samples the host in the background and keeps the latest reading.
type Monitor struct {
	opts Options
	log  *logx.Logger

	mu   sync.RWMutex
	snap Snapshot
	prev *rawSample

	startMu sync.Mutex
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	started bool
}

// New builds a monitor. It does not read anything until Start.
//
// Options below their floor are raised to it rather than rejected. The relay's
// configuration validation reports these as problems but still lets the process
// start, so this is where the bound is actually enforced — a panel is never a
// reason for the service to refuse to run, and it is never a reason for the
// service to spin either.
func New(opts Options) *Monitor {
	// A zero value means "not set" and takes the default; a value that was set
	// but is too small is clamped to the floor, so an operator who asked for
	// something faster gets the fastest safe rate rather than silently getting
	// a different number they did not choose.
	opts.Interval = clampPeriod(opts.Interval, DefaultInterval, minInterval)
	opts.PingInterval = clampPeriod(opts.PingInterval, DefaultPingInterval, minPingInterval)
	opts.PingTimeout = clampPeriod(opts.PingTimeout, DefaultPingTimeout, minPingTimeout)

	if opts.PingTargets == nil {
		opts.PingTargets = slices.Clone(DefaultPingTargets)
	}
	if opts.PingCount <= 0 {
		opts.PingCount = DefaultPingCount
	}
	if opts.PingCount > maxPingCount {
		opts.PingCount = maxPingCount
	}
	if opts.Logger == nil {
		opts.Logger = logx.Discard()
	}
	return &Monitor{opts: opts, log: opts.Logger}
}

// clampPeriod returns def when v is unset, at least floor when v is set.
func clampPeriod(v, def, floor time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	if v < floor {
		return floor
	}
	return v
}

// Start begins sampling and returns immediately.
//
// The first reading is taken here rather than in the loop so that a console
// opened right after a restart already has CPU percentages: they need two
// readings, and an operator who just restarted the service should not be shown
// an empty panel.
func (m *Monitor) Start(ctx context.Context) error {
	m.startMu.Lock()
	defer m.startMu.Unlock()
	if m.started {
		return errors.New("hostmon: already started")
	}
	m.started = true
	ctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	first, err := readRaw()
	if err != nil {
		m.mu.Lock()
		m.snap = Snapshot{Supported: false, Reason: err.Error(), SampledAt: time.Now()}
		m.mu.Unlock()
		// This is a warning and not an error: the console is still useful
		// without the host panel, and refusing to serve it would be worse.
		m.log.Warn("主机资源采集不可用", "err", err)
		return nil
	}

	m.mu.Lock()
	m.prev = first
	m.snap = buildSnapshot(first, nil, m.opts)
	m.mu.Unlock()

	m.wg.Add(1)
	go m.sampleLoop(ctx)
	if len(m.opts.PingTargets) > 0 {
		m.wg.Add(1)
		go m.pingLoop(ctx)
	}
	return nil
}

// Stop ends sampling and waits for the goroutines to finish.
func (m *Monitor) Stop() {
	m.startMu.Lock()
	cancel, started := m.cancel, m.started
	m.cancel, m.started = nil, false
	m.startMu.Unlock()
	if !started || cancel == nil {
		return
	}
	cancel()
	m.wg.Wait()
}

// Snapshot returns a copy of the latest reading. The slices are cloned because
// the caller hands them to the JSON encoder while the sampler keeps running.
func (m *Monitor) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.snap
	s.CPU.PerCorePct = slices.Clone(s.CPU.PerCorePct)
	s.Disks = slices.Clone(s.Disks)
	s.Thermal = slices.Clone(s.Thermal)
	s.Network.Interfaces = slices.Clone(s.Network.Interfaces)
	for i := range s.Network.Interfaces {
		s.Network.Interfaces[i].Addrs = slices.Clone(s.Network.Interfaces[i].Addrs)
	}
	s.Ping.Targets = slices.Clone(s.Ping.Targets)
	return s
}

// sampleLoop reads the host on a fixed period.
func (m *Monitor) sampleLoop(ctx context.Context) {
	defer m.wg.Done()

	// The second reading comes quickly, so the first CPU percentage the
	// operator sees is current rather than an average over a whole interval.
	timer := time.NewTimer(cpuWindow)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
		m.sample()
	}

	t := time.NewTicker(m.opts.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.sample()
		}
	}
}

// sample takes one reading and publishes it.
func (m *Monitor) sample() {
	cur, err := readRaw()
	if err != nil {
		// A transient read failure is not worth a log line per interval; the
		// previous snapshot stays visible and the next tick tries again.
		m.log.Debug("主机采样失败", "err", err)
		return
	}

	m.mu.Lock()
	prev := m.prev
	m.prev = cur
	s := buildSnapshot(cur, prev, m.opts)
	// The ping loop owns this field and runs on its own schedule, so a resource
	// sample must not blank it.
	s.Ping = m.snap.Ping
	m.snap = s
	m.mu.Unlock()
}

// pingLoop measures outbound quality on its own, slower schedule.
func (m *Monitor) pingLoop(ctx context.Context) {
	defer m.wg.Done()

	// One round immediately: an operator opening the console should not wait a
	// whole interval to learn whether the host can reach the internet.
	m.runPing(ctx)

	t := time.NewTicker(m.opts.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.runPing(ctx)
		}
	}
}

// runPing probes every target concurrently and publishes the aggregate.
func (m *Monitor) runPing(ctx context.Context) {
	targets := m.opts.PingTargets
	if len(targets) == 0 {
		return
	}

	out := make([]PingTarget, len(targets))
	var wg sync.WaitGroup
	for i, addr := range targets {
		wg.Add(1)
		go func(i int, addr string) {
			defer wg.Done()
			out[i] = probeOne(ctx, addr, m.opts.PingCount, m.opts.PingTimeout)
		}(i, addr)
	}
	wg.Wait()

	info := aggregatePing(out)
	m.mu.Lock()
	m.snap.Ping = info
	m.mu.Unlock()
}

/* ----------------------------------------------------------- delta maths */

// buildSnapshot turns one reading plus the previous one into a snapshot.
func buildSnapshot(cur, prev *rawSample, opts Options) Snapshot {
	s := cur.snap
	s.Ready = true
	s.SampledAt = cur.at
	s.Interval = opts.Interval.Seconds()
	s.Network.Interfaces = append([]NetIface(nil), s.Network.Interfaces...)

	if prev == nil {
		return s
	}
	dt := cur.at.Sub(prev.at).Seconds()
	if dt <= 0 {
		return s
	}
	if len(prev.cpu) == len(cur.cpu) {
		fillCPUUsage(&s, cur.cpu, prev.cpu)
	}
	fillNetRates(&s, cur.net, prev.net, dt)
	return s
}

// fillCPUUsage converts two cumulative /proc/stat readings into percentages.
func fillCPUUsage(s *Snapshot, cur, prev []cpuTimes) {
	if len(cur) == 0 || len(prev) == 0 {
		return
	}

	// /proc/stat lists the machine-wide "cpu" line first and the individual
	// cores after it. That first line is already the sum of the rest, so it is
	// the totals and it is not a core: summing every line for the aggregate
	// would double each counter, and emitting it as a core would draw one bar
	// more than the machine has CPUs.
	agg, aggPrev := cur[0], prev[0]

	perCore := make([]float64, 0, len(cur)-1)
	for i := 1; i < len(cur); i++ {
		c, p := cur[i], prev[i]
		total := c.total() - p.total()
		busy := c.busy() - p.busy()
		// A core that produced no jiffies at all (an offline CPU, or a counter
		// that wrapped) would divide by zero.
		if total == 0 {
			perCore = append(perCore, 0)
			continue
		}
		perCore = append(perCore, round1(float64(busy)*100/float64(total)))
	}
	s.CPU.PerCorePct = perCore

	total := agg.total() - aggPrev.total()
	if total == 0 {
		return
	}
	pct := func(v uint64) float64 { return round1(float64(v) * 100 / float64(total)) }
	s.CPU.UsagePct = round1(float64(agg.busy()-aggPrev.busy()) * 100 / float64(total))
	s.CPU.UserPct = pct((agg.user + agg.nice) - (aggPrev.user + aggPrev.nice))
	s.CPU.SystemPct = pct((agg.system + agg.irq + agg.softirq) - (aggPrev.system + aggPrev.irq + aggPrev.softirq))
	s.CPU.IOWaitPct = pct(agg.iowait - aggPrev.iowait)
	s.CPU.StealPct = pct(agg.steal - aggPrev.steal)
	s.CPU.IdlePct = pct(agg.idle - aggPrev.idle)
}

// fillNetRates converts two cumulative /proc/net/dev readings into per-second
// rates. The absolute counters are already in the snapshot.
func fillNetRates(s *Snapshot, cur, prev map[string]netCounters, dt float64) {
	for i := range s.Network.Interfaces {
		iface := &s.Network.Interfaces[i]
		c, ok := cur[iface.Name]
		if !ok {
			continue
		}
		p := prev[iface.Name]
		iface.RxRate = round1(float64(counterDelta(c.rxBytes, p.rxBytes)) / dt)
		iface.TxRate = round1(float64(counterDelta(c.txBytes, p.txBytes)) / dt)
	}

	// The aggregate follows the same rule as the totals: loopback traffic is
	// this host talking to itself and would double-count every relayed byte.
	var rx, tx, rxp, txp float64
	for _, iface := range s.Network.Interfaces {
		if iface.Loopback {
			continue
		}
		rx += iface.RxRate
		tx += iface.TxRate
		if c, ok := cur[iface.Name]; ok {
			p := prev[iface.Name]
			rxp += float64(counterDelta(c.rxPackets, p.rxPackets)) / dt
			txp += float64(counterDelta(c.txPackets, p.txPackets)) / dt
		}
	}
	s.Network.RxRate = round1(rx)
	s.Network.TxRate = round1(tx)
	s.Network.RxPPS = round1(rxp)
	s.Network.TxPPS = round1(txp)
}

// counterDelta subtracts two counters that may have wrapped, and never returns
// a negative rate. The kernel's 64-bit counters do not wrap in practice, but an
// interface that is recreated restarts at zero, and a negative rate rendered as
// a huge number is far more alarming than a missing one.
func counterDelta(cur, prev uint64) uint64 {
	if cur < prev {
		return 0
	}
	return cur - prev
}

// round1 rounds to one decimal, which is all the precision a percentage or a
// millisecond reading needs, and keeps the JSON readable.
func round1(v float64) float64 {
	if v != v { // NaN
		return 0
	}
	return float64(int64(v*10+sign(v)*0.5)) / 10
}

func sign(v float64) float64 {
	if v < 0 {
		return -1
	}
	return 1
}
