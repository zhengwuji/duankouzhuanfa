package hostmon

import (
	"testing"
	"time"
)

// The delta maths is where this package can be quietly wrong: every percentage
// and every rate comes from subtracting two cumulative kernel counters, and a
// mistake there produces a plausible number rather than a crash. These tests
// pin the arithmetic directly, with the kernel files left out of the picture.

// TestCPUUsageExcludesTheAggregateLine is the regression test for a snapshot
// that reported one more core than the machine has.
//
// /proc/stat's first line is the machine-wide "cpu" total and the lines after
// it are the individual cores. Summing every line into the aggregate double
// counts every jiffy, and emitting every line as a core draws N+1 bars for an
// N-core host.
func TestCPUUsageExcludesTheAggregateLine(t *testing.T) {
	// Two cores, each 100% busy over the window, and the aggregate line that a
	// real kernel would print: the sum of the two.
	prev := []cpuTimes{
		{user: 1000, system: 1000}, // cpu
		{user: 500, system: 500},   // cpu0
		{user: 500, system: 500},   // cpu1
	}
	cur := []cpuTimes{
		{user: 1100, system: 1100},
		{user: 550, system: 550},
		{user: 550, system: 550},
	}

	var s Snapshot
	fillCPUUsage(&s, cur, prev)

	if got := len(s.CPU.PerCorePct); got != 2 {
		t.Errorf("PerCorePct has %d entries for a 2-core machine, want 2 "+
			"(the aggregate line is not a core)", got)
	}
	if s.CPU.UsagePct != 100 {
		t.Errorf("UsagePct = %v, want 100: the aggregate line was summed with the cores, "+
			"so its own counters were counted twice", s.CPU.UsagePct)
	}
	for i, pct := range s.CPU.PerCorePct {
		if pct != 100 {
			t.Errorf("core %d = %v%%, want 100%%", i, pct)
		}
	}
}

// TestCPUUsageIsIdleWhenNothingChanged covers the division guard: two readings
// with no elapsed jiffies would otherwise produce NaN, which JSON encodes as an
// unparseable value and the console renders as a blank.
func TestCPUUsageIsIdleWhenNothingChanged(t *testing.T) {
	same := []cpuTimes{{user: 10}, {user: 5}, {user: 5}}

	var s Snapshot
	fillCPUUsage(&s, same, same)

	if s.CPU.UsagePct != 0 {
		t.Errorf("UsagePct = %v for two identical readings, want 0", s.CPU.UsagePct)
	}
	for i, pct := range s.CPU.PerCorePct {
		if pct != 0 {
			t.Errorf("core %d = %v for two identical readings, want 0", i, pct)
		}
	}
}

// TestCPUUsageSplitsBusyFromWaiting proves a process blocked on the disk is not
// counted as consuming the CPU: iowait is part of total but not of busy.
func TestCPUUsageSplitsBusyFromWaiting(t *testing.T) {
	prev := []cpuTimes{{idle: 100}}
	cur := []cpuTimes{{idle: 100, iowait: 100}}

	var s Snapshot
	fillCPUUsage(&s, cur, prev)

	if s.CPU.UsagePct != 0 {
		t.Errorf("UsagePct = %v, want 0: time waiting on I/O is not CPU time", s.CPU.UsagePct)
	}
	if s.CPU.IOWaitPct != 100 {
		t.Errorf("IOWaitPct = %v, want 100", s.CPU.IOWaitPct)
	}
}

// TestNetworkRatesExcludeLoopback pins the rule that keeps the byte counters
// honest. A relay moving data between a local client and a local listener sends
// every byte over loopback as well, so counting it would roughly double the
// traffic the operator sees.
func TestNetworkRatesExcludeLoopback(t *testing.T) {
	s := Snapshot{Network: NetworkInfo{Interfaces: []NetIface{
		{Name: "eth0"},
		{Name: "lo", Loopback: true},
	}}}
	prev := map[string]netCounters{
		"eth0": {rxBytes: 0, txBytes: 0, rxPackets: 0, txPackets: 0},
		"lo":   {rxBytes: 0, txBytes: 0},
	}
	cur := map[string]netCounters{
		"eth0": {rxBytes: 1000, txBytes: 2000, rxPackets: 10, txPackets: 20},
		"lo":   {rxBytes: 5000, txBytes: 5000},
	}

	fillNetRates(&s, cur, prev, 1)

	if s.Network.RxRate != 1000 {
		t.Errorf("RxRate = %v, want 1000: loopback traffic was added to the total", s.Network.RxRate)
	}
	if s.Network.TxRate != 2000 {
		t.Errorf("TxRate = %v, want 2000", s.Network.TxRate)
	}
	// The interface's own rate is still reported; only the aggregate skips it.
	if s.Network.Interfaces[1].RxRate != 5000 {
		t.Errorf("the loopback interface's own rate = %v, want 5000", s.Network.Interfaces[1].RxRate)
	}
}

// TestNetworkRateNeverGoesNegative covers an interface that was recreated and
// restarted its counters at zero. A negative rate formatted as a huge unsigned
// number is far more alarming than a missing one.
func TestNetworkRateNeverGoesNegative(t *testing.T) {
	if got := counterDelta(10, 1000); got != 0 {
		t.Errorf("counterDelta(10, 1000) = %d, want 0: a counter that went backwards "+
			"must not produce a negative rate", got)
	}
	if got := counterDelta(1000, 10); got != 990 {
		t.Errorf("counterDelta(1000, 10) = %d, want 990", got)
	}
}

// TestNewAppliesDefaults proves a zero-valued Options produces a working
// monitor rather than one that samples every zero seconds or probes with a
// zero timeout.
func TestNewAppliesDefaults(t *testing.T) {
	m := New(Options{})

	if m.opts.Interval != DefaultInterval {
		t.Errorf("Interval = %v, want %v", m.opts.Interval, DefaultInterval)
	}
	if m.opts.PingInterval != DefaultPingInterval {
		t.Errorf("PingInterval = %v, want %v", m.opts.PingInterval, DefaultPingInterval)
	}
	if m.opts.PingCount != DefaultPingCount {
		t.Errorf("PingCount = %d, want %d", m.opts.PingCount, DefaultPingCount)
	}
	if m.opts.PingTimeout != DefaultPingTimeout {
		t.Errorf("PingTimeout = %v, want %v", m.opts.PingTimeout, DefaultPingTimeout)
	}
	if len(m.opts.PingTargets) != len(DefaultPingTargets) {
		t.Errorf("PingTargets = %v, want the built-in set", m.opts.PingTargets)
	}
}

// TestNewClampsUnsafePeriods proves a period that was set but is too small is
// raised to the floor instead of being honoured.
//
// Configuration validation reports these but deliberately does not reject them,
// because a status panel must not stop the relay from starting. That leaves the
// monitor as the only place the bound is enforced — and without it a mistyped
// "1ms" would turn a display into a busy loop on the machine the relay serves.
func TestNewClampsUnsafePeriods(t *testing.T) {
	m := New(Options{
		Interval:     time.Millisecond,
		PingInterval: time.Millisecond,
		PingTimeout:  time.Millisecond,
		PingCount:    1000,
	})

	if m.opts.Interval < minInterval {
		t.Errorf("Interval = %v, want at least %v", m.opts.Interval, minInterval)
	}
	if m.opts.PingInterval < minPingInterval {
		t.Errorf("PingInterval = %v, want at least %v", m.opts.PingInterval, minPingInterval)
	}
	if m.opts.PingTimeout < minPingTimeout {
		t.Errorf("PingTimeout = %v, want at least %v", m.opts.PingTimeout, minPingTimeout)
	}
	if m.opts.PingCount > maxPingCount {
		t.Errorf("PingCount = %d, want at most %d: 1000 probes per target per round is "+
			"a load, not a measurement", m.opts.PingCount, maxPingCount)
	}

	// A value that was already safe must be kept exactly, not rounded to a
	// default: the operator chose it.
	exact := New(Options{Interval: 7 * time.Second, PingTimeout: 2 * time.Second})
	if exact.opts.Interval != 7*time.Second {
		t.Errorf("Interval = %v, want the configured 7s", exact.opts.Interval)
	}
	if exact.opts.PingTimeout != 2*time.Second {
		t.Errorf("PingTimeout = %v, want the configured 2s", exact.opts.PingTimeout)
	}
}

// TestEmptyPingTargetsDisablesProbing pins the distinction between nil and an
// empty slice: nil means "use the defaults", empty means "the operator turned
// this off". Collapsing the two would make `"pingTargets": []` silently probe
// three public resolvers.
func TestEmptyPingTargetsDisablesProbing(t *testing.T) {
	m := New(Options{PingTargets: []string{}})
	if len(m.opts.PingTargets) != 0 {
		t.Errorf("an explicit empty target list became %v, want it to stay empty",
			m.opts.PingTargets)
	}
}

// TestSnapshotIsCopied proves Snapshot hands back a copy: the console encodes it
// while the sampler keeps replacing slices underneath, and sharing the backing
// array would race.
func TestSnapshotIsCopied(t *testing.T) {
	m := New(Options{})
	m.mu.Lock()
	m.snap = Snapshot{
		CPU:     CPUInfo{PerCorePct: []float64{1, 2}},
		Disks:   []DiskInfo{{Mount: "/"}},
		Thermal: []ThermalInfo{{Zone: "zone0"}},
		Network: NetworkInfo{Interfaces: []NetIface{{Name: "eth0", Addrs: []string{"10.0.0.1/24"}}}},
		Ping:    PingInfo{Targets: []PingTarget{{Address: "1.1.1.1"}}},
	}
	m.mu.Unlock()

	got := m.Snapshot()
	got.CPU.PerCorePct[0] = 99
	got.Disks[0].Mount = "/changed"
	got.Thermal[0].Zone = "changed"
	got.Network.Interfaces[0].Addrs[0] = "changed"
	got.Ping.Targets[0].Address = "changed"

	again := m.Snapshot()
	if again.CPU.PerCorePct[0] != 1 || again.Disks[0].Mount != "/" ||
		again.Thermal[0].Zone != "zone0" || again.Network.Interfaces[0].Addrs[0] != "10.0.0.1/24" ||
		again.Ping.Targets[0].Address != "1.1.1.1" {
		t.Error("mutating the returned snapshot changed the monitor's own copy: " +
			"the console would read a value being rewritten by the sampler")
	}
}

// TestUnsupportedHostIsReportedNotFatal lives in hostmon_linux_test.go: it
// points the collector at a directory with no /proc in it, and only the Linux
// build has a collector to point.
