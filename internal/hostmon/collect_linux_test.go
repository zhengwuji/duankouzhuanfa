//go:build linux

package hostmon

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests exercise the Linux collector against a fixture tree rather than
// the running host, so they assert what the parser does with a given kernel
// file instead of whatever this machine happens to be doing.

// TestUnsupportedHostIsReportedNotFatal proves a host that cannot be sampled
// still produces a monitor that starts, serves a snapshot and says why. The
// console is useful without the host panel, so this must never be an error.
func TestUnsupportedHostIsReportedNotFatal(t *testing.T) {
	// Empty directories: no /proc/stat to read.
	empty := t.TempDir()
	oldProc, oldSys, oldOS := procRoot, sysRoot, osReleasePath
	procRoot, sysRoot, osReleasePath = empty, empty, filepath.Join(empty, "os-release")
	t.Cleanup(func() { procRoot, sysRoot, osReleasePath = oldProc, oldSys, oldOS })

	m := New(Options{Interval: time.Second})
	if err := m.Start(t.Context()); err != nil {
		t.Fatalf("Start returned %v on a host with no /proc; it must report, not fail", err)
	}
	t.Cleanup(m.Stop)

	snap := m.Snapshot()
	if snap.Supported {
		t.Error("Supported = true on a host with no readable /proc/stat")
	}
	if snap.Reason == "" {
		t.Error("no reason was given for an unsupported host, so the console " +
			"cannot explain the missing panel")
	}
}

// TestReadRawParsesAKernelTree proves the collector reads a realistic tree:
// the aggregate line is kept separate from the cores, memory is taken from
// MemAvailable, and the loopback interface is marked so the totals can skip it.
func TestReadRawParsesAKernelTree(t *testing.T) {
	f := newFixture(t)
	f.use()

	s, err := readRaw()
	if err != nil {
		t.Fatalf("readRaw: %v", err)
	}

	if len(s.cpu) != 3 {
		t.Errorf("read %d cpu lines, want 3 (the aggregate and two cores)", len(s.cpu))
	}
	// A readable /proc/stat is what "supported" means, and the console believes
	// this flag over the values: with it unset, a host that produced a complete
	// reading was still rendered as "此平台不支持主机资源采集".
	if !s.snap.Supported {
		t.Error("Supported = false for a host whose /proc/stat was read successfully, " +
			"so a working panel is replaced by an unsupported-platform message")
	}
	if s.snap.Reason != "" {
		t.Errorf("Reason = %q on a host that was read successfully, want empty", s.snap.Reason)
	}
	if s.cpu[0].user != 200 || s.cpu[0].idle != 800 {
		t.Errorf("the aggregate line parsed as %+v, want user=200 idle=800", s.cpu[0])
	}

	if s.snap.Memory.TotalBytes != 8*1024*1024*1024 {
		t.Errorf("MemTotal = %d, want 8 GiB", s.snap.Memory.TotalBytes)
	}
	// MemAvailable is 6 GiB of 8, so 2 GiB is in use. Free alone would report
	// 1 GiB used and call the page cache free, which is not what the kernel
	// would hand back without evicting anything.
	if s.snap.Memory.UsedBytes != 2*1024*1024*1024 {
		t.Errorf("UsedBytes = %d, want 2 GiB (from MemAvailable, not MemFree)",
			s.snap.Memory.UsedBytes)
	}
	if s.snap.Memory.UsagePct != 25 {
		t.Errorf("UsagePct = %v, want 25", s.snap.Memory.UsagePct)
	}
	// Cached is Cached + SReclaimable - Shmem, in bytes.
	if want := uint64(512000+51200-10240) * 1024; s.snap.Memory.CachedBytes != want {
		t.Errorf("CachedBytes = %d, want %d", s.snap.Memory.CachedBytes, want)
	}

	if s.snap.System.Hostname == "" {
		t.Error("the hostname was not read")
	}
	if s.snap.System.Distro != "Debian GNU/Linux 13 (trixie)" {
		t.Errorf("Distro = %q, want the PRETTY_NAME from os-release", s.snap.System.Distro)
	}
	if s.snap.System.Virtualized != "QEMU" {
		t.Errorf("Virtualized = %q, want QEMU from the DMI product name", s.snap.System.Virtualized)
	}
	if s.snap.System.CPUGovernor != "performance" {
		t.Errorf("CPUGovernor = %q, want performance", s.snap.System.CPUGovernor)
	}
	if s.snap.CPU.Model != "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz" {
		t.Errorf("CPU.Model = %q", s.snap.CPU.Model)
	}
	if s.snap.CPU.MHz != 2400 {
		t.Errorf("CPU.MHz = %v, want 2400", s.snap.CPU.MHz)
	}
	if s.snap.Load.One != 0.3 {
		t.Errorf("Load.One = %v, want 0.3 (rounded from 0.25)", s.snap.Load.One)
	}
	if s.snap.Load.Running != 1 || s.snap.Load.Total != 128 {
		t.Errorf("Load running/total = %d/%d, want 1/128", s.snap.Load.Running, s.snap.Load.Total)
	}
	if s.snap.Uptime != 12345.67 {
		t.Errorf("Uptime = %v, want the host's own uptime", s.snap.Uptime)
	}
}

// TestReadNetDevParsesCounters reads the interface counters on their own.
//
// It deliberately does not go through readRaw: the interface list is joined
// with the names the running kernel reports, so a test of the parser must not
// depend on which NICs the machine running it happens to have.
func TestReadNetDevParsesCounters(t *testing.T) {
	f := newFixture(t)
	f.use()

	counters := readNetDev()
	lo, ok := counters["lo"]
	if !ok {
		t.Fatal("the loopback counters were not parsed")
	}
	if lo.rxBytes != 500000 || lo.txBytes != 500000 {
		t.Errorf("lo rx/tx = %d/%d, want 500000/500000", lo.rxBytes, lo.txBytes)
	}
	eth, ok := counters["eth0"]
	if !ok {
		t.Fatal("the eth0 counters were not parsed")
	}
	if eth.rxBytes != 1000000 || eth.txBytes != 800000 {
		t.Errorf("eth0 rx/tx = %d/%d, want 1000000/800000", eth.rxBytes, eth.txBytes)
	}
	if eth.rxPackets != 2000 || eth.txPackets != 1500 {
		t.Errorf("eth0 rx/tx packets = %d/%d, want 2000/1500", eth.rxPackets, eth.txPackets)
	}
}

// TestIfacesFromMarksLoopback proves the flag that keeps loopback traffic out of
// the totals is set from the interface flags rather than from its name.
func TestIfacesFromMarksLoopback(t *testing.T) {
	counters := map[string]netCounters{
		"lo":   {rxBytes: 1, txBytes: 2},
		"eth0": {rxBytes: 3, txBytes: 4},
	}

	var sawLo bool
	for _, iface := range ifacesFrom(counters) {
		if iface.Name == "lo" {
			sawLo = true
			if !iface.Loopback {
				t.Error("the loopback interface was not flagged, so its traffic " +
					"would be counted in the host totals")
			}
			if iface.RxBytes != 1 {
				t.Errorf("lo RxBytes = %d, want the /proc counter to be joined in", iface.RxBytes)
			}
		}
	}
	if !sawLo {
		t.Skip("this machine has no interface named lo")
	}
}

// TestIfacesFromWithoutTheGoStack covers a host where the interface list cannot
// be read. The counters are still worth showing, so they must come through
// under their /proc names instead of the panel going empty.
func TestIfacesFromWithoutTheGoStack(t *testing.T) {
	got := ifacesFrom(nil)
	for _, iface := range got {
		if iface.Name == "" {
			t.Error("an interface with no name was produced")
		}
	}
}

// TestReadCPUStatIgnoresNonCPUCPULines covers the lines in /proc/stat that
// begin with "cpu" without being processors. A kernel that adds one must not
// add a phantom core.
func TestReadCPUStatIgnoresNonCPUCPULines(t *testing.T) {
	f := newFixture(t)
	f.write(f.procPath("stat"), `cpu  200 0 50 800 0 0 0 0
cpu0 100 0 25 400 0 0 0 0
cpu1 100 0 25 400 0 0 0 0
cpufreq 1 2 3
cpuN 1 2 3 4
intr 5
`)
	f.use()

	cpu, err := readCPUStat()
	if err != nil {
		t.Fatalf("readCPUStat: %v", err)
	}
	if len(cpu) != 3 {
		t.Errorf("read %d cpu lines, want 3: a line that merely starts with "+
			"\"cpu\" is not a processor", len(cpu))
	}
}

// TestReadCPUStatToleratesShortLines covers a kernel that omits the newer
// counters (steal, guest) on an old or restricted host. Missing fields must
// read as zero rather than shifting the ones that are present.
func TestReadCPUStatToleratesShortLines(t *testing.T) {
	f := newFixture(t)
	// Only user, nice, system, idle — no iowait and beyond.
	f.write(f.procPath("stat"), "cpu  10 20 30 40\n")
	f.use()

	cpu, err := readCPUStat()
	if err != nil {
		t.Fatalf("readCPUStat: %v", err)
	}
	if len(cpu) != 1 {
		t.Fatalf("read %d lines, want 1", len(cpu))
	}
	if cpu[0].user != 10 || cpu[0].nice != 20 || cpu[0].system != 30 || cpu[0].idle != 40 {
		t.Errorf("parsed %+v, want user=10 nice=20 system=30 idle=40", cpu[0])
	}
	if cpu[0].iowait != 0 || cpu[0].steal != 0 {
		t.Errorf("a missing field parsed as %+v, want zero", cpu[0])
	}
}

// TestReadMemoryWithoutMemAvailable covers an older kernel that predates
// MemAvailable.
func TestReadMemoryWithoutMemAvailable(t *testing.T) {
	f := newFixture(t)
	f.write(f.procPath("meminfo"), `MemTotal:        1048576 kB
MemFree:          262144 kB
Buffers:           10240 kB
Cached:            51200 kB
`)
	f.use()

	var s Snapshot
	readMemory(&s)

	if s.Memory.TotalBytes != 1024*1024*1024 {
		t.Errorf("MemTotal = %d, want 1 GiB", s.Memory.TotalBytes)
	}
	if s.Memory.UsedBytes != 768*1024*1024 {
		t.Errorf("UsedBytes = %d, want 768 MiB (Total - MemFree)", s.Memory.UsedBytes)
	}
}

// TestReadDisksSkipsPseudoFilesystems proves the disk list is storage and not
// kernel objects: a panel listing proc, sysfs, tmpfs and cgroup alongside the
// real disk buries the one row an operator is looking for.
//
// The mount point has to be a directory that exists, because the size comes
// from statfs on it; the fixture points the real entry at a temporary directory
// and the pseudo entries at the same place, so only the fstype can decide which
// one is reported.
func TestReadDisksSkipsPseudoFilesystems(t *testing.T) {
	f := newFixture(t)
	real := t.TempDir()
	f.write(f.procPath("mounts"), strings.Join([]string{
		"proc " + real + " proc rw 0 0",
		"tmpfs " + real + " tmpfs rw 0 0",
		"cgroup2 " + real + " cgroup2 rw 0 0",
		"/dev/vda1 " + real + " ext4 rw 0 0",
	}, "\n")+"\n")
	f.use()

	disks := readDisks()
	if len(disks) != 1 {
		t.Fatalf("read %d disks, want 1 (only the ext4 entry is storage): %+v", len(disks), disks)
	}
	if disks[0].Device != "/dev/vda1" {
		t.Errorf("Device = %q, want /dev/vda1", disks[0].Device)
	}
	if disks[0].TotalBytes == 0 {
		t.Error("TotalBytes = 0: the size was not read from statfs")
	}
	if disks[0].UsagePct < 0 || disks[0].UsagePct > 100 {
		t.Errorf("UsagePct = %v, want a percentage", disks[0].UsagePct)
	}
}

// TestReadDisksReportsADeviceOnce covers a bind mount or a container's view,
// where the same storage appears at several mount points. Listing it per mount
// would double-count the same disk.
func TestReadDisksReportsADeviceOnce(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	f.write(f.procPath("mounts"), strings.Join([]string{
		"/dev/vda1 " + dir + " ext4 rw 0 0",
		"/dev/vda1 " + dir + " ext4 rw 0 0",
	}, "\n")+"\n")
	f.use()

	if disks := readDisks(); len(disks) != 1 {
		t.Errorf("read %d entries for one device, want 1", len(disks))
	}
}

// TestUnescapeMount covers the octal escapes /proc/mounts uses for spaces,
// which would otherwise be shown to the operator as "\040".
func TestUnescapeMount(t *testing.T) {
	cases := map[string]string{
		"/mnt/data":          "/mnt/data",
		`/mnt/my\040disk`:    "/mnt/my disk",
		`/mnt/tab\011here`:   "/mnt/tab\there",
		`/mnt/back\134slash`: `/mnt/back\slash`,
		`/mnt/incomplete\04`: `/mnt/incomplete\04`, // not a full escape
		`/mnt/notoctal\zzz`:  `/mnt/notoctal\zzz`,
		// 0777 is 511, which is not a byte. /proc/mounts only escapes
		// characters below 256, so this escape cannot occur; leaving it
		// verbatim is better than truncating it into a different character
		// than the one that was written.
		`/mnt/overflow\777`: `/mnt/overflow\777`,
	}
	for in, want := range cases {
		if got := unescapeMount(in); got != want {
			t.Errorf("unescapeMount(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestReadThermalDropsImplausibleZones covers a virtual machine that exposes a
// thermal zone with nothing behind it. A card reporting 0 °C or 5000 °C is
// worse than one with no temperature at all.
func TestReadThermalDropsImplausibleZones(t *testing.T) {
	f := newFixture(t)
	f.write(f.sysPath("class/thermal/thermal_zone0/temp"), "45000\n")
	f.write(f.sysPath("class/thermal/thermal_zone0/type"), "x86_pkg_temp\n")
	f.write(f.sysPath("class/thermal/thermal_zone1/temp"), "0\n")
	f.write(f.sysPath("class/thermal/thermal_zone1/type"), "acpitz\n")
	f.write(f.sysPath("class/thermal/thermal_zone2/temp"), "5000000\n")
	f.write(f.sysPath("class/thermal/thermal_zone2/type"), "bogus\n")
	f.use()

	zones := readThermal()
	if len(zones) != 1 {
		t.Fatalf("read %d thermal zones, want 1", len(zones))
	}
	if zones[0].TempC != 45 {
		t.Errorf("TempC = %v, want 45", zones[0].TempC)
	}
	if zones[0].Label != "x86_pkg_temp" {
		t.Errorf("Label = %q, want the zone type", zones[0].Label)
	}
}

// TestReadDistroWithoutOsRelease covers a container or a minimal image with no
// /etc/os-release. The field is optional and must not take the sample down.
func TestReadDistroWithoutOsRelease(t *testing.T) {
	f := newFixture(t)
	f.write(f.osRelease, "")
	_ = os.Remove(f.osRelease)
	f.use()

	if got := readDistro(); got != "" {
		t.Errorf("readDistro = %q with no os-release, want empty", got)
	}
}

// TestRoundAndCounterDelta covers the two helpers the arithmetic leans on.
func TestRoundAndCounterDelta(t *testing.T) {
	if got := round1(1.25); got != 1.3 {
		t.Errorf("round1(1.25) = %v, want 1.3", got)
	}
	if got := round1(1.24); got != 1.2 {
		t.Errorf("round1(1.24) = %v, want 1.2", got)
	}
	if got := round1(-1.25); got != -1.3 {
		t.Errorf("round1(-1.25) = %v, want -1.3", got)
	}
	// NaN reaches round1 from a zero-length delta and must not survive into
	// JSON, where it has no representation.
	if got := round1(math.NaN()); got != 0 {
		t.Errorf("round1(NaN) = %v, want 0", got)
	}
	if got := counterDelta(10, 1000); got != 0 {
		t.Errorf("counterDelta(10, 1000) = %d, want 0", got)
	}
	if got := counterDelta(1000, 10); got != 990 {
		t.Errorf("counterDelta(1000, 10) = %d, want 990", got)
	}
}

/* ---------------------------------------------------------------- fixtures */

// fixture is a temporary /proc, /sys and /etc/os-release.
type fixture struct {
	proc      string
	sys       string
	osRelease string
	t         *testing.T
}

// newFixture writes a small but realistic kernel tree.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{
		proc:      filepath.Join(root, "proc"),
		sys:       filepath.Join(root, "sys"),
		osRelease: filepath.Join(root, "os-release"),
		t:         t,
	}

	f.write(f.procPath("stat"), `cpu  200 0 50 800 0 0 0 0
cpu0 100 0 25 400 0 0 0 0
cpu1 100 0 25 400 0 0 0 0
intr 5
`)
	f.write(f.procPath("uptime"), "12345.67 98765.43\n")
	f.write(f.procPath("meminfo"), `MemTotal:        8388608 kB
MemFree:         7340032 kB
MemAvailable:    6291456 kB
Buffers:          102400 kB
Cached:           512000 kB
SReclaimable:      51200 kB
Shmem:             10240 kB
SwapTotal:       2097152 kB
SwapFree:        2097152 kB
`)
	f.write(f.procPath("loadavg"), "0.25 0.10 0.05 1/128 4242\n")
	f.write(f.procPath("cpuinfo"), `processor	: 0
model name	: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
cpu MHz		: 2400.000
physical id	: 0
flags		: fpu vme de pse hypervisor
`)
	f.write(f.procPath("net/dev"), `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  500000    1000    0    0    0     0          0         0   500000    1000    0    0    0     0       0          0
  eth0: 1000000    2000    0    0    0     0          0         0   800000    1500    0    0    0     0       0          0
`)
	f.write(f.procPath("net/tcp"), `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 20 4 30 10 -1
`)

	f.write(f.sysPath("class/dmi/id/product_name"), "Standard PC (i440FX + PIIX, 1996)\n")
	f.write(f.sysPath("class/dmi/id/sys_vendor"), "QEMU\n")
	f.write(f.sysPath("devices/system/cpu/cpu0/cpufreq/scaling_governor"), "performance\n")
	f.write(f.osRelease, `NAME="Debian GNU/Linux"
PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
VERSION_ID="13"
`)
	return f
}

// use points the collector at this fixture for the duration of the test.
func (f *fixture) use() {
	f.t.Helper()
	oldProc, oldSys, oldOS := procRoot, sysRoot, osReleasePath
	procRoot, sysRoot, osReleasePath = f.proc, f.sys, f.osRelease
	f.t.Cleanup(func() { procRoot, sysRoot, osReleasePath = oldProc, oldSys, oldOS })
}

func (f *fixture) procPath(rel string) string { return filepath.Join(f.proc, rel) }
func (f *fixture) sysPath(rel string) string  { return filepath.Join(f.sys, rel) }

// write writes a fixture file, creating its parent directories.
func (f *fixture) write(path, content string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		f.t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		f.t.Fatalf("write %s: %v", path, err)
	}
}
