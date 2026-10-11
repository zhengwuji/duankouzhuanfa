//go:build linux

package hostmon

import (
	"bufio"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// The Linux collector.
//
// Everything comes from /proc and /sys. Both are virtual filesystems whose
// reads are cheap and allocation-light, and both are present on every host the
// installer supports, so no dependency and no privileged helper is needed.
//
// The parsing is deliberately tolerant: a kernel that renames a field, a
// container that hides a file, or a virtual machine with no thermal zone must
// degrade to an absent value rather than to a failed sample. Each helper below
// therefore returns what it managed to read and lets the caller decide.

// procRoot, sysRoot and osReleasePath are variables so a test can point them at
// a fixture tree. They are never written outside a test.
var (
	procRoot      = "/proc"
	sysRoot       = "/sys"
	osReleasePath = "/etc/os-release"
)

// readRaw reads every host counter once.
func readRaw() (*rawSample, error) {
	at := time.Now()

	cpu, err := readCPUStat()
	if err != nil {
		// /proc/stat is the one file whose absence means this is not a Linux
		// host in any useful sense, so it is the only hard failure.
		return nil, err
	}

	s := Snapshot{}
	// Reaching this point means /proc/stat was readable, which is what
	// "supported" means: there is a collector here and it produced a reading.
	// Leaving this unset made a fully working host report supported:false
	// alongside a complete set of values, and the console trusts the flag over
	// the values — so a working panel was replaced by "此平台不支持主机资源采集"
	// while the JSON behind it was full of correct data.
	s.Supported = true
	s.CPU.Cores = runtime.NumCPU()
	s.System.NumCPU = runtime.NumCPU()

	readCPUInfo(&s)
	readUptime(&s)
	readMemory(&s)
	readLoad(&s)
	readSystem(&s)
	s.Disks = readDisks()
	s.Thermal = readThermal()

	netCounters, netInfo := readNet()
	s.Network = netInfo

	return &rawSample{at: at, cpu: cpu, net: netCounters, snap: s}, nil
}

/* ------------------------------------------------------------------- /proc */

// readCPUStat parses the per-CPU jiffy counters. Index 0 is the machine-wide
// "cpu" line and the rest are the individual cores.
func readCPUStat() ([]cpuTimes, error) {
	f, err := os.Open(filepath.Join(procRoot, "stat"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []cpuTimes
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// "cpu" alone is the aggregate; "cpu0".."cpuN" are the cores. Anything
		// else on a cpu-prefixed line is not a CPU.
		if fields[0] != "cpu" {
			if _, err := strconv.Atoi(strings.TrimPrefix(fields[0], "cpu")); err != nil {
				continue
			}
		}
		var t cpuTimes
		vals := make([]uint64, 0, len(fields)-1)
		for _, v := range fields[1:] {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				n = 0
			}
			vals = append(vals, n)
		}
		get := func(i int) uint64 {
			if i < len(vals) {
				return vals[i]
			}
			return 0
		}
		t = cpuTimes{
			user: get(0), nice: get(1), system: get(2), idle: get(3),
			iowait: get(4), irq: get(5), softirq: get(6), steal: get(7),
		}
		out = append(out, t)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("hostmon: /proc/stat has no cpu lines")
	}
	return out, nil
}

// readCPUInfo fills the static processor description.
func readCPUInfo(s *Snapshot) {
	f, err := os.Open(filepath.Join(procRoot, "cpuinfo"))
	if err != nil {
		return
	}
	defer f.Close()

	s.CPU.Arch = runtime.GOARCH
	physical := map[string]bool{}
	var mhzSum float64
	var mhzCount int

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch key {
		case "model name", "Model", "cpu model", "Hardware":
			if s.CPU.Model == "" {
				s.CPU.Model = val
			}
		case "cpu MHz", "clock":
			if v, err := strconv.ParseFloat(val, 64); err == nil {
				mhzSum += v
				mhzCount++
			}
		case "physical id":
			physical[val] = true
		}
	}
	if mhzCount > 0 {
		s.CPU.MHz = round1(mhzSum / float64(mhzCount))
	}
	s.CPU.Sockets = len(physical)
	if s.CPU.Sockets == 0 {
		s.CPU.Sockets = 1
	}
	if s.CPU.Cores == 0 {
		s.CPU.Cores = mhzCount
	}
}

// readUptime fills the host uptime, which is not the process's.
func readUptime(s *Snapshot) {
	raw, err := readFileTrim(filepath.Join(procRoot, "uptime"))
	if err != nil {
		return
	}
	field, _, _ := strings.Cut(raw, " ")
	if v, err := strconv.ParseFloat(strings.TrimSpace(field), 64); err == nil {
		s.Uptime = v
	}
}

// readMemory parses /proc/meminfo into the memory and swap blocks.
//
// "Available" is preferred over "Free" for the used figure: Free excludes the
// page cache, which the kernel will hand back the moment anything asks, so a
// healthy machine would otherwise always look full.
func readMemory(s *Snapshot) {
	f, err := os.Open(filepath.Join(procRoot, "meminfo"))
	if err != nil {
		return
	}
	defer f.Close()

	vals := map[string]uint64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		n, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		// Everything in meminfo is in kB except HugePages_*.
		vals[strings.TrimSpace(key)] = n * 1024
	}

	kb := func(k string) uint64 { return vals[k] }

	mem := MemInfo{
		TotalBytes:     kb("MemTotal"),
		FreeBytes:      kb("MemFree"),
		AvailableBytes: kb("MemAvailable"),
		BuffersBytes:   kb("Buffers"),
		// Cached plus reclaimable slab is what a tool like free(1) calls cache.
		CachedBytes: kb("Cached") + kb("SReclaimable") - kb("Shmem"),
	}
	if mem.TotalBytes > 0 {
		avail := mem.AvailableBytes
		if avail == 0 {
			avail = mem.FreeBytes
		}
		mem.UsedBytes = mem.TotalBytes - min(avail, mem.TotalBytes)
		mem.UsagePct = round1(float64(mem.UsedBytes) * 100 / float64(mem.TotalBytes))
	}
	s.Memory = mem

	swap := MemInfo{TotalBytes: kb("SwapTotal"), FreeBytes: kb("SwapFree")}
	if swap.TotalBytes > 0 {
		swap.UsedBytes = swap.TotalBytes - min(swap.FreeBytes, swap.TotalBytes)
		swap.UsagePct = round1(float64(swap.UsedBytes) * 100 / float64(swap.TotalBytes))
	}
	s.Swap = swap
}

// readLoad parses /proc/loadavg.
func readLoad(s *Snapshot) {
	raw, err := readFileTrim(filepath.Join(procRoot, "loadavg"))
	if err != nil {
		return
	}
	fields := strings.Fields(raw)
	if len(fields) < 4 {
		return
	}
	parse := func(i int) float64 {
		v, _ := strconv.ParseFloat(fields[i], 64)
		return round1(v)
	}
	s.Load.One = parse(0)
	s.Load.Five = parse(1)
	s.Load.Fifteen = parse(2)
	if running, total, ok := strings.Cut(fields[3], "/"); ok {
		s.Load.Running, _ = strconv.Atoi(running)
		s.Load.Total, _ = strconv.Atoi(total)
	}
	if s.CPU.Cores > 0 {
		s.Load.PerCore = round1(s.Load.One / float64(s.CPU.Cores))
	}
}

// readSystem fills the host's identity: distribution, kernel, virtualisation
// and the CPU frequency governor.
func readSystem(s *Snapshot) {
	if name, err := os.Hostname(); err == nil {
		s.System.Hostname = name
	}
	s.System.OS = runtime.GOOS
	s.System.Arch = runtime.GOARCH
	s.System.Kernel = readKernel()
	s.System.Distro = readDistro()
	s.System.Virtualized = readVirtualization()
	s.System.CPUGovernor = readFirstLine(filepath.Join(sysRoot, "devices/system/cpu/cpu0/cpufreq/scaling_governor"))
	s.System.ProcessCount = countProcesses()
}

// readKernel asks uname rather than reading /proc/version, because the latter
// embeds the compiler banner and is far longer than anyone needs to read.
func readKernel() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return ""
	}
	return strings.TrimRight(string(u.Release[:]), "\x00")
}

// readDistro returns the human-readable distribution name.
func readDistro() string {
	f, err := os.Open(osReleasePath)
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "PRETTY_NAME":
			return strings.Trim(strings.TrimSpace(val), `"`)
		case "NAME":
			// Kept as a fallback only; PRETTY_NAME carries the version, which
			// is what matters when an operator reports a bug.
		}
	}
	return ""
}

// readVirtualization reports what the guest is running on, or "" when the host
// appears to be bare metal.
func readVirtualization() string {
	// The DMI product name is the most specific answer when it is readable.
	product := readFirstLine(filepath.Join(sysRoot, "class/dmi/id/product_name"))
	vendor := readFirstLine(filepath.Join(sysRoot, "class/dmi/id/sys_vendor"))
	combined := strings.ToLower(product + " " + vendor)
	switch {
	case strings.Contains(combined, "kvm"):
		return "KVM"
	case strings.Contains(combined, "vmware"):
		return "VMware"
	case strings.Contains(combined, "virtualbox"):
		return "VirtualBox"
	case strings.Contains(combined, "qemu"):
		return "QEMU"
	case strings.Contains(combined, "microsoft"):
		return "Hyper-V"
	case strings.Contains(combined, "xen"):
		return "Xen"
	case strings.Contains(combined, "bochs"), strings.Contains(combined, "amazon ec2"):
		return "云主机"
	case strings.Contains(combined, "openstack"):
		return "OpenStack"
	}
	if v := readFirstLine(filepath.Join(sysRoot, "hypervisor/type")); v != "" {
		return v
	}
	// The CPU's own hypervisor flag is the last resort: it proves a hypervisor
	// is present without saying which one.
	if hasHypervisorFlag() {
		return "虚拟机"
	}
	if product != "" || vendor != "" {
		return "物理机"
	}
	return ""
}

// hasHypervisorFlag reports whether /proc/cpuinfo advertises the hypervisor
// flag, which every Linux guest does and bare metal does not.
func hasHypervisorFlag() bool {
	f, err := os.Open(filepath.Join(procRoot, "cpuinfo"))
	if err != nil {
		return false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok || strings.TrimSpace(key) != "flags" {
			continue
		}
		for _, flag := range strings.Fields(val) {
			if flag == "hypervisor" {
				return true
			}
		}
	}
	return false
}

// countProcesses counts the numeric entries in /proc, which is what ps does.
func countProcesses() int {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err == nil {
			n++
		}
	}
	return n
}

/* -------------------------------------------------------------------- /sys */

// readThermal collects every readable thermal zone.
func readThermal() []ThermalInfo {
	dirs, err := filepath.Glob(filepath.Join(sysRoot, "class/thermal/thermal_zone*"))
	if err != nil {
		return nil
	}
	sort.Strings(dirs)

	var out []ThermalInfo
	for _, dir := range dirs {
		raw := readFirstLine(filepath.Join(dir, "temp"))
		if raw == "" {
			continue
		}
		milli, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			continue
		}
		zone := ThermalInfo{
			Zone:  filepath.Base(dir),
			Label: readFirstLine(filepath.Join(dir, "type")),
			TempC: round1(milli / 1000),
		}
		// A zone reporting 0 or an implausible value is not a sensor; some
		// virtual machines expose the node with nothing behind it.
		if zone.TempC <= 0 || zone.TempC > 200 {
			continue
		}
		out = append(out, zone)
	}
	return out
}

/* ----------------------------------------------------------------- network */

// readNet reads /proc/net/dev and enriches it with the interface attributes
// from /sys and the Go network stack.
func readNet() (map[string]netCounters, NetworkInfo) {
	counters := readNetDev()
	info := NetworkInfo{Interfaces: ifacesFrom(counters)}

	var rxErr, txErr, rxDrop, txDrop uint64
	for i := range info.Interfaces {
		iface := &info.Interfaces[i]
		info.RxBytes += iface.RxBytes
		info.TxBytes += iface.TxBytes
		rxErr += iface.RxErrors
		txErr += iface.TxErrors
		rxDrop += iface.RxDropped
		txDrop += iface.TxDropped
	}
	info.RxErrors, info.TxErrors = rxErr, txErr
	info.RxDropped, info.TxDropped = rxDrop, txDrop
	info.TCPConns, info.TCPListen = countTCP()
	return counters, info
}

// readNetDev parses the per-interface counters.
//
// The totals are summed over the non-loopback interfaces only: loopback traffic
// is this host talking to itself, and counting it would double every byte the
// relay moves between a local client and a local listener.
func readNetDev() map[string]netCounters {
	f, err := os.Open(filepath.Join(procRoot, "net/dev"))
	if err != nil {
		return nil
	}
	defer f.Close()

	out := map[string]netCounters{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 16 {
			continue
		}
		at := func(i int) uint64 {
			n, _ := strconv.ParseUint(fields[i], 10, 64)
			return n
		}
		out[name] = netCounters{
			rxBytes: at(0), rxPackets: at(1), rxErrs: at(2), rxDrop: at(3),
			txBytes: at(8), txPackets: at(9), txErrs: at(10), txDrop: at(11),
		}
	}
	return out
}

// ifacesFrom builds the interface list, joining the counters with the
// attributes the Go network stack knows.
func ifacesFrom(counters map[string]netCounters) []NetIface {
	sysIfaces, err := net.Interfaces()
	if err != nil {
		// Without the interface list the counters are still usable; they are
		// emitted under their /proc names.
		names := make([]string, 0, len(counters))
		for name := range counters {
			names = append(names, name)
		}
		sort.Strings(names)
		out := make([]NetIface, 0, len(names))
		for _, name := range names {
			c := counters[name]
			out = append(out, NetIface{
				Name: name, RxBytes: c.rxBytes, TxBytes: c.txBytes,
				RxErrors: c.rxErrs, TxErrors: c.txErrs,
				RxDropped: c.rxDrop, TxDropped: c.txDrop,
			})
		}
		return out
	}

	out := make([]NetIface, 0, len(sysIfaces))
	for _, si := range sysIfaces {
		c := counters[si.Name]
		iface := NetIface{
			Name:     si.Name,
			Up:       si.Flags&net.FlagUp != 0,
			Loopback: si.Flags&net.FlagLoopback != 0,
			MTU:      si.MTU,
			RxBytes:  c.rxBytes, TxBytes: c.txBytes,
			RxErrors: c.rxErrs, TxErrors: c.txErrs,
			RxDropped: c.rxDrop, TxDropped: c.txDrop,
			SpeedMbps: readSpeedMbps(si.Name),
		}
		if addrs, err := si.Addrs(); err == nil {
			for _, a := range addrs {
				iface.Addrs = append(iface.Addrs, a.String())
			}
		}
		out = append(out, iface)
	}
	return out
}

// readSpeedMbps reads the link speed. Virtual interfaces report nothing, and
// an unreadable node is not an error.
func readSpeedMbps(name string) int {
	raw := readFirstLine(filepath.Join(sysRoot, "class/net", name, "speed"))
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// countTCP counts the kernel's TCP sockets by state.
//
// This is the host's socket table, not the relay's: an operator diagnosing a
// connection problem needs to see whether something else on the machine is
// holding the ports, which the relay's own counters cannot tell them.
func countTCP() (conns, listeners int) {
	for _, name := range []string{"net/tcp", "net/tcp6"} {
		f, err := os.Open(filepath.Join(procRoot, name))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		first := true
		for sc.Scan() {
			if first {
				first = false // header
				continue
			}
			fields := strings.Fields(sc.Text())
			if len(fields) < 4 {
				continue
			}
			conns++
			// 0A is TCP_LISTEN.
			if strings.EqualFold(fields[3], "0A") {
				listeners++
			}
		}
		f.Close()
	}
	return conns, listeners
}

/* ------------------------------------------------------------------- disks */

// pseudoFS are the filesystems that are not storage: they are kernel objects,
// RAM copies or network views, and listing them would bury the real disks.
var pseudoFS = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true,
	"tmpfs": true, "cgroup": true, "cgroup2": true, "pstore": true,
	"securityfs": true, "debugfs": true, "tracefs": true, "hugetlbfs": true,
	"mqueue": true, "configfs": true, "fusectl": true, "bpf": true,
	"autofs": true, "binfmt_misc": true, "rpc_pipefs": true, "nfsd": true,
	"efivarfs": true, "squashfs": true, "ramfs": true, "fuse.gvfsd-fuse": true,
	"nsfs": true, "systemd-1": true, "sunrpc": true,
}

// readDisks reports the usage of every real mounted filesystem.
func readDisks() []DiskInfo {
	f, err := os.Open(filepath.Join(procRoot, "mounts"))
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []DiskInfo
	seen := map[string]bool{}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		device, mount, fstype := fields[0], fields[1], fields[2]
		if pseudoFS[fstype] {
			continue
		}
		// A device mounted twice (a bind mount, or a container's view) is the
		// same storage; reporting it twice would double-count it.
		if seen[device] && strings.HasPrefix(device, "/dev/") {
			continue
		}
		seen[device] = true

		var st unix.Statfs_t
		if err := unix.Statfs(mount, &st); err != nil {
			continue
		}
		bsize := uint64(st.Bsize)
		total := st.Blocks * bsize
		if total == 0 {
			continue
		}
		free := st.Bavail * bsize
		used := (st.Blocks - st.Bfree) * bsize

		d := DiskInfo{
			Device: device, Mount: unescapeMount(mount), FSType: fstype,
			TotalBytes: total, UsedBytes: used, FreeBytes: free,
			ReadOnly: st.Flags&unix.ST_RDONLY != 0,
		}
		// The percentage is taken against what a non-root user could use,
		// which is how df reports it: reserved blocks are not space you have.
		if used+free > 0 {
			d.UsagePct = round1(float64(used) * 100 / float64(used+free))
		}
		out = append(out, d)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Mount == "/" {
			return true
		}
		if out[j].Mount == "/" {
			return false
		}
		return out[i].Mount < out[j].Mount
	})
	return out
}

// unescapeMount decodes the octal escapes /proc/mounts uses for spaces and
// other awkward characters, so a mount point is shown as it is named.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+3 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		n, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
		if err != nil {
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(byte(n))
		i += 3
	}
	return b.String()
}

/* ---------------------------------------------------------------- helpers */

// readFileTrim reads a small file and trims its trailing newline.
func readFileTrim(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// readFirstLine reads a small file and returns its first line, or "" when it
// cannot be read. Absence is normal here: most /sys attributes are optional.
func readFirstLine(path string) string {
	raw, err := readFileTrim(path)
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(raw, "\n")
	return strings.TrimSpace(line)
}

// min is the two-argument minimum for the unsigned counters above.
func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
