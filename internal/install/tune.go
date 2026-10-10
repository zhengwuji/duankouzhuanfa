package install

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// sysctlSettings is the relay's kernel tuning, in application order.
//
// Every entry exists because a relay has a specific shape of traffic: two
// long-haul legs (so packet loss is expected), many concurrent streams, and a
// fresh outbound connection for every client connection. The defaults are
// tuned for a single interactive session on a low-latency link, which is the
// opposite of this.
//
// The values are deliberately conservative: nothing here weakens a security
// boundary or changes semantics, only buffer sizes and bookkeeping.
var sysctlSettings = []struct {
	Key   string
	Value string
	// Why is kept next to the value so a future reader can judge whether it
	// still applies rather than cargo-culting it.
	Why string
}{
	{"net.core.default_qdisc", "fq",
		"BBR 需要 fq 作为队列规则才能发挥作用"},
	{"net.core.rmem_max", "67108864",
		"跨国链路带宽延迟积很大，默认接收缓冲（通常 208KB）会限制单连接吞吐"},
	{"net.core.wmem_max", "67108864",
		"同上，发送方向"},
	{"net.ipv4.tcp_rmem", "4096 87380 33554432",
		"自动调优的上限，与 rmem_max 配合"},
	{"net.ipv4.tcp_wmem", "4096 65536 33554432",
		"自动调优的上限，与 wmem_max 配合"},
	{"net.core.somaxconn", "32768",
		"中转同时持有大量连接，默认 4096 在突发时丢握手"},
	{"net.ipv4.tcp_max_syn_backlog", "8192",
		"与 somaxconn 配合，避免高延迟链路上 SYN 被丢弃"},
	{"net.ipv4.ip_local_port_range", "10240 65535",
		"每条客户端连接对应一条出站连接，默认约 28k 个端口在高峰期会耗尽"},
	{"net.ipv4.tcp_tw_reuse", "1",
		"复用 TIME_WAIT 的出站连接；只影响主动发起方，是安全的"},
	{"net.ipv4.tcp_slow_start_after_idle", "0",
		"长连接空闲后再突发时不要重置拥塞窗口——中转的典型流量形态"},
	{"net.ipv4.tcp_mtu_probing", "1",
		"路径上若有设备丢弃 ICMP，能自动降低 MSS 而不是形成黑洞"},
	{"net.ipv4.tcp_fastopen", "3",
		"客户端与服务端都启用，省一个 RTT"},
	{"net.ipv4.tcp_keepalive_time", "600",
		"更积极地回收空闲的已建立连接，避免堆积无用状态"},
	{"net.ipv4.tcp_keepalive_intvl", "30",
		"与 keepalive_time 配合"},
	{"net.ipv4.tcp_keepalive_probes", "5",
		"与 keepalive_time 配合"},
}

// congestionControlKey is applied separately because it depends on what the
// running kernel actually offers.
const congestionControlKey = "net.ipv4.tcp_congestion_control"

// SysctlContent renders the file written to SysctlPath.
func SysctlContent(withBBR bool) string {
	var b strings.Builder
	b.WriteString("# PortTransit 中转性能调优\n")
	b.WriteString("# 由 porttransit 生成；删除本文件并执行 sysctl --system 即可恢复系统默认值。\n")
	b.WriteString("# 这些参数针对的是「两段跨国链路 + 大量并发连接」的流量形态。\n\n")
	for _, s := range sysctlSettings {
		fmt.Fprintf(&b, "# %s\n%s = %s\n", s.Why, s.Key, s.Value)
	}
	if withBBR {
		b.WriteString("\n# 有丢包的跨国链路上，CUBIC 会把窗口砍半而 BBR 不会。\n")
		fmt.Fprintf(&b, "%s = bbr\n", congestionControlKey)
	}
	return b.String()
}

// TuneResult reports what the tuning pass did.
type TuneResult struct {
	// Applied counts settings the kernel accepted.
	Applied int
	// Skipped counts settings the kernel refused, with the reasons.
	Skipped map[string]string
	// CongestionControl is the value in effect afterwards.
	CongestionControl string
	// QueueDiscipline is the value in effect afterwards.
	QueueDiscipline string
	// BBRSupported reports whether bbr is in effect afterwards, decided by the
	// read-back of tcp_congestion_control rather than by what the kernel
	// advertised beforehand.
	BBRSupported bool
	// Writable is false in containers where /proc/sys is read-only.
	Writable bool
	// Path is where the persistent file was written, empty when not written.
	Path string
}

// Summary renders a one-line description for the console and the installer.
func (r TuneResult) Summary() string {
	if !r.Writable {
		// Nothing took effect. Saying "applied" here would be a lie the
		// operator cannot see through, because the relay keeps working either
		// way and the difference only shows up as unexplained slowness.
		return "内核参数不可写（容器环境？），未能调优"
	}
	parts := []string{fmt.Sprintf("拥塞控制 %s", r.CongestionControl), fmt.Sprintf("队列规则 %s", r.QueueDiscipline)}
	if !r.BBRSupported {
		// Deliberately not "内核不支持 BBR": the usual reason is an absent
		// tcp_bbr module or a read-only /proc/sys, and asserting the kernel
		// lacks the algorithm would send the operator looking in the wrong
		// place. What is certain is that it is not in effect.
		parts = append(parts, "BBR 未生效，已改用缓冲区与连接数调优")
	}
	if len(r.Skipped) > 0 {
		parts = append(parts, fmt.Sprintf("%d 项未生效", len(r.Skipped)))
	}
	return strings.Join(parts, "，")
}

// SkippedList renders the refused settings sorted for stable output.
func (r TuneResult) SkippedList() []string {
	keys := make([]string, 0, len(r.Skipped))
	for k := range r.Skipped {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+": "+r.Skipped[k])
	}
	return out
}

// TuneKernel applies the relay's kernel tuning and persists it.
//
// It is idempotent and degrades gracefully: a container with a read-only
// /proc/sys, or an old kernel without bbr, reports what it could not do rather
// than failing the installation. A relay still works without any of this — it
// is simply slower on a lossy path.
func TuneKernel(persist bool) (TuneResult, error) {
	res := TuneResult{Skipped: map[string]string{}}

	if runtime.GOOS != "linux" {
		return res, fmt.Errorf("install: 内核调优只支持 Linux（当前是 %s）", runtime.GOOS)
	}

	// bbr is probed, not merely detected.
	//
	// Most kernels ship tcp_bbr as a module that nothing pulls in at boot, so a
	// freshly provisioned host advertises neither bbr in
	// tcp_available_congestion_control nor the module in lsmod — which is the
	// common case for exactly the machines this runs on. The module is loaded
	// when bbr is *missing*, not when it is present.
	//
	// Loading it here is belt-and-braces: the write below is what actually
	// decides (see there), but an accurate availability list makes the reported
	// state and the `--show` preview agree with reality.
	if !bbrAvailable() {
		loadBBRModule()
	}

	// Every setting is attempted independently. A restricted container often
	// exposes a handful of writable knobs and hides the rest, so a single
	// global "is /proc/sys writable" probe would throw away the ones that
	// would have worked — somaxconn in particular is usually still settable.
	//
	// Success is decided by reading the value back, not by the write returning
	// nil: some environments (WSL is one) accept the write and discard it, and
	// reporting those as applied would tell the operator their relay is tuned
	// when it is not.
	apply := func(key, value string) {
		if err := writeSysctl(key, value); err != nil {
			res.Skipped[key] = err.Error()
			return
		}
		if got := readSysctl(key); !sysctlValueEqual(got, value) {
			res.Skipped[key] = fmt.Sprintf("写入未生效（仍为 %q）", got)
			return
		}
		res.Applied++
		res.Writable = true
	}

	for _, s := range sysctlSettings {
		apply(s.Key, s.Value)
	}

	// bbr is requested unconditionally and judged by the read-back, because
	// "is bbr in tcp_available_congestion_control?" is not the question that
	// matters. Linux autoloads the algorithm's module when one is written to
	// tcp_congestion_control, so on a host where tcp_bbr was never loaded the
	// list says no and the write still succeeds — gating on the list is what
	// made this report "内核不支持 BBR" on machines that support it fine.
	//
	// A kernel with no bbr at all rejects the write, which lands in Skipped
	// like any other refused setting.
	apply(congestionControlKey, "bbr")

	res.CongestionControl = readSysctl(congestionControlKey)
	res.QueueDiscipline = readSysctl("net.core.default_qdisc")
	res.BBRSupported = res.CongestionControl == "bbr"

	if persist && res.Writable {
		content := SysctlContent(res.BBRSupported)
		if err := os.MkdirAll(filepath.Dir(SysctlPath), 0o755); err != nil {
			return res, fmt.Errorf("install: create sysctl dir: %w", err)
		}
		if err := os.WriteFile(SysctlPath, []byte(content), 0o644); err != nil {
			return res, fmt.Errorf("install: write %s: %w", SysctlPath, err)
		}
		res.Path = SysctlPath
	}
	return res, nil
}

// sysctlValueEqual compares a read-back value with what was written.
//
// Kernels normalise some values: a multi-value knob may collapse whitespace or
// report a rounded figure, and writing "3" to a knob whose range starts at 1
// reads back as "3" while writing to tcp_fastopen may report a different bit
// set. So the comparison is on whitespace-normalised tokens rather than raw
// bytes, which is strict enough to catch a discarded write without flagging a
// cosmetic difference as a failure.
func sysctlValueEqual(got, want string) bool {
	return strings.Join(strings.Fields(got), " ") == strings.Join(strings.Fields(want), " ")
}

// sysctlRoot is where kernel parameters are read and written. It is a variable
// so tests can exercise the real apply path against a temporary directory
// instead of mutating the host's kernel.
var sysctlRoot = "/proc/sys"

// sysctlFilePath maps a dotted key to its file under sysctlRoot.
func sysctlFilePath(key string) string {
	return filepath.Join(sysctlRoot, filepath.FromSlash(strings.ReplaceAll(key, ".", "/")))
}

// bbrAvailable reports whether the kernel currently offers the bbr algorithm.
//
// A false result does not mean bbr is unusable: an unloaded tcp_bbr module is
// absent from this list and still works once loaded. Use bbrModulePresent for
// the "could it work here" question.
func bbrAvailable() bool {
	return strings.Contains(readSysctl("net.ipv4.tcp_available_congestion_control"), "bbr")
}

// loadBBRModule asks the kernel to load tcp_bbr.
//
// Failures are ignored on purpose: a kernel with bbr built in needs nothing,
// and one without it cannot be helped from here. Whether bbr actually took
// effect is decided by the write and its read-back, never by this call.
func loadBBRModule() {
	_ = bbrLoader()
}

// bbrLoader is where the module load happens. It is a variable so tests can
// exercise the tuning pass without running modprobe on the test host.
var bbrLoader = func() error {
	if runtime.GOOS != "linux" {
		return errors.New("not linux")
	}
	return exec.Command("modprobe", "tcp_bbr").Run()
}

// bbrModulePresent reports whether the kernel ships an unloaded tcp_bbr module.
//
// This is the read-only companion to loadBBRModule, for `tune --show`, which
// must preview what a real run would do without modifying the host. Without it
// the preview would omit bbr on exactly the freshly provisioned hosts where a
// real run does set it.
func bbrModulePresent() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	out, err := exec.Command("modinfo", "-n", "tcp_bbr").Output()
	return err == nil && strings.TrimSpace(string(out)) != ""
}

// writeSysctl sets one parameter.
func writeSysctl(key, value string) error {
	path := sysctlFilePath(key)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return errors.New("内核不提供该参数")
		}
		return err
	}
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		return unwrapSyscall(err)
	}
	return nil
}

// readSysctl reads one parameter, returning "" when unavailable.
func readSysctl(key string) string {
	b, err := os.ReadFile(sysctlFilePath(key))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// unwrapSyscall turns a raw write error into something an operator can act on.
// "operation not permitted" from a container is the common case and reads very
// differently from a genuine bug.
func unwrapSyscall(err error) error {
	if errors.Is(err, os.ErrPermission) {
		return errors.New("权限不足（容器或只读 /proc/sys）")
	}
	return err
}

// Tune is the CLI entry point for `porttransit tune`.
func Tune(args []string) error {
	fs := flag.NewFlagSet("tune", flag.ContinueOnError)
	var (
		show    bool
		noWrite bool
		revert  bool
	)
	fs.BoolVar(&show, "show", false, "只打印将要写入的配置，不做修改")
	fs.BoolVar(&noWrite, "no-persist", false, "应用但不在 /etc/sysctl.d 留下文件")
	fs.BoolVar(&revert, "revert", false, "删除持久化文件（当前生效值需重启才恢复）")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if show {
		// The preview is generated from the same source as the real thing, so
		// what an operator reviews is exactly what would be applied.
		//
		// bbr counts as available when the algorithm is offered *or* the module
		// merely exists: a real run loads the module and then sets bbr, so a
		// preview that only checked the live list would hide the most important
		// line on a fresh host.
		fmt.Print(SysctlContent(bbrAvailable() || bbrModulePresent()))
		return nil
	}

	if revert {
		if err := os.Remove(SysctlPath); err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("没有找到 %s，无需删除\n", SysctlPath)
				return nil
			}
			return fmt.Errorf("install: remove %s: %w", SysctlPath, err)
		}
		fmt.Printf("✔ 已删除 %s\n", SysctlPath)
		fmt.Println("  当前生效的内核参数仍是调优值，重启后恢复系统默认。")
		return nil
	}

	res, err := TuneKernel(!noWrite)
	if err != nil {
		return err
	}
	// The marker has to match what actually happened: a tick next to "未能调优"
	// reads as success and is exactly the kind of detail an operator skims past.
	if res.Writable {
		fmt.Printf("✔ %s\n", res.Summary())
	} else {
		fmt.Printf("! %s\n", res.Summary())
	}
	if res.Path != "" {
		fmt.Printf("  已写入 %s\n", res.Path)
	}
	for _, line := range res.SkippedList() {
		fmt.Printf("  ! %s\n", line)
	}
	return nil
}
