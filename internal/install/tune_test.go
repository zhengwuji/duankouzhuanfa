package install

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSysctlContentIncludesEverySetting(t *testing.T) {
	content := SysctlContent(true)
	for _, s := range sysctlSettings {
		line := s.Key + " = " + s.Value
		if !strings.Contains(content, line) {
			t.Errorf("the generated file is missing %q", line)
		}
	}
	// The rationale has to travel with the value: a bare list of magic numbers
	// is what gets cargo-culted into a broken config later.
	if !strings.Contains(content, sysctlSettings[0].Why) {
		t.Error("the generated file dropped the explanations")
	}
}

func TestSysctlContentAddsBBROnlyWhenSupported(t *testing.T) {
	with := SysctlContent(true)
	if !strings.Contains(with, "net.ipv4.tcp_congestion_control = bbr") {
		t.Error("bbr was not requested even though the kernel supports it")
	}

	without := SysctlContent(false)
	if strings.Contains(without, "net.ipv4.tcp_congestion_control") {
		t.Error("the file sets a congestion control the kernel does not offer, " +
			"which would fail on reload and could drop the whole file")
	}
	// The rest of the tuning must still be present without bbr.
	if !strings.Contains(without, "net.core.rmem_max") {
		t.Error("buffer tuning disappeared when bbr was unavailable")
	}
}

// The file is written to /etc/sysctl.d and read by tools that expect the
// documented `key = value` syntax; a comment without '#' would break parsing.
func TestSysctlContentIsParseable(t *testing.T) {
	for _, line := range strings.Split(SysctlContent(true), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			t.Errorf("unparseable line %q", line)
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" || value == "" {
			t.Errorf("line %q has an empty key or value", line)
		}
		if !strings.HasPrefix(key, "net.") {
			t.Errorf("line %q does not set a net.* key", line)
		}
	}
}

// Duplicate keys would make the effective value depend on file order.
func TestSysctlContentHasNoDuplicateKeys(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range sysctlSettings {
		if seen[s.Key] {
			t.Errorf("%s appears twice in the tuning list", s.Key)
		}
		seen[s.Key] = true
	}
	if seen[congestionControlKey] {
		t.Errorf("%s is in the static list as well as the bbr branch", congestionControlKey)
	}
}

// A value that is not a plausible kernel parameter would be applied blindly by
// a root process, so guard the shapes we actually use.
func TestSysctlValuesLookReasonable(t *testing.T) {
	for _, s := range sysctlSettings {
		if strings.ContainsAny(s.Value, "\n\r\x00") {
			t.Errorf("%s has a control character in its value", s.Key)
		}
		if s.Value == "" {
			t.Errorf("%s has an empty value", s.Key)
		}
		if s.Why == "" {
			t.Errorf("%s has no explanation", s.Key)
		}
	}
}

func TestTuneResultSummaryReportsWhatHappened(t *testing.T) {
	base := TuneResult{
		Writable:          true,
		Applied:           10,
		CongestionControl: "bbr",
		QueueDiscipline:   "fq",
		BBRSupported:      true,
	}
	got := base.Summary()
	if !strings.Contains(got, "bbr") || !strings.Contains(got, "fq") {
		t.Errorf("summary %q does not name the effective settings", got)
	}
	if strings.Contains(got, "未生效") {
		t.Errorf("summary %q mentions failures when there were none", got)
	}

	// A container is the common "did nothing" case and must say so plainly
	// rather than claiming success.
	container := TuneResult{Writable: false}
	if !strings.Contains(container.Summary(), "未能调优") {
		t.Errorf("summary %q does not explain that nothing was applied", container.Summary())
	}

	noBBR := base
	noBBR.BBRSupported = false
	if !strings.Contains(noBBR.Summary(), "BBR") {
		t.Errorf("summary %q does not mention the missing BBR support", noBBR.Summary())
	}

	withSkips := base
	withSkips.Skipped = map[string]string{"net.core.somaxconn": "read-only file system"}
	if !strings.Contains(withSkips.Summary(), "1 项未生效") {
		t.Errorf("summary %q does not report skipped settings", withSkips.Summary())
	}
}

func TestSkippedListIsSorted(t *testing.T) {
	res := TuneResult{Skipped: map[string]string{
		"net.ipv4.tcp_wmem": "x",
		"net.core.rmem_max": "y",
		"net.ipv4.tcp_rmem": "z",
	}}
	got := res.SkippedList()
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Fatalf("entries are not sorted: %v", got)
		}
	}
}

func TestSkippedListEmptyWhenEverythingApplied(t *testing.T) {
	if got := (TuneResult{}).SkippedList(); len(got) != 0 {
		t.Fatalf("got %v, want nothing", got)
	}
}

// TuneKernel is Linux-only; the point of the guard is a clear message rather
// than a confusing write failure.
func TestTuneKernelRejectsNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("this host is Linux, so the non-Linux guard cannot be exercised")
	}
	if _, err := TuneKernel(false); err == nil {
		t.Fatal("expected an error on a non-Linux host")
	}
}

// On Linux the call must not fail even in a container where nothing is
// writable: an unusable relay is a much worse outcome than an untuned one.
func TestTuneKernelDegradesGracefully(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	res, err := TuneKernel(false)
	if err != nil {
		t.Fatalf("TuneKernel returned an error instead of degrading: %v", err)
	}
	if !res.Writable {
		// A container: nothing applied, and it must say so.
		if res.Applied != 0 {
			t.Errorf("applied %d settings in a read-only environment", res.Applied)
		}
		if !strings.Contains(res.Summary(), "未能调优") {
			t.Errorf("summary %q hides that nothing was applied", res.Summary())
		}
		return
	}
	if res.Applied == 0 {
		t.Error("a writable /proc/sys applied nothing")
	}
	if res.CongestionControl == "" {
		t.Error("did not report the effective congestion control")
	}
	// Whatever happened, every refusal must carry a reason.
	for k, why := range res.Skipped {
		if strings.TrimSpace(why) == "" {
			t.Errorf("%s was skipped with no explanation", k)
		}
	}
}

// persist=false must never touch the filesystem; the GUI preview and the
// --no-persist flag rely on that.
func TestTuneKernelDoesNotPersistWhenAskedNotTo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	res, err := TuneKernel(false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Path != "" {
		t.Fatalf("wrote %s despite persist=false", res.Path)
	}
}

func TestReadSysctlReturnsEmptyForUnknownKey(t *testing.T) {
	if got := readSysctl("net.ipv4.this_does_not_exist"); got != "" {
		t.Fatalf("got %q for a nonexistent key, want an empty string", got)
	}
}

// fakeSysctlRoot builds a directory tree that looks like /proc/sys, so the real
// apply path can be exercised without touching the host kernel.
func fakeSysctlRoot(t *testing.T, keys ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, k := range keys {
		p := filepath.Join(root, filepath.FromSlash(strings.ReplaceAll(k, ".", "/")))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("default\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// withSysctlRoot points the package at a temporary tree for one test.
//
// It also stubs out the bbr module loader. A fake /proc/sys means the test is
// simulating a kernel, so actually running modprobe on the test host would be
// both pointless and a side effect on the developer's machine.
func withSysctlRoot(t *testing.T, root string) {
	t.Helper()
	old := sysctlRoot
	sysctlRoot = root
	oldLoader := bbrLoader
	bbrLoader = func() error { return nil }
	t.Cleanup(func() {
		sysctlRoot = old
		bbrLoader = oldLoader
	})
}

// This is the behaviour that matters: every setting is attempted on its own.
// A restricted container typically exposes a few writable knobs and hides the
// rest, and an all-or-nothing probe would discard the ones that would work.
func TestTuneKernelAppliesEachSettingIndependently(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	// Only two of the tuning keys exist in this fake kernel.
	root := fakeSysctlRoot(t, "net.core.somaxconn", "net.ipv4.tcp_tw_reuse")
	withSysctlRoot(t, root)

	res, err := TuneKernel(false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied != 2 {
		t.Errorf("applied %d settings, want the 2 that exist", res.Applied)
	}
	if !res.Writable {
		t.Error("Writable should be true once something was actually applied")
	}
	// The missing ones must be reported, not silently dropped.
	for _, key := range []string{"net.core.rmem_max", "net.ipv4.tcp_rmem"} {
		if _, ok := res.Skipped[key]; !ok {
			t.Errorf("%s is missing from the skipped list", key)
		}
	}
	// And the values must really be on disk.
	got, err := os.ReadFile(filepath.Join(root, "net/core/somaxconn"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "32768" {
		t.Errorf("somaxconn is %q, want 32768", strings.TrimSpace(string(got)))
	}
}

func TestTuneKernelReportsNothingWritable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	// An empty tree: nothing exists, so nothing can be applied.
	withSysctlRoot(t, t.TempDir())

	res, err := TuneKernel(false)
	if err != nil {
		t.Fatalf("a read-only environment must not be an error: %v", err)
	}
	if res.Writable {
		t.Error("Writable is true although nothing was applied")
	}
	if res.Applied != 0 {
		t.Errorf("applied %d settings in an empty tree", res.Applied)
	}
	if !strings.Contains(res.Summary(), "未能调优") {
		t.Errorf("summary %q does not say that nothing was applied", res.Summary())
	}
	if res.Path != "" {
		t.Errorf("wrote %s although nothing was applied", res.Path)
	}
}

// The reported bbr state is decided by the read-back, not by what the kernel
// advertised before the write.
//
// This is the regression that mattered in the field: Linux autoloads tcp_bbr
// when bbr is written to tcp_congestion_control, so a freshly provisioned host
// advertises "reno cubic" and still ends up on bbr. Gating on the advertised
// list made the installer announce "内核不支持 BBR" on machines that support it
// perfectly well.
func TestTuneKernelSetsBBRWhenTheKernelAcceptsIt(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	root := fakeSysctlRoot(t,
		"net.ipv4.tcp_available_congestion_control",
		"net.ipv4.tcp_congestion_control",
	)
	withSysctlRoot(t, root)
	// bbr is absent from the advertised list, as on an unloaded module.
	if err := os.WriteFile(filepath.Join(root, "net/ipv4/tcp_available_congestion_control"),
		[]byte("reno cubic\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "net/ipv4/tcp_congestion_control"),
		[]byte("cubic\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := TuneKernel(false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.BBRSupported {
		t.Error("the kernel accepted bbr but it was reported as unsupported")
	}
	if res.CongestionControl != "bbr" {
		t.Errorf("result reports %q, want bbr", res.CongestionControl)
	}
	got, err := os.ReadFile(filepath.Join(root, "net/ipv4/tcp_congestion_control"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "bbr" {
		t.Errorf("congestion control is %q, want bbr", strings.TrimSpace(string(got)))
	}
}

// And when the kernel genuinely has no bbr, the refusal must be reported rather
// than papered over. A directory in place of the knob makes the write fail the
// way an unknown algorithm does, without depending on running as non-root.
func TestTuneKernelReportsBBRWhenTheKernelRefusesIt(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	root := fakeSysctlRoot(t, "net.ipv4.tcp_available_congestion_control")
	withSysctlRoot(t, root)
	if err := os.WriteFile(filepath.Join(root, "net/ipv4/tcp_available_congestion_control"),
		[]byte("reno cubic\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The knob exists but cannot be written, so bbr never takes effect.
	if err := os.MkdirAll(filepath.Join(root, "net/ipv4/tcp_congestion_control"), 0o755); err != nil {
		t.Fatal(err)
	}

	res, err := TuneKernel(false)
	if err != nil {
		t.Fatal(err)
	}
	if res.BBRSupported {
		t.Error("bbr was reported as supported although the write was refused")
	}
	if _, ok := res.Skipped[congestionControlKey]; !ok {
		t.Errorf("a refused %s was not reported in the skipped list", congestionControlKey)
	}
}

// A write that is accepted but silently discarded must not count as bbr taking
// effect, for the same reason the other settings are read back.
func TestTuneKernelDoesNotClaimBBROnADiscardedWrite(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	root := fakeSysctlRoot(t,
		"net.ipv4.tcp_available_congestion_control",
		"net.ipv4.tcp_congestion_control",
	)
	withSysctlRoot(t, root)
	if err := os.WriteFile(filepath.Join(root, "net/ipv4/tcp_available_congestion_control"),
		[]byte("reno cubic bbr\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Read-only knob: writing fails for a normal user, and root's write is
	// caught by the read-back below either way.
	if err := os.Chmod(filepath.Join(root, "net/ipv4/tcp_congestion_control"), 0o444); err != nil {
		t.Fatal(err)
	}

	res, err := TuneKernel(false)
	if err != nil {
		t.Fatal(err)
	}
	// Whatever happened, the two must agree — that is the invariant.
	if res.BBRSupported != (res.CongestionControl == "bbr") {
		t.Errorf("BBRSupported=%v but congestion control reads %q",
			res.BBRSupported, res.CongestionControl)
	}
}

func TestWriteSysctlRejectsAnUnknownKey(t *testing.T) {
	withSysctlRoot(t, t.TempDir())
	err := writeSysctl("net.ipv4.does_not_exist", "1")
	if err == nil {
		t.Fatal("expected an error for a key the kernel does not provide")
	}
	if !strings.Contains(err.Error(), "不提供") {
		t.Errorf("error %q does not say the parameter is unavailable", err)
	}
}

// A write that the kernel silently discards must not be reported as applied.
// WSL accepts writes to /proc/sys and ignores them; claiming success there
// would tell an operator their relay is tuned when it is not.
func TestTuneKernelDetectsADiscardedWrite(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	root := fakeSysctlRoot(t, "net.core.somaxconn")
	withSysctlRoot(t, root)
	// Make the file read-only *and* unchanging: a plain write to a 0444 file
	// fails outright, so use a directory in place of the file to make the
	// write fail while the read still yields the old value.
	if err := os.Remove(filepath.Join(root, "net/core/somaxconn")); err != nil {
		t.Fatal(err)
	}
	// Recreate it read-only so writes fail but reads succeed.
	if err := os.WriteFile(filepath.Join(root, "net/core/somaxconn"), []byte("128\n"), 0o444); err != nil {
		t.Fatal(err)
	}

	res, err := TuneKernel(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, skipped := res.Skipped["net.core.somaxconn"]; !skipped {
		// Running as root can write a 0444 file, so the write may genuinely
		// succeed here; in that case the read-back must agree with it.
		if got := readSysctl("net.core.somaxconn"); got != "32768" {
			t.Errorf("somaxconn was reported applied but reads back as %q", got)
		}
	}
}

func TestSysctlValueEqualToleratesWhitespaceOnly(t *testing.T) {
	if !sysctlValueEqual("32768", "32768") {
		t.Error("identical values compared unequal")
	}
	if !sysctlValueEqual("10240 65535\n", "10240 65535") {
		t.Error("a trailing newline should not count as a difference")
	}
	if !sysctlValueEqual("10240  65535", "10240 65535") {
		t.Error("collapsed whitespace should not count as a difference")
	}
	// A genuinely different value must not compare equal, or a discarded write
	// would look like success.
	if sysctlValueEqual("128", "32768") {
		t.Error("different values compared equal")
	}
}

// Tune's console output must not put a success marker next to a report of
// failure. An operator skims the tick marks, so a tick beside "未能调优" reads
// as "this worked" — which is the one thing a tuning step must not imply when
// nothing was applied.
func TestTuneCommandOutputMarkersMatchReality(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	// An empty tree: nothing can be applied, so the honest output is a warning.
	withSysctlRoot(t, t.TempDir())

	out, err := captureStdout(t, func() error { return Tune(nil) })
	if err != nil {
		t.Fatalf("Tune returned an error instead of degrading: %v", err)
	}

	if strings.Contains(out, "✔") {
		t.Errorf("a success marker was printed although nothing was applied:\n%s", out)
	}
	if !strings.Contains(out, "未能调优") {
		t.Errorf("the output does not say nothing was applied:\n%s", out)
	}
}

// And the converse: when settings really are applied, the output must say so.
func TestTuneCommandReportsSuccessWhenItApplies(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	root := fakeSysctlRoot(t, "net.core.somaxconn")
	withSysctlRoot(t, root)

	out, err := captureStdout(t, func() error { return Tune([]string{"--no-persist"}) })
	if err != nil {
		t.Fatalf("Tune: %v", err)
	}
	if !strings.Contains(out, "✔") {
		t.Errorf("a setting was applied but the output shows no success marker:\n%s", out)
	}
}
