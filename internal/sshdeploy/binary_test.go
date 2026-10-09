package sshdeploy

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// makeELF builds a minimal ELF header with the given machine type.
func makeELF(machine uint16, bigEndian bool) []byte {
	b := make([]byte, 64)
	copy(b, []byte{0x7f, 'E', 'L', 'F'})
	b[4] = 2 // 64-bit
	if bigEndian {
		b[5] = 2
		binary.BigEndian.PutUint16(b[18:20], machine)
	} else {
		b[5] = 1
		binary.LittleEndian.PutUint16(b[18:20], machine)
	}
	return b
}

// makePE builds a minimal DOS stub plus PE header.
func makePE(machine uint16) []byte {
	b := make([]byte, 0x200)
	copy(b, []byte{'M', 'Z'})
	const peOff = 0x80
	binary.LittleEndian.PutUint32(b[0x3C:0x40], peOff)
	copy(b[peOff:], []byte{'P', 'E', 0x00, 0x00})
	binary.LittleEndian.PutUint16(b[peOff+4:peOff+6], machine)
	return b
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInspectBinaryIdentifiesELF(t *testing.T) {
	cases := []struct {
		name    string
		data    []byte
		want    BinaryFormat
		usable  bool
		goarch  string
		comment string
	}{
		{"amd64", makeELF(0x3E, false), BinaryFormat{OS: "linux", Arch: "amd64"}, true, "amd64", "the common server case"},
		{"arm64", makeELF(0xB7, false), BinaryFormat{OS: "linux", Arch: "arm64"}, true, "arm64", "ARM servers and Apple silicon VMs"},
		{"arm", makeELF(0x28, false), BinaryFormat{OS: "linux", Arch: "arm"}, false, "amd64", "32-bit ARM is not a supported target"},
		{"386", makeELF(0x03, false), BinaryFormat{OS: "linux", Arch: "386"}, false, "amd64", "32-bit x86 is not a supported target"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeTemp(t, "bin", tc.data)
			got, err := InspectBinary(p)
			if err != nil {
				t.Fatalf("InspectBinary: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			if u := got.UsableOn("linux", tc.goarch); u != tc.usable {
				t.Fatalf("UsableOn(linux,%s) = %v, want %v (%s)", tc.goarch, u, tc.usable, tc.comment)
			}
		})
	}
}

// A big-endian ELF must be read with its own byte order; assuming little-endian
// would decode arm64 (0x00B7) as 0xB700, an unknown machine.
func TestInspectBinaryRespectsELFByteOrder(t *testing.T) {
	p := writeTemp(t, "be", makeELF(0xB7, true))
	got, err := InspectBinary(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.OS != "linux" || got.Arch != "arm64" {
		t.Fatalf("big-endian arm64 decoded as %+v", got)
	}
}

func TestInspectBinaryIdentifiesPE(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mach   uint16
		arch   string
		usable bool
	}{
		{"amd64", 0x8664, "amd64", false},
		{"arm64", 0xAA64, "arm64", false},
		{"386", 0x014C, "386", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := writeTemp(t, "bin.exe", makePE(tc.mach))
			got, err := InspectBinary(p)
			if err != nil {
				t.Fatal(err)
			}
			if got.OS != "windows" || got.Arch != tc.arch {
				t.Fatalf("got %+v, want windows/%s", got, tc.arch)
			}
			// This is the whole point: a Windows build must never be accepted
			// as something that runs on Linux, even when the CPU matches.
			if got.UsableOn("linux", tc.arch) {
				t.Fatalf("windows/%s wrongly reported as usable on linux/%s", tc.arch, tc.arch)
			}
		})
	}
}

func TestInspectBinaryIdentifiesMachO(t *testing.T) {
	b := make([]byte, 32)
	binary.BigEndian.PutUint32(b[0:4], 0xFEEDFACF)
	binary.BigEndian.PutUint32(b[4:8], 0x0100000C) // arm64
	p := writeTemp(t, "macho", b)
	got, err := InspectBinary(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.OS != "darwin" || got.Arch != "arm64" {
		t.Fatalf("got %+v, want darwin/arm64", got)
	}
	if got.UsableOn("linux", "arm64") {
		t.Fatal("a macOS build must not be usable on linux")
	}
}

func TestInspectBinaryRejectsNonExecutables(t *testing.T) {
	for name, data := range map[string][]byte{
		"shell script": []byte("#!/bin/sh\necho hi\n"),
		"json":         []byte(`{"mode":"server"}`),
		"truncated":    {0x7f},
		"empty":        {},
	} {
		t.Run(name, func(t *testing.T) {
			p := writeTemp(t, "f", data)
			got, err := InspectBinary(p)
			if err != nil {
				// A too-short file is a hard error, which is fine.
				return
			}
			if got.OS != "" {
				t.Fatalf("non-executable %s identified as %+v", name, got)
			}
			if got.UsableOn("linux", "amd64") {
				t.Fatal("a non-executable must never be usable")
			}
		})
	}
}

func TestInspectBinaryMissingFile(t *testing.T) {
	if _, err := InspectBinary(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

// The running test binary is the one case where we know the real answer.
func TestInspectBinaryMatchesTheHost(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip("cannot locate the test executable")
	}
	got, err := InspectBinary(self)
	if err != nil {
		t.Fatal(err)
	}
	wantOS := runtime.GOOS
	// Go reports "linux", "windows", "darwin" — the same strings we produce.
	if got.OS != wantOS {
		t.Fatalf("host binary reported as %q, want %q", got.OS, wantOS)
	}
	if got.Arch != runtime.GOARCH {
		t.Fatalf("host binary arch %q, want %q", got.Arch, runtime.GOARCH)
	}
	if !got.UsableOn(runtime.GOOS, runtime.GOARCH) {
		t.Fatal("the host binary must be usable on its own host")
	}
}

func TestFindCompatibleBinaryPicksTheMatchingBuild(t *testing.T) {
	dir := t.TempDir()
	// A Windows client bundle: the running .exe plus a linux build beside it.
	execPath := filepath.Join(dir, "porttransit.exe")
	if err := os.WriteFile(execPath, makePE(0x8664), 0o755); err != nil {
		t.Fatal(err)
	}
	linux := filepath.Join(dir, "porttransit-linux-amd64")
	if err := os.WriteFile(linux, makeELF(0x3E, false), 0o755); err != nil {
		t.Fatal(err)
	}

	found, hint := FindCompatibleBinary(execPath, "linux", "amd64")
	if found != linux {
		t.Fatalf("found %q (hint %q), want %q", found, hint, linux)
	}
}

func TestFindCompatibleBinaryIgnoresTheWrongArchitecture(t *testing.T) {
	dir := t.TempDir()
	execPath := filepath.Join(dir, "porttransit.exe")
	if err := os.WriteFile(execPath, makePE(0x8664), 0o755); err != nil {
		t.Fatal(err)
	}
	// Only an arm64 Linux build is present, but we need amd64. Uploading it
	// would fail on the remote host just as badly as the Windows one.
	if err := os.WriteFile(filepath.Join(dir, "porttransit-linux-arm64"), makeELF(0xB7, false), 0o755); err != nil {
		t.Fatal(err)
	}

	found, hint := FindCompatibleBinary(execPath, "linux", "amd64")
	if found != "" {
		t.Fatalf("picked %q despite the architecture mismatch", found)
	}
	if hint == "" {
		t.Fatal("a failure must list the paths that were tried")
	}
}

func TestFindCompatibleBinaryReturnsNothingWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	execPath := filepath.Join(dir, "porttransit.exe")
	if err := os.WriteFile(execPath, makePE(0x8664), 0o755); err != nil {
		t.Fatal(err)
	}
	found, hint := FindCompatibleBinary(execPath, "linux", "amd64")
	if found != "" {
		t.Fatalf("unexpectedly found %q", found)
	}
	if hint == "" {
		t.Fatal("expected a hint naming the inspected paths")
	}
}

func TestFindCompatibleBinaryHandlesEmptyPath(t *testing.T) {
	if p, h := FindCompatibleBinary("", "linux", "amd64"); p != "" || h != "" {
		t.Fatalf("empty input produced %q / %q", p, h)
	}
}

func TestExpandDownloadURL(t *testing.T) {
	got := ExpandDownloadURL(
		"https://example.com/{os}/{arch}/porttransit_{os}_{arch}.tar.gz", "linux", "arm64")
	want := "https://example.com/linux/arm64/porttransit_linux_arm64.tar.gz"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// A URL with no placeholders must pass through untouched.
	plain := "https://example.com/fixed.tar.gz"
	if got := ExpandDownloadURL(plain, "linux", "amd64"); got != plain {
		t.Fatalf("plain URL was rewritten to %q", got)
	}
}

func TestBinaryFormatString(t *testing.T) {
	for _, tc := range []struct {
		f    BinaryFormat
		want string
	}{
		{BinaryFormat{OS: "linux", Arch: "amd64"}, "linux/amd64"},
		{BinaryFormat{OS: "windows", Arch: "amd64"}, "windows/amd64"},
		{BinaryFormat{OS: "linux"}, "linux（架构未知）"},
		{BinaryFormat{}, "无法识别的可执行文件格式"},
	} {
		if got := tc.f.String(); got != tc.want {
			t.Fatalf("String() = %q, want %q", got, tc.want)
		}
	}
}
