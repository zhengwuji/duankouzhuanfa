package sshdeploy

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// BinaryFormat is the platform a local executable actually runs on.
type BinaryFormat struct {
	// OS is "linux", "windows", "darwin", or "" when the header is not a
	// recognised executable.
	OS string
	// Arch is "amd64", "arm64", or "" when it could not be determined.
	Arch string
}

// UsableOn reports whether this binary can execute on the given platform.
func (f BinaryFormat) UsableOn(goos, goarch string) bool {
	return f.OS != "" && f.OS == goos && f.Arch == goarch
}

func (f BinaryFormat) String() string {
	switch {
	case f.OS == "":
		return "无法识别的可执行文件格式"
	case f.Arch == "":
		return f.OS + "（架构未知）"
	default:
		return f.OS + "/" + f.Arch
	}
}

// headerBytes is enough to cover the ELF header, the Mach-O header, and a
// typical DOS stub plus PE signature.
const headerBytes = 4096

// InspectBinary identifies the platform a file will run on by reading its
// header. This exists because uploading the running executable is only correct
// when it was built for the target: a Windows client deploying to a Linux
// server would otherwise install a PE image that the remote kernel refuses with
// "Exec format error".
func InspectBinary(path string) (BinaryFormat, error) {
	f, err := os.Open(path)
	if err != nil {
		return BinaryFormat{}, err
	}
	defer f.Close()

	buf := make([]byte, headerBytes)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return BinaryFormat{}, err
	}
	buf = buf[:n]
	if len(buf) < 4 {
		return BinaryFormat{}, fmt.Errorf("sshdeploy: %s is too short to be an executable", path)
	}

	switch {
	case len(buf) >= 20 && buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F':
		return inspectELF(buf), nil
	case buf[0] == 'M' && buf[1] == 'Z':
		return inspectPE(buf), nil
	case isMachO(buf):
		return inspectMachO(buf), nil
	default:
		return BinaryFormat{}, nil
	}
}

func inspectELF(buf []byte) BinaryFormat {
	f := BinaryFormat{OS: "linux"}
	// EI_DATA at offset 5 selects the byte order of every multi-byte field.
	var order binary.ByteOrder = binary.LittleEndian
	if buf[5] == 2 {
		order = binary.BigEndian
	}
	switch order.Uint16(buf[18:20]) { // e_machine
	case 0x3E:
		f.Arch = "amd64"
	case 0xB7:
		f.Arch = "arm64"
	case 0x28:
		f.Arch = "arm"
	case 0x03:
		f.Arch = "386"
	}
	return f
}

func inspectPE(buf []byte) BinaryFormat {
	f := BinaryFormat{OS: "windows"}
	if len(buf) < 0x40 {
		return f
	}
	// The DOS stub holds a little-endian offset to the PE signature at 0x3C.
	peOff := int(binary.LittleEndian.Uint32(buf[0x3C:0x40]))
	if peOff <= 0 || peOff+6 > len(buf) {
		return f
	}
	if string(buf[peOff:peOff+4]) != "PE\x00\x00" {
		return f
	}
	switch binary.LittleEndian.Uint16(buf[peOff+4 : peOff+6]) { // Machine
	case 0x8664:
		f.Arch = "amd64"
	case 0xAA64:
		f.Arch = "arm64"
	case 0x014C:
		f.Arch = "386"
	case 0x01C4:
		f.Arch = "arm"
	}
	return f
}

func isMachO(buf []byte) bool {
	if len(buf) < 4 {
		return false
	}
	magic := binary.BigEndian.Uint32(buf[0:4])
	switch magic {
	case 0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, 0xCAFEBABE:
		return true
	}
	return false
}

func inspectMachO(buf []byte) BinaryFormat {
	f := BinaryFormat{OS: "darwin"}
	// CPU type sits right after the magic, in the file's own byte order.
	var order binary.ByteOrder = binary.BigEndian
	if binary.BigEndian.Uint32(buf[0:4]) == 0xCEFAEDFE || binary.BigEndian.Uint32(buf[0:4]) == 0xCFFAEDFE {
		order = binary.LittleEndian
	}
	if len(buf) >= 8 {
		switch order.Uint32(buf[4:8]) {
		case 0x01000007:
			f.Arch = "amd64"
		case 0x0100000C:
			f.Arch = "arm64"
		}
	}
	return f
}

// candidateNames lists the file names to look for beside the running
// executable when it cannot run on the target. These match the release layout
// (dist/porttransit-linux-amd64) so a user who downloaded the client bundle
// already has the right binaries on disk.
func candidateNames(goos, goarch string) []string {
	return []string{
		fmt.Sprintf("porttransit-%s-%s", goos, goarch),
		fmt.Sprintf("porttransit_%s_%s", goos, goarch),
		fmt.Sprintf("%s-%s/porttransit", goos, goarch),
		fmt.Sprintf("%s_%s/porttransit", goos, goarch),
	}
}

// FindCompatibleBinary looks for a prebuilt binary for the target platform next
// to the given executable, and in a couple of conventional subdirectories.
//
// It returns the first path whose header matches the target, or "" when none
// does. The hint is a human-readable list of what was inspected, so a failure
// can name the exact paths that were tried instead of just "not found".
func FindCompatibleBinary(execPath, goos, goarch string) (path, hint string) {
	if execPath == "" {
		return "", ""
	}
	dir := filepath.Dir(execPath)
	var tried []string
	for _, name := range candidateNames(goos, goarch) {
		p := filepath.Join(dir, filepath.FromSlash(name))
		tried = append(tried, p)
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			continue
		}
		f, err := InspectBinary(p)
		if err != nil {
			continue
		}
		if f.UsableOn(goos, goarch) {
			return p, ""
		}
	}
	return "", strings.Join(tried, ", ")
}

// ExpandDownloadURL substitutes {os} and {arch} in a release URL template.
func ExpandDownloadURL(tmpl, goos, goarch string) string {
	r := strings.NewReplacer("{os}", goos, "{arch}", goarch)
	return r.Replace(tmpl)
}
