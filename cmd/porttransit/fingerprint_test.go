package main

import (
	"os"
	"strings"
	"testing"
)

// The CLI is the only way an operator obtains a fingerprint, so the command has
// to be reachable and discoverable. Neither property is enforced by the
// compiler: a missing switch case produces "unknown command", and a missing
// usage line means an operator who does not already know the command exists
// will never find it — and will reach for insecure: true instead.

// TestUsageDocumentsTheFingerprintCommand proves the command is listed in the
// help text.
//
// The help text is what an operator reads when they do not know how to do
// something, so a command that is implemented but undocumented is, for practical
// purposes, a command that does not exist.
func TestUsageDocumentsTheFingerprintCommand(t *testing.T) {
	out := captureStderr(t, usage)

	if !strings.Contains(out, "fingerprint") {
		t.Errorf("the usage text does not mention the fingerprint command:\n%s", out)
	}
	// The setting the value is destined for has to be named too: "fingerprint"
	// alone is ambiguous, since the same word is already used for the uTLS
	// ClientHello profile setting.
	if !strings.Contains(out, "certFingerprint") {
		t.Errorf("the usage text does not name the certFingerprint setting the value is for:\n%s", out)
	}
	// Both sources should be discoverable, because which one an operator needs
	// depends on whether they are on the relay host.
	for _, want := range []string{"--cert", "--server"} {
		if !strings.Contains(out, want) {
			t.Errorf("the usage text does not show the %s form:\n%s", want, out)
		}
	}
}

// TestUsageStillDocumentsTheOtherCommands guards against the edit that added the
// fingerprint line having dropped a neighbouring one.
//
// The usage block is a single string literal, so a careless insertion is a
// silent deletion: nothing fails to compile, and the command simply stops being
// discoverable.
func TestUsageStillDocumentsTheOtherCommands(t *testing.T) {
	out := captureStderr(t, usage)

	for _, cmd := range []string{
		"run", "server", "client", "status",
		"init", "install", "uninstall", "reset-password", "show-credentials", "tune",
		"deploy", "version", "help",
	} {
		if !strings.Contains(out, cmd) {
			t.Errorf("the usage text no longer documents %q:\n%s", cmd, out)
		}
	}
}

// captureStderr runs fn with stderr redirected and returns what it printed.
//
// usage() writes to stderr because that is where a usage error belongs: stdout
// is reserved for output a script would parse, and a caller that piped the help
// text into a parser would otherwise get it mixed in with real results.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	saved := os.Stderr
	os.Stderr = w

	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 8192)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- sb.String()
	}()

	fn()
	w.Close()
	os.Stderr = saved
	return <-done
}
