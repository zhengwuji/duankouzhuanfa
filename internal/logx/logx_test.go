package logx

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseLevel covers the accepted spellings, because a typo in a config
// silently changes verbosity and an operator diagnosing an incident needs the
// level they asked for.
func TestParseLevel(t *testing.T) {
	cases := []struct {
		in   string
		want slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"nonsense", slog.LevelInfo},
	}
	for _, tc := range cases {
		if got := ParseLevel(tc.in); got != tc.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestBufferIsBounded proves the ring does not grow without limit, because a
// relay running for months must not accumulate every log line in memory.
func TestBufferIsBounded(t *testing.T) {
	b := NewBuffer(10)
	for i := 0; i < 100; i++ {
		b.Add(Entry{Level: "info", Message: "line"})
	}
	snap := b.Snapshot(0)
	if len(snap) > 10 {
		t.Fatalf("buffer holds %d entries, exceeding its capacity of 10", len(snap))
	}
	if len(snap) == 0 {
		t.Fatal("buffer is empty after 100 additions")
	}
}

// TestBufferSnapshotReturnsNewest proves Snapshot returns the most recent
// entries, which is what an operator wants to see first.
func TestBufferSnapshotReturnsNewest(t *testing.T) {
	b := NewBuffer(5)
	for _, msg := range []string{"one", "two", "three"} {
		b.Add(Entry{Level: "info", Message: msg})
	}

	snap := b.Snapshot(0)
	if len(snap) != 3 {
		t.Fatalf("snapshot holds %d entries, want 3", len(snap))
	}
	if snap[0].Message != "one" {
		t.Errorf("the snapshot is not in chronological order: first is %q", snap[0].Message)
	}

	limited := b.Snapshot(2)
	if len(limited) != 2 {
		t.Fatalf("a limited snapshot holds %d entries, want 2", len(limited))
	}
	if limited[len(limited)-1].Message != "three" {
		t.Errorf("a limited snapshot does not end at the newest entry: %v", limited)
	}
}

// TestBufferClear proves the buffer can be emptied, which the console exposes.
func TestBufferClear(t *testing.T) {
	b := NewBuffer(5)
	b.Add(Entry{Level: "info", Message: "x"})
	b.Clear()
	if len(b.Snapshot(0)) != 0 {
		t.Error("Clear left entries behind")
	}
}

// TestRedactHidesSecrets proves the redaction helper replaces a secret value
// while keeping a short value fully masked, since a partial reveal of a short
// secret is effectively the whole secret.
func TestRedactHidesSecrets(t *testing.T) {
	// A short value must be entirely masked.
	if got := Redact("password", "abc"); strings.Contains(got, "abc") {
		t.Errorf("Redact leaked a short secret: %q", got)
	}
	// A long value may show a prefix and suffix to aid recognition, but must
	// not contain the middle.
	long := "supersecretvalue-that-is-long-enough"
	got := Redact("password", long)
	if strings.Contains(got, "secretvalue") {
		t.Errorf("Redact leaked the middle of a secret: %q", got)
	}
	if !strings.Contains(got, "su") {
		t.Errorf("Redact did not keep a recognisable prefix: %q", got)
	}
	// A non-secret key must pass through unchanged, or the log becomes useless.
	if got := Redact("target", "example.com:443"); got != "example.com:443" {
		t.Errorf("Redact altered a non-secret value: %q", got)
	}
}

// TestMaskMasksShortAndLong proves Mask never returns the original value.
func TestMaskMasksShortAndLong(t *testing.T) {
	for _, s := range []string{"", "a", "abcdefgh", "abcdefghijklmnop"} {
		got := Mask(s)
		if s != "" && got == s {
			t.Errorf("Mask(%q) returned the input unchanged", s)
		}
		if s == "" && got != "" {
			t.Errorf("Mask of an empty string = %q, want empty", got)
		}
	}
}

// TestLoggerWritesJSON proves the JSON mode emits parseable records, which is
// what a log shipper consumes.
func TestLoggerWritesJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	l, err := New(Options{
		Level:   slog.LevelDebug,
		JSON:    true,
		File:    path,
		Console: false,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	l.Info("hello", "key", "value")
	l.Debug("detailed", "n", 42)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the log file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		t.Fatalf("the log file holds %d lines, want at least 2", len(lines))
	}

	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("the first line is not JSON: %v (%q)", err, lines[0])
	}
	if rec["msg"] != "hello" {
		t.Errorf("the record message is %v, want hello", rec["msg"])
	}
	if rec["key"] != "value" {
		t.Errorf("the attribute was not recorded: %v", rec)
	}
}

// TestLoggerRespectsLevel proves a level filter suppresses lower-severity
// records, which is what keeps a production log readable.
func TestLoggerRespectsLevel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "level.log")

	l, err := New(Options{
		Level:   slog.LevelWarn,
		JSON:    true,
		File:    path,
		Console: false,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	l.Debug("debug line")
	l.Info("info line")
	l.Warn("warn line")
	l.Error("error line")

	data, _ := os.ReadFile(path)
	text := string(data)
	if strings.Contains(text, "debug line") {
		t.Error("a debug record was written despite a warn level")
	}
	if strings.Contains(text, "info line") {
		t.Error("an info record was written despite a warn level")
	}
	if !strings.Contains(text, "warn line") || !strings.Contains(text, "error line") {
		t.Error("a record at or above the configured level was suppressed")
	}
}

// TestLoggerComponentAndWith proves the derived loggers tag their records,
// which is what makes a multi-subsystem log navigable.
func TestLoggerComponentAndWith(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "component.log")

	base, err := New(Options{Level: slog.LevelDebug, JSON: true, File: path, Console: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer base.Close()
	base.Component("relay").Info("bound", "listen", ":8443")

	data, _ := os.ReadFile(path)
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &rec); err != nil {
		t.Fatalf("the record is not JSON: %v", err)
	}
	if rec["component"] != "relay" {
		t.Errorf("the component tag is %v, want relay", rec["component"])
	}
	if rec["listen"] != ":8443" {
		t.Errorf("the attribute was lost: %v", rec)
	}
}

// TestDiscardLoggerIsSafe proves the discard logger accepts calls, since the
// transports and tests rely on it as a no-op.
func TestDiscardLoggerIsSafe(t *testing.T) {
	l := Discard()
	l.Debug("d")
	l.Info("i")
	l.Warn("w")
	l.Error("e")
	l.Component("x").Info("y")
	l.With("k", "v").Info("z")
	if l.Buffer() != nil {
		t.Error("the discard logger exposes a buffer")
	}
}

// TestNilLoggerMethodsAreSafe proves a nil *Logger tolerates method calls.
//
// This matters because the transport adapters deliberately return a typed nil
// in some paths; a panic here would take down a relay mid-handshake.
func TestNilLoggerMethodsAreSafe(t *testing.T) {
	var l *Logger
	l.Debug("d")
	l.Info("i")
	l.Warn("w")
	l.Error("e")
}

// TestBufferReceivesLoggerOutput proves the ring the console reads is fed by
// the logger, which is the whole point of having it.
func TestBufferReceivesLoggerOutput(t *testing.T) {
	buf := NewBuffer(50)
	l, err := New(Options{Level: slog.LevelDebug, Buffer: buf, Console: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	l.Info("recorded message", "target", "example.com:443")

	snap := buf.Snapshot(0)
	if len(snap) == 0 {
		t.Fatal("the buffer did not receive the record")
	}
	last := snap[len(snap)-1]
	if last.Message != "recorded message" {
		t.Errorf("the buffered message is %q", last.Message)
	}
	if last.Level != "info" {
		t.Errorf("the buffered level is %q, want info", last.Level)
	}
	if last.Attrs["target"] != "example.com:443" {
		t.Errorf("the buffered attributes are %v", last.Attrs)
	}
}

// TestLoggerCreatesMissingDirectory proves the logger creates its directory,
// because the default log path does not exist on a fresh install.
func TestLoggerCreatesMissingDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "deeper", "app.log")

	l, err := New(Options{Level: slog.LevelInfo, File: path, Console: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	l.Info("hello")
	// The file must be closed before the temporary directory is removed, or
	// Windows refuses to delete a file that is still open.
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the log file was not created: %v", err)
	}
}
