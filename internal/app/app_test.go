package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"porttransit/internal/config"
)

// writeConfig saves a configuration to a temporary file and returns its path.
func writeConfig(t *testing.T, cfg *config.Config) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := cfg.Save(path); err != nil {
		t.Fatalf("save the config: %v", err)
	}
	return path
}

// serverConfig builds a minimal server configuration that does not touch the
// real filesystem outside its temporary directory.
func serverConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default(config.ModeServer)
	// The default log path is /var/log/porttransit, which a test must not
	// create, so every path is redirected into the temporary directory.
	cfg.Log.File = filepath.Join(dir, "porttransit.log")
	cfg.WebUI.Enabled = false
	cfg.Server.DataDir = dir
	cfg.Server.Listeners[0].Settings["certFile"] = filepath.Join(dir, "relay.crt")
	cfg.Server.Listeners[0].Settings["keyFile"] = filepath.Join(dir, "relay.key")
	return cfg
}

// TestNewRequiresConfigPath proves a missing path is refused rather than
// silently falling back to defaults, which would start a relay with a random
// identity.
func TestNewRequiresConfigPath(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("New accepted an empty configuration path")
	}
}

// TestNewReportsMissingConfigHelpfully proves a first run is told how to fix
// itself, because "file not found" alone sends the operator to the docs.
func TestNewReportsMissingConfigHelpfully(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.json")
	_, err := New(Options{ConfigPath: path})
	if err == nil {
		t.Fatal("New accepted a missing configuration file")
	}
	if !strings.Contains(err.Error(), "porttransit init") {
		t.Errorf("the error does not suggest the init command: %v", err)
	}
}

// TestNewBuildsServerOnly proves a server-mode configuration produces a relay
// and no client, so a relay host never opens local proxy ports.
func TestNewBuildsServerOnly(t *testing.T) {
	path := writeConfig(t, serverConfig(t))

	a, err := New(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Stop()

	if a.Server() == nil {
		t.Error("server mode produced no relay")
	}
	if a.Client() != nil {
		t.Error("server mode produced a client")
	}
	if a.WebUI() != nil {
		t.Error("the management interface was created despite NoWebUI being unset in the file")
	}
}

// TestNewBuildsClientOnly proves a client-mode configuration produces a client
// and no relay.
func TestNewBuildsClientOnly(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default(config.ModeClient)
	cfg.Log.File = filepath.Join(dir, "porttransit.log")
	cfg.WebUI.Enabled = false
	cfg.Client.DataDir = dir
	path := writeConfig(t, cfg)

	a, err := New(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Stop()

	if a.Client() == nil {
		t.Error("client mode produced no client")
	}
	if a.Server() != nil {
		// ModeClient must not build a relay.
		t.Error("client mode produced a relay")
	}
}

// TestModeOverrideChangesRole proves the command-line override wins over the
// file, which is how one binary serves both roles from a shared image.
func TestModeOverrideChangesRole(t *testing.T) {
	dir := t.TempDir()
	// A "both" configuration carries a server and a client section, so
	// overriding the mode to either role has a section to work with. Starting
	// from a client-only file would instead exercise the missing-section
	// validation, which TestOverrideIsRevalidated covers.
	cfg := config.Default(config.ModeBoth)
	cfg.Log.File = filepath.Join(dir, "porttransit.log")
	cfg.WebUI.Enabled = false
	cfg.Client.DataDir = dir
	cfg.Server.DataDir = dir
	cfg.Server.Listeners[0].Settings["certFile"] = filepath.Join(dir, "relay.crt")
	cfg.Server.Listeners[0].Settings["keyFile"] = filepath.Join(dir, "relay.key")
	path := writeConfig(t, cfg)

	a, err := New(Options{ConfigPath: path, ModeOverride: config.ModeServer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Stop()

	if a.Server() == nil {
		t.Error("the server override did not create a relay")
	}
	if a.Client() != nil {
		t.Error("the server override left the client running")
	}
}

// TestModeOverrideRequiresTheSection proves overriding the mode to a role the
// file has no section for is refused rather than starting an empty service.
//
// A relay that starts with no listeners, or a client with no relays, would
// appear healthy while doing nothing at all, which is worse than a startup
// failure the operator can see.
func TestModeOverrideRequiresTheSection(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default(config.ModeClient)
	cfg.Log.File = filepath.Join(dir, "porttransit.log")
	cfg.WebUI.Enabled = false
	cfg.Client.DataDir = dir
	path := writeConfig(t, cfg)

	if _, err := New(Options{ConfigPath: path, ModeOverride: config.ModeServer}); err == nil {
		t.Fatal("a server override was accepted against a client-only configuration")
	}
}

// TestNoWebUIDisablesConsole proves the flag wins over a configuration that
// enables the console, because it is the escape hatch for a locked-out
// operator.
func TestNoWebUIDisablesConsole(t *testing.T) {
	dir := t.TempDir()
	cfg := serverConfig(t)
	cfg.WebUI.Enabled = true
	cfg.WebUI.PasswordHash = "$2a$10$abcdefghijklmnopqrstuv"
	cfg.Log.File = filepath.Join(dir, "porttransit.log")
	path := writeConfig(t, cfg)

	a, err := New(Options{ConfigPath: path, NoWebUI: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Stop()

	if a.WebUI() != nil {
		t.Error("NoWebUI did not disable the management interface")
	}
}

// TestLogFileDashForcesConsole proves "-" removes the file sink, which is how
// a container run sends logs to stdout for the platform to collect.
func TestLogFileDashForcesConsole(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default(config.ModeClient)
	cfg.WebUI.Enabled = false
	cfg.Client.DataDir = dir
	cfg.Log.File = filepath.Join(dir, "from-file.log")
	path := writeConfig(t, cfg)

	a, err := New(Options{ConfigPath: path, LogFile: "-"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Stop()

	if a.Config().Log.File != "" {
		t.Errorf("Log.File = %q, want it cleared by \"-\"", a.Config().Log.File)
	}
	if _, err := os.Stat(filepath.Join(dir, "from-file.log")); !os.IsNotExist(err) {
		t.Error("the log file from the configuration was still created")
	}
}

// TestLogLevelOverrideIsApplied proves the flag reaches the configuration that
// the logger is built from.
func TestLogLevelOverrideIsApplied(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default(config.ModeClient)
	cfg.WebUI.Enabled = false
	cfg.Client.DataDir = dir
	cfg.Log.File = filepath.Join(dir, "porttransit.log")
	path := writeConfig(t, cfg)

	a, err := New(Options{ConfigPath: path, LogLevel: "debug"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Stop()

	if got := a.Config().Log.Level; got != "debug" {
		t.Errorf("Log.Level = %q, want debug", got)
	}
}

// TestOverrideIsRevalidated proves an override that creates an invalid
// combination is caught, because the file alone was valid.
//
// Binding the console to a non-loopback address without AllowRemote is the
// realistic case: the file says 127.0.0.1 and the operator edits it to 0.0.0.0.
func TestOverrideIsRevalidated(t *testing.T) {
	dir := t.TempDir()
	cfg := serverConfig(t)
	cfg.WebUI.Enabled = true
	cfg.WebUI.Listen = "0.0.0.0:8787"
	// Deliberately no password hash and no AllowRemote.
	cfg.Log.File = filepath.Join(dir, "porttransit.log")
	path := writeConfig(t, cfg)

	if _, err := New(Options{ConfigPath: path}); err == nil {
		t.Fatal("New accepted a console exposed on a public interface without a password")
	}
}

// TestRunStartsAndStopsCleanly proves the full lifecycle works: every subsystem
// binds, then a cancelled context shuts them all down.
func TestRunStartsAndStopsCleanly(t *testing.T) {
	dir := t.TempDir()
	cfg := serverConfig(t)
	cfg.Log.File = filepath.Join(dir, "porttransit.log")
	// A port of zero lets the kernel pick one, so the test never collides with
	// a real relay on the machine.
	cfg.Server.Listeners[0].Listen = "127.0.0.1:0"
	path := writeConfig(t, cfg)

	a, err := New(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	// Give the listener a moment to bind, then verify it did.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st := a.Server().ListenerStatuses(); len(st) > 0 && st[0].Listening {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	st := a.Server().ListenerStatuses()
	if len(st) == 0 || !st[0].Listening {
		cancel()
		<-done
		t.Fatalf("the relay never reported its listener as bound: %+v", st)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil after a clean shutdown", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

// TestStopIsIdempotent proves Stop can be called twice, because a deferred
// Stop and a signal handler may both fire.
func TestStopIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default(config.ModeClient)
	cfg.WebUI.Enabled = false
	cfg.Client.DataDir = dir
	cfg.Client.Proxy.Enabled = false
	cfg.Client.Health.Enabled = false
	cfg.Log.File = filepath.Join(dir, "porttransit.log")
	path := writeConfig(t, cfg)

	a, err := New(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.Stop()
	a.Stop()
}

// TestStopWithoutRunIsSafe proves a construction failure path can always call
// Stop, since New's caller cannot tell how far construction got.
func TestStopWithoutRunIsSafe(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default(config.ModeClient)
	cfg.WebUI.Enabled = false
	cfg.Client.DataDir = dir
	cfg.Log.File = filepath.Join(dir, "porttransit.log")
	path := writeConfig(t, cfg)

	a, err := New(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Never started.
	a.Stop()
}

// TestNewCreatesLogDirectory proves the logger's directory is created, because
// the default path does not exist on a fresh install and a relay that cannot
// log is a relay nobody can debug.
func TestNewCreatesLogDirectory(t *testing.T) {
	dir := t.TempDir()
	cfg := serverConfig(t)
	nested := filepath.Join(dir, "logs", "deeper", "porttransit.log")
	cfg.Log.File = nested
	path := writeConfig(t, cfg)

	a, err := New(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Stop()

	if _, err := os.Stat(filepath.Dir(nested)); err != nil {
		t.Errorf("the log directory was not created: %v", err)
	}
}
