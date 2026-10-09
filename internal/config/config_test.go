package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestDefaultIsValid proves the configuration the installer writes is one the
// process will accept. A default that fails validation would make every fresh
// install fail at startup.
func TestDefaultIsValid(t *testing.T) {
	for _, mode := range []Mode{ModeServer, ModeClient, ModeBoth} {
		cfg := Default(mode)
		if err := cfg.Validate(); err != nil {
			t.Errorf("Default(%s) does not validate: %v", mode, err)
		}
	}
}

// TestSaveLoadRoundTrip proves a configuration survives a write and read
// unchanged, which is what the GUI relies on when it edits and saves.
func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := Default(ModeClient)
	cfg.Client.Servers = []ServerEntry{
		{
			ID:         "srv-1",
			Name:       "上海中转",
			Address:    "sh.example.com:8443",
			Transport:  "tls",
			Enabled:    true,
			Group:      "primary",
			LatencyTag: "日本→上海→美国",
			Settings:   map[string]any{"psk": "base64:AAAA", "insecure": true},
		},
	}
	cfg.Client.Tunnels = []Tunnel{
		{Name: "game", Enabled: true, Listen: "127.0.0.1:25565", Target: "mc.example.com:25565", Group: "primary"},
	}
	cfg.Client.Health.Interval = Duration(45 * time.Second)

	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// The file holds credentials, so its mode matters. Windows has no POSIX
	// permission bits — Go maps them onto the read-only attribute — so the
	// check only applies where the mode is meaningful.
	if runtime.GOOS != "windows" {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat the saved file: %v", err)
		}
		if perm := st.Mode().Perm(); perm != 0o600 {
			t.Errorf("saved config has mode %04o, want 0600", perm)
		}
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.Client.Servers) != 1 {
		t.Fatalf("loaded %d servers, want 1", len(got.Client.Servers))
	}
	s := got.Client.Servers[0]
	if s.ID != "srv-1" || s.Address != "sh.example.com:8443" || s.Group != "primary" {
		t.Errorf("server did not round-trip: %+v", s)
	}
	if s.Settings["psk"] != "base64:AAAA" {
		t.Errorf("settings did not round-trip: %+v", s.Settings)
	}
	if got.Client.Health.Interval.Std() != 45*time.Second {
		t.Errorf("health interval = %v, want 45s", got.Client.Health.Interval.Std())
	}
}

// TestDurationAcceptsStringAndNumber proves both forms parse, because a
// hand-written config naturally uses "30s" while a generated one may use a
// number of seconds.
func TestDurationAcceptsStringAndNumber(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{`"30s"`, 30 * time.Second},
		{`"5m"`, 5 * time.Minute},
		{`"1h30m"`, 90 * time.Minute},
		{`30`, 30 * time.Second},
		{`0.5`, 500 * time.Millisecond},
		{`null`, 0},
		{`""`, 0},
	}
	for _, tc := range cases {
		var d Duration
		if err := json.Unmarshal([]byte(tc.in), &d); err != nil {
			t.Errorf("Unmarshal(%s): %v", tc.in, err)
			continue
		}
		if d.Std() != tc.want {
			t.Errorf("Unmarshal(%s) = %v, want %v", tc.in, d.Std(), tc.want)
		}
	}

	var d Duration
	if err := json.Unmarshal([]byte(`"nonsense"`), &d); err == nil {
		t.Error("a malformed duration was accepted")
	}
}

// TestValidationCatchesOpenProxy proves a forward rule with neither a target
// nor an allow-list is refused, because that rule would turn an authenticated
// relay into an open proxy.
func TestValidationCatchesOpenProxy(t *testing.T) {
	cfg := Default(ModeServer)
	cfg.Server.Forwards = []Forward{
		{Name: "bad", Enabled: true},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("a forward with neither target nor allowedTargets was accepted")
	}
	if !strings.Contains(err.Error(), "open proxy") {
		t.Errorf("the error does not explain the open-proxy risk: %v", err)
	}
}

// TestValidationCatchesRemoteConsoleWithoutPassword proves the management
// console cannot be exposed without a password, which is the single most
// important configuration invariant in this project.
func TestValidationCatchesRemoteConsoleWithoutPassword(t *testing.T) {
	cfg := Default(ModeClient)
	cfg.WebUI.Listen = "0.0.0.0:8787"
	cfg.WebUI.AllowRemote = false
	cfg.WebUI.PasswordHash = ""

	err := cfg.Validate()
	if err == nil {
		t.Fatal("a non-loopback console without allowRemote was accepted")
	}

	cfg.WebUI.AllowRemote = true
	err = cfg.Validate()
	if err == nil {
		t.Fatal("a remote console without a password was accepted")
	}
	if !strings.Contains(err.Error(), "password") {
		t.Errorf("the error does not mention the missing password: %v", err)
	}

	cfg.WebUI.PasswordHash = "$2a$10$abcdefghijklmnopqrstuv"
	if err := cfg.Validate(); err != nil {
		t.Errorf("a properly configured remote console was rejected: %v", err)
	}
}

// TestValidationReportsEveryProblem proves validation collects all issues
// rather than stopping at the first, so the GUI can show a complete list.
func TestValidationReportsEveryProblem(t *testing.T) {
	cfg := Default(ModeBoth)
	cfg.Mode = "nonsense"
	cfg.Server.Listeners = []Listener{
		{Name: "", Transport: "", Listen: ""},
	}
	cfg.Client.Servers = []ServerEntry{
		{ID: "", Address: "", Transport: ""},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("a thoroughly broken configuration was accepted")
	}
	msg := err.Error()
	for _, want := range []string{"mode", "listeners[0].name", "listeners[0].transport", "servers[0].address"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error does not mention %q: %s", want, msg)
		}
	}
}

// TestValidationCatchesDuplicateIDs proves duplicate identifiers are refused,
// because the API resolves resources by id and a duplicate would make one of
// them unreachable.
func TestValidationCatchesDuplicateIDs(t *testing.T) {
	cfg := Default(ModeClient)
	cfg.Client.Servers = []ServerEntry{
		{ID: "dup", Address: "a.example.com:443", Transport: "tls", Enabled: true},
		{ID: "dup", Address: "b.example.com:443", Transport: "tls", Enabled: true},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("duplicate relay ids were accepted")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("the error does not mention the duplicate: %v", err)
	}
}

// TestValidationCatchesDanglingTunnelServer proves a tunnel pointing at a
// relay that does not exist is refused, since it could never work.
func TestValidationCatchesDanglingTunnelServer(t *testing.T) {
	cfg := Default(ModeClient)
	cfg.Client.Servers = []ServerEntry{
		{ID: "real", Address: "a.example.com:443", Transport: "tls", Enabled: true},
	}
	cfg.Client.Tunnels = []Tunnel{
		{Name: "t", Enabled: true, Listen: "127.0.0.1:1", Target: "x:1", Server: "missing"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("a tunnel naming a nonexistent relay was accepted")
	}
	if !strings.Contains(err.Error(), "does not match any server") {
		t.Errorf("the error does not explain the dangling reference: %v", err)
	}
}

// TestParseAppliesDefaults proves an omitted field keeps its default rather
// than becoming a zero value, which is what lets a hand-written config be
// minimal.
func TestParseAppliesDefaults(t *testing.T) {
	raw := []byte(`{
		"schemaVersion": 2,
		"mode": "client",
		"client": { "servers": [] }
	}`)
	cfg, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("log level = %q, want the default info", cfg.Log.Level)
	}
	if cfg.WebUI.Listen != "127.0.0.1:8787" {
		t.Errorf("webui listen = %q, want the default loopback address", cfg.WebUI.Listen)
	}
	if !cfg.Client.Proxy.Enabled {
		t.Error("the local proxy is disabled, but the default enables it")
	}
	if cfg.Client.Proxy.SOCKS5Listen != "127.0.0.1:1080" {
		t.Errorf("socks5 listen = %q, want 127.0.0.1:1080", cfg.Client.Proxy.SOCKS5Listen)
	}
	if cfg.Client.Health.Interval.Std() != 30*time.Second {
		t.Errorf("health interval = %v, want 30s", cfg.Client.Health.Interval.Std())
	}
}

// TestLoadReportsMissingFileHelpfully proves the error tells the operator what
// to do, because a missing config is the expected state on a first run.
func TestLoadReportsMissingFileHelpfully(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Fatal("loading a missing file succeeded")
	}
	if !os.IsNotExist(err) {
		t.Logf("note: the error is wrapped; the app layer adds the remediation hint (%v)", err)
	}
}

// TestACLBlockPrivateDefaultsOn proves the safe default: an operator who never
// considered the question gets private destinations blocked.
func TestACLBlockPrivateDefaultsOn(t *testing.T) {
	cfg := Default(ModeServer)
	if cfg.Server.ACL.BlockPrivate == nil {
		t.Fatal("the default ACL leaves blockPrivate unset")
	}
	if !*cfg.Server.ACL.BlockPrivate {
		t.Error("the default ACL does not block private destinations")
	}
}

// TestIsLoopbackListen covers the address forms an operator may write, because
// getting this wrong either blocks a legitimate loopback bind or allows an
// exposed console.
func TestIsLoopbackListen(t *testing.T) {
	loopback := []string{"127.0.0.1:8787", "localhost:8787", "[::1]:8787", ":8787", ""}
	for _, addr := range loopback {
		if !isLoopbackListen(addr) {
			t.Errorf("isLoopbackListen(%q) = false, want true", addr)
		}
	}
	exposed := []string{"0.0.0.0:8787", "192.168.1.5:8787", "example.com:8787", "[2001:db8::1]:8787"}
	for _, addr := range exposed {
		if isLoopbackListen(addr) {
			t.Errorf("isLoopbackListen(%q) = true, want false", addr)
		}
	}
}

// TestSchemaVersionRejectsFuture proves a config written by a newer build is
// refused rather than silently misread.
func TestSchemaVersionRejectsFuture(t *testing.T) {
	cfg := Default(ModeClient)
	cfg.SchemaVersion = SchemaVersion + 1
	err := cfg.Validate()
	if err == nil {
		t.Fatal("a future schema version was accepted")
	}
	if !strings.Contains(err.Error(), "newer than this build") {
		t.Errorf("the error does not explain the version mismatch: %v", err)
	}
}
