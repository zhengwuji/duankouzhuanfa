package install

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"porttransit/internal/config"
	"porttransit/internal/sshdeploy"
)

// clientConfigFile writes a minimal client configuration and returns its path.
func clientConfigFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default(config.ModeClient)
	cfg.Client.DataDir = dir
	cfg.Log.File = filepath.Join(dir, "porttransit.log")
	cfg.WebUI.Enabled = false
	path := filepath.Join(dir, "config.json")
	if err := cfg.Save(path); err != nil {
		t.Fatalf("save the config: %v", err)
	}
	return path
}

// TestAppendServerAddsEntry proves a deployed relay is written into the client
// configuration, which is what makes the one-click deployment finish the job
// instead of asking the operator to copy an address by hand.
func TestAppendServerAddsEntry(t *testing.T) {
	path := clientConfigFile(t)

	res := &sshdeploy.Result{
		OK:        true,
		Address:   "203.0.113.10:443",
		Transport: "tls",
		Port:      443,
		Settings:  map[string]string{"name": "东京中转", "serverName": "a.example.com"},
	}

	if err := appendServerToConfig(path, res); err != nil {
		t.Fatalf("appendServerToConfig: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload the config: %v", err)
	}
	if len(cfg.Client.Servers) != 1 {
		t.Fatalf("the config holds %d relays, want 1", len(cfg.Client.Servers))
	}
	got := cfg.Client.Servers[0]
	if got.Address != res.Address {
		t.Errorf("address = %q, want %q", got.Address, res.Address)
	}
	if got.Transport != "tls" {
		t.Errorf("transport = %q, want tls", got.Transport)
	}
	if got.Name != "东京中转" {
		t.Errorf("name = %q, want the name from the deployment", got.Name)
	}
	if got.Settings["serverName"] != "a.example.com" {
		t.Errorf("the deployment settings were not carried over: %v", got.Settings)
	}
	if !got.Enabled {
		t.Error("the new relay was added disabled, so it would never be used")
	}
	if got.ID == "" {
		t.Error("the new relay has no id")
	}
}

// TestAppendServerIsIdempotent proves redeploying to the same host updates the
// existing entry rather than adding a second one, so a retry after a partial
// failure repairs the configuration instead of duplicating the relay.
func TestAppendServerIsIdempotent(t *testing.T) {
	path := clientConfigFile(t)

	first := &sshdeploy.Result{
		Address:   "203.0.113.10:443",
		Transport: "tls",
		Settings:  map[string]string{"name": "东京中转"},
	}
	if err := appendServerToConfig(path, first); err != nil {
		t.Fatalf("first append: %v", err)
	}

	cfg, _ := config.Load(path)
	originalID := cfg.Client.Servers[0].ID

	// A second deployment to the same address with a new name must update the
	// entry in place and keep its identity, because tunnels reference the id.
	second := &sshdeploy.Result{
		Address:   "203.0.113.10:443",
		Transport: "tls",
		Settings:  map[string]string{"name": "东京中转-新"},
	}
	if err := appendServerToConfig(path, second); err != nil {
		t.Fatalf("second append: %v", err)
	}

	cfg2, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(cfg2.Client.Servers) != 1 {
		t.Fatalf("the config holds %d relays after a redeploy, want 1", len(cfg2.Client.Servers))
	}
	if cfg2.Client.Servers[0].Name != "东京中转-新" {
		t.Errorf("the entry was not updated: name = %q", cfg2.Client.Servers[0].Name)
	}
	if cfg2.Client.Servers[0].ID != originalID {
		t.Errorf("the relay id changed from %q to %q, which would break tunnels referencing it",
			originalID, cfg2.Client.Servers[0].ID)
	}
}

// TestAppendServerKeepsDistinctRelays proves a second relay on a different
// address is added alongside the first, since a chain of relays is the whole
// point of the product.
func TestAppendServerKeepsDistinctRelays(t *testing.T) {
	path := clientConfigFile(t)

	for _, addr := range []string{"203.0.113.10:443", "198.51.100.7:443", "192.0.2.5:8443"} {
		res := &sshdeploy.Result{Address: addr, Transport: "tls"}
		if err := appendServerToConfig(path, res); err != nil {
			t.Fatalf("append %s: %v", addr, err)
		}
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(cfg.Client.Servers) != 3 {
		t.Fatalf("the config holds %d relays, want 3", len(cfg.Client.Servers))
	}

	seen := map[string]bool{}
	for _, s := range cfg.Client.Servers {
		if seen[s.ID] {
			t.Errorf("two relays share the id %q", s.ID)
		}
		seen[s.ID] = true
	}
}

// TestAppendServerRejectsServerConfig proves a deployment against a
// server-only configuration is refused with a clear message rather than
// writing a client section into a relay host's file.
func TestAppendServerRejectsServerConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default(config.ModeServer)
	cfg.Server.DataDir = dir
	cfg.Log.File = filepath.Join(dir, "porttransit.log")
	cfg.WebUI.Enabled = false
	path := filepath.Join(dir, "config.json")
	if err := cfg.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	err := appendServerToConfig(path, &sshdeploy.Result{Address: "203.0.113.10:443", Transport: "tls"})
	if err == nil {
		t.Fatal("a relay was appended to a server-only configuration")
	}
}

// TestRandomPasswordIsStrong proves generated passwords are long and distinct,
// because they protect a console that can rewrite the whole relay.
func TestRandomPasswordIsStrong(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		p := randomPassword()
		if len(p) < 24 {
			t.Fatalf("generated password is %d characters, want at least 24", len(p))
		}
		if seen[p] {
			t.Fatalf("the password %q was generated twice", p)
		}
		seen[p] = true
	}
}

// TestHashPasswordIsVerifiable proves the stored hash verifies against the
// password and rejects a wrong one, which is what the console login relies on.
func TestHashPasswordIsVerifiable(t *testing.T) {
	pw := randomPassword()
	hash, err := hashPassword(pw)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("the hash %q is not bcrypt, so the console would compare it as plaintext", hash)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)); err != nil {
		t.Errorf("the hash does not verify against its password: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw+"x")); err == nil {
		t.Error("the hash verified against a wrong password")
	}
}

// TestShortIDIsUsable proves the id suffix is hex and non-empty, since it is
// embedded in a relay id that appears in configuration and the console.
func TestShortIDIsUsable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		id := shortID()
		if id == "" {
			t.Fatal("shortID returned an empty string")
		}
		for _, r := range id {
			if !strings.ContainsRune("0123456789abcdef", r) {
				t.Fatalf("shortID returned %q, which is not hexadecimal", id)
			}
		}
		seen[id] = true
	}
	if len(seen) < 45 {
		t.Errorf("shortID produced only %d distinct values in 50 draws, so it is not random", len(seen))
	}
}

// TestFirstNonEmpty proves the helper returns the first usable value, which is
// what selects a display name from a list of fallbacks.
func TestFirstNonEmpty(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"a", "b"}, "a"},
		{[]string{"", "b"}, "b"},
		{[]string{"", "", "c"}, "c"},
		{[]string{"", ""}, ""},
		{nil, ""},
	}
	for _, tc := range cases {
		if got := firstNonEmpty(tc.in...); got != tc.want {
			t.Errorf("firstNonEmpty(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestCopyFileIsAtomicAndExecutable proves the binary lands at the destination
// with the requested mode and leaves no temporary file behind, because the
// destination is the path systemd execs.
func TestCopyFileIsAtomicAndExecutable(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source")
	content := []byte("#!/bin/sh\necho hello\n")
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatalf("write the source: %v", err)
	}
	dst := filepath.Join(dir, "installed")

	if err := copyFile(src, dst, 0o755); err != nil {
		t.Fatalf("copyFile: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read the destination: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("the copied content differs: %q", got)
	}

	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Error("the temporary file was left behind")
	}

	// The mode check is Unix-only: Windows does not report the executable bit.
	if runtime.GOOS != "windows" {
		st, err := os.Stat(dst)
		if err != nil {
			t.Fatalf("stat the destination: %v", err)
		}
		if st.Mode().Perm()&0o111 == 0 {
			t.Errorf("the installed binary is not executable: mode %04o", st.Mode().Perm())
		}
	}
}

// TestCopyFileRejectsMissingSource proves a missing source is reported rather
// than creating an empty destination, which would install a zero-byte binary
// that systemd then fails to exec.
func TestCopyFileRejectsMissingSource(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "installed")

	if err := copyFile(filepath.Join(dir, "absent"), dst, 0o755); err == nil {
		t.Fatal("copyFile accepted a missing source")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("copyFile created a destination despite failing")
	}
}

// TestUninstallRequiresRootOnLinux proves the destructive path refuses to run
// without the privileges it needs, since a partial uninstall is worse than
// none.
func TestUninstallRequiresRootOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the root check is Unix-only")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root, so the refusal cannot be observed")
	}
	if err := Uninstall([]string{"--yes"}); err == nil {
		t.Error("Uninstall ran without root")
	}
}
