package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"porttransit/internal/install"
)

// The tests below pin the one thing an operator needs after installing with the
// console on loopback: a way to open it at http://<server-ip>:8787 without
// regenerating the configuration.
//
// Regenerating is what the installer's --force-config does, and it rewrites
// every credential — so the console would come back at the cost of every client
// already pointed at this relay. `set-console` exists instead, and these tests
// hold it to that promise: the address moves, nothing else does.

// stubPublicIP keeps ConsoleURL from calling an external service during tests.
// A build must not go red because ipify is unreachable.
func stubPublicIP(t *testing.T) {
	t.Helper()
	orig := install.PublicIP
	install.PublicIP = func() string { return "203.0.113.7" }
	t.Cleanup(func() { install.PublicIP = orig })
}

func TestSetConsoleExposesAnExistingInstall(t *testing.T) {
	stubPublicIP(t)

	path := filepath.Join(t.TempDir(), "config.json")
	initRelay(t, path, "--transport", "tls", "--listen", "0.0.0.0:8443")
	before := loadConfig(t, path)
	if before.WebUI.Listen == "0.0.0.0:8787" {
		t.Fatalf("a fresh install already listens on %q; this test would prove nothing", before.WebUI.Listen)
	}

	var err error
	out := captureStdout(t, func() {
		err = install.SetConsole([]string{"--config", path, "--listen", "0.0.0.0:8787", "--allow-remote"})
	})
	if err != nil {
		t.Fatalf("SetConsole: %v", err)
	}
	if !strings.Contains(out, "0.0.0.0:8787") {
		t.Errorf("the new address is not reported:\n%s", out)
	}
	// The operator has to be told how to make it take effect, or the browser
	// keeps talking to the old listener and the command looks broken.
	if !strings.Contains(out, "systemctl restart") {
		t.Errorf("the restart instruction is missing:\n%s", out)
	}

	after := loadConfig(t, path)
	if after.WebUI.Listen != "0.0.0.0:8787" {
		t.Errorf("webui.listen = %q, want 0.0.0.0:8787", after.WebUI.Listen)
	}
	if !after.WebUI.AllowRemote {
		t.Error("webui.allowRemote is false; the config would be refused at the next start")
	}

	// Everything else is carried through untouched. A new password or a new PSK
	// here would be indistinguishable, from the operator's side, from the
	// --force-config this command exists to avoid.
	if after.WebUI.PasswordHash != before.WebUI.PasswordHash {
		t.Error("the console password hash changed; every existing admin session would be broken")
	}
	if after.WebUI.Username != before.WebUI.Username {
		t.Errorf("webui.username changed: %q -> %q", before.WebUI.Username, after.WebUI.Username)
	}
	if !after.WebUI.Enabled {
		t.Error("webui.enabled became false")
	}
	if len(after.Server.Listeners) != len(before.Server.Listeners) {
		t.Fatalf("listener count changed: %d -> %d", len(before.Server.Listeners), len(after.Server.Listeners))
	}
	if got, want := after.Server.Listeners[0].Settings["psk"], before.Server.Listeners[0].Settings["psk"]; got != want {
		t.Errorf("relay PSK changed: %v -> %v", want, got)
	}
}

// TestSetConsoleRefusesSilentExposure pins the acknowledgement. The installer
// requires --webui-allow-remote for the same reason: nobody should end up with a
// management console on the public internet because a flag was half-remembered.
func TestSetConsoleRefusesSilentExposure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	initRelay(t, path, "--transport", "tls", "--listen", "0.0.0.0:8443")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	err = install.SetConsole([]string{"--config", path, "--listen", "0.0.0.0:8787"})
	if err == nil {
		t.Fatal("a public address was accepted without --allow-remote")
	}
	if !strings.Contains(err.Error(), "--allow-remote") {
		t.Errorf("the error does not name the missing flag: %v", err)
	}
	// A refused command must leave the file byte-for-byte as it found it: a
	// half-written config is a relay that does not come back up.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("a refused command rewrote the configuration")
	}
}

func TestSetConsoleReturnsToLoopback(t *testing.T) {
	stubPublicIP(t)

	path := filepath.Join(t.TempDir(), "config.json")
	initRelay(t, path, "--transport", "tls", "--listen", "0.0.0.0:8443")

	expose := []string{"--config", path, "--listen", "0.0.0.0:8787", "--allow-remote"}
	if err := install.SetConsole(expose); err != nil {
		t.Fatalf("SetConsole (expose): %v", err)
	}

	out := captureStdout(t, func() {
		if err := install.SetConsole([]string{"--config", path, "--listen", "127.0.0.1:8787"}); err != nil {
			t.Errorf("SetConsole (loopback): %v", err)
		}
	})
	if !strings.Contains(out, "127.0.0.1:8787") {
		t.Errorf("the loopback address is not reported:\n%s", out)
	}

	// loadConfig goes through Validate, so this also proves the result is a
	// configuration the relay will actually start with.
	after := loadConfig(t, path)
	if after.WebUI.Listen != "127.0.0.1:8787" {
		t.Errorf("webui.listen = %q, want 127.0.0.1:8787", after.WebUI.Listen)
	}
	if after.WebUI.AllowRemote {
		t.Error("webui.allowRemote stayed set after returning to loopback; the next edit would be pre-approved")
	}
}

// TestSetConsoleRequiresAPasswordBeforeExposure covers the install that has a
// console without a password. Validate would refuse the public address, so the
// command must refuse it too — and name the command that fixes it.
func TestSetConsoleRequiresAPasswordBeforeExposure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	initRelay(t, path, "--transport", "tls", "--listen", "0.0.0.0:8443")

	cfg := loadConfig(t, path)
	passwordless := cfg.WebUI.Listen
	cfg.WebUI.PasswordHash = ""
	if err := cfg.Save(path); err != nil {
		t.Fatalf("save config: %v", err)
	}

	err := install.SetConsole([]string{"--config", path, "--listen", "0.0.0.0:8787", "--allow-remote"})
	if err == nil {
		t.Fatal("a public address was accepted for a console without a password")
	}
	if !strings.Contains(err.Error(), "reset-password") {
		t.Errorf("the error does not name the command that fixes it: %v", err)
	}

	after := loadConfig(t, path)
	if after.WebUI.Listen != passwordless {
		t.Errorf("webui.listen changed to %q by a refused command", after.WebUI.Listen)
	}
}

func TestSetConsoleRejectsUsageErrors(t *testing.T) {
	stubPublicIP(t) // a refusal must not depend on, or wait for, an external service

	path := filepath.Join(t.TempDir(), "config.json")
	initRelay(t, path, "--transport", "tls", "--listen", "0.0.0.0:8443")

	cases := []struct {
		name string
		args []string
		want string // substring the error must carry; "" means any error
	}{
		{"no address", []string{"--config", path}, "--listen"},
		// A bare host is the typo that would otherwise be accepted here and
		// only surface as a bind failure at the next start.
		{"bare host", []string{"--config", path, "--listen", "0.0.0.0", "--allow-remote"}, "主机:端口"},
		{"unparseable port", []string{"--config", path, "--listen", "0.0.0.0:notaport", "--allow-remote"}, "1-65535"},
		{"port out of range", []string{"--config", path, "--listen", "0.0.0.0:99999", "--allow-remote"}, "1-65535"},
		{"missing config", []string{"--config", filepath.Join(t.TempDir(), "absent.json"), "--listen", "0.0.0.0:8787", "--allow-remote"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := install.SetConsole(tc.args)
			if err == nil {
				t.Fatal("accepted an invalid command line")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}

	// After every refused command the console is still where it was: a
	// partially applied change is a console the operator cannot reach.
	if got := loadConfig(t, path).WebUI.Listen; got != "127.0.0.1:8787" {
		t.Errorf("webui.listen = %q after refused commands, want the untouched default", got)
	}
}
