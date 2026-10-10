package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"porttransit/internal/config"
	"porttransit/internal/install"
)

// The tests below pin the behaviour that the remote deployment path depends on.
//
// `deploy` runs `init` on the remote host. It used to run `init --force`, which
// replaced the entire listener list — so deploying a second line to a server
// that already had one silently deleted the first, and the deployment still
// reported success. Every assertion here exists because that failure was real.

// initRelay creates a fresh server configuration on disk.
func initRelay(t *testing.T, path string, args ...string) {
	t.Helper()
	base := []string{"--config", path, "--mode", "server", "--admin-password", "firstpassword"}
	if err := cmdInit(append(base, args...)); err != nil {
		t.Fatalf("cmdInit(%v): %v", args, err)
	}
}

func loadConfig(t *testing.T, path string) *config.Config {
	t.Helper()
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load(%s): %v", path, err)
	}
	return cfg
}

// TestAddListenerKeepsExistingListeners is the regression test for the
// destructive deployment.
//
// The decisive assertion is the count: adding a line must leave the ones
// already configured alone. The old code produced exactly one listener here.
func TestAddListenerKeepsExistingListeners(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	initRelay(t, path, "--transport", "tls", "--listen", "0.0.0.0:8443", "--name", "relay-a")

	if err := cmdInit([]string{
		"--config", path, "--add-listener",
		"--transport", "trojan", "--listen", "0.0.0.0:9443", "--name", "relay-b",
	}); err != nil {
		t.Fatalf("cmdInit --add-listener: %v", err)
	}

	cfg := loadConfig(t, path)
	if len(cfg.Server.Listeners) != 2 {
		t.Fatalf("got %d listeners, want 2 (adding a line must not delete the others): %+v",
			len(cfg.Server.Listeners), cfg.Server.Listeners)
	}
	names := map[string]string{}
	for _, l := range cfg.Server.Listeners {
		names[l.Name] = l.Transport
	}
	if names["relay-a"] != "tls" {
		t.Errorf("relay-a = %q, want tls (the pre-existing line was disturbed)", names["relay-a"])
	}
	if names["relay-b"] != "trojan" {
		t.Errorf("relay-b = %q, want trojan", names["relay-b"])
	}
}

// TestAddListenerPreservesTheConsolePassword proves appending a line does not
// regenerate the management password.
//
// A regenerated password would be hashed into the config and never shown: the
// deployment path reads relay credentials back and never looks at the console
// password. The operator would simply find themselves locked out of a console
// they were using, with no message saying why.
func TestAddListenerPreservesTheConsolePassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	initRelay(t, path, "--transport", "tls", "--listen", "0.0.0.0:8443", "--name", "relay-a")
	before := loadConfig(t, path).WebUI.PasswordHash
	if before == "" {
		t.Fatal("the initial configuration has no password hash")
	}

	if err := cmdInit([]string{
		"--config", path, "--add-listener",
		"--transport", "vless", "--listen", "0.0.0.0:9443", "--name", "relay-b",
	}); err != nil {
		t.Fatalf("cmdInit --add-listener: %v", err)
	}

	after := loadConfig(t, path).WebUI.PasswordHash
	if after != before {
		t.Errorf("the console password hash changed:\n before %s\n  after %s", before, after)
	}
}

// TestAddListenerPreservesTheMode proves appending cannot silently convert a
// server into a client, or the reverse.
func TestAddListenerPreservesTheMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	initRelay(t, path, "--transport", "tls", "--listen", "0.0.0.0:8443", "--name", "relay-a")

	if err := cmdInit([]string{
		"--config", path, "--add-listener",
		"--transport", "vless", "--listen", "0.0.0.0:9443", "--name", "relay-b",
	}); err != nil {
		t.Fatalf("cmdInit --add-listener: %v", err)
	}
	if got := loadConfig(t, path).Mode; got != config.ModeServer {
		t.Errorf("mode = %q, want %q", got, config.ModeServer)
	}

	// Asking for a different mode while appending is refused rather than
	// quietly honoured, because the rest of the file belongs to the old mode.
	err := cmdInit([]string{
		"--config", path, "--add-listener", "--mode", "client",
		"--transport", "vless", "--listen", "0.0.0.0:10443", "--name", "relay-c",
	})
	if err == nil {
		t.Fatal("--add-listener with a conflicting --mode was accepted")
	}
	if !strings.Contains(err.Error(), "模式") {
		t.Errorf("error %q does not explain the mode conflict", err)
	}
}

// TestAddListenerUpdatesALineWithTheSameName proves a repeated deployment
// repairs its own line instead of accumulating duplicates.
//
// Two listeners claiming the same port cannot both bind, so a deploy that
// appended blindly would leave the host permanently broken from the second run
// onwards.
func TestAddListenerUpdatesALineWithTheSameName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	initRelay(t, path, "--transport", "tls", "--listen", "0.0.0.0:8443", "--name", "relay-a")

	if err := cmdInit([]string{
		"--config", path, "--add-listener",
		"--transport", "trojan", "--listen", "0.0.0.0:8443", "--name", "relay-a",
	}); err != nil {
		t.Fatalf("cmdInit --add-listener: %v", err)
	}

	cfg := loadConfig(t, path)
	if len(cfg.Server.Listeners) != 1 {
		t.Fatalf("got %d listeners, want 1 (a repeated name updates, it does not append)", len(cfg.Server.Listeners))
	}
	if got := cfg.Server.Listeners[0].Transport; got != "trojan" {
		t.Errorf("transport = %q, want trojan (the line was not updated)", got)
	}
}

// TestAddListenerKeepsTheCredentialsOfAnExistingLine proves a repeated
// deployment repairs its line instead of invalidating it.
//
// The same name updates the entry in place, so a naive update would generate a
// fresh PSK — silently breaking every client already configured with the old
// one, while the deployment reported success. The listen address still comes
// from the invocation, so moving a line to another port keeps working.
func TestAddListenerKeepsTheCredentialsOfAnExistingLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	initRelay(t, path, "--transport", "tls", "--listen", "0.0.0.0:8443", "--name", "relay-a")

	before := loadConfig(t, path).Server.Listeners[0].Settings
	psk, _ := before["psk"].(string)
	if psk == "" {
		t.Fatal("the first init did not record a psk")
	}

	// Same name and scheme, different port: the line is updated, not rekeyed.
	if err := cmdInit([]string{
		"--config", path, "--add-listener",
		"--transport", "tls", "--listen", "0.0.0.0:9443", "--name", "relay-a",
	}); err != nil {
		t.Fatalf("cmdInit --add-listener: %v", err)
	}

	cfg := loadConfig(t, path)
	if len(cfg.Server.Listeners) != 1 {
		t.Fatalf("got %d listeners, want 1", len(cfg.Server.Listeners))
	}
	got, _ := cfg.Server.Listeners[0].Settings["psk"].(string)
	if got != psk {
		t.Errorf("the psk rotated on a repeated deployment (%q -> %q): every client already "+
			"configured with the old key is now broken", psk, got)
	}
	if listen := cfg.Server.Listeners[0].Listen; listen != "0.0.0.0:9443" {
		t.Errorf("listen = %q, want 0.0.0.0:9443 (the invocation must still move the line)", listen)
	}

	// A different scheme needs its own settings, so those must be regenerated
	// rather than carried over: a UUID means nothing to trojan.
	if err := cmdInit([]string{
		"--config", path, "--add-listener",
		"--transport", "trojan", "--listen", "0.0.0.0:9443", "--name", "relay-a",
	}); err != nil {
		t.Fatalf("cmdInit --add-listener (transport change): %v", err)
	}
	switched := loadConfig(t, path).Server.Listeners[0].Settings
	if switched["password"] == nil {
		t.Errorf("a transport change kept the old scheme's settings: %v", switched)
	}
	if switched["psk"] == psk {
		t.Error("a transport change reused the previous psk")
	}
}

// TestAddListenerRejectsAPortAnotherLineOwns catches the collision while the
// operator is still watching.
//
// The relay would otherwise fail to bind and report it only in its own log,
// long after the deployment had printed success.
func TestAddListenerRejectsAPortAnotherLineOwns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	initRelay(t, path, "--transport", "tls", "--listen", "0.0.0.0:8443", "--name", "relay-a")

	err := cmdInit([]string{
		"--config", path, "--add-listener",
		"--transport", "trojan", "--listen", "0.0.0.0:8443", "--name", "relay-b",
	})
	if err == nil {
		t.Fatal("two lines were allowed to claim the same port")
	}
	if !strings.Contains(err.Error(), "relay-a") {
		t.Errorf("error %q does not name the line that already owns the port", err)
	}
	if got := len(loadConfig(t, path).Server.Listeners); got != 1 {
		t.Errorf("the rejected append still changed the config: %d listeners", got)
	}
}

// TestAddListenerRequiresAnExistingConfig proves the flag cannot be used to
// create a file by accident, which would look like it worked.
func TestAddListenerRequiresAnExistingConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.json")
	err := cmdInit([]string{
		"--config", path, "--add-listener",
		"--transport", "tls", "--listen", "0.0.0.0:8443", "--name", "relay-a",
	})
	if err == nil {
		t.Fatal("--add-listener on a missing file was accepted")
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("--add-listener created a file even though it reported an error")
	}
}

// TestAddListenerAndForceAreMutuallyExclusive proves the two opposite intents
// cannot be combined into something with no defined meaning.
func TestAddListenerAndForceAreMutuallyExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	initRelay(t, path, "--transport", "tls", "--listen", "0.0.0.0:8443", "--name", "relay-a")

	err := cmdInit([]string{
		"--config", path, "--add-listener", "--force",
		"--transport", "tls", "--listen", "0.0.0.0:9443", "--name", "relay-b",
	})
	if err == nil {
		t.Fatal("--add-listener together with --force was accepted")
	}
}

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	fn()
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// TestShowCredentialsSelectsByName is the regression test for the deployment
// reading back the wrong relay.
//
// `show-credentials` used to report only the first enabled listener. After a
// deployment appended a line, the read-back returned whichever relay happened
// to be configured first, and the client was wired to an endpoint the operator
// never asked for — while the transcript showed credentials that looked
// perfectly valid.
func TestShowCredentialsSelectsByName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	initRelay(t, path, "--transport", "tls", "--listen", "0.0.0.0:8443", "--name", "relay-a")
	if err := cmdInit([]string{
		"--config", path, "--add-listener",
		"--transport", "vless", "--listen", "0.0.0.0:9443", "--name", "relay-b",
	}); err != nil {
		t.Fatalf("cmdInit --add-listener: %v", err)
	}

	var second error
	out := captureStdout(t, func() {
		second = install.ShowCredentials([]string{"--config", path, "--name", "relay-b"})
	})
	if second != nil {
		t.Fatalf("ShowCredentials --name relay-b: %v", second)
	}
	if !strings.Contains(out, "name=relay-b") {
		t.Errorf("--name relay-b reported the wrong listener:\n%s", out)
	}
	if strings.Contains(out, "name=relay-a") {
		t.Errorf("--name relay-b also reported relay-a:\n%s", out)
	}

	// Without a name the first enabled line is still reported, so the flag
	// stays backwards compatible for the one-click script's output.
	var first error
	all := captureStdout(t, func() {
		first = install.ShowCredentials([]string{"--config", path})
	})
	if first != nil {
		t.Fatalf("ShowCredentials: %v", first)
	}
	if !strings.Contains(all, "name=relay-a") {
		t.Errorf("the unnamed lookup did not report the first listener:\n%s", all)
	}
}

// TestShowCredentialsRejectsAnUnknownName proves a typo in the deployment's
// listener name fails loudly rather than falling back to some other relay.
func TestShowCredentialsRejectsAnUnknownName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	initRelay(t, path, "--transport", "tls", "--listen", "0.0.0.0:8443", "--name", "relay-a")

	var err error
	out := captureStdout(t, func() {
		err = install.ShowCredentials([]string{"--config", path, "--name", "relay-typo"})
	})
	if err == nil {
		t.Fatalf("an unknown listener name was accepted and printed:\n%s", out)
	}
	if !strings.Contains(err.Error(), "relay-typo") {
		t.Errorf("error %q does not name the listener that was looked up", err)
	}
}
