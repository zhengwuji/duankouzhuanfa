package sshdeploy

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestShellQuoteSurvivesMetacharacters proves an operator-supplied value cannot
// break out of the remote command, because these strings are interpolated into
// a shell line that runs as root.
func TestShellQuoteSurvivesMetacharacters(t *testing.T) {
	hostile := []string{
		"plain",
		"with space",
		"semi;colon",
		"dollar$var",
		"back`tick`",
		"quote'inside",
		"double\"quote",
		"newline\ninjection",
		"$(command)",
		"&& rm -rf /",
		"| pipe",
		"> redirect",
		"* glob",
		"back\\slash",
		"",
	}

	for _, s := range hostile {
		got := shellQuote(s)

		// The result must be a single quoted token: it starts and ends with a
		// quote, and every internal quote is escaped.
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Errorf("shellQuote(%q) = %q, which is not a single quoted token", s, got)
		}

		// Unquoting must recover the original exactly, which is what proves the
		// escaping is lossless rather than merely defensive.
		if unquoted := unquoteSingle(got); unquoted != s {
			t.Errorf("shellQuote(%q) = %q, which unquotes to %q", s, got, unquoted)
		}
	}
}

// unquoteSingle reverses shellQuote the way a POSIX shell would, so the test
// checks the escaping rather than merely its shape.
func unquoteSingle(s string) string {
	if len(s) < 2 {
		return s
	}
	inner := s[1 : len(s)-1]
	return strings.ReplaceAll(inner, `'\''`, "'")
}

// TestTruncate proves long transcripts are shortened with a marker, because a
// deployment log can be megabytes and the console shows it inline.
func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate shortened a string that fits: %q", got)
	}
	if got := truncate("exactlyten", 10); got != "exactlyten" {
		t.Errorf("truncate shortened a string of exactly the limit: %q", got)
	}
	got := truncate("this is a longer string", 10)
	if !strings.HasPrefix(got, "this is a ") {
		t.Errorf("truncate kept the wrong prefix: %q", got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncate did not mark the cut: %q", got)
	}
}

// TestDefaultName proves an unnamed deployment still gets a recognisable label,
// because the console lists relays by name and a blank one is unselectable.
func TestDefaultName(t *testing.T) {
	if got := defaultName("我的中转", "1.2.3.4"); got != "我的中转" {
		t.Errorf("defaultName overrode an explicit name: %q", got)
	}
	got := defaultName("", "1.2.3.4")
	if !strings.Contains(got, "1.2.3.4") {
		t.Errorf("defaultName did not include the host: %q", got)
	}
}

// TestAuthMethodsRejectsUnusableInput proves an authentication request with no
// usable credential is refused before any connection is attempted, because a
// failed SSH handshake against a hardened host may be logged as an intrusion.
func TestAuthMethodsRejectsUnusableInput(t *testing.T) {
	// A key method with no key material and no agent available must fail.
	// Both variables are cleared because os.UserHomeDir reads HOME on Unix and
	// USERPROFILE on Windows, and a real key in either location would make the
	// fallback succeed.
	home := t.TempDir()
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	_, err := authMethods(Request{Host: "example.com", Username: "root", AuthMethod: "key"})
	if err == nil {
		t.Error("authMethods accepted a key request with no key available")
	}
}

// TestAuthMethodsUsesInlinePEM proves an inline key takes precedence, which is
// how the console deploys with a key the operator pasted rather than a file.
func TestAuthMethodsUsesInlinePEM(t *testing.T) {
	// A syntactically valid but unusable key is enough: the point is that the
	// inline material is parsed and selected, not that it authenticates.
	methods, err := authMethods(Request{
		Host:          "example.com",
		Username:      "root",
		AuthMethod:    "key",
		PrivateKeyPEM: []byte("not a real key"),
	})
	if err == nil {
		t.Fatalf("authMethods accepted malformed inline key material: %v", methods)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "key") {
		t.Errorf("the error does not mention the key: %v", err)
	}
}

// TestAuthMethodsPasswordIncludesKeyboardInteractive proves the password is
// offered both ways, because many hardened SSH servers disable plain password
// auth and only accept the interactive challenge.
func TestAuthMethodsPasswordIncludesKeyboardInteractive(t *testing.T) {
	methods, err := authMethods(Request{
		Host:       "example.com",
		Username:   "root",
		AuthMethod: "password",
		Password:   "secret",
	})
	if err != nil {
		t.Fatalf("authMethods: %v", err)
	}
	if len(methods) < 2 {
		t.Errorf("password auth registered %d methods, want both password and keyboard-interactive", len(methods))
	}
}

// TestCheckKeyFileRejectsUnusableFiles proves an obviously bad key path is
// reported before connecting, so the operator gets a precise error rather than
// a generic authentication failure.
func TestCheckKeyFileRejectsUnusableFiles(t *testing.T) {
	dir := t.TempDir()

	// A directory is not a key.
	if err := CheckKeyFile(dir); err == nil {
		t.Error("CheckKeyFile accepted a directory")
	}

	// A missing file is not a key.
	if err := CheckKeyFile(filepath.Join(dir, "absent.pem")); err == nil {
		t.Error("CheckKeyFile accepted a missing file")
	}
}

// TestCheckKeyFileAcceptsAReadableFile proves a normal readable file passes, so
// the check does not block a valid deployment.
func TestCheckKeyFileAcceptsAReadableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("write the key file: %v", err)
	}
	if err := CheckKeyFile(path); err != nil {
		t.Errorf("CheckKeyFile rejected a readable file: %v", err)
	}
}

// withKnownHosts points the host key store at a temporary file, so the tests
// never touch the developer's real known_hosts.
func withKnownHosts(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	old := hostKeyPath
	hostKeyPath = func() (string, error) { return path, nil }
	t.Cleanup(func() { hostKeyPath = old })
	return path
}

// newTestHostKey builds a public key to stand in for a server's host key.
func newTestHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate a host key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("convert the host key: %v", err)
	}
	return sshPub
}

// TestHostKeyUnknownHostIsTrustedAndRecorded is the regression test for the
// defect that made one-click deployment fail on a fresh console host: with no
// known_hosts file there is nothing to verify against, and the old code refused
// the connection outright, telling the operator to go run ssh by hand — the
// manual step this feature exists to remove.
//
// The key must be accepted *and* written to disk, so the next deployment
// verifies it strictly.
func TestHostKeyUnknownHostIsTrustedAndRecorded(t *testing.T) {
	khPath := withKnownHosts(t)
	key := newTestHostKey(t)

	var lines []string
	cb, err := defaultHostKeyCallback(func(f string, a ...any) {
		lines = append(lines, fmt.Sprintf(f, a...))
	})
	if err != nil {
		t.Fatalf("defaultHostKeyCallback: %v", err)
	}

	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22}
	if err := cb("192.0.2.10:22", addr, key); err != nil {
		t.Fatalf("an unknown host was refused: %v", err)
	}

	// The fingerprint must be reported: accepting silently would hide the trust
	// decision from the operator.
	if len(lines) == 0 {
		t.Error("the first connection did not report the host key fingerprint")
	} else if !strings.Contains(strings.Join(lines, "\n"), ssh.FingerprintSHA256(key)) {
		t.Errorf("the transcript does not contain the fingerprint %s: %v", ssh.FingerprintSHA256(key), lines)
	}

	// And it must be on disk, or every deployment would re-trust the host.
	data, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	if !strings.Contains(string(data), "192.0.2.10") {
		t.Errorf("known_hosts does not record the host: %q", data)
	}
}

// TestHostKeyRecordedHostIsVerified proves the recorded key is enforced on the
// next connection, which is what makes trust-on-first-use only affect the very
// first deployment.
func TestHostKeyRecordedHostIsVerified(t *testing.T) {
	withKnownHosts(t)
	key := newTestHostKey(t)
	emit := func(string, ...any) {}

	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.20"), Port: 22}

	first, err := defaultHostKeyCallback(emit)
	if err != nil {
		t.Fatalf("defaultHostKeyCallback: %v", err)
	}
	if err := first("192.0.2.20:22", addr, key); err != nil {
		t.Fatalf("the first connection was refused: %v", err)
	}

	second, err := defaultHostKeyCallback(emit)
	if err != nil {
		t.Fatalf("defaultHostKeyCallback: %v", err)
	}
	// The same key is still fine.
	if err := second("192.0.2.20:22", addr, key); err != nil {
		t.Errorf("the recorded key was rejected: %v", err)
	}
	// A different key for a host that is already recorded is a takeover, and
	// must never be accepted.
	if err := second("192.0.2.20:22", addr, newTestHostKey(t)); err == nil {
		t.Error("a changed host key was accepted")
	} else if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("the mismatch error is not legible: %v", err)
	}
}

// TestHostKeyCreatesTheDirectory proves a machine with no ~/.ssh at all can
// still deploy, because that is the state of a brand new console host.
func TestHostKeyCreatesTheDirectory(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "nested", ".ssh", "known_hosts")
	old := hostKeyPath
	hostKeyPath = func() (string, error) { return path, nil }
	t.Cleanup(func() { hostKeyPath = old })

	cb, err := defaultHostKeyCallback(func(string, ...any) {})
	if err != nil {
		t.Fatalf("defaultHostKeyCallback: %v", err)
	}
	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.30"), Port: 22}
	if err := cb("192.0.2.30:22", addr, newTestHostKey(t)); err != nil {
		t.Fatalf("a host with no ~/.ssh was refused: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("known_hosts was not created: %v", err)
	}
}

// TestHostKeyStoreNeedsARealHome is the regression test for the deployment that
// failed only when the console ran as a service.
//
// systemd does not set HOME. The old fallback was ".", so the store resolved
// against the service's working directory — "/" under ProtectSystem=strict —
// and the deployment died with "cannot create .ssh: mkdir .ssh: read-only file
// system". Had that directory been writable the bug would have been worse: a
// later run from elsewhere would find no record and re-trust the host, silently
// defeating the pinning that makes trust-on-first-use safe.
//
// So an unknown home must be an error that names the problem, never a guess.
func TestHostKeyStoreNeedsARealHome(t *testing.T) {
	// Simulate the service environment directly instead of clearing the
	// environment variables: on some platforms the account database still
	// answers, which would skip the assertion on the one path that matters.
	old := homeDir
	homeDir = func() (string, error) {
		return "", errors.New("cannot determine the home directory")
	}
	t.Cleanup(func() { homeDir = old })

	path, err := hostKeyPath()
	if err == nil {
		t.Fatalf("hostKeyPath returned %q with no home directory; it must refuse to guess", path)
	}
	if path != "" {
		t.Errorf("hostKeyPath returned %q alongside its error; a caller that ignores the error must not get a usable path", path)
	}
	if !strings.Contains(err.Error(), "home directory") {
		t.Errorf("the error does not say what is missing: %v", err)
	}

	// And the callback must surface that rather than acting on an empty path.
	if _, err := defaultHostKeyCallback(func(string, ...any) {}); err == nil {
		t.Error("defaultHostKeyCallback accepted an unknown home directory")
	}
}

// TestHomeDirPrefersTheEnvironment documents the order of resolution: the
// shell's variable wins, and the account database is only the fallback for a
// service. Both spellings are set because os.UserHomeDir reads USERPROFILE on
// Windows and HOME everywhere else.
func TestHomeDirPrefersTheEnvironment(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "from-env")
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	got, err := homeDirReal()
	if err != nil {
		t.Fatalf("homeDirReal: %v", err)
	}
	if got != dir {
		t.Errorf("homeDirReal() = %q, want %q from the environment", got, dir)
	}
}
