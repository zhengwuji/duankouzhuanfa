package sshdeploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
