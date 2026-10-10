package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"porttransit/internal/config"
)

// TestPasswordHashing proves a password is stored as a bcrypt hash and that
// verification works, including rejecting the wrong password.
func TestPasswordHashing(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("the hash %q is not bcrypt", hash)
	}
	if hash == "correct horse battery staple" {
		t.Fatal("the password was stored in cleartext")
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Error("the correct password was rejected")
	}
	if VerifyPassword(hash, "wrong password") {
		t.Error("an incorrect password was accepted")
	}
	if VerifyPassword("", "anything") {
		t.Error("an empty stored hash accepted a password")
	}
}

// TestPasswordValidation proves the minimum policy is enforced, so a console
// password cannot be a single character.
func TestPasswordValidation(t *testing.T) {
	if err := ValidatePassword("short"); err == nil {
		t.Error("a five-character password was accepted")
	}
	if err := ValidatePassword("longenough"); err != nil {
		t.Errorf("an eight-character password was rejected: %v", err)
	}
}

// TestSessionLifecycle proves a session can be created, validated, touched and
// destroyed, which is the whole basis of console authentication.
func TestSessionLifecycle(t *testing.T) {
	s := newSessionStore(time.Hour)

	if s.valid("") {
		t.Error("an empty token validated")
	}
	if s.valid("nonexistent") {
		t.Error("an unknown token validated")
	}

	token := s.create("127.0.0.1")
	if !s.valid(token) {
		t.Fatal("a freshly created session did not validate")
	}
	if s.count() != 1 {
		t.Errorf("the store holds %d sessions, want 1", s.count())
	}

	s.touch(token)
	if !s.valid(token) {
		t.Error("a session did not survive being touched")
	}

	s.destroy(token)
	if s.valid(token) {
		t.Error("a destroyed session still validated")
	}
}

// TestSessionDestroyAll proves a password change can invalidate every session,
// which is the operator's remedy for a suspected compromise.
func TestSessionDestroyAll(t *testing.T) {
	s := newSessionStore(time.Hour)
	a := s.create("a")
	b := s.create("b")
	if s.count() != 2 {
		t.Fatalf("the store holds %d sessions, want 2", s.count())
	}
	s.destroyAll()
	if s.valid(a) || s.valid(b) {
		t.Error("a session survived destroyAll")
	}
}

// TestSessionExpiry proves an idle session expires, so an abandoned console
// does not stay open indefinitely.
func TestSessionExpiry(t *testing.T) {
	s := newSessionStore(10 * time.Millisecond)
	token := s.create("127.0.0.1")
	if !s.valid(token) {
		t.Fatal("a fresh session did not validate")
	}
	time.Sleep(25 * time.Millisecond)
	if s.valid(token) {
		t.Error("a session past its TTL still validated")
	}
}

// TestRandomTokenIsUnique proves tokens do not repeat, because a repeated
// token would let one operator's session be hijacked by another.
func TestRandomTokenIsUnique(t *testing.T) {
	seen := make(map[string]bool, 500)
	for i := 0; i < 500; i++ {
		tok := randomToken()
		if seen[tok] {
			t.Fatalf("randomToken produced a duplicate after %d draws", i)
		}
		seen[tok] = true
		if len(tok) < 40 {
			t.Fatalf("token %q is only %d characters, expected a 32-byte encoding", tok, len(tok))
		}
	}
}

// TestRedactConfigHidesSecrets proves the API never returns a credential,
// which is what keeps a screenshot or a proxy log from leaking one.
func TestRedactConfigHidesSecrets(t *testing.T) {
	cfg := config.Default(config.ModeBoth)
	cfg.WebUI.PasswordHash = "$2a$10$realsecrethash"
	cfg.Server.Listeners = []config.Listener{
		{
			Name:      "relay",
			Transport: "tls",
			Listen:    "0.0.0.0:8443",
			Enabled:   true,
			Settings: map[string]any{
				"psk":      "base64:SUPERSECRETKEY",
				"certFile": "/etc/porttransit/certs/relay.crt",
			},
		},
	}
	cfg.Server.Clients = []config.ClientAccount{
		{
			ID:      "c1",
			Enabled: true,
			Credentials: map[string]string{
				"uuid":     "de305d54-75b4-431b-adb2-eb6b9e546014",
				"password": "hunter2",
			},
		},
	}
	cfg.Client.Servers = []config.ServerEntry{
		{
			ID:        "srv-1",
			Address:   "sh.example.com:8443",
			Transport: "tls",
			Enabled:   true,
			Settings:  map[string]any{"psk": "base64:ANOTHERSECRET"},
		},
	}

	redacted := redactConfig(cfg)

	raw, err := json.Marshal(redacted)
	if err != nil {
		t.Fatalf("marshal the redacted config: %v", err)
	}
	text := string(raw)

	for _, secret := range []string{
		"SUPERSECRETKEY", "realsecrethash", "de305d54-75b4-431b-adb2-eb6b9e546014",
		"hunter2", "ANOTHERSECRET",
	} {
		if strings.Contains(text, secret) {
			t.Errorf("the redacted config still contains %q", secret)
		}
	}

	// Non-secret values must survive, or the GUI cannot show the configuration.
	if !strings.Contains(text, "/etc/porttransit/certs/relay.crt") {
		t.Error("redaction removed a non-secret setting")
	}
	if !strings.Contains(text, "sh.example.com:8443") {
		t.Error("redaction removed a relay address")
	}
	if !strings.Contains(text, RedactedPlaceholder) {
		t.Error("no placeholder was emitted for the redacted values")
	}
}

// TestRedactionRoundTripPreservesSecrets proves the property the GUI depends
// on: submitting the redacted document unchanged must not overwrite a stored
// secret with the placeholder.
func TestRedactionRoundTripPreservesSecrets(t *testing.T) {
	current := config.Default(config.ModeBoth)
	current.WebUI.PasswordHash = "$2a$10$realsecrethash"
	current.Server.Listeners = []config.Listener{
		{
			Name:      "relay",
			Transport: "tls",
			Listen:    "0.0.0.0:8443",
			Enabled:   true,
			Settings:  map[string]any{"psk": "base64:REALPSK", "certFile": "/certs/x.crt"},
		},
	}
	current.Server.Clients = []config.ClientAccount{
		{ID: "c1", Enabled: true, Credentials: map[string]string{"uuid": "real-uuid-value"}},
	}
	current.Client.Servers = []config.ServerEntry{
		{ID: "srv-1", Address: "a:1", Transport: "tls", Enabled: true, Settings: map[string]any{"psk": "base64:RELAYPSK"}},
	}

	// Round-trip through JSON exactly as the browser does.
	raw, err := json.Marshal(redactConfig(current))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	incoming, err := config.Parse(raw)
	if err != nil {
		t.Fatalf("the redacted document does not parse back: %v", err)
	}

	applyRedactionInPlace(incoming, current)

	if incoming.WebUI.PasswordHash != "$2a$10$realsecrethash" {
		t.Errorf("the web UI password was not restored: %q", incoming.WebUI.PasswordHash)
	}
	if got := incoming.Server.Listeners[0].Settings["psk"]; got != "base64:REALPSK" {
		t.Errorf("the listener PSK was not restored: %v", got)
	}
	if got := incoming.Server.Clients[0].Credentials["uuid"]; got != "real-uuid-value" {
		t.Errorf("the client uuid was not restored: %v", got)
	}
	if got := incoming.Client.Servers[0].Settings["psk"]; got != "base64:RELAYPSK" {
		t.Errorf("the relay PSK was not restored: %v", got)
	}
	// A non-secret must not be clobbered by the restore path.
	if got := incoming.Server.Listeners[0].Settings["certFile"]; got != "/certs/x.crt" {
		t.Errorf("a non-secret setting was altered: %v", got)
	}
}

// TestRedactionAcceptsNewSecrets proves the restore path does not block an
// operator from setting a new credential: a value that is not the placeholder
// must be kept as submitted.
func TestRedactionAcceptsNewSecrets(t *testing.T) {
	current := config.Default(config.ModeBoth)
	current.Server.Listeners = []config.Listener{
		{Name: "relay", Transport: "tls", Enabled: true, Settings: map[string]any{"psk": "base64:OLD"}},
	}

	incoming := config.Default(config.ModeBoth)
	incoming.Server.Listeners = []config.Listener{
		{Name: "relay", Transport: "tls", Enabled: true, Settings: map[string]any{"psk": "base64:NEW"}},
	}

	applyRedactionInPlace(incoming, current)

	if got := incoming.Server.Listeners[0].Settings["psk"]; got != "base64:NEW" {
		t.Errorf("a newly supplied PSK was overwritten with the stored value: %v", got)
	}
}

// TestSessionCookieFlags proves the cookie carries the flags that keep a
// management session safe from script access and cross-site requests.
func TestSessionCookieFlags(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", nil)

	setSessionCookie(rec, req, "test-token", time.Hour)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != sessionCookieName {
		t.Errorf("cookie name = %q, want %q", c.Name, sessionCookieName)
	}
	if !c.HttpOnly {
		t.Error("the session cookie is not HttpOnly, so any script could read it")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Error("the session cookie is not SameSite=Strict, so a cross-site request could carry it")
	}
	if c.Secure {
		t.Error("the cookie is marked Secure over plain HTTP, so a browser would drop it")
	}
	if c.MaxAge != 3600 {
		t.Errorf("cookie MaxAge = %d, want 3600", c.MaxAge)
	}
}

// TestSessionCookieSecureOverTLS proves the Secure flag is set when the
// console is served over TLS.
func TestSessionCookieSecureOverTLS(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://localhost/api/v1/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")

	setSessionCookie(rec, req, "token", time.Hour)
	if !rec.Result().Cookies()[0].Secure {
		t.Error("the cookie is not Secure behind a TLS-terminating proxy")
	}
}

// TestSessionTokenSources proves the API accepts the token from a cookie or a
// bearer header, so a script can drive the console without cookies.
func TestSessionTokenSources(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	if got := sessionToken(req); got != "" {
		t.Errorf("sessionToken on a bare request = %q, want empty", got)
	}

	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "from-cookie"})
	if got := sessionToken(req); got != "from-cookie" {
		t.Errorf("sessionToken = %q, want from-cookie", got)
	}

	bearer := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	bearer.Header.Set("Authorization", "Bearer from-header")
	if got := sessionToken(bearer); got != "from-header" {
		t.Errorf("sessionToken = %q, want from-header", got)
	}
}

// TestClientIPTrustedProxies proves X-Forwarded-For is honoured only from a
// configured proxy, because trusting it unconditionally would let any client
// forge its address in the audit log.
func TestClientIPTrustedProxies(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.7, 203.0.113.1")

	// With no trusted proxies the header is ignored.
	if got := clientIP(req, nil); got != "203.0.113.9" {
		t.Errorf("clientIP with no trusted proxies = %q, want the socket address", got)
	}

	// From an untrusted source the header is still ignored.
	if got := clientIP(req, []string{"10.0.0.0/8"}); got != "203.0.113.9" {
		t.Errorf("clientIP with an untrusted source = %q, want the socket address", got)
	}

	// From a trusted proxy the first forwarded address is used.
	if got := clientIP(req, []string{"203.0.113.0/24"}); got != "198.51.100.7" {
		t.Errorf("clientIP with a trusted proxy = %q, want 198.51.100.7", got)
	}

	// A bare address entry is treated as a single host.
	if got := clientIP(req, []string{"203.0.113.9"}); got != "198.51.100.7" {
		t.Errorf("clientIP with a bare trusted address = %q", got)
	}
}

// TestTransportListAnnotatesEncryption proves every registered transport is
// classified, because an unclassified scheme would be reported as unencrypted
// and could mislead an operator into exposing a listener.
func TestTransportListAnnotatesEncryption(t *testing.T) {
	list := transportList()
	if len(list) == 0 {
		t.Fatal("no transports were registered; the aggregate import is missing")
	}
	for _, td := range list {
		if td.Name == "" {
			t.Error("a transport descriptor has no name")
		}
		if _, ok := transportEncrypted[td.Name]; !ok {
			t.Errorf("transport %q has no encryption classification", td.Name)
		}
	}
}

// TestSplitProblems proves a validation error is broken into a list the GUI
// can render, rather than one long string.
func TestSplitProblems(t *testing.T) {
	got := splitProblems("config: first problem; second problem; third")
	if len(got) != 3 {
		t.Fatalf("split into %d problems, want 3: %v", len(got), got)
	}
	if got[0] != "first problem" {
		t.Errorf("the first problem is %q", got[0])
	}
}

// TestRedactAllValues proves a credentials map has every value replaced, since
// the map is keyed by transport name and each value is a secret regardless of
// its own key.
func TestRedactAllValues(t *testing.T) {
	in := map[string]any{"uuid": "a", "password": "b", "empty": ""}
	out := redactAllValues(in)
	for k, v := range out {
		if k == "empty" {
			continue
		}
		if v != RedactedPlaceholder {
			t.Errorf("value for %q was not redacted: %v", k, v)
		}
	}
}

// TestIsSecretKey proves the secret classification covers the names a transport
// actually uses, since a missed name leaks a credential.
func TestIsSecretKey(t *testing.T) {
	secret := []string{"psk", "PSK", "password", "passwordHash", "uuid", "privateKey", "token", "credentials", "secret"}
	for _, k := range secret {
		if !isSecretKey(k) {
			t.Errorf("isSecretKey(%q) = false, want true", k)
		}
	}
	notSecret := []string{"certFile", "serverName", "listen", "path", "method", "address"}
	for _, k := range notSecret {
		if isSecretKey(k) {
			t.Errorf("isSecretKey(%q) = true, want false", k)
		}
	}
}

// TestStaticHandlerAnswersUnknownAPIPathsWith404 proves a mistyped endpoint is
// reported as missing rather than being answered with the single-page shell.
//
// The catch-all static handler falls back to index.html so a deep link works on
// refresh, and that fallback used to swallow /api/ as well: an unknown endpoint
// returned 200 with HTML, so a caller saw success and then failed parsing HTML
// as JSON, and a probe could not distinguish a missing endpoint from a present
// one.
func TestStaticHandlerAnswersUnknownAPIPathsWith404(t *testing.T) {
	s := &Server{}
	h := s.staticHandler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/does-not-exist", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown API path returned %d, want 404 (body starts %q)", rec.Code, firstBytes(rec.Body.String(), 40))
	}
	if ct := rec.Header().Get("Content-Type"); strings.Contains(ct, "text/html") {
		t.Errorf("unknown API path was answered with HTML (%s)", ct)
	}

	// A real client-side route must still get the shell, or a refresh on a deep
	// link would break.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/some/client/route", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("client-side route returned %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<title>") {
		t.Errorf("client-side route did not serve the shell: %q", firstBytes(rec.Body.String(), 60))
	}
}

func firstBytes(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
