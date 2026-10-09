package webui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// sessionCookieName is the cookie the front end carries.
const sessionCookieName = "pt_session"

// sessionStore holds live management sessions.
//
// Tokens are 32 random bytes held only in memory. A restart invalidates every
// session, which is the right behaviour for an administrative console: an
// operator who restarts the service expects to log in again, and a token that
// survived a restart would be a token that had to be written to disk.
type sessionStore struct {
	ttl      time.Duration
	mu       sync.Mutex
	sessions map[string]*session
}

type session struct {
	created time.Time
	seen    time.Time
	remote  string
}

func newSessionStore(ttl time.Duration) *sessionStore {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	s := &sessionStore{ttl: ttl, sessions: map[string]*session{}}
	go s.reap()
	return s
}

// create mints a new session for remote and returns its token.
func (s *sessionStore) create(remote string) string {
	token := randomToken()
	now := time.Now()
	s.mu.Lock()
	s.sessions[token] = &session{created: now, seen: now, remote: remote}
	s.mu.Unlock()
	return token
}

// valid reports whether a token names a live session.
func (s *sessionStore) valid(token string) bool {
	if token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return false
	}
	if time.Since(sess.seen) > s.ttl {
		delete(s.sessions, token)
		return false
	}
	return true
}

// touch extends a session's sliding expiry.
func (s *sessionStore) touch(token string) {
	s.mu.Lock()
	if sess, ok := s.sessions[token]; ok {
		sess.seen = time.Now()
	}
	s.mu.Unlock()
}

// destroy removes a session.
func (s *sessionStore) destroy(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// destroyAll removes every session, which is what a password change must do.
func (s *sessionStore) destroyAll() {
	s.mu.Lock()
	s.sessions = map[string]*session{}
	s.mu.Unlock()
}

// count reports how many sessions are live.
func (s *sessionStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// reap drops expired sessions so an abandoned console does not hold memory.
func (s *sessionStore) reap() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-s.ttl)
		s.mu.Lock()
		for token, sess := range s.sessions {
			if sess.seen.Before(cutoff) {
				delete(s.sessions, token)
			}
		}
		s.mu.Unlock()
	}
}

// randomToken returns a 32-byte URL-safe random token.
func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// A console that cannot mint a session token must not mint a
		// predictable one, so failing loudly is the only safe option.
		panic("webui: entropy source failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashPassword renders a password as a bcrypt hash.
//
// bcrypt rather than a plain digest: it is deliberately slow and salted per
// password, so a leaked config file does not yield the administrator's
// password to an offline attack.
func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// VerifyPassword checks a password against a stored hash.
//
// A stored value that is not a bcrypt hash is compared as plaintext, which
// keeps a hand-written config working; the comparison is constant-time so it
// does not leak the stored value byte by byte.
func VerifyPassword(hash, password string) bool {
	if hash == "" {
		return false
	}
	if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(hash), []byte(password)) == 1
}

// ValidatePassword applies the minimum policy a management console needs.
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return errPasswordTooShort
	}
	return nil
}

type passwordError string

func (e passwordError) Error() string { return string(e) }

const errPasswordTooShort = passwordError("password must be at least 8 characters")

// setSessionCookie writes the session cookie.
//
// HttpOnly keeps the token out of reach of any script, and SameSite=Strict
// means a cross-site request cannot carry it — which is what makes the API
// resistant to CSRF without a separate token.
func setSessionCookie(w http.ResponseWriter, r *http.Request, token string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   isTLSRequest(r),
		MaxAge:   int(ttl.Seconds()),
	})
}

// clearSessionCookie expires the session cookie.
func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   isTLSRequest(r),
		MaxAge:   -1,
	})
}

// isTLSRequest reports whether the request arrived over TLS, directly or
// through a trusted reverse proxy.
func isTLSRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
