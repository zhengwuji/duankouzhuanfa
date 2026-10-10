// Package webui implements the PortTransit management interface: a REST API
// plus an embedded single-page front end.
//
// # Why the GUI lives on the client
//
// The relay's job is to forward bytes and nothing else. Every listening socket
// on a relay is an attack surface, and an administrative console is the most
// valuable one on the host. The client, by contrast, is a workstation that
// already runs the operator's browser. So the management interface ships with
// the client and reaches relays through the same SSH channel the installer
// uses, rather than exposing an admin port on the relay itself.
//
// # Threat model
//
// The GUI binds to loopback by default. Exposing it on a routable address
// requires an explicit `allowRemote` plus a password, and validation refuses to
// start otherwise. Sessions are opaque random tokens held server-side, so a
// stolen cookie cannot be turned into a credential and a logout is immediate.
package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"porttransit/internal/client"
	"porttransit/internal/config"
	"porttransit/internal/logx"
	"porttransit/internal/server"
	"porttransit/internal/transport"
	"porttransit/internal/version"

	// The console lists the available schemes, so it must trigger their
	// registration itself rather than relying on whichever caller happens to
	// have imported the aggregate package first.
	_ "porttransit/internal/transports"
)

// Options parameterises New.
type Options struct {
	// Config is the live configuration the API reads and writes.
	Config *config.Config
	// Path is where Config is persisted after a change.
	Path string
	// Logger receives request and audit records.
	Logger *logx.Logger
	// Buffer is the in-memory log ring the API exposes.
	Buffer *logx.Buffer
	// Server is the relay, or nil when this process is client-only.
	Server *server.Server
	// Client is the client, or nil when this process is server-only.
	Client *client.Client
}

// Server is the management HTTP server.
type Server struct {
	cfg    *config.Config
	path   string
	log    *logx.Logger
	buffer *logx.Buffer
	relay  *server.Server
	cli    *client.Client

	sessions *sessionStore
	// logins throttles password guessing. It only matters when the console is
	// exposed beyond loopback, but it is always active: an operator who
	// misconfigures the bind should not also lose the protection.
	logins *loginThrottle

	mu       sync.Mutex
	httpSrv  *http.Server
	listener net.Listener
	started  bool
}

// New builds the management server.
func New(opts Options) (*Server, error) {
	if opts.Config == nil {
		return nil, errors.New("webui: config is required")
	}
	if opts.Path == "" {
		return nil, errors.New("webui: a config path is required to persist changes")
	}
	log := opts.Logger
	if log == nil {
		log = logx.Discard()
	}

	ttl := opts.Config.WebUI.SessionTTL.Or(12 * time.Hour)
	return &Server{
		cfg:      opts.Config,
		path:     opts.Path,
		log:      log.Component("webui"),
		buffer:   opts.Buffer,
		relay:    opts.Server,
		cli:      opts.Client,
		sessions: newSessionStore(ttl),
		logins:   newLoginThrottle(),
	}, nil
}

// Start binds the listener and serves in the background.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("webui: already started")
	}

	addr := s.cfg.WebUI.Listen
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("webui: bind %s: %w", addr, err)
	}
	s.listener = ln
	s.started = true

	mux := s.routes()
	s.httpSrv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: the log-streaming endpoint is long-lived by design,
		// and a write timeout would sever it mid-stream.
		IdleTimeout: 120 * time.Second,
	}
	srv := s.httpSrv
	s.mu.Unlock()

	s.log.Info("management interface listening",
		"listen", ln.Addr().String(),
		"tls", s.cfg.WebUI.TLS,
		"remote", s.cfg.WebUI.AllowRemote,
	)

	go func() {
		<-ctx.Done()
		s.Stop()
	}()

	go func() {
		var err error
		if s.cfg.WebUI.TLS {
			err = srv.ServeTLS(ln, s.cfg.WebUI.CertFile, s.cfg.WebUI.KeyFile)
		} else {
			err = srv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("management interface stopped unexpectedly", "err", err)
		}
	}()
	return nil
}

// Stop shuts the management server down.
func (s *Server) Stop() {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return
	}
	s.started = false
	srv := s.httpSrv
	s.mu.Unlock()

	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		s.log.Warn("management interface shutdown was not graceful", "err", err)
	}
	s.log.Info("management interface stopped")
}

// Addr reports the bound address, or the configured one before Start.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.cfg.WebUI.Listen
}

// URL reports the address an operator should open in a browser.
func (s *Server) URL() string {
	scheme := "http"
	if s.cfg.WebUI.TLS {
		scheme = "https"
	}
	addr := s.Addr()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return scheme + "://" + addr
	}
	// A wildcard bind is not a browsable address; loopback is the address the
	// operator can actually reach from the same machine.
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

// routes builds the mux.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// Public: the login form needs these without a session.
	mux.HandleFunc("/api/v1/login", s.handleLogin)
	mux.HandleFunc("/api/v1/logout", s.handleLogout)
	mux.HandleFunc("/api/v1/session", s.handleSession)

	// Authenticated API.
	mux.HandleFunc("/api/v1/status", s.auth(s.handleStatus))
	mux.HandleFunc("/api/v1/config", s.auth(s.handleConfig))
	mux.HandleFunc("/api/v1/config/validate", s.auth(s.handleValidate))
	mux.HandleFunc("/api/v1/reload", s.auth(s.handleReload))
	mux.HandleFunc("/api/v1/logs", s.auth(s.handleLogs))
	mux.HandleFunc("/api/v1/transports", s.auth(s.handleTransports))

	mux.HandleFunc("/api/v1/servers", s.auth(s.handleServers))
	mux.HandleFunc("/api/v1/servers/", s.auth(s.handleServerByID))
	mux.HandleFunc("/api/v1/tunnels", s.auth(s.handleTunnels))
	mux.HandleFunc("/api/v1/tunnels/", s.auth(s.handleTunnelByName))
	mux.HandleFunc("/api/v1/health", s.auth(s.handleHealth))
	mux.HandleFunc("/api/v1/probe", s.auth(s.handleProbe))
	mux.HandleFunc("/api/v1/password", s.auth(s.handlePassword))
	mux.HandleFunc("/api/v1/accounts", s.auth(s.handleAccounts))
	// Registered before the "/accounts" pattern would match it, because a
	// trailing-slash pattern is more specific and wins in ServeMux.
	mux.HandleFunc("/api/v1/accounts/reset", s.auth(s.handleAccountsReset))

	// Remote relay deployment over SSH — the "install the relay on my server"
	// button. It is authenticated and audited like any other mutation.
	mux.HandleFunc("/api/v1/deploy", s.auth(s.handleDeploy))
	mux.HandleFunc("/api/v1/deploy/", s.auth(s.handleDeployByID))

	// Static assets. The catch-all must be registered last so it does not
	// shadow the API paths.
	mux.Handle("/", s.staticHandler())

	return s.recoverMiddleware(s.logMiddleware(s.securityHeaders(mux)))
}

// auth wraps a handler with session verification.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := sessionToken(r)
		if token == "" || !s.sessions.valid(token) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": "authentication required",
				"code":  "unauthorized",
			})
			return
		}
		// Sliding expiry: an operator actively using the console is not logged
		// out mid-task, while an abandoned session still expires.
		s.sessions.touch(token)
		next(w, r)
	}
}

// sessionToken extracts the session token from the cookie or the
// Authorization header, so a script can drive the API without cookies.
func sessionToken(r *http.Request) string {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return ""
}

// securityHeaders applies the headers that keep a browser from turning a
// management console into a liability.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// The console renders no third-party content and loads no remote
		// script, so the strictest possible policy costs nothing.
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if s.cfg.WebUI.TLS {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// logMiddleware records every API call for audit.
func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		// Static assets are not interesting and would drown the audit trail.
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			return
		}
		level := s.log.Info
		if rec.status >= 400 {
			level = s.log.Warn
		}
		level("api request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"remote", clientIP(r, s.cfg.WebUI.TrustedProxies),
			"ms", time.Since(start).Milliseconds(),
		)
	})
}

// recoverMiddleware turns a handler panic into a 500 instead of killing the
// process, which matters because the console is the operator's only view into
// a relay that may still be serving traffic.
func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic in management handler",
					"path", r.URL.Path,
					"panic", fmt.Sprint(rec),
				)
				writeJSON(w, http.StatusInternalServerError, map[string]any{
					"error": "internal error",
					"code":  "panic",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// statusRecorder captures the response status for the audit log.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.written {
		r.status = code
		r.written = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	r.written = true
	return r.ResponseWriter.Write(b)
}

// Flush forwards to the underlying writer so streaming endpoints work.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// clientIP resolves the request's source address, honouring X-Forwarded-For
// only from a configured trusted proxy.
//
// Trusting the header unconditionally would let any client forge its address
// in the audit log, which is exactly the log an operator would consult after
// an incident.
func clientIP(r *http.Request, trusted []string) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if len(trusted) == 0 {
		return host
	}
	if !ipInCIDRs(net.ParseIP(host), trusted) {
		return host
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first, _, ok := strings.Cut(xff, ","); ok {
			return strings.TrimSpace(first)
		}
		return strings.TrimSpace(xff)
	}
	return host
}

// ipInCIDRs reports whether ip falls inside any of the CIDR strings. A bare
// address is treated as a /32 or /128.
func ipInCIDRs(ip net.IP, cidrs []string) bool {
	if ip == nil {
		return false
	}
	for _, entry := range cidrs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			if net.ParseIP(entry) != nil && net.ParseIP(entry).Equal(ip) {
				return true
			}
			continue
		}
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// writeJSON renders v as a JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// writeError renders a structured error the front end can display.
func writeError(w http.ResponseWriter, status int, code, format string, args ...any) {
	writeJSON(w, status, map[string]any{
		"error": fmt.Sprintf(format, args...),
		"code":  code,
	})
}

// decodeJSON reads a bounded JSON body.
//
// The limit matters: the API is reachable from a browser, and an unbounded
// decoder would let a single request exhaust the process's memory.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "expected a write method, got %s", r.Method)
		return false
	}
	defer r.Body.Close()

	const maxBody = 4 << 20
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", "could not parse the request body: %v", err)
		return false
	}
	return true
}

// versionInfo is the version block the front end displays.
type versionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	BuildTime string `json:"buildTime,omitempty"`
	Channel   string `json:"channel,omitempty"`
	Protocol  uint8  `json:"protocol"`
}

func currentVersion() versionInfo {
	return versionInfo{
		Version:   version.Version,
		Commit:    version.Commit,
		BuildTime: version.BuildTime,
		Channel:   version.Channel,
		Protocol:  version.ProtocolVersion,
	}
}

// transportDescriptor is the JSON view of a registered transport.
type transportDescriptor struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	DefaultPort int    `json:"defaultPort"`
	// Encrypted reports whether the transport protects the payload. The GUI
	// uses it to warn before an operator exposes an unencrypted listener.
	Encrypted bool `json:"encrypted"`
	// NativeHeader reports whether the scheme carries its own framing, which
	// decides whether the PortTransit preamble is used.
	NativeHeader bool `json:"nativeHeader"`
}

// transportEncrypted lists the schemes that protect the payload.
//
// It is a static table rather than a property of the transport interface
// because "is this encrypted" is a claim about the protocol, not about the
// implementation, and it must not be possible for a transport to declare
// itself safe by accident.
var transportEncrypted = map[string]bool{
	"tls":         true,
	"reality":     true,
	"trojan":      true,
	"vless":       true,
	"vmess":       true,
	"shadowsocks": true,
	"websocket":   false,
	"ws":          false,
	"http":        false,
	"httpupgrade": false,
	"socks5":      false,
	"direct":      false,
}

func transportList() []transportDescriptor {
	factories := transport.Descriptors()
	out := make([]transportDescriptor, 0, len(factories))
	for _, f := range factories {
		out = append(out, transportDescriptor{
			Name:         f.Name,
			Description:  f.Description,
			DefaultPort:  f.DefaultPort,
			Encrypted:    transportEncrypted[f.Name],
			NativeHeader: f.NativeHeader,
		})
	}
	return out
}
