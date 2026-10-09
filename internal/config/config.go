// Package config defines the on-disk configuration schema shared by the relay
// server, the client and the Web GUI.
//
// # Compatibility contract
//
// The JSON tags in this file are a public interface: the Web GUI, the installer
// script and hand-written configs all rely on them. Renaming a tag is a
// breaking change and requires a SchemaVersion bump plus a migration in
// migrate.go.
//
// # Secrets
//
// Values under a key named password, token, uuid or private_key are written to
// disk with 0600 permissions and are never echoed back by the REST API in
// cleartext (see the webui package's redaction rules).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SchemaVersion is the config layout revision this build reads and writes.
const SchemaVersion = 2

// Mode selects which roles a single config file describes. One file may
// describe both roles so a relay host can also run a client for its own
// upstream hop.
type Mode string

const (
	// ModeServer runs inbound listeners and static forward rules.
	ModeServer Mode = "server"
	// ModeClient runs outbound tunnels and the local SOCKS5/HTTP proxy.
	ModeClient Mode = "client"
	// ModeBoth runs both roles from one process.
	ModeBoth Mode = "both"
)

// Config is the root document.
type Config struct {
	// SchemaVersion is checked on load; older files are migrated forward.
	SchemaVersion int `json:"schemaVersion"`
	// Mode selects which subsystems start.
	Mode Mode `json:"mode"`
	// Log configures logging for every subsystem.
	Log LogConfig `json:"log"`
	// WebUI configures the management HTTP server.
	WebUI WebUIConfig `json:"webui"`
	// Server holds relay-side settings. Nil when Mode is ModeClient.
	Server *ServerConfig `json:"server,omitempty"`
	// Client holds client-side settings. Nil when Mode is ModeServer.
	Client *ClientConfig `json:"client,omitempty"`
}

// LogConfig controls the shared logger.
type LogConfig struct {
	// Level is one of debug, info, warn, error.
	Level string `json:"level"`
	// File is an optional log file path. Empty logs to stderr only.
	File string `json:"file,omitempty"`
	// JSON selects machine-readable output.
	JSON bool `json:"json,omitempty"`
	// BufferSize is how many recent records the Web GUI can display.
	BufferSize int `json:"bufferSize,omitempty"`
}

// WebUIConfig controls the management interface.
//
// The GUI binds to loopback by default. Exposing it on a public interface
// requires an explicit AllowRemote plus a password, and the server refuses to
// start otherwise so a relay is never left with an open admin console.
type WebUIConfig struct {
	// Enabled turns the management server on.
	Enabled bool `json:"enabled"`
	// Listen is the bind address, default 127.0.0.1:8787.
	Listen string `json:"listen"`
	// Username is the administrator account name.
	Username string `json:"username"`
	// PasswordHash is a bcrypt hash. The plaintext is never stored.
	PasswordHash string `json:"passwordHash,omitempty"`
	// AllowRemote permits binding to a non-loopback address.
	AllowRemote bool `json:"allowRemote,omitempty"`
	// TLS enables HTTPS. CertFile and KeyFile must then be set, or a
	// self-signed certificate is generated into DataDir.
	TLS bool `json:"tls,omitempty"`
	// CertFile is the PEM certificate path.
	CertFile string `json:"certFile,omitempty"`
	// KeyFile is the PEM private key path.
	KeyFile string `json:"keyFile,omitempty"`
	// SessionTTL bounds how long a GUI login stays valid.
	SessionTTL Duration `json:"sessionTtl,omitempty"`
	// TrustedProxies lists CIDRs whose X-Forwarded-For header is honoured.
	TrustedProxies []string `json:"trustedProxies,omitempty"`
}

// ServerConfig is the relay side.
type ServerConfig struct {
	// DataDir stores runtime state such as the generated certificate and the
	// traffic counters. Defaults to /var/lib/porttransit.
	DataDir string `json:"dataDir,omitempty"`

	// Listeners are inbound endpoints. Each one speaks exactly one transport.
	Listeners []Listener `json:"listeners"`

	// Forwards are static port-forwarding rules evaluated before the generic
	// tunnel handler. They let one relay expose a fixed target on a fixed port
	// without the client naming a target.
	Forwards []Forward `json:"forwards,omitempty"`

	// Clients maps a client id to its credential and policy. A relay with an
	// empty Clients list accepts any authenticated credential it is
	// configured with; a non-empty list enables per-client policy.
	Clients []ClientAccount `json:"clients,omitempty"`

	// ACL is the global destination policy.
	ACL ACLConfig `json:"acl"`

	// Limits bounds resource use per connection and per client.
	Limits LimitConfig `json:"limits"`

	// Resolver overrides DNS for relay-side target resolution.
	Resolver ResolverConfig `json:"resolver,omitempty"`

	// Masking configures what an unauthenticated prober sees.
	Masking MaskingConfig `json:"masking,omitempty"`
}

// Listener is one inbound endpoint.
type Listener struct {
	// Name is a stable identifier used by the API and by forward rules.
	Name string `json:"name"`
	// Transport names a registered transport scheme.
	Transport string `json:"transport"`
	// Listen is the bind address, e.g. 0.0.0.0:8443.
	Listen string `json:"listen"`
	// Enabled turns this listener on.
	Enabled bool `json:"enabled"`
	// Network is tcp, tcp4, tcp6 or udp. Empty means tcp.
	Network string `json:"network,omitempty"`
	// Settings holds transport-specific parameters such as uuid, password,
	// sni, path, network and cert files.
	Settings map[string]any `json:"settings,omitempty"`
	// AllowForward restricts this listener to matching forward rules. Empty
	// allows every rule.
	AllowForward []string `json:"allowForward,omitempty"`
	// DenyForward blocks matching forward rules.
	DenyForward []string `json:"denyForward,omitempty"`
	// TCPFastOpen enables TCP fast open where the platform supports it.
	TCPFastOpen bool `json:"tcpFastOpen,omitempty"`
	// MPTCP enables multipath TCP where the platform supports it.
	MPTCP bool `json:"mptcp,omitempty"`
	// ProxyProtocol accepts a HAProxy PROXY protocol header before the
	// transport handshake, so a relay can sit behind another load balancer.
	ProxyProtocol bool `json:"proxyProtocol,omitempty"`
	// Note is free-form text shown in the GUI.
	Note string `json:"note,omitempty"`
}

// Forward is a static port-forwarding rule.
//
// Two shapes are supported:
//
//   - Target is set: the relay dials Target directly, ignoring whatever the
//     client asked for. This is the classic "listen here, send there" rule.
//   - Target is empty: the relay dials the address the client names, but only
//     when that address matches AllowedTargets. This turns one listener into a
//     constrained gateway.
type Forward struct {
	// Name is a stable identifier.
	Name string `json:"name"`
	// Enabled turns the rule on.
	Enabled bool `json:"enabled"`
	// Listener names the Listener this rule attaches to. Empty attaches to
	// every listener, which is only sensible for a single-listener relay.
	Listener string `json:"listener,omitempty"`
	// Transport restricts the rule to one transport scheme. Empty matches all.
	Transport string `json:"transport,omitempty"`
	// Target is the upstream address. Empty means "honour the client's target".
	Target string `json:"target,omitempty"`
	// AllowedTargets lists destinations the client may name when Target is
	// empty. Entries may be exact host:port, a bare host (any port) or a
	// domain suffix prefixed with ".".
	AllowedTargets []string `json:"allowedTargets,omitempty"`
	// Client restricts the rule to one client id. Empty matches all.
	Client string `json:"client,omitempty"`
	// Balance selects the upstream strategy when Target names several hosts
	// separated by commas: first, round-robin, random, least-conn or
	// least-latency.
	Balance string `json:"balance,omitempty"`
	// ProxyProtocolOut prepends a PROXY protocol v1 header when dialing the
	// target, so the target can see the original client address.
	ProxyProtocolOut bool `json:"proxyProtocolOut,omitempty"`
	// Sniff overrides protocol sniffing for this rule. Nil inherits the global
	// setting.
	Sniff *bool `json:"sniff,omitempty"`
	// Note is free-form text shown in the GUI.
	Note string `json:"note,omitempty"`
}

// ClientAccount is one client's credential and policy on the relay.
type ClientAccount struct {
	// ID is the client identifier the client reports.
	ID string `json:"id"`
	// Name is a human label.
	Name string `json:"name,omitempty"`
	// Enabled turns the account on without deleting it.
	Enabled bool `json:"enabled"`
	// Credentials holds per-transport secrets. The key is the transport name
	// (uuid for vless/vmess, password for trojan/shadowsocks, ...). A single
	// account can hold credentials for several transports so one client can
	// use different schemes on different networks.
	Credentials map[string]string `json:"credentials,omitempty"`
	// AllowedTargets narrows the global ACL for this client. Empty inherits.
	AllowedTargets []string `json:"allowedTargets,omitempty"`
	// DeniedTargets blocks destinations for this client. Deny wins over allow.
	DeniedTargets []string `json:"deniedTargets,omitempty"`
	// MaxConnections caps concurrent streams. Zero means unlimited.
	MaxConnections int `json:"maxConnections,omitempty"`
	// RateLimitKBps caps throughput in kilobytes per second. Zero means
	// unlimited.
	RateLimitKBps int `json:"rateLimitKBps,omitempty"`
	// QuotaBytes caps total traffic. Zero means unlimited.
	QuotaBytes int64 `json:"quotaBytes,omitempty"`
	// ExpiresAt disables the account after this time. Zero means never.
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
	// Note is free-form text shown in the GUI.
	Note string `json:"note,omitempty"`
}

// ACLConfig is the relay's destination policy.
type ACLConfig struct {
	// Allow lists permitted destinations. Empty means "allow everything not
	// denied", which is the default for a self-hosted relay.
	Allow []string `json:"allow,omitempty"`
	// Deny lists blocked destinations. Deny is evaluated first.
	Deny []string `json:"deny,omitempty"`
	// BlockPrivate rejects destinations in RFC1918, loopback, link-local and
	// other non-routable ranges. It is on by default so a relay cannot be
	// turned into a probe of its own private network.
	BlockPrivate *bool `json:"blockPrivate,omitempty"`
	// BlockPorts lists destination ports that are always refused.
	BlockPorts []int `json:"blockPorts,omitempty"`
	// AllowPorts, when non-empty, restricts destinations to these ports.
	AllowPorts []int `json:"allowPorts,omitempty"`
}

// LimitConfig bounds relay resource use.
type LimitConfig struct {
	// MaxConnections caps concurrent streams across all clients.
	MaxConnections int `json:"maxConnections,omitempty"`
	// MaxConnectionsPerIP caps concurrent streams from one source address.
	MaxConnectionsPerIP int `json:"maxConnectionsPerIP,omitempty"`
	// HandshakeTimeout bounds the transport handshake.
	HandshakeTimeout Duration `json:"handshakeTimeout,omitempty"`
	// IdleTimeout closes a stream with no traffic in either direction.
	IdleTimeout Duration `json:"idleTimeout,omitempty"`
	// DialTimeout bounds connecting to the final target.
	DialTimeout Duration `json:"dialTimeout,omitempty"`
	// UDPTimeout bounds an idle UDP association.
	UDPTimeout Duration `json:"udpTimeout,omitempty"`
	// BufferSize is the per-direction copy buffer in bytes.
	BufferSize int `json:"bufferSize,omitempty"`
	// RateLimitKBps caps total relay throughput. Zero means unlimited.
	RateLimitKBps int `json:"rateLimitKBps,omitempty"`
	// MaxHandshakesPerSecondPerIP throttles connection attempts per source.
	MaxHandshakesPerSecondPerIP int `json:"maxHandshakesPerSecondPerIP,omitempty"`
}

// ResolverConfig overrides DNS behaviour on the relay.
type ResolverConfig struct {
	// Servers lists DNS server addresses. Empty uses the system resolver.
	Servers []string `json:"servers,omitempty"`
	// Protocol is udp, tcp, tcp-tls or https.
	Protocol string `json:"protocol,omitempty"`
	// Timeout bounds a single lookup.
	Timeout Duration `json:"timeout,omitempty"`
	// Strategy is prefer_ipv4, prefer_ipv6 or as-is.
	Strategy string `json:"strategy,omitempty"`
}

// MaskingConfig controls how the relay presents itself to unauthenticated
// probes.
//
// A relay that answers nothing is trivially identifiable as a proxy. Masking
// makes the listener behave like the site it claims to be: a TLS listener
// completes a handshake with a real certificate, an HTTP listener serves a real
// page, and everything else is forwarded to a fallback site.
type MaskingConfig struct {
	// Mode is none, tls-fallback or http-fallback.
	Mode string `json:"mode,omitempty"`
	// FallbackAddr receives traffic that fails authentication. Pointing this
	// at a real website makes probing the relay indistinguishable from probing
	// that website.
	FallbackAddr string `json:"fallbackAddr,omitempty"`
	// FallbackServerName is the SNI used when dialing FallbackAddr.
	FallbackServerName string `json:"fallbackServerName,omitempty"`
	// FallbackHTTPHost is the Host header sent to an HTTP fallback.
	FallbackHTTPHost string `json:"fallbackHTTPHost,omitempty"`
	// CertFile and KeyFile present a real certificate to probes.
	CertFile string `json:"certFile,omitempty"`
	KeyFile  string `json:"keyFile,omitempty"`
	// Sniff enables protocol sniffing so a failed TLS handshake is still
	// routed to the fallback rather than dropped.
	Sniff bool `json:"sniff,omitempty"`
}

// ClientConfig is the client side.
type ClientConfig struct {
	// DataDir stores runtime state such as health-check history.
	DataDir string `json:"dataDir,omitempty"`

	// Servers are the remote relays this client can use.
	Servers []ServerEntry `json:"servers"`

	// Tunnels are port-forwarding rules that send local traffic through a
	// relay to a fixed target.
	Tunnels []Tunnel `json:"tunnels,omitempty"`

	// Proxy configures the local SOCKS5 and HTTP proxy endpoints.
	Proxy LocalProxyConfig `json:"proxy"`

	// Health controls relay probing and automatic failover.
	Health HealthConfig `json:"health"`
}

// ServerEntry is one remote relay.
type ServerEntry struct {
	// ID is a stable identifier used by tunnels and the API.
	ID string `json:"id"`
	// Name is a human label shown in the GUI.
	Name string `json:"name,omitempty"`
	// Address is the relay endpoint, host:port.
	Address string `json:"address"`
	// Transport names the scheme used to reach this relay.
	Transport string `json:"transport"`
	// ServerName overrides the SNI/Host presented to the relay. Defaults to
	// the host part of Address.
	ServerName string `json:"serverName,omitempty"`
	// Settings holds transport-specific parameters.
	Settings map[string]any `json:"settings,omitempty"`
	// ClientID is reported to the relay for per-client policy.
	ClientID string `json:"clientId,omitempty"`
	// Enabled turns this relay on.
	Enabled bool `json:"enabled"`
	// Weight biases load balancing. Zero is treated as 1.
	Weight int `json:"weight,omitempty"`
	// Group names a failover/load-balance group. Empty means standalone.
	Group string `json:"group,omitempty"`
	// LatencyTag is free-form text describing the expected path, e.g.
	// "JP→SH→US". Shown in the GUI.
	LatencyTag string `json:"latencyTag,omitempty"`
	// Note is free-form text shown in the GUI.
	Note string `json:"note,omitempty"`
}

// Tunnel is one client-side port-forwarding rule.
type Tunnel struct {
	// Name is a stable identifier.
	Name string `json:"name"`
	// Enabled turns the tunnel on.
	Enabled bool `json:"enabled"`
	// Listen is the local bind address, e.g. 127.0.0.1:8388.
	Listen string `json:"listen"`
	// Network is tcp, udp or both.
	Network string `json:"network,omitempty"`
	// Target is the final destination the relay dials.
	Target string `json:"target"`
	// Server names a ServerEntry by ID. Empty means "any server in Group".
	Server string `json:"server,omitempty"`
	// Group selects a failover/load-balance group. Ignored when Server is set.
	Group string `json:"group,omitempty"`
	// Balance is the strategy across the group: first, round-robin, random or
	// least-latency.
	Balance string `json:"balance,omitempty"`
	// Note is free-form text shown in the GUI.
	Note string `json:"note,omitempty"`
}

// LocalProxyConfig configures the client's local proxy endpoints.
type LocalProxyConfig struct {
	// Enabled turns the local proxy on.
	Enabled bool `json:"enabled"`
	// SOCKS5Listen is the SOCKS5 bind address. Empty disables SOCKS5.
	SOCKS5Listen string `json:"socks5Listen,omitempty"`
	// HTTPListen is the HTTP proxy bind address. Empty disables HTTP.
	HTTPListen string `json:"httpListen,omitempty"`
	// Username and PasswordHash protect the local proxy. Empty allows any
	// local process, which is the default because the proxy binds to loopback.
	Username     string `json:"username,omitempty"`
	PasswordHash string `json:"passwordHash,omitempty"`
	// Server names a ServerEntry. Empty means "any server in Group".
	Server string `json:"server,omitempty"`
	// Group selects a failover/load-balance group.
	Group string `json:"group,omitempty"`
	// Balance is the strategy across the group.
	Balance string `json:"balance,omitempty"`
	// UDP enables UDP-over-TCP relay through the tunnel.
	UDP bool `json:"udp,omitempty"`
	// DirectRules lists destinations that bypass the relay and are dialed
	// directly. Entries may be exact host:port, a bare host or a ".suffix".
	DirectRules []string `json:"directRules,omitempty"`
	// ProxyRules, when non-empty, restricts relayed destinations to this list.
	ProxyRules []string `json:"proxyRules,omitempty"`
	// BlockRules lists destinations that are refused outright.
	BlockRules []string `json:"blockRules,omitempty"`
}

// HealthConfig controls relay probing and failover.
type HealthConfig struct {
	// Enabled turns periodic probing on.
	Enabled bool `json:"enabled"`
	// Interval is the delay between probes of one relay.
	Interval Duration `json:"interval,omitempty"`
	// Timeout bounds a single probe.
	Timeout Duration `json:"timeout,omitempty"`
	// Failures is how many consecutive failures retire a relay.
	Failures int `json:"failures,omitempty"`
	// Successes is how many consecutive successes bring it back.
	Successes int `json:"successes,omitempty"`
	// ProbeTarget is the address the relay is asked to reach during a probe.
	// Empty uses the relay's ping command, which measures the relay hop alone.
	ProbeTarget string `json:"probeTarget,omitempty"`
	// AutoFailover switches traffic to a healthy relay in the same group when
	// the active one fails.
	AutoFailover bool `json:"autoFailover,omitempty"`
}

// Duration is a time.Duration that marshals as a human string ("30s") so
// configs stay readable.
type Duration time.Duration

// MarshalJSON renders the duration as a string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON accepts a duration string or a bare number of seconds.
func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" || s == `""` {
		*d = 0
		return nil
	}
	if strings.HasPrefix(s, `"`) {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
		v, err := time.ParseDuration(str)
		if err != nil {
			return fmt.Errorf("config: invalid duration %q: %w", str, err)
		}
		*d = Duration(v)
		return nil
	}
	var n float64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("config: invalid duration %s", s)
	}
	*d = Duration(time.Duration(n * float64(time.Second)))
	return nil
}

// Std returns the duration as a time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// Or returns the duration, or def when it is zero.
func (d Duration) Or(def time.Duration) time.Duration {
	if d == 0 {
		return def
	}
	return time.Duration(d)
}

// Default returns a fully populated configuration for the given mode.
func Default(mode Mode) *Config {
	c := &Config{
		SchemaVersion: SchemaVersion,
		Mode:          mode,
		Log: LogConfig{
			Level:      "info",
			BufferSize: 1000,
		},
		WebUI: WebUIConfig{
			Enabled:    true,
			Listen:     "127.0.0.1:8787",
			Username:   "admin",
			SessionTTL: Duration(12 * time.Hour),
		},
	}
	if mode == ModeServer || mode == ModeBoth {
		c.Server = defaultServer()
	}
	if mode == ModeClient || mode == ModeBoth {
		c.Client = defaultClient()
	}
	return c
}

func defaultServer() *ServerConfig {
	blockPrivate := true
	return &ServerConfig{
		DataDir: "/var/lib/porttransit",
		Listeners: []Listener{
			{
				Name:      "relay-tls",
				Transport: "tls",
				Listen:    "0.0.0.0:8443",
				Enabled:   true,
				Settings: map[string]any{
					"certFile": "/etc/porttransit/certs/relay.crt",
					"keyFile":  "/etc/porttransit/certs/relay.key",
				},
			},
		},
		ACL: ACLConfig{BlockPrivate: &blockPrivate},
		Limits: LimitConfig{
			HandshakeTimeout: Duration(10 * time.Second),
			IdleTimeout:      Duration(300 * time.Second),
			DialTimeout:      Duration(10 * time.Second),
			UDPTimeout:       Duration(120 * time.Second),
			BufferSize:       32 * 1024,
		},
		Masking: MaskingConfig{Mode: "none"},
	}
}

func defaultClient() *ClientConfig {
	return &ClientConfig{
		DataDir: "/var/lib/porttransit",
		Proxy: LocalProxyConfig{
			Enabled:      true,
			SOCKS5Listen: "127.0.0.1:1080",
			HTTPListen:   "127.0.0.1:8118",
		},
		Health: HealthConfig{
			Enabled:      true,
			Interval:     Duration(30 * time.Second),
			Timeout:      Duration(5 * time.Second),
			Failures:     3,
			Successes:    2,
			AutoFailover: true,
		},
	}
}

// Load reads and validates a config file, applying defaults for absent fields.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	cfg, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes and validates a config document.
func Parse(raw []byte) (*Config, error) {
	// Decode into a fresh default so absent fields keep their defaults rather
	// than becoming zero values.
	var probe struct {
		Mode Mode `json:"mode"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if probe.Mode == "" {
		probe.Mode = ModeBoth
	}
	cfg := Default(probe.Mode)
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if cfg.Mode == "" {
		cfg.Mode = probe.Mode
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Save writes the config atomically with 0600 permissions, because it holds
// credentials.
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("config: create dir: %w", err)
	}
	buf, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("config: encode: %w", err)
	}
	buf = append(buf, '\n')

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return fmt.Errorf("config: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("config: replace %s: %w", path, err)
	}
	return nil
}

// Validate checks internal consistency and reports every problem it finds
// rather than stopping at the first one, so the GUI can show a full list.
func (c *Config) Validate() error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if c.SchemaVersion == 0 {
		c.SchemaVersion = SchemaVersion
	}
	if c.SchemaVersion > SchemaVersion {
		add("schemaVersion %d is newer than this build supports (%d)", c.SchemaVersion, SchemaVersion)
	}
	switch c.Mode {
	case ModeServer, ModeClient, ModeBoth:
	default:
		add("mode %q is not one of server, client, both", c.Mode)
	}

	if c.WebUI.Enabled {
		if c.WebUI.Listen == "" {
			add("webui.listen is empty")
		}
		if c.WebUI.Username == "" {
			add("webui.username is empty")
		}
		if !c.WebUI.AllowRemote && !isLoopbackListen(c.WebUI.Listen) {
			add("webui.listen %q is not a loopback address; set webui.allowRemote to acknowledge the exposure", c.WebUI.Listen)
		}
		if c.WebUI.AllowRemote && c.WebUI.PasswordHash == "" {
			add("webui.allowRemote is set but webui.passwordHash is empty; a remote admin console must be password protected")
		}
		if c.WebUI.TLS && c.WebUI.CertFile != "" && c.WebUI.KeyFile == "" {
			add("webui.tls is on and webui.certFile is set but webui.keyFile is empty")
		}
		if c.WebUI.TLS && c.WebUI.KeyFile != "" && c.WebUI.CertFile == "" {
			add("webui.tls is on and webui.keyFile is set but webui.certFile is empty")
		}
	}

	// Validate any section that is present, not only the ones the mode selects.
	// A config whose mode excludes a section but which still carries one is
	// exactly the case where a stale, broken section goes unnoticed and then
	// breaks the moment the operator switches mode.
	if c.Server != nil {
		problems = append(problems, validateServer(c.Server)...)
	}
	if c.Client != nil {
		problems = append(problems, validateClient(c.Client)...)
	}

	// A section the mode requires but which is absent would otherwise start a
	// process that silently does nothing.
	switch c.Mode {
	case ModeServer, ModeBoth:
		if c.Server == nil {
			add("mode is %s but server is missing", c.Mode)
		}
	case ModeClient:
		if c.Client == nil {
			add("mode is %s but client is missing", c.Mode)
		}
	}

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("config: %s", strings.Join(problems, "; "))
}

func validateServer(s *ServerConfig) []string {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if len(s.Listeners) == 0 {
		add("server.listeners is empty; a relay needs at least one inbound endpoint")
	}
	names := map[string]bool{}
	for i, l := range s.Listeners {
		where := fmt.Sprintf("server.listeners[%d]", i)
		if l.Name == "" {
			add("%s.name is empty", where)
		} else if names[l.Name] {
			add("%s.name %q is a duplicate", where, l.Name)
		} else {
			names[l.Name] = true
		}
		if l.Transport == "" {
			add("%s.transport is empty", where)
		}
		if l.Listen == "" {
			add("%s.listen is empty", where)
		}
		switch l.Network {
		case "", "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		default:
			add("%s.network %q is not a valid network", where, l.Network)
		}
		if l.Transport == "tls" || l.Transport == "reality" {
			if l.Settings == nil {
				add("%s is %s but has no settings", where, l.Transport)
			}
		}
	}

	fwdNames := map[string]bool{}
	for i, f := range s.Forwards {
		where := fmt.Sprintf("server.forwards[%d]", i)
		if f.Name == "" {
			add("%s.name is empty", where)
		} else if fwdNames[f.Name] {
			add("%s.name %q is a duplicate", where, f.Name)
		} else {
			fwdNames[f.Name] = true
		}
		if f.Listener != "" && !names[f.Listener] {
			add("%s.listener %q does not match any listener", where, f.Listener)
		}
		if f.Target == "" && len(f.AllowedTargets) == 0 {
			add("%s has neither target nor allowedTargets; the relay would be an open proxy", where)
		}
		switch f.Balance {
		case "", "first", "round-robin", "random", "least-conn", "least-latency":
		default:
			add("%s.balance %q is not a known strategy", where, f.Balance)
		}
	}

	acctIDs := map[string]bool{}
	for i, a := range s.Clients {
		where := fmt.Sprintf("server.clients[%d]", i)
		if a.ID == "" {
			add("%s.id is empty", where)
		} else if acctIDs[a.ID] {
			add("%s.id %q is a duplicate", where, a.ID)
		} else {
			acctIDs[a.ID] = true
		}
		if len(a.Credentials) == 0 {
			add("%s has no credentials; the account could never authenticate", where)
		}
		if a.RateLimitKBps < 0 {
			add("%s.rateLimitKBps is negative", where)
		}
		if a.QuotaBytes < 0 {
			add("%s.quotaBytes is negative", where)
		}
	}

	for i, p := range s.ACL.BlockPorts {
		if p < 1 || p > 65535 {
			add("server.acl.blockPorts[%d] = %d is out of range", i, p)
		}
	}
	for i, p := range s.ACL.AllowPorts {
		if p < 1 || p > 65535 {
			add("server.acl.allowPorts[%d] = %d is out of range", i, p)
		}
	}

	if s.Limits.BufferSize < 0 {
		add("server.limits.bufferSize is negative")
	}
	if s.Limits.HandshakeTimeout < 0 || s.Limits.IdleTimeout < 0 || s.Limits.DialTimeout < 0 {
		add("server.limits timeouts must not be negative")
	}

	switch s.Masking.Mode {
	case "", "none", "tls-fallback", "http-fallback":
	default:
		add("server.masking.mode %q is not none, tls-fallback or http-fallback", s.Masking.Mode)
	}
	if s.Masking.Mode == "tls-fallback" || s.Masking.Mode == "http-fallback" {
		if s.Masking.FallbackAddr == "" {
			add("server.masking.mode is %s but server.masking.fallbackAddr is empty", s.Masking.Mode)
		}
	}
	return problems
}

func validateClient(c *ClientConfig) []string {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	ids := map[string]bool{}
	for i, s := range c.Servers {
		where := fmt.Sprintf("client.servers[%d]", i)
		if s.ID == "" {
			add("%s.id is empty", where)
		} else if ids[s.ID] {
			add("%s.id %q is a duplicate", where, s.ID)
		} else {
			ids[s.ID] = true
		}
		if s.Address == "" {
			add("%s.address is empty", where)
		}
		if s.Transport == "" {
			add("%s.transport is empty", where)
		}
		if s.Weight < 0 {
			add("%s.weight is negative", where)
		}
	}

	tunnelNames := map[string]bool{}
	for i, t := range c.Tunnels {
		where := fmt.Sprintf("client.tunnels[%d]", i)
		if t.Name == "" {
			add("%s.name is empty", where)
		} else if tunnelNames[t.Name] {
			add("%s.name %q is a duplicate", where, t.Name)
		} else {
			tunnelNames[t.Name] = true
		}
		if t.Listen == "" {
			add("%s.listen is empty", where)
		}
		if t.Target == "" {
			add("%s.target is empty", where)
		}
		if t.Server != "" && !ids[t.Server] {
			add("%s.server %q does not match any server", where, t.Server)
		}
		if t.Server == "" && t.Group == "" && len(c.Servers) == 0 {
			add("%s has no server to use", where)
		}
		switch t.Balance {
		case "", "first", "round-robin", "random", "least-latency":
		default:
			add("%s.balance %q is not a known strategy", where, t.Balance)
		}
		switch t.Network {
		case "", "tcp", "udp", "both":
		default:
			add("%s.network %q is not tcp, udp or both", where, t.Network)
		}
	}

	if c.Proxy.Enabled {
		if c.Proxy.SOCKS5Listen == "" && c.Proxy.HTTPListen == "" {
			add("client.proxy is enabled but neither socks5Listen nor httpListen is set")
		}
		if c.Proxy.Server != "" && !ids[c.Proxy.Server] {
			add("client.proxy.server %q does not match any server", c.Proxy.Server)
		}
		if !isLoopbackListen(c.Proxy.SOCKS5Listen) && c.Proxy.SOCKS5Listen != "" && c.Proxy.PasswordHash == "" {
			add("client.proxy.socks5Listen %q is not loopback but no proxy password is set", c.Proxy.SOCKS5Listen)
		}
		if !isLoopbackListen(c.Proxy.HTTPListen) && c.Proxy.HTTPListen != "" && c.Proxy.PasswordHash == "" {
			add("client.proxy.httpListen %q is not loopback but no proxy password is set", c.Proxy.HTTPListen)
		}
	}

	if c.Health.Enabled {
		if c.Health.Interval <= 0 {
			add("client.health.interval must be positive when health checking is on")
		}
		if c.Health.Timeout <= 0 {
			add("client.health.timeout must be positive when health checking is on")
		}
		if c.Health.Failures < 0 || c.Health.Successes < 0 {
			add("client.health failure and success thresholds must not be negative")
		}
	}
	return problems
}

// isLoopbackListen reports whether a bind address is confined to the loopback
// interface or a unix socket.
func isLoopbackListen(addr string) bool {
	if addr == "" {
		return true
	}
	if strings.HasPrefix(addr, "/") || strings.HasPrefix(addr, "@") {
		return true // unix socket
	}
	host := addr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		host = addr[:i]
	}
	host = strings.Trim(host, "[]")
	switch host {
	case "", "localhost", "127.0.0.1", "::1":
		return true
	}
	return strings.HasPrefix(host, "127.")
}
