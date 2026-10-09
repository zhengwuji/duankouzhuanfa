// Package transport defines the pluggable relay-transport contract used by
// every PortTransit component.
//
// # Topology
//
//	local app ──▶ client ──[ transport ]──▶ relay server ──▶ final target
//	                        (encrypted)      (中转线路)
//
// The client opens a *stream* to the relay using one of the registered
// transports. The stream carries the identity of the final target; the relay
// decodes it, dials the target, and pipes bytes in both directions.
//
// # Two families of transports
//
// Native-header transports (vless, vmess, trojan, shadowsocks) carry the target
// address inside their own wire protocol. Simple transports (direct, tls,
// reality, ws, socks5, http) complete their handshake first and then exchange a
// PortTransit preamble (see preamble.go) that carries the target.
//
// Both families surface the same Stream interface, so the relay and the client
// never branch on the transport family.
package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"porttransit/internal/logx"
)

// Command enumerates what a client asks the relay to do for one stream.
type Command uint8

const (
	// CmdConnectTCP asks the relay to open a TCP connection to Target.
	CmdConnectTCP Command = 0x01
	// CmdUDPAssociate asks the relay to relay UDP datagrams for Target.
	CmdUDPAssociate Command = 0x02
	// CmdPing is a liveness probe: the relay answers and closes without
	// dialing anything. Used by health checks and the Web GUI latency test.
	CmdPing Command = 0x03
)

// String renders the command for logs and API payloads.
func (c Command) String() string {
	switch c {
	case CmdConnectTCP:
		return "tcp"
	case CmdUDPAssociate:
		return "udp"
	case CmdPing:
		return "ping"
	default:
		return fmt.Sprintf("unknown(0x%02x)", uint8(c))
	}
}

// Valid reports whether the command byte is one this build understands.
func (c Command) Valid() bool {
	switch c {
	case CmdConnectTCP, CmdUDPAssociate, CmdPing:
		return true
	}
	return false
}

// Request is the decoded intent behind one stream.
type Request struct {
	// Command is the operation the client requested.
	Command Command `json:"command"`
	// Target is the final destination in host:port form. Empty for CmdPing.
	Target string `json:"target"`
	// Transport names the scheme that carried this request, e.g. "vless".
	Transport string `json:"transport"`
	// ClientID optionally identifies the client. Native-header transports fill
	// it from the credential they authenticated with; simple transports leave
	// it empty unless the preamble carried one.
	ClientID string `json:"clientId,omitempty"`
	// Meta carries transport-specific extras (SNI, flow, network, ...).
	Meta map[string]string `json:"meta,omitempty"`
}

// Clone returns a deep copy so callers can safely mutate the result.
func (r *Request) Clone() *Request {
	if r == nil {
		return nil
	}
	out := *r
	if r.Meta != nil {
		out.Meta = make(map[string]string, len(r.Meta))
		for k, v := range r.Meta {
			out.Meta[k] = v
		}
	}
	return &out
}

// Stream is an established tunnel to the relay. Bytes written are delivered to
// the relay's side of the tunnel and vice versa.
type Stream interface {
	net.Conn
	// Request returns what the peer asked for. Never nil on a healthy stream.
	Request() *Request
	// TransportName returns the scheme that established this stream.
	TransportName() string
	// Latency reports the round-trip time measured during the handshake, when
	// the transport can measure one. Zero means "not measured".
	Latency() time.Duration
}

// baseStream is the shared implementation embedded by concrete streams.
type baseStream struct {
	net.Conn
	req  *Request
	name string
	rtt  time.Duration
}

func (b *baseStream) Request() *Request      { return b.req }
func (b *baseStream) TransportName() string  { return b.name }
func (b *baseStream) Latency() time.Duration { return b.rtt }

// CloseWrite forwards a half-close to the underlying connection when it
// supports one.
//
// This cannot be left to the embedded net.Conn: that field is the net.Conn
// *interface*, whose method set has no CloseWrite, so the method would simply
// not exist on the wrapper. Every caller that tests for
// interface{ CloseWrite() error } — the relay's copy loop and the client's
// pipe — would then silently take the "not supported" branch, and a half-close
// would never reach the peer. The symptom is not a visible error but a
// connection that lingers until its idle timeout, because neither side can
// tell that the other has finished writing.
func (b *baseStream) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// CloseRead forwards a half-close of the read side, with the same reasoning as
// CloseWrite.
func (b *baseStream) CloseRead() error {
	if cr, ok := b.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

// NewStream wraps conn so it satisfies Stream. Transports that need extra
// behaviour define their own type instead.
func NewStream(conn net.Conn, req *Request, name string, rtt time.Duration) Stream {
	return &baseStream{Conn: conn, req: req, name: name, rtt: rtt}
}

// DialRequest is the client-side input to Dialer.Dial.
type DialRequest struct {
	// ServerAddr is the relay endpoint, host:port.
	ServerAddr string
	// ServerName is the TLS SNI / HTTP Host / WebSocket host to present. It
	// defaults to the host part of ServerAddr when empty.
	ServerName string
	// Request is the intent to convey to the relay.
	Request *Request
	// Timeout bounds the whole handshake. Zero means the context governs.
	Timeout time.Duration
	// Logger receives handshake diagnostics. May be nil.
	Logger *logx.Logger
	// Settings holds transport-specific configuration (password, uuid, sni,
	// path, network, ...). Keys are transport-defined.
	Settings Settings
}

// HandleRequest is the server-side input to Handler.Handle.
type HandleRequest struct {
	// Timeout bounds the handshake read. Zero means no extra deadline.
	Timeout time.Duration
	// Logger receives handshake diagnostics. May be nil.
	Logger *logx.Logger
	// Settings holds the relay's configured parameters for this transport.
	Settings Settings
}

// Dialer establishes client→relay streams for one transport scheme.
type Dialer interface {
	// Name is the registry key, e.g. "vless".
	Name() string
	// Dial performs the handshake and returns a ready stream.
	Dial(ctx context.Context, req DialRequest) (Stream, error)
}

// Handler decodes client→relay streams for one transport scheme.
type Handler interface {
	// Name is the registry key, matching the Dialer of the same scheme.
	Name() string
	// Handle performs the handshake on an already-accepted TCP connection and
	// returns a ready stream whose Request names the final target.
	//
	// Handle owns raw: on error it must close raw; on success the returned
	// Stream owns it.
	Handle(ctx context.Context, raw net.Conn, req HandleRequest) (Stream, error)
}

// Settings is a string-keyed configuration bag. Transports document which keys
// they read; unknown keys are ignored so a config written for a newer build
// still loads.
type Settings map[string]any

// GetString returns the value at key as a string, or def when absent or not a
// string.
func (s Settings) GetString(key, def string) string {
	if s == nil {
		return def
	}
	v, ok := s[key]
	if !ok || v == nil {
		return def
	}
	switch t := v.(type) {
	case string:
		if t == "" {
			return def
		}
		return t
	case fmt.Stringer:
		return t.String()
	default:
		return fmt.Sprint(v)
	}
}

// GetBool returns the value at key as a bool, or def when absent or not a bool.
func (s Settings) GetBool(key string, def bool) bool {
	if s == nil {
		return def
	}
	v, ok := s[key]
	if !ok || v == nil {
		return def
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		switch t {
		case "1", "true", "TRUE", "yes", "on":
			return true
		case "0", "false", "FALSE", "no", "off":
			return false
		}
	}
	return def
}

// GetInt returns the value at key as an int, or def when absent or unparsable.
func (s Settings) GetInt(key string, def int) int {
	if s == nil {
		return def
	}
	v, ok := s[key]
	if !ok || v == nil {
		return def
	}
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		var n int
		if _, err := fmt.Sscanf(t, "%d", &n); err == nil {
			return n
		}
	}
	return def
}

// GetStringSlice returns the value at key as a []string. A bare string is
// promoted to a one-element slice so configs can be written either way.
func (s Settings) GetStringSlice(key string) []string {
	if s == nil {
		return nil
	}
	v, ok := s[key]
	if !ok || v == nil {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, fmt.Sprint(e))
		}
		return out
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	}
	return nil
}

// GetDuration returns the value at key as a duration. Bare numbers are read as
// seconds; strings accept Go duration syntax ("30s", "5m").
func (s Settings) GetDuration(key string, def time.Duration) time.Duration {
	if s == nil {
		return def
	}
	v, ok := s[key]
	if !ok || v == nil {
		return def
	}
	switch t := v.(type) {
	case time.Duration:
		return t
	case int:
		return time.Duration(t) * time.Second
	case int64:
		return time.Duration(t) * time.Second
	case float64:
		return time.Duration(t * float64(time.Second))
	case string:
		if t == "" {
			return def
		}
		if d, err := time.ParseDuration(t); err == nil {
			return d
		}
		var n int
		if _, err := fmt.Sscanf(t, "%d", &n); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	return def
}

// Sentinel errors shared across transports so callers can classify failures
// without string matching.
var (
	// ErrUnsupportedTransport means no dialer/handler is registered under the
	// requested name.
	ErrUnsupportedTransport = errors.New("transport: unsupported scheme")
	// ErrAuthFailed means the client presented credentials the relay rejected.
	ErrAuthFailed = errors.New("transport: authentication failed")
	// ErrProtocol means the peer sent a frame that violates the wire format.
	ErrProtocol = errors.New("transport: protocol violation")
	// ErrNotImplemented means the scheme is registered but this build lacks the
	// implementation.
	ErrNotImplemented = errors.New("transport: not implemented in this build")
	// ErrClosed means the stream was closed before the handshake completed.
	ErrClosed = errors.New("transport: stream closed")
)

// Factory builds a Dialer/Handler pair for one transport scheme from settings.
// Most schemes share one struct implementing both interfaces, so the two
// returned values are frequently the same pointer.
type Factory struct {
	// Name is the registry key. It must match Dialer.Name().
	Name string
	// Description is shown in the Web GUI protocol picker.
	Description string
	// NativeHeader reports whether the scheme carries the target address in
	// its own wire header. It drives GUI hints only.
	NativeHeader bool
	// DefaultPort is the conventional listen port, used by GUI defaults.
	DefaultPort int
	// Build constructs the dialer and handler. It may return nil for either
	// side when the build only supports one direction.
	Build func() (Dialer, Handler)
}

var (
	regMu    sync.RWMutex
	registry = map[string]Factory{}
)

// Register adds a transport factory to the global registry. It panics on a
// duplicate or malformed registration because that is a programming error
// caught at init time.
func Register(f Factory) {
	if f.Name == "" || f.Build == nil {
		panic("transport: Register requires Name and Build")
	}
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := registry[f.Name]; dup {
		panic("transport: duplicate registration for " + f.Name)
	}
	registry[f.Name] = f
}

// Lookup returns the factory registered under name.
func Lookup(name string) (Factory, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	f, ok := registry[name]
	return f, ok
}

// NewDialer builds the client side of the named transport.
func NewDialer(name string) (Dialer, error) {
	f, ok := Lookup(name)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedTransport, name)
	}
	d, _ := f.Build()
	if d == nil {
		return nil, fmt.Errorf("%w: %q has no dialer", ErrNotImplemented, name)
	}
	return d, nil
}

// NewHandler builds the server side of the named transport.
func NewHandler(name string) (Handler, error) {
	f, ok := Lookup(name)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedTransport, name)
	}
	_, h := f.Build()
	if h == nil {
		return nil, fmt.Errorf("%w: %q has no handler", ErrNotImplemented, name)
	}
	return h, nil
}

// Names lists every registered transport scheme in sorted order.
func Names() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Descriptors lists the registered transports with their GUI metadata.
func Descriptors() []Factory {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]Factory, 0, len(registry))
	for _, f := range registry {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
