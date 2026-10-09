// Package socks5 implements the PortTransit SOCKS5 transport.
//
// The relay speaks ordinary SOCKS5 (RFC 1928). This is useful for chaining:
// an existing SOCKS5-capable client, or a relay that already exposes a SOCKS5
// port, can feed into PortTransit without any new protocol. It is also the
// simplest way to verify a relay is reachable before configuring a stronger
// transport.
//
// # Wire format
//
//	client → relay: 05 NMETHODS METHODS...        (greeting)
//	relay  → client: 05 METHOD
//	                 — method 0x00 no auth, or 0x02 username/password
//	client → relay: 01 VERSION USERNAME PASSWORD  (RFC 1929, when method 2)
//	relay  → client: 01 STATUS
//	client → relay: 05 CMD RSV ATYP ADDR PORT     (request)
//	relay  → client: 05 REP RSV ATYP BND.ADDR BND.PORT
//	then:           raw bidirectional bytes
//
// # Why a relay would use this
//
// The relay is normally reached over TLS or REALITY. Exposing SOCKS5 directly
// means the target address and the payload are in cleartext, so this transport
// carries the same warning as `direct` and is intended for a private hop.
package socks5

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"time"

	"porttransit/internal/logx"
	"porttransit/internal/transport"
)

// Name is the registry key.
const Name = "socks5"

// DefaultPort is the conventional listen port.
const DefaultPort = 1080

func init() {
	transport.Register(transport.Factory{
		Name:         Name,
		Description:  "Standard SOCKS5 (RFC 1928) with optional username/password. Plaintext — use on a private hop or behind another tunnel.",
		NativeHeader: true,
		DefaultPort:  DefaultPort,
		Build:        func() (transport.Dialer, transport.Handler) { return Dialer{}, Handler{} },
	})
}

// Settings keys understood by this transport.
const (
	// SettingUsername and SettingPassword enable RFC 1929 authentication on
	// the relay. When empty the relay offers the no-auth method.
	SettingUsername = "username"
	SettingPassword = "password"
	// SettingTimeout bounds the handshake.
	SettingTimeout = "timeout"
)

// Protocol constants.
const (
	version5 = 0x05

	methodNoAuth   = 0x00
	methodUserPass = 0x02
	methodNone     = 0xFF

	authVersion = 0x01
	authOK      = 0x00
	authFail    = 0x01

	cmdConnect = 0x01
	cmdUDP     = 0x03

	replySuccess         = 0x00
	replyGeneralFailure  = 0x01
	replyHostUnreachable = 0x04
	replyCommandNotSupp  = 0x07
	replyAddrTypeNotSupp = 0x08
	replyAuthRequired    = 0x02
)

// Dialer establishes client→relay SOCKS5 streams.
type Dialer struct{}

// Name returns the registry key.
func (Dialer) Name() string { return Name }

// Dial performs the SOCKS5 handshake and issues a CONNECT or UDP ASSOCIATE.
func (d Dialer) Dial(ctx context.Context, req transport.DialRequest) (transport.Stream, error) {
	timeout := req.Settings.GetDuration(SettingTimeout, 10*time.Second)
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	conn, err := (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", req.ServerAddr)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, err
	}

	username := req.Settings.GetString(SettingUsername, "")
	password := req.Settings.GetString(SettingPassword, "")

	if err := clientGreeting(conn, username != ""); err != nil {
		conn.Close()
		return nil, err
	}
	if username != "" {
		if err := clientAuth(conn, username, password); err != nil {
			conn.Close()
			return nil, err
		}
	}

	command := byte(cmdConnect)
	if req.Request != nil && req.Request.Command == transport.CmdUDPAssociate {
		command = cmdUDP
	}
	target := ""
	if req.Request != nil {
		target = req.Request.Target
	}
	if req.Request == nil || req.Request.Command == transport.CmdPing || target == "" {
		// A ping is a CONNECT to the relay's own SOCKS5 port: the relay
		// accepts, reports success, and the client closes immediately. That
		// measures the full handshake without dialing anything external.
		target = req.ServerAddr
		command = cmdConnect
		req.Request = &transport.Request{
			Command:   transport.CmdConnectTCP,
			Target:    target,
			Transport: Name,
			Meta:      map[string]string{"ping": "true"},
		}
	}

	if err := clientRequest(conn, command, target); err != nil {
		conn.Close()
		return nil, err
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return transport.NewStream(conn, req.Request, Name, 0), nil
}

// Handler accepts relay-side SOCKS5 streams.
type Handler struct{}

// Name returns the registry key.
func (Handler) Name() string { return Name }

// Handle performs the server side of the SOCKS5 handshake.
func (h Handler) Handle(ctx context.Context, raw net.Conn, req transport.HandleRequest) (transport.Stream, error) {
	timeout := req.Settings.GetDuration(SettingTimeout, 10*time.Second)
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
		raw.Close()
		return nil, err
	}

	username := req.Settings.GetString(SettingUsername, "")
	password := req.Settings.GetString(SettingPassword, "")

	if err := serverGreeting(raw, username != ""); err != nil {
		raw.Close()
		return nil, err
	}
	if username != "" {
		if err := serverAuth(raw, username, password); err != nil {
			raw.Close()
			loggerFor(req.Logger).Warn("socks5: authentication failed", "remote", transport.RemoteAddrString(raw))
			return nil, err
		}
	}

	command, target, err := serverRequest(raw)
	if err != nil {
		raw.Close()
		return nil, err
	}

	reqCommand := transport.CmdConnectTCP
	if command == cmdUDP {
		reqCommand = transport.CmdUDPAssociate
	}

	// The success reply is written by the caller only after the target is
	// actually connected, because a SOCKS5 client treats replySuccess as
	// "the target is reachable". Reporting success before dialing would make
	// the client misattribute a dial failure to the application.
	if err := raw.SetDeadline(time.Time{}); err != nil {
		raw.Close()
		return nil, err
	}

	streamReq := &transport.Request{
		Command:   reqCommand,
		Target:    target,
		Transport: Name,
	}
	return transport.NewStream(raw, streamReq, Name, 0), nil
}

// WriteSuccessReply writes the SOCKS5 success reply. The relay calls it once
// the upstream connection is established.
func WriteSuccessReply(w io.Writer) error {
	// BND.ADDR/BND.PORT are zeroed: the client does not use them for CONNECT,
	// and reporting the relay's real address would leak its topology.
	reply := []byte{version5, replySuccess, 0x00, transport.AddrTypeIPv4, 0, 0, 0, 0, 0, 0}
	_, err := w.Write(reply)
	return err
}

// WriteFailureReply writes a SOCKS5 failure reply with the given reply code.
func WriteFailureReply(w io.Writer, code byte) error {
	reply := []byte{version5, code, 0x00, transport.AddrTypeIPv4, 0, 0, 0, 0, 0, 0}
	_, err := w.Write(reply)
	return err
}

func clientGreeting(conn net.Conn, withAuth bool) error {
	methods := []byte{methodNoAuth}
	if withAuth {
		methods = []byte{methodUserPass}
	}
	buf := append([]byte{version5, byte(len(methods))}, methods...)
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("socks5: write greeting: %w", err)
	}

	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("socks5: read greeting reply: %w", err)
	}
	if resp[0] != version5 {
		return fmt.Errorf("%w: socks5 server replied version 0x%02x", transport.ErrProtocol, resp[0])
	}
	if resp[1] == methodNone {
		return fmt.Errorf("%w: socks5 server rejected every offered method", transport.ErrAuthFailed)
	}
	if withAuth && resp[1] != methodUserPass {
		return fmt.Errorf("%w: socks5 server chose method 0x%02x, expected username/password", transport.ErrAuthFailed, resp[1])
	}
	if !withAuth && resp[1] != methodNoAuth {
		return fmt.Errorf("%w: socks5 server requires authentication", transport.ErrAuthFailed)
	}
	return nil
}

func clientAuth(conn net.Conn, username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return fmt.Errorf("%w: socks5 username or password exceeds 255 bytes", transport.ErrProtocol)
	}
	buf := make([]byte, 0, 3+len(username)+len(password))
	buf = append(buf, authVersion, byte(len(username)))
	buf = append(buf, username...)
	buf = append(buf, byte(len(password)))
	buf = append(buf, password...)

	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("socks5: write auth: %w", err)
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("socks5: read auth reply: %w", err)
	}
	if resp[1] != authOK {
		return fmt.Errorf("%w: socks5 username or password rejected", transport.ErrAuthFailed)
	}
	return nil
}

func clientRequest(conn net.Conn, command byte, target string) error {
	buf := []byte{version5, command, 0x00}
	var err error
	buf, err = transport.EncodeAddr(buf, target)
	if err != nil {
		return err
	}
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("socks5: write request: %w", err)
	}

	var head [3]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return fmt.Errorf("socks5: read reply: %w", err)
	}
	if head[0] != version5 {
		return fmt.Errorf("%w: socks5 reply version 0x%02x", transport.ErrProtocol, head[0])
	}
	if head[1] != replySuccess {
		return fmt.Errorf("socks5: relay refused the request: %s", replyText(head[1]))
	}
	// Consume the bound address so the stream starts at the payload. Only the
	// version, reply and reserved bytes were consumed above: the address type
	// is the next byte and belongs to DecodeAddr, so reading four bytes here
	// would swallow it and leave DecodeAddr reading the address from one byte
	// too late.
	if _, err := transport.DecodeAddr(conn); err != nil {
		return fmt.Errorf("socks5: read bound address: %w", err)
	}
	return nil
}

func serverGreeting(conn net.Conn, requireAuth bool) error {
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return err
	}
	if head[0] != version5 {
		return fmt.Errorf("%w: socks5 client sent version 0x%02x", transport.ErrProtocol, head[0])
	}
	n := int(head[1])
	if n == 0 {
		return fmt.Errorf("%w: socks5 client offered no methods", transport.ErrProtocol)
	}
	methods := make([]byte, n)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	want := byte(methodNoAuth)
	if requireAuth {
		want = methodUserPass
	}
	for _, m := range methods {
		if m == want {
			if _, err := conn.Write([]byte{version5, want}); err != nil {
				return err
			}
			return nil
		}
	}
	// No acceptable method: RFC 1928 requires the 0xFF reply before closing.
	_, _ = conn.Write([]byte{version5, methodNone})
	return fmt.Errorf("%w: socks5 client did not offer the required method", transport.ErrAuthFailed)
}

func serverAuth(conn net.Conn, username, password string) error {
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return err
	}
	if head[0] != authVersion {
		return fmt.Errorf("%w: socks5 auth version 0x%02x", transport.ErrProtocol, head[0])
	}
	user := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}
	var plen [1]byte
	if _, err := io.ReadFull(conn, plen[:]); err != nil {
		return err
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}

	okUser := subtle.ConstantTimeCompare(user, []byte(username)) == 1
	okPass := subtle.ConstantTimeCompare(pass, []byte(password)) == 1
	if !okUser || !okPass {
		_, _ = conn.Write([]byte{authVersion, authFail})
		return fmt.Errorf("%w: socks5 bad credentials", transport.ErrAuthFailed)
	}
	_, err := conn.Write([]byte{authVersion, authOK})
	return err
}

func serverRequest(conn net.Conn) (byte, string, error) {
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return 0, "", err
	}
	if head[0] != version5 {
		return 0, "", fmt.Errorf("%w: socks5 request version 0x%02x", transport.ErrProtocol, head[0])
	}
	command := head[1]
	if command != cmdConnect && command != cmdUDP {
		_ = WriteFailureReply(conn, replyCommandNotSupp)
		return 0, "", fmt.Errorf("%w: socks5 command 0x%02x is not supported", transport.ErrProtocol, command)
	}
	if head[2] != 0x00 {
		return 0, "", fmt.Errorf("%w: socks5 reserved byte is 0x%02x", transport.ErrProtocol, head[2])
	}

	// head[3] is the address type, but DecodeAddr re-reads it, so the reader is
	// primed with that byte before continuing with the live connection.
	target, err := transport.DecodeAddr(io.MultiReader(newOneShotReader(head[3]), conn))
	if err != nil {
		_ = WriteFailureReply(conn, replyAddrTypeNotSupp)
		return 0, "", err
	}
	return command, target, nil
}

// oneShotReader yields its byte exactly once and then reports EOF, so the
// caller's io.MultiReader moves on to the real connection.
type oneShotReader struct {
	b   byte
	got bool
}

func newOneShotReader(b byte) *oneShotReader { return &oneShotReader{b: b} }

func (r *oneShotReader) Read(p []byte) (int, error) {
	if r.got || len(p) == 0 {
		return 0, io.EOF
	}
	r.got = true
	p[0] = r.b
	return 1, nil
}

func replyText(code byte) string {
	switch code {
	case replySuccess:
		return "succeeded"
	case replyGeneralFailure:
		return "general SOCKS server failure"
	case replyAuthRequired:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case replyHostUnreachable:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case replyCommandNotSupp:
		return "command not supported"
	case replyAddrTypeNotSupp:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown reply 0x%02x", code)
	}
}

// loggerFor adapts the shared logger to the transport package's minimal
// interface.
//
// It returns an explicit no-op rather than nil: a nil interface panics on the
// first method call, and the transports log from inside handshake paths where
// a panic would take down the whole relay.
func loggerFor(l *logx.Logger) transport.Logger {
	if l == nil {
		return transport.NopLogger()
	}
	return l
}
