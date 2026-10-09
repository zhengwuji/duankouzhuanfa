// Package trojan implements the Trojan protocol.
//
// Trojan's whole design premise is that the relay should be indistinguishable
// from an HTTPS server. A client connects with a real TLS handshake, and the
// only thing that marks the connection as a proxy is a password hash sent as
// the first bytes inside the encrypted stream. A probe that completes the TLS
// handshake but sends an HTTP request instead is forwarded to a real website,
// so the relay answers exactly like the site it is imitating.
//
// # Wire format (client → relay)
//
//	hex(SHA224(password))   56 bytes ASCII
//	CRLF                    2 bytes
//	command                 1 byte  (0x01 CONNECT, 0x03 UDP ASSOCIATE)
//	address                 SOCKS5 encoding (type, addr, port)
//	CRLF                    2 bytes
//	payload                 raw bytes
//
// The relay sends no acknowledgement: data flows as soon as the target is
// connected. A failure is signalled by closing the connection, which is why
// Trojan clients must not wait for a response byte.
//
// # Fallback
//
// Any connection whose first 56 bytes are not a valid password hash is piped
// verbatim to the configured fallback site. That is the entire camouflage
// mechanism, and it is why a Trojan relay needs a real certificate and a real
// website to forward to.
package trojan

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"porttransit/internal/logx"
	"porttransit/internal/transport"
)

// Name is the registry key.
const Name = "trojan"

// DefaultPort is the conventional listen port.
const DefaultPort = 443

func init() {
	transport.Register(transport.Factory{
		Name:         Name,
		Description:  "Trojan: TLS with a password hash in the stream. Indistinguishable from HTTPS, with automatic fallback to a real website.",
		NativeHeader: true,
		DefaultPort:  DefaultPort,
		Build:        func() (transport.Dialer, transport.Handler) { return Dialer{}, Handler{} },
	})
}

// Settings keys understood by this transport.
const (
	// SettingPassword is the shared password.
	SettingPassword = "password"
	// SettingServerName overrides the SNI.
	SettingServerName = "serverName"
	// SettingInsecureSkipVerify accepts any server certificate.
	SettingInsecureSkipVerify = "insecure"
	// SettingCertFingerprint pins the SHA-256 fingerprint of the relay's leaf
	// certificate. It replaces insecure: true for a self-signed relay and takes
	// precedence over it when both are set.
	SettingCertFingerprint = "certFingerprint"
	// SettingCertFile and SettingKeyFile give the relay its certificate.
	SettingCertFile = "certFile"
	SettingKeyFile  = "keyFile"
	// SettingFallbackAddr is where unauthenticated traffic is forwarded. A
	// Trojan relay without a fallback answers nothing and is trivially
	// identifiable.
	SettingFallbackAddr = "fallbackAddr"
	// SettingFallbackSNI is the SNI used when dialing the fallback.
	SettingFallbackSNI = "fallbackServerName"
	// SettingTimeout bounds the handshake.
	SettingTimeout = "timeout"
	// SettingMinVersion pins the minimum TLS version.
	SettingMinVersion = "minVersion"
)

// hashLen is the length of the ASCII password hash that opens every Trojan
// connection: SHA-224 renders as 56 hex characters.
const hashLen = 56

// commandConnect and commandUDP mirror Trojan's command byte values.
const (
	commandConnect = 0x01
	commandUDP     = 0x03
)

// PasswordHash returns the ASCII form of hex(SHA224(password)), which is what
// goes on the wire.
//
// SHA-224 is used because that is what Trojan specifies. It is not a password
// KDF: the security of the scheme rests on the TLS layer, and the hash exists
// only so the plaintext password never appears on the wire.
func PasswordHash(password string) string {
	sum := sha256.Sum224([]byte(password))
	return hex.EncodeToString(sum[:])
}

// Dialer establishes client→relay Trojan streams.
type Dialer struct{}

// Name returns the registry key.
func (Dialer) Name() string { return Name }

// Dial performs the TLS handshake and writes the Trojan header.
func (d Dialer) Dial(ctx context.Context, req transport.DialRequest) (transport.Stream, error) {
	timeout := req.Settings.GetDuration(SettingTimeout, 10*time.Second)
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	password := req.Settings.GetString(SettingPassword, "")
	if password == "" {
		return nil, fmt.Errorf("trojan: %s is required", SettingPassword)
	}

	host, _, err := transport.SplitHostPort(req.ServerAddr)
	if err != nil {
		return nil, err
	}
	sni := req.ServerName
	if sni == "" {
		sni = req.Settings.GetString(SettingServerName, host)
	}

	// The pin is resolved before the socket is used so a mistyped fingerprint is
	// reported as a configuration error rather than as a certificate mismatch
	// from a relay that was never at fault.
	certPolicy, err := transport.ResolveClientCertPolicy(req.Settings, SettingCertFingerprint,
		req.Settings.GetBool(SettingInsecureSkipVerify, true))
	if err != nil {
		return nil, err
	}

	raw, err := (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", req.ServerAddr)
	if err != nil {
		return nil, err
	}
	if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
		raw.Close()
		return nil, err
	}

	cfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: certPolicy.InsecureSkipVerify,
		MinVersion:         minVersion(req.Settings.GetString(SettingMinVersion, "1.2")),
		NextProtos:         []string{"h2", "http/1.1"},
	}
	cfg.VerifyConnection = certPolicy.VerifyConnection()
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("trojan: TLS handshake with %s: %w", req.ServerAddr, err)
	}

	cmd := byte(commandConnect)
	if req.Request != nil && req.Request.Command == transport.CmdUDPAssociate {
		cmd = commandUDP
	}
	if req.Request == nil || req.Request.Command == transport.CmdPing {
		// Trojan has no ping command. A CONNECT to a discard port would still
		// dial on the relay, so the probe is expressed as a TCP connect to the
		// relay's own address, which the relay accepts and closes. That keeps
		// the liveness check honest: it measures the full TLS round trip.
		cmd = commandConnect
		req.Request = &transport.Request{
			Command:   transport.CmdConnectTCP,
			Target:    req.ServerAddr,
			Transport: Name,
			Meta:      map[string]string{"ping": "true"},
		}
	}

	header := make([]byte, 0, hashLen+2+1+262+2)
	header = append(header, PasswordHash(password)...)
	header = append(header, '\r', '\n')
	header = append(header, cmd)
	var encErr error
	header, encErr = transport.EncodeAddr(header, req.Request.Target)
	if encErr != nil {
		tc.Close()
		return nil, encErr
	}
	header = append(header, '\r', '\n')

	if _, err := tc.Write(header); err != nil {
		tc.Close()
		return nil, fmt.Errorf("trojan: write header: %w", err)
	}
	if err := tc.SetDeadline(time.Time{}); err != nil {
		tc.Close()
		return nil, err
	}

	return transport.NewStream(tc, req.Request, Name, 0), nil
}

// Handler accepts relay-side Trojan streams.
type Handler struct{}

// Name returns the registry key.
func (Handler) Name() string { return Name }

// Handle reads the Trojan header from an accepted TLS connection.
//
// When the password does not match, Handle does not simply close: it pipes the
// connection to the configured fallback, which is what makes the relay look
// like the website it claims to be. The returned error is ErrFallbackHandled
// so the caller knows the connection was consumed rather than dropped.
func (h Handler) Handle(ctx context.Context, raw net.Conn, req transport.HandleRequest) (transport.Stream, error) {
	timeout := req.Settings.GetDuration(SettingTimeout, 10*time.Second)
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	password := req.Settings.GetString(SettingPassword, "")
	if password == "" {
		raw.Close()
		return nil, fmt.Errorf("trojan: %s is required", SettingPassword)
	}

	cert, err := loadCert(req.Settings)
	if err != nil {
		raw.Close()
		return nil, err
	}

	// Report the fingerprint once so an operator can copy it into a client's
	// certFingerprint setting instead of reaching for insecure: true.
	transport.LogCertificateFingerprint(loggerFor(req.Logger), cert)

	if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
		raw.Close()
		return nil, err
	}

	tc := tls.Server(raw, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersion(req.Settings.GetString(SettingMinVersion, "1.2")),
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		loggerFor(req.Logger).Debug("trojan: TLS handshake failed", "remote", transport.RemoteAddrString(raw), "err", err)
		return nil, err
	}

	// Read the fixed-length password hash and the trailing CRLF. Reading
	// exactly hashLen bytes is what makes the fallback possible: an HTTP
	// request is shorter than 56 bytes, so a short read is itself the signal
	// to fall back rather than an error.
	head := make([]byte, hashLen+2)
	n, err := io.ReadFull(tc, head)
	if err != nil {
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return h.fallback(ctx, tc, req, head[:n])
		}
		tc.Close()
		return nil, err
	}

	want := PasswordHash(password)
	if subtle.ConstantTimeCompare(head[:hashLen], []byte(want)) != 1 || head[hashLen] != '\r' || head[hashLen+1] != '\n' {
		return h.fallback(ctx, tc, req, head)
	}

	var cmd [1]byte
	if _, err := io.ReadFull(tc, cmd[:]); err != nil {
		tc.Close()
		return nil, err
	}

	target, err := transport.DecodeAddr(tc)
	if err != nil {
		tc.Close()
		return nil, err
	}

	var crlf [2]byte
	if _, err := io.ReadFull(tc, crlf[:]); err != nil {
		tc.Close()
		return nil, err
	}
	if crlf[0] != '\r' || crlf[1] != '\n' {
		tc.Close()
		return nil, fmt.Errorf("%w: trojan header missing trailing CRLF", transport.ErrProtocol)
	}

	command := transport.CmdConnectTCP
	if cmd[0] == commandUDP {
		command = transport.CmdUDPAssociate
	}

	if err := tc.SetDeadline(time.Time{}); err != nil {
		tc.Close()
		return nil, err
	}

	streamReq := &transport.Request{
		Command:   command,
		Target:    target,
		Transport: Name,
	}
	return transport.NewStream(tc, streamReq, Name, 0), nil
}

// fallback pipes the connection to the configured fallback site.
//
// prelude holds bytes already read from the client that must be replayed to
// the fallback, because they are the beginning of its request.
func (h Handler) fallback(ctx context.Context, tc net.Conn, req transport.HandleRequest, prelude []byte) (transport.Stream, error) {
	addr := req.Settings.GetString(SettingFallbackAddr, "")
	if addr == "" {
		// Without a fallback the relay cannot pretend to be anything, so the
		// only safe action is to close. Returning the auth error keeps the
		// failure visible in the relay's counters.
		tc.Close()
		return nil, fmt.Errorf("%w: trojan password mismatch and no fallback configured", transport.ErrAuthFailed)
	}

	timeout := req.Settings.GetDuration("fallbackTimeout", 10*time.Second)
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	upstream, err := (&net.Dialer{Timeout: timeout}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		tc.Close()
		loggerFor(req.Logger).Debug("trojan: fallback dial failed", "addr", addr, "err", err)
		return nil, err
	}

	if len(prelude) > 0 {
		if _, err := upstream.Write(prelude); err != nil {
			upstream.Close()
			tc.Close()
			return nil, err
		}
	}

	transport.CopyBidirectional(tc, upstream)
	return nil, ErrFallbackHandled
}

// ErrFallbackHandled reports that a connection failed authentication and was
// forwarded to the fallback site instead. It is not a failure: the relay did
// exactly what it was configured to do.
var ErrFallbackHandled = fmt.Errorf("trojan: connection forwarded to fallback")

func loadCert(s transport.Settings) (tls.Certificate, error) {
	certFile := s.GetString(SettingCertFile, "")
	keyFile := s.GetString(SettingKeyFile, "")

	// When no explicit pair is configured, fall back to a pair kept beside the
	// data directory so a restart does not change the fingerprint.
	if certFile == "" && keyFile == "" {
		if dir := s.GetString("dataDir", ""); dir != "" {
			c := dir + "/certs/relay.crt"
			k := dir + "/certs/relay.key"
			if fileExists(c) && fileExists(k) {
				certFile, keyFile = c, k
			}
		}
	}

	return transport.LoadOrGenerateCertificate(certFile, keyFile, transport.SelfSignedOptions{
		CommonName: s.GetString("certCommonName", "porttransit-relay"),
		DNSNames:   s.GetStringSlice("certNames"),
	})
}

// fileExists reports whether p names an existing regular file.
func fileExists(p string) bool {
	if p == "" {
		return false
	}
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func minVersion(s string) uint16 {
	switch strings.TrimSpace(s) {
	case "1.3", "tls1.3", "TLS1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
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
