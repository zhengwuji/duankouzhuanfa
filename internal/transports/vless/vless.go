// Package vless implements the VLESS protocol with optional XTLS-Vision flow
// control.
//
// VLESS is deliberately minimal: it provides authentication and target
// addressing and nothing else, on the theory that the outer transport (TLS,
// REALITY, WebSocket) already provides confidentiality. It has no encryption
// of its own, which is why a VLESS listener is only ever deployed behind TLS
// or REALITY.
//
// # Request header (client → relay)
//
//	offset  size  field
//	0       1     version (0)
//	1       16    uuid
//	17      1     addon length
//	18      n     addons (protoBuf-ish; see encodeAddons)
//	18+n    1     command: 1 TCP, 2 UDP, 3 MUX
//	19+n    2     port, big endian
//	21+n    1     address type: 1 IPv4, 2 domain, 3 IPv6
//	22+n    m     address
//
// Note the address type values differ from SOCKS5: VLESS numbers them 1/2/3 in
// the order IPv4, domain, IPv6, whereas SOCKS5 uses 1/3/4. Mixing the two up is
// the single most common VLESS implementation bug.
//
// # Response header (relay → client)
//
//	offset  size  field
//	0       1     version (0)
//	1       1     addon length
//	2       n     addons
//
// The relay sends this immediately after connecting to the target. A client
// that waits for it before sending payload avoids a race where the target's
// first response arrives before the client's request.
//
// # Vision flow (xtls-rprx-vision)
//
// Vision removes the TLS-in-TLS overhead that makes a proxy detectable by
// traffic analysis. In the uplink the client sends the VLESS header, then a
// padded region, then the raw payload:
//
//	[VLESS header][padding length(2)][padding][payload]
//
// In the downlink the relay mirrors it:
//
//	[VLESS response header][padding length(2)][padding][payload]
//
// The padding length is big-endian and bounded by maxPadding. Padding bytes
// are random. This build implements the padding framing so it interoperates
// with Vision clients; it does not implement the full TLS-record-aware splice,
// which requires access to the outer TLS connection's record boundaries.
package vless

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"porttransit/internal/cryptox"
	"porttransit/internal/logx"
	"porttransit/internal/transport"
)

// Name is the registry key.
const Name = "vless"

// DefaultPort is the conventional listen port.
const DefaultPort = 443

func init() {
	transport.Register(transport.Factory{
		Name:         Name,
		Description:  "VLESS with optional XTLS-Vision. Minimal overhead; must run behind TLS or REALITY.",
		NativeHeader: true,
		DefaultPort:  DefaultPort,
		Build:        func() (transport.Dialer, transport.Handler) { return Dialer{}, Handler{} },
	})
}

// Settings keys understood by this transport.
const (
	// SettingUUID is the user identifier shared with the relay.
	SettingUUID = "uuid"
	// SettingFlow selects the flow control: "" (none) or "xtls-rprx-vision".
	SettingFlow = "flow"
	// SettingServerName overrides the SNI.
	SettingServerName = "serverName"
	// SettingInsecureSkipVerify accepts any server certificate.
	SettingInsecureSkipVerify = "insecure"
	// SettingCertFingerprint pins the SHA-256 fingerprint of the relay's leaf
	// certificate. It replaces insecure: true for a self-signed relay and takes
	// precedence over it when both are set.
	SettingCertFingerprint = "certFingerprint"
	// SettingTLS wraps the stream in TLS. Default true; VLESS without TLS is
	// unencrypted.
	SettingTLS = "tls"
	// SettingCertFile and SettingKeyFile give the relay its certificate.
	SettingCertFile = "certFile"
	SettingKeyFile  = "keyFile"
	// SettingTimeout bounds the handshake.
	SettingTimeout = "timeout"
	// SettingMinVersion pins the minimum TLS version.
	SettingMinVersion = "minVersion"
	// SettingDecryption names the VLESS Encryption method when the relay
	// expects one. Empty means plain VLESS.
	SettingDecryption = "decryption"
)

// VLESS address type bytes. These are NOT the SOCKS5 values.
const (
	addrTypeIPv4   = 0x01
	addrTypeDomain = 0x02
	addrTypeIPv6   = 0x03
)

// Command bytes.
const (
	cmdTCP = 0x01
	cmdUDP = 0x02
	cmdMux = 0x03
)

// maxPadding bounds the Vision padding region. Vision specifies 0..255; the
// extra headroom here is for the response direction, where some clients emit
// longer pads.
const maxPadding = 255

// FlowVision is the flow-control identifier for XTLS-Vision.
const FlowVision = "xtls-rprx-vision"

// Dialer establishes client→relay VLESS streams.
type Dialer struct{}

// Name returns the registry key.
func (Dialer) Name() string { return Name }

// Dial performs the TLS handshake (unless disabled) and writes the VLESS
// request header.
func (d Dialer) Dial(ctx context.Context, req transport.DialRequest) (transport.Stream, error) {
	timeout := req.Settings.GetDuration(SettingTimeout, 10*time.Second)
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	uuidStr := req.Settings.GetString(SettingUUID, "")
	if uuidStr == "" {
		return nil, fmt.Errorf("vless: %s is required", SettingUUID)
	}
	uuid, err := cryptox.ParseUUID(uuidStr)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}

	host, _, err := transport.SplitHostPort(req.ServerAddr)
	if err != nil {
		return nil, err
	}
	sni := req.ServerName
	if sni == "" {
		sni = req.Settings.GetString(SettingServerName, host)
	}

	// The pin is resolved before the socket is opened, and outside the TLS
	// branch, so a mistyped fingerprint is reported as a configuration error
	// rather than as a certificate mismatch from a relay that was never at
	// fault. Validating it even when the TLS wrapper is switched off is
	// deliberate: the setting is still wrong, and the operator would otherwise
	// discover it only on the day they turned TLS back on.
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

	var conn net.Conn = raw
	if req.Settings.GetBool(SettingTLS, true) {
		cfg := &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: certPolicy.InsecureSkipVerify,
			MinVersion:         minVersion(req.Settings.GetString(SettingMinVersion, "1.2")),
			// Vision requires ALPN h2 so the outer TLS session looks like an
			// HTTP/2 connection, which is what a browser would negotiate.
			NextProtos: []string{"h2", "http/1.1"},
		}
		cfg.VerifyConnection = certPolicy.VerifyConnection()
		tc := tls.Client(raw, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("vless: TLS handshake with %s: %w", req.ServerAddr, err)
		}
		conn = tc
	}

	// A nil request means a reachability probe. VLESS has no ping command, so
	// the probe is a TCP connect to the relay's own listening address: the
	// relay accepts and immediately closes, which still exercises the whole
	// handshake path.
	//
	// This rewrite must happen before anything dereferences req.Request: the
	// original code read req.Request.Target first and only checked for nil
	// afterwards, so the nil branch panicked instead of being reached.
	if req.Request == nil || req.Request.Command == transport.CmdPing {
		req.Request = &transport.Request{
			Command:   transport.CmdConnectTCP,
			Target:    req.ServerAddr,
			Transport: Name,
			Meta:      map[string]string{"ping": "true"},
		}
	}

	target := req.Request.Target
	command := byte(cmdTCP)
	if req.Request.Command == transport.CmdUDPAssociate {
		command = cmdUDP
	}

	flow := req.Settings.GetString(SettingFlow, "")
	header, err := encodeRequest(uuid, command, target, flow)
	if err != nil {
		conn.Close()
		return nil, err
	}

	vision := flow == FlowVision
	if vision {
		// Vision inserts a padding region between the header and the payload.
		pad, err := randomPadding()
		if err != nil {
			conn.Close()
			return nil, err
		}
		header = append(header, pad...)
	}

	if _, err := conn.Write(header); err != nil {
		conn.Close()
		return nil, fmt.Errorf("vless: write header: %w", err)
	}

	// The response header is read unconditionally, not only for Vision: the
	// relay always sends its two-byte version/addon-length prefix, so skipping
	// this read would leave those bytes at the head of the payload and shift
	// every subsequent byte by two. Vision merely adds a padding region after
	// the prefix.
	if err := readResponse(conn, vision); err != nil {
		conn.Close()
		return nil, err
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return transport.NewStream(conn, req.Request, Name, 0), nil
}

// Handler accepts relay-side VLESS streams.
type Handler struct{}

// Name returns the registry key.
func (Handler) Name() string { return Name }

// Handle reads the VLESS request header from an accepted connection.
func (h Handler) Handle(ctx context.Context, raw net.Conn, req transport.HandleRequest) (transport.Stream, error) {
	timeout := req.Settings.GetDuration(SettingTimeout, 10*time.Second)
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	uuidStr := req.Settings.GetString(SettingUUID, "")
	if uuidStr == "" {
		raw.Close()
		return nil, fmt.Errorf("vless: %s is required", SettingUUID)
	}
	wantUUID, err := cryptox.ParseUUID(uuidStr)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("vless: %w", err)
	}

	var conn net.Conn = raw
	if req.Settings.GetBool(SettingTLS, true) {
		cert, err := loadCert(req.Settings)
		if err != nil {
			raw.Close()
			return nil, err
		}
		// Report the fingerprint once so an operator can copy it into a
		// client's certFingerprint setting instead of reaching for insecure.
		transport.LogCertificateFingerprint(loggerFor(req.Logger), cert)
		tc := tls.Server(raw, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   minVersion(req.Settings.GetString(SettingMinVersion, "1.2")),
			NextProtos:   []string{"h2", "http/1.1"},
		})
		if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
			raw.Close()
			return nil, err
		}
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			loggerFor(req.Logger).Debug("vless: TLS handshake failed", "remote", transport.RemoteAddrString(raw), "err", err)
			return nil, err
		}
		conn = tc
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, err
	}

	version, gotUUID, command, target, addons, err := decodeRequest(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if version != 0 {
		conn.Close()
		return nil, fmt.Errorf("%w: vless version %d is not supported", transport.ErrProtocol, version)
	}
	// Constant-time comparison: a timing-observable UUID check would let an
	// attacker recover the identifier one byte at a time.
	if !cryptox.ConstantTimeEqual(gotUUID[:], wantUUID[:]) {
		conn.Close()
		loggerFor(req.Logger).Warn("vless: unknown user", "remote", transport.RemoteAddrString(raw))
		return nil, fmt.Errorf("%w: unknown uuid", transport.ErrAuthFailed)
	}

	flow := ""
	if addons != nil {
		flow = addons["flow"]
	}

	// Echo the response header before any payload flows, so the client can
	// start writing without racing the target's first response.
	resp := []byte{0x00, 0x00}
	if flow == FlowVision {
		pad, err := randomPadding()
		if err != nil {
			conn.Close()
			return nil, err
		}
		resp = append(resp, pad...)
	}
	if _, err := conn.Write(resp); err != nil {
		conn.Close()
		return nil, err
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}

	reqCommand := transport.CmdConnectTCP
	switch command {
	case cmdUDP:
		reqCommand = transport.CmdUDPAssociate
	case cmdMux:
		// MUX is a client-side multiplexing request that this relay does not
		// implement; the client's own multiplexing layer already handles
		// multiplexing above the transport, so a MUX command here would be a
		// client bug.
		conn.Close()
		return nil, fmt.Errorf("%w: vless MUX command is not supported", transport.ErrProtocol)
	}

	streamReq := &transport.Request{
		Command:   reqCommand,
		Target:    target,
		Transport: Name,
		Meta:      map[string]string{},
	}
	if flow != "" {
		streamReq.Meta["flow"] = flow
	}

	stream := transport.NewStream(conn, streamReq, Name, 0)
	if flow == FlowVision {
		return &visionStream{Stream: stream, conn: conn}, nil
	}
	return stream, nil
}

// visionStream unwraps the Vision padding region on the first read so callers
// see a clean byte stream.
type visionStream struct {
	transport.Stream
	conn     net.Conn
	stripped bool
}

// Read strips the Vision padding region the first time it is called.
func (v *visionStream) Read(p []byte) (int, error) {
	if !v.stripped {
		v.stripped = true
		if err := skipVisionPadding(v.conn); err != nil {
			return 0, err
		}
	}
	return v.conn.Read(p)
}

// encodeRequest builds a VLESS request header.
func encodeRequest(uuid cryptox.UUID, command byte, target, flow string) ([]byte, error) {
	host, portStr, err := transport.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 0, 64)
	buf = append(buf, 0x00)
	buf = append(buf, uuid[:]...)

	addons := encodeAddons(flow)
	buf = append(buf, byte(len(addons)))
	buf = append(buf, addons...)

	buf = append(buf, command)
	buf = binary.BigEndian.AppendUint16(buf, port)

	// VLESS uses its own address type numbering.
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, addrTypeIPv4)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, addrTypeIPv6)
			buf = append(buf, ip.To16()...)
		}
	} else {
		// An empty host would encode as a zero-length domain, which this
		// transport's own decoder rejects. Reporting it here keeps the failure
		// at the caller, where the target string is still visible, rather than
		// at the relay as an opaque protocol error.
		if host == "" {
			return nil, fmt.Errorf("%w: vless missing host in %q", transport.ErrBadAddress, target)
		}
		if len(host) > 255 {
			return nil, fmt.Errorf("vless: domain %q is longer than 255 bytes", host)
		}
		buf = append(buf, addrTypeDomain, byte(len(host)))
		buf = append(buf, host...)
	}
	return buf, nil
}

// encodeAddons renders the addon block.
//
// The encoding is a simple tag-length-value list rather than real protobuf:
// field 1 is the flow string. An empty flow yields a zero-length block, which
// is what a non-Vision client sends.
func encodeAddons(flow string) []byte {
	if flow == "" {
		return nil
	}
	// tag 0x01 (flow), length, value
	return append([]byte{0x01, byte(len(flow))}, flow...)
}

// decodeRequest parses a VLESS request header.
func decodeRequest(r io.Reader) (version byte, uuid cryptox.UUID, command byte, target string, addons map[string]string, err error) {
	var head [18]byte
	if _, err = io.ReadFull(r, head[:]); err != nil {
		return
	}
	version = head[0]
	copy(uuid[:], head[1:17])
	addonLen := int(head[17])

	if addonLen > 0 {
		blob := make([]byte, addonLen)
		if _, err = io.ReadFull(r, blob); err != nil {
			return
		}
		addons = decodeAddons(blob)
	}

	var cmd [1]byte
	if _, err = io.ReadFull(r, cmd[:]); err != nil {
		return
	}
	command = cmd[0]

	var portBuf [2]byte
	if _, err = io.ReadFull(r, portBuf[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf[:])

	var atyp [1]byte
	if _, err = io.ReadFull(r, atyp[:]); err != nil {
		return
	}

	var host string
	switch atyp[0] {
	case addrTypeIPv4:
		var b [4]byte
		if _, err = io.ReadFull(r, b[:]); err != nil {
			return
		}
		host = net.IP(b[:]).String()
	case addrTypeIPv6:
		var b [16]byte
		if _, err = io.ReadFull(r, b[:]); err != nil {
			return
		}
		host = net.IP(b[:]).String()
	case addrTypeDomain:
		var l [1]byte
		if _, err = io.ReadFull(r, l[:]); err != nil {
			return
		}
		if l[0] == 0 {
			err = fmt.Errorf("%w: vless zero-length domain", transport.ErrProtocol)
			return
		}
		b := make([]byte, l[0])
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		host = string(b)
	default:
		err = fmt.Errorf("%w: vless address type 0x%02x", transport.ErrProtocol, atyp[0])
		return
	}

	target = net.JoinHostPort(host, fmt.Sprint(port))
	return
}

// decodeAddons parses the tag-length-value addon block.
func decodeAddons(b []byte) map[string]string {
	out := map[string]string{}
	for i := 0; i+1 < len(b); {
		tag := b[i]
		l := int(b[i+1])
		i += 2
		if i+l > len(b) {
			break
		}
		val := string(b[i : i+l])
		i += l
		switch tag {
		case 0x01:
			out["flow"] = val
		case 0x02:
			out["seed"] = val
		default:
			out[fmt.Sprintf("tag%d", tag)] = val
		}
	}
	return out
}

// randomPadding builds the Vision padding region: a big-endian length followed
// by that many random bytes.
//
// The length is drawn from 0..maxPadding rather than always being the maximum,
// because a constant padding length would itself be a fingerprint.
func randomPadding() ([]byte, error) {
	n := int(cryptox.RandomBytes(1)[0])
	buf := make([]byte, 0, 2+n)
	buf = binary.BigEndian.AppendUint16(buf, uint16(n))
	if n > 0 {
		buf = append(buf, cryptox.RandomBytes(n)...)
	}
	return buf, nil
}

// readResponse consumes the relay's response header, and the Vision padding
// region when the request used the Vision flow.
//
// The header is always present: version(1) + addonLen(1) + addons. Vision adds
// a length-prefixed padding region after it, which the relay sends to blunt
// length analysis of the first packets.
func readResponse(r io.Reader, vision bool) error {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return fmt.Errorf("vless: read response header: %w", err)
	}
	if head[1] > 0 {
		skip := make([]byte, head[1])
		if _, err := io.ReadFull(r, skip); err != nil {
			return fmt.Errorf("vless: read response addons: %w", err)
		}
	}
	if !vision {
		return nil
	}
	return skipVisionPadding(r)
}

// skipVisionPadding consumes a length-prefixed padding region.
func skipVisionPadding(r io.Reader) error {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return fmt.Errorf("vless: read vision padding length: %w", err)
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n == 0 {
		return nil
	}
	if n > maxPadding {
		return fmt.Errorf("%w: vless vision padding length %d exceeds %d", transport.ErrProtocol, n, maxPadding)
	}
	skip := make([]byte, n)
	if _, err := io.ReadFull(r, skip); err != nil {
		return fmt.Errorf("vless: read vision padding: %w", err)
	}
	return nil
}

func parsePort(s string) (uint16, error) {
	var p int
	if _, err := fmt.Sscanf(s, "%d", &p); err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("%w: vless bad port %q", transport.ErrBadAddress, s)
	}
	return uint16(p), nil
}

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
	switch s {
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
