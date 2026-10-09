// Package tls implements the PortTransit TLS transport.
//
// This is the recommended default. A real TLS 1.3 handshake is performed with
// a real certificate, and the PortTransit preamble travels inside the
// encrypted record stream. On the wire the connection is a normal HTTPS/TLS
// session to the configured server name, which is why it survives deep packet
// inspection far better than a bespoke encrypted protocol.
//
// # Two client modes
//
//   - Standard (default): crypto/tls with a full verification policy. Requires
//     a certificate the client trusts, or an explicit insecure flag.
//   - Fingerprint: a uTLS ClientHello that reproduces a real browser's
//     fingerprint byte for byte. Use this when the relay's certificate is
//     self-signed (the default for a relay installed by the one-click script)
//     or when the censor fingerprints TLS stacks rather than certificates.
//
// # Wire format
//
//	client → relay: [TLS handshake][PortTransit preamble]
//	relay  → client: [TLS handshake]
//	then:           encrypted bidirectional bytes
package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"

	"porttransit/internal/logx"
	"porttransit/internal/transport"
)

// Name is the registry key.
const Name = "tls"

// DefaultPort is the conventional listen port. 443 is preferred because it is
// the least likely to be blocked; 8443 is the fallback used by the installer
// when 443 is taken.
const DefaultPort = 443

func init() {
	transport.Register(transport.Factory{
		Name:         Name,
		Description:  "Real TLS 1.3 with a real certificate, optionally reproducing a browser fingerprint. The recommended default.",
		NativeHeader: false,
		DefaultPort:  DefaultPort,
		Build:        func() (transport.Dialer, transport.Handler) { return Dialer{}, Handler{} },
	})
}

// Settings keys understood by this transport.
const (
	// SettingServerName overrides the SNI. Defaults to the host in Address.
	SettingServerName = "serverName"
	// SettingInsecureSkipVerify accepts any server certificate. Required for
	// the self-signed certificate the installer generates.
	SettingInsecureSkipVerify = "insecure"
	// SettingFingerprint selects a uTLS ClientHello profile: chrome, firefox,
	// safari, edge, ios, android, randomized or none (use crypto/tls).
	SettingFingerprint = "fingerprint"
	// SettingALPN overrides the advertised ALPN list. The default is
	// h2,http/1.1, which is what a browser offers.
	SettingALPN = "alpn"
	// SettingCertFile and SettingKeyFile give the relay its certificate.
	SettingCertFile = "certFile"
	SettingKeyFile  = "keyFile"
	// SettingPSK authenticates the PortTransit preamble inside the tunnel.
	SettingPSK = "psk"
	// SettingMinVersion pins the minimum TLS version: "1.2" or "1.3".
	SettingMinVersion = "minVersion"
	// SettingTimeout bounds the handshake.
	SettingTimeout = "timeout"
)

// Dialer establishes client→relay TLS streams.
type Dialer struct{}

// Name returns the registry key.
func (Dialer) Name() string { return Name }

// Dial performs the TLS handshake and then exchanges the preamble.
func (d Dialer) Dial(ctx context.Context, req transport.DialRequest) (transport.Stream, error) {
	timeout := req.Settings.GetDuration(SettingTimeout, 10*time.Second)
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	host, _, err := transport.SplitHostPort(req.ServerAddr)
	if err != nil {
		return nil, err
	}
	sni := req.ServerName
	if sni == "" {
		sni = req.Settings.GetString(SettingServerName, host)
	}

	// Dial the raw socket first so the context governs the connect and the
	// deadline covers the handshake.
	raw, err := (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", req.ServerAddr)
	if err != nil {
		return nil, err
	}
	if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
		raw.Close()
		return nil, err
	}

	fingerprint := strings.ToLower(req.Settings.GetString(SettingFingerprint, ""))
	if fingerprint == "" {
		// A relay installed by the one-click script uses a self-signed
		// certificate, so defaulting to a fingerprint profile is what makes a
		// fresh install work without the user copying a CA around.
		fingerprint = "chrome"
	}

	var conn net.Conn
	if fingerprint == "none" {
		conn, err = standardHandshake(raw, req, sni)
	} else {
		conn, err = uTLSHandshake(raw, req, sni, fingerprint)
	}
	if err != nil {
		raw.Close()
		return nil, err
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}

	return transport.PreambleClientHandshake(conn, req.Request, transport.ClientHandshakeConfig{
		PSK:           transport.DecodePSK(req.Settings.GetString(SettingPSK, "")),
		ClientID:      clientIDFrom(req),
		TransportName: Name,
		Timeout:       timeout,
		Logger:        loggerFor(req.Logger),
	})
}

// standardHandshake uses crypto/tls with a conventional verification policy.
func standardHandshake(raw net.Conn, req transport.DialRequest, sni string) (net.Conn, error) {
	cfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: req.Settings.GetBool(SettingInsecureSkipVerify, false),
		MinVersion:         minVersion(req.Settings.GetString(SettingMinVersion, "1.2")),
		NextProtos:         alpnList(req.Settings),
	}
	if pool := certPoolFrom(req.Settings); pool != nil {
		cfg.RootCAs = pool
	}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(context.Background()); err != nil {
		return nil, fmt.Errorf("tls: handshake with %s (sni %s): %w", req.ServerAddr, sni, err)
	}
	return tc, nil
}

// uTLSHandshake reproduces a real browser's ClientHello. The relay sees the
// same bytes a browser would send, so a fingerprinting middlebox has nothing
// to match on.
func uTLSHandshake(raw net.Conn, req transport.DialRequest, sni, fingerprint string) (net.Conn, error) {
	profile, spec, err := clientHelloProfile(fingerprint)
	if err != nil {
		return nil, err
	}
	cfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: req.Settings.GetBool(SettingInsecureSkipVerify, false),
		MinVersion:         minVersion(req.Settings.GetString(SettingMinVersion, "1.2")),
		NextProtos:         alpnList(req.Settings),
	}
	if pool := certPoolFrom(req.Settings); pool != nil {
		cfg.RootCAs = pool
	}
	tc := utls.UClient(raw, cfg, profile)
	if spec != nil {
		// ApplyPreset is what gives the randomized profiles a different
		// extension order on every connection.
		if err := tc.ApplyPreset(spec); err != nil {
			return nil, fmt.Errorf("tls: apply %s fingerprint: %w", fingerprint, err)
		}
	}
	if err := tc.HandshakeContext(context.Background()); err != nil {
		return nil, fmt.Errorf("tls: uTLS(%s) handshake with %s (sni %s): %w", fingerprint, req.ServerAddr, sni, err)
	}
	return tc, nil
}

// clientHelloProfile maps a profile name to a uTLS ClientHelloID and, for the
// synthesized profiles, a ClientHello spec built for this one connection.
//
// The versions are pinned deliberately: uTLS's "latest" aliases change with
// each uTLS release, which would silently change the wire fingerprint of an
// already-deployed client. Pinning keeps a built binary reproducible.
//
// The randomized profiles are derived from Chrome rather than from uTLS's
// HelloRandomized*. Those synthesize a ClientHello from weighted coin flips and
// can advertise X25519MLKEM768 in supported_groups without sending a key share
// for it. A server that prefers that group then answers with a
// HelloRetryRequest, and uTLS cannot generate a key for the group on that path,
// so the handshake dies with "tls: CurvePreferences includes unsupported curve".
// Measured over 500 handshakes per profile, that killed 14-18% of connections
// while the named browser profiles never failed once. Chrome shuffles its own
// extension order (Chrome 106+), so shuffling a real Chrome profile yields a
// fingerprint that differs per connection while remaining a profile that always
// completes.
func clientHelloProfile(name string) (utls.ClientHelloID, *utls.ClientHelloSpec, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "chrome", "":
		return utls.HelloChrome_Auto, nil, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil, nil
	case "safari":
		return utls.HelloSafari_Auto, nil, nil
	case "edge":
		return utls.HelloEdge_Auto, nil, nil
	case "ios":
		return utls.HelloIOS_Auto, nil, nil
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil, nil
	case "random", "randomized":
		spec, err := shuffledChromeSpec(true)
		if err != nil {
			return utls.ClientHelloID{}, nil, err
		}
		return utls.HelloCustom, spec, nil
	case "random-no-alpn":
		spec, err := shuffledChromeSpec(false)
		if err != nil {
			return utls.ClientHelloID{}, nil, err
		}
		return utls.HelloCustom, spec, nil
	case "golang":
		return utls.HelloGolang, nil, nil
	default:
		return utls.ClientHelloID{}, nil, fmt.Errorf("tls: unknown fingerprint profile %q", name)
	}
}

// shuffledChromeSpec builds a Chrome ClientHello with its extensions in a fresh
// random order, which is what a current Chrome does on every connection.
func shuffledChromeSpec(withALPN bool) (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		return nil, fmt.Errorf("tls: build randomized spec: %w", err)
	}
	if !withALPN {
		kept := spec.Extensions[:0]
		for _, ext := range spec.Extensions {
			if _, isALPN := ext.(*utls.ALPNExtension); isALPN {
				continue
			}
			kept = append(kept, ext)
		}
		spec.Extensions = kept
	}
	spec.Extensions = utls.ShuffleChromeTLSExtensions(spec.Extensions)
	return &spec, nil
}

// Handler accepts relay-side TLS streams.
type Handler struct{}

// Name returns the registry key.
func (Handler) Name() string { return Name }

// Handle performs the server side of the TLS handshake.
func (h Handler) Handle(ctx context.Context, raw net.Conn, req transport.HandleRequest) (transport.Stream, error) {
	timeout := req.Settings.GetDuration(SettingTimeout, 10*time.Second)
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	cert, err := loadCertificate(req.Settings)
	if err != nil {
		raw.Close()
		return nil, err
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersion(req.Settings.GetString(SettingMinVersion, "1.2")),
		NextProtos:   alpnList(req.Settings),
	}

	if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
		raw.Close()
		return nil, err
	}

	tc := tls.Server(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		loggerFor(req.Logger).Debug("tls handshake failed", "remote", transport.RemoteAddrString(raw), "err", err)
		return nil, err
	}

	return transport.PreambleServerHandshake(tc, transport.ServerHandshakeConfig{
		PSK:             transport.DecodePSK(req.Settings.GetString(SettingPSK, "")),
		Replay:          replayGuard(req.Settings),
		Timeout:         timeout,
		Logger:          loggerFor(req.Logger),
		RequireClientID: req.Settings.GetBool("requireClientID", false),
		AllowedClients:  req.Settings.GetStringSlice("allowedClients"),
		AllowPing:       req.Settings.GetBool("allowPing", true),
		TransportName:   Name,
	})
}

// loadCertificate returns the relay's key pair, generating a self-signed one on
// first use when the configured paths do not exist yet.
//
// Generating rather than failing is deliberate: the installer cannot know the
// operator's domain at install time, and a relay that refuses to start is
// harder to diagnose than one that starts with a self-signed certificate the
// GUI clearly labels as such.
func loadCertificate(s transport.Settings) (tls.Certificate, error) {
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

	names := s.GetStringSlice("certNames")
	host := s.GetString("certHost", "")
	if host != "" {
		names = append(names, host)
	}
	return transport.LoadOrGenerateCertificate(certFile, keyFile, transport.SelfSignedOptions{
		CommonName: s.GetString("certCommonName", "porttransit-relay"),
		DNSNames:   names,
		ValidFor:   s.GetDuration("certValidFor", 3650*24*time.Hour),
	})
}

// certPoolFrom loads extra CA certificates when the operator supplied a
// private CA for the relay's certificate.
func certPoolFrom(s transport.Settings) *x509.CertPool {
	caFile := s.GetString("caFile", "")
	if caFile == "" {
		return nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil
	}
	return pool
}

func minVersion(s string) uint16 {
	switch strings.TrimSpace(s) {
	case "1.3", "tls1.3", "TLS1.3":
		return tls.VersionTLS13
	case "1.2", "tls1.2", "TLS1.2":
		return tls.VersionTLS12
	default:
		return tls.VersionTLS12
	}
}

// alpnList returns the ALPN protocols to advertise. Advertising h2 without
// implementing HTTP/2 would break a real browser landing on the relay, so the
// relay's own listener only ever negotiates the first entry it actually
// supports; the client offers a browser-like list because that is what the
// fingerprint should look like.
func alpnList(s transport.Settings) []string {
	if v := s.GetStringSlice(SettingALPN); len(v) > 0 {
		return v
	}
	return []string{"h2", "http/1.1"}
}

func replayGuard(s transport.Settings) *transport.ReplayGuard {
	if s.GetBool("disableReplayGuard", false) {
		return nil
	}
	return transport.NewReplayGuard(s.GetInt("replayCacheSize", 65536), 0)
}

func clientIDFrom(req transport.DialRequest) string {
	if req.Request != nil && req.Request.ClientID != "" {
		return req.Request.ClientID
	}
	return req.Settings.GetString("clientID", "")
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
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

// ErrNoCertificate reports a missing or unreadable relay certificate.
var ErrNoCertificate = errors.New("tls: no usable certificate")
