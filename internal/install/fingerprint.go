package install

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"time"

	"porttransit/internal/transport"
)

// Fingerprint prints the SHA-256 fingerprint of a relay's certificate.
//
// It exists because the value it prints is what a client must put in
// certFingerprint, and the alternative ways of obtaining it — reading it out of
// a browser's certificate dialog, or running openssl through the right
// incantation — are exactly the steps an operator skips before reaching for
// `insecure: true` instead. A one-command answer is what makes pinning the
// easier option.
//
// Two sources are supported, because an operator is not always on the host that
// holds the certificate file:
//
//   - --cert: a local certificate file, PEM or DER.
//   - --server: a running relay, whose presented certificate is read from a
//     handshake. This is the client-side case, where the relay is remote and
//     the only thing to hand is its address.
//
// The output is `key=value` lines, matching show-credentials, so the value can
// be piped into a script on a host with no JSON tooling.
func Fingerprint(args []string) error {
	fs := flag.NewFlagSet("fingerprint", flag.ContinueOnError)
	var (
		certPath   string
		serverAddr string
		serverName string
		timeout    time.Duration
	)
	fs.StringVar(&certPath, "cert", "", "证书文件路径（PEM 或 DER）")
	fs.StringVar(&serverAddr, "server", "", "从运行中的中转服务端读取证书，例如 relay.example.com:8443")
	fs.StringVar(&serverName, "server-name", "", "读取证书时使用的 SNI，默认取 --server 的主机名")
	fs.DurationVar(&timeout, "timeout", 10*time.Second, "读取证书的超时时间")
	if err := fs.Parse(args); err != nil {
		return err
	}

	switch {
	case certPath == "" && serverAddr == "":
		return errors.New("fingerprint: 需要 --cert 或 --server 其中之一")
	case certPath != "" && serverAddr != "":
		// Accepting both would mean silently picking one, and the operator
		// would have no way to tell which certificate they were shown.
		return errors.New("fingerprint: --cert 与 --server 只能给一个")
	}

	var leaf *x509.Certificate
	var err error
	if certPath != "" {
		leaf, err = readCertificateFile(certPath)
	} else {
		leaf, err = readCertificateFromServer(serverAddr, serverName, timeout)
	}
	if err != nil {
		return err
	}

	fmt.Printf("certFingerprint=%s\n", transport.CertificateFingerprint(leaf))
	fmt.Printf("subject=%s\n", leaf.Subject.CommonName)
	fmt.Printf("notAfter=%s\n", leaf.NotAfter.Format("2006-01-02"))
	return nil
}

// readCertificateFile parses the first certificate in a PEM or DER file.
//
// The fingerprint is computed by the transport package rather than here so this
// command and the client that consumes its output can never disagree about which
// certificate in a bundle the value belongs to, or about how it is formatted.
func readCertificateFile(path string) (*x509.Certificate, error) {
	cert, err := transport.LoadCertificateFile(path)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: %w", err)
	}
	return cert, nil
}

// readCertificateFromServer dials a relay and returns the leaf certificate it
// presents.
//
// Verification is switched off deliberately and is the entire point: the
// certificate being read is the self-signed one the client cannot verify yet,
// which is precisely why its fingerprint is being fetched. Nothing is trusted
// from this handshake — the operator compares the printed value against the one
// the relay's own log or console shows, and it is that comparison which makes
// the pin meaningful.
func readCertificateFromServer(addr, serverName string, timeout time.Duration) (*x509.Certificate, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: %w", err)
	}
	if serverName == "" {
		serverName = host
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: dial %s: %w", addr, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	tc := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tc.Handshake(); err != nil {
		return nil, fmt.Errorf("fingerprint: TLS handshake with %s: %w", addr, err)
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("fingerprint: %s presented no certificate", addr)
	}
	return certs[0], nil
}
