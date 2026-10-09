package transport

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadOrGenerateCertificateGeneratesWhenAbsent is the regression test for a
// bug that broke the default installation.
//
// The one-click installer writes certFile and keyFile paths into the config
// before those files exist, expecting the transport to generate a self-signed
// pair on first use. The loader instead called tls.LoadX509KeyPair
// unconditionally whenever the paths were set, so it failed on the very first
// start. The relay still bound its port and logged "relay started", which made
// the failure look like a client problem: every handshake was rejected with
// "load certificate: no such file or directory" while the relay appeared
// healthy.
//
// The assertion is therefore that a configured-but-absent pair is generated and
// persisted, not reported as an error.
func TestLoadOrGenerateCertificateGeneratesWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "certs", "relay.crt")
	keyFile := filepath.Join(dir, "certs", "relay.key")

	cert, err := LoadOrGenerateCertificate(certFile, keyFile, SelfSignedOptions{CommonName: "relay"})
	if err != nil {
		t.Fatalf("LoadOrGenerateCertificate with absent files: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("the returned certificate carries no DER")
	}

	// The pair must be persisted, otherwise every restart would change the
	// fingerprint and invalidate any client that pinned it.
	for _, p := range []string{certFile, keyFile} {
		if !fileExists(p) {
			t.Errorf("the generated pair was not persisted to %s", p)
		}
	}
}

// TestLoadOrGenerateCertificateReusesThePersistedPair proves a second call
// returns the same certificate, which is what makes fingerprint pinning
// survive a restart.
func TestLoadOrGenerateCertificateReusesThePersistedPair(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "relay.crt")
	keyFile := filepath.Join(dir, "relay.key")

	first, err := LoadOrGenerateCertificate(certFile, keyFile, SelfSignedOptions{})
	if err != nil {
		t.Fatalf("the first call failed: %v", err)
	}
	second, err := LoadOrGenerateCertificate(certFile, keyFile, SelfSignedOptions{})
	if err != nil {
		t.Fatalf("the second call failed: %v", err)
	}

	if string(first.Certificate[0]) != string(second.Certificate[0]) {
		t.Error("the second call produced a different certificate, so a pinned fingerprint would break on restart")
	}
}

// TestLoadOrGenerateCertificateReportsABrokenPair proves a corrupt but present
// certificate is reported rather than silently replaced.
//
// Replacing it would invalidate every client that pinned the fingerprint, and
// would do so without telling the operator.
func TestLoadOrGenerateCertificateReportsABrokenPair(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "relay.crt")
	keyFile := filepath.Join(dir, "relay.key")

	if err := os.WriteFile(certFile, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOrGenerateCertificate(certFile, keyFile, SelfSignedOptions{}); err == nil {
		t.Fatal("a corrupt certificate pair was accepted")
	}
}

// TestLoadOrGenerateCertificateReportsAHalfConfiguredPair proves that having
// only one of the two files is reported rather than papered over.
//
// A half-provisioned pair usually means a copy was interrupted or a path was
// mistyped, and generating over it would hide the mistake until the operator
// noticed the fingerprint had changed.
func TestLoadOrGenerateCertificateReportsAHalfConfiguredPair(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "relay.crt")
	keyFile := filepath.Join(dir, "relay.key")

	if err := os.WriteFile(certFile, []byte("present"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadOrGenerateCertificate(certFile, keyFile, SelfSignedOptions{})
	if err == nil {
		t.Fatal("a certificate without its key was accepted")
	}
	// The message must name both files, since that is what the operator needs
	// to fix it.
	for _, want := range []string{certFile, keyFile} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not name %s: %v", want, err)
		}
	}
}

// TestLoadOrGenerateCertificateInMemoryWhenUnconfigured proves that leaving
// both paths empty still yields a usable certificate.
//
// The installer always sets the paths, but a hand-written config may not, and a
// relay that refuses to start over a missing optional setting is a poor
// failure mode.
func TestLoadOrGenerateCertificateInMemoryWhenUnconfigured(t *testing.T) {
	cert, err := LoadOrGenerateCertificate("", "", SelfSignedOptions{})
	if err != nil {
		t.Fatalf("LoadOrGenerateCertificate with no paths: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("no certificate was produced")
	}
	if _, ok := cert.PrivateKey.(interface{}); !ok {
		t.Fatal("no private key was produced")
	}
}

// TestLoadOrGenerateCertificateProducesAUsableTLSKeyPair proves the returned
// value can actually complete a handshake, rather than merely being non-empty.
//
// The generated pair is the relay's only certificate, so a subtle encoding
// mistake would take down every listener that uses it.
func TestLoadOrGenerateCertificateProducesAUsableTLSKeyPair(t *testing.T) {
	dir := t.TempDir()
	cert, err := LoadOrGenerateCertificate(
		filepath.Join(dir, "relay.crt"),
		filepath.Join(dir, "relay.key"),
		SelfSignedOptions{CommonName: "relay", DNSNames: []string{"relay.test"}},
	)
	if err != nil {
		t.Fatalf("LoadOrGenerateCertificate: %v", err)
	}

	if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		t.Fatal("the pair is incomplete")
	}
	// The leaf must parse as an X.509 certificate and carry the requested name,
	// because a client verifying against the configured server name relies on
	// that SAN being present.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("the generated leaf does not parse: %v", err)
	}
	found := false
	for _, n := range leaf.DNSNames {
		if n == "relay.test" {
			found = true
		}
	}
	if !found {
		t.Errorf("the requested DNS name is missing from the certificate: %v", leaf.DNSNames)
	}

	// The pair must be usable for a real handshake, not merely well-formed:
	// this certificate is the relay's only one, so an encoding mistake would
	// take down every listener that uses it.
	serverCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	// InsecureSkipVerify is set because the generated pair is self-signed: the
	// point of this test is that the key pair works, not that a self-signed
	// certificate validates against a system root.
	clientCfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "relay.test",
		MinVersion:         tls.VersionTLS13,
	}

	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	errCh := make(chan error, 1)
	go func() {
		tc := tls.Server(serverRaw, serverCfg)
		errCh <- tc.Handshake()
	}()

	client := tls.Client(clientRaw, clientCfg)
	if err := client.Handshake(); err != nil {
		t.Fatalf("a client could not complete a handshake against the generated pair: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("the server side of the handshake failed: %v", err)
	}
	// The negotiated name must be the one that was requested, which is what a
	// client relying on the SAN depends on.
	if got := client.ConnectionState().ServerName; got != "" && got != "relay.test" {
		t.Errorf("the negotiated server name is %q, want relay.test", got)
	}
}
