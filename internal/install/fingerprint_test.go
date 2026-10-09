package install

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"porttransit/internal/transport"
)

// The fingerprint command is how an operator obtains the value a client pins, so
// a bug here does not produce a visible failure: it produces a client configured
// with a wrong value, or — worse — an operator who gives up and reaches for
// insecure: true instead. The assertions below are therefore about the printed
// value being exactly the one the client will compare against.

// fingerprintTestCert writes a self-signed pair into a temporary directory and
// returns the certificate path and its canonical fingerprint.
func fingerprintTestCert(t *testing.T, cn string) (certPath string, want string) {
	t.Helper()
	dir := t.TempDir()
	certPath = filepath.Join(dir, "relay.crt")
	cert, err := transport.GenerateSelfSigned(transport.SelfSignedOptions{
		CommonName:  cn,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		CertFile:    certPath,
		KeyFile:     filepath.Join(dir, "relay.key"),
	})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse the generated certificate: %v", err)
	}
	return certPath, transport.CertificateFingerprint(leaf)
}

// captureStdout runs fn with stdout redirected and returns what it printed.
//
// The command prints to stdout rather than returning a value, because that is
// what an operator pipes into a script; asserting on the printed text is
// therefore asserting on the actual contract rather than on an internal one.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	saved := os.Stdout
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- sb.String()
	}()

	runErr := fn()
	w.Close()
	os.Stdout = saved
	return <-done, runErr
}

// TestFingerprintFromACertificateFile proves the primary operator path: reading
// a fingerprint off the relay's own certificate file.
//
// The value has to be byte-identical to what the client compares against, so it
// is checked against transport.CertificateFingerprint rather than merely being
// asserted to be 95 characters long.
func TestFingerprintFromACertificateFile(t *testing.T) {
	certPath, want := fingerprintTestCert(t, "fingerprint-relay")

	out, err := captureStdout(t, func() error {
		return Fingerprint([]string{"--cert", certPath})
	})
	if err != nil {
		t.Fatalf("Fingerprint --cert: %v", err)
	}

	if !strings.Contains(out, "certFingerprint="+want) {
		t.Errorf("the output does not carry certFingerprint=%s; it printed:\n%s", want, out)
	}
	// The subject and expiry are printed alongside so an operator can confirm
	// they are looking at the right certificate before pinning it.
	if !strings.Contains(out, "fingerprint-relay") {
		t.Errorf("the output does not name the subject; it printed:\n%s", out)
	}
	if !strings.Contains(out, "notAfter=") {
		t.Errorf("the output does not carry the expiry; it printed:\n%s", out)
	}
}

// TestFingerprintMatchesWhatTheClientPins is the assertion that ties the command
// to the feature.
//
// Printing a plausible-looking string is not enough: the value has to be one
// that ResolveClientCertPolicy accepts and that matches the certificate. A
// command that printed, say, the lowercase or bare-hex form would still "work"
// for a human reading it but would be compared against the wrong thing by any
// tooling that did a string equality check.
func TestFingerprintMatchesWhatTheClientPins(t *testing.T) {
	certPath, want := fingerprintTestCert(t, "roundtrip-relay")

	out, err := captureStdout(t, func() error {
		return Fingerprint([]string{"--cert", certPath})
	})
	if err != nil {
		t.Fatalf("Fingerprint --cert: %v", err)
	}

	printed := ""
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(line, "certFingerprint="); ok {
			printed = strings.TrimSpace(v)
		}
	}
	if printed == "" {
		t.Fatalf("the command printed no certFingerprint line:\n%s", out)
	}
	if printed != want {
		t.Errorf("the printed fingerprint is %q, want %q", printed, want)
	}

	// The printed value must round-trip through the client's own parser, which
	// is the real contract: whatever this prints is what goes in the config.
	policy, err := transport.ResolveClientCertPolicy(
		transport.Settings{"certFingerprint": printed}, "certFingerprint", false)
	if err != nil {
		t.Fatalf("the printed fingerprint is not accepted by the client: %v", err)
	}

	leaf, err := transport.LoadCertificateFile(certPath)
	if err != nil {
		t.Fatalf("LoadCertificateFile: %v", err)
	}
	if err := policy.VerifyPeerCertificates([]*x509.Certificate{leaf}); err != nil {
		t.Errorf("a client pinning the printed fingerprint would reject the certificate it came from: %v", err)
	}
}

// TestFingerprintAcceptsDER proves the file reader handles the encoding a
// certificate exported from a store arrives in.
//
// Telling an operator to convert it first is a step they will skip — or worse,
// get wrong and pin the fingerprint of a file the relay never presents.
func TestFingerprintAcceptsDER(t *testing.T) {
	certPath, want := fingerprintTestCert(t, "der-relay")

	pemData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("the generated file is not PEM")
	}
	derPath := filepath.Join(t.TempDir(), "relay.der")
	if err := os.WriteFile(derPath, block.Bytes, 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := captureStdout(t, func() error {
		return Fingerprint([]string{"--cert", derPath})
	})
	if err != nil {
		t.Fatalf("Fingerprint --cert on a DER file: %v", err)
	}
	if !strings.Contains(out, "certFingerprint="+want) {
		t.Errorf("the DER file produced a different fingerprint; printed:\n%s", out)
	}
}

// TestFingerprintRejectsMissingAndCorruptFiles proves a bad input is an error
// rather than a zero or empty fingerprint.
//
// Printing an empty value would be the worst outcome: an operator copying it
// into a client would either get a configuration error they cannot explain or,
// if the value were ever treated as "unset", no verification at all.
func TestFingerprintRejectsMissingAndCorruptFiles(t *testing.T) {
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "corrupt.crt")
	if err := os.WriteFile(corrupt, []byte("this is not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"a missing file": filepath.Join(dir, "absent.crt"),
		"a corrupt file": corrupt,
		"a directory":    dir,
		"a private key":  writeFile(t, dir, "only.key", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
	}

	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := captureStdout(t, func() error {
				return Fingerprint([]string{"--cert", path})
			})
			if err == nil {
				t.Fatalf("Fingerprint accepted %s and printed:\n%s", name, out)
			}
			if strings.Contains(out, "certFingerprint=") {
				t.Errorf("a fingerprint was printed despite the failure:\n%s", out)
			}
		})
	}
}

// TestFingerprintFlagValidation proves the command refuses an ambiguous or empty
// request rather than silently picking one source.
//
// Silently choosing would leave an operator with no way to tell which
// certificate the printed value came from — and the whole point of the command
// is that the value is trustworthy.
func TestFingerprintFlagValidation(t *testing.T) {
	certPath, _ := fingerprintTestCert(t, "flags-relay")

	cases := []struct {
		name string
		args []string
	}{
		{"neither source", nil},
		{"both sources", []string{"--cert", certPath, "--server", "127.0.0.1:8443"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := captureStdout(t, func() error { return Fingerprint(tc.args) })
			if err == nil {
				t.Fatalf("Fingerprint accepted %v and printed:\n%s", tc.args, out)
			}
			if !strings.Contains(err.Error(), "--cert") || !strings.Contains(err.Error(), "--server") {
				t.Errorf("the error %q does not name both flags, so the operator cannot tell what to change", err.Error())
			}
		})
	}
}

// TestFingerprintReadsARunningRelay proves the client-side path: reading the
// certificate a remote relay actually presents.
//
// This is the case where the operator has no file to hand, and it is also the
// only way to obtain the fingerprint of the certificate a relay presents as
// opposed to the one it has on disk — which matters when the two have drifted.
func TestFingerprintReadsARunningRelay(t *testing.T) {
	certPath, want := fingerprintTestCert(t, "served-relay")
	keyPath := filepath.Join(filepath.Dir(certPath), "relay.key")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load the pair: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
				if err := tc.Handshake(); err != nil {
					return
				}
				// Hold the connection until the client closes it, so the
				// reading side never races a close before it has the chain.
				_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = tc.Read(make([]byte, 1))
			}(conn)
		}
	}()

	out, err := captureStdout(t, func() error {
		return Fingerprint([]string{"--server", ln.Addr().String()})
	})
	if err != nil {
		t.Fatalf("Fingerprint --server: %v", err)
	}
	if !strings.Contains(out, "certFingerprint="+want) {
		t.Errorf("reading the running relay produced the wrong fingerprint; want %s, printed:\n%s", want, out)
	}
}

// TestFingerprintReportsAnUnreachableServer proves a failure to connect is
// reported rather than producing an empty or zero fingerprint.
func TestFingerprintReportsAnUnreachableServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dead := ln.Addr().String()
	ln.Close()

	out, err := captureStdout(t, func() error {
		return Fingerprint([]string{"--server", dead, "--timeout", "2s"})
	})
	if err == nil {
		t.Fatalf("Fingerprint against a closed port succeeded and printed:\n%s", out)
	}
	if strings.Contains(out, "certFingerprint=") {
		t.Errorf("a fingerprint was printed although no handshake completed:\n%s", out)
	}
}

// TestFingerprintReportsAMalformedServerAddress proves a missing port is
// reported as a usage problem rather than as a connection failure.
func TestFingerprintReportsAMalformedServerAddress(t *testing.T) {
	out, err := captureStdout(t, func() error {
		return Fingerprint([]string{"--server", "relay.example.com"})
	})
	if err == nil {
		t.Fatalf("Fingerprint accepted a server address with no port and printed:\n%s", out)
	}
}

// writeFile writes content into dir under name and returns the path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
