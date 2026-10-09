package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// SelfSignedOptions parameterises GenerateSelfSigned.
type SelfSignedOptions struct {
	// CommonName is the certificate subject common name.
	CommonName string
	// DNSNames lists subject alternative names for DNS.
	DNSNames []string
	// IPAddresses lists subject alternative names for IP literals. When empty
	// and DNSNames is empty, loopback addresses are added so a local test
	// works.
	IPAddresses []net.IP
	// ValidFor is the certificate lifetime. Zero means ten years.
	ValidFor time.Duration
	// CertFile and KeyFile, when both set, persist the generated pair so a
	// restart does not change the fingerprint.
	CertFile string
	KeyFile  string
}

// LoadOrGenerateCertificate returns the relay's key pair.
//
// The distinction this function exists to make is between "not provisioned yet"
// and "provisioned but broken":
//
//   - Both paths set and both files present: load them. A parse failure is
//     reported, because silently replacing a certificate an operator installed
//     would invalidate every client that pinned its fingerprint.
//   - Both paths set and neither file present: generate a self-signed pair and
//     persist it to those paths, so a restart keeps the same fingerprint. This
//     is the state a fresh install is in — the installer cannot know the
//     operator's domain, and a relay that refuses to start is far harder to
//     diagnose than one that starts with a certificate the console labels as
//     self-signed.
//   - Exactly one of the two present: report it. That is a half-finished
//     configuration, and generating over it would hide a real mistake.
//   - Neither path set: generate an in-memory pair. The relay then gets a new
//     fingerprint on every restart, which is why the installer always sets the
//     paths.
func LoadOrGenerateCertificate(certFile, keyFile string, opts SelfSignedOptions) (tls.Certificate, error) {
	opts.CertFile = certFile
	opts.KeyFile = keyFile

	if certFile == "" && keyFile == "" {
		return GenerateSelfSigned(opts)
	}

	certExists := fileExists(certFile)
	keyExists := fileExists(keyFile)

	switch {
	case certExists && keyExists:
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("cert: load %s: %w", certFile, err)
		}
		return cert, nil

	case !certExists && !keyExists:
		// First run. Persist so the fingerprint is stable across restarts.
		return GenerateSelfSigned(opts)

	default:
		missing, present := certFile, keyFile
		if keyExists {
			missing, present = keyFile, certFile
		}
		return tls.Certificate{}, fmt.Errorf(
			"cert: %s exists but %s does not; remove %s to have a self-signed pair generated, or supply the missing file",
			present, missing, present)
	}
}

// fileExists reports whether p names an existing regular file.
func fileExists(p string) bool {
	if p == "" {
		return false
	}
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// GenerateSelfSigned creates an ECDSA P-256 self-signed certificate.
//
// ECDSA rather than RSA is deliberate: it generates in milliseconds instead of
// seconds, and the smaller handshake messages matter on the constrained relays
// this project targets. TLS 1.3 does not allow RSA key exchange anyway, so the
// only cost is that a very old client cannot connect — which is acceptable for
// a modern relay.
func GenerateSelfSigned(opts SelfSignedOptions) (tls.Certificate, error) {
	if opts.CommonName == "" {
		opts.CommonName = "porttransit-relay"
	}
	if opts.ValidFor == 0 {
		// Zero means "unspecified", so the default applies. A negative lifetime
		// is honoured rather than replaced: it is how an already-expired
		// certificate is expressed, and silently turning it into a ten-year
		// certificate would make a deliberate request indistinguishable from a
		// default one.
		opts.ValidFor = 3650 * 24 * time.Hour
	}
	if len(opts.DNSNames) == 0 && len(opts.IPAddresses) == 0 {
		opts.DNSNames = []string{"localhost"}
		opts.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cert: generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cert: generate serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: []string{"PortTransit"},
		},
		NotBefore:             now.Add(-time.Hour), // tolerate clock skew
		NotAfter:              now.Add(opts.ValidFor),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              opts.DNSNames,
		IPAddresses:           opts.IPAddresses,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cert: create: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cert: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if opts.CertFile != "" && opts.KeyFile != "" {
		if err := os.MkdirAll(filepath.Dir(opts.CertFile), 0o750); err != nil {
			return tls.Certificate{}, fmt.Errorf("cert: create dir: %w", err)
		}
		if err := os.WriteFile(opts.CertFile, certPEM, 0o644); err != nil {
			return tls.Certificate{}, fmt.Errorf("cert: write %s: %w", opts.CertFile, err)
		}
		// The key is 0600: anyone who can read it can impersonate the relay.
		if err := os.MkdirAll(filepath.Dir(opts.KeyFile), 0o750); err != nil {
			return tls.Certificate{}, fmt.Errorf("cert: create dir: %w", err)
		}
		if err := os.WriteFile(opts.KeyFile, keyPEM, 0o600); err != nil {
			return tls.Certificate{}, fmt.Errorf("cert: write %s: %w", opts.KeyFile, err)
		}
	}

	return tls.X509KeyPair(certPEM, keyPEM)
}

// CertificateFingerprint returns the SHA-256 fingerprint of a certificate's
// DER encoding, formatted the way the Web GUI and the client both display it:
// colon-separated uppercase hex.
//
// Pinning this value is how a client trusts a self-signed relay without
// disabling verification entirely.
func CertificateFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return formatFingerprint(sha256Sum(cert.Raw))
}

// formatFingerprint renders a digest as colon-separated uppercase hex.
//
// It is separate from CertificateFingerprint because FingerprintPin.Display
// needs the same rendering for a digest that arrived as hex text rather than as
// a certificate, and an operator comparing two fingerprints character by
// character must never be shown two different spellings of the same value.
func formatFingerprint(sum []byte) string {
	const hexDigits = "0123456789ABCDEF"
	if len(sum) == 0 {
		return ""
	}
	out := make([]byte, 0, len(sum)*3-1)
	for i, b := range sum {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
	}
	return string(out)
}

// sha256Sum returns the SHA-256 digest of b.
func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// LoadCertificateFile parses the first certificate in a PEM or DER file.
//
// It returns the parsed certificate rather than only its fingerprint so a caller
// that wants to print the subject or the expiry alongside the fingerprint — the
// CLI does — does not have to parse the file a second time.
//
// Both encodings are accepted. A relay writes PEM, because that is what
// tls.LoadX509KeyPair and every certificate tool in the ecosystem expect, but a
// file exported from a certificate store is often DER, and telling an operator
// to convert it first is a step they will skip — or worse, get wrong and pin the
// fingerprint of a file the relay never presents.
//
// "First certificate" rather than "leaf" is the honest description: a bundle may
// hold a chain, and the certificate a relay presents is always the first entry.
// A caller that wanted a different entry would have no way to say which.
func LoadCertificateFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cert: read %s: %w", path, err)
	}
	return ParseCertificateBytes(path, data)
}

// ParseCertificateBytes parses the first certificate in data, which may be PEM
// or DER.
func ParseCertificateBytes(name string, data []byte) (*x509.Certificate, error) {
	der := data
	if first, _ := pem.Decode(data); first != nil {
		// A PEM file may open with a banner or hold several blocks, so the
		// first CERTIFICATE block is searched for rather than the first block
		// being assumed to be one.
		der = nil
		rest := data
		for {
			block, remainder := pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				der = block.Bytes
				break
			}
			rest = remainder
		}
		if der == nil {
			return nil, fmt.Errorf("cert: %s holds no CERTIFICATE block", name)
		}
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("cert: parse %s: %w", name, err)
	}
	return leaf, nil
}
