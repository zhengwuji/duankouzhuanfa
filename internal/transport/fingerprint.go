package transport

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// FingerprintHexLen is the number of hex characters in a SHA-256 fingerprint:
// two per digest byte.
const FingerprintHexLen = 64

// ErrBadFingerprint reports a pinned certificate fingerprint that cannot be a
// SHA-256 digest.
//
// It is a sentinel rather than a bare message so a caller can classify the
// failure without matching on text. Every occurrence of it is a configuration
// typo, and the one outcome this whole feature must never produce is a client
// that accepts a connection while checking nothing — so the value is rejected
// loudly rather than being treated as "no pin configured".
var ErrBadFingerprint = errors.New("invalid certificate fingerprint")

// FingerprintPin is a validated SHA-256 certificate fingerprint, held in the
// normalised form ParseFingerprintPin produces: lowercase hex, no separators.
//
// Keeping the normalised form rather than the operator's spelling is what makes
// the per-handshake comparison a plain byte compare instead of a re-parse.
type FingerprintPin string

// ParseFingerprintPin validates and normalises a fingerprint from configuration.
//
// The accepted input is deliberately forgiving about spelling: case is ignored,
// and colons, dashes, spaces, tabs and newlines are stripped. Operators copy
// these values out of browsers, out of `porttransit fingerprint`, and out of
// other tools, and each of those writes the separators differently. Rejecting
// a value for its punctuation would only teach people to reach for
// `insecure: true` instead.
//
// What is *not* forgiving is the length and the character set. Only the exact
// empty string means "no pin": an absent setting never reaches this function,
// and everything else — a truncated paste, a stray character, a fingerprint
// from a different hash algorithm — is an error naming what was wrong with it.
func ParseFingerprintPin(s string) (FingerprintPin, error) {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ':', '-', ' ', '\t', '\n', '\r':
			// Separators carry no information; the digest is the hex digits.
			continue
		}
		if r >= 'A' && r <= 'F' {
			r += 'a' - 'A'
		}
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			b.WriteRune(r)
			continue
		}
		return "", fmt.Errorf("%w: %q contains %q, which is not a hex digit", ErrBadFingerprint, s, r)
	}

	out := b.String()
	if len(out) != FingerprintHexLen {
		return "", fmt.Errorf("%w: %q has %d hex digits, want %d (a SHA-256 digest)",
			ErrBadFingerprint, s, len(out), FingerprintHexLen)
	}
	return FingerprintPin(out), nil
}

// Matches reports whether cert's leaf certificate is the pinned one.
//
// A nil certificate, or an empty pin, never matches: both mean "there is
// nothing to compare", and answering true there would turn a missing pin into a
// silent accept.
func (p FingerprintPin) Matches(cert *x509.Certificate) bool {
	if p == "" || cert == nil {
		return false
	}
	want, err := hex.DecodeString(string(p))
	if err != nil {
		// Unreachable for a pin built by ParseFingerprintPin, but a value
		// constructed by hand must not be treated as a match.
		return false
	}
	// Constant-time out of consistency with the other credential checks in this
	// tree. A fingerprint is public, so the timing here is not actually
	// sensitive; the comparison is simply too cheap to justify a second idiom.
	return subtle.ConstantTimeCompare(sha256Sum(cert.Raw), want) == 1
}

// Display renders the pin the way the Web GUI and `porttransit fingerprint`
// print fingerprints: colon-separated uppercase hex, so a value in an error
// message can be compared character for character with what was printed.
func (p FingerprintPin) Display() string {
	sum, err := hex.DecodeString(string(p))
	if err != nil {
		return string(p)
	}
	return formatFingerprint(sum)
}

// ClientCertPolicy is the client-side certificate-verification policy for one
// dial, resolved from a transport's settings.
type ClientCertPolicy struct {
	// InsecureSkipVerify is what the transport must assign to
	// tls.Config.InsecureSkipVerify.
	InsecureSkipVerify bool
	// Pin, when non-empty, must be matched against the relay's leaf
	// certificate.
	Pin FingerprintPin
}

// ResolveClientCertPolicy reads the fingerprint pin from s and applies it to the
// caller's already-resolved insecure flag.
//
// The precedence rule is the point of this function. When a pin is configured it
// wins outright: chain verification is switched off and replaced by the pin, and
// a configured `insecure: true` is ignored. A pin is a much stronger statement
// than "accept anything", so a client that honoured insecure while a pin was
// set would leave the operator believing their relay was pinned when nothing
// was checked at all.
//
// Chain verification has to be switched off for the pin to work, which is not a
// weakening: a self-signed relay — the case this exists for — has no chain to
// verify, so the pin is the verification.
//
// insecure is passed in rather than read here because its default differs per
// transport, and that default is load-bearing enough to stay visible at the
// call site.
//
// When no pin is configured the returned policy is exactly the caller's insecure
// flag, so an existing deployment behaves as it did before this feature existed.
func ResolveClientCertPolicy(s Settings, fingerprintKey string, insecure bool) (ClientCertPolicy, error) {
	raw := s.GetString(fingerprintKey, "")
	if raw == "" {
		return ClientCertPolicy{InsecureSkipVerify: insecure}, nil
	}
	pin, err := ParseFingerprintPin(raw)
	if err != nil {
		// The setting name is attached here rather than in the parser because
		// the key belongs to the transport, not to the pin format.
		return ClientCertPolicy{}, fmt.Errorf("transport: setting %s: %w", fingerprintKey, err)
	}
	return ClientCertPolicy{InsecureSkipVerify: true, Pin: pin}, nil
}

// VerifyPeerCertificates returns nil when the peer's certificate chain satisfies
// the policy.
//
// It is meant to be called from tls.Config.VerifyConnection (and from uTLS's
// mirror of that field), which is why it takes the chain rather than a
// ConnectionState: the two libraries' state types are distinct, so a shared
// helper cannot take either one, but both expose the parsed peer chain.
func (p ClientCertPolicy) VerifyPeerCertificates(certs []*x509.Certificate) error {
	if p.Pin == "" {
		return nil
	}
	if len(certs) == 0 {
		// The relay sent no certificate at all. There is nothing to match
		// against, and returning nil here would be precisely the "verification
		// ran and checked nothing" outcome the pin exists to prevent.
		return fmt.Errorf("transport: the relay sent no certificate to match against the pinned %s", p.Pin.Display())
	}
	if !p.Pin.Matches(certs[0]) {
		return fmt.Errorf("transport: relay certificate fingerprint %s does not match the pinned %s",
			CertificateFingerprint(certs[0]), p.Pin.Display())
	}
	return nil
}

// VerifyConnection returns a crypto/tls callback that enforces the policy, or
// nil when no pin is configured.
//
// Returning nil rather than an always-succeeding closure matters: assigning a
// no-op to tls.Config.VerifyConnection would put every handshake on a code path
// it never took before, and a client with no pin configured is supposed to run
// exactly the code it used to.
func (p ClientCertPolicy) VerifyConnection() func(tls.ConnectionState) error {
	if p.Pin == "" {
		return nil
	}
	return func(cs tls.ConnectionState) error {
		return p.VerifyPeerCertificates(cs.PeerCertificates)
	}
}

// loggedFingerprints records the fingerprints already reported by
// LogCertificateFingerprint, so a relay logs its identity once rather than on
// every connection.
var loggedFingerprints sync.Map

// LogCertificateFingerprint reports a relay's leaf-certificate fingerprint so an
// operator can copy it into a client's certFingerprint setting.
//
// It is called from the relay's handshake path rather than from a startup
// routine because on a fresh install the certificate does not exist until the
// first handshake: the installer records certFile and keyFile paths and lets the
// transport generate the pair on first use. Logging at this point covers both
// that case and an operator-supplied certificate, without restructuring startup.
//
// The line is emitted once per distinct certificate per process. A relay serves
// one certificate, so "once" is what "at startup" amounts to here; without the
// dedupe the message would repeat on every connection and bury everything else
// in the log.
func LogCertificateFingerprint(log Logger, cert tls.Certificate) {
	if log == nil || len(cert.Certificate) == 0 {
		return
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		// A certificate that does not parse has no fingerprint to report. The
		// handshake itself will fail with a better message than anything
		// printable from here.
		return
	}
	fp := CertificateFingerprint(leaf)
	if _, seen := loggedFingerprints.LoadOrStore(fp, struct{}{}); seen {
		return
	}
	log.Info("relay certificate fingerprint",
		"fingerprint", fp,
		"subject", leaf.Subject.CommonName,
		"notAfter", leaf.NotAfter.Format("2006-01-02"),
	)
}
