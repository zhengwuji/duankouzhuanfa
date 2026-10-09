package transport

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// knownDigest is an arbitrary 32-byte value spelled in the three notations an
// operator actually pastes. The bytes are not a real certificate digest; the
// parser is a pure function of the text, so a fixed value makes the assertions
// readable and the accepted/rejected boundary obvious.
const (
	knownColonUpper = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
	knownBareLower  = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	knownDashed     = "aa-bb-cc-dd-ee-ff-00-11-22-33-44-55-66-77-88-99-aa-bb-cc-dd-ee-ff-00-11-22-33-44-55-66-77-88-99"
)

// TestParseFingerprintPinAcceptsEverySpelling pins the tolerant input format.
//
// The format has to be tolerant because operators copy these values out of a
// browser's certificate dialog, out of `porttransit fingerprint`, and out of
// other tools, and each writes the separators differently. A parser that
// rejected a value over its punctuation would push people towards
// `insecure: true`, which is the outcome this whole feature exists to avoid.
func TestParseFingerprintPinAcceptsEverySpelling(t *testing.T) {
	want := FingerprintPin(knownBareLower)

	cases := []struct {
		name string
		in   string
	}{
		{"colon-separated uppercase", knownColonUpper},
		{"bare lowercase", knownBareLower},
		{"dash-separated", knownDashed},
		{"bare uppercase", strings.ToUpper(knownBareLower)},
		{"spaces instead of colons", strings.ReplaceAll(knownColonUpper, ":", " ")},
		{"colon-separated lowercase", strings.ToLower(knownColonUpper)},
		{"mixed case and separators", "Aa:Bb-cc ddEeFf00112233445566778899AABBCCDDEEFF00112233445566778899"},
		{"surrounding whitespace", "  " + knownColonUpper + "\n"},
		{"tabs between groups", strings.ReplaceAll(knownColonUpper, ":", "\t")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseFingerprintPin(tc.in)
			if err != nil {
				t.Fatalf("ParseFingerprintPin(%q): %v", tc.in, err)
			}
			if got != want {
				t.Errorf("ParseFingerprintPin(%q) = %q, want the normalised %q", tc.in, got, want)
			}
		})
	}
}

// TestParseFingerprintPinRejectsMalformedInput is the most important assertion
// in this file.
//
// A typo that silently disables verification is the worst possible outcome for
// this feature: the operator believes their relay is pinned, and in fact
// anything is accepted. So every malformed value has to be an error, and the
// error has to say what was wrong with it rather than merely that something was.
func TestParseFingerprintPinRejectsMalformedInput(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"too short", "aabbcc"},
		{"one character short", knownBareLower[:len(knownBareLower)-1]},
		{"one character long", knownBareLower + "0"},
		{"sixty-four characters of the wrong alphabet", strings.Repeat("z", 64)},
		{"a SHA-1 digest", strings.Repeat("ab", 20)},
		{"an MD5 digest", strings.Repeat("ab", 16)},
		{"a non-hex character in the middle", knownBareLower[:32] + "g" + knownBareLower[33:]},
		{"a full-width digit", strings.Repeat("０", 64)},
		{"only separators", strings.Repeat(":", 63)},
		{"a base64 value", "aGVsbG8gd29ybGQgdGhpcyBpcyBub3QgYSBmaW5nZXJwcmludA=="},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseFingerprintPin(tc.in)
			if err == nil {
				t.Fatalf("ParseFingerprintPin(%q) accepted the value as %q, want an error", tc.in, got)
			}
			if !errors.Is(err, ErrBadFingerprint) {
				t.Errorf("the error is %v, want it to wrap ErrBadFingerprint", err)
			}
		})
	}
}

// TestParseFingerprintPinReportsWhatIsWrong proves the message is diagnostic.
//
// The two failure shapes an operator actually hits are a truncated paste and a
// stray character, and each needs a different fix. An error that only said
// "invalid fingerprint" would leave them comparing 64 characters by eye.
func TestParseFingerprintPinReportsWhatIsWrong(t *testing.T) {
	t.Run("a length problem names both lengths", func(t *testing.T) {
		_, err := ParseFingerprintPin("aabbcc")
		if err == nil {
			t.Fatal("a six-character fingerprint was accepted")
		}
		msg := err.Error()
		for _, want := range []string{"6", "64"} {
			if !strings.Contains(msg, want) {
				t.Errorf("the error %q does not mention %s", msg, want)
			}
		}
	})

	t.Run("a character problem names the character", func(t *testing.T) {
		_, err := ParseFingerprintPin(knownBareLower[:32] + "g" + knownBareLower[33:])
		if err == nil {
			t.Fatal("a fingerprint containing 'g' was accepted")
		}
		if !strings.Contains(err.Error(), "g") {
			t.Errorf("the error %q does not name the offending character", err.Error())
		}
	})
}

// TestFingerprintPinMatches covers the comparison itself, including the two
// cases where "nothing to compare" must not read as a match.
func TestFingerprintPinMatches(t *testing.T) {
	cert := selfSignedForTest(t, "matching-relay")
	other := selfSignedForTest(t, "other-relay")

	pin, err := ParseFingerprintPin(CertificateFingerprint(cert))
	if err != nil {
		t.Fatalf("ParseFingerprintPin(CertificateFingerprint(cert)): %v", err)
	}

	if !pin.Matches(cert) {
		t.Error("a pin did not match the certificate it was derived from")
	}
	if pin.Matches(other) {
		t.Error("a pin matched a different certificate")
	}
	if pin.Matches(nil) {
		t.Error("a pin matched a nil certificate")
	}

	// An empty pin means "no pin configured", and a hand-built pin holding
	// non-hex text is unusable. Neither may be treated as a match.
	if FingerprintPin("").Matches(cert) {
		t.Error("an empty pin matched a certificate")
	}
	if FingerprintPin("not-hex").Matches(cert) {
		t.Error("a malformed pin matched a certificate")
	}
}

// TestFingerprintPinDisplayRoundTrips proves the pin renders in the same
// notation CertificateFingerprint uses.
//
// The value is printed so an operator can compare it character by character
// against what `porttransit fingerprint` and the relay's log show. Two different
// spellings of one digest would make that comparison meaningless.
func TestFingerprintPinDisplayRoundTrips(t *testing.T) {
	cert := selfSignedForTest(t, "display-relay")
	want := CertificateFingerprint(cert)

	pin, err := ParseFingerprintPin(strings.ReplaceAll(strings.ToLower(want), ":", ""))
	if err != nil {
		t.Fatalf("ParseFingerprintPin: %v", err)
	}
	if got := pin.Display(); got != want {
		t.Errorf("Display() = %q, want the canonical %q", got, want)
	}
	if FingerprintPin("").Display() != "" {
		t.Error("an empty pin rendered as something other than the empty string")
	}
}

// TestResolveClientCertPolicyWithNoPinLeavesInsecureAlone is the compatibility
// assertion.
//
// Rule three of this feature is that a configuration with no pin behaves exactly
// as it did before the setting existed. That means the caller's insecure flag
// passes through untouched, in both directions.
func TestResolveClientCertPolicyWithNoPinLeavesInsecureAlone(t *testing.T) {
	for _, insecure := range []bool{true, false} {
		policy, err := ResolveClientCertPolicy(Settings{}, "certFingerprint", insecure)
		if err != nil {
			t.Fatalf("ResolveClientCertPolicy with no pin (insecure=%v): %v", insecure, err)
		}
		if policy.InsecureSkipVerify != insecure {
			t.Errorf("with no pin and insecure=%v the policy reports InsecureSkipVerify=%v", insecure, policy.InsecureSkipVerify)
		}
		if policy.Pin != "" {
			t.Errorf("with no pin configured the policy carries the pin %q", policy.Pin)
		}
		if cb := policy.VerifyConnection(); cb != nil {
			t.Error("with no pin configured a VerifyConnection callback was installed, so every handshake takes a code path it did not take before")
		}
	}

	// An explicitly empty value is the same as an absent one: a config written
	// with "certFingerprint": "" is not an error, it is just unset.
	policy, err := ResolveClientCertPolicy(Settings{"certFingerprint": ""}, "certFingerprint", true)
	if err != nil {
		t.Fatalf("ResolveClientCertPolicy with an empty value: %v", err)
	}
	if policy.InsecureSkipVerify != true || policy.Pin != "" {
		t.Errorf("an empty setting produced %+v, want insecure passthrough with no pin", policy)
	}
}

// TestResolveClientCertPolicyPinOverridesInsecure is the precedence rule.
//
// A pin is a far stronger statement than "accept anything". A client that
// honoured insecure while a pin was configured would leave the operator
// believing their relay was pinned while nothing at all was checked, so the pin
// must win — including, and especially, when insecure is explicitly true.
func TestResolveClientCertPolicyPinOverridesInsecure(t *testing.T) {
	for _, insecure := range []bool{true, false} {
		policy, err := ResolveClientCertPolicy(Settings{"certFingerprint": knownColonUpper}, "certFingerprint", insecure)
		if err != nil {
			t.Fatalf("ResolveClientCertPolicy (insecure=%v): %v", insecure, err)
		}
		if policy.Pin == "" {
			t.Fatalf("with insecure=%v the configured pin was dropped", insecure)
		}
		if !policy.InsecureSkipVerify {
			t.Errorf("with a pin configured InsecureSkipVerify is false, so chain verification runs against a self-signed relay and the pin is never reached")
		}
		if cb := policy.VerifyConnection(); cb == nil {
			t.Error("with a pin configured no VerifyConnection callback was installed, so nothing checks the fingerprint")
		}
	}
}

// TestResolveClientCertPolicyRejectsAMalformedPin proves a typo fails the dial
// rather than disabling verification.
func TestResolveClientCertPolicyRejectsAMalformedPin(t *testing.T) {
	_, err := ResolveClientCertPolicy(Settings{"certFingerprint": "aabbcc"}, "certFingerprint", true)
	if err == nil {
		t.Fatal("a malformed fingerprint was accepted")
	}
	if !errors.Is(err, ErrBadFingerprint) {
		t.Errorf("the error is %v, want it to wrap ErrBadFingerprint", err)
	}
	// The setting name has to be in the message: the operator needs to know
	// which key to fix.
	if !strings.Contains(err.Error(), "certFingerprint") {
		t.Errorf("the error %q does not name the setting", err.Error())
	}
}

// TestVerifyPeerCertificates covers the check the handshake actually runs.
func TestVerifyPeerCertificates(t *testing.T) {
	cert := selfSignedForTest(t, "pinned-relay")
	other := selfSignedForTest(t, "impostor-relay")

	matching, err := ResolveClientCertPolicy(Settings{"certFingerprint": CertificateFingerprint(cert)}, "certFingerprint", false)
	if err != nil {
		t.Fatalf("ResolveClientCertPolicy: %v", err)
	}
	mismatched, err := ResolveClientCertPolicy(Settings{"certFingerprint": CertificateFingerprint(other)}, "certFingerprint", false)
	if err != nil {
		t.Fatalf("ResolveClientCertPolicy: %v", err)
	}

	if err := matching.VerifyPeerCertificates([]*x509.Certificate{cert}); err != nil {
		t.Errorf("a matching chain was rejected: %v", err)
	}

	err = mismatched.VerifyPeerCertificates([]*x509.Certificate{cert})
	if err == nil {
		t.Fatal("a mismatched chain was accepted, which is the man-in-the-middle case this exists to stop")
	}
	// Both fingerprints belong in the message: the operator has to see which
	// one the relay presented in order to decide whether the relay changed or
	// the pin is stale.
	for _, want := range []string{CertificateFingerprint(cert), CertificateFingerprint(other)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q does not name the fingerprint %s", err.Error(), want)
		}
	}

	// A peer that sends no certificate at all must be refused rather than
	// treated as "nothing to compare".
	if err := matching.VerifyPeerCertificates(nil); err == nil {
		t.Error("a peer that presented no certificate was accepted against a pin")
	}
}

// TestVerifyPeerCertificatesWithNoPinIsANoOp proves the policy's own check is
// inert when no pin is configured, so a transport that calls it unconditionally
// does not change behaviour for existing deployments.
func TestVerifyPeerCertificatesWithNoPinIsANoOp(t *testing.T) {
	var policy ClientCertPolicy
	if err := policy.VerifyPeerCertificates(nil); err != nil {
		t.Errorf("a policy with no pin rejected an empty chain: %v", err)
	}
}

// TestCertificateFingerprintFormat pins the output shape the rest of the tree
// depends on: colon-separated uppercase hex, 95 characters for a SHA-256 digest.
//
// The Web GUI, the relay's log line and `porttransit fingerprint` all print this
// value for an operator to compare against a client's setting, so a change in
// its spelling is a user-visible break even though nothing would fail to
// compile.
func TestCertificateFingerprintFormat(t *testing.T) {
	cert := selfSignedForTest(t, "format-relay")
	fp := CertificateFingerprint(cert)

	if len(fp) != 32*3-1 {
		t.Errorf("the fingerprint is %d characters, want %d", len(fp), 32*3-1)
	}
	if fp != strings.ToUpper(fp) {
		t.Errorf("the fingerprint %q is not uppercase", fp)
	}
	if strings.Count(fp, ":") != 31 {
		t.Errorf("the fingerprint %q has %d separators, want 31", fp, strings.Count(fp, ":"))
	}
	// It must survive its own parser, or an operator could not copy the value
	// the tool printed back into a configuration.
	if _, err := ParseFingerprintPin(fp); err != nil {
		t.Errorf("the printed fingerprint does not parse: %v", err)
	}
	if CertificateFingerprint(nil) != "" {
		t.Error("CertificateFingerprint(nil) is not the empty string")
	}
}

// TestLoadCertificateFileReadsPEMAndDER proves the CLI helper accepts both
// encodings.
//
// A relay writes PEM, but a certificate exported from a store is often DER, and
// telling an operator to convert it first is a step they will skip — or worse,
// get wrong and pin the fingerprint of a file the relay never presents.
func TestLoadCertificateFileReadsPEMAndDER(t *testing.T) {
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "relay.crt")
	cert, err := GenerateSelfSigned(SelfSignedOptions{CommonName: "file-relay", CertFile: pemPath, KeyFile: filepath.Join(dir, "relay.key")})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	pemLeaf, err := LoadCertificateFile(pemPath)
	if err != nil {
		t.Fatalf("LoadCertificateFile on PEM: %v", err)
	}
	if pemLeaf.Subject.CommonName != "file-relay" {
		t.Errorf("the PEM file parsed to CN %q, want \"file-relay\"", pemLeaf.Subject.CommonName)
	}

	derPath := filepath.Join(dir, "relay.der")
	if err := os.WriteFile(derPath, cert.Certificate[0], 0o644); err != nil {
		t.Fatal(err)
	}
	derLeaf, err := LoadCertificateFile(derPath)
	if err != nil {
		t.Fatalf("LoadCertificateFile on DER: %v", err)
	}
	if CertificateFingerprint(derLeaf) != CertificateFingerprint(pemLeaf) {
		t.Error("the same certificate in PEM and DER produced two different fingerprints")
	}
}

// TestParseCertificateBytesSearchesForTheCertificateBlock proves a PEM file is
// searched rather than assumed to open with a certificate.
//
// A bundle exported from a tool often carries a banner comment, and a key file
// carries a PRIVATE KEY block. Taking the first block blindly would either fail
// on the banner or, far worse, fingerprint the wrong block.
func TestParseCertificateBytesSearchesForTheCertificateBlock(t *testing.T) {
	dir := t.TempDir()
	cert, err := GenerateSelfSigned(SelfSignedOptions{CommonName: "bundled-relay"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	want := CertificateFingerprint(mustParseLeaf(t, cert.Certificate[0]))

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a real key")})

	t.Run("a leading key block is skipped", func(t *testing.T) {
		leaf, err := ParseCertificateBytes("bundle", append(keyPEM, certPEM...))
		if err != nil {
			t.Fatalf("ParseCertificateBytes: %v", err)
		}
		if got := CertificateFingerprint(leaf); got != want {
			t.Errorf("the fingerprint is %s, want %s", got, want)
		}
	})

	t.Run("a leading banner is tolerated", func(t *testing.T) {
		leaf, err := ParseCertificateBytes("bundle", append([]byte("# exported by some tool\n\n"), certPEM...))
		if err != nil {
			t.Fatalf("ParseCertificateBytes: %v", err)
		}
		if got := CertificateFingerprint(leaf); got != want {
			t.Errorf("the fingerprint is %s, want %s", got, want)
		}
	})

	t.Run("a PEM file with no certificate block is an error", func(t *testing.T) {
		_, err := ParseCertificateBytes("keyonly", keyPEM)
		if err == nil {
			t.Fatal("a PEM file holding only a private key was accepted as a certificate")
		}
		if !strings.Contains(err.Error(), "keyonly") {
			t.Errorf("the error %q does not name the file", err.Error())
		}
	})

	t.Run("garbage is an error naming the file", func(t *testing.T) {
		_, err := ParseCertificateBytes("garbage.crt", []byte("this is not a certificate"))
		if err == nil {
			t.Fatal("garbage was accepted as a certificate")
		}
		if !strings.Contains(err.Error(), "garbage.crt") {
			t.Errorf("the error %q does not name the file", err.Error())
		}
	})

	t.Run("a missing file is an error", func(t *testing.T) {
		if _, err := LoadCertificateFile(filepath.Join(dir, "absent.crt")); err == nil {
			t.Fatal("a missing certificate file was accepted")
		}
	})
}

// TestLogCertificateFingerprintReportsOnce proves the relay-side convenience
// logs its identity exactly once per certificate.
//
// Once is the whole point: the call sits in the handshake path because a fresh
// install has no certificate until the first handshake generates one, and a
// message repeated on every connection would bury everything else in the log.
func TestLogCertificateFingerprintReportsOnce(t *testing.T) {
	cert, err := GenerateSelfSigned(SelfSignedOptions{CommonName: "logged-relay"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	want := CertificateFingerprint(mustParseLeaf(t, cert.Certificate[0]))

	rec := &recordingLogger{}
	LogCertificateFingerprint(rec, cert)
	LogCertificateFingerprint(rec, cert)
	LogCertificateFingerprint(rec, cert)

	if len(rec.infos) != 1 {
		t.Fatalf("the fingerprint was logged %d times, want exactly 1", len(rec.infos))
	}
	joined := strings.Join(rec.infos[0], " ")
	if !strings.Contains(joined, want) {
		t.Errorf("the log line %q does not carry the fingerprint %s", joined, want)
	}
	if !strings.Contains(joined, "logged-relay") {
		t.Errorf("the log line %q does not carry the subject", joined)
	}

	// A distinct certificate must still be reported: the dedupe is per
	// certificate, not "once per process", so a relay that reloaded a new
	// certificate would still tell the operator.
	other, err := GenerateSelfSigned(SelfSignedOptions{CommonName: "second-relay"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	LogCertificateFingerprint(rec, other)
	if len(rec.infos) != 2 {
		t.Errorf("a second, different certificate was not logged; %d lines recorded", len(rec.infos))
	}

	// Nothing about a nil logger or an empty certificate may panic: this is
	// called from inside a handshake path.
	LogCertificateFingerprint(nil, cert)
	LogCertificateFingerprint(rec, tls.Certificate{})
}

// recordingLogger captures the info lines LogCertificateFingerprint emits.
type recordingLogger struct {
	infos [][]string
}

func (r *recordingLogger) Debug(string, ...any) {}
func (r *recordingLogger) Info(msg string, args ...any) {
	line := []string{msg}
	for _, a := range args {
		line = append(line, fmt.Sprint(a))
	}
	r.infos = append(r.infos, line)
}
func (r *recordingLogger) Warn(string, ...any)  {}
func (r *recordingLogger) Error(string, ...any) {}

// selfSignedForTest generates a certificate with a distinctive common name.
func selfSignedForTest(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	cert, err := GenerateSelfSigned(SelfSignedOptions{CommonName: cn})
	if err != nil {
		t.Fatalf("GenerateSelfSigned(%q): %v", cn, err)
	}
	return mustParseLeaf(t, cert.Certificate[0])
}

// mustParseLeaf parses a DER certificate or fails the test.
func mustParseLeaf(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return leaf
}

// TestFingerprintNormalisationIsNotAffectedByEncoding guards the hex decoding
// path: an uppercase digest must produce the same 32 bytes as its lowercase
// spelling, since that is what the constant-time compare runs over.
func TestFingerprintNormalisationIsNotAffectedByEncoding(t *testing.T) {
	upper, err := ParseFingerprintPin(knownColonUpper)
	if err != nil {
		t.Fatalf("ParseFingerprintPin(upper): %v", err)
	}
	lower, err := ParseFingerprintPin(knownBareLower)
	if err != nil {
		t.Fatalf("ParseFingerprintPin(lower): %v", err)
	}
	if upper != lower {
		t.Fatalf("the two spellings normalised differently: %q vs %q", upper, lower)
	}

	decoded, err := hex.DecodeString(string(upper))
	if err != nil {
		t.Fatalf("the normalised form is not valid hex: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("the normalised form decodes to %d bytes, want 32", len(decoded))
	}
}
