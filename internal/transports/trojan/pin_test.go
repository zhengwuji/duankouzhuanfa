package trojan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"porttransit/internal/transport"
)

// Trojan is TLS with a password hash inside the stream, and its client defaults
// to insecure. The certificate pin is therefore the only thing that lets an
// operator notice a relay certificate being substituted, and — because Trojan's
// whole design premise is that the relay is indistinguishable from an ordinary
// HTTPS site — an attacker who can substitute the certificate has exactly the
// cover story they need. These tests drive the real Dialer against a real TLS
// listener because the pin lives inside the handshake.

// pinTestPassword is the credential every handshake here uses.
const pinTestPassword = "pin-test-password"

// pinFixture is a loopback TLS relay presenting a known certificate.
type pinFixture struct {
	addr string
	leaf *x509.Certificate
	// want is the fingerprint of the certificate the relay presents, in the
	// canonical colon-separated form.
	want string
}

// startPinRelay generates a self-signed certificate and serves the Trojan
// protocol handler over a real TLS listener.
//
// A real listener rather than a pipe is required: Dial opens its own TCP
// connection, so there is no seam at which to inject one. The TLS wrapper is
// terminated here and the protocol handler then runs over the established
// connection, which leaves the client's handshake path — the part under test —
// entirely real.
func startPinRelay(t *testing.T) *pinFixture {
	t.Helper()

	cert, err := transport.GenerateSelfSigned(transport.SelfSignedOptions{
		CommonName:  "trojan-pin-relay",
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse the generated certificate: %v", err)
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
				tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
				if err := tc.Handshake(); err != nil {
					conn.Close()
					return
				}
				st, err := Handler{}.Handle(context.Background(), tc, transport.HandleRequest{
					Timeout:  5 * time.Second,
					Settings: transport.Settings{SettingPassword: pinTestPassword},
				})
				if err == nil && st != nil {
					// Hold the stream open briefly so the client's Dial can
					// complete rather than racing a close. Without a fallback
					// configured, a mismatch closes instead.
					_, _ = io.Copy(io.Discard, st)
					st.Close()
				}
			}(conn)
		}
	}()

	return &pinFixture{addr: ln.Addr().String(), leaf: leaf, want: transport.CertificateFingerprint(leaf)}
}

// dialPin runs the real Dialer against the fixture with the given client
// settings.
func (f *pinFixture) dial(t *testing.T, settings transport.Settings) (transport.Stream, error) {
	t.Helper()
	s := transport.Settings{SettingPassword: pinTestPassword}
	for k, v := range settings {
		s[k] = v
	}
	return Dialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: f.addr,
		Request:    &transport.Request{Command: transport.CmdConnectTCP, Target: "example.com:443", Transport: Name},
		Timeout:    5 * time.Second,
		Settings:   s,
	})
}

// TestPinAcceptsAMatchingFingerprint proves a pinned client connects to the
// relay it pinned, with no CA file and no insecure flag.
func TestPinAcceptsAMatchingFingerprint(t *testing.T) {
	relay := startPinRelay(t)

	stream, err := relay.dial(t, transport.Settings{SettingCertFingerprint: relay.want})
	if err != nil {
		t.Fatalf("Dial with a correct pin: %v", err)
	}
	t.Cleanup(func() { stream.Close() })

	if got := stream.Request().Target; got != "example.com:443" {
		t.Errorf("the client stream reports target %q, want example.com:443", got)
	}
}

// TestPinToleratesPastedSpellings proves the accepted input format end to end.
func TestPinToleratesPastedSpellings(t *testing.T) {
	relay := startPinRelay(t)

	spellings := map[string]string{
		"lowercase":                strings.ToLower(relay.want),
		"bare hex":                 strings.ReplaceAll(relay.want, ":", ""),
		"dashes":                   strings.ReplaceAll(relay.want, ":", "-"),
		"spaces":                   strings.ReplaceAll(relay.want, ":", " "),
		"surrounded by whitespace": " " + relay.want + "\n",
	}

	for name, spelling := range spellings {
		t.Run(name, func(t *testing.T) {
			stream, err := relay.dial(t, transport.Settings{SettingCertFingerprint: spelling})
			if err != nil {
				t.Fatalf("Dial with the pin spelled as %q: %v", spelling, err)
			}
			stream.Close()
		})
	}
}

// TestPinRejectsAMismatchedFingerprint is the assertion that makes the setting
// worth having: a substituted certificate must be refused.
//
// It matters more here than on the other transports. Trojan's camouflage is that
// the relay looks like an ordinary website, so an attacker who can substitute
// the certificate gets a cover story for free; without a pin there is nothing to
// notice.
func TestPinRejectsAMismatchedFingerprint(t *testing.T) {
	relay := startPinRelay(t)

	other, err := transport.GenerateSelfSigned(transport.SelfSignedOptions{CommonName: "impostor"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	otherLeaf, err := x509.ParseCertificate(other.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	wrong := transport.CertificateFingerprint(otherLeaf)

	stream, err := relay.dial(t, transport.Settings{SettingCertFingerprint: wrong})
	if err == nil {
		stream.Close()
		t.Fatal("the client accepted a relay whose certificate did not match the pin")
	}
	for _, want := range []string{wrong, relay.want} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q does not name the fingerprint %s", err.Error(), want)
		}
	}
}

// TestPinTakesPrecedenceOverInsecure is the precedence rule.
//
// `insecure` defaults to true for this transport, so a client that let it win
// would never check the pin at all — the setting would look configured and do
// nothing.
func TestPinTakesPrecedenceOverInsecure(t *testing.T) {
	relay := startPinRelay(t)

	other, err := transport.GenerateSelfSigned(transport.SelfSignedOptions{CommonName: "impostor"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	otherLeaf, err := x509.ParseCertificate(other.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	wrong := transport.CertificateFingerprint(otherLeaf)

	t.Run("a correct pin still connects with insecure set", func(t *testing.T) {
		stream, err := relay.dial(t, transport.Settings{
			SettingCertFingerprint:    relay.want,
			SettingInsecureSkipVerify: true,
		})
		if err != nil {
			t.Fatalf("Dial with a correct pin and insecure=true: %v", err)
		}
		stream.Close()
	})

	t.Run("a wrong pin is refused even though insecure is set", func(t *testing.T) {
		stream, err := relay.dial(t, transport.Settings{
			SettingCertFingerprint:    wrong,
			SettingInsecureSkipVerify: true,
		})
		if err == nil {
			stream.Close()
			t.Fatal("insecure=true overrode the pin: a certificate whose fingerprint did not match was accepted")
		}
		if !strings.Contains(err.Error(), wrong) {
			t.Errorf("the error %q does not name the pinned fingerprint", err.Error())
		}
	})
}

// TestMalformedPinIsRejectedWithoutDialling proves a typo fails loudly and
// locally, before any socket is opened.
//
// On Trojan the distinction is sharpest of all: with no fallback configured on
// this fixture, a relay-side rejection closes the connection, so a pin problem
// reported only after the dial would be indistinguishable from a relay that is
// down or a password that is wrong.
func TestMalformedPinIsRejectedWithoutDialling(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dead := ln.Addr().String()
	ln.Close()

	bad := map[string]string{
		"too short":           "aabbcc",
		"one character short": strings.Repeat("ab", 31),
		"non-hex":             strings.Repeat("z", 64),
		"a SHA-1 digest":      strings.Repeat("ab", 20),
	}

	for name, pin := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := Dialer{}.Dial(context.Background(), transport.DialRequest{
				ServerAddr: dead,
				Request:    &transport.Request{Command: transport.CmdConnectTCP, Target: "example.com:443"},
				Timeout:    2 * time.Second,
				Settings: transport.Settings{
					SettingPassword:        pinTestPassword,
					SettingCertFingerprint: pin,
				},
			})
			if err == nil {
				t.Fatalf("Dial accepted the malformed pin %q", pin)
			}
			if !errors.Is(err, transport.ErrBadFingerprint) {
				t.Errorf("the error %v does not wrap ErrBadFingerprint; a malformed pin must not look like a network failure", err)
			}
			if !strings.Contains(err.Error(), SettingCertFingerprint) {
				t.Errorf("the error %q does not name the %s setting", err.Error(), SettingCertFingerprint)
			}
		})
	}
}

// TestNoPinLeavesInsecureAlone is the compatibility assertion.
//
// A configuration with no certFingerprint must behave exactly as it did before
// the setting existed.
func TestNoPinLeavesInsecureAlone(t *testing.T) {
	relay := startPinRelay(t)

	t.Run("insecure still accepts the self-signed relay", func(t *testing.T) {
		stream, err := relay.dial(t, transport.Settings{SettingInsecureSkipVerify: true})
		if err != nil {
			t.Fatalf("Dial with insecure=true and no pin: %v", err)
		}
		stream.Close()
	})

	t.Run("an empty pin is the same as no pin", func(t *testing.T) {
		stream, err := relay.dial(t, transport.Settings{
			SettingInsecureSkipVerify: true,
			SettingCertFingerprint:    "",
		})
		if err != nil {
			t.Fatalf("Dial with an explicitly empty pin: %v", err)
		}
		stream.Close()
	})
}

// TestCertFingerprintSettingName pins the configuration key.
//
// A renamed key is silently ignored: the client would fall back to insecure and
// an operator's pin would quietly stop being enforced, with nothing failing to
// compile and no error at runtime.
func TestCertFingerprintSettingName(t *testing.T) {
	if SettingCertFingerprint != "certFingerprint" {
		t.Errorf("SettingCertFingerprint = %q, want the literal \"certFingerprint\"", SettingCertFingerprint)
	}
}
