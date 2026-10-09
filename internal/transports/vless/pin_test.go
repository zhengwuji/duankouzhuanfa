package vless

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

// VLESS is normally deployed behind TLS, so the client-side certificate pin is
// the only thing standing between an operator and `insecure: true` on the
// transport that most installations use. These tests drive the real Dialer
// against a real TLS listener running the real Handler, because the pin lives
// inside the handshake: a test that stubbed the handshake would not be testing
// the code the pin was added to.
//
// The relay's certificate is self-signed, so `insecure` is already the
// transport's default. That makes the precedence rule — a pin beats insecure —
// the assertion that matters most here, and it is the one a weaker test would
// miss entirely.

// pinTestUUID is the credential every handshake test in this file uses.
const pinTestUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// pinFixture is a loopback TLS relay presenting a known certificate.
type pinFixture struct {
	addr string
	leaf *x509.Certificate
	// want is the fingerprint of the certificate the relay presents, in the
	// canonical colon-separated form.
	want string
}

// startPinRelay generates a self-signed certificate and serves the transport's
// Handler behind a real TLS listener.
//
// A real listener rather than a pipe is required: the client opens its own TCP
// connection, so there is no seam at which to inject one.
func startPinRelay(t *testing.T) *pinFixture {
	t.Helper()

	cert, err := transport.GenerateSelfSigned(transport.SelfSignedOptions{
		CommonName:  "vless-pin-relay",
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

	settings := transport.Settings{
		SettingUUID:     pinTestUUID,
		SettingCertFile: "",
		SettingKeyFile:  "",
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				// The handler owns the TLS wrapper, so the certificate is
				// supplied through a listener-level config the handler cannot
				// see. Serving the handshake here and then running the protocol
				// handler over the established connection exercises exactly the
				// same client code path.
				tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
				if err := tc.Handshake(); err != nil {
					conn.Close()
					return
				}
				st, err := Handler{}.Handle(context.Background(), tc, transport.HandleRequest{
					Timeout:  5 * time.Second,
					Settings: noTLS(settings),
				})
				if err == nil && st != nil {
					// Hold the stream open briefly so the client's Dial can
					// complete rather than racing a close.
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
	s := transport.Settings{SettingUUID: pinTestUUID}
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
// relay it pinned, without insecure and without a CA file.
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
// worth having.
//
// VLESS's default is insecure, so before this feature existed a client had no
// way at all to notice a substituted certificate. The pin has to refuse it.
func TestPinRejectsAMismatchedFingerprint(t *testing.T) {
	relay := startPinRelay(t)

	// A second, unrelated certificate, so the pin is well formed and the
	// failure is genuinely about the mismatch rather than about the format.
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
	// The error has to name both fingerprints: the operator needs to see what
	// the relay actually presented in order to tell a stale pin from an attack.
	for _, want := range []string{wrong, relay.want} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error %q does not name the fingerprint %s", err.Error(), want)
		}
	}
}

// TestPinTakesPrecedenceOverInsecure is the precedence rule, and it is the
// assertion most specific to this transport.
//
// `insecure` defaults to true here, so a client that let it win would never
// check the pin at all — the setting would look configured and do nothing.
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
// locally.
//
// A pin that silently disables verification is the worst possible outcome, so a
// malformed value must be an error. Asserting it against a dead address also
// proves the check runs before the socket is opened: the operator must not be
// left reading a connection error when the real fault is a mistyped setting.
func TestMalformedPinIsRejectedWithoutDialling(t *testing.T) {
	// A port nothing is listening on. If the pin were validated after the
	// dial, the error would be a connection refusal instead.
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
					SettingUUID:            pinTestUUID,
					SettingCertFingerprint: pin,
				},
			})
			if err == nil {
				t.Fatalf("Dial accepted the malformed pin %q", pin)
			}
			if !errors.Is(err, transport.ErrBadFingerprint) {
				t.Errorf("the error %v does not wrap ErrBadFingerprint; a malformed pin must not be reported as a network failure", err)
			}
			if !strings.Contains(err.Error(), SettingCertFingerprint) {
				t.Errorf("the error %q does not name the %s setting", err.Error(), SettingCertFingerprint)
			}
		})
	}
}

// TestNoPinLeavesInsecureAlone is the compatibility assertion.
//
// A configuration with no certFingerprint has to behave exactly as it did before
// the setting existed, in both directions of the insecure flag.
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

// TestPinWithTLSDisabledIsStillValidated proves a malformed pin is reported even
// when the TLS wrapper is switched off.
//
// The setting is still wrong, and an operator would otherwise discover it only
// on the day they turned TLS back on — by which point the connection is being
// refused by a relay that has nothing to do with the mistake.
func TestPinWithTLSDisabledIsStillValidated(t *testing.T) {
	_, err := Dialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: "127.0.0.1:1",
		Request:    &transport.Request{Command: transport.CmdConnectTCP, Target: "example.com:443"},
		Timeout:    time.Second,
		Settings: transport.Settings{
			SettingUUID:            pinTestUUID,
			SettingTLS:             false,
			SettingCertFingerprint: "aabbcc",
		},
	})
	if err == nil {
		t.Fatal("a malformed pin was ignored when TLS was disabled")
	}
	if !errors.Is(err, transport.ErrBadFingerprint) {
		t.Errorf("the error %v does not wrap ErrBadFingerprint", err)
	}
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
