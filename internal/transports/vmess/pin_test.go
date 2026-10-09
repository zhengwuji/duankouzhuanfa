package vmess

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

// VMess is normally wrapped in TLS, and its client defaults to insecure, so the
// certificate pin is the only thing that lets an operator notice a substituted
// relay certificate. These tests drive the real Dialer against a real TLS
// listener, because the pin lives inside the handshake and a stubbed handshake
// would not exercise the code the pin was added to.

// pinTestUUID is the credential every handshake in this file uses.
const pinTestUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// pinFixture is a loopback TLS relay presenting a known certificate.
type pinFixture struct {
	addr string
	leaf *x509.Certificate
	// want is the fingerprint of the certificate the relay presents, in the
	// canonical colon-separated form.
	want string
}

// startPinRelay generates a self-signed certificate and serves the VMess
// protocol handler over a real TLS listener.
//
// A real listener rather than a pipe is required: Dial opens its own TCP
// connection, so there is no seam at which to inject one. The TLS wrapper is
// terminated here and the protocol handler is then run with TLS disabled, which
// leaves the client's handshake path — the part under test — entirely real.
func startPinRelay(t *testing.T) *pinFixture {
	t.Helper()

	cert, err := transport.GenerateSelfSigned(transport.SelfSignedOptions{
		CommonName:  "vmess-pin-relay",
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
					Timeout: 5 * time.Second,
					Settings: transport.Settings{
						SettingUUID: pinTestUUID,
						SettingTLS:  false,
					},
				})
				if err == nil && st != nil {
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
		"surrounded by whitespace": "\t" + relay.want + "\r\n",
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
	// Both fingerprints belong in the message, so the operator can tell a stale
	// pin from a relay that changed identity.
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
					SettingUUID:            pinTestUUID,
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

// TestPinWithTLSDisabledIsStillValidated proves a malformed pin is reported even
// when the TLS wrapper is switched off, so the mistake surfaces when it is made
// rather than on the day TLS is turned back on.
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
