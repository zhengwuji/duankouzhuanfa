package transport

import (
	"bytes"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// TestPreambleRoundTrip proves a frame written by the client decodes to the
// same request on the relay and passes MAC verification. Every simple
// transport depends on this, so it is the highest-value test in the package.
func TestPreambleRoundTrip(t *testing.T) {
	psk := []byte("test-pre-shared-key-0123456789")

	cases := []struct {
		name    string
		command Command
		target  string
		client  string
	}{
		{"ipv4 tcp", CmdConnectTCP, "93.184.216.34:443", "client-a"},
		{"domain tcp", CmdConnectTCP, "example.com:443", "client-a"},
		{"ipv6 tcp", CmdConnectTCP, "[2606:2800:220:1:248:1893:25c8:1946]:80", ""},
		{"domain udp", CmdUDPAssociate, "dns.example.com:53", "c2"},
		{"ping", CmdPing, "", "c3"},
		{"long domain", CmdConnectTCP, "a-very-long-subdomain-name-that-still-fits.example.com:8443", "c4"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &Preamble{
				Command:  tc.command,
				ClientID: tc.client,
				Target:   tc.target,
			}
			frame, err := EncodePreamble(src, psk)
			if err != nil {
				t.Fatalf("EncodePreamble: %v", err)
			}
			if len(frame) > PreambleMaxLen {
				t.Fatalf("encoded frame is %d bytes, exceeding the %d limit", len(frame), PreambleMaxLen)
			}

			got, err := DecodePreamble(bytes.NewReader(frame))
			if err != nil {
				t.Fatalf("DecodePreamble: %v", err)
			}
			if err := got.Verify(psk); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if err := got.Freshness(PreambleSkew); err != nil {
				t.Fatalf("Freshness: %v", err)
			}
			if got.Command != tc.command {
				t.Errorf("command = %v, want %v", got.Command, tc.command)
			}
			if got.ClientID != tc.client {
				t.Errorf("client id = %q, want %q", got.ClientID, tc.client)
			}
			if tc.command != CmdPing && got.Target != tc.target {
				t.Errorf("target = %q, want %q", got.Target, tc.target)
			}
		})
	}
}

// TestPreambleRejectsBadMAC proves a frame with a wrong key is refused, which
// is the property that keeps a relay from being an open proxy.
func TestPreambleRejectsBadMAC(t *testing.T) {
	frame, err := EncodePreamble(&Preamble{Command: CmdConnectTCP, Target: "example.com:443"}, []byte("right-key"))
	if err != nil {
		t.Fatalf("EncodePreamble: %v", err)
	}

	got, err := DecodePreamble(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("DecodePreamble: %v", err)
	}
	err = got.Verify([]byte("wrong-key"))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("Verify with the wrong key returned %v, want ErrAuthFailed", err)
	}
}

// TestPreambleRejectsTamperedTarget proves the MAC covers the target address,
// so an on-path attacker cannot redirect a connection by editing the frame.
func TestPreambleRejectsTamperedTarget(t *testing.T) {
	frame, err := EncodePreamble(&Preamble{Command: CmdConnectTCP, Target: "example.com:443"}, []byte("k"))
	if err != nil {
		t.Fatalf("EncodePreamble: %v", err)
	}

	// Flip one byte inside the address region and confirm verification fails.
	tampered := append([]byte(nil), frame...)
	idx := bytes.Index(tampered, []byte("example"))
	if idx < 0 {
		t.Fatal("the address is not present in the frame")
	}
	tampered[idx] ^= 0x01

	got, err := DecodePreamble(bytes.NewReader(tampered))
	if err != nil {
		// A tampered address may fail to parse, which is also a refusal.
		return
	}
	if err := got.Verify([]byte("k")); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("Verify accepted a tampered target: %v", err)
	}
}

// TestPreambleZeroMACWithoutKey covers the deliberate unauthenticated mode:
// with no key configured the relay only accepts a zero MAC, so a frame that
// carries a real MAC is refused rather than silently downgraded.
func TestPreambleZeroMACWithoutKey(t *testing.T) {
	framed, err := EncodePreamble(&Preamble{Command: CmdConnectTCP, Target: "example.com:443"}, nil)
	if err != nil {
		t.Fatalf("EncodePreamble: %v", err)
	}
	got, err := DecodePreamble(bytes.NewReader(framed))
	if err != nil {
		t.Fatalf("DecodePreamble: %v", err)
	}
	if err := got.Verify(nil); err != nil {
		t.Fatalf("Verify with no key rejected a zero-MAC frame: %v", err)
	}

	keyed, err := EncodePreamble(&Preamble{Command: CmdConnectTCP, Target: "example.com:443"}, []byte("k"))
	if err != nil {
		t.Fatalf("EncodePreamble: %v", err)
	}
	got2, err := DecodePreamble(bytes.NewReader(keyed))
	if err != nil {
		t.Fatalf("DecodePreamble: %v", err)
	}
	if err := got2.Verify(nil); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("Verify accepted a MACed frame with no configured key: %v", err)
	}
}

// TestPreambleRejectsBadMagic proves a port scanner's bytes are refused before
// anything is allocated, which is the common case on a public relay.
func TestPreambleRejectsBadMagic(t *testing.T) {
	junk := append([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), make([]byte, 64)...)
	_, err := DecodePreamble(bytes.NewReader(junk))
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("DecodePreamble on junk returned %v, want ErrProtocol", err)
	}
}

// TestFreshnessWindow proves a stale frame is refused, which is the first half
// of replay protection.
func TestFreshnessWindow(t *testing.T) {
	p := &Preamble{Time: time.Now().Add(-10 * time.Minute)}
	if err := p.Freshness(PreambleSkew); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("a ten-minute-old frame was accepted: %v", err)
	}

	// A small negative skew must be tolerated: relays and clients routinely
	// have clocks a few seconds apart.
	p2 := &Preamble{Time: time.Now().Add(20 * time.Second)}
	if err := p2.Freshness(PreambleSkew); err != nil {
		t.Fatalf("a 20-second future skew was rejected: %v", err)
	}
}

// TestReplayGuard proves a nonce cannot be reused, which is the second half of
// replay protection.
func TestReplayGuard(t *testing.T) {
	g := NewReplayGuard(16, time.Minute)

	nonce := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	if !g.Check(nonce) {
		t.Fatal("the first use of a nonce was rejected")
	}
	if g.Check(nonce) {
		t.Fatal("a replayed nonce was accepted")
	}
	if g.Len() != 1 {
		t.Fatalf("guard holds %d nonces, want 1", g.Len())
	}

	// A different nonce must still be accepted, and the ring must not grow
	// without bound as more arrive.
	for i := 0; i < 100; i++ {
		var n [8]byte
		n[0] = byte(i + 10)
		if !g.Check(n) {
			t.Fatalf("a fresh nonce %d was rejected", i)
		}
	}
	if g.Len() > 16 {
		t.Fatalf("guard holds %d nonces, exceeding its capacity of 16", g.Len())
	}
}

// TestReplayGuardNilIsPermissive documents that a disabled guard must not
// reject anything, because a relay behind CGNAT may legitimately see repeated
// nonces from a broken client and must not become unusable.
func TestReplayGuardNilIsPermissive(t *testing.T) {
	var g *ReplayGuard
	nonce := [8]byte{9, 9, 9, 9, 9, 9, 9, 9}
	if !g.Check(nonce) || !g.Check(nonce) {
		t.Fatal("a nil guard rejected a nonce")
	}
	if g.Len() != 0 {
		t.Fatalf("a nil guard reports %d entries", g.Len())
	}
}

// TestPreambleClientServerHandshake exercises the full helper pair over an
// in-memory pipe, which is what every simple transport uses.
func TestPreambleClientServerHandshake(t *testing.T) {
	psk := []byte("pipe-test-key")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	type outcome struct {
		stream Stream
		err    error
	}
	serverCh := make(chan outcome, 1)
	go func() {
		s, err := PreambleServerHandshake(server, ServerHandshakeConfig{
			PSK:           psk,
			Timeout:       3 * time.Second,
			AllowPing:     true,
			TransportName: "test",
		})
		serverCh <- outcome{s, err}
	}()

	req := &Request{Command: CmdConnectTCP, Target: "example.com:443", Transport: "test"}
	clientStream, err := PreambleClientHandshake(client, req, ClientHandshakeConfig{
		PSK:           psk,
		ClientID:      "pipe-client",
		TransportName: "test",
		Timeout:       3 * time.Second,
	})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if clientStream == nil {
		t.Fatal("client handshake returned a nil stream")
	}

	res := <-serverCh
	if res.err != nil {
		t.Fatalf("server handshake: %v", res.err)
	}
	if got := res.stream.Request().Target; got != "example.com:443" {
		t.Errorf("relay saw target %q, want example.com:443", got)
	}
	if got := res.stream.Request().ClientID; got != "pipe-client" {
		t.Errorf("relay saw client %q, want pipe-client", got)
	}

	// The stream must carry bytes after the handshake.
	go func() {
		_, _ = clientStream.Write([]byte("hello"))
	}()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(res.stream, buf); err != nil {
		t.Fatalf("read after handshake: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("payload = %q, want hello", buf)
	}
}

// TestPreambleServerRejectsWrongKey proves the relay closes rather than
// serving a client whose key is wrong.
func TestPreambleServerRejectsWrongKey(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := PreambleServerHandshake(server, ServerHandshakeConfig{
			PSK:           []byte("server-key"),
			Timeout:       2 * time.Second,
			TransportName: "test",
		})
		errCh <- err
	}()

	_, err := PreambleClientHandshake(client, &Request{Command: CmdConnectTCP, Target: "x:1"}, ClientHandshakeConfig{
		PSK:           []byte("client-key"),
		TransportName: "test",
		Timeout:       2 * time.Second,
	})
	// The client may or may not observe the close depending on timing; what
	// matters is that the relay refuses.
	_ = err

	if err := <-errCh; !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("relay returned %v, want ErrAuthFailed", err)
	}
}

// TestPingAnswered proves a ping is answered and reported through the
// sentinel, so the relay counts it as a success rather than a failure.
func TestPingAnswered(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := PreambleServerHandshake(server, ServerHandshakeConfig{
			PSK:           []byte("k"),
			Timeout:       2 * time.Second,
			AllowPing:     true,
			TransportName: "test",
		})
		errCh <- err
	}()

	stream, err := PreambleClientHandshake(client, &Request{Command: CmdPing, Transport: "test"}, ClientHandshakeConfig{
		PSK:           []byte("k"),
		TransportName: "test",
		Timeout:       2 * time.Second,
	})
	if err != nil {
		t.Fatalf("ping handshake: %v", err)
	}
	// The round trip over an in-memory pipe can measure as exactly zero on a
	// platform with a coarse monotonic clock, so only a negative value (which
	// would mean the clock ran backwards) is a failure.
	if stream.Latency() < 0 {
		t.Errorf("ping reported a negative latency %v", stream.Latency())
	}

	err = <-errCh
	if !IsPingAnswered(err) {
		t.Fatalf("relay returned %v, want the ping-answered sentinel", err)
	}
	if !isPingAnsweredText(err) {
		t.Log("note: the sentinel is not classified by text, which is expected")
	}
}

// isPingAnsweredText is a helper that documents the sentinel is identified by
// identity rather than by message text.
func isPingAnsweredText(err error) bool { return errors.Is(err, errPingAnswered) }

// TestAddrEncodingRoundTrip covers the SOCKS5 address codec that VLESS, VMess,
// Trojan and Shadowsocks all share. A bug here breaks every one of them.
func TestAddrEncodingRoundTrip(t *testing.T) {
	cases := []string{
		"1.2.3.4:80",
		"255.255.255.255:65535",
		"example.com:443",
		"a.b.c.d.e.f.example.com:8443",
		"[2001:db8::1]:8080",
		"[::1]:1",
	}
	for _, target := range cases {
		encoded, err := EncodeAddr(nil, target)
		if err != nil {
			t.Errorf("EncodeAddr(%q): %v", target, err)
			continue
		}
		decoded, n, err := DecodeAddrFrom(encoded)
		if err != nil {
			t.Errorf("DecodeAddrFrom(%q): %v", target, err)
			continue
		}
		if n != len(encoded) {
			t.Errorf("DecodeAddrFrom(%q) consumed %d of %d bytes", target, n, len(encoded))
		}
		if decoded != target {
			t.Errorf("round trip of %q produced %q", target, decoded)
		}
	}
}

// TestNormalizeAddr proves a bare host gets a default port and an explicit one
// is preserved, which is what the relay relies on when a client omits a port.
func TestNormalizeAddr(t *testing.T) {
	cases := []struct {
		in      string
		defPort int
		want    string
	}{
		{"example.com", 443, "example.com:443"},
		{"example.com:8080", 443, "example.com:8080"},
		{"1.2.3.4", 80, "1.2.3.4:80"},
		{"[::1]:22", 80, "[::1]:22"},
	}
	for _, tc := range cases {
		got, err := NormalizeAddr(tc.in, tc.defPort)
		if err != nil {
			t.Errorf("NormalizeAddr(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("NormalizeAddr(%q, %d) = %q, want %q", tc.in, tc.defPort, got, tc.want)
		}
	}
}

// TestSplitHostPort proves the shared parser handles the forms a client may
// send, including a bare host and an IPv6 literal.
func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port string
	}{
		{"example.com:443", "example.com", "443"},
		{"1.2.3.4:80", "1.2.3.4", "80"},
		{"[2001:db8::1]:443", "2001:db8::1", "443"},
		{"example.com", "example.com", ""},
	}
	for _, tc := range cases {
		host, port, err := SplitHostPort(tc.in)
		if err != nil {
			t.Errorf("SplitHostPort(%q): %v", tc.in, err)
			continue
		}
		if host != tc.host || port != tc.port {
			t.Errorf("SplitHostPort(%q) = (%q, %q), want (%q, %q)", tc.in, host, port, tc.host, tc.port)
		}
	}
}

// TestDecodePSK covers the accepted key forms, because a mismatch here
// presents as an authentication failure that is hard to diagnose.
func TestDecodePSK(t *testing.T) {
	cases := []struct {
		in   string
		want []byte
	}{
		{"", nil},
		{"literal-key", []byte("literal-key")},
		{"hex:414243", []byte("ABC")},
		{"base64:QUJD", []byte("ABC")},
	}
	for _, tc := range cases {
		got := DecodePSK(tc.in)
		if !bytes.Equal(got, tc.want) {
			t.Errorf("DecodePSK(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestGenerateSelfSigned proves a generated certificate is usable and that its
// fingerprint is stable for the same certificate, which is what a client pins.
func TestGenerateSelfSigned(t *testing.T) {
	cert, err := GenerateSelfSigned(SelfSignedOptions{
		CommonName: "test-relay",
		DNSNames:   []string{"relay.example.com"},
	})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("the generated certificate has no DER bytes")
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse the generated certificate: %v", err)
	}

	fp1 := CertificateFingerprint(parsed)
	fp2 := CertificateFingerprint(parsed)
	if fp1 != fp2 {
		t.Errorf("the fingerprint of one certificate is not stable: %q vs %q", fp1, fp2)
	}
	if len(fp1) != 95 {
		t.Errorf("fingerprint %q is %d characters, expected 95 for a colon-separated SHA-256", fp1, len(fp1))
	}
	// The certificate must be valid immediately despite a client clock that is
	// slightly behind, which is why NotBefore is backdated.
	if parsed.NotBefore.After(time.Now()) {
		t.Errorf("the certificate is not yet valid: NotBefore is %v", parsed.NotBefore)
	}
}
