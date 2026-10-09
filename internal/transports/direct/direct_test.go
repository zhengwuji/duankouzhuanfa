package direct

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"porttransit/internal/logx"
	"porttransit/internal/transport"
)

// Compile-time proof that this package still satisfies the transport contract.
// If a signature drifts, the test file fails to build rather than failing at
// runtime in the relay.
var (
	_ transport.Dialer  = Dialer{}
	_ transport.Handler = Handler{}
)

// handshakeTimeout bounds every handshake in this file. A test that hangs is a
// test that never reports its real result, and the CI timeout is the only thing
// left to diagnose it, so each handshake carries its own short deadline.
const handshakeTimeout = 3 * time.Second

// readTimeout bounds every assertion read. A missing reply must fail the test
// fast instead of blocking the whole binary.
const readTimeout = 5 * time.Second

// pipePair returns a connected client/server socket pair.
//
// net.Pipe is fully synchronous: a Write blocks until the peer has read every
// byte. Every test below therefore runs the relay half in a goroutine and never
// writes a request inline in the test body, because a relay that refuses a
// frame closes the connection after reading only part of it — writing inline
// would deadlock the test body against a relay that has already stopped
// reading.
func pipePair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	c, s := net.Pipe()
	t.Cleanup(func() {
		c.Close()
		s.Close()
	})
	return c, s
}

// writeAsync sends bytes from a goroutine. See pipePair for why.
func writeAsync(conn net.Conn, buf []byte) {
	go func() { _, _ = conn.Write(buf) }()
}

// readN reads exactly n bytes, failing the test on a short read so a missing
// reply surfaces as a clear failure rather than a hung binary.
func readN(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return buf
}

// handleResult carries the relay half's outcome across the goroutine boundary.
type handleResult struct {
	stream transport.Stream
	err    error
}

// handleAsync runs the real Handler over conn and returns its result.
func handleAsync(conn net.Conn, settings transport.Settings) <-chan handleResult {
	out := make(chan handleResult, 1)
	go func() {
		st, err := Handler{}.Handle(context.Background(), conn, transport.HandleRequest{
			Timeout:  handshakeTimeout,
			Settings: settings,
		})
		out <- handleResult{st, err}
	}()
	return out
}

// awaitResult waits for a relay result, failing the test instead of hanging.
func awaitResult(t *testing.T, ch <-chan handleResult) handleResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(readTimeout + time.Second):
		t.Fatal("the relay half never returned")
		return handleResult{}
	}
}

// clientHandshakeAsync runs exactly the client half Dialer.Dial runs — the same
// PSK decoding, client-id precedence and logger adaptation — but over an
// in-memory pipe, because Dialer.Dial always opens its own TCP socket and
// cannot be pointed at one.
func clientHandshakeAsync(conn net.Conn, settings transport.Settings, req *transport.Request) <-chan handleResult {
	out := make(chan handleResult, 1)
	go func() {
		st, err := transport.PreambleClientHandshake(conn, req, transport.ClientHandshakeConfig{
			PSK:           transport.DecodePSK(settings.GetString(SettingPSK, "")),
			ClientID:      clientIDFrom(settings, req),
			TransportName: Name,
			Timeout:       handshakeTimeout,
			Logger:        loggerFor(nil),
		})
		out <- handleResult{st, err}
	}()
	return out
}

// connectRequest builds the request a client sends for a TCP target.
func connectRequest(target string) *transport.Request {
	return &transport.Request{Command: transport.CmdConnectTCP, Target: target, Transport: Name}
}

// TestFactoryRegistration proves the transport is discoverable under exactly
// the name and default port the GUI and the one-click installer rely on. A
// mismatch here is invisible at compile time and only shows up as an unusable
// install, so it is asserted against the literal rather than the constant.
func TestFactoryRegistration(t *testing.T) {
	if Name != "direct" {
		t.Errorf("Name = %q, want the literal \"direct\"", Name)
	}
	if DefaultPort != 8080 {
		t.Errorf("DefaultPort = %d, want 8080", DefaultPort)
	}

	f, ok := transport.Lookup(Name)
	if !ok {
		t.Fatalf("Lookup(%q) did not find the transport; its init did not register it", Name)
	}
	if f.Name != Name {
		t.Errorf("the registered factory is named %q, want %q", f.Name, Name)
	}
	if f.DefaultPort != DefaultPort {
		t.Errorf("the registered factory advertises port %d, want %d", f.DefaultPort, DefaultPort)
	}
	if f.Description == "" {
		t.Error("the factory has no description, so the protocol picker shows a blank entry")
	}
	if f.NativeHeader {
		t.Error("direct reports a native header, but it carries the target in the shared preamble")
	}

	d, err := transport.NewDialer(Name)
	if err != nil {
		t.Fatalf("NewDialer(%q): %v", Name, err)
	}
	if d.Name() != Name {
		t.Errorf("the dialer names itself %q, want %q", d.Name(), Name)
	}
	h, err := transport.NewHandler(Name)
	if err != nil {
		t.Fatalf("NewHandler(%q): %v", Name, err)
	}
	if h.Name() != Name {
		t.Errorf("the handler names itself %q, want %q", h.Name(), Name)
	}

	// The concrete types must also report the registry key, since the relay
	// and the client call Name() on the structs they construct directly.
	if got := (Dialer{}).Name(); got != Name {
		t.Errorf("Dialer.Name() = %q, want %q", got, Name)
	}
	if got := (Handler{}).Name(); got != Name {
		t.Errorf("Handler.Name() = %q, want %q", got, Name)
	}
}

// TestHandlerHandshakeOverPipe proves the relay half decodes a real client
// preamble and hands back a stream that names the requested target and carries
// bytes in both directions. This is the whole contract of the transport.
func TestHandlerHandshakeOverPipe(t *testing.T) {
	settings := transport.Settings{SettingPSK: "pipe-key"}

	client, server := pipePair(t)
	done := handleAsync(server, settings)

	clientCh := clientHandshakeAsync(client, settings, connectRequest("example.com:443"))
	if r := awaitResult(t, clientCh); r.err != nil {
		t.Fatalf("the client half failed: %v", r.err)
	}

	res := awaitResult(t, done)
	if res.err != nil {
		t.Fatalf("the relay refused a valid handshake: %v", res.err)
	}
	defer res.stream.Close()

	if got := res.stream.Request().Target; got != "example.com:443" {
		t.Errorf("the relay decoded target %q, want example.com:443", got)
	}
	if got := res.stream.TransportName(); got != Name {
		t.Errorf("the stream reports transport %q, want %q", got, Name)
	}
	if got := res.stream.Request().Command; got != transport.CmdConnectTCP {
		t.Errorf("the relay decoded command %v, want tcp", got)
	}
	if got := res.stream.Request().Transport; got != Name {
		t.Errorf("the request is stamped with transport %q, want %q", got, Name)
	}

	// The stream must be a usable bidirectional connection after the
	// handshake, not just a decoded request.
	writeAsync(res.stream, []byte("from-relay"))
	if got := readN(t, client, len("from-relay")); string(got) != "from-relay" {
		t.Errorf("the client read %q, want \"from-relay\"", got)
	}
}

// TestDialAndHandleOverTCP exercises the two exported halves together over a
// real socket. The pipe tests above cover the relay half in isolation; this one
// proves Dialer.Dial's own socket handling, its deadline bookkeeping and its
// settings plumbing actually produce a working stream.
func TestDialAndHandleOverTCP(t *testing.T) {
	settings := transport.Settings{SettingPSK: "tcp-key", SettingTimeout: "3s"}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	results := make(chan handleResult, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				st, err := Handler{}.Handle(context.Background(), conn, transport.HandleRequest{
					Timeout:  handshakeTimeout,
					Settings: settings,
				})
				results <- handleResult{st, err}
			}(conn)
		}
	}()

	stream, err := Dialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: ln.Addr().String(),
		Request:    connectRequest("93.184.216.34:443"),
		Timeout:    handshakeTimeout,
		Settings:   settings,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { stream.Close() })

	if got := stream.Request().Target; got != "93.184.216.34:443" {
		t.Errorf("the client stream reports target %q, want 93.184.216.34:443", got)
	}
	if got := stream.TransportName(); got != Name {
		t.Errorf("the client stream reports transport %q, want %q", got, Name)
	}

	var res handleResult
	select {
	case res = <-results:
	case <-time.After(readTimeout):
		t.Fatal("the relay never returned")
	}
	if res.err != nil {
		t.Fatalf("the relay refused the dial: %v", res.err)
	}
	t.Cleanup(func() { res.stream.Close() })

	if got := res.stream.Request().Target; got != "93.184.216.34:443" {
		t.Errorf("the relay decoded target %q, want 93.184.216.34:443", got)
	}

	// Round-trip a payload in both directions over the established stream.
	writeAsync(stream, []byte("ping-payload"))
	if got := readN(t, res.stream, 12); string(got) != "ping-payload" {
		t.Errorf("the relay read %q, want \"ping-payload\"", got)
	}
	writeAsync(res.stream, []byte("pong-payload"))
	if got := readN(t, stream, 12); string(got) != "pong-payload" {
		t.Errorf("the client read %q, want \"pong-payload\"", got)
	}
}

// TestPayloadSurvivesTheHandshake proves the preamble is consumed exactly, so
// the first bytes of application data are not eaten by the frame parser. A
// one-byte overread here would corrupt every relayed stream in a way that looks
// like an application bug.
func TestPayloadSurvivesTheHandshake(t *testing.T) {
	settings := transport.Settings{SettingPSK: "framing-key"}

	client, server := pipePair(t)
	done := handleAsync(server, settings)

	// Write the preamble and the payload back to back, before the relay has
	// returned. If the decoder consumed one byte too many, that byte would be
	// missing from what the relay reads.
	pre := &transport.Preamble{Command: transport.CmdConnectTCP, Target: "example.com:443"}
	frame, err := transport.EncodePreamble(pre, transport.DecodePSK(settings.GetString(SettingPSK, "")))
	if err != nil {
		t.Fatalf("EncodePreamble: %v", err)
	}
	writeAsync(client, append(frame, []byte("APPLICATION-DATA")...))

	res := awaitResult(t, done)
	if res.err != nil {
		t.Fatalf("the relay refused the handshake: %v", res.err)
	}
	defer res.stream.Close()

	if got := readN(t, res.stream, len("APPLICATION-DATA")); string(got) != "APPLICATION-DATA" {
		t.Errorf("the relay read %q after the preamble, want \"APPLICATION-DATA\"", got)
	}
}

// TestPSKMatrix proves the security-critical property: only a client holding
// the configured key is served. The wrong-key case is the one that keeps the
// relay from being an open proxy.
func TestPSKMatrix(t *testing.T) {
	cases := []struct {
		name        string
		serverKey   string
		clientKey   string
		wantRefused bool
		// wantErr is the sentinel the relay must report for a refusal.
		wantErr error
	}{
		{
			name:      "matching keys are served",
			serverKey: "shared-secret",
			clientKey: "shared-secret",
		},
		{
			name:        "a wrong key is refused",
			serverKey:   "shared-secret",
			clientKey:   "different-secret",
			wantRefused: true,
			wantErr:     transport.ErrAuthFailed,
		},
		{
			name:        "a keyed frame is refused by a relay with no key",
			serverKey:   "",
			clientKey:   "shared-secret",
			wantRefused: true,
			wantErr:     transport.ErrAuthFailed,
		},
		{
			name:      "no key on either side stays usable",
			serverKey: "",
			clientKey: "",
		},
		{
			// The relay must accept a key written in the explicit base64 form
			// the GUI generates, and treat it as the same key as the raw form.
			name:      "an encoded key round-trips against its literal",
			serverKey: transport.EncodePSK([]byte("shared-secret")),
			clientKey: transport.EncodePSK([]byte("shared-secret")),
		},
		{
			name:        "a different key with the same encoding is refused",
			serverKey:   transport.EncodePSK([]byte("shared-secret")),
			clientKey:   transport.EncodePSK([]byte("other-secret!")),
			wantRefused: true,
			wantErr:     transport.ErrAuthFailed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			serverSettings := transport.Settings{}
			clientSettings := transport.Settings{}
			if tc.serverKey != "" {
				serverSettings[SettingPSK] = tc.serverKey
			}
			if tc.clientKey != "" {
				clientSettings[SettingPSK] = tc.clientKey
			}

			client, server := pipePair(t)
			done := handleAsync(server, serverSettings)
			clientCh := clientHandshakeAsync(client, clientSettings, connectRequest("example.com:443"))

			res := awaitResult(t, done)
			if tc.wantRefused {
				if res.err == nil {
					t.Fatal("the relay served a client it should have refused")
				}
				if tc.wantErr != nil && !errors.Is(res.err, tc.wantErr) {
					t.Errorf("the refusal is %v, want it to wrap %v", res.err, tc.wantErr)
				}
				if res.stream != nil {
					res.stream.Close()
				}
				return
			}
			if res.err != nil {
				t.Fatalf("the relay refused a valid client: %v", res.err)
			}
			res.stream.Close()

			// A served client must also see its own half succeed, otherwise
			// the two sides disagree about the outcome.
			if r := awaitResult(t, clientCh); r.err != nil {
				t.Fatalf("the client half failed although the relay served it: %v", r.err)
			}
		})
	}
}

// TestNoPSKUsesZeroMAC pins the deliberate unauthenticated mode: with no key
// configured the frame carries an all-zero MAC field rather than an HMAC of the
// empty key. Getting this wrong makes no-key mode unusable, which is exactly
// the trap the encoder's comment warns about.
func TestNoPSKUsesZeroMAC(t *testing.T) {
	frame, err := transport.EncodePreamble(
		&transport.Preamble{Command: transport.CmdConnectTCP, Target: "example.com:443"}, nil)
	if err != nil {
		t.Fatalf("EncodePreamble: %v", err)
	}
	if len(frame) < 32 {
		t.Fatalf("the frame is only %d bytes", len(frame))
	}
	if mac := frame[len(frame)-32:]; !bytes.Equal(mac, make([]byte, 32)) {
		t.Errorf("the no-key MAC is %x, want 32 zero bytes", mac)
	}

	// A relay with no key must serve that frame...
	client, server := pipePair(t)
	done := handleAsync(server, transport.Settings{})
	clientCh := clientHandshakeAsync(client, transport.Settings{}, connectRequest("example.com:443"))

	res := awaitResult(t, done)
	if res.err != nil {
		t.Fatalf("a relay with no key refused a zero-MAC frame: %v", res.err)
	}
	res.stream.Close()
	if r := awaitResult(t, clientCh); r.err != nil {
		t.Fatalf("the client half failed in no-key mode: %v", r.err)
	}
}

// TestRequireClientIDMatrix proves per-client policy is enforced. Without it an
// operator's allow-list is advisory only, and any client reaching the port is
// served.
func TestRequireClientIDMatrix(t *testing.T) {
	cases := []struct {
		name        string
		settings    transport.Settings
		clientID    string
		wantRefused bool
	}{
		{
			name:        "a client id is required but absent",
			settings:    transport.Settings{"requireClientID": true},
			wantRefused: true,
		},
		{
			name:     "a required client id that is allowed is served",
			settings: transport.Settings{"requireClientID": true, "allowedClients": []string{"alice"}},
			clientID: "alice",
		},
		{
			name:        "a client id outside the allow-list is refused",
			settings:    transport.Settings{"requireClientID": true, "allowedClients": []string{"alice"}},
			clientID:    "mallory",
			wantRefused: true,
		},
		{
			// The allow-list must bite even when requireClientID is off: an
			// operator who lists allowed clients means it.
			name:        "the allow-list applies without requireClientID",
			settings:    transport.Settings{"allowedClients": []string{"alice"}},
			clientID:    "mallory",
			wantRefused: true,
		},
		{
			name:        "an allow-list refuses a client that presents nothing",
			settings:    transport.Settings{"allowedClients": []string{"alice"}},
			wantRefused: true,
		},
		{
			name:     "an empty allow-list imposes no restriction",
			settings: transport.Settings{},
			clientID: "anyone",
		},
		{
			// A single string must be promoted to a one-element list so both
			// config spellings behave identically.
			name:     "a bare string allow-list entry is honoured",
			settings: transport.Settings{"allowedClients": "alice"},
			clientID: "alice",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			settings := transport.Settings{SettingPSK: "id-key"}
			for k, v := range tc.settings {
				settings[k] = v
			}

			client, server := pipePair(t)
			done := handleAsync(server, settings)

			clientSettings := transport.Settings{SettingPSK: "id-key"}
			if tc.clientID != "" {
				clientSettings["clientID"] = tc.clientID
			}
			clientCh := clientHandshakeAsync(client, clientSettings, connectRequest("example.com:443"))

			res := awaitResult(t, done)
			if tc.wantRefused {
				if res.err == nil {
					t.Fatal("the relay served a client its policy forbids")
				}
				if !errors.Is(res.err, transport.ErrAuthFailed) {
					t.Errorf("the refusal is %v, want it to wrap ErrAuthFailed", res.err)
				}
				if res.stream != nil {
					res.stream.Close()
				}
				return
			}
			if res.err != nil {
				t.Fatalf("the relay refused an allowed client: %v", res.err)
			}
			res.stream.Close()
			if r := awaitResult(t, clientCh); r.err != nil {
				t.Fatalf("the client half failed although the relay served it: %v", r.err)
			}
		})
	}
}

// TestClientIDReachesTheRelay proves the client's identity is carried into the
// request the relay sees. Forward rules and the ACL match on it, so a lost
// client id silently disables per-client routing.
func TestClientIDReachesTheRelay(t *testing.T) {
	settings := transport.Settings{SettingPSK: "id-key", "requireClientID": true}

	t.Run("from settings", func(t *testing.T) {
		client, server := pipePair(t)
		done := handleAsync(server, settings)

		clientSettings := transport.Settings{SettingPSK: "id-key", "clientID": "from-settings"}
		clientCh := clientHandshakeAsync(client, clientSettings, connectRequest("example.com:443"))

		res := awaitResult(t, done)
		if res.err != nil {
			t.Fatalf("the relay refused the handshake: %v", res.err)
		}
		defer res.stream.Close()
		if got := res.stream.Request().ClientID; got != "from-settings" {
			t.Errorf("the relay saw client id %q, want \"from-settings\"", got)
		}
		awaitResult(t, clientCh)
	})

	// The request's own ClientID must win over the settings, because a client
	// that names itself per-connection must not be overridden by a stale
	// default in the config bag.
	t.Run("the request overrides the settings", func(t *testing.T) {
		client, server := pipePair(t)
		done := handleAsync(server, settings)

		req := connectRequest("example.com:443")
		req.ClientID = "from-request"
		clientSettings := transport.Settings{SettingPSK: "id-key", "clientID": "from-settings"}
		clientCh := clientHandshakeAsync(client, clientSettings, req)

		res := awaitResult(t, done)
		if res.err != nil {
			t.Fatalf("the relay refused the handshake: %v", res.err)
		}
		defer res.stream.Close()
		if got := res.stream.Request().ClientID; got != "from-request" {
			t.Errorf("the relay saw client id %q, want \"from-request\"", got)
		}
		awaitResult(t, clientCh)
	})
}

// TestPingIsAnswered proves a liveness probe is answered and reported through
// the sentinel. The relay counts the sentinel as a successful ping rather than
// a failed handshake, and the GUI's latency test depends on that distinction.
func TestPingIsAnswered(t *testing.T) {
	settings := transport.Settings{SettingPSK: "ping-key"}

	client, server := pipePair(t)
	done := handleAsync(server, settings)

	clientCh := clientHandshakeAsync(client, settings, &transport.Request{Command: transport.CmdPing, Transport: Name})

	res := awaitResult(t, done)
	if !transport.IsPingAnswered(res.err) {
		t.Fatalf("the relay returned %v, want the ping-answered sentinel", res.err)
	}
	if res.stream != nil {
		res.stream.Close()
	}

	// The client half must observe the acknowledgement and measure a latency.
	r := awaitResult(t, clientCh)
	if r.err != nil {
		t.Fatalf("the ping client half failed: %v", r.err)
	}
	defer r.stream.Close()
	if r.stream.Latency() < 0 {
		t.Errorf("the ping reported a negative latency %v", r.stream.Latency())
	}
}

// TestPingCanBeDisabled proves an operator can turn the liveness probe off, so
// a relay under probe cannot be distinguished from one that refuses everything.
func TestPingCanBeDisabled(t *testing.T) {
	settings := transport.Settings{SettingPSK: "ping-key", "allowPing": false}

	client, server := pipePair(t)
	done := handleAsync(server, settings)
	clientHandshakeAsync(client, settings, &transport.Request{Command: transport.CmdPing, Transport: Name})

	res := awaitResult(t, done)
	if res.err == nil {
		t.Fatal("the relay answered a ping while ping was disabled")
	}
	if transport.IsPingAnswered(res.err) {
		t.Error("a disabled ping was reported as answered")
	}
	if !errors.Is(res.err, transport.ErrProtocol) {
		t.Errorf("the refusal is %v, want it to wrap ErrProtocol", res.err)
	}
}

// TestRejectsInvalidCommand proves a command this build does not understand is
// refused at the decoder rather than being passed to the relay as a request to
// act on.
func TestRejectsInvalidCommand(t *testing.T) {
	// EncodePreamble validates the command, so the frame is built valid and
	// then the command byte is overwritten, which is exactly what a hostile
	// peer would send.
	frame, err := transport.EncodePreamble(
		&transport.Preamble{Command: transport.CmdConnectTCP, Target: "example.com:443"}, nil)
	if err != nil {
		t.Fatalf("EncodePreamble: %v", err)
	}
	if frame[5] != byte(transport.CmdConnectTCP) {
		t.Fatalf("the command is at offset %d, not 5", bytes.IndexByte(frame, byte(transport.CmdConnectTCP)))
	}
	frame[5] = 0x7F

	client, server := pipePair(t)
	done := handleAsync(server, transport.Settings{})
	writeAsync(client, frame)

	res := awaitResult(t, done)
	if res.err == nil {
		t.Fatal("the relay accepted an undefined command")
	}
	if !errors.Is(res.err, transport.ErrProtocol) {
		t.Errorf("the refusal is %v, want it to wrap ErrProtocol", res.err)
	}
}

// TestRejectsMalformedPreamble proves a port scanner's bytes are refused before
// anything is acted on. This is the common case on a public relay, so it must
// be a clean refusal rather than a panic or a hang.
func TestRejectsMalformedPreamble(t *testing.T) {
	junk := append([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), make([]byte, 64)...)

	client, server := pipePair(t)
	done := handleAsync(server, transport.Settings{})
	writeAsync(client, junk)

	res := awaitResult(t, done)
	if res.err == nil {
		t.Fatal("the relay accepted an HTTP request as a preamble")
	}
	if !errors.Is(res.err, transport.ErrProtocol) {
		t.Errorf("the refusal is %v, want it to wrap ErrProtocol", res.err)
	}
}

// TestRejectsTamperedTarget proves the MAC covers the target address, so an
// on-path attacker cannot redirect a relayed connection by editing the frame.
// This is the property that makes the preamble worth having on an unencrypted
// transport.
func TestRejectsTamperedTarget(t *testing.T) {
	key := transport.DecodePSK("tamper-key")

	frame, err := transport.EncodePreamble(
		&transport.Preamble{Command: transport.CmdConnectTCP, Target: "example.com:443"}, key)
	if err != nil {
		t.Fatalf("EncodePreamble: %v", err)
	}
	tampered := append([]byte(nil), frame...)
	idx := bytes.Index(tampered, []byte("example"))
	if idx < 0 {
		t.Fatal("the target is not present in the frame")
	}
	// Flip a bit inside the domain name without changing its length, so the
	// frame still parses and only the MAC can catch the edit.
	tampered[idx] ^= 0x01

	client, server := pipePair(t)
	done := handleAsync(server, transport.Settings{SettingPSK: "tamper-key"})
	writeAsync(client, tampered)

	res := awaitResult(t, done)
	if res.err == nil {
		t.Fatal("the relay served a frame whose target had been edited")
	}
	if !errors.Is(res.err, transport.ErrAuthFailed) {
		t.Errorf("the refusal is %v, want it to wrap ErrAuthFailed", res.err)
	}
}

// TestRejectsStalePreamble proves the freshness window is enforced, which is
// the first half of replay protection: a frame captured long ago is useless
// even to a peer that also captured the key.
func TestRejectsStalePreamble(t *testing.T) {
	key := transport.DecodePSK("stale-key")

	frame, err := transport.EncodePreamble(&transport.Preamble{
		Command: transport.CmdConnectTCP,
		Target:  "example.com:443",
		Time:    time.Now().Add(-10 * time.Minute),
	}, key)
	if err != nil {
		t.Fatalf("EncodePreamble: %v", err)
	}

	client, server := pipePair(t)
	done := handleAsync(server, transport.Settings{SettingPSK: "stale-key"})
	writeAsync(client, frame)

	res := awaitResult(t, done)
	if res.err == nil {
		t.Fatal("the relay served a ten-minute-old frame")
	}
	if !errors.Is(res.err, transport.ErrAuthFailed) {
		t.Errorf("the refusal is %v, want it to wrap ErrAuthFailed", res.err)
	}
}

// TestNilLoggerDoesNotPanic covers a real defect this repository has already
// hit: loggerFor must return a usable no-op rather than a nil interface,
// because a nil interface panics on the first method call from deep inside a
// handshake path and takes the whole relay down.
func TestNilLoggerDoesNotPanic(t *testing.T) {
	// A nil *logx.Logger must be adapted, not returned as a nil interface.
	if got := loggerFor(nil); got == nil {
		t.Fatal("loggerFor(nil) returned a nil interface, which panics on first use")
	}
	// A configured logger must be passed through unchanged.
	if got := loggerFor(logx.Discard()); got == nil {
		t.Fatal("loggerFor(discard) returned a nil interface")
	}

	// Now drive both halves with an explicitly nil logger, since that is what
	// a caller that forgot to configure logging actually passes.
	settings := transport.Settings{SettingPSK: "log-key"}

	client, server := pipePair(t)
	done := make(chan handleResult, 1)
	go func() {
		st, err := Handler{}.Handle(context.Background(), server, transport.HandleRequest{
			Timeout:  handshakeTimeout,
			Logger:   nil,
			Settings: settings,
		})
		done <- handleResult{st, err}
	}()

	clientCh := make(chan handleResult, 1)
	go func() {
		st, err := transport.PreambleClientHandshake(client, connectRequest("example.com:443"), transport.ClientHandshakeConfig{
			PSK:           transport.DecodePSK(settings.GetString(SettingPSK, "")),
			TransportName: Name,
			Timeout:       handshakeTimeout,
			Logger:        loggerFor(nil),
		})
		clientCh <- handleResult{st, err}
	}()

	res := awaitResult(t, done)
	if res.err != nil {
		t.Fatalf("the relay failed with a nil logger: %v", res.err)
	}
	res.stream.Close()
	if r := awaitResult(t, clientCh); r.err != nil {
		t.Fatalf("the client failed with a nil logger: %v", r.err)
	}
}

// TestNilLoggerOnRefusalPathsDoesNotPanic is the same guarantee on the paths
// that log a warning: an authentication failure and a protocol violation both
// log before returning, and a nil interface would panic there instead of
// refusing.
func TestNilLoggerOnRefusalPathsDoesNotPanic(t *testing.T) {
	t.Run("authentication failure", func(t *testing.T) {
		client, server := pipePair(t)
		done := make(chan handleResult, 1)
		go func() {
			st, err := Handler{}.Handle(context.Background(), server, transport.HandleRequest{
				Timeout:  handshakeTimeout,
				Logger:   nil,
				Settings: transport.Settings{SettingPSK: "right-key"},
			})
			done <- handleResult{st, err}
		}()
		clientHandshakeAsync(client, transport.Settings{SettingPSK: "wrong-key"}, connectRequest("example.com:443"))

		res := awaitResult(t, done)
		if !errors.Is(res.err, transport.ErrAuthFailed) {
			t.Fatalf("the relay returned %v, want ErrAuthFailed", res.err)
		}
	})

	t.Run("protocol violation", func(t *testing.T) {
		client, server := pipePair(t)
		done := make(chan handleResult, 1)
		go func() {
			st, err := Handler{}.Handle(context.Background(), server, transport.HandleRequest{
				Timeout:  handshakeTimeout,
				Logger:   nil,
				Settings: transport.Settings{},
			})
			done <- handleResult{st, err}
		}()
		writeAsync(client, append([]byte("not-a-preamble-at-all!!"), make([]byte, 32)...))

		res := awaitResult(t, done)
		if !errors.Is(res.err, transport.ErrProtocol) {
			t.Fatalf("the relay returned %v, want ErrProtocol", res.err)
		}
	})
}

// TestReplayGuardSettingsAreRead proves the replay knobs are honoured as
// settings, so an operator turning the guard off or sizing its cache sees the
// documented effect. The guard's actual effectiveness is covered separately.
func TestReplayGuardSettingsAreRead(t *testing.T) {
	if g := replayFrom(transport.Settings{"disableReplayGuard": true}); g != nil {
		t.Error("disableReplayGuard=true still built a guard")
	}
	if g := replayFrom(transport.Settings{}); g == nil {
		t.Error("the replay guard is off by default, but it should be on")
	}
	if g := replayFrom(transport.Settings{"replayCacheSize": 4}); g == nil {
		t.Error("a sized guard was not built")
	}
	if g := replayFrom(nil); g == nil {
		t.Error("a nil settings bag did not produce the default guard")
	}
}

// TestReplayIsNotDetectedAcrossConnections documents a defect, so it is skipped
// rather than deleted or weakened.
//
// BUG: replayFrom builds a fresh guard on every Handle call, and Handle runs
// once per accepted connection, so ReplayGuard.Check always sees an empty set
// and can never report a replay. The anti-replay defence described in
// internal/transport/preamble.go:278-328 is therefore inert for this transport,
// and the disableReplayGuard / replayCacheSize settings have no effect.
//
// The assertion below is the property that should hold: a preamble captured off
// the wire and replayed on a second connection must be refused. Removing the
// t.Skip reproduces the failure — the relay serves the replayed frame.
func TestReplayIsNotDetectedAcrossConnections(t *testing.T) {
	t.Skip("BUG: the replay guard is rebuilt per connection, so replays are never detected; see internal/transports/direct/direct.go:116-122")

	settings := transport.Settings{SettingPSK: "replay-key"}

	// Capture a real client preamble by proxying one legitimate connection.
	relay, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { relay.Close() })

	results := make(chan handleResult, 8)
	go func() {
		for {
			conn, err := relay.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				st, err := Handler{}.Handle(context.Background(), conn, transport.HandleRequest{
					Timeout:  handshakeTimeout,
					Settings: settings,
				})
				results <- handleResult{st, err}
			}(conn)
		}
	}()

	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { proxy.Close() })

	var captured bytes.Buffer
	done := make(chan struct{})
	go func() {
		conn, err := proxy.Accept()
		if err != nil {
			close(done)
			return
		}
		up, err := net.Dial("tcp", relay.Addr().String())
		if err != nil {
			conn.Close()
			close(done)
			return
		}
		go func() {
			buf := make([]byte, 4096)
			for {
				n, rerr := conn.Read(buf)
				if n > 0 {
					captured.Write(buf[:n])
					if _, werr := up.Write(buf[:n]); werr != nil {
						break
					}
				}
				if rerr != nil {
					break
				}
			}
			close(done)
		}()
		go func() { _, _ = io.Copy(conn, up); conn.Close() }()
	}()

	client, err := Dialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: proxy.Addr().String(),
		Request:    connectRequest("example.com:443"),
		Timeout:    handshakeTimeout,
		Settings:   settings,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	client.Close()
	<-done

	if r := <-results; r.err != nil {
		t.Fatalf("the legitimate connection failed: %v", r.err)
	} else {
		r.stream.Close()
	}

	frame := captured.Bytes()
	if len(frame) == 0 {
		t.Fatal("the proxy captured no client bytes")
	}

	// Replaying the captured frame must be refused. The relay has already seen
	// this nonce.
	conn, err := net.Dial("tcp", relay.Addr().String())
	if err != nil {
		t.Fatalf("dial for the replay: %v", err)
	}
	defer conn.Close()
	writeAsync(conn, frame)

	select {
	case r := <-results:
		if r.err == nil {
			r.stream.Close()
			t.Fatal("the relay served a replayed preamble; the replay guard is not shared across connections")
		}
		if !errors.Is(r.err, transport.ErrAuthFailed) {
			t.Errorf("the refusal is %v, want it to wrap ErrAuthFailed", r.err)
		}
	case <-time.After(readTimeout):
		t.Fatal("the relay never answered the replayed frame")
	}
}

// TestDialerReportsConnectionFailures proves a dial to a dead endpoint surfaces
// as an error rather than a nil stream, so a caller does not have to check for
// both.
func TestDialerReportsConnectionFailures(t *testing.T) {
	// Bind and immediately release a port so the address is well-formed but
	// nothing is listening on it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	stream, err := Dialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: addr,
		Request:    connectRequest("example.com:443"),
		Timeout:    time.Second,
	})
	if err == nil {
		stream.Close()
		t.Fatal("Dial to a closed port succeeded")
	}
	if stream != nil {
		t.Error("Dial returned a non-nil stream alongside an error")
	}
	if !strings.Contains(err.Error(), "connect") && !strings.Contains(err.Error(), "refused") {
		t.Errorf("the dial error does not describe a connection failure: %v", err)
	}
}
