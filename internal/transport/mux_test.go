package transport

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

// TestMuxPreambleRoundTrip proves a CmdMux frame survives encode and decode
// with no target address and a valid MAC.
//
// It is worth its own case rather than another row in the general preamble test
// because CmdMux omits the address field: encoding it with an address, or
// decoding it expecting one, would desynchronise the frame — the relay would
// read the padding length out of the address bytes and reject a frame that was
// in fact authentic.
func TestMuxPreambleRoundTrip(t *testing.T) {
	psk := []byte("mux-test-key-0123456789")

	frame, err := EncodePreamble(&Preamble{Command: CmdMux, ClientID: "mux-client"}, psk)
	if err != nil {
		t.Fatalf("EncodePreamble: %v", err)
	}

	got, err := DecodePreamble(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("DecodePreamble: %v", err)
	}
	if err := got.Verify(psk); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Command != CmdMux {
		t.Errorf("command = %v, want %v", got.Command, CmdMux)
	}
	if got.Target != "" {
		t.Errorf("target = %q, want empty: a mux frame carries no destination", got.Target)
	}
	if got.ClientID != "mux-client" {
		t.Errorf("client id = %q, want %q", got.ClientID, "mux-client")
	}

	// Everything after the frame must still be readable as payload: a frame
	// that consumed one byte too many or too few would corrupt the first byte
	// of whatever follows it.
	trailing := []byte("stream payload")
	combined := append(append([]byte{}, frame...), trailing...)
	r := bytes.NewReader(combined)
	if _, err := DecodePreamble(r); err != nil {
		t.Fatalf("DecodePreamble over a combined buffer: %v", err)
	}
	rest := make([]byte, len(trailing))
	if _, err := r.Read(rest); err != nil {
		t.Fatalf("read the trailing payload: %v", err)
	}
	if !bytes.Equal(rest, trailing) {
		t.Errorf("trailing bytes = %q, want %q", rest, trailing)
	}
}

// TestMuxCommandIsDistinctFromPing proves the multiplexing request cannot be
// mistaken for a ping.
//
// The two commands are the ones the relay branches on at the top of its serving
// path, and getting them confused is not a subtle failure: a ping is answered
// and closed, so a client that asked to multiplex would see its session die at
// once, and a health probe that asked for a session would open one it never
// uses. The values are pinned here because VLESS's own MUX command occupies
// 0x03 and the VLESS handler maps its command byte onto this enumeration.
func TestMuxCommandIsDistinctFromPing(t *testing.T) {
	if CmdMux == CmdPing {
		t.Fatal("CmdMux and CmdPing share a value")
	}
	if !CmdMux.Valid() {
		t.Error("CmdMux is not a valid command, so a mux frame would be rejected as a protocol violation")
	}
	if CmdMux.String() != "mux" {
		t.Errorf("CmdMux.String() = %q, want %q", CmdMux.String(), "mux")
	}

	// The address field is present exactly for the commands that name a
	// destination. CmdConnectTCP and CmdUDPAssociate must keep it.
	if !CmdConnectTCP.carriesTarget() {
		t.Error("CmdConnectTCP does not carry a target")
	}
	if !CmdUDPAssociate.carriesTarget() {
		t.Error("CmdUDPAssociate does not carry a target")
	}
	if CmdPing.carriesTarget() {
		t.Error("CmdPing carries a target")
	}
	if CmdMux.carriesTarget() {
		t.Error("CmdMux carries a target")
	}
}

// TestSupportsMuxFollowsTheNativeHeaderFlag proves the capability check is
// exactly "this scheme speaks the preamble".
//
// It is what keeps the client from asking a native-header transport for a
// session: such a scheme carries the target inside its own wire protocol, so a
// connection-level request with no target cannot be expressed on it at all.
//
// The check is exercised against factories registered here rather than against
// the real transports, because this package is what the transports import —
// importing them back would be a cycle. The real schemes are checked from the
// server package, which already registers them.
func TestSupportsMuxFollowsTheNativeHeaderFlag(t *testing.T) {
	build := func() (Dialer, Handler) { return nil, nil }
	// Register panics on a duplicate, and a test binary may run this function
	// more than once (go test -count=N), so the factories are only registered
	// when they are not already present.
	registerOnce(t, Factory{Name: "mux-test-preamble", Build: build})
	registerOnce(t, Factory{Name: "mux-test-native", NativeHeader: true, Build: build})

	if !SupportsMux("mux-test-preamble") {
		t.Error("SupportsMux is false for a preamble-carrying transport")
	}
	if SupportsMux("mux-test-native") {
		t.Error("SupportsMux is true for a native-header transport")
	}
	if SupportsMux("not-a-real-transport") {
		t.Error("SupportsMux reported true for an unregistered transport")
	}
	if SupportsMux("") {
		t.Error("SupportsMux reported true for an empty name")
	}
}

// registerOnce registers f unless a factory of the same name already exists.
func registerOnce(t *testing.T, f Factory) {
	t.Helper()
	if _, ok := Lookup(f.Name); ok {
		return
	}
	Register(f)
}

// TestMuxSessionConfigDefaultsAndClamps proves the session parameters are
// usable out of the box and that every value yamux would reject is repaired
// rather than passed to the library.
//
// Repairing matters more than it looks: yamux.VerifyConfig rejects a bad config
// outright, so a rejected value means no session at all — every connection
// falls back to a dedicated one and the operator sees multiplexing "not
// working" with no error anywhere near the setting they changed.
func TestMuxSessionConfigDefaultsAndClamps(t *testing.T) {
	cfg, err := MuxSessionConfig(nil, NopLogger())
	if err != nil {
		t.Fatalf("MuxSessionConfig with no settings: %v", err)
	}
	if cfg.AcceptBacklog != DefaultMuxAcceptBacklog {
		t.Errorf("default accept backlog = %d, want %d", cfg.AcceptBacklog, DefaultMuxAcceptBacklog)
	}
	if !cfg.EnableKeepAlive {
		t.Error("the keepalive is off by default, but an idle NAT mapping is exactly what it detects")
	}
	if cfg.KeepAliveInterval != DefaultMuxKeepAliveInterval {
		t.Errorf("default keepalive interval = %s, want %s", cfg.KeepAliveInterval, DefaultMuxKeepAliveInterval)
	}
	if cfg.MaxStreamWindowSize != DefaultMuxMaxWindowSize {
		t.Errorf("default window = %d, want %d", cfg.MaxStreamWindowSize, DefaultMuxMaxWindowSize)
	}
	if cfg.StreamOpenTimeout != DefaultMuxStreamOpenTimeout {
		t.Errorf("default stream open timeout = %s, want %s", cfg.StreamOpenTimeout, DefaultMuxStreamOpenTimeout)
	}
	if cfg.StreamCloseTimeout != DefaultMuxStreamCloseTimeout {
		t.Errorf("default stream close timeout = %s, want %s", cfg.StreamCloseTimeout, DefaultMuxStreamCloseTimeout)
	}
	if cfg.ConnectionWriteTimeout != DefaultMuxConnectionWriteTimeout {
		t.Errorf("default connection write timeout = %s, want %s", cfg.ConnectionWriteTimeout, DefaultMuxConnectionWriteTimeout)
	}

	// yamux.DefaultConfig sets LogOutput to os.Stderr. Leaving it would let
	// the library write straight to the relay's stderr, bypassing the
	// structured logger entirely. Exactly one of the two fields must be set,
	// so this checks both halves of that rule.
	if cfg.LogOutput != nil {
		t.Error("LogOutput is set, so yamux would write its diagnostics to os.Stderr instead of the project's logger")
	}
	if cfg.Logger == nil {
		t.Error("neither Logger nor LogOutput is set, which yamux.VerifyConfig rejects")
	}

	// A window below yamux's own minimum is rejected by the library, so it has
	// to be clamped here. Refusing instead would take a working configuration
	// out of service over a value the library could simply have honoured as
	// its minimum.
	cfg, err = MuxSessionConfig(Settings{SettingMuxMaxWindowSize: 1024}, NopLogger())
	if err != nil {
		t.Fatalf("MuxSessionConfig with a window below the minimum: %v", err)
	}
	if cfg.MaxStreamWindowSize != MinMuxMaxWindowSize {
		t.Errorf("window = %d, want it clamped up to %d", cfg.MaxStreamWindowSize, MinMuxMaxWindowSize)
	}
	if cfg.MaxStreamWindowSize < 256*1024 {
		t.Errorf("window = %d, which yamux rejects: VerifyConfig requires at least 256 KiB", cfg.MaxStreamWindowSize)
	}

	// A zero or negative value for a field yamux requires to be positive would
	// make the session unbuildable, so it falls back to the default rather than
	// being passed through.
	cfg, err = MuxSessionConfig(Settings{
		SettingMuxMaxWindowSize:          0,
		SettingMuxAcceptBacklog:          0,
		SettingMuxKeepAliveInterval:      "0s",
		SettingMuxConnectionWriteTimeout: "0s",
	}, NopLogger())
	if err != nil {
		t.Fatalf("MuxSessionConfig with zero values: %v", err)
	}
	if cfg.AcceptBacklog != DefaultMuxAcceptBacklog {
		t.Errorf("accept backlog = %d, want the default %d", cfg.AcceptBacklog, DefaultMuxAcceptBacklog)
	}
	if cfg.KeepAliveInterval != DefaultMuxKeepAliveInterval {
		t.Errorf("keepalive interval = %s, want the default %s", cfg.KeepAliveInterval, DefaultMuxKeepAliveInterval)
	}
	if cfg.ConnectionWriteTimeout != DefaultMuxConnectionWriteTimeout {
		t.Errorf("connection write timeout = %s, want the default %s", cfg.ConnectionWriteTimeout, DefaultMuxConnectionWriteTimeout)
	}

	// A zero stream-open or stream-close timeout is meaningful in yamux — it
	// disables that timeout — so it must survive as a zero rather than being
	// replaced by the default.
	cfg, err = MuxSessionConfig(Settings{
		SettingMuxStreamOpenTimeout:  "0s",
		SettingMuxStreamCloseTimeout: "0s",
	}, NopLogger())
	if err != nil {
		t.Fatalf("MuxSessionConfig with the timeouts disabled: %v", err)
	}
	if cfg.StreamOpenTimeout != 0 {
		t.Errorf("stream open timeout = %s, want 0: yamux reads zero as \"disabled\"", cfg.StreamOpenTimeout)
	}
	if cfg.StreamCloseTimeout != 0 {
		t.Errorf("stream close timeout = %s, want 0: yamux reads zero as \"disabled\"", cfg.StreamCloseTimeout)
	}

	// The keepalive-disabled key is the inverse of yamux's own field, so the
	// polarity is worth pinning: a mis-signed mapping would leave the keepalive
	// on when the operator asked for it off, or worse, off by default.
	cfg, err = MuxSessionConfig(Settings{SettingMuxKeepAliveDisabled: true}, NopLogger())
	if err != nil {
		t.Fatalf("MuxSessionConfig with the keepalive disabled: %v", err)
	}
	if cfg.EnableKeepAlive {
		t.Error("muxKeepAliveDisabled is true but yamux's EnableKeepAlive is still set")
	}

	// The values an operator does set must survive untouched.
	cfg, err = MuxSessionConfig(Settings{
		SettingMuxMaxWindowSize:          1024 * 1024,
		SettingMuxAcceptBacklog:          32,
		SettingMuxKeepAliveInterval:      "45s",
		SettingMuxStreamOpenTimeout:      "20s",
		SettingMuxStreamCloseTimeout:     "90s",
		SettingMuxConnectionWriteTimeout: "3s",
	}, NopLogger())
	if err != nil {
		t.Fatalf("MuxSessionConfig with explicit values: %v", err)
	}
	if cfg.MaxStreamWindowSize != 1024*1024 {
		t.Errorf("window = %d, want 1048576", cfg.MaxStreamWindowSize)
	}
	if cfg.AcceptBacklog != 32 {
		t.Errorf("accept backlog = %d, want 32", cfg.AcceptBacklog)
	}
	if cfg.KeepAliveInterval != 45*time.Second {
		t.Errorf("keepalive interval = %s, want 45s", cfg.KeepAliveInterval)
	}
	if cfg.StreamOpenTimeout != 20*time.Second {
		t.Errorf("stream open timeout = %s, want 20s", cfg.StreamOpenTimeout)
	}
	if cfg.StreamCloseTimeout != 90*time.Second {
		t.Errorf("stream close timeout = %s, want 90s", cfg.StreamCloseTimeout)
	}
	if cfg.ConnectionWriteTimeout != 3*time.Second {
		t.Errorf("connection write timeout = %s, want 3s", cfg.ConnectionWriteTimeout)
	}
}

// TestMuxLimitsFallBackOnNonsense proves a limit that cannot be honoured is
// replaced by the default rather than used.
//
// A stream cap of zero would make every session useless — the client would open
// one, fail to put a stream on it, and fall back to a dedicated connection
// forever, which is a performance regression an operator would read as
// multiplexing being broken.
func TestMuxLimitsFallBackOnNonsense(t *testing.T) {
	if got := MuxMaxStreams(Settings{SettingMuxMaxStreams: 0}); got != DefaultMuxMaxStreams {
		t.Errorf("MuxMaxStreams(0) = %d, want %d", got, DefaultMuxMaxStreams)
	}
	if got := MuxMaxStreams(Settings{SettingMuxMaxStreams: -5}); got != DefaultMuxMaxStreams {
		t.Errorf("MuxMaxStreams(-5) = %d, want %d", got, DefaultMuxMaxStreams)
	}
	if got := MuxMaxStreams(Settings{SettingMuxMaxStreams: 12}); got != 12 {
		t.Errorf("MuxMaxStreams(12) = %d, want 12", got)
	}
	if got := MuxMaxSessions(Settings{SettingMuxMaxSessions: 0}); got != DefaultMuxMaxSessions {
		t.Errorf("MuxMaxSessions(0) = %d, want %d", got, DefaultMuxMaxSessions)
	}

	// The client's idle default must be shorter than the relay's, or the two
	// would expire at the same moment and every idle timeout would race a new
	// stream against a close.
	if ClientMuxIdleTimeout >= ServerMuxIdleTimeout {
		t.Errorf("the client idle timeout %s is not shorter than the relay's %s",
			ClientMuxIdleTimeout, ServerMuxIdleTimeout)
	}

	// A negative idle timeout means "use the default" rather than "close
	// immediately", which would retire every session the instant it went quiet.
	if got := MuxIdleTimeout(Settings{SettingMuxIdleTimeout: "-1s"}, ClientMuxIdleTimeout); got != ClientMuxIdleTimeout {
		t.Errorf("MuxIdleTimeout(-1s) = %s, want the default %s", got, ClientMuxIdleTimeout)
	}
	if got := MuxIdleTimeout(nil, ClientMuxIdleTimeout); got != ClientMuxIdleTimeout {
		t.Errorf("MuxIdleTimeout with no settings = %s, want the default %s", got, ClientMuxIdleTimeout)
	}

	// The relay's default idle timeout is the backstop that reclaims a session
	// whose client vanished, so it must be the longer of the two: a relay that
	// retired sessions faster than the client's reaper would close sessions
	// out from under a client that was still using them.
	if ServerMuxIdleTimeout <= ClientMuxIdleTimeout {
		t.Errorf("the relay idle timeout %s is not longer than the client's %s",
			ServerMuxIdleTimeout, ClientMuxIdleTimeout)
	}
}

// TestMuxEnabledDefaultsOff proves multiplexing is opt-in.
//
// A default of on would silently change the behaviour of every existing
// deployment on upgrade, and would fail outright against a relay that had not
// been updated — which is why the setting exists at all.
func TestMuxEnabledDefaultsOff(t *testing.T) {
	if MuxEnabled(nil) {
		t.Error("MuxEnabled(nil) is true")
	}
	if MuxEnabled(Settings{}) {
		t.Error("MuxEnabled on an empty settings bag is true")
	}
	if MuxEnabled(Settings{"mux": false}) {
		t.Error("MuxEnabled with mux false is true")
	}
	if !MuxEnabled(Settings{"mux": true}) {
		t.Error("MuxEnabled with mux true is false")
	}
	// The string forms are what a JSON config with a quoted value produces.
	if !MuxEnabled(Settings{"mux": "true"}) {
		t.Error("MuxEnabled with the string \"true\" is false")
	}

	// The key is the one the README and the console document. An old smux* key
	// is ignored outright rather than honoured: this feature has never been
	// released, so there is nothing to migrate, and quietly accepting both
	// spellings would leave two names for one setting in every future bug
	// report.
	if MuxEnabled(Settings{"smux": true}) {
		t.Error("the retired smux key still switches multiplexing on")
	}
}

// TestMuxAckRoundTrip proves the acknowledgement byte is read back exactly, and
// that a relay which closes without answering is reported as an error.
//
// The error case is the important one: it is what turns a relay that does not
// multiplex into an immediate, classifiable failure instead of a connection
// that hangs until the session keepalive gives up.
func TestMuxAckRoundTrip(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_ = AcknowledgeMux(server, 2*time.Second)
	}()
	if err := AwaitMuxAck(client, 2*time.Second); err != nil {
		t.Fatalf("AwaitMuxAck: %v", err)
	}

	// A relay that refuses multiplexing closes the connection instead of
	// answering.
	client2, server2 := net.Pipe()
	defer client2.Close()
	go func() {
		_ = server2.Close()
	}()
	if err := AwaitMuxAck(client2, 2*time.Second); err == nil {
		t.Fatal("AwaitMuxAck succeeded on a connection that was closed without an acknowledgement")
	}

	// A wrong byte is a protocol violation, not a refusal: the relay answered,
	// so it speaks the contract, and something is wrong with what it said.
	client3, server3 := net.Pipe()
	defer client3.Close()
	defer server3.Close()
	go func() {
		_, _ = server3.Write([]byte{0xFF})
	}()
	err := AwaitMuxAck(client3, 2*time.Second)
	if err == nil {
		t.Fatal("AwaitMuxAck accepted a wrong acknowledgement byte")
	}
	if !errors.Is(err, ErrProtocol) {
		t.Errorf("AwaitMuxAck error = %v, want it to wrap ErrProtocol", err)
	}
}

// TestStreamHandshakeConfigsReadTheTransportKeys proves the per-stream
// handshake is configured from the same keys a transport reads for a whole
// connection.
//
// A second spelling of the pre-shared key would silently disable
// authentication on multiplexed streams: the relay would compare the client's
// MAC against an empty key and reject every stream, or worse, a relay
// configured without a key would accept a stream that presented one.
func TestStreamHandshakeConfigsReadTheTransportKeys(t *testing.T) {
	settings := Settings{
		SettingPSK:           "shared-secret",
		"clientID":           "from-settings",
		"requireClientID":    true,
		"allowedClients":     []string{"alice"},
		"allowPing":          false,
		"disableReplayGuard": true,
	}

	sc := ServerStreamConfig(settings, "direct", 3*time.Second, nil, NopLogger())
	if !bytes.Equal(sc.PSK, []byte("shared-secret")) {
		t.Errorf("server PSK = %q, want %q", sc.PSK, "shared-secret")
	}
	if !sc.RequireClientID {
		t.Error("the server config does not carry requireClientID")
	}
	if len(sc.AllowedClients) != 1 || sc.AllowedClients[0] != "alice" {
		t.Errorf("allowed clients = %v, want [alice]", sc.AllowedClients)
	}
	if sc.AllowPing {
		t.Error("the server config allows ping despite allowPing false")
	}
	if sc.TransportName != "direct" {
		t.Errorf("transport name = %q, want %q", sc.TransportName, "direct")
	}

	cc := ClientStreamConfig(settings, "direct", "", 3*time.Second, NopLogger())
	if !bytes.Equal(cc.PSK, []byte("shared-secret")) {
		t.Errorf("client PSK = %q, want %q", cc.PSK, "shared-secret")
	}
	if cc.ClientID != "from-settings" {
		t.Errorf("client id = %q, want it taken from the settings", cc.ClientID)
	}

	// An explicit client id — from the relay entry — wins over the settings
	// bag, because the entry is the more specific statement.
	cc = ClientStreamConfig(settings, "direct", "from-entry", 3*time.Second, NopLogger())
	if cc.ClientID != "from-entry" {
		t.Errorf("client id = %q, want the explicit one to win", cc.ClientID)
	}

	// The replay guard is disabled by the setting, which is what the transports
	// do too.
	if g := NewStreamReplayGuard(settings); g != nil {
		t.Error("NewStreamReplayGuard returned a guard despite disableReplayGuard")
	}
	if g := NewStreamReplayGuard(Settings{"replayCacheSize": 16}); g == nil {
		t.Error("NewStreamReplayGuard returned nil for an enabled guard")
	}
}

// TestMuxStreamWrapperExposesHalfClose proves the adapter over a yamux stream
// publishes CloseWrite.
//
// This is the trap the whole wrapper exists for. yamux's Stream.Close is a
// half-close, but the method is named Close — and every caller in this codebase
// finds half-close support by type-asserting interface{ CloseWrite() error }.
// Handing a raw *yamux.Stream to the relay or the client would therefore leave
// every one of those assertions failing, silently turning each half-close into
// a no-op: a connection that lingers until an idle timeout instead of ending
// when one direction finishes.
func TestMuxStreamWrapperExposesHalfClose(t *testing.T) {
	clientSess, serverSess, stop := muxTestSessionPair(t)
	defer stop()

	st, err := clientSess.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer st.Close()

	conn := NewMuxStream(st)

	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("the wrapper around %T exposes no CloseWrite, so a half-close cannot reach the peer", st)
	}
	// baseStream is the type the transports actually return, so the property
	// that matters is that the wrapper survives baseStream's own forwarding.
	stream := NewStream(conn, &Request{Command: CmdConnectTCP}, "direct", 0)
	if _, ok := stream.(interface{ CloseWrite() error }); !ok {
		t.Fatalf("a %T built over the wrapper exposes no CloseWrite", stream)
	}
	// CloseRead has no yamux equivalent and must be a no-op rather than an
	// error: baseStream treats "unsupported" as success, and a non-nil error
	// here would be reported as a failed half-close by any caller that checked.
	cr, ok := conn.(interface{ CloseRead() error })
	if !ok {
		t.Fatal("the wrapper exposes no CloseRead")
	}
	if err := cr.CloseRead(); err != nil {
		t.Errorf("CloseRead returned %v, want nil: yamux has no read-side half-close and a no-op is the honest answer", err)
	}

	// CloseWrite must be a genuine half-close, not a full close: the read side
	// has to keep working, which is what the whole request/response pattern
	// depends on.
	serverSide, err := serverSess.AcceptStream()
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	defer serverSide.Close()

	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	// The peer sees the request and then EOF, which is what proves the FIN
	// travelled.
	//
	// The deadline is load bearing rather than defensive: this read is what
	// detects a CloseWrite that does not send a FIN, and without a bound the
	// failure surfaces as the whole package hitting the test timeout instead of
	// this test failing. A regression test has to fail on the assertion it is
	// about, in seconds, with a message naming the property — not three minutes
	// later as a panic that names nothing.
	_ = serverSide.SetReadDeadline(time.Now().Add(5 * time.Second))
	body, err := io.ReadAll(serverSide)
	if err != nil {
		t.Fatalf("read the request on the peer side: %v", err)
	}
	if string(body) != "request" {
		t.Fatalf("the peer read %q, want %q", body, "request")
	}

	// And this side can still read, which is what proves it was a half-close.
	if _, err := serverSide.Write([]byte("reply")); err != nil {
		t.Fatalf("write the reply: %v", err)
	}
	if err := serverSide.Close(); err != nil {
		t.Fatalf("close the peer's write side: %v", err)
	}
	got := make([]byte, len("reply"))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read the reply after our own half-close: %v", err)
	}
	if string(got) != "reply" {
		t.Fatalf("read %q, want %q", got, "reply")
	}
}

// TestMuxHalfCloseDeliversTheReply is the permanent regression test for the
// defect that forced this layer off smux.
//
// # What it pins
//
// A reply written after the peer has half-closed must still be delivered. The
// smux implementation this layer replaced discarded a stream's unread receive
// buffer as soon as both ends had sent FIN — Session.streamClosed →
// stream.recycleTokens — so a reply that arrived just before the FIN was
// thrown away and the reader saw a bare EOF. That is the ordinary shape of a
// relayed request/response protocol, not an edge case.
//
// # Why it loops
//
// The smux defect was probabilistic: a reader already blocked in Read was woken
// by the same push that buffered the data and usually won the race against the
// FIN. A single-shot version of this test passed most of the time and would
// have proved nothing. Looping it is what makes it a regression test rather
// than a coin toss — and it is why the round count is a floor, not a
// preference.
//
// # Why the reader is deliberately late
//
// Each round lets the FIN be processed before reading, so the outcome does not
// depend on scheduling. That is the worst case for this property, and the
// worst case is the one worth pinning: an implementation that passes only when
// the reader wins a race has not fixed anything.
func TestMuxHalfCloseDeliversTheReply(t *testing.T) {
	const rounds = 200

	for i := 0; i < rounds; i++ {
		if why := halfCloseExchange(t); why != "" {
			t.Fatalf("round %d of %d: %s", i+1, rounds, why)
		}
	}
}

// halfCloseExchange runs one request/reply exchange over a real multiplexed
// session and reports why the reply was not delivered, or "" on success.
//
// The exchange is the one a relay sees constantly:
//
//	client: Write(request); CloseWrite()   → the peer reads the request, then EOF
//	server: Write(reply);   Close()        → the peer must read the reply, then EOF
//
// Both halves run through NewMuxStream, so this exercises the adapter the
// production paths use rather than a raw yamux stream.
func halfCloseExchange(t *testing.T) string {
	t.Helper()

	clientSess, serverSess, stop := muxTestSessionPair(t)
	defer stop()

	const request = "request"
	const reply = "reply:" + request

	serverDone := make(chan string, 1)
	go func() {
		st, err := serverSess.AcceptStream()
		if err != nil {
			serverDone <- "accept stream: " + err.Error()
			return
		}
		defer st.Close()
		conn := NewMuxStream(st)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		body, err := io.ReadAll(conn)
		if err != nil {
			serverDone <- "read the request: " + err.Error()
			return
		}
		if string(body) != request {
			serverDone <- fmt.Sprintf("read %q, want %q", body, request)
			return
		}
		if _, err := conn.Write([]byte(reply)); err != nil {
			serverDone <- "write the reply: " + err.Error()
			return
		}
		// The half-close that used to trigger the loss: yamux sends a FIN and
		// leaves our read side open, which is exactly what smux mishandled.
		if err := conn.Close(); err != nil {
			serverDone <- "half-close: " + err.Error()
			return
		}
		serverDone <- ""
	}()

	st, err := clientSess.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer st.Close()
	conn := NewMuxStream(st)

	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("write the request: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("half-close our write side: %v", err)
	}

	if why := <-serverDone; why != "" {
		return "server side: " + why
	}

	// Let the peer's FIN be processed before reading, so the result does not
	// depend on which side wins a scheduling race. This is the delay that made
	// the smux defect deterministic.
	time.Sleep(20 * time.Millisecond)

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Sprintf("read the reply: %v (after %d bytes %q)", err, len(got), got)
	}
	if string(got) != reply {
		return fmt.Sprintf("read %q, want %q", got, reply)
	}
	return ""
}

// muxTestSessionPair returns a connected client/server session pair over a real
// TCP connection, plus a cleanup function.
//
// A real socket is used rather than net.Pipe because net.Pipe is synchronous
// and has no buffering: a write only completes when the peer reads it, which
// would make a half-close test measure the pipe's rendezvous rather than the
// multiplexer's FIN handling.
func muxTestSessionPair(t *testing.T) (*yamux.Session, *yamux.Session, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	type accepted struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan accepted, 1)
	go func() {
		conn, err := ln.Accept()
		acceptCh <- accepted{conn: conn, err: err}
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		t.Fatalf("dial: %v", err)
	}

	cfg := func() *yamux.Config {
		c := yamux.DefaultConfig()
		// The test must not write to os.Stderr, and yamux refuses a config with
		// neither field set.
		c.LogOutput = nil
		c.Logger = yamuxLogger{log: NopLogger()}
		return c
	}

	clientSess, err := yamux.Client(clientConn, cfg())
	if err != nil {
		_ = clientConn.Close()
		_ = ln.Close()
		t.Fatalf("client session: %v", err)
	}

	a := <-acceptCh
	if a.err != nil {
		_ = clientSess.Close()
		_ = ln.Close()
		t.Fatalf("accept: %v", a.err)
	}
	serverSess, err := yamux.Server(a.conn, cfg())
	if err != nil {
		_ = a.conn.Close()
		_ = clientSess.Close()
		_ = ln.Close()
		t.Fatalf("server session: %v", err)
	}

	stop := func() {
		_ = clientSess.Close()
		_ = serverSess.Close()
		_ = ln.Close()
	}
	return clientSess, serverSess, stop
}

// TestYamuxLoggerRoutesToTheProjectLogger proves yamux's diagnostics reach the
// project's logger instead of os.Stderr.
//
// yamux logs through a *log.Logger-shaped surface with the severity inside the
// message text. Flattening every line into one level would hide the errors that
// matter, so the adapter reads the "[ERR]"/"[WARN]" markers yamux emits. The
// markers are the library's own, so this test also pins the assumption the
// adapter is built on: if yamux ever drops them, every message lands at debug
// and the operator stops seeing session errors.
func TestYamuxLoggerRoutesToTheProjectLogger(t *testing.T) {
	rec := &muxRecordingLogger{}
	log := yamuxLogger{log: rec}

	log.Printf("[ERR] yamux: Failed to read header: %v", errors.New("boom"))
	log.Printf("[WARN] yamux: Discarding data for stream: %d", 3)
	log.Print("yamux: something routine")

	if len(rec.warns) != 1 {
		t.Fatalf("the [ERR] line produced %d warn entries, want 1: %v", len(rec.warns), rec.warns)
	}
	if !contains(rec.warns[0], "Failed to read header") {
		t.Errorf("the warn entry is %q, want it to carry the library's message", rec.warns[0])
	}
	if contains(rec.warns[0], "[ERR]") || contains(rec.warns[0], "yamux:") {
		t.Errorf("the warn entry is %q, want the redundant severity marker and package name stripped", rec.warns[0])
	}
	if len(rec.debugs) != 2 {
		t.Fatalf("the [WARN] and routine lines produced %d debug entries, want 2: %v", len(rec.debugs), rec.debugs)
	}
}

// muxRecordingLogger captures the level each message landed at.
type muxRecordingLogger struct {
	debugs []string
	warns  []string
}

func (r *muxRecordingLogger) Debug(msg string, args ...any) {
	r.debugs = append(r.debugs, msg+" "+fmt.Sprint(args...))
}
func (r *muxRecordingLogger) Info(string, ...any) {}
func (r *muxRecordingLogger) Warn(msg string, args ...any) {
	r.warns = append(r.warns, msg+" "+fmt.Sprint(args...))
}
func (r *muxRecordingLogger) Error(string, ...any) {}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || bytes.Contains([]byte(haystack), []byte(needle))
}
