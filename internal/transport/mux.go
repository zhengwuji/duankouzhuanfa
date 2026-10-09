package transport

import (
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
)

// This file defines the multiplexing layer that sits above a transport
// connection.
//
// # Why it exists
//
// Opening a proxied connection costs a full transport handshake: a TCP
// connection plus, on the encrypted schemes, a TLS or REALITY handshake. That
// is one or two round trips to the relay, paid again for every connection a
// browser or an application opens — dozens for a single page load. On a
// long-haul path the handshake dominates the connection's whole lifetime.
//
// Multiplexing pays that cost once. One transport connection carries a yamux
// session, and each proxied connection becomes a stream inside it. Later
// connections cost no handshake at all, and all of them share one congestion
// window, which behaves better on a lossy path than dozens of windows
// competing with each other.
//
// # Wire contract
//
//	client → relay: [transport handshake][preamble, command CmdMux]
//	then, for each multiplexed stream:
//	  client → relay: [yamux SYN][preamble for that stream][payload]
//
// The connection-level preamble carries no target address: it exists so the
// relay's ordinary transport handler can accept and authenticate the
// connection with the code it already has, and so it can recognise the request
// as "multiplex this" rather than "forward this".
//
// The per-stream preamble is the *same* preamble a single-connection tunnel
// sends. That is deliberate: it means each stream carries its own target, its
// own client id and its own MAC, so the relay's ACL, account admission, forward
// matching and per-connection limits apply to a multiplexed stream exactly as
// they apply to a plain connection. It also means the framing is already
// implemented and already covered by tests, rather than a second hand-rolled
// request format that could drift from the first.
//
// # Which schemes can carry it
//
// Multiplexing rides the PortTransit preamble, so it works for the schemes that
// speak it: those whose factory reports NativeHeader false (direct, tls,
// reality, ws, httpupgrade). A scheme that carries the target inside its own
// wire protocol has no way to express a connection-level command, and its
// per-connection header cannot describe a stream. SupportsMux reports which is
// which, and the client only attempts a session on a scheme that supports one.
//
// # Half-close
//
// A multiplexed stream propagates half-close, and with yamux that is the
// library's *native* behaviour rather than an extra: Stream.Close on an
// established stream moves it to streamLocalClose, sends a FIN, and leaves the
// read side working until the peer's own FIN arrives — at which point the
// stream reaches streamClosed. Data the peer wrote before its FIN stays in the
// stream's receive buffer and is still returned by Read.
//
// yamux's Stream nevertheless has no CloseWrite method, and this codebase
// relies on CloseWrite being discoverable — baseStream.CloseWrite forwards to
// the underlying net.Conn only when it implements interface{ CloseWrite()
// error }, and the relay's copy loop and the client's pipe probe for the same
// interface. The yamux stream is therefore wrapped in muxStream below, whose
// CloseWrite maps onto yamux's Close.
//
// Propagating half-close matters rather than being a detail, for two reasons:
//
//   - The relay's copy loop and the client's pipe both probe for CloseWrite and
//     take a different path when it is absent — closing the whole connection
//     instead. A stream that did not half-close would be torn down when one
//     direction finished, truncating a response whose request side has already
//     been sent.
//   - yamux releases a stream's bookkeeping only once both sides have sent FIN.
//     Half-close is therefore also what stops a long-lived session from
//     accumulating entries for finished streams.
//
// # Why yamux rather than the smux library
//
// The predecessor of this layer used the `smux` package from the `xtaci`
// organisation, which had a data-loss defect that made it unusable here: once
// both ends of a stream had half-closed, smux's tryHalfCloseCleanup ran
// Session.streamClosed → stream.recycleTokens, which drained the stream's
// receive ring buffer to return session tokens. Any bytes the peer had written
// but this side had not read yet were discarded and the reader saw a bare EOF.
// That is exactly the relay's traffic pattern — any request/response protocol
// where one direction finishes before the reply is read — and it reproduced on
// roughly 80% of attempts. yamux does not recycle a closed stream's buffer, so
// the reply survives the FIN. TestMuxHalfCloseDeliversTheReply in this package
// pins that property and loops it, because the old defect was probabilistic and
// a single-shot test would have passed by luck.
//
// # Settings
//
// Both sides read the same keys, so an operator writes them once per relay and
// once per listener. A mismatch in the session parameters does not hang: the
// session dies immediately and the client falls back to one connection per
// stream (see the client's session pool).

// Settings keys understood by the multiplexing layer. They are read from a
// transport's Settings bag on both the client and the relay, because both ends
// have to agree on the session's framing parameters.
//
// The keys are deliberately library-neutral. They were named smux* while smux
// was the session library; this feature has never been released, so they were
// renamed outright rather than carried forward as aliases. An smux* key left in
// a configuration is simply ignored.
const (
	// SettingMux turns multiplexing on for this relay entry or listener. It
	// defaults to off: an operator opts in, and an existing deployment is
	// unaffected until they do.
	SettingMux = "mux"
	// SettingMuxMaxStreams caps how many streams one session may carry at
	// once. It is the per-session bound that stops one session from being used
	// to exhaust the relay.
	//
	// yamux has no such limit of its own, so this is enforced by PortTransit on
	// both ends: the relay refuses to admit a stream past the cap (muxSession.
	// admitStream) and the client opens another session rather than overfilling
	// one (relayPool.pick).
	SettingMuxMaxStreams = "muxMaxStreams"
	// SettingMuxMaxSessions caps how many sessions a client will open to one
	// relay when its existing sessions are all full. It bounds the client's own
	// resource use, and beyond it the client falls back to a dedicated
	// connection per stream rather than refusing to serve.
	SettingMuxMaxSessions = "muxMaxSessions"
	// SettingMuxIdleTimeout closes a session that has carried no stream for
	// this long. Zero or negative disables it, which means a client would hold
	// the connection open forever.
	SettingMuxIdleTimeout = "muxIdleTimeout"
	// SettingMuxKeepAliveInterval is how often yamux pings the peer. It maps
	// to yamux's KeepAliveInterval.
	SettingMuxKeepAliveInterval = "muxKeepAliveInterval"
	// SettingMuxKeepAliveDisabled turns the keepalive off entirely. It maps to
	// yamux's EnableKeepAlive, inverted: yamux spells the field positively, so
	// this key is negated before it is stored.
	SettingMuxKeepAliveDisabled = "muxKeepAliveDisabled"
	// SettingMuxMaxWindowSize is the largest receive window one stream may
	// advertise, in bytes. It maps to yamux's MaxStreamWindowSize, which is
	// what a stalled reader can make the *peer* hold on this stream's behalf.
	SettingMuxMaxWindowSize = "muxMaxWindowSize"
	// SettingMuxAcceptBacklog bounds how many streams may be waiting to be
	// accepted. It maps to yamux's AcceptBacklog, and on the client it is also
	// the number of unacknowledged stream opens the session will allow in
	// flight before blocking the open.
	SettingMuxAcceptBacklog = "muxAcceptBacklog"
	// SettingMuxStreamOpenTimeout bounds how long a stream may stay
	// unacknowledged before yamux closes the session. Zero disables it, which
	// is a deliberate choice the operator can make.
	SettingMuxStreamOpenTimeout = "muxStreamOpenTimeout"
	// SettingMuxStreamCloseTimeout bounds how long a half-closed stream may
	// wait for the peer's FIN before yamux force-closes it and sends a reset.
	// It is the backstop for a peer that half-closes and then vanishes without
	// ever finishing the close. Zero disables it.
	SettingMuxStreamCloseTimeout = "muxStreamCloseTimeout"
	// SettingMuxConnectionWriteTimeout is yamux's "safety valve" for writes to
	// the underlying connection: if a write cannot be queued and completed
	// within it, the session is torn down rather than blocking forever.
	SettingMuxConnectionWriteTimeout = "muxConnectionWriteTimeout"
	// SettingPSK is the preamble's pre-shared key. It is declared here because
	// the per-stream handshake helpers below have to read exactly the key the
	// transports themselves read; a second spelling would silently disable
	// authentication on multiplexed streams.
	SettingPSK = "psk"
)

// Defaults for the multiplexing settings.
const (
	// DefaultMuxMaxStreams caps a session at 256 concurrent streams. A
	// browser rarely exceeds a few dozen, so this leaves generous headroom
	// while keeping the relay's per-session memory and file-descriptor use
	// bounded. Raising it lets a single hostile session claim more of the
	// relay; lowering it makes the client open more sessions, each of which
	// costs a handshake — the very cost multiplexing exists to remove.
	DefaultMuxMaxStreams = 256
	// DefaultMuxMaxSessions caps how many sessions a client opens to one
	// relay: four sessions of 256 streams is 1024 concurrent proxied
	// connections, far beyond what a desktop workload reaches. The cap is what
	// keeps a runaway local program from turning into an unbounded number of
	// relay connections; past it the client degrades to one connection per
	// stream, which is correct and merely slower.
	DefaultMuxMaxSessions = 4
	// DefaultMuxKeepAliveInterval matches yamux's own default. It is what
	// detects a relay that vanished without sending anything — a dead NAT
	// mapping, a black-holed route — which TCP keepalive alone would take
	// minutes to notice.
	DefaultMuxKeepAliveInterval = 30 * time.Second
	// MinMuxMaxWindowSize is the smallest stream window yamux will accept.
	// yamux.VerifyConfig rejects anything below it outright, and a rejected
	// config means no session at all, so a smaller configured value is clamped
	// up to this rather than passed through to fail opaquely at first use.
	MinMuxMaxWindowSize uint32 = 256 * 1024
	// DefaultMuxMaxWindowSize matches yamux's own default, which is also its
	// minimum. It is deliberately modest: the window is what a stalled reader
	// can make the peer hold on that stream's behalf, so 256 streams of 256 KiB
	// is the worst case a full session can pin on the other end.
	DefaultMuxMaxWindowSize = 256 * 1024
	// DefaultMuxAcceptBacklog matches yamux's own default.
	DefaultMuxAcceptBacklog = 256
	// DefaultMuxStreamOpenTimeout matches yamux's own default. A stream that is
	// never acknowledged means the peer is not processing frames at all, so
	// closing the session and starting over is better than waiting.
	DefaultMuxStreamOpenTimeout = 75 * time.Second
	// DefaultMuxStreamCloseTimeout matches yamux's own default.
	//
	// It is a backstop, not the primary reclaim path, and the ordering is worth
	// stating because it is the one place this library swap could have changed
	// which mechanism tears a dead stream down. In the normal case the relay's
	// own per-stream read deadline (limits.idleTimeout, 300s by default) fires
	// first: the copy loop returns, the stream is half-closed, and the session's
	// idle timer (ServerMuxIdleTimeout, also 300s) then closes the whole
	// session. yamux's timer only ever fires on a peer that half-closed and then
	// stopped answering entirely, where our read deadline has already unwound
	// the stream — so it is bounded cleanup, not a competing policy. An
	// operator who wants it shorter than the idle timeout can lower this key.
	DefaultMuxStreamCloseTimeout = 5 * time.Minute
	// DefaultMuxConnectionWriteTimeout matches yamux's own default. Writes to
	// the underlying connection are expected to move along quickly, so a write
	// that cannot be completed in ten seconds means the connection is gone.
	DefaultMuxConnectionWriteTimeout = 10 * time.Second

	// ClientMuxIdleTimeout is how long the client keeps an idle session. It
	// is deliberately shorter than the relay's default (ServerMuxIdleTimeout)
	// so the client retires a session first: if both ends expired at the same
	// moment, every idle timeout would race a close against a new stream, and
	// the stream would land on a session that is being torn down.
	ClientMuxIdleTimeout = 60 * time.Second
	// ServerMuxIdleTimeout is how long the relay keeps a session that has
	// carried no stream. It is longer than the client's so a session is
	// normally retired by the side that owns the pool; the relay's timeout is
	// the backstop that stops a client which never closes anything from
	// holding a connection open indefinitely.
	ServerMuxIdleTimeout = 300 * time.Second
)

// SupportsMux reports whether the named transport scheme can carry a
// multiplexed session.
//
// It is true exactly for the schemes that exchange the PortTransit preamble:
// the mux request is a preamble command, and each multiplexed stream begins
// with a preamble of its own. A scheme that reports NativeHeader carries the
// target inside its own wire protocol instead, so it has no connection-level
// command to express the request with.
func SupportsMux(name string) bool {
	f, ok := Lookup(name)
	if !ok {
		return false
	}
	return !f.NativeHeader
}

// MuxEnabled reports whether multiplexing is switched on in these settings.
func MuxEnabled(s Settings) bool { return s.GetBool(SettingMux, false) }

// MuxMaxStreams returns the per-session stream cap.
func MuxMaxStreams(s Settings) int {
	n := s.GetInt(SettingMuxMaxStreams, DefaultMuxMaxStreams)
	if n < 1 {
		// A cap below one would make the session useless rather than safe, so
		// a nonsense value falls back to the default instead of refusing every
		// stream and looking like an outage.
		return DefaultMuxMaxStreams
	}
	return n
}

// MuxIdleTimeout returns how long an idle session is kept, or zero when idle
// expiry is switched off.
func MuxIdleTimeout(s Settings, def time.Duration) time.Duration {
	d := s.GetDuration(SettingMuxIdleTimeout, def)
	if d < 0 {
		return def
	}
	return d
}

// MuxMaxSessions returns how many sessions the client will open to one relay
// before it starts using dedicated connections instead.
func MuxMaxSessions(s Settings) int {
	n := s.GetInt(SettingMuxMaxSessions, DefaultMuxMaxSessions)
	if n < 1 {
		return DefaultMuxMaxSessions
	}
	return n
}

// MuxSessionConfig builds the yamux session parameters from settings.
//
// log receives yamux's own diagnostics, which would otherwise go to os.Stderr
// and bypass the relay's structured logger. See the LogOutput handling below.
//
// Every field yamux's VerifyConfig rejects is repaired here rather than passed
// through, because a rejected config means no session at all: the operator
// would see every connection fall back to a dedicated one, with the real reason
// buried in a log line they did not ask for. Repairing keeps the operator's
// intent as far as the library allows.
func MuxSessionConfig(s Settings, log Logger) (*yamux.Config, error) {
	cfg := yamux.DefaultConfig()

	cfg.EnableKeepAlive = !s.GetBool(SettingMuxKeepAliveDisabled, false)
	cfg.KeepAliveInterval = s.GetDuration(SettingMuxKeepAliveInterval, DefaultMuxKeepAliveInterval)
	if cfg.KeepAliveInterval <= 0 {
		// yamux rejects a zero interval even when the keepalive is disabled,
		// so a zero here would make the session unbuildable rather than merely
		// quiet. Falling back to the default is the only reading that keeps the
		// setting meaningful.
		cfg.KeepAliveInterval = DefaultMuxKeepAliveInterval
	}

	// The window is read as an int64 so the clamp below is correct on a 32-bit
	// build too, where an int cannot hold yamux's full uint32 range.
	window := int64(s.GetInt(SettingMuxMaxWindowSize, DefaultMuxMaxWindowSize))
	if window < int64(MinMuxMaxWindowSize) {
		window = int64(MinMuxMaxWindowSize)
	}
	if window > int64(math.MaxUint32) {
		window = int64(math.MaxUint32)
	}
	cfg.MaxStreamWindowSize = uint32(window)

	cfg.AcceptBacklog = s.GetInt(SettingMuxAcceptBacklog, DefaultMuxAcceptBacklog)
	if cfg.AcceptBacklog < 1 {
		cfg.AcceptBacklog = DefaultMuxAcceptBacklog
	}

	// A zero stream-open timeout is meaningful in yamux — it disables the
	// timeout entirely — so only a negative value falls back to the default.
	cfg.StreamOpenTimeout = s.GetDuration(SettingMuxStreamOpenTimeout, DefaultMuxStreamOpenTimeout)
	if cfg.StreamOpenTimeout < 0 {
		cfg.StreamOpenTimeout = DefaultMuxStreamOpenTimeout
	}
	cfg.StreamCloseTimeout = s.GetDuration(SettingMuxStreamCloseTimeout, DefaultMuxStreamCloseTimeout)
	if cfg.StreamCloseTimeout < 0 {
		cfg.StreamCloseTimeout = DefaultMuxStreamCloseTimeout
	}

	cfg.ConnectionWriteTimeout = s.GetDuration(SettingMuxConnectionWriteTimeout, DefaultMuxConnectionWriteTimeout)
	if cfg.ConnectionWriteTimeout <= 0 {
		// A zero write timeout would make every internal timer fire
		// immediately, tearing sessions down as fast as they are built.
		cfg.ConnectionWriteTimeout = DefaultMuxConnectionWriteTimeout
	}

	// yamux.DefaultConfig sets LogOutput to os.Stderr, which would let the
	// library write its own diagnostics straight to the relay's stderr —
	// bypassing the structured logger, escaping the log level, and polluting
	// the operator's console. The two fields are mutually exclusive (yamux
	// rejects a config with both set) and one of them must be set, so the
	// output field is cleared and the logger is pointed at this package's
	// logger instead.
	cfg.LogOutput = nil
	cfg.Logger = yamuxLogger{log: orNop(log)}

	if err := yamux.VerifyConfig(cfg); err != nil {
		return nil, fmt.Errorf("%w: multiplexing session parameters: %v", ErrProtocol, err)
	}
	return cfg, nil
}

// yamuxLogger adapts this package's Logger to the interface yamux expects.
//
// yamux emits its diagnostics through a *log.Logger-style surface: Print,
// Printf and Println, with the severity carried inside the message text as an
// "[ERR]" or "[WARN]" prefix. The prefix is what this adapter reads, so
// yamux's errors land at a level the operator's log configuration can actually
// act on instead of being flattened into debug output.
type yamuxLogger struct{ log Logger }

func (y yamuxLogger) Print(v ...any)                 { y.emit(fmt.Sprint(v...)) }
func (y yamuxLogger) Printf(format string, v ...any) { y.emit(fmt.Sprintf(format, v...)) }
func (y yamuxLogger) Println(v ...any)               { y.emit(fmt.Sprintln(v...)) }

func (y yamuxLogger) emit(msg string) {
	msg = strings.TrimSpace(msg)
	switch {
	case strings.Contains(msg, "[ERR]"):
		y.log.Warn("yamux session error", "err", trimYamuxPrefix(msg, "[ERR]"))
	case strings.Contains(msg, "[WARN]"):
		y.log.Debug("yamux session warning", "msg", trimYamuxPrefix(msg, "[WARN]"))
	default:
		y.log.Debug("yamux session", "msg", msg)
	}
}

// trimYamuxPrefix strips the library's own severity marker and its package
// name, both of which are redundant once the message has been routed to a
// levelled logger.
func trimYamuxPrefix(msg, marker string) string {
	msg = strings.TrimSpace(strings.TrimPrefix(msg, marker))
	return strings.TrimSpace(strings.TrimPrefix(msg, "yamux:"))
}

// muxStream adapts a yamux stream to the surface the rest of PortTransit
// expects: net.Conn plus a discoverable half-close.
//
// # Why the wrapper is necessary
//
// yamux's Stream.Close *is* a half-close: on an established stream it moves the
// state to streamLocalClose, sends a FIN, and leaves reads working until the
// peer's FIN arrives. But there is no CloseWrite method to find, and every
// caller in this codebase — baseStream.CloseWrite, the relay's copyWithLimits
// and the client's pipe — discovers half-close support by type-asserting
// interface{ CloseWrite() error }. Without this wrapper those assertions would
// all fail, each caller would take its "half-close unsupported" branch, and a
// request/response protocol would have its reply truncated or its connection
// left lingering until an idle timeout.
type muxStream struct {
	*yamux.Stream
}

// CloseWrite half-closes the write side. yamux's Stream.Close is itself a
// half-close, so it maps directly.
func (s *muxStream) CloseWrite() error { return s.Stream.Close() }

// CloseRead is a no-op, which is what baseStream does when a connection has no
// read-side half-close. yamux has none, and inventing one by discarding the
// receive buffer would throw away exactly the data this layer exists to
// preserve.
func (s *muxStream) CloseRead() error { return nil }

// newMuxStream wraps one accepted or opened yamux stream.
func newMuxStream(st *yamux.Stream) *muxStream { return &muxStream{Stream: st} }

// NewMuxStream wraps a yamux stream so the result carries a discoverable
// half-close, and returns it as a net.Conn.
//
// Every caller that puts a yamux stream into the relay's or the client's data
// path must go through this rather than passing the *yamux.Stream directly: a
// raw stream has no CloseWrite, so each caller's half-close probe would fail
// and the half-close would silently become a no-op. See muxStream for the full
// reasoning.
func NewMuxStream(st *yamux.Stream) net.Conn { return newMuxStream(st) }

// ServerStreamConfig builds the relay-side handshake for one multiplexed
// stream.
//
// It reads the same keys the preamble-carrying transports read for a whole
// connection, so a stream inside a session is authenticated and policed by the
// same rules as a connection: the same pre-shared key, the same client-id
// requirements, the same ping policy. A second set of keys here would be a way
// to bypass policy simply by multiplexing.
//
// replay is shared by every stream of a listener rather than built per stream.
// A per-stream guard would start empty and therefore accept a nonce it had
// already seen on a sibling stream, which is exactly what a replay guard is
// for.
func ServerStreamConfig(s Settings, transportName string, timeout time.Duration, replay *ReplayGuard, log Logger) ServerHandshakeConfig {
	return ServerHandshakeConfig{
		PSK:             DecodePSK(s.GetString(SettingPSK, "")),
		Replay:          replay,
		Timeout:         timeout,
		Logger:          log,
		RequireClientID: s.GetBool("requireClientID", false),
		AllowedClients:  s.GetStringSlice("allowedClients"),
		AllowPing:       s.GetBool("allowPing", true),
		TransportName:   transportName,
	}
}

// NewStreamReplayGuard builds the replay guard one listener shares across all
// of its multiplexed streams. It returns nil when the guard is disabled.
func NewStreamReplayGuard(s Settings) *ReplayGuard {
	if s.GetBool("disableReplayGuard", false) {
		return nil
	}
	return NewReplayGuard(s.GetInt("replayCacheSize", 65536), 0)
}

// ClientStreamConfig builds the client-side handshake for one multiplexed
// stream. It mirrors ServerStreamConfig, reading the same keys a transport
// reads when it opens a connection of its own.
func ClientStreamConfig(s Settings, transportName, clientID string, timeout time.Duration, log Logger) ClientHandshakeConfig {
	if clientID == "" {
		clientID = s.GetString("clientID", "")
	}
	return ClientHandshakeConfig{
		PSK:           DecodePSK(s.GetString(SettingPSK, "")),
		ClientID:      clientID,
		TransportName: transportName,
		Timeout:       timeout,
		Logger:        log,
	}
}

// MuxAck is the single byte the relay writes on the underlying connection once
// it has agreed to serve a multiplexed session.
//
// # Why an acknowledgement exists at all
//
// The preamble is a one-way frame: a transport's client handshake writes it and
// returns without reading a reply, because for an ordinary forward there is
// nothing to reply with. Multiplexing is the exception, because the two ends
// must agree on the session parameters and only the relay knows whether it was
// configured for it.
//
// Without this byte, a client configured for multiplexing against a relay that
// is not would see a successful handshake — the preamble write does not fail —
// and then start a session on a connection the relay has already closed. The
// first symptom would be a connection that hangs until the session keepalive
// gives up, thirty seconds later, and the client would keep doing that for
// every connection. With the byte, the refusal surfaces immediately as a failed
// read, which the client turns into a normal dial failure and a fallback to a
// dedicated connection.
const MuxAck = 0x01

// AcknowledgeMux tells the client that the relay accepted the session.
//
// It is written before the yamux session starts, so the byte is the first thing
// on the connection after the preamble and the client can read it with a plain
// ReadFull. Writing it later would interleave it with session frames.
func AcknowledgeMux(conn net.Conn, timeout time.Duration) error {
	if timeout > 0 {
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()
	}
	_, err := conn.Write([]byte{MuxAck})
	return err
}

// AwaitMuxAck reads the relay's acceptance byte, bounded by timeout.
//
// A relay that does not serve multiplexing closes the connection instead, so a
// refusal arrives here as io.EOF or a reset rather than as a wrong byte. Both
// are reported as an error, which is what lets the caller fall back cleanly.
func AwaitMuxAck(conn net.Conn, timeout time.Duration) error {
	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	}
	var b [1]byte
	if _, err := io.ReadFull(conn, b[:]); err != nil {
		return fmt.Errorf("transport: no multiplexing acknowledgement: %w", err)
	}
	if b[0] != MuxAck {
		return fmt.Errorf("%w: unexpected multiplexing acknowledgement 0x%02x", ErrProtocol, b[0])
	}
	return nil
}
