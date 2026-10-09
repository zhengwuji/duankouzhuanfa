// Package shadowsocks implements Shadowsocks-2022 (TCP) and the legacy
// AEAD-2017 ciphers.
//
// Shadowsocks-2022 is a substantial redesign of the original protocol. Its
// purpose is to defeat replay and active probing, which the 2017 AEAD design
// was vulnerable to: an attacker who captured a valid request could replay it,
// and an attacker who guessed the password could confirm the guess by watching
// for a response.
//
// # What 2022 adds
//
//   - Every TCP session opens with a random salt and *two* encrypted header
//     chunks, the first of which carries a timestamp. A relay rejects a header
//     whose timestamp is outside a narrow window and remembers every salt it
//     has accepted, which makes replay useless.
//   - The relay sends no response until it has authenticated a request, so a
//     prober who guesses wrong learns nothing — there is no distinguishable
//     failure mode.
//   - The session subkey comes from BLAKE3's key-derivation mode rather than
//     HKDF, and the AEAD nonce is a 96-bit little-endian counter.
//
// # Wire format (client → relay), per SIP022 section 3.1
//
//	request salt            16 or 32 bytes, same length as the PSK
//	fixed-length header     AEAD, nonce 0
//	  type                  1 byte  (0x00 client stream)
//	  timestamp             8 bytes big endian, Unix epoch seconds
//	  length                2 bytes big endian: plaintext length of the next chunk
//	variable-length header  AEAD, nonce 1
//	  ATYP + address + port SOCKS5 encoding
//	  padding length        2 bytes big endian
//	  padding               padding length bytes, non-zero on a client that
//	                        has no initial payload to send
//	  initial payload       whatever follows the padding, if any
//	length chunk            AEAD, 2-byte big-endian payload length
//	payload chunk           AEAD, up to 0xFFFF bytes of plaintext
//
// The relay's response stream is shorter: its own salt, then a single
// fixed-length header that doubles as the first length chunk (type 0x01, the
// timestamp, the request salt it is answering, and the payload length), then a
// payload chunk and the usual length/payload pairs.
//
// # Legacy AEAD-2017
//
// The older format is also implemented because many existing servers still
// speak it: a salt, then a stream of length-prefixed AEAD chunks with a
// monotonically incrementing nonce and no header at all. Selecting it is a
// deliberate downgrade and the GUI marks it as such.
package shadowsocks

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"lukechampine.com/blake3"

	"porttransit/internal/cryptox"
	"porttransit/internal/logx"
	"porttransit/internal/transport"
)

// Name is the registry key.
const Name = "shadowsocks"

// DefaultPort is the conventional listen port.
const DefaultPort = 8388

func init() {
	transport.Register(transport.Factory{
		Name:         Name,
		Description:  "Shadowsocks-2022 AEAD with replay protection, or the legacy AEAD-2017 ciphers for compatibility.",
		NativeHeader: true,
		DefaultPort:  DefaultPort,
		Build:        func() (transport.Dialer, transport.Handler) { return Dialer{}, Handler{} },
	})
}

// Settings keys understood by this transport.
const (
	// SettingMethod selects the cipher: 2022-blake3-aes-128-gcm,
	// 2022-blake3-aes-256-gcm, 2022-blake3-chacha20-poly1305, or a legacy
	// AEAD-2017 method.
	SettingMethod = "method"
	// SettingPassword is the shared secret. For the 2022 methods it must be
	// base64 of exactly the cipher's key length.
	SettingPassword = "password"
	// SettingTimeout bounds the handshake.
	SettingTimeout = "timeout"
	// SettingLegacy forces the AEAD-2017 framing even when a 2022 method name
	// is configured.
	SettingLegacy = "legacy"
)

// Method names supported by this build.
const (
	Method2022AES128GCM    = "2022-blake3-aes-128-gcm"
	Method2022AES256GCM    = "2022-blake3-aes-256-gcm"
	Method2022ChaCha20Poly = "2022-blake3-chacha20-poly1305"
	MethodAES128GCM        = "aes-128-gcm"
	MethodAES256GCM        = "aes-256-gcm"
	MethodChaCha20Poly1305 = "chacha20-ietf-poly1305"
)

// header type bytes, per the 2022 spec.
const (
	headerTypeClientStream = 0x00
	headerTypeServerStream = 0x01
)

// Framing limits from the 2022 spec's header section.
const (
	// minPaddingLength and maxPaddingLength bound the request header's padding.
	minPaddingLength = 0
	maxPaddingLength = 900

	// requestFixedHeaderLen is type + timestamp + length.
	requestFixedHeaderLen = 1 + 8 + 2

	// responseFixedHeaderLenBase is type + timestamp + length; the request salt
	// the header echoes sits between the timestamp and the length.
	responseFixedHeaderLenBase = 1 + 8 + 2

	// minVariableHeaderLen is the shortest a variable-length header can be: the
	// smallest SOCKS5 address (a one-character domain) plus its padding length.
	minVariableHeaderLen = 1 + 1 + 1 + 2 + 2

	// maxVariableHeaderLen bounds the second request header chunk.
	//
	// The chunk carries the address, a big-endian padding length, the padding,
	// and whatever initial payload the client sent with the header. The spec
	// caps the padding at 900 bytes but deliberately does not cap the payload —
	// a client is entitled to send a full chunk's worth of first bytes, and the
	// reference implementation does exactly that. The bound is therefore the
	// length field's own maximum: nothing larger can be expressed, and a probe
	// can never make the server allocate more than one chunk.
	maxVariableHeaderLen = 0xFFFF

	// maxChunkPayloadLegacy is the largest plaintext a 2017 AEAD chunk may
	// carry: the length field is 2 bytes and the top two bits are reserved, so
	// the usable maximum is 16383.
	maxChunkPayloadLegacy = 0x3FFF

	// maxChunkPayload2022 is the 2022 limit. The edition raises the cap to the
	// full 16-bit range because the length field is itself authenticated.
	maxChunkPayload2022 = 0xFFFF
)

// sessionSubkeyContext is the BLAKE3 key-derivation context string the 2022
// spec fixes. It must match byte for byte: it is what domain-separates this
// derivation from every other BLAKE3 use.
const sessionSubkeyContext = "shadowsocks 2022 session subkey"

// timestampMaxSkew is how far a header's timestamp may differ from local time
// before the message is treated as a replay.
const timestampMaxSkew = 30 * time.Second

// saltRetention is how long an accepted request salt is remembered. The spec
// requires at least 60 seconds, which is longer than the 30-second timestamp
// window, so a captured request stays unusable for its whole life.
const saltRetention = 60 * time.Second

// sessionSubkey2022 derives a session subkey the way SIP022 section 2.2
// requires: BLAKE3's key-derivation mode over the PSK concatenated with the
// salt, key first.
//
// The subkey is as long as the cipher's key, which is also the salt length.
// DeriveKey is BLAKE3's XOF, so any output length is available from one
// derivation.
func sessionSubkey2022(key, salt []byte) []byte {
	material := make([]byte, 0, len(key)+len(salt))
	material = append(material, key...)
	material = append(material, salt...)

	sub := make([]byte, len(key))
	blake3.DeriveKey(sub, sessionSubkeyContext, material)
	return sub
}

// checkTimestamp rejects a header whose timestamp is outside the accepted
// window. The spec treats anything beyond 30 seconds as a replay.
func checkTimestamp(ts uint64) error {
	skew := time.Since(time.Unix(int64(ts), 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > timestampMaxSkew {
		return fmt.Errorf("%w: shadowsocks timestamp skew %s", transport.ErrAuthFailed, skew.Truncate(time.Second))
	}
	return nil
}

// replayGuard remembers recently accepted request salts so a captured request
// cannot be replayed inside the timestamp window.
//
// The spec forbids a Bloom filter here: a false positive would reject a
// legitimate client, and salts only have to be held for 60 seconds, so an exact
// map is both correct and cheap.
type replayGuard struct {
	mu    sync.Mutex
	seen  map[string]time.Time
	clock func() time.Time

	// lastSweep throttles expiry so the cost is amortised rather than paid by
	// every connection. Without it, a relay taking many connections a second
	// would walk the whole table on each one — quadratic in the connection
	// rate, which is exactly the load a busy relay is under.
	lastSweep time.Time
}

// newReplayGuard returns an empty guard.
func newReplayGuard() *replayGuard {
	return &replayGuard{seen: make(map[string]time.Time), clock: time.Now}
}

// check records salt and reports whether it had already been seen.
//
// It is called only after the header has authenticated, so an unauthenticated
// probe cannot flood the table: an attacker who cannot forge a tag never gets
// an entry.
func (g *replayGuard) check(salt []byte) bool {
	now := g.clock()

	g.mu.Lock()
	defer g.mu.Unlock()

	// Expired entries are swept at most once per retention window. Entries live
	// for saltRetention, so sweeping that often still keeps the table to
	// roughly the salts seen in one window, and the sweep is off the per-
	// connection path. It also avoids a background goroutine, which would need
	// a lifetime tied to the process for no benefit.
	if now.Sub(g.lastSweep) >= saltRetention {
		for k, exp := range g.seen {
			if now.After(exp) {
				delete(g.seen, k)
			}
		}
		g.lastSweep = now
	}

	k := string(salt)
	if exp, dup := g.seen[k]; dup {
		// An entry that has outlived its window is not a replay. The sweep is
		// throttled, so a stale entry can still be present when it is looked up.
		if now.Before(exp) {
			return false
		}
	}
	g.seen[k] = now.Add(saltRetention)
	return true
}

// replaySalts is the process-wide guard. A replay is a replay whichever
// listener receives it, so the table is shared rather than per-listener.
var replaySalts = newReplayGuard()

// method describes one cipher suite.
type method struct {
	name    string
	keyLen  int
	saltLen int
	aead    cryptox.Cipher
	is2022  bool
}

// maxChunkPayload is the largest plaintext a single chunk of this method may
// carry. The 2022 edition raised it from 0x3FFF to the full 16-bit range.
func (m method) maxChunkPayload() int {
	if m.is2022 {
		return maxChunkPayload2022
	}
	return maxChunkPayloadLegacy
}

// resolveMethod maps a configured name to its parameters.
func resolveMethod(name string) (method, error) {
	switch name {
	case Method2022AES128GCM:
		return method{name: name, keyLen: 16, saltLen: 16, aead: cryptox.CipherAES128GCM, is2022: true}, nil
	case Method2022AES256GCM:
		return method{name: name, keyLen: 32, saltLen: 32, aead: cryptox.CipherAES256GCM, is2022: true}, nil
	case Method2022ChaCha20Poly:
		return method{name: name, keyLen: 32, saltLen: 32, aead: cryptox.CipherChaCha20Poly1305, is2022: true}, nil
	case MethodAES128GCM:
		return method{name: name, keyLen: 16, saltLen: 16, aead: cryptox.CipherAES128GCM}, nil
	case MethodAES256GCM:
		return method{name: name, keyLen: 32, saltLen: 32, aead: cryptox.CipherAES256GCM}, nil
	case MethodChaCha20Poly1305:
		return method{name: name, keyLen: 32, saltLen: 32, aead: cryptox.CipherChaCha20Poly1305}, nil
	default:
		return method{}, fmt.Errorf("shadowsocks: unknown method %q", name)
	}
}

// deriveKey turns the configured password into the master key.
//
// For the 2022 methods the spec requires the password to already be base64 of
// exactly keyLen bytes — it is a raw key, not a passphrase, and the spec
// forbids deriving it from a password. For the legacy methods the password is a
// passphrase and is stretched with the classic EVP_BytesToKey construction.
func (m method) deriveKey(password string) ([]byte, error) {
	if m.is2022 {
		key, err := cryptox.Base64DecodeLenient(password)
		if err != nil {
			return nil, fmt.Errorf("shadowsocks: %s password must be base64: %w", m.name, err)
		}
		if len(key) != m.keyLen {
			return nil, fmt.Errorf("shadowsocks: %s needs a %d-byte key, the password decodes to %d", m.name, m.keyLen, len(key))
		}
		return key, nil
	}
	return evpBytesToKey([]byte(password), m.keyLen), nil
}

// evpBytesToKey is OpenSSL's classic key derivation: repeatedly hash the
// passphrase, concatenating the digests until enough bytes are available.
//
// It is weak by modern standards — no salt, no work factor — but it is what
// every legacy Shadowsocks implementation uses, so interoperability requires
// it. This is the reason the GUI steers users to the 2022 methods.
func evpBytesToKey(password []byte, keyLen int) []byte {
	var out []byte
	var prev []byte
	for len(out) < keyLen {
		h := cryptox.MD5Sum(append(append([]byte{}, prev...), password...))
		out = append(out, h...)
		prev = h
	}
	return out[:keyLen]
}

// Dialer establishes client→relay Shadowsocks streams.
type Dialer struct{}

// Name returns the registry key.
func (Dialer) Name() string { return Name }

// Dial performs the Shadowsocks handshake and writes the request header.
func (d Dialer) Dial(ctx context.Context, req transport.DialRequest) (transport.Stream, error) {
	timeout := req.Settings.GetDuration(SettingTimeout, 10*time.Second)
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	m, key, err := resolveSettings(req.Settings)
	if err != nil {
		return nil, err
	}

	conn, err := (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", req.ServerAddr)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, err
	}

	target := ""
	if req.Request != nil {
		target = req.Request.Target
	}
	if req.Request == nil || req.Request.Command == transport.CmdPing || target == "" {
		// Shadowsocks has no ping. A TCP connect to the relay's own port is
		// the honest probe: the relay accepts and closes, exercising the full
		// key derivation and AEAD setup.
		target = req.ServerAddr
		req.Request = &transport.Request{
			Command:   transport.CmdConnectTCP,
			Target:    target,
			Transport: Name,
			Meta:      map[string]string{"ping": "true"},
		}
	}

	var stream transport.Stream
	if m.is2022 {
		stream, err = clientHandshake2022(conn, m, key, target, req.Request)
	} else {
		stream, err = clientHandshakeLegacy(conn, m, key, target, req.Request)
	}
	if err != nil {
		conn.Close()
		return nil, err
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return stream, nil
}

// clientHandshake2022 writes the salt and both encrypted request header chunks.
//
// The salt and the two chunks are buffered into one buffer and handed to a
// single Write, which the spec requires: splitting them would produce
// predictable packet sizes that reveal the protocol.
func clientHandshake2022(conn net.Conn, m method, key []byte, target string, req *transport.Request) (transport.Stream, error) {
	salt := cryptox.RandomBytes(m.saltLen)
	// The session subkey binds the salt to the master key, so a salt that
	// happens to repeat across sessions still yields a fresh AEAD key.
	aead, err := cryptox.NewAEAD(m.aead, sessionSubkey2022(key, salt))
	if err != nil {
		return nil, err
	}

	addr, err := encodeTarget(target)
	if err != nil {
		return nil, err
	}

	// This client writes no initial payload with the header, so the spec
	// requires non-zero padding: a header carrying neither payload nor padding
	// is exactly the shape a server must reject. The length is drawn from the
	// full permitted range so the padding is not a deterministic function of
	// the address length, which would otherwise leak it.
	padLen := minPaddingLength + 1 + int(binary.BigEndian.Uint16(cryptox.RandomBytes(2))%(maxPaddingLength-minPaddingLength))

	// The variable-length header is the address, then a big-endian padding
	// length, then the padding itself.
	variable := make([]byte, 0, len(addr)+2+padLen)
	variable = append(variable, addr...)
	variable = binary.BigEndian.AppendUint16(variable, uint16(padLen))
	variable = append(variable, cryptox.RandomBytes(padLen)...)

	// The fixed-length header's length field describes the *next* chunk, which
	// is the variable-length header.
	fixed := make([]byte, 0, requestFixedHeaderLen)
	fixed = append(fixed, headerTypeClientStream)
	fixed = binary.BigEndian.AppendUint64(fixed, uint64(time.Now().Unix()))
	fixed = binary.BigEndian.AppendUint16(fixed, uint16(len(variable)))

	fixedSealed := aead.Seal(nil, nonceLE(0), fixed, nil)
	variableSealed := aead.Seal(nil, nonceLE(1), variable, nil)

	out := make([]byte, 0, len(salt)+len(fixedSealed)+len(variableSealed))
	out = append(out, salt...)
	out = append(out, fixedSealed...)
	out = append(out, variableSealed...)
	if _, err := conn.Write(out); err != nil {
		return nil, fmt.Errorf("shadowsocks: write header: %w", err)
	}

	c := newSSConn(conn, m, key, true, req)
	c.write = aead
	// Both header chunks consumed a nonce, so the first payload chunk uses 2.
	c.writeN = 2
	// The response header must echo this salt; the client checks that it does.
	c.requestSalt = salt
	return c, nil
}

// clientHandshakeLegacy writes the salt and starts the 2017 AEAD chunk stream.
func clientHandshakeLegacy(conn net.Conn, m method, key []byte, target string, req *transport.Request) (transport.Stream, error) {
	salt := cryptox.RandomBytes(m.saltLen)
	if _, err := conn.Write(salt); err != nil {
		return nil, fmt.Errorf("shadowsocks: write salt: %w", err)
	}
	// The 2017 design derives the AEAD key directly from the salt.
	sessionKey := cryptox.HKDF(key, salt, "ss-subkey", m.keyLen)
	aead, err := cryptox.NewAEAD(m.aead, sessionKey)
	if err != nil {
		return nil, err
	}

	c := newSSConn(conn, m, key, true, req)
	c.legacy = true
	c.write = aead
	c.read = aead

	addr, err := encodeTarget(target)
	if err != nil {
		return nil, err
	}
	// The first chunk carries the target address, which is what a 2017 relay
	// expects at the head of the stream.
	if _, err := c.Write(addr); err != nil {
		return nil, err
	}
	return c, nil
}

// Handler accepts relay-side Shadowsocks streams.
type Handler struct{}

// Name returns the registry key.
func (Handler) Name() string { return Name }

// Handle reads the Shadowsocks header from an accepted connection.
func (h Handler) Handle(ctx context.Context, raw net.Conn, req transport.HandleRequest) (transport.Stream, error) {
	timeout := req.Settings.GetDuration(SettingTimeout, 10*time.Second)
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	m, key, err := resolveSettings(req.Settings)
	if err != nil {
		raw.Close()
		return nil, err
	}

	if err := raw.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		raw.Close()
		return nil, err
	}

	if !m.is2022 {
		return serverHandshakeLegacy(raw, m, key, req)
	}
	return serverHandshake2022(raw, m, key, req)
}

// closeUnverified closes a connection whose request header failed to
// authenticate or validate, without revealing how many bytes were consumed.
//
// The spec's detection-prevention section explains the problem: closing a
// socket that still has unread data makes the kernel send RST, while closing an
// empty one sends FIN. A prober that dribbles one byte at a time therefore
// learns exactly how far the server read before giving up, which is a
// fingerprint. Setting SO_LINGER to zero forces RST in both cases, so the close
// looks identical whether the receive buffer still holds probe bytes or not.
// It is the spec's first suggested strategy and the only one that needs no
// drain loop.
func closeUnverified(raw net.Conn) {
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	raw.Close()
}

// serverHandshake2022 reads and validates a 2022 request stream.
func serverHandshake2022(raw net.Conn, m method, key []byte, req transport.HandleRequest) (transport.Stream, error) {
	// The salt and the fixed-length header are read in exactly one call, as the
	// spec requires. The length is fixed by the salt length alone — nothing in
	// the header says how long it is — which is what makes a single read
	// unambiguous.
	headerLen := m.saltLen + requestFixedHeaderLen + m.aead.TagSize()
	blob := make([]byte, headerLen)
	if _, err := io.ReadFull(raw, blob); err != nil {
		// A truncated read is what a prober dribbling one byte at a time
		// produces, so it gets the same non-revealing close as a failed tag.
		closeUnverified(raw)
		return nil, err
	}

	salt := blob[:m.saltLen]
	aead, err := cryptox.NewAEAD(m.aead, sessionSubkey2022(key, salt))
	if err != nil {
		closeUnverified(raw)
		return nil, err
	}

	fixed, err := aead.Open(nil, nonceLE(0), blob[m.saltLen:], nil)
	if err != nil {
		closeUnverified(raw)
		// A failed Open is the normal outcome of a probe, so it is logged at
		// debug and the connection is closed without a reply. That silence is
		// the point: there is no failure mode for a prober to distinguish.
		loggerFor(req.Logger).Debug("shadowsocks: header authentication failed", "remote", transport.RemoteAddrString(raw))
		return nil, fmt.Errorf("%w: %w", transport.ErrAuthFailed, err)
	}
	if len(fixed) != requestFixedHeaderLen {
		closeUnverified(raw)
		return nil, fmt.Errorf("%w: shadowsocks header decoded to %d bytes", transport.ErrProtocol, len(fixed))
	}
	if fixed[0] != headerTypeClientStream {
		closeUnverified(raw)
		return nil, fmt.Errorf("%w: shadowsocks unexpected header type 0x%02x", transport.ErrProtocol, fixed[0])
	}

	// Timestamp freshness is what defeats replay: a captured header replayed
	// more than 30 seconds later is rejected even though its AEAD tag is valid.
	ts := binary.BigEndian.Uint64(fixed[1:9])
	if err := checkTimestamp(ts); err != nil {
		closeUnverified(raw)
		loggerFor(req.Logger).Warn("shadowsocks: header timestamp outside the accepted window", "remote", transport.RemoteAddrString(raw))
		return nil, err
	}

	// The salt is only recorded once the header has authenticated and its
	// timestamp has passed, so an unauthenticated probe cannot fill the table
	// and lock out real clients.
	if !replaySalts.check(salt) {
		closeUnverified(raw)
		loggerFor(req.Logger).Warn("shadowsocks: replayed request salt", "remote", transport.RemoteAddrString(raw))
		return nil, fmt.Errorf("%w: shadowsocks request salt was already used", transport.ErrAuthFailed)
	}

	varLen := int(binary.BigEndian.Uint16(fixed[9:11]))
	if varLen < minVariableHeaderLen || varLen > maxVariableHeaderLen {
		closeUnverified(raw)
		return nil, fmt.Errorf("%w: shadowsocks variable header length %d is out of range", transport.ErrProtocol, varLen)
	}

	// The second header chunk is a standalone AEAD chunk with its own nonce,
	// read at the length the first chunk announced.
	variable := make([]byte, varLen+m.aead.TagSize())
	if _, err := io.ReadFull(raw, variable); err != nil {
		closeUnverified(raw)
		return nil, err
	}
	plain, err := aead.Open(variable[:0], nonceLE(1), variable, nil)
	if err != nil {
		closeUnverified(raw)
		loggerFor(req.Logger).Debug("shadowsocks: variable header authentication failed", "remote", transport.RemoteAddrString(raw))
		return nil, fmt.Errorf("%w: shadowsocks variable header: %w", transport.ErrAuthFailed, err)
	}

	target, addrLen, err := transport.DecodeAddrFrom(plain)
	if err != nil {
		closeUnverified(raw)
		return nil, fmt.Errorf("%w: shadowsocks address: %w", transport.ErrProtocol, err)
	}

	// The address is followed by a big-endian padding length, the padding, and
	// then whatever initial payload the client sent. A server must reject a
	// header that runs past the chunk it arrived in.
	rest := plain[addrLen:]
	if len(rest) < 2 {
		closeUnverified(raw)
		return nil, fmt.Errorf("%w: shadowsocks header has no padding length", transport.ErrProtocol)
	}
	padLen := int(binary.BigEndian.Uint16(rest[:2]))
	if padLen > len(rest)-2 {
		closeUnverified(raw)
		return nil, fmt.Errorf("%w: shadowsocks padding length %d overruns the header chunk", transport.ErrProtocol, padLen)
	}
	payload := rest[2+padLen:]

	// Either initial payload or padding must be present. A header with neither
	// is the shape a prober's truncated request would have, so it is rejected
	// rather than answered.
	if padLen == 0 && len(payload) == 0 {
		closeUnverified(raw)
		return nil, fmt.Errorf("%w: shadowsocks header carries neither payload nor padding", transport.ErrProtocol)
	}

	conn := newSSConn(raw, m, key, false, &transport.Request{
		Command:   transport.CmdConnectTCP,
		Target:    target,
		Transport: Name,
	})
	conn.read = aead
	// The response header must echo the salt this request used.
	conn.requestSalt = salt
	// Both header chunks consumed a nonce, so payload chunks start at 2.
	conn.readN = 2
	// Any initial payload the client sent past the header belongs to the
	// stream and must not be lost.
	if len(payload) > 0 {
		conn.inBuf = append(conn.inBuf, payload...)
	}

	if err := raw.SetReadDeadline(time.Time{}); err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// serverHandshakeLegacy reads a 2017 AEAD stream whose first chunk is the
// target address.
func serverHandshakeLegacy(raw net.Conn, m method, key []byte, req transport.HandleRequest) (transport.Stream, error) {
	salt := make([]byte, m.saltLen)
	if _, err := io.ReadFull(raw, salt); err != nil {
		raw.Close()
		return nil, err
	}
	sessionKey := cryptox.HKDF(key, salt, "ss-subkey", m.keyLen)
	aead, err := cryptox.NewAEAD(m.aead, sessionKey)
	if err != nil {
		raw.Close()
		return nil, err
	}

	conn := newSSConn(raw, m, key, false, nil)
	conn.legacy = true
	conn.read = aead
	conn.write = aead

	// The first decrypted chunk is the address. It may be split across chunks
	// in theory, so the address is accumulated until it parses.
	addr := make([]byte, 0, 262)
	buf := make([]byte, 512)
	for {
		n, err := conn.readChunk(buf)
		if err != nil {
			raw.Close()
			return nil, err
		}
		addr = append(addr, buf[:n]...)
		if t, consumed, err := transport.DecodeAddrFrom(addr); err == nil {
			conn.req = &transport.Request{
				Command:   transport.CmdConnectTCP,
				Target:    t,
				Transport: Name,
			}
			// Bytes after the address are payload.
			if rest := addr[consumed:]; len(rest) > 0 {
				conn.inBuf = append(conn.inBuf, rest...)
			}
			if err := raw.SetReadDeadline(time.Time{}); err != nil {
				raw.Close()
				return nil, err
			}
			return conn, nil
		}
		if len(addr) > 512 {
			raw.Close()
			return nil, fmt.Errorf("%w: shadowsocks address did not parse", transport.ErrProtocol)
		}
	}
}

func resolveSettings(s transport.Settings) (method, []byte, error) {
	name := s.GetString(SettingMethod, Method2022ChaCha20Poly)
	m, err := resolveMethod(name)
	if err != nil {
		return method{}, nil, err
	}
	password := s.GetString(SettingPassword, "")
	if password == "" {
		return method{}, nil, fmt.Errorf("shadowsocks: %s is required", SettingPassword)
	}
	key, err := m.deriveKey(password)
	if err != nil {
		return method{}, nil, err
	}
	return m, key, nil
}

func hostOf(target string) string {
	h, _, err := transport.SplitHostPort(target)
	if err != nil {
		return target
	}
	return h
}

// encodeTarget renders host:port in the SOCKS5 address encoding the protocol
// uses for both the 2022 header and the 2017 first chunk.
func encodeTarget(target string) ([]byte, error) {
	return transport.EncodeAddr(nil, target)
}

// loggerFor adapts the shared logger to the transport package's minimal
// interface.
//
// It returns an explicit no-op rather than nil: a nil interface panics on the
// first method call, and the transports log from inside handshake paths where
// a panic would take down the whole relay.
func loggerFor(l *logx.Logger) transport.Logger {
	if l == nil {
		return transport.NopLogger()
	}
	return l
}
