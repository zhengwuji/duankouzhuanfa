package shadowsocks

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"porttransit/internal/cryptox"
	"porttransit/internal/transport"
)

// ssConn adapts a Shadowsocks AEAD chunk stream to net.Conn.
//
// Shadowsocks is a record protocol: every write becomes one length-prefixed
// AEAD chunk. net.Conn is a byte stream, so this type buffers a partially
// consumed chunk for reads and splits large writes into chunks of at most
// maxChunkPayload.
//
// # Key schedules
//
// Read and write use independent AEADs and independent nonce counters. This is
// not an optimisation: reusing a nonce across directions would be a complete
// break of both AES-GCM and ChaCha20-Poly1305, so the two directions are kept
// in separate fields that can never alias.
//
//   - 2022, client: write is keyed from a salt this side generated; read is
//     keyed from the salt the relay sends with its first response chunk.
//   - 2022, relay: read is keyed from the client's salt; write is keyed from a
//     fresh salt the relay generates and sends before its first response byte.
//   - legacy: both directions share one salt-derived key, as the 2017 design
//     specifies.
type ssConn struct {
	conn net.Conn
	m    method
	key  []byte

	// isClient reports which side initiated the connection.
	isClient bool

	// legacy selects the 2017 framing: no header, shared nonce counter.
	legacy bool

	// req is the decoded request.
	req *transport.Request

	// requestSalt is the salt the client sent on its request stream.
	//
	// The 2022 response header must echo it, which is how a client binds a
	// response to the request that caused it. The client fills this from its own
	// handshake and checks the echo; the relay fills it from the request it
	// decoded.
	requestSalt []byte

	// pendingDataLen is the payload length announced by a 2022 response header,
	// or -1 when there is none.
	//
	// A response header doubles as its stream's first length chunk, so the
	// payload chunk that follows it is read directly instead of after a length
	// chunk. Holding the length here keeps the rest of the read path identical
	// in both directions.
	pendingDataLen int

	writeMu sync.Mutex
	write   cipher.AEAD
	writeN  uint64

	readMu sync.Mutex
	read   cipher.AEAD
	readN  uint64
	inBuf  []byte

	// respReady tracks whether the client has consumed the relay's salt.
	respReady bool

	// saltSent tracks whether the relay has emitted its own salt. The salt
	// must precede the first response byte and must be emitted exactly once.
	saltSent bool

	closeOnce sync.Once
}

// newSSConn builds a Shadowsocks stream. The caller installs the AEADs.
func newSSConn(conn net.Conn, m method, key []byte, isClient bool, req *transport.Request) *ssConn {
	return &ssConn{conn: conn, m: m, key: key, isClient: isClient, req: req, pendingDataLen: -1}
}

// nonceLE renders n as the 12-byte little-endian counter Shadowsocks 2022 uses
// as an AEAD nonce.
//
// The 2022 spec is explicit that the counter is a 96-bit little-endian integer
// incremented once per encryption or decryption operation. It is deliberately
// not the construction cryptox.Chacha20Nonce builds, which puts a big-endian
// counter in the first four bytes and zeroes the rest: the two disagree from
// the second nonce onwards, so mixing them would desynchronise a 2022 peer.
func nonceLE(n uint64) []byte {
	var b [12]byte
	binary.LittleEndian.PutUint64(b[:8], n)
	return b[:]
}

// Request returns the decoded request.
func (c *ssConn) Request() *transport.Request { return c.req }

// TransportName returns the registry key.
func (c *ssConn) TransportName() string { return Name }

// Latency reports zero: Shadowsocks measures no round trip during setup.
func (c *ssConn) Latency() time.Duration { return 0 }

// Read returns the next bytes of plaintext.
func (c *ssConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.inBuf) == 0 {
		if err := c.fill(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.inBuf)
	c.inBuf = c.inBuf[n:]
	return n, nil
}

// fill reads and decrypts one chunk into inBuf.
func (c *ssConn) fill() error {
	// A loop rather than recursion: a peer that sends an endless run of
	// zero-length chunks must not be able to grow the goroutine stack.
	for {
		// The client's first read also consumes the relay's salt and response
		// header, which the relay only sends once it has a target to talk to.
		if c.isClient && c.m.is2022 && !c.respReady {
			if err := c.readResponseHeader2022(); err != nil {
				return err
			}
		}

		buf := make([]byte, c.m.maxChunkPayload()+64)
		var n int
		var err error
		if c.pendingDataLen >= 0 {
			// A response header already announced this chunk's length, so it is
			// not preceded by a length chunk.
			n, err = c.readDataChunk(c.pendingDataLen, buf)
			c.pendingDataLen = -1
		} else {
			n, err = c.readChunk(buf)
		}
		if err != nil {
			return err
		}
		if n == 0 {
			// A zero-length chunk is a keepalive, not an EOF: net.Conn's
			// contract reserves zero-with-nil-error for an empty read, so keep
			// going.
			continue
		}
		c.inBuf = append(c.inBuf, buf[:n]...)
		return nil
	}
}

// readChunk reads one length chunk and the payload chunk it announces, writing
// the plaintext into dst and returning its length.
func (c *ssConn) readChunk(dst []byte) (int, error) {
	aead := c.read
	if aead == nil {
		return 0, fmt.Errorf("shadowsocks: no read cipher is established")
	}

	if c.legacy {
		// The 2017 design sends the ciphertext length in the clear.
		var lenBuf [2]byte
		if _, err := io.ReadFull(c.conn, lenBuf[:]); err != nil {
			return 0, err
		}
		payloadLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if payloadLen > maxChunkPayloadLegacy+aead.Overhead() {
			return 0, fmt.Errorf("%w: shadowsocks chunk length %d exceeds the maximum", transport.ErrProtocol, payloadLen)
		}
		if payloadLen < aead.Overhead() {
			return 0, fmt.Errorf("%w: shadowsocks chunk length %d is below the tag size", transport.ErrProtocol, payloadLen)
		}
		return c.readDataChunk(payloadLen-aead.Overhead(), dst)
	}

	// In 2022 the length field is itself an encrypted 2-byte AEAD chunk, and it
	// carries the *plaintext* length of the next payload chunk rather than that
	// chunk's ciphertext length. Encrypting the length is what removes the
	// length oracle the 2017 design had, where an observer could read the
	// plaintext chunk size straight off the wire.
	lenRec := make([]byte, 2+aead.Overhead())
	if _, err := io.ReadFull(c.conn, lenRec); err != nil {
		return 0, err
	}
	lenPlain, err := aead.Open(lenRec[:0], c.nextReadNonce(), lenRec, nil)
	if err != nil {
		return 0, fmt.Errorf("%w: shadowsocks chunk length: %w", transport.ErrAuthFailed, err)
	}
	if len(lenPlain) != 2 {
		return 0, fmt.Errorf("%w: shadowsocks chunk length decoded to %d bytes", transport.ErrProtocol, len(lenPlain))
	}
	payloadLen := int(binary.BigEndian.Uint16(lenPlain))
	if payloadLen > c.m.maxChunkPayload() {
		return 0, fmt.Errorf("%w: shadowsocks chunk length %d exceeds the maximum", transport.ErrProtocol, payloadLen)
	}
	return c.readDataChunk(payloadLen, dst)
}

// readDataChunk reads one payload chunk whose plaintext is size bytes long.
//
// Both editions share it because they differ only in how the length is
// conveyed, not in how the payload that follows is framed.
func (c *ssConn) readDataChunk(size int, dst []byte) (int, error) {
	aead := c.read
	if aead == nil {
		return 0, fmt.Errorf("shadowsocks: no read cipher is established")
	}
	if size > len(dst) {
		return 0, fmt.Errorf("%w: shadowsocks chunk plaintext %d exceeds buffer %d", transport.ErrProtocol, size, len(dst))
	}

	ciphertext := make([]byte, size+aead.Overhead())
	if _, err := io.ReadFull(c.conn, ciphertext); err != nil {
		return 0, err
	}
	plain, err := aead.Open(ciphertext[:0], c.nextReadNonce(), ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("%w: shadowsocks chunk: %w", transport.ErrAuthFailed, err)
	}
	copy(dst, plain)
	return len(plain), nil
}

// nextReadNonce returns the nonce for the next read chunk and advances the
// counter.
func (c *ssConn) nextReadNonce() []byte {
	n := c.readN
	c.readN++
	if c.legacy {
		// The legacy path keeps the construction this build has always used, so
		// a peer that already interoperates with it keeps working.
		return cryptox.Chacha20Nonce(uint32(n), [8]byte{})
	}
	return nonceLE(n)
}

// nextWriteNonce returns the nonce for the next write chunk and advances the
// counter.
func (c *ssConn) nextWriteNonce() []byte {
	n := c.writeN
	c.writeN++
	if c.legacy {
		return cryptox.Chacha20Nonce(uint32(n), [8]byte{})
	}
	return nonceLE(n)
}

// readResponseHeader2022 consumes the relay's salt and decrypts its response
// header.
//
// The header's plaintext length is fixed by the salt length alone — type,
// timestamp, the echoed request salt and a length field — which is what makes a
// single read unambiguous: nothing else in the stream is readable before the
// AEAD tag verifies.
func (c *ssConn) readResponseHeader2022() error {
	const fixedPart = 1 + 8 + 2 // type + timestamp + length
	headerPlainLen := fixedPart + c.m.saltLen

	blob := make([]byte, c.m.saltLen+headerPlainLen+c.m.aead.TagSize())
	if _, err := io.ReadFull(c.conn, blob); err != nil {
		return fmt.Errorf("shadowsocks: read response header: %w", err)
	}

	salt := blob[:c.m.saltLen]
	subkey := sessionSubkey2022(c.key, salt)
	aead, err := cryptox.NewAEAD(c.m.aead, subkey)
	if err != nil {
		return err
	}

	plain, err := aead.Open(nil, nonceLE(0), blob[c.m.saltLen:], nil)
	if err != nil {
		return fmt.Errorf("%w: shadowsocks response header: %w", transport.ErrAuthFailed, err)
	}
	if len(plain) != headerPlainLen {
		return fmt.Errorf("%w: shadowsocks response header is %d bytes, want %d", transport.ErrProtocol, len(plain), headerPlainLen)
	}
	if plain[0] != headerTypeServerStream {
		return fmt.Errorf("%w: shadowsocks unexpected response header type 0x%02x", transport.ErrProtocol, plain[0])
	}
	// A response whose timestamp is outside the window is as useless as a
	// replayed request, so the same rule applies in this direction.
	if err := checkTimestamp(binary.BigEndian.Uint64(plain[1:9])); err != nil {
		return err
	}

	// The echoed request salt is what binds this response to the request that
	// caused it. Without this check a relay could splice a response from one
	// session into another.
	echoed := plain[9 : 9+c.m.saltLen]
	if !cryptox.ConstantTimeEqual(echoed, c.requestSalt) {
		return fmt.Errorf("%w: shadowsocks response header did not echo the request salt", transport.ErrAuthFailed)
	}

	c.read = aead
	// The header consumed nonce 0, so payload chunks start at 1.
	c.readN = 1
	c.pendingDataLen = int(binary.BigEndian.Uint16(plain[9+c.m.saltLen:]))
	c.respReady = true
	return nil
}

// Write encrypts p as one or more AEAD chunks.
func (c *ssConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	// A relay's 2022 response stream does not exist until it has something to
	// say: its salt and header go out together with the first payload bytes,
	// because the spec requires the header to always be sent along with payload.
	if !c.isClient && c.m.is2022 && !c.saltSent {
		if len(p) == 0 {
			return 0, nil
		}
		return c.writeFirstResponse2022(p)
	}

	if c.write == nil {
		return 0, fmt.Errorf("shadowsocks: no write cipher is established")
	}

	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > c.m.maxChunkPayload() {
			n = c.m.maxChunkPayload()
		}
		chunk := p[:n]
		p = p[n:]

		if _, err := c.conn.Write(c.sealChunk(chunk)); err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// sealChunk encrypts one payload chunk into its wire form.
func (c *ssConn) sealChunk(chunk []byte) []byte {
	if c.legacy {
		sealed := c.write.Seal(nil, c.nextWriteNonce(), chunk, nil)
		out := make([]byte, 2+len(sealed))
		binary.BigEndian.PutUint16(out[:2], uint16(len(sealed)))
		copy(out[2:], sealed)
		return out
	}

	// Nonces are handed out in wire order, not in the order the pieces happen to
	// be computed. The length chunk goes out first, so it must take the lower
	// nonce; sealing the payload first would give the two chunks each other's
	// nonce and the peer, which decrypts strictly in stream order, would reject
	// the length chunk before it ever saw the payload.
	lenPlain := make([]byte, 2)
	binary.BigEndian.PutUint16(lenPlain, uint16(len(chunk)))
	lenSealed := c.write.Seal(nil, c.nextWriteNonce(), lenPlain, nil)
	sealed := c.write.Seal(nil, c.nextWriteNonce(), chunk, nil)

	out := make([]byte, 0, len(lenSealed)+len(sealed))
	out = append(out, lenSealed...)
	out = append(out, sealed...)
	return out
}

// writeFirstResponse2022 emits the relay's salt, its response header and the
// first payload chunk in a single write, then switches the write direction to
// the new key.
//
// The header carries the echoed request salt and the length of the payload
// chunk that rides along with it, so it doubles as the stream's first length
// chunk. Everything is buffered and handed to one Write because the spec
// forbids splitting the salt from the header chunks: separate writes produce
// predictable packet sizes that fingerprint the protocol.
func (c *ssConn) writeFirstResponse2022(p []byte) (int, error) {
	if len(c.requestSalt) != c.m.saltLen {
		return 0, fmt.Errorf("shadowsocks: response stream has no request salt to echo")
	}

	salt := cryptox.RandomBytes(c.m.saltLen)
	subkey := sessionSubkey2022(c.key, salt)
	aead, err := cryptox.NewAEAD(c.m.aead, subkey)
	if err != nil {
		return 0, err
	}
	c.write = aead
	c.writeN = 0

	n := len(p)
	if n > c.m.maxChunkPayload() {
		n = c.m.maxChunkPayload()
	}
	chunk := p[:n]

	plain := make([]byte, 0, 1+8+len(c.requestSalt)+2)
	plain = append(plain, headerTypeServerStream)
	plain = binary.BigEndian.AppendUint64(plain, uint64(time.Now().Unix()))
	plain = append(plain, c.requestSalt...)
	plain = binary.BigEndian.AppendUint16(plain, uint16(n))

	header := aead.Seal(nil, c.nextWriteNonce(), plain, nil)
	payload := aead.Seal(nil, c.nextWriteNonce(), chunk, nil)

	out := make([]byte, 0, len(salt)+len(header)+len(payload))
	out = append(out, salt...)
	out = append(out, header...)
	out = append(out, payload...)
	if _, err := c.conn.Write(out); err != nil {
		return 0, err
	}
	c.saltSent = true

	total := n
	for p = p[n:]; len(p) > 0; {
		m := len(p)
		if m > c.m.maxChunkPayload() {
			m = c.m.maxChunkPayload()
		}
		if _, err := c.conn.Write(c.sealChunk(p[:m])); err != nil {
			return total, err
		}
		total += m
		p = p[m:]
	}
	return total, nil
}

// Close closes the underlying connection.
func (c *ssConn) Close() error {
	var err error
	c.closeOnce.Do(func() { err = c.conn.Close() })
	return err
}

// LocalAddr reports the local socket address.
func (c *ssConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// RemoteAddr reports the peer socket address.
func (c *ssConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// SetDeadline applies both deadlines.
func (c *ssConn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

// SetReadDeadline applies a read deadline.
func (c *ssConn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

// SetWriteDeadline applies a write deadline.
func (c *ssConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// CloseWrite half-closes the underlying connection when it supports it.
func (c *ssConn) CloseWrite() error {
	if cw, ok := c.conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
