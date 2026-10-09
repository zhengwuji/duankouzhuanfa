package transport

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"porttransit/internal/version"
)

// ProtocolVersion is re-exported so transport implementations do not need to
// import the version package for the common case.
const ProtocolVersion = version.ProtocolVersion

// The PortTransit preamble is the framed request that simple transports
// (direct, tls, reality, ws, http) exchange *after* their own handshake
// completes.
//
//	offset  size  field
//	0       4     magic "PTRF" (PortTransit Relay Frame)
//	4       1     protocol version
//	5       1     command (CmdConnectTCP / CmdUDPAssociate / CmdPing)
//	6       1     flags (reserved, must be 0)
//	7       1     reserved (must be 0)
//	8       8     unix timestamp, seconds, big endian
//	16      8     nonce, random
//	24      1     client-id length
//	25      n     client-id bytes
//	25+n    m     SOCKS5-encoded target address (absent for CmdPing)
//	…       1     padding length
//	…       p     padding bytes (random)
//	…       32    HMAC-SHA256 of every preceding byte, keyed by the PSK
//
// The MAC is what stops the relay from being an open proxy: without the PSK a
// prober cannot produce a frame the relay will act on, and the relay answers
// nothing distinguishable before the MAC verifies.
const (
	preambleMagic0 = 'P'
	preambleMagic1 = 'T'
	preambleMagic2 = 'R'
	preambleMagic3 = 'F'

	// PreambleMinLen is the size of a preamble with no client id, no address
	// and no padding.
	PreambleMinLen = 4 + 1 + 1 + 1 + 1 + 8 + 8 + 1 + 1 + 32

	// PreambleMaxLen bounds a decoded preamble so a hostile peer cannot make
	// the relay allocate without limit.
	PreambleMaxLen = 4 + 1 + 1 + 1 + 1 + 8 + 8 + 1 + 64 + (1 + 255 + 2) + 1 + 256 + 32

	// MaxPreamblePadding is the largest random pad a client may insert.
	MaxPreamblePadding = 256

	// PreambleSkew is how far a client clock may drift before the relay
	// rejects the frame as stale.
	PreambleSkew = 90 * time.Second
)

// Preamble carries a decoded request plus the anti-replay material needed to
// validate it.
type Preamble struct {
	Version  uint8
	Command  Command
	Time     time.Time
	Nonce    [8]byte
	ClientID string
	Target   string
	// MAC is the received tag. Verify overwrites it with the expected tag.
	MAC [32]byte

	// macInput is the exact byte range the MAC covers, captured during decode.
	// Keeping it unexported means a caller cannot verify a MAC over different
	// bytes than the ones actually received.
	macInput []byte
}

// EncodePreamble serialises p, padding it to a random length and appending an
// HMAC keyed by psk. When psk is empty the MAC field is filled with zeros and
// the relay must be configured to accept unauthenticated frames.
func EncodePreamble(p *Preamble, psk []byte) ([]byte, error) {
	if !p.Command.Valid() {
		return nil, fmt.Errorf("%w: invalid command 0x%02x", ErrProtocol, uint8(p.Command))
	}
	if len(p.ClientID) > 64 {
		return nil, fmt.Errorf("%w: client id too long (%d > 64)", ErrProtocol, len(p.ClientID))
	}

	version := p.Version
	if version == 0 {
		version = ProtocolVersion
	}

	buf := make([]byte, 0, PreambleMinLen+len(p.ClientID)+len(p.Target))
	buf = append(buf, preambleMagic0, preambleMagic1, preambleMagic2, preambleMagic3, version, byte(p.Command), 0, 0)

	ts := p.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	buf = binary.BigEndian.AppendUint64(buf, uint64(ts.Unix()))

	nonce := p.Nonce
	if nonce == ([8]byte{}) {
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, fmt.Errorf("preamble: nonce: %w", err)
		}
	}
	buf = append(buf, nonce[:]...)

	buf = append(buf, byte(len(p.ClientID)))
	buf = append(buf, p.ClientID...)

	if p.Command != CmdPing {
		var err error
		buf, err = EncodeAddr(buf, p.Target)
		if err != nil {
			return nil, err
		}
	}

	// Random padding defeats length fingerprinting of the target address.
	var padLen [1]byte
	if _, err := rand.Read(padLen[:]); err != nil {
		return nil, fmt.Errorf("preamble: padding length: %w", err)
	}
	n := int(padLen[0]) % (MaxPreamblePadding + 1)
	buf = append(buf, byte(n))
	if n > 0 {
		pad := make([]byte, n)
		if _, err := rand.Read(pad); err != nil {
			return nil, fmt.Errorf("preamble: padding: %w", err)
		}
		buf = append(buf, pad...)
	}

	// With no key configured the MAC field must be all zeros: Verify rejects a
	// keyed frame when the relay has no key, so writing an HMAC of the empty
	// key here would make the unauthenticated mode unusable.
	var sum []byte
	if len(psk) == 0 {
		sum = make([]byte, sha256.Size)
	} else {
		mac := hmac.New(sha256.New, psk)
		mac.Write(buf)
		sum = mac.Sum(nil)
	}
	buf = append(buf, sum...)
	return buf, nil
}

// DecodePreamble reads exactly one preamble from r. The returned MAC is the
// received tag; callers must run Verify (or VerifyWithReplay) before acting.
func DecodePreamble(r io.Reader) (*Preamble, error) {
	head := make([]byte, 24)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	if head[0] != preambleMagic0 || head[1] != preambleMagic1 || head[2] != preambleMagic2 || head[3] != preambleMagic3 {
		return nil, fmt.Errorf("%w: bad preamble magic", ErrProtocol)
	}
	p := &Preamble{
		Version: head[4],
		Command: Command(head[5]),
	}
	if head[6] != 0 || head[7] != 0 {
		return nil, fmt.Errorf("%w: reserved preamble flags set", ErrProtocol)
	}
	if p.Version != ProtocolVersion {
		return nil, fmt.Errorf("%w: protocol version %d, this build speaks %d", ErrProtocol, p.Version, ProtocolVersion)
	}
	if !p.Command.Valid() {
		return nil, fmt.Errorf("%w: invalid command 0x%02x", ErrProtocol, head[5])
	}
	p.Time = time.Unix(int64(binary.BigEndian.Uint64(head[8:16])), 0)
	copy(p.Nonce[:], head[16:24])

	// The MAC covers everything up to the final 32 bytes, so the whole frame
	// must be buffered to verify it. PreambleMaxLen caps that buffering.
	body := make([]byte, 0, 128)
	body = append(body, head...)

	var idLen [1]byte
	if _, err := io.ReadFull(r, idLen[:]); err != nil {
		return nil, err
	}
	body = append(body, idLen[0])
	if int(idLen[0]) > 64 {
		return nil, fmt.Errorf("%w: client id length %d exceeds 64", ErrProtocol, idLen[0])
	}
	if idLen[0] > 0 {
		id := make([]byte, idLen[0])
		if _, err := io.ReadFull(r, id); err != nil {
			return nil, err
		}
		p.ClientID = string(id)
		body = append(body, id...)
	}

	if p.Command != CmdPing {
		addr, n, err := readAddrStream(r)
		if err != nil {
			return nil, err
		}
		p.Target = addr
		body = append(body, n...)
	}

	var padLen [1]byte
	if _, err := io.ReadFull(r, padLen[:]); err != nil {
		return nil, err
	}
	body = append(body, padLen[0])
	if int(padLen[0]) > MaxPreamblePadding {
		return nil, fmt.Errorf("%w: padding length %d exceeds %d", ErrProtocol, padLen[0], MaxPreamblePadding)
	}
	if padLen[0] > 0 {
		pad := make([]byte, padLen[0])
		if _, err := io.ReadFull(r, pad); err != nil {
			return nil, err
		}
		body = append(body, pad...)
	}

	if len(body) > PreambleMaxLen {
		return nil, fmt.Errorf("%w: preamble length %d exceeds %d", ErrProtocol, len(body), PreambleMaxLen)
	}

	if _, err := io.ReadFull(r, p.MAC[:]); err != nil {
		return nil, err
	}
	p.macInput = body
	return p, nil
}

// Verify recomputes the HMAC over the received frame and compares it in
// constant time. An empty psk means the relay accepts unauthenticated frames,
// in which case the received tag must be all zeros.
func (p *Preamble) Verify(psk []byte) error {
	if len(psk) == 0 {
		if p.MAC != ([32]byte{}) {
			return fmt.Errorf("%w: frame is MACed but no key is configured", ErrAuthFailed)
		}
		return nil
	}
	mac := hmac.New(sha256.New, psk)
	mac.Write(p.macInput)
	want := mac.Sum(nil)
	if subtle.ConstantTimeCompare(want, p.MAC[:]) != 1 {
		return fmt.Errorf("%w: preamble MAC mismatch", ErrAuthFailed)
	}
	return nil
}

// Freshness checks the frame timestamp against the relay clock. It is separate
// from Verify so a relay can apply it only after the MAC has passed, which
// avoids leaking timing information to an unauthenticated prober.
func (p *Preamble) Freshness(skew time.Duration) error {
	if skew <= 0 {
		skew = PreambleSkew
	}
	now := time.Now()
	delta := now.Sub(p.Time)
	if delta < 0 {
		delta = -delta
	}
	if delta > skew {
		return fmt.Errorf("%w: preamble timestamp %s is %s away from relay clock", ErrAuthFailed, p.Time.Format(time.RFC3339), delta.Truncate(time.Second))
	}
	return nil
}

// ReplayGuard remembers recently seen nonces so a captured frame cannot be
// replayed inside the freshness window.
//
// It is a fixed-size ring plus a map, giving O(1) insert and lookup with a
// bounded memory footprint. Entries older than the window are evicted lazily.
type ReplayGuard struct {
	mu       sync.Mutex
	capacity int
	window   time.Duration
	seen     map[[8]byte]time.Time
	ring     [][8]byte
	next     int
}

// NewReplayGuard builds a guard retaining up to capacity nonces for window.
func NewReplayGuard(capacity int, window time.Duration) *ReplayGuard {
	if capacity <= 0 {
		capacity = 65536
	}
	if window <= 0 {
		window = 2 * PreambleSkew
	}
	return &ReplayGuard{
		capacity: capacity,
		window:   window,
		seen:     make(map[[8]byte]time.Time, capacity),
		ring:     make([][8]byte, capacity),
	}
}

// Check records nonce as seen. It returns false when the nonce was already
// recorded inside the window, meaning the frame is a replay.
func (g *ReplayGuard) Check(nonce [8]byte) bool {
	if g == nil {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	if prev, ok := g.seen[nonce]; ok && now.Sub(prev) <= g.window {
		return false
	}
	if old := g.ring[g.next]; old != nonce {
		delete(g.seen, old)
	}
	g.ring[g.next] = nonce
	g.next = (g.next + 1) % len(g.ring)
	g.seen[nonce] = now
	return true
}

// Len reports how many nonces are currently retained.
func (g *ReplayGuard) Len() int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.seen)
}

// readAddrStream reads a SOCKS5 address directly from r and also returns the
// raw bytes so the caller can fold them into the MAC input.
func readAddrStream(r io.Reader) (string, []byte, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", nil, err
	}
	raw := []byte{atyp[0]}

	var body []byte
	switch atyp[0] {
	case AddrTypeIPv4:
		body = make([]byte, 4+2)
	case AddrTypeIPv6:
		body = make([]byte, 16+2)
	case AddrTypeDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", nil, err
		}
		if l[0] == 0 {
			return "", nil, fmt.Errorf("%w: zero-length domain", ErrBadAddress)
		}
		raw = append(raw, l[0])
		body = make([]byte, int(l[0])+2)
	default:
		return "", nil, fmt.Errorf("%w: unknown address type 0x%02x", ErrBadAddress, atyp[0])
	}
	if _, err := io.ReadFull(r, body); err != nil {
		return "", nil, err
	}
	raw = append(raw, body...)

	addr, _, err := DecodeAddrFrom(raw)
	if err != nil {
		return "", nil, err
	}
	return addr, raw, nil
}
