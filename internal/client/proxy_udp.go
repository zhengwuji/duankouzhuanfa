package client

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"porttransit/internal/transport"
)

// SOCKS5 UDP ASSOCIATE (RFC 1928 section 7).
//
// # Why this exists
//
// A browser given only a SOCKS5 CONNECT proxy cannot resolve DNS through the
// tunnel and cannot use QUIC/HTTP3: it falls back to the system resolver and to
// TCP, which leaks exactly the destinations the relay exists to hide. The
// datagram path is therefore not an optional extra — without it the local
// proxy's privacy promise is only half kept.
//
// # Shape of an association
//
// The client opens a TCP connection, negotiates authentication and sends UDP
// ASSOCIATE. The reply names a UDP socket this process bound on loopback; the
// client sends its datagrams there, each prefixed with a SOCKS5 UDP request
// header that names the destination. The control connection carries no payload
// at all: RFC 1928 makes it the association's lifetime, so the datagram socket
// is closed and every flow released when the client closes that connection.
//
// # One flow per destination
//
// Each destination gets its own relay stream, reused across datagrams. A
// per-datagram handshake would add a full round trip to every DNS query and
// multiply the relay's connection count by the packet rate, which is precisely
// what makes a naive implementation unusable for QUIC.

const (
	// maxProxyUDPFlows bounds the destinations one association may hold open at
	// once. The flow table is keyed by destination, so without a bound a client
	// could allocate one relay stream per address it names and exhaust memory.
	maxProxyUDPFlows = 256

	// maxProxyUDPAssociations bounds the concurrent associations one client
	// serves. Each association owns a UDP socket, a reaper goroutine and a
	// control-connection watcher, so the limit is what stops a local process
	// from exhausting descriptors by opening associations in a loop.
	maxProxyUDPAssociations = 64

	// maxSocksUDPHeader is the largest SOCKS5 UDP request header: RSV(2),
	// FRAG(1), ATYP(1), a 255-byte domain name and the port.
	maxSocksUDPHeader = 3 + 1 + 1 + 255 + 2
)

// errSocksUDPFragment reports a datagram asking for reassembly.
//
// Fragmentation is optional in RFC 1928 and this client never emits it, so
// honouring it would mean buffering attacker-controlled partial datagrams per
// association until a timeout — a memory-exhaustion vector in exchange for
// interoperability nobody needs. The datagram is dropped.
var errSocksUDPFragment = errors.New("client: socks5 udp fragmentation is not supported")

// errSocksUDPShort reports a datagram too short to hold a SOCKS5 UDP header.
var errSocksUDPShort = errors.New("client: socks5 udp datagram is too short to hold a header")

// errSocksUDPReserved reports a datagram whose reserved field is not zero.
var errSocksUDPReserved = errors.New("client: socks5 udp reserved field is not zero")

// appendSocksUDPHeader appends the RFC 1928 UDP request header for addr:
//
//	RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT
//
// The address encoding is the one the SOCKS5 request uses, so the transport
// package's codec is reused rather than reimplemented.
func appendSocksUDPHeader(dst []byte, addr string) ([]byte, error) {
	// FRAG is always zero on send: this client never fragments, and a peer that
	// sees a non-zero FRAG must drop the datagram, so emitting one would only
	// produce traffic the peer discards.
	dst = append(dst, 0x00, 0x00, 0x00)
	return transport.EncodeAddr(dst, addr)
}

// parseSocksUDPDatagram splits one client datagram into its destination and
// payload. The payload is a sub-slice of pkt and is not copied.
func parseSocksUDPDatagram(pkt []byte) (addr string, payload []byte, err error) {
	if len(pkt) < 4 {
		return "", nil, errSocksUDPShort
	}
	if pkt[0] != 0 || pkt[1] != 0 {
		// RSV must be zero. A non-zero value means the sender is not speaking
		// RFC 1928, and guessing at its intent would hide a client bug rather
		// than surface it.
		return "", nil, errSocksUDPReserved
	}
	if pkt[2] != 0 {
		return "", nil, errSocksUDPFragment
	}
	addr, n, err := transport.DecodeAddrFrom(pkt[3:])
	if err != nil {
		return "", nil, err
	}
	return addr, pkt[3+n:], nil
}

// proxyUDPFlow is one destination's flow inside one association.
//
// It mirrors udpSession from udp.go — one flow per destination, the same
// idempotent close and the same lock-free idle stamp — and additionally covers
// the direct route, where the flow is a plain UDP socket rather than a relay
// stream.
type proxyUDPFlow struct {
	// conn is the relay stream when framed is true and a directly dialed UDP
	// socket otherwise. Both satisfy net.Conn, so the plumbing is shared.
	conn   net.Conn
	framed bool

	// frame is reused across sends so a datagram does not allocate. Only the
	// association's single read loop calls send, so it needs no lock.
	frame []byte

	// last is the Unix nanosecond time of the most recent activity in either
	// direction, read by the reaper without taking a lock.
	last   atomic.Int64
	closed atomic.Bool
	// onDone releases the flow's slot in the association, exactly once.
	onDone func()
}

func (f *proxyUDPFlow) touch() { f.last.Store(time.Now().UnixNano()) }

// close releases the flow's socket or stream.
//
// CompareAndSwap makes the teardown idempotent: the reaper, the reply pump and
// a failed write can all decide to close the same flow.
func (f *proxyUDPFlow) close() {
	if f.closed.CompareAndSwap(false, true) {
		_ = f.conn.Close()
		if f.onDone != nil {
			f.onDone()
		}
	}
}

// send carries one payload to the flow's destination.
func (f *proxyUDPFlow) send(payload []byte) error {
	if !f.framed {
		_, err := f.conn.Write(payload)
		return err
	}
	// The relay reads a fixed two-byte big-endian length prefix, so the frame
	// must reach it in a single write: a partial write would desynchronise the
	// framing and every later datagram would be misread.
	need := 2 + len(payload)
	if cap(f.frame) < need {
		f.frame = make([]byte, need)
	}
	frame := f.frame[:need]
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	copy(frame[2:], payload)
	_, err := f.conn.Write(frame)
	return err
}

// serveUDPAssociate runs one SOCKS5 UDP association until the control
// connection closes or the client shuts down.
func (c *Client) serveUDPAssociate(ctrl net.Conn) {
	// A bound on the number of associations is taken before the socket is
	// bound, so a client that opens associations in a loop is refused rather
	// than allowed to consume descriptors.
	if c.udpAssocs.Add(1) > maxProxyUDPAssociations {
		c.udpAssocs.Add(-1)
		c.log.Warn("socks5 udp association limit reached", "limit", maxProxyUDPAssociations)
		writeSocksReply(ctrl, 0x01)
		return
	}
	defer c.udpAssocs.Add(-1)

	// The control connection carries no payload, so its read deadline must be
	// cleared: the association lives as long as the client keeps the TCP
	// connection open, which is far longer than the handshake budget set when
	// the connection was accepted.
	if err := ctrl.SetDeadline(time.Time{}); err != nil {
		return
	}

	// The datagram socket is bound on loopback with a kernel-chosen port.
	//
	// It must not reuse the TCP port: the client sends its datagrams to the
	// address in the reply, and sharing the port would mix datagrams into the
	// control connection's byte stream.
	//
	// The address is always a loopback one, never the control connection's own
	// local address: a proxy bound on 0.0.0.0 would otherwise hand back a LAN
	// address and expose an unauthenticated datagram relay to the network. Only
	// the family follows the control connection, because a client that reached
	// the proxy over ::1 cannot send to a v4 loopback socket.
	pc, err := net.ListenPacket("udp", net.JoinHostPort(loopbackFor(ctrl), "0"))
	if err != nil {
		writeSocksReply(ctrl, 0x01)
		c.log.Warn("socks5 udp associate could not bind a relay socket", "err", err)
		return
	}
	defer pc.Close()

	// The bound address is the only thing that tells the client where to send
	// its datagrams, so the reply is written before anything else can fail.
	if err := writeSocksReplyAddr(ctrl, 0x00, pc.LocalAddr().String()); err != nil {
		return
	}

	var (
		mu    sync.Mutex
		flows = map[string]*proxyUDPFlow{}
	)

	drop := func(dest string) {
		mu.Lock()
		delete(flows, dest)
		mu.Unlock()
	}

	// closeAll removes every flow from the table and then closes them with the
	// lock released.
	//
	// The two steps must not be combined: a flow's teardown callback calls
	// drop, which takes this same lock, so closing under it would deadlock the
	// goroutine that owns the table. This is the same hazard udp.go documents
	// and fixed; do not fold the loop back under the lock.
	closeAll := func() {
		mu.Lock()
		pending := make([]*proxyUDPFlow, 0, len(flows))
		for dest, f := range flows {
			pending = append(pending, f)
			delete(flows, dest)
		}
		mu.Unlock()

		for _, f := range pending {
			f.close()
		}
	}

	// The reaper releases flows the client stopped using. A browser that
	// switches resolver or moves from QUIC to TCP leaves a stream behind for
	// every destination it named, and nothing else would ever release them.
	reaperDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(udpSessionIdle / 4)
		defer ticker.Stop()
		for {
			select {
			case <-reaperDone:
				return
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				now := time.Now().UnixNano()

				mu.Lock()
				var idle []*proxyUDPFlow
				for dest, f := range flows {
					if now-f.last.Load() > int64(udpSessionIdle) {
						idle = append(idle, f)
						delete(flows, dest)
					}
				}
				mu.Unlock()

				for _, f := range idle {
					f.close()
				}
			}
		}
	}()

	defer func() {
		close(reaperDone)
		closeAll()
	}()

	// ctrlClosed reports that the client closed the control connection, which
	// RFC 1928 defines as the end of the association.
	ctrlClosed := make(chan struct{})
	go func() {
		defer close(ctrlClosed)
		// The client sends nothing on the control connection, so this read
		// blocks until the peer closes it and then reports EOF. Draining rather
		// than erroring means a client that does write something cannot stall
		// the association.
		_, _ = io.Copy(io.Discard, ctrl)
	}()

	// Closing the datagram socket is what unblocks the read loop below, so both
	// the association's end and a client shutdown funnel through here. Without
	// the context case a shutdown would wait out the whole Stop timeout for a
	// browser that keeps its socket open.
	go func() {
		select {
		case <-ctrlClosed:
		case <-c.ctx.Done():
		}
		_ = pc.Close()
	}()

	// The read buffer has to hold a maximum-size payload plus the largest
	// possible header, or a full datagram to a domain destination would be
	// silently truncated by the kernel.
	buf := make([]byte, maxUDPDatagram+maxSocksUDPHeader)
	peer := peerIP(ctrl)

	var (
		clientAddr   net.Addr
		warnedSource bool
	)

	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-c.ctx.Done():
				return
			default:
			}
			c.log.Debug("socks5 udp read failed", "err", err)
			return
		}
		if n == 0 {
			continue
		}

		// The association is pinned to the first source address that uses it,
		// and that address must belong to the control connection's peer.
		//
		// A SOCKS5 datagram carries no credential, so the control connection is
		// the only thing tying datagrams to an authenticated client; without
		// this check any local process could inject traffic into another
		// process's association and read the replies. Only the host is compared
		// because a client almost never uses its control connection's port.
		if clientAddr == nil {
			if !sameIP(from, peer) {
				// Logged once: a warning per datagram would be a log-flood
				// vector for anyone able to send a burst.
				if !warnedSource {
					warnedSource = true
					c.log.Warn("socks5 udp datagram from outside the control connection's peer",
						"from", from.String(),
						"peer", ctrl.RemoteAddr().String(),
					)
				}
				continue
			}
			clientAddr = from
			c.log.Debug("socks5 udp association established",
				"client", from.String(),
				"relay", pc.LocalAddr().String(),
			)
		} else if from.String() != clientAddr.String() {
			continue
		}

		dest, payload, err := parseSocksUDPDatagram(buf[:n])
		if err != nil {
			// A fragmented or malformed datagram cannot be answered at all:
			// the SOCKS5 UDP header carries no request id, so there is nothing
			// to correlate a reply with. Dropping is the whole response.
			c.log.Debug("socks5 udp datagram dropped", "from", from.String(), "err", err)
			continue
		}
		if len(payload) == 0 {
			// An empty payload is not relayed: the relay's framing uses a
			// zero-length frame as end-of-stream, so forwarding one would tear
			// the destination's association down.
			continue
		}
		if len(payload) > maxUDPDatagram {
			// Unreachable through a real UDP socket, but the relay's length
			// prefix cannot represent more than this and the guard is what
			// keeps that assumption honest.
			c.log.Debug("socks5 udp datagram exceeds the maximum size", "size", len(payload))
			continue
		}
		if transport.PortOnly(dest) == "0" {
			// Port zero addresses nothing; relaying it would ask the relay to
			// dial a target that cannot exist.
			c.log.Debug("socks5 udp datagram names no destination port", "target", dest)
			continue
		}

		// The routing rules are the same ones the TCP path applies, so a
		// blocked destination cannot be reached over UDP either and a
		// direct-listed one does not appear on the relay's connection log.
		// Dropping a blocked datagram rather than answering it matches the
		// datagram model: there is no reply to refuse with.
		route := c.decide(dest)
		if route == decisionBlock {
			c.log.Debug("local proxy blocked a udp destination", "target", dest)
			continue
		}

		mu.Lock()
		flow, ok := flows[dest]
		if !ok && len(flows) >= maxProxyUDPFlows {
			mu.Unlock()
			c.log.Debug("socks5 udp flow limit reached, dropping a datagram",
				"target", dest,
				"limit", maxProxyUDPFlows,
			)
			continue
		}
		mu.Unlock()

		if !ok {
			flow, err = c.startProxyUDPFlow(dest, route)
			if err != nil {
				c.log.Debug("socks5 udp flow could not be opened", "target", dest, "err", err)
				continue
			}
			flow.onDone = func() {
				c.stats.ActiveConnections.Add(-1)
				drop(dest)
			}
			// Only this goroutine inserts, so the table cannot gain a duplicate
			// key for the same destination between the lookup and the store.
			mu.Lock()
			flows[dest] = flow
			mu.Unlock()
			go c.pumpProxyUDPToClient(pc, flow, dest, clientAddr, drop)
		}

		flow.touch()

		// A relay that stops reading must not park this loop forever: it is the
		// only reader for every flow in the association.
		_ = flow.conn.SetWriteDeadline(time.Now().Add(udpWriteTimeout))
		if err := flow.send(payload); err != nil {
			flow.close()
			drop(dest)
			continue
		}
		c.stats.BytesUp.Add(int64(len(payload)))
	}
}

// startProxyUDPFlow opens one flow to dest, through the relay or directly.
func (c *Client) startProxyUDPFlow(dest string, route decision) (*proxyUDPFlow, error) {
	if route == decisionDirect {
		// A connected socket, so the kernel filters replies from anyone but the
		// destination and the reply address needs no bookkeeping.
		conn, err := net.DialTimeout("udp", dest, 10*time.Second)
		if err != nil {
			return nil, err
		}
		f := &proxyUDPFlow{conn: conn}
		f.touch()
		c.stats.ActiveConnections.Add(1)
		c.stats.TotalConnections.Add(1)
		c.log.Debug("socks5 udp flow dialed directly", "target", dest)
		return f, nil
	}

	req := &transport.Request{
		Command: transport.CmdUDPAssociate,
		Target:  dest,
	}
	stream, entry, err := c.openStream(c.cfg.Proxy.Server, c.cfg.Proxy.Group, c.cfg.Proxy.Balance, req)
	if err != nil {
		return nil, err
	}

	f := &proxyUDPFlow{conn: stream, framed: true}
	f.touch()
	c.stats.ActiveConnections.Add(1)
	c.stats.TotalConnections.Add(1)
	c.log.Debug("socks5 udp flow established",
		"target", dest,
		"server", entry.Name,
		"transport", stream.TransportName(),
	)
	return f, nil
}

// pumpProxyUDPToClient reads payloads from one flow and writes them back to the
// client wrapped in a SOCKS5 UDP header naming the destination.
func (c *Client) pumpProxyUDPToClient(pc net.PacketConn, f *proxyUDPFlow, dest string, client net.Addr, drop func(string)) {
	// The flow is released when this pump ends for any reason: the relay
	// closed, the idle deadline passed, or the socket failed. Leaving it
	// registered would send every later datagram to a dead stream.
	defer func() {
		f.close()
		drop(dest)
	}()

	buf := make([]byte, maxUDPDatagram)
	out := make([]byte, 0, maxUDPDatagram+maxSocksUDPHeader)

	var lenBuf [2]byte
	for {
		if err := f.conn.SetReadDeadline(time.Now().Add(udpSessionIdle)); err != nil {
			return
		}

		var payload []byte
		if f.framed {
			if _, err := io.ReadFull(f.conn, lenBuf[:]); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(lenBuf[:]))
			if n == 0 {
				// A zero-length frame is the relay's end-of-association
				// marker.
				return
			}
			payload = buf[:n]
			if _, err := io.ReadFull(f.conn, payload); err != nil {
				return
			}
		} else {
			n, err := f.conn.Read(buf)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			payload = buf[:n]
		}
		f.touch()

		// The reply names the destination the client asked for, not whatever
		// address the answer came from: a client that resolved a name expects
		// to match the answer against the query it sent.
		head, err := appendSocksUDPHeader(out[:0], dest)
		if err != nil {
			return
		}
		frame := append(head, payload...)
		if _, err := pc.WriteTo(frame, client); err != nil {
			return
		}
		c.stats.BytesDown.Add(int64(len(payload)))
	}
}

// writeSocksReplyAddr sends a SOCKS5 reply whose BND.ADDR/BND.PORT is addr.
//
// The zeroed variant in proxy.go cannot carry a datagram relay's port, and the
// reply is the client's only way to learn where to send its datagrams.
func writeSocksReplyAddr(w io.Writer, code byte, addr string) error {
	buf := make([]byte, 0, 3+maxSocksUDPHeader)
	buf = append(buf, 0x05, code, 0x00)
	buf, err := transport.EncodeAddr(buf, addr)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}

// peerIP returns the host of a connection's peer, or nil when it is not a TCP
// connection.
func peerIP(conn net.Conn) net.IP {
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return ta.IP
	}
	return nil
}

// loopbackFor returns the loopback literal matching the control connection's
// address family, defaulting to IPv4 when it cannot be determined.
func loopbackFor(conn net.Conn) string {
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok && ta.IP.To4() == nil {
		return "::1"
	}
	return "127.0.0.1"
}

// sameIP reports whether a datagram source belongs to host.
//
// An unknown host (nil) matches nothing, so a connection whose peer cannot be
// determined fails closed rather than accepting datagrams from anywhere.
func sameIP(a net.Addr, host net.IP) bool {
	if host == nil || a == nil {
		return false
	}
	ua, ok := a.(*net.UDPAddr)
	if !ok {
		return false
	}
	return ua.IP.Equal(host)
}
