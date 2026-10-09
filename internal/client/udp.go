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

// maxUDPDatagram is the largest datagram a UDP tunnel carries. 65535 is the
// theoretical UDP maximum; a relay must not impose a smaller limit than the
// network does, and the length prefix has exactly this range.
const maxUDPDatagram = 65535

// udpSessionIdle is how long one UDP flow may stay silent before its relay
// stream is released.
//
// A UDP client never signals that it is finished — there is no close for a
// datagram socket — so without an idle timeout every distinct source address
// would hold a relay stream open forever. The value is deliberately shorter
// than the relay's own default UDP timeout so the client releases the stream
// first, rather than racing the relay's teardown.
const udpSessionIdle = 60 * time.Second

// udpWriteTimeout bounds a single framed write to the relay, so a relay that
// stops reading cannot block the tunnel's only reader forever.
const udpWriteTimeout = 30 * time.Second

// udpSession is one local source address's flow through the relay.
//
// One stream per source address rather than one per datagram: opening a
// transport handshake for every datagram would make DNS lookups and QUIC
// handshakes unusably slow, and would multiply the relay's connection count by
// the packet rate.
type udpSession struct {
	stream transport.Stream
	// last is the Unix nanosecond time of the most recent activity in either
	// direction, read by the reaper without taking a lock.
	last   atomic.Int64
	closed atomic.Bool
	// onDone releases the resources the session holds, exactly once.
	onDone func()
}

func (s *udpSession) touch() { s.last.Store(time.Now().UnixNano()) }

func (s *udpSession) close() {
	// CompareAndSwap makes the teardown idempotent: the reaper, the read pump
	// and a write failure can all decide to close the same session.
	if s.closed.CompareAndSwap(false, true) {
		_ = s.stream.Close()
		if s.onDone != nil {
			s.onDone()
		}
	}
}

// acceptUDPTunnel reads datagrams from the local socket and carries each
// source address's flow through the relay.
func (c *Client) acceptUDPTunnel(h *tunnelHandle) {
	var (
		mu       sync.Mutex
		sessions = map[string]*udpSession{}
	)

	drop := func(key string) {
		mu.Lock()
		delete(sessions, key)
		mu.Unlock()
	}

	// closeAll removes every session from the table and then closes them with
	// the lock released.
	//
	// The two steps must not be combined: a session's teardown callback calls
	// drop, which takes this same lock, so closing under it would deadlock the
	// goroutine that owns the table.
	closeAll := func() {
		mu.Lock()
		pending := make([]*udpSession, 0, len(sessions))
		for key, s := range sessions {
			pending = append(pending, s)
			delete(sessions, key)
		}
		mu.Unlock()

		for _, s := range pending {
			s.close()
		}
	}

	// The reaper releases idle flows. Without it a laptop that changes network
	// would leave one relay stream behind per address it used.
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
				var idle []*udpSession
				for key, s := range sessions {
					if now-s.last.Load() > int64(udpSessionIdle) {
						idle = append(idle, s)
						delete(sessions, key)
					}
				}
				mu.Unlock()

				for _, s := range idle {
					s.close()
				}
			}
		}
	}()

	// Every session is released when the tunnel stops, so a shutdown does not
	// leave relay streams open.
	defer func() {
		close(reaperDone)
		closeAll()
	}()

	buf := make([]byte, maxUDPDatagram)
	frame := make([]byte, 2+maxUDPDatagram)

	for {
		n, from, err := h.pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			c.log.Warn("udp tunnel read failed", "tunnel", h.cfg.Name, "err", err)
			return
		}
		if n == 0 {
			// An empty datagram carries no payload to relay.
			continue
		}

		key := from.String()
		mu.Lock()
		s, ok := sessions[key]
		mu.Unlock()

		if !ok {
			s, err = c.startUDPSession(h, key, drop)
			if err != nil {
				h.failed.Add(1)
				c.stats.TunnelFailures.Add(1)
				c.log.Warn("udp tunnel could not reach the relay",
					"tunnel", h.cfg.Name,
					"target", h.cfg.Target,
					"err", err,
				)
				continue
			}
			mu.Lock()
			sessions[key] = s
			mu.Unlock()
			go c.pumpUDPToClient(h, s, from, drop)
		}

		s.touch()

		binary.BigEndian.PutUint16(frame[:2], uint16(n))
		copy(frame[2:], buf[:n])

		// The whole frame goes out in a single write: the relay reads a fixed
		// two-byte length prefix, so a partial write would desynchronise the
		// framing and every later datagram would be misread.
		_ = s.stream.SetWriteDeadline(time.Now().Add(udpWriteTimeout))
		if _, err := s.stream.Write(frame[:2+n]); err != nil {
			s.close()
			drop(key)
			continue
		}
		c.stats.BytesUp.Add(int64(n))
	}
}

// startUDPSession opens one relay stream for a UDP flow.
func (c *Client) startUDPSession(h *tunnelHandle, key string, drop func(string)) (*udpSession, error) {
	req := &transport.Request{
		Command: transport.CmdUDPAssociate,
		Target:  h.cfg.Target,
	}

	stream, entry, err := c.openStream(h.cfg.Server, h.cfg.Group, h.cfg.Balance, req)
	if err != nil {
		return nil, err
	}

	s := &udpSession{stream: stream}
	s.touch()
	s.onDone = func() {
		h.conns.Add(-1)
		c.stats.ActiveConnections.Add(-1)
		drop(key)
	}

	h.conns.Add(1)
	h.accepted.Add(1)
	c.stats.ActiveConnections.Add(1)
	c.stats.TotalConnections.Add(1)

	c.log.Debug("udp flow established",
		"tunnel", h.cfg.Name,
		"target", h.cfg.Target,
		"server", entry.Name,
		"transport", stream.TransportName(),
		"source", key,
	)
	return s, nil
}

// pumpUDPToClient reads framed datagrams from the relay and writes them back
// to the local source address.
func (c *Client) pumpUDPToClient(h *tunnelHandle, s *udpSession, from net.Addr, drop func(string)) {
	// The session is released when this pump ends for any reason: the relay
	// closed, the idle deadline passed, or the socket failed. Leaving it
	// registered would send every later datagram to a dead stream.
	defer func() {
		s.close()
		drop(from.String())
	}()

	var lenBuf [2]byte
	for {
		if err := s.stream.SetReadDeadline(time.Now().Add(udpSessionIdle)); err != nil {
			return
		}
		if _, err := io.ReadFull(s.stream, lenBuf[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lenBuf[:]))
		if n == 0 {
			// A zero-length frame is the relay's end-of-association marker.
			return
		}

		payload := make([]byte, n)
		if _, err := io.ReadFull(s.stream, payload); err != nil {
			return
		}
		s.touch()

		if _, err := h.pc.WriteTo(payload, from); err != nil {
			return
		}
		c.stats.BytesDown.Add(int64(n))
	}
}
