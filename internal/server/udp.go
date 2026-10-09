package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"porttransit/internal/transport"
)

// UDP relay over a tunnel.
//
// # Framing
//
// A tunnel is a byte stream, but UDP is a datagram protocol: message
// boundaries matter and a datagram must never be split or merged. The relay
// therefore frames each datagram with a 2-byte big-endian length prefix in
// both directions:
//
//	client → relay: length(2) | payload(length)
//	relay  → client: length(2) | payload(length)
//
// A zero length is not a valid datagram and is treated as end-of-stream.
//
// # Why a connected socket per association
//
// The relay opens one UDP socket per association and connects it to the target
// address the client named. That gives three things at once: the kernel
// filters replies from anyone but the target, the relay cannot be used as a
// UDP amplifier, and the reply address is unambiguous. A target that answers
// from a different port (common for some game and VoIP protocols) would be
// filtered, which is why the association is torn down and a log line emitted
// rather than silently dropping — the operator can then decide whether to
// allow it.

// maxDatagram is the largest UDP payload the relay will relay. 65535 is the
// theoretical UDP maximum; the practical limit is the path MTU, but a relay
// must not impose a smaller limit than the network does.
const maxDatagram = 65535

// ErrDatagramTooLarge reports a datagram exceeding the relay's limit.
var ErrDatagramTooLarge = errors.New("server: datagram exceeds the maximum size")

// relayUDP runs one UDP association until either side closes or the
// association is idle for the configured timeout.
//
// acct may be nil, which means the relay has no client accounts configured.
func relayUDP(ctx context.Context, stream transport.Stream, target string, idle time.Duration, stats *Stats, acct *accountRuntime) error {
	if idle <= 0 {
		idle = 120 * time.Second
	}

	remote, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return fmt.Errorf("server: resolve %s: %w", target, err)
	}

	// A connected UDP socket: the kernel then rejects datagrams from any
	// other source, which is both a security property and the reason the
	// reply path needs no address bookkeeping.
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return fmt.Errorf("server: dial udp %s: %w", target, err)
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	// client → target
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		errCh <- pumpClientToTarget(stream, conn, idle, acct)
	}()

	// target → client
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		errCh <- pumpTargetToClient(conn, stream, idle, acct)
	}()

	// Watch the context so a shutdown closes the socket and unblocks both
	// pumps rather than leaving them parked on a read.
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
			_ = stream.Close()
		case <-watchDone:
		}
	}()

	wg.Wait()
	close(watchDone)

	// Report the first non-benign error.
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil && !isBenignNetErr(err) {
				return err
			}
		default:
		}
	}
	return nil
}

// pumpClientToTarget reads framed datagrams from the tunnel and sends them.
func pumpClientToTarget(stream transport.Stream, conn *net.UDPConn, idle time.Duration, acct *accountRuntime) error {
	var lenBuf [2]byte
	for {
		if err := stream.SetReadDeadline(time.Now().Add(idle)); err != nil {
			return err
		}
		if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
			return err
		}
		n := int(binary.BigEndian.Uint16(lenBuf[:]))
		if n == 0 {
			// A zero-length frame is the client's end-of-stream marker.
			return nil
		}
		if n > maxDatagram {
			return fmt.Errorf("%w: %d bytes", ErrDatagramTooLarge, n)
		}

		payload := make([]byte, n)
		if _, err := io.ReadFull(stream, payload); err != nil {
			return err
		}
		if _, err := conn.Write(payload); err != nil {
			return err
		}
		acct.addBytes(int64(n))
	}
}

// pumpTargetToClient reads datagrams from the target and frames them onto the
// tunnel.
func pumpTargetToClient(conn *net.UDPConn, stream transport.Stream, idle time.Duration, acct *accountRuntime) error {
	buf := make([]byte, maxDatagram)
	var frame []byte
	for {
		if err := conn.SetReadDeadline(time.Now().Add(idle)); err != nil {
			return err
		}
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}

		frame = frame[:0]
		frame = binary.BigEndian.AppendUint16(frame, uint16(n))
		frame = append(frame, buf[:n]...)

		// The whole frame must go out in one Write: the tunnel is a byte
		// stream and a partial write would desynchronise the framing.
		if err := stream.SetWriteDeadline(time.Now().Add(idle)); err != nil {
			return err
		}
		if _, err := stream.Write(frame); err != nil {
			return err
		}
		acct.addBytes(int64(n))
	}
}

// isBenignNetErr reports whether an error is the ordinary consequence of a
// peer closing, rather than a real fault worth logging at info level.
func isBenignNetErr(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return true
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		// An idle timeout on a UDP association is normal: the client simply
		// stopped using it.
		return true
	}
	return false
}
