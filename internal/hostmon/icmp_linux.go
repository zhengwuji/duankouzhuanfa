//go:build linux

package hostmon

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// ICMP echo on Linux.
//
// Two socket types can carry an echo request. A raw socket needs CAP_NET_RAW,
// which the service has when it runs as root but not in every container. An
// "unprivileged ping" datagram socket (SOCK_DGRAM with IPPROTO_ICMP) needs only
// the kernel's ping_group_range to include the process's group, which is the
// default on Debian, Ubuntu and their derivatives.
//
// The datagram form is tried first because it is the one that works without
// privileges. Either way, a refusal is not fatal: probeOne falls back to a TCP
// handshake and reports that as the method, so the console always says which
// measurement it is showing.

// icmpEchoRequest and icmpEchoReply are the ICMPv4 message types.
const (
	icmpEchoReply   = 0
	icmpEchoRequest = 8
)

// icmpProbe sends count echo requests to host and returns the round trips in
// milliseconds. The returned method is always "icmp" on success.
func icmpProbe(ctx context.Context, host string, count int, timeout time.Duration) ([]float64, error) {
	// Only IPv4 is handled. An IPv6-only target falls through to the TCP
	// probe, which measures reachability just as truthfully and needs no
	// second socket family here.
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return nil, errors.New("无法解析目标地址")
	}
	dst := ips[0].To4()
	if dst == nil {
		return nil, errors.New("目标不是 IPv4 地址")
	}

	fd, err := openICMPSocket()
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	// A receive timeout is what makes a lost reply a measurement rather than a
	// hang. The kernel enforces it, so no goroutine has to.
	tv := unix.NsecToTimeval(int64(timeout))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	sa := &unix.SockaddrInet4{}
	copy(sa.Addr[:], dst)

	var lat []float64
	var lastErr error
	for seq := 0; seq < count; seq++ {
		select {
		case <-ctx.Done():
			return lat, ctx.Err()
		default:
		}

		// The identifier is left at zero: on a ping socket the kernel rewrites
		// it with the socket's own port, so matching on it would never work.
		// The sequence number is ours and is enough to pair a reply.
		msg := buildEchoRequest(uint16(seq), uint16(os.Getpid()))
		start := time.Now()
		if err := unix.Sendto(fd, msg, 0, sa); err != nil {
			lastErr = err
			continue
		}

		rtt, err := awaitEcho(fd, dst, uint16(seq), start)
		if err != nil {
			lastErr = err
			continue
		}
		lat = append(lat, rtt)
		if seq < count-1 {
			// A short gap between probes keeps one burst of congestion from
			// being reported as the network's steady state.
			time.Sleep(120 * time.Millisecond)
		}
	}

	if len(lat) == 0 {
		if lastErr == nil {
			lastErr = errors.New("无应答")
		}
		return nil, lastErr
	}
	return lat, nil
}

// openICMPSocket opens the least privileged ICMP socket available.
func openICMPSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
	if err == nil {
		return fd, nil
	}
	// A raw socket is the fallback for a host whose ping_group_range excludes
	// this process; it needs root, and fails cleanly when it is not.
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		return -1, errors.New("无法创建 ICMP 套接字（需要 CAP_NET_RAW 或 ping_group_range 允许）")
	}
	return fd, nil
}

// awaitEcho reads until the reply matching seq arrives or the socket times out.
//
// Replies for other sequence numbers are discarded rather than treated as
// failures: on a datagram ICMP socket the kernel delivers whatever arrives, and
// a late answer to the previous probe is not an answer to this one.
func awaitEcho(fd int, dst []byte, seq uint16, start time.Time) (float64, error) {
	buf := make([]byte, 1500)
	deadline := start.Add(3 * time.Second)

	for time.Now().Before(deadline) {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			// EAGAIN and EWOULDBLOCK are the socket timeout: the probe is lost.
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return 0, errors.New("无应答")
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return 0, err
		}
		payload, ok := stripIPHeader(buf[:n])
		if !ok || len(payload) < 8 {
			continue
		}
		if payload[0] != icmpEchoReply {
			continue
		}
		if binary.BigEndian.Uint16(payload[6:8]) != seq {
			continue
		}
		if sa, ok := from.(*unix.SockaddrInet4); ok {
			if sa.Addr != [4]byte(dst) {
				continue
			}
		}
		return float64(time.Since(start).Microseconds()) / 1000, nil
	}
	return 0, errors.New("无应答")
}

// stripIPHeader removes the IPv4 header a raw socket prepends.
//
// A datagram ping socket delivers the ICMP message alone; a raw socket delivers
// it behind the IP header. Detecting the version nibble distinguishes the two
// without having to remember which socket was opened.
func stripIPHeader(b []byte) ([]byte, bool) {
	if len(b) < 20 {
		return nil, false
	}
	if b[0]>>4 != 4 {
		// No IP header: the buffer already starts at the ICMP message.
		return b, true
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || ihl > len(b) {
		return nil, false
	}
	return b[ihl:], true
}

// buildEchoRequest assembles an ICMP echo request with a valid checksum.
func buildEchoRequest(seq, id uint16) []byte {
	msg := make([]byte, 8+16)
	msg[0] = icmpEchoRequest
	msg[1] = 0
	binary.BigEndian.PutUint16(msg[4:6], id)
	binary.BigEndian.PutUint16(msg[6:8], seq)
	// The payload carries a timestamp so the size resembles what ping(8)
	// sends, which matters on paths that drop unusually small frames.
	binary.BigEndian.PutUint64(msg[8:16], uint64(time.Now().UnixNano()))

	// A datagram ping socket has its checksum filled in by the kernel, and a
	// raw socket does not. Computing it here is correct in both cases: the
	// kernel overwrites an already-correct value with the same value.
	binary.BigEndian.PutUint16(msg[2:4], icmpChecksum(msg))
	return msg
}

// icmpChecksum is the standard one's-complement sum over the message.
func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
