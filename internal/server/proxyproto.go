package server

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// proxyProtocolError reports a malformed inbound PROXY protocol header.
var proxyProtocolError = errors.New("server: malformed PROXY protocol header")

const (
	proxyV1Prefix    = "PROXY "
	proxyV2Signature = "\r\n\r\n\x00\r\nQUIT\n"
)

// bufferedConn re-attaches bytes read past the PROXY protocol header.
//
// The header is parsed through a bufio.Reader, which necessarily reads ahead: a
// client that pipelines its first payload into the same segment as the header
// leaves those bytes sitting in the buffer. Handing back the raw socket would
// silently discard them, and the handshake would then fail with a confusing
// protocol error rather than a missing header. Wrapping keeps them in order.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite forwards the half-close when the underlying socket supports one,
// so a relayed stream still ends cleanly instead of waiting for the idle
// timeout.
func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// addressedConn overrides the reported remote address.
//
// It exists for the PROXY protocol path: the transports and the relay's own
// logging call RemoteAddr, and when a load balancer is in front the socket's
// address is the balancer's rather than the client's. Overriding it makes the
// log and the audit trail name the actual client.
type addressedConn struct {
	net.Conn
	remote net.Addr
}

func (c *addressedConn) RemoteAddr() net.Addr { return c.remote }

// ReadProxyHeader consumes an inbound HAProxy PROXY protocol v1 or v2 header
// and returns the connection plus the real client address.
//
// It exists because a relay behind a load balancer or CDN otherwise sees only
// the balancer's address: per-IP rate limiting, per-IP connection caps and the
// audit log would all attribute every client to one address, which both breaks
// the limits and makes the log useless.
//
// Only the address is taken from the header; everything after it is passed
// through unchanged. The listener must be configured to expect this, because
// reading it unconditionally would consume the first bytes of a normal
// connection. A nil address with a nil error means the header was well-formed
// but carried no client address (PROXY UNKNOWN / LOCAL), which the spec permits
// for health checks.
//
// The parsing is portable rather than Linux-only: it is pure byte handling with
// no socket options involved, and a relay behind a load balancer is just as
// likely to be running on another platform during development.
func ReadProxyHeader(conn net.Conn, timeout time.Duration) (net.Conn, net.Addr, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return conn, nil, err
	}
	defer conn.SetReadDeadline(time.Time{})

	br := bufio.NewReaderSize(conn, 512)
	sig, err := br.Peek(12)
	if err != nil {
		return conn, nil, err
	}
	wrapped := &bufferedConn{Conn: conn, r: br}

	switch {
	case bytes.HasPrefix(sig, []byte(proxyV2Signature)):
		addr, err := readProxyV2(br)
		return wrapped, addr, err
	case bytes.HasPrefix(sig, []byte(proxyV1Prefix)):
		addr, err := readProxyV1(br)
		return wrapped, addr, err
	default:
		return wrapped, nil, fmt.Errorf("%w: no v1 or v2 signature", proxyProtocolError)
	}
}

// readProxyV1 parses the human-readable header.
func readProxyV1(br *bufio.Reader) (net.Addr, error) {
	// The header ends with CRLF and the spec bounds its length, so a cap stops
	// a malicious peer from feeding an unbounded line.
	const maxLine = 108
	line, err := readLimitedLine(br, maxLine)
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "PROXY" {
		return nil, fmt.Errorf("%w: %q", proxyProtocolError, line)
	}
	if fields[1] == "UNKNOWN" {
		return nil, nil
	}
	if len(fields) != 6 {
		return nil, fmt.Errorf("%w: expected 6 fields, got %d", proxyProtocolError, len(fields))
	}
	return parseProxyAddr(fields[2], fields[4])
}

// readLimitedLine reads until LF, refusing to grow past max bytes.
func readLimitedLine(br *bufio.Reader, max int) (string, error) {
	var sb strings.Builder
	for sb.Len() <= max {
		b, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '\n' {
			return strings.TrimRight(sb.String(), "\r"), nil
		}
		sb.WriteByte(b)
	}
	return "", fmt.Errorf("%w: line exceeds %d bytes", proxyProtocolError, max)
}

// readProxyV2 parses the binary header.
func readProxyV2(br *bufio.Reader) (net.Addr, error) {
	header := make([]byte, 16)
	if _, err := io.ReadFull(br, header); err != nil {
		return nil, err
	}
	verCmd := header[12]
	if verCmd>>4 != 0x2 {
		return nil, fmt.Errorf("%w: version %d", proxyProtocolError, verCmd>>4)
	}
	// 0x0 is LOCAL (a health check, with no real client) and 0x1 is PROXY.
	if verCmd&0x0F != 0x1 {
		return nil, nil
	}
	fam := header[13]
	length := int(binary.BigEndian.Uint16(header[14:16]))
	payload := make([]byte, length)
	if _, err := io.ReadFull(br, payload); err != nil {
		return nil, err
	}

	switch fam >> 4 {
	case 0x1: // AF_INET
		if len(payload) < 12 {
			return nil, fmt.Errorf("%w: short IPv4 payload", proxyProtocolError)
		}
		return &net.TCPAddr{
			IP:   net.IP(payload[0:4]),
			Port: int(binary.BigEndian.Uint16(payload[8:10])),
		}, nil
	case 0x2: // AF_INET6
		if len(payload) < 36 {
			return nil, fmt.Errorf("%w: short IPv6 payload", proxyProtocolError)
		}
		return &net.TCPAddr{
			IP:   net.IP(payload[0:16]),
			Port: int(binary.BigEndian.Uint16(payload[32:34])),
		}, nil
	default:
		// AF_UNIX and AF_UNSPEC carry no usable address.
		return nil, nil
	}
}

func parseProxyAddr(host, port string) (net.Addr, error) {
	p, err := strconv.Atoi(port)
	if err != nil || p < 0 || p > 65535 {
		return nil, fmt.Errorf("%w: bad port %q", proxyProtocolError, port)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("%w: bad address %q", proxyProtocolError, host)
	}
	return &net.TCPAddr{IP: ip, Port: p}, nil
}
