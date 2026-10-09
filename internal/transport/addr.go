package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// SOCKS5 address types, reused verbatim by the VLESS, VMess, Trojan and
// Shadowsocks wire formats because they all inherited this encoding.
const (
	AddrTypeIPv4   byte = 0x01
	AddrTypeDomain byte = 0x03
	AddrTypeIPv6   byte = 0x04
)

// maxDomainLen is the longest domain the SOCKS5 encoding can express: the
// length field is a single byte.
const maxDomainLen = 255

// ErrBadAddress reports an address that cannot be encoded or decoded.
var ErrBadAddress = errors.New("transport: malformed address")

// SplitHostPort splits host:port, tolerating bare hosts and bracketed IPv6.
// A missing port yields an empty port string rather than an error, which lets
// callers apply their own default.
func SplitHostPort(addr string) (host, port string, err error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", "", fmt.Errorf("%w: empty address", ErrBadAddress)
	}
	// Bracketed IPv6, with or without a port.
	if strings.HasPrefix(addr, "[") {
		end := strings.Index(addr, "]")
		if end < 0 {
			return "", "", fmt.Errorf("%w: unterminated IPv6 literal %q", ErrBadAddress, addr)
		}
		host = addr[1:end]
		rest := addr[end+1:]
		switch {
		case rest == "":
			return host, "", nil
		case strings.HasPrefix(rest, ":"):
			return host, rest[1:], nil
		default:
			return "", "", fmt.Errorf("%w: trailing junk after IPv6 literal %q", ErrBadAddress, addr)
		}
	}
	// A single colon is a host:port split; several colons means a bare IPv6
	// literal with no port.
	if n := strings.Count(addr, ":"); n > 1 {
		return addr, "", nil
	} else if n == 1 {
		i := strings.LastIndex(addr, ":")
		return addr[:i], addr[i+1:], nil
	}
	return addr, "", nil
}

// NormalizeAddr fills in a default port when addr omits one and validates that
// the result is host:port.
func NormalizeAddr(addr string, defaultPort int) (string, error) {
	host, port, err := SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if host == "" {
		return "", fmt.Errorf("%w: missing host in %q", ErrBadAddress, addr)
	}
	if port == "" {
		if defaultPort <= 0 {
			return "", fmt.Errorf("%w: missing port in %q", ErrBadAddress, addr)
		}
		port = strconv.Itoa(defaultPort)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("%w: bad port %q", ErrBadAddress, port)
	}
	return net.JoinHostPort(host, port), nil
}

// EncodeAddr appends the SOCKS5-format encoding of host:port to dst and
// returns the extended slice.
//
// Layout:
//
//	domain: ATYP=0x03, len(1), name, port(2, big endian)
//	IPv4:   ATYP=0x01, 4 bytes, port(2)
//	IPv6:   ATYP=0x04, 16 bytes, port(2)
//
// A bare IP literal is encoded as its binary form; anything else is encoded as
// a domain so the relay can resolve it (and so the target hostname is never
// resolved client-side, which matters for geo-routed targets).
func EncodeAddr(dst []byte, addr string) ([]byte, error) {
	host, portStr, err := SplitHostPort(addr)
	if err != nil {
		return dst, err
	}
	if host == "" {
		return dst, fmt.Errorf("%w: missing host in %q", ErrBadAddress, addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return dst, fmt.Errorf("%w: bad port %q in %q", ErrBadAddress, portStr, addr)
	}
	return AppendAddr(dst, host, uint16(port)), nil
}

// AppendAddr encodes host and port onto dst using the SOCKS5 address format.
// It panics on nothing and returns dst unchanged only when host is empty.
func AppendAddr(dst []byte, host string, port uint16) []byte {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			dst = append(dst, AddrTypeIPv4)
			dst = append(dst, v4...)
		} else {
			dst = append(dst, AddrTypeIPv6)
			dst = append(dst, ip.To16()...)
		}
	} else {
		name := host
		if len(name) > maxDomainLen {
			name = name[:maxDomainLen]
		}
		dst = append(dst, AddrTypeDomain, byte(len(name)))
		dst = append(dst, name...)
	}
	return binary.BigEndian.AppendUint16(dst, port)
}

// AddrSize reports how many bytes the SOCKS5 encoding of addr occupies, or -1
// when addr cannot be encoded. Useful for size-prefixed protocols.
func AddrSize(addr string) int {
	host, portStr, err := SplitHostPort(addr)
	if err != nil || host == "" {
		return -1
	}
	if _, err := strconv.Atoi(portStr); err != nil {
		return -1
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return 1 + 4 + 2
		}
		return 1 + 16 + 2
	}
	if len(host) > maxDomainLen {
		return -1
	}
	return 1 + 1 + len(host) + 2
}

// DecodeAddr reads one SOCKS5-format address from r and returns it as
// host:port.
func DecodeAddr(r io.Reader) (string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", err
	}
	return decodeAddrBody(r, atyp[0])
}

// DecodeAddrFrom parses one address out of b and reports how many bytes it
// consumed. It is the in-memory counterpart of DecodeAddr, used by transports
// that frame the address inside a buffer.
func DecodeAddrFrom(b []byte) (addr string, n int, err error) {
	if len(b) < 1 {
		return "", 0, io.ErrUnexpectedEOF
	}
	atyp := b[0]
	body := &sliceReader{b: b[1:]}
	a, err := decodeAddrBody(body, atyp)
	if err != nil {
		return "", 0, err
	}
	return a, 1 + body.off, nil
}

func decodeAddrBody(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case AddrTypeIPv4:
		var buf [4]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return "", err
		}
		port, err := readPort(r)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(net.IP(buf[:]).String(), port), nil

	case AddrTypeIPv6:
		var buf [16]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return "", err
		}
		port, err := readPort(r)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(net.IP(buf[:]).String(), port), nil

	case AddrTypeDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		if l[0] == 0 {
			return "", fmt.Errorf("%w: zero-length domain", ErrBadAddress)
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return "", err
		}
		port, err := readPort(r)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(string(name), port), nil

	default:
		return "", fmt.Errorf("%w: unknown address type 0x%02x", ErrBadAddress, atyp)
	}
}

func readPort(r io.Reader) (string, error) {
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", err
	}
	return strconv.Itoa(int(binary.BigEndian.Uint16(p[:]))), nil
}

// sliceReader adapts a byte slice to io.Reader and tracks the read offset so
// DecodeAddrFrom can report the consumed length.
type sliceReader struct {
	b   []byte
	off int
}

func (s *sliceReader) Read(p []byte) (int, error) {
	if s.off >= len(s.b) {
		return 0, io.EOF
	}
	n := copy(p, s.b[s.off:])
	s.off += n
	return n, nil
}

// HostOnly strips the port from addr, returning addr unchanged when it has no
// port. It tolerates bracketed IPv6.
func HostOnly(addr string) string {
	host, _, err := SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// PortOnly returns the port from addr, or "" when absent.
func PortOnly(addr string) string {
	_, port, err := SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return port
}

// IsIPLiteral reports whether host is an IP address rather than a domain name.
func IsIPLiteral(host string) bool {
	return net.ParseIP(strings.Trim(host, "[]")) != nil
}
