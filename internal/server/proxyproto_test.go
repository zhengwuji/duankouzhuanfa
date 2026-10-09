package server

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// pipeConn wraps one end of a net.Pipe so a test can act as the peer.
//
// net.Pipe is fully synchronous — a write blocks until the peer reads every
// byte — so anything the test writes must go out on a goroutine while the code
// under test reads.
func pipeConn(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

// feedAsync writes payload to conn on a goroutine, because net.Pipe blocks the
// writer until every byte is consumed.
func feedAsync(conn net.Conn, payload []byte) {
	go func() {
		_, _ = conn.Write(payload)
	}()
}

func TestProxyHeaderV1IPv4(t *testing.T) {
	client, server := pipeConn(t)
	// A pipelined payload in the same write: this is the case that a naive
	// implementation loses, because parsing the header reads ahead.
	feedAsync(client, []byte("PROXY TCP4 203.0.113.7 198.51.100.1 51234 443\r\nHELLO"))

	conn, addr, err := ReadProxyHeader(server, 2*time.Second)
	if err != nil {
		t.Fatalf("ReadProxyHeader: %v", err)
	}
	if addr == nil {
		t.Fatal("no address was returned")
	}
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("address is %T, want *net.TCPAddr", addr)
	}
	if got := tcp.IP.String(); got != "203.0.113.7" {
		t.Errorf("client IP is %s, want 203.0.113.7", got)
	}
	if tcp.Port != 51234 {
		t.Errorf("client port is %d, want 51234", tcp.Port)
	}

	// The bytes after the header must still be readable, in order.
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("reading the pipelined payload: %v", err)
	}
	if string(got) != "HELLO" {
		t.Fatalf("pipelined payload is %q, want HELLO", got)
	}
}

func TestProxyHeaderV1IPv6(t *testing.T) {
	client, server := pipeConn(t)
	feedAsync(client, []byte("PROXY TCP6 2001:db8::1 2001:db8::2 40000 443\r\n"))

	conn, addr, err := ReadProxyHeader(server, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tcp := addr.(*net.TCPAddr)
	if got := tcp.IP.String(); got != "2001:db8::1" {
		t.Errorf("client IP is %s, want 2001:db8::1", got)
	}
	if tcp.Port != 40000 {
		t.Errorf("client port is %d, want 40000", tcp.Port)
	}
	_ = conn
}

// PROXY UNKNOWN is what the spec permits for a health check, where there is no
// real client. It must parse successfully and report no address, rather than
// being treated as a malformed header.
func TestProxyHeaderV1UnknownIsAcceptedWithoutAnAddress(t *testing.T) {
	client, server := pipeConn(t)
	feedAsync(client, []byte("PROXY UNKNOWN\r\nrest"))

	conn, addr, err := ReadProxyHeader(server, 2*time.Second)
	if err != nil {
		t.Fatalf("PROXY UNKNOWN was rejected: %v", err)
	}
	if addr != nil {
		t.Errorf("address is %v, want nil", addr)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("payload after the header: %v", err)
	}
	if string(got) != "rest" {
		t.Fatalf("payload is %q, want rest", got)
	}
}

func TestProxyHeaderV2IPv4(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(proxyV2Signature)
	buf.WriteByte(0x21) // version 2, PROXY
	buf.WriteByte(0x11) // AF_INET, STREAM
	buf.Write([]byte{0x00, 0x0C})
	buf.Write([]byte{203, 0, 113, 9})
	buf.Write([]byte{198, 51, 100, 1})
	buf.Write([]byte{0xC3, 0x50}) // source port 50000
	buf.Write([]byte{0x01, 0xBB}) // destination port 443
	buf.WriteString("PAYLOAD")

	client, server := pipeConn(t)
	feedAsync(client, buf.Bytes())

	conn, addr, err := ReadProxyHeader(server, 2*time.Second)
	if err != nil {
		t.Fatalf("ReadProxyHeader: %v", err)
	}
	tcp := addr.(*net.TCPAddr)
	if got := tcp.IP.String(); got != "203.0.113.9" {
		t.Errorf("client IP is %s, want 203.0.113.9", got)
	}
	if tcp.Port != 50000 {
		t.Errorf("client port is %d, want 50000", tcp.Port)
	}
	got := make([]byte, 7)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("payload after the header: %v", err)
	}
	if string(got) != "PAYLOAD" {
		t.Fatalf("payload is %q, want PAYLOAD", got)
	}
}

// A v2 header with the LOCAL command is a health check, and carries no client.
func TestProxyHeaderV2LocalHasNoAddress(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(proxyV2Signature)
	buf.WriteByte(0x20) // version 2, LOCAL
	buf.WriteByte(0x00) // AF_UNSPEC
	buf.Write([]byte{0x00, 0x00})

	client, server := pipeConn(t)
	feedAsync(client, buf.Bytes())

	_, addr, err := ReadProxyHeader(server, 2*time.Second)
	if err != nil {
		t.Fatalf("a LOCAL header was rejected: %v", err)
	}
	if addr != nil {
		t.Errorf("address is %v, want nil", addr)
	}
}

func TestProxyHeaderRejectsGarbage(t *testing.T) {
	// A normal connection that does not speak the PROXY protocol must be
	// rejected rather than having its first bytes eaten silently.
	client, server := pipeConn(t)
	feedAsync(client, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))

	_, _, err := ReadProxyHeader(server, 2*time.Second)
	if err == nil {
		t.Fatal("a plain HTTP request was accepted as a PROXY header")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("error %q does not explain the missing signature", err)
	}
}

func TestProxyHeaderRejectsMalformedV1(t *testing.T) {
	for name, line := range map[string]string{
		"too few fields":    "PROXY TCP4 203.0.113.7\r\n",
		"bad port":          "PROXY TCP4 203.0.113.7 198.51.100.1 notaport 443\r\n",
		"port out of range": "PROXY TCP4 203.0.113.7 198.51.100.1 99999 443\r\n",
		"bad address":       "PROXY TCP4 nonsense 198.51.100.1 1234 443\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			client, server := pipeConn(t)
			feedAsync(client, []byte(line))
			if _, _, err := ReadProxyHeader(server, 2*time.Second); err == nil {
				t.Fatalf("malformed header %q was accepted", line)
			}
		})
	}
}

// An unbounded line would let a peer feed the relay arbitrary memory.
func TestProxyHeaderV1RejectsAnOverlongLine(t *testing.T) {
	client, server := pipeConn(t)
	// No newline anywhere, so the reader must give up on the length cap.
	feedAsync(client, []byte("PROXY TCP4 "+strings.Repeat("9", 500)))

	_, _, err := ReadProxyHeader(server, 2*time.Second)
	if err == nil {
		t.Fatal("an overlong header line was accepted")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error %q does not mention the length limit", err)
	}
}

func TestProxyHeaderV2RejectsAWrongVersion(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(proxyV2Signature)
	buf.WriteByte(0x31) // version 3, which does not exist
	buf.WriteByte(0x11)
	buf.Write([]byte{0x00, 0x00})

	client, server := pipeConn(t)
	feedAsync(client, buf.Bytes())

	if _, _, err := ReadProxyHeader(server, 2*time.Second); err == nil {
		t.Fatal("a v2 header claiming version 3 was accepted")
	}
}

// A v2 header whose declared payload length is shorter than the address needs
// must be refused rather than read out of bounds.
func TestProxyHeaderV2RejectsAShortPayload(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(proxyV2Signature)
	buf.WriteByte(0x21) // PROXY
	buf.WriteByte(0x11) // AF_INET
	buf.Write([]byte{0x00, 0x04})
	buf.Write([]byte{203, 0, 113, 9}) // only 4 bytes, an IPv4 address needs 12

	client, server := pipeConn(t)
	feedAsync(client, buf.Bytes())

	if _, _, err := ReadProxyHeader(server, 2*time.Second); err == nil {
		t.Fatal("a short v2 payload was accepted")
	}
}

// The wrapper must report the real client address, because that is the entire
// reason for parsing the header.
func TestAddressedConnOverridesTheRemoteAddress(t *testing.T) {
	_, server := pipeConn(t)
	real := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51234}
	wrapped := &addressedConn{Conn: server, remote: real}

	if got := wrapped.RemoteAddr(); got.String() != real.String() {
		t.Fatalf("RemoteAddr is %s, want %s", got, real)
	}
	// The underlying socket address must still be reachable for anything that
	// genuinely needs it.
	if wrapped.Conn.RemoteAddr() == nil {
		t.Fatal("the underlying connection was replaced rather than wrapped")
	}
}

// CloseWrite must be forwarded so a relayed stream ends cleanly. net.Pipe has
// no half-close, so the wrapper must report success rather than panicking or
// propagating a failure that would end the stream early.
func TestBufferedConnCloseWriteIsSafeWithoutSupport(t *testing.T) {
	_, server := pipeConn(t)
	wrapped := &bufferedConn{Conn: server, r: bufio.NewReader(server)}
	if err := wrapped.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite returned %v, want nil", err)
	}
}

func TestParseProxyAddrRejectsBadInput(t *testing.T) {
	for _, tc := range []struct{ host, port string }{
		{"203.0.113.7", "notaport"},
		{"203.0.113.7", "-1"},
		{"203.0.113.7", "65536"},
		{"not-an-ip", "443"},
		{"", "443"},
	} {
		if _, err := parseProxyAddr(tc.host, tc.port); err == nil {
			t.Errorf("parseProxyAddr(%q, %q) was accepted", tc.host, tc.port)
		}
	}
	if _, err := parseProxyAddr("203.0.113.7", "443"); err != nil {
		t.Errorf("a valid address was rejected: %v", err)
	}
}

// A big-endian port is what the spec specifies; a little-endian read would give
// a plausible-looking but wrong port, which is the kind of bug that only shows
// up in production.
func TestProxyHeaderV2PortIsBigEndian(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(proxyV2Signature)
	buf.WriteByte(0x21)
	buf.WriteByte(0x11)
	buf.Write([]byte{0x00, 0x0C})
	buf.Write([]byte{10, 0, 0, 1})
	buf.Write([]byte{10, 0, 0, 2})
	buf.Write([]byte{0x01, 0x00}) // 256, which read little-endian would be 1
	buf.Write([]byte{0x01, 0xBB})

	client, server := pipeConn(t)
	feedAsync(client, buf.Bytes())

	_, addr, err := ReadProxyHeader(server, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := addr.(*net.TCPAddr).Port; got != 256 {
		t.Fatalf("port is %d, want 256 (a little-endian read would give 1)", got)
	}
}
