package client

import (
	"bytes"
	"errors"
	"net"
	"testing"
)

// TestAppendSocksUDPHeaderEncodesRFC1928Form pins the wire form of the UDP
// request header, since every datagram depends on the relay and the client
// agreeing on it byte for byte.
func TestAppendSocksUDPHeaderEncodesRFC1928Form(t *testing.T) {
	cases := []struct {
		name string
		addr string
		want []byte
	}{
		{
			name: "ipv4",
			addr: "1.2.3.4:53",
			want: []byte{0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x35},
		},
		{
			name: "ipv6",
			addr: "[2001:db8::1]:5353",
			want: append(
				[]byte{0x00, 0x00, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01},
				0x14, 0xe9,
			),
		},
		{
			name: "domain",
			addr: "dns.example.com:53",
			want: append(
				[]byte{0x00, 0x00, 0x00, 0x03, 15},
				append([]byte("dns.example.com"), 0x00, 0x35)...,
			),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := appendSocksUDPHeader(nil, tc.addr)
			if err != nil {
				t.Fatalf("appendSocksUDPHeader(%q): %v", tc.addr, err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("header for %q = % x, want % x", tc.addr, got, tc.want)
			}
			// FRAG is the third byte and must always be zero on send: a peer
			// that sees a non-zero FRAG is required to drop the datagram, so
			// emitting one would produce traffic that is discarded.
			if got[2] != 0x00 {
				t.Errorf("FRAG = 0x%02x, want 0x00", got[2])
			}
		})
	}
}

// TestAppendSocksUDPHeaderRejectsBadAddress proves an unencodable destination
// is reported rather than silently producing a truncated header, which the
// client would then misparse.
func TestAppendSocksUDPHeaderRejectsBadAddress(t *testing.T) {
	for _, addr := range []string{"", "1.2.3.4", "1.2.3.4:0", "1.2.3.4:99999", "host:port"} {
		if _, err := appendSocksUDPHeader(nil, addr); err == nil {
			t.Errorf("appendSocksUDPHeader(%q) accepted an invalid address", addr)
		}
	}
}

// TestSocksUDPDatagramRoundTrip proves the encoder and decoder agree, which is
// what lets the reply header be built by the same code path as the request.
func TestSocksUDPDatagramRoundTrip(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}

	for _, addr := range []string{"1.2.3.4:53", "[2001:db8::1]:5353", "dns.example.com:53"} {
		t.Run(addr, func(t *testing.T) {
			pkt, err := appendSocksUDPHeader(nil, addr)
			if err != nil {
				t.Fatalf("encode %q: %v", addr, err)
			}
			pkt = append(pkt, payload...)

			gotAddr, gotPayload, err := parseSocksUDPDatagram(pkt)
			if err != nil {
				t.Fatalf("parse %q: %v", addr, err)
			}
			if gotAddr != addr {
				t.Errorf("destination = %q, want %q", gotAddr, addr)
			}
			if !bytes.Equal(gotPayload, payload) {
				t.Errorf("payload = % x, want % x", gotPayload, payload)
			}
		})
	}
}

// TestParseSocksUDPDatagramDropsFragments proves a datagram with FRAG != 0 is
// rejected.
//
// Reassembly is the reason: honouring it would mean buffering attacker-supplied
// partial datagrams per association until a timeout, which is a
// memory-exhaustion vector, and RFC 1928 makes fragmentation optional for
// exactly that reason.
func TestParseSocksUDPDatagramDropsFragments(t *testing.T) {
	for _, frag := range []byte{0x01, 0x02, 0x80, 0xff} {
		pkt := []byte{0x00, 0x00, frag, 0x01, 1, 2, 3, 4, 0x00, 0x35, 'h', 'i'}
		_, _, err := parseSocksUDPDatagram(pkt)
		if !errors.Is(err, errSocksUDPFragment) {
			t.Errorf("FRAG=0x%02x returned %v, want errSocksUDPFragment", frag, err)
		}
	}
}

// TestParseSocksUDPDatagramRejectsMalformed covers the shapes a hostile or
// buggy client can send. None may panic or be relayed.
func TestParseSocksUDPDatagramRejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
		want error
	}{
		{"empty", nil, errSocksUDPShort},
		{"header only", []byte{0x00, 0x00, 0x00}, errSocksUDPShort},
		{"reserved set", []byte{0x01, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0, 53}, errSocksUDPReserved},
		{"reserved second byte", []byte{0x00, 0xff, 0x00, 0x01, 1, 2, 3, 4, 0, 53}, errSocksUDPReserved},
		// An unknown address type must not be guessed at: the payload offset
		// would be wrong and the destination meaningless.
		{"unknown atyp", []byte{0x00, 0x00, 0x00, 0x09, 1, 2, 3, 4, 0, 53}, transportBadAddr{}},
		// A truncated IPv4 address must not be read past the end of the
		// datagram.
		{"truncated ipv4", []byte{0x00, 0x00, 0x00, 0x01, 1, 2, 3}, transportBadAddr{}},
		// A zero-length domain is not a destination.
		{"zero length domain", []byte{0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x35}, transportBadAddr{}},
		// A domain longer than the datagram must not be over-read.
		{"truncated domain", []byte{0x00, 0x00, 0x00, 0x03, 0x0a, 'a', 'b'}, transportBadAddr{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseSocksUDPDatagram(tc.pkt)
			if err == nil {
				t.Fatalf("parseSocksUDPDatagram(% x) accepted a malformed datagram", tc.pkt)
			}
			if _, ok := tc.want.(transportBadAddr); ok {
				// Any address error is acceptable; the point is that it is
				// reported rather than silently tolerated.
				if errors.Is(err, errSocksUDPFragment) {
					t.Fatalf("parseSocksUDPDatagram reported a fragment error for % x", tc.pkt)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// transportBadAddr is a sentinel standing in for "any address decoding error",
// so the table above does not have to import the transport package's error
// values and can stay readable.
type transportBadAddr struct{}

func (transportBadAddr) Error() string { return "address decoding error" }

// TestParseSocksUDPDatagramKeepsPayload proves the payload is returned intact,
// including bytes that look like another header: the payload must never be
// re-parsed.
func TestParseSocksUDPDatagramKeepsPayload(t *testing.T) {
	nested := []byte{0x00, 0x00, 0x00, 0x01, 9, 9, 9, 9, 0x00, 0x35}
	pkt := []byte{0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x35}
	pkt = append(pkt, nested...)

	addr, payload, err := parseSocksUDPDatagram(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if addr != "1.2.3.4:53" {
		t.Errorf("destination = %q, want 1.2.3.4:53", addr)
	}
	if !bytes.Equal(payload, nested) {
		t.Errorf("payload = % x, want % x", payload, nested)
	}
}

// TestParseSocksUDPDatagramEmptyPayloadIsAllowed proves a header with no
// payload parses; the caller is the layer that decides to drop it, because the
// relay's framing reserves a zero-length frame for end-of-stream.
func TestParseSocksUDPDatagramEmptyPayloadIsAllowed(t *testing.T) {
	pkt := []byte{0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x35}
	addr, payload, err := parseSocksUDPDatagram(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if addr != "1.2.3.4:53" {
		t.Errorf("destination = %q, want 1.2.3.4:53", addr)
	}
	if len(payload) != 0 {
		t.Errorf("payload = % x, want empty", payload)
	}
}

// TestWriteSocksReplyAddrCarriesTheBoundPort proves the association reply names
// a usable address, since it is the client's only way to learn where to send
// its datagrams.
func TestWriteSocksReplyAddrCarriesTheBoundPort(t *testing.T) {
	var buf bytes.Buffer
	if err := writeSocksReplyAddr(&buf, 0x00, "127.0.0.1:41234"); err != nil {
		t.Fatalf("writeSocksReplyAddr: %v", err)
	}
	want := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0xa1, 0x12}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("reply = % x, want % x", buf.Bytes(), want)
	}
}

// TestWriteSocksReplyAddrRejectsBadAddress proves a reply that cannot name a
// valid address is reported, so a caller cannot send a header that would
// desynchronise the client's parsing.
func TestWriteSocksReplyAddrRejectsBadAddress(t *testing.T) {
	var buf bytes.Buffer
	if err := writeSocksReplyAddr(&buf, 0x00, "not-an-address"); err == nil {
		t.Fatal("writeSocksReplyAddr accepted an invalid address")
	}
}

// TestSameIPBindsToTheControlPeer proves the association's source check
// compares hosts only, and fails closed when the peer is unknown.
//
// A SOCKS5 datagram carries no credential, so the control connection is the
// only thing tying datagrams to an authenticated client. Only the host is
// compared because a client almost never sends from its control connection's
// port; failing closed on an unknown peer is what stops the check from
// degrading into "accept anything".
func TestSameIPBindsToTheControlPeer(t *testing.T) {
	v4 := net.ParseIP("127.0.0.1")
	v6 := net.ParseIP("::1")

	cases := []struct {
		name string
		from net.Addr
		host net.IP
		want bool
	}{
		{"same host, any port", &net.UDPAddr{IP: v4, Port: 5555}, v4, true},
		{"control peer port is irrelevant", &net.UDPAddr{IP: v4, Port: 1080}, v4, true},
		{"different host", &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 5555}, v4, false},
		{"different family", &net.UDPAddr{IP: v6, Port: 5555}, v4, false},
		{"unknown peer fails closed", &net.UDPAddr{IP: v4, Port: 5555}, nil, false},
		{"nil source fails closed", nil, v4, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameIP(tc.from, tc.host); got != tc.want {
				t.Fatalf("sameIP(%v, %v) = %v, want %v", tc.from, tc.host, got, tc.want)
			}
		})
	}
}

// TestPeerIPIgnoresNonTCPPeers proves an unusable control connection is
// reported as an unknown peer, which sameIP then rejects.
func TestPeerIPIgnoresNonTCPPeers(t *testing.T) {
	if ip := peerIP(&udpOnlyConn{}); ip != nil {
		t.Fatalf("peerIP returned %v for a non-TCP connection", ip)
	}
}

// udpOnlyConn is a net.Conn whose remote address is not a TCP address.
type udpOnlyConn struct{ net.Conn }

func (c *udpOnlyConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}
}
