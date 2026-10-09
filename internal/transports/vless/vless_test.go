package vless

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"porttransit/internal/cryptox"
	"porttransit/internal/logx"
	"porttransit/internal/transport"
)

// The VLESS request and response headers are short, fixed-layout byte strings
// with no framing to resynchronise on, so every assertion here is on exact
// bytes. A one-byte slip does not fail loudly — it silently shifts the whole
// payload, which is precisely the bug this file exists to prevent.

// pair returns a connected client/server socket pair for driving the protocol
// halves against each other without touching the network.
//
// net.Pipe is fully synchronous — a Write blocks until the peer reads every
// byte — so the relay half always runs in a goroutine and the test body plays
// the client. Writing a request inline while the relay half wrote a reply would
// deadlock for the whole test timeout.
func pair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	c, s := net.Pipe()
	t.Cleanup(func() {
		c.Close()
		s.Close()
	})
	return c, s
}

// writeAsync sends a frame from a goroutine.
//
// A synchronous pipe blocks a Write until the peer consumes it, and the
// rejection paths here close the connection after reading only part of a
// request. Writing inline would then deadlock: the test body would still be
// waiting to finish a write the relay half has already stopped reading.
func writeAsync(conn net.Conn, buf []byte) {
	go func() { _, _ = conn.Write(buf) }()
}

// readN reads exactly n bytes, failing the test on a short read.
//
// The deadline matters: without it a missing reply hangs the test binary until
// the package timeout rather than failing the one test that is broken.
func readN(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return buf
}

// fixedUUID is the credential used by every handshake test. Its 16 wire bytes
// are asserted literally, so the value is spelled out rather than generated.
const fixedUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// noTLS disables the TLS wrapper so a handshake can run over an in-memory pipe,
// where there is no certificate to verify and no TCP connection to make.
func noTLS(extra transport.Settings) transport.Settings {
	s := transport.Settings{SettingTLS: false}
	for k, v := range extra {
		s[k] = v
	}
	return s
}

// requestHeader assembles a VLESS request header by hand.
//
// It is built here rather than by calling encodeRequest so the assertions below
// are about the wire format and not about the encoder agreeing with itself.
func requestHeader(uuid []byte, addons []byte, command byte, port uint16, atyp byte, addr []byte) []byte {
	buf := []byte{0x00}
	buf = append(buf, uuid...)
	buf = append(buf, byte(len(addons)))
	buf = append(buf, addons...)
	buf = append(buf, command)
	buf = binary.BigEndian.AppendUint16(buf, port)
	buf = append(buf, atyp)
	return append(buf, addr...)
}

// handleResult carries the relay half's outcome back to the test body.
type handleResult struct {
	stream transport.Stream
	err    error
}

// runHandle drives Handler.Handle in a goroutine.
func runHandle(conn net.Conn, req transport.HandleRequest) <-chan handleResult {
	out := make(chan handleResult, 1)
	go func() {
		st, err := Handler{}.Handle(context.Background(), conn, req)
		out <- handleResult{st, err}
	}()
	return out
}

// drainAsync consumes everything the relay writes until the connection ends.
//
// This is needed on the rejection paths: the relay closes the connection while
// the test body is only waiting for Handle to return, and on a synchronous pipe
// a close that has bytes behind it blocks until the peer reads them.
func drainAsync(conn net.Conn) {
	go func() {
		buf := make([]byte, 256)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}()
}

// TestAddressTypeConstantsDifferFromSOCKS5 pins VLESS's own address type
// numbering.
//
// VLESS numbers the types 1/2/3 in the order IPv4, domain, IPv6; SOCKS5 numbers
// them 1/3/4. Reusing the shared SOCKS5 constants — which is exactly what the
// sibling transports do — would therefore be silently wrong for every domain
// target: the relay would read address type 2 as "IPv4" and consume four bytes
// of the hostname as an address. Nothing would error; the target would just be
// wrong, and every request would stall or connect somewhere unintended.
func TestAddressTypeConstantsDifferFromSOCKS5(t *testing.T) {
	if addrTypeIPv4 != 0x01 {
		t.Errorf("addrTypeIPv4 = 0x%02x, want 0x01", addrTypeIPv4)
	}
	if addrTypeDomain != 0x02 {
		t.Errorf("addrTypeDomain = 0x%02x, want 0x02", addrTypeDomain)
	}
	if addrTypeIPv6 != 0x03 {
		t.Errorf("addrTypeIPv6 = 0x%02x, want 0x03", addrTypeIPv6)
	}

	// The shared SOCKS5 constants must NOT be what VLESS uses for domain and
	// IPv6; this is the regression the values above exist to catch.
	if addrTypeDomain == transport.AddrTypeDomain {
		t.Errorf("VLESS reuses the SOCKS5 domain type 0x%02x", transport.AddrTypeDomain)
	}
	if addrTypeIPv6 == transport.AddrTypeIPv6 {
		t.Errorf("VLESS reuses the SOCKS5 IPv6 type 0x%02x", transport.AddrTypeIPv6)
	}
	// IPv4 happens to agree in both numbering schemes, which is why a mixed-up
	// implementation survives every IPv4 test.
	if addrTypeIPv4 != transport.AddrTypeIPv4 {
		t.Errorf("the IPv4 type is 0x%02x, but SOCKS5 uses 0x%02x", addrTypeIPv4, transport.AddrTypeIPv4)
	}
}

// TestCommandByteValues pins the three command bytes.
func TestCommandByteValues(t *testing.T) {
	if cmdTCP != 0x01 {
		t.Errorf("cmdTCP = 0x%02x, want 0x01", cmdTCP)
	}
	if cmdUDP != 0x02 {
		t.Errorf("cmdUDP = 0x%02x, want 0x02", cmdUDP)
	}
	if cmdMux != 0x03 {
		t.Errorf("cmdMux = 0x%02x, want 0x03", cmdMux)
	}
	// The relay maps the wire command onto transport.Command, whose values are
	// a different enumeration: CmdUDPAssociate is 0x02 there too, but CmdPing is
	// 0x03 — the same number as VLESS's MUX. Confusing the two would turn a MUX
	// refusal into a ping.
	if transport.CmdPing == transport.Command(cmdMux) {
		t.Log("note: VLESS MUX and transport CmdPing share the value 0x03 by coincidence")
	}
	if cmdUDP == cmdMux {
		t.Fatal("the UDP and MUX command bytes are identical")
	}
}

// TestFlowVisionConstant pins the flow identifier, which is what the addon
// carries and what both sides compare against.
func TestFlowVisionConstant(t *testing.T) {
	if FlowVision != "xtls-rprx-vision" {
		t.Errorf("FlowVision = %q, want \"xtls-rprx-vision\"", FlowVision)
	}
	if maxPadding != 255 {
		t.Errorf("maxPadding = %d, want 255", maxPadding)
	}
}

// TestEncodeRequestDomainLayout asserts the exact request header for a domain
// target, field by field and then as one byte string.
func TestEncodeRequestDomainLayout(t *testing.T) {
	uuid := cryptox.MustParseUUID(fixedUUID)
	got, err := encodeRequest(uuid, cmdTCP, "example.com:443", "")
	if err != nil {
		t.Fatalf("encodeRequest: %v", err)
	}

	// The UUID's wire form is fixed by the constant above, so it is asserted
	// literally: a parser that dropped the dashes in the wrong order, or that
	// silently zeroed an unparsable value, would pass a round-trip test but
	// fail this one.
	wantUUID := []byte{
		0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53,
		0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11,
	}
	want := []byte{0x00}
	want = append(want, wantUUID...)
	want = append(want, 0x00) // addon length: no flow
	want = append(want, cmdTCP)
	want = append(want, 0x01, 0xBB) // port 443, big endian
	want = append(want, addrTypeDomain, byte(len("example.com")))
	want = append(want, "example.com"...)

	if !bytes.Equal(got, want) {
		t.Fatalf("the header is\n  % x\nwant\n  % x", got, want)
	}

	// Field offsets spelled out so a failure above is readable without decoding
	// hex. The header layout is version(1) uuid(16) addonLen(1) addons command(1)
	// port(2) atyp(1) address.
	if got[0] != 0x00 {
		t.Errorf("the version byte is 0x%02x, want 0x00", got[0])
	}
	if !bytes.Equal(got[1:17], wantUUID) {
		t.Errorf("the uuid bytes are % x, want % x", got[1:17], wantUUID)
	}
	if got[17] != 0x00 {
		t.Errorf("the addon length is %d, want 0 for a non-Vision client", got[17])
	}
	if got[18] != cmdTCP {
		t.Errorf("the command byte is 0x%02x, want 0x%02x", got[18], cmdTCP)
	}
	// The port is big endian: a little-endian port would arrive as 0xBB01 =
	// 47873, which is a perfectly valid port number and so would never be
	// rejected — the connection would simply go somewhere else.
	if got[19] != 0x01 || got[20] != 0xBB {
		t.Errorf("the port bytes are %02x %02x, want 01 bb (443, big endian)", got[19], got[20])
	}
	if got[21] != addrTypeDomain {
		t.Errorf("the address type is 0x%02x, want 0x%02x (VLESS domain)", got[21], addrTypeDomain)
	}
	if int(got[22]) != len("example.com") {
		t.Errorf("the host length is %d, want %d", got[22], len("example.com"))
	}
}

// TestEncodeRequestIPv4Layout asserts the IPv4 literal form, which uses a
// different address type and a fixed-length address.
func TestEncodeRequestIPv4Layout(t *testing.T) {
	uuid := cryptox.MustParseUUID(fixedUUID)
	got, err := encodeRequest(uuid, cmdTCP, "93.184.216.34:443", "")
	if err != nil {
		t.Fatalf("encodeRequest: %v", err)
	}

	want := []byte{0x00}
	want = append(want, uuid[:]...)
	want = append(want, 0x00, cmdTCP, 0x01, 0xBB, addrTypeIPv4, 93, 184, 216, 34)

	if !bytes.Equal(got, want) {
		t.Fatalf("the header is\n  % x\nwant\n  % x", got, want)
	}
	if got[21] != addrTypeIPv4 {
		t.Errorf("the address type is 0x%02x, want 0x%02x (VLESS IPv4)", got[21], addrTypeIPv4)
	}
}

// TestEncodeRequestIPv6Layout asserts the 16-byte address form and its type,
// which is the value most likely to be confused with SOCKS5's 0x04.
func TestEncodeRequestIPv6Layout(t *testing.T) {
	uuid := cryptox.MustParseUUID(fixedUUID)
	got, err := encodeRequest(uuid, cmdTCP, "[2001:db8::1]:8080", "")
	if err != nil {
		t.Fatalf("encodeRequest: %v", err)
	}

	if got[19] != 0x1F || got[20] != 0x90 {
		t.Errorf("the port bytes are %02x %02x, want 1f 90 (8080, big endian)", got[19], got[20])
	}
	if got[21] != addrTypeIPv6 {
		t.Errorf("the address type is 0x%02x, want 0x%02x (VLESS IPv6)", got[21], addrTypeIPv6)
	}
	if len(got) != 22+16 {
		t.Errorf("the header is %d bytes, want %d", len(got), 22+16)
	}
	wantIP := net.ParseIP("2001:db8::1").To16()
	if !bytes.Equal(got[22:], wantIP) {
		t.Errorf("the address bytes are % x, want % x", got[22:], wantIP)
	}
}

// TestEncodeRequestUDPCommand proves the UDP command byte reaches the wire.
func TestEncodeRequestUDPCommand(t *testing.T) {
	uuid := cryptox.MustParseUUID(fixedUUID)
	got, err := encodeRequest(uuid, cmdUDP, "dns.example.com:53", "")
	if err != nil {
		t.Fatalf("encodeRequest: %v", err)
	}
	if got[18] != cmdUDP {
		t.Errorf("the command byte is 0x%02x, want 0x%02x (UDP)", got[18], cmdUDP)
	}
	if got[19] != 0x00 || got[20] != 0x35 {
		t.Errorf("the port bytes are %02x %02x, want 00 35 (53, big endian)", got[19], got[20])
	}
}

// TestEncodeRequestRejectsBadTarget proves a target whose port cannot be
// encoded is refused instead of being written as a truncated header.
func TestEncodeRequestRejectsBadTarget(t *testing.T) {
	uuid := cryptox.MustParseUUID(fixedUUID)
	for _, target := range []string{"example.com:0", "example.com:70000", "example.com:notaport", ""} {
		if _, err := encodeRequest(uuid, cmdTCP, target, ""); err == nil {
			t.Errorf("encodeRequest accepted the target %q", target)
		}
	}
}

// TestEncodeRequestRejectsAnEmptyHost is the regression test for an asymmetry
// between the encoder and the decoder.
//
// encodeRequest(":443") used to succeed: SplitHostPort yields an empty host,
// the host is not an IP literal, so it took the domain branch and emitted
// atyp=0x02 with a zero length — the exact frame decodeRequest refuses as
// "vless zero-length domain". The encoder therefore produced a request its own
// decoder was guaranteed to reject, so a client whose target had lost its host
// failed at the relay with an opaque protocol error instead of at the dial with
// a bad-address error that names the target.
func TestEncodeRequestRejectsAnEmptyHost(t *testing.T) {
	uuid := cryptox.MustParseUUID(fixedUUID)

	_, err := encodeRequest(uuid, cmdTCP, ":443", "")
	if err == nil {
		t.Fatal("encodeRequest accepted a target with no host")
	}
	if !errors.Is(err, transport.ErrBadAddress) {
		t.Errorf("the error is %v, want ErrBadAddress", err)
	}
	// The message must name the offending target: this error is the only place
	// the malformed value is still visible.
	if !strings.Contains(err.Error(), ":443") {
		t.Errorf("the error does not name the target: %v", err)
	}
}

// TestEncodeRequestRejectsOverlongDomain proves a domain longer than the
// one-byte length field can express is refused rather than silently truncated,
// which would send the request to a different host.
func TestEncodeRequestRejectsOverlongDomain(t *testing.T) {
	uuid := cryptox.MustParseUUID(fixedUUID)
	long := strings.Repeat("a", 256) + ":443"
	if _, err := encodeRequest(uuid, cmdTCP, long, ""); err == nil {
		t.Fatal("encodeRequest accepted a 256-byte domain")
	}
}

// TestUUIDWireBytesAreExact proves a canonical UUID string round-trips into the
// 16 bytes the protocol carries.
func TestUUIDWireBytesAreExact(t *testing.T) {
	uuid := cryptox.MustParseUUID(fixedUUID)
	want := [16]byte{
		0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53,
		0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11,
	}
	if uuid != want {
		t.Fatalf("the uuid bytes are % x, want % x", uuid[:], want[:])
	}

	// The parser tolerates the forms configuration files actually contain:
	// braces and a bare 32-character hex string. Accepting them is a
	// convenience, but it must not change the bytes.
	for _, form := range []string{
		fixedUUID,
		"{" + fixedUUID + "}",
		"b831381d63244d53ad4f8cda48b30811",
		strings.ToUpper(fixedUUID),
		"  " + fixedUUID + "  ",
	} {
		got, err := cryptox.ParseUUID(form)
		if err != nil {
			t.Errorf("ParseUUID(%q): %v", form, err)
			continue
		}
		if got != want {
			t.Errorf("ParseUUID(%q) produced % x, want % x", form, got[:], want[:])
		}
	}
}

// TestInvalidUUIDIsRejected proves a malformed credential is refused rather
// than silently becoming the all-zero UUID.
//
// Zeroing matters more than it looks: an all-zero identifier is a valid-looking
// 16-byte value, so a relay configured with a typo would happily authenticate a
// client that also had a typo — or, worse, one that deliberately sent zeroes.
func TestInvalidUUIDIsRejected(t *testing.T) {
	for _, bad := range []string{
		"",
		"not-a-uuid",
		"b831381d-6324-4d53-ad4f-8cda48b3081",   // one character short
		"b831381d-6324-4d53-ad4f-8cda48b308112", // one character long
		"b831381d-6324-4d53-ad4f-8cda48b3081z",  // non-hex
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
	} {
		got, err := cryptox.ParseUUID(bad)
		if err == nil {
			t.Errorf("ParseUUID(%q) succeeded and returned % x", bad, got[:])
			continue
		}
		if got != (cryptox.UUID{}) {
			t.Errorf("ParseUUID(%q) returned % x alongside its error, want the zero uuid", bad, got[:])
		}
	}
}

// TestEncodeAddonsFlowOnly asserts the tag-length-value encoding of a
// flow-only addon block.
func TestEncodeAddonsFlowOnly(t *testing.T) {
	got := encodeAddons(FlowVision)
	want := []byte{0x01, byte(len(FlowVision))}
	want = append(want, FlowVision...)

	if !bytes.Equal(got, want) {
		t.Fatalf("the addon block is % x, want % x", got, want)
	}
	if got[0] != 0x01 {
		t.Errorf("the flow tag is 0x%02x, want 0x01", got[0])
	}
	if int(got[1]) != len(FlowVision) {
		t.Errorf("the flow length is %d, want %d", got[1], len(FlowVision))
	}
}

// TestEncodeAddonsEmptyIsZeroLength proves a non-Vision client sends a single
// zero length byte and no addon bytes, which is what keeps the command byte at
// a fixed offset for the common case.
func TestEncodeAddonsEmptyIsZeroLength(t *testing.T) {
	got := encodeAddons("")
	if len(got) != 0 {
		t.Fatalf("the addon block is % x, want empty", got)
	}

	// The length byte written into the header must be zero, so the header is
	// exactly 22 bytes for a domain target.
	uuid := cryptox.MustParseUUID(fixedUUID)
	header, err := encodeRequest(uuid, cmdTCP, "example.com:443", "")
	if err != nil {
		t.Fatalf("encodeRequest: %v", err)
	}
	if header[17] != 0x00 {
		t.Errorf("the addon length byte is 0x%02x, want 0x00", header[17])
	}
	if header[18] != cmdTCP {
		t.Errorf("the command byte is at offset 18 with value 0x%02x; a non-zero addon length shifted it", header[18])
	}
}

// TestAddonRoundTrip proves the encoder and decoder agree for a flow-only
// addon, a seed-only addon, and both together.
func TestAddonRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		blob []byte
		want map[string]string
	}{
		{
			name: "flow only",
			blob: encodeAddons(FlowVision),
			want: map[string]string{"flow": FlowVision},
		},
		{
			// The seed is what a Vision client uses to derive its padding; it
			// must survive the round trip or the two sides desynchronise.
			name: "flow and seed",
			blob: append(append([]byte{0x01, byte(len(FlowVision))}, FlowVision...), 0x02, 0x04, 'a', 'b', 'c', 'd'),
			want: map[string]string{"flow": FlowVision, "seed": "abcd"},
		},
		{
			name: "unknown tag is preserved under a synthetic name",
			blob: []byte{0x07, 0x02, 'h', 'i'},
			want: map[string]string{"tag7": "hi"},
		},
		{
			name: "empty value",
			blob: []byte{0x01, 0x00},
			want: map[string]string{"flow": ""},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decodeAddons(tc.blob)
			if len(got) != len(tc.want) {
				t.Fatalf("decodeAddons(% x) = %v, want %v", tc.blob, got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("decodeAddons(% x)[%q] = %q, want %q", tc.blob, k, got[k], v)
				}
			}
		})
	}
}

// TestDecodeAddonsIgnoresATruncatedTail proves a malformed addon block does not
// panic or read past its buffer.
//
// The block arrives from an unauthenticated peer, so a length that runs off the
// end is entirely attacker-controlled input; the decoder must stop rather than
// slice out of range.
func TestDecodeAddonsIgnoresATruncatedTail(t *testing.T) {
	blob := []byte{0x01, 0x10, 'a', 'b'} // claims 16 bytes, supplies 2
	got := decodeAddons(blob)
	if got["flow"] != "" {
		t.Errorf("a truncated addon yielded flow %q, want nothing", got["flow"])
	}

	// A trailing tag with no length byte at all must also be tolerated.
	got = decodeAddons([]byte{0x01, 0x02, 'o', 'k', 0x02})
	if got["flow"] != "ok" {
		t.Errorf("the valid prefix was lost: %v", got)
	}
}

// TestDecodeRequestParsesDomain proves the relay half decodes a domain target
// and the command it carried.
func TestDecodeRequestParsesDomain(t *testing.T) {
	uuid := cryptox.MustParseUUID(fixedUUID)
	frame := requestHeader(uuid[:], nil, cmdTCP, 443, addrTypeDomain, append([]byte{byte(len("example.com"))}, "example.com"...))

	version, gotUUID, command, target, addons, err := decodeRequest(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("decodeRequest: %v", err)
	}
	if version != 0 {
		t.Errorf("version = %d, want 0", version)
	}
	if gotUUID != uuid {
		t.Errorf("uuid = % x, want % x", gotUUID[:], uuid[:])
	}
	if command != cmdTCP {
		t.Errorf("command = 0x%02x, want 0x%02x", command, cmdTCP)
	}
	if target != "example.com:443" {
		t.Errorf("target = %q, want example.com:443", target)
	}
	if len(addons) != 0 {
		t.Errorf("addons = %v, want none", addons)
	}
}

// TestDecodeRequestParsesDomainWithVLESSAddressType is the direct regression
// test for the numbering difference.
//
// The frame here is exactly what a real VLESS client sends: address type 0x02
// for a domain. If the relay were parsing with the SOCKS5 table it would read
// 0x02 as "IPv6" and consume sixteen bytes, so the assertion on the decoded
// target is what catches it.
func TestDecodeRequestParsesDomainWithVLESSAddressType(t *testing.T) {
	uuid := cryptox.MustParseUUID(fixedUUID)
	host := "example.com"
	// 0x02, the VLESS domain type. 0x03 is the SOCKS5 domain type and must not
	// be what this frame uses.
	frame := requestHeader(uuid[:], nil, cmdTCP, 80, 0x02, append([]byte{byte(len(host))}, host...))

	_, _, _, target, _, err := decodeRequest(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("decodeRequest: %v", err)
	}
	if target != "example.com:80" {
		t.Fatalf("target = %q, want example.com:80", target)
	}
	if addrTypeDomain != 0x02 {
		t.Fatalf("the frame used the VLESS domain type 0x02 but addrTypeDomain is 0x%02x", addrTypeDomain)
	}
}

// TestDecodeRequestRejectsUnknownAddressType proves a type byte the relay does
// not implement is refused instead of being guessed at.
func TestDecodeRequestRejectsUnknownAddressType(t *testing.T) {
	uuid := cryptox.MustParseUUID(fixedUUID)
	// 0x04 is SOCKS5's IPv6 type, which VLESS deliberately does not define.
	// Treating it as valid would be exactly the mixing-up this package warns
	// about.
	frame := requestHeader(uuid[:], nil, cmdTCP, 443, 0x04, []byte{0, 0, 0, 0, 0, 0})

	_, _, _, _, _, err := decodeRequest(bytes.NewReader(frame))
	if err == nil {
		t.Fatal("decodeRequest accepted SOCKS5's address type 0x04")
	}
	if !errors.Is(err, transport.ErrProtocol) {
		t.Errorf("decodeRequest returned %v, want ErrProtocol", err)
	}
	if !strings.Contains(err.Error(), "0x04") {
		t.Errorf("the error does not name the offending type: %v", err)
	}
}

// TestDecodeRequestRejectsZeroLengthDomain proves a domain with no name is
// refused: a zero-length name would decode to ":port", which the relay would
// then dial against its own host.
func TestDecodeRequestRejectsZeroLengthDomain(t *testing.T) {
	uuid := cryptox.MustParseUUID(fixedUUID)
	frame := requestHeader(uuid[:], nil, cmdTCP, 443, addrTypeDomain, []byte{0x00})

	_, _, _, _, _, err := decodeRequest(bytes.NewReader(frame))
	if err == nil {
		t.Fatal("decodeRequest accepted a zero-length domain")
	}
	if !errors.Is(err, transport.ErrProtocol) {
		t.Errorf("decodeRequest returned %v, want ErrProtocol", err)
	}
}

// TestDecodeRequestRejectsATruncatedHeader proves a short frame fails rather
// than being decoded from whatever bytes happened to be in the buffer.
func TestDecodeRequestRejectsATruncatedHeader(t *testing.T) {
	uuid := cryptox.MustParseUUID(fixedUUID)
	full := requestHeader(uuid[:], nil, cmdTCP, 443, addrTypeDomain, append([]byte{byte(len("example.com"))}, "example.com"...))

	for _, n := range []int{0, 1, 16, 17, 18, 20, 21, 22, len(full) - 1} {
		if _, _, _, _, _, err := decodeRequest(bytes.NewReader(full[:n])); err == nil {
			t.Errorf("decodeRequest accepted a %d-byte prefix of a %d-byte header", n, len(full))
		}
	}
}

// TestReadResponseConsumesAddons proves the response reader consumes the addon
// bytes its length field announces, so they do not end up at the head of the
// payload.
func TestReadResponseConsumesAddons(t *testing.T) {
	// version 0, addon length 3, three addon bytes, then the payload.
	wire := []byte{0x00, 0x03, 'a', 'b', 'c', 'P', 'A', 'Y'}

	r := bytes.NewReader(wire)
	if err := readResponse(r, false); err != nil {
		t.Fatalf("readResponse: %v", err)
	}
	rest, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read the payload: %v", err)
	}
	if string(rest) != "PAY" {
		t.Errorf("the stream holds %q after the response header, want \"PAY\"", rest)
	}
}

// TestReadResponseRejectsATruncatedHeader proves a relay that closed before
// sending its response header is reported as an error rather than silently
// treated as success.
func TestReadResponseRejectsATruncatedHeader(t *testing.T) {
	for _, wire := range [][]byte{
		{},           // nothing at all
		{0x00},       // only the version byte
		{0x00, 0x04}, // announces four addon bytes and supplies none
		{0x00, 0x04, 'a', 'b'},
	} {
		if err := readResponse(bytes.NewReader(wire), false); err == nil {
			t.Errorf("readResponse accepted the truncated header % x", wire)
		}
	}
}

// TestReadResponseNonVisionLeavesThePayloadIntact is the regression test for
// the worst bug this transport has had.
//
// The relay writes its two-byte response header unconditionally, but the client
// once read it only when the Vision flow was enabled. Every non-Vision stream
// therefore had two unconsumed bytes at its head, and the entire payload was
// shifted by two — a corruption that produced no error anywhere, just wrong
// bytes, and was invisible to every test that did not compare the payload
// exactly.
func TestReadResponseNonVisionLeavesThePayloadIntact(t *testing.T) {
	// A payload whose first two bytes are deliberately not the header, so a
	// reader that skipped too much or too little is caught immediately.
	payload := []byte{'h', 'e', 'l', 'l', 'o'}
	wire := append([]byte{0x00, 0x00}, payload...)

	r := bytes.NewReader(wire)
	if err := readResponse(r, false); err != nil {
		t.Fatalf("readResponse: %v", err)
	}

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read the payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("the payload is %q, want %q — the response header was not consumed exactly once", got, payload)
	}
	if len(got) > 0 && got[0] == 0x00 {
		t.Error("the payload still starts with a header byte, which is the two-byte shift")
	}
}

// TestReadResponseVisionConsumesPadding proves the Vision path consumes the
// length-prefixed padding region as well as the header.
func TestReadResponseVisionConsumesPadding(t *testing.T) {
	payload := []byte("hello")
	// header, then padding length 3, three padding bytes, then the payload.
	wire := append([]byte{0x00, 0x00, 0x00, 0x03, 'p', 'p', 'p'}, payload...)

	r := bytes.NewReader(wire)
	if err := readResponse(r, true); err != nil {
		t.Fatalf("readResponse: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read the payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("the payload is %q, want %q", got, payload)
	}
}

// TestReadResponseHandlesBothPaddingExtremes covers the maximum padding and the
// zero-padding case.
//
// Zero is the interesting one: a length of 0 is legal and must consume exactly
// the two length bytes and nothing more. An implementation that always read at
// least one padding byte would eat the first payload byte on every stream.
func TestReadResponseHandlesBothPaddingExtremes(t *testing.T) {
	cases := []struct {
		name string
		pad  int
	}{
		{"zero padding", 0},
		{"one byte of padding", 1},
		{"maximum padding", maxPadding},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte("payload")
			wire := []byte{0x00, 0x00}
			wire = binary.BigEndian.AppendUint16(wire, uint16(tc.pad))
			wire = append(wire, bytes.Repeat([]byte{0xAA}, tc.pad)...)
			wire = append(wire, payload...)

			r := bytes.NewReader(wire)
			if err := readResponse(r, true); err != nil {
				t.Fatalf("readResponse: %v", err)
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("read the payload: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("the payload is %q, want %q", got, payload)
			}
		})
	}
}

// TestSkipVisionPaddingRejectsAnOverlongLength proves a padding length above
// the protocol maximum is refused rather than being honoured.
//
// Honouring it would let a hostile relay make the client allocate and consume
// an arbitrary number of bytes — the length field is two bytes wide, so it can
// ask for 65535 — which stalls the stream until its deadline.
func TestSkipVisionPaddingRejectsAnOverlongLength(t *testing.T) {
	wire := binary.BigEndian.AppendUint16(nil, maxPadding+1)
	wire = append(wire, bytes.Repeat([]byte{0x00}, maxPadding+1)...)

	err := skipVisionPadding(bytes.NewReader(wire))
	if err == nil {
		t.Fatalf("skipVisionPadding accepted a padding length of %d", maxPadding+1)
	}
	if !errors.Is(err, transport.ErrProtocol) {
		t.Errorf("skipVisionPadding returned %v, want ErrProtocol", err)
	}
	if !strings.Contains(err.Error(), "padding") {
		t.Errorf("the error does not name the problem: %v", err)
	}
}

// TestRandomPaddingIsWellFormed proves the generated padding region is a
// big-endian length followed by exactly that many bytes, bounded by maxPadding.
//
// A generator that wrote a length it did not honour — or that emitted the
// maximum every time — would desynchronise the receiver; a constant length is
// additionally a fingerprint, which is why the length is drawn at random.
func TestRandomPaddingIsWellFormed(t *testing.T) {
	seen := map[int]bool{}
	for i := 0; i < 200; i++ {
		pad, err := randomPadding()
		if err != nil {
			t.Fatalf("randomPadding: %v", err)
		}
		if len(pad) < 2 {
			t.Fatalf("the padding region is %d bytes, too short to hold a length", len(pad))
		}
		n := int(binary.BigEndian.Uint16(pad[:2]))
		if n > maxPadding {
			t.Fatalf("the announced padding length is %d, above the maximum %d", n, maxPadding)
		}
		if len(pad) != 2+n {
			t.Fatalf("the padding region is %d bytes but announces %d", len(pad), n)
		}
		seen[n] = true
	}
	// A fixed length would be a fingerprint, so the generator must vary. Two
	// hundred draws landing on one value would be overwhelming evidence of a
	// constant.
	if len(seen) < 2 {
		t.Errorf("200 padding regions all had the same length %v, which is a fingerprint", seen)
	}
}

// TestHandlerParsesTCPHandshake proves the relay half hands back a stream
// naming the target, which is the whole contract of the transport.
func TestHandlerParsesTCPHandshake(t *testing.T) {
	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: noTLS(transport.Settings{SettingUUID: fixedUUID}),
		Timeout:  5 * time.Second,
		Logger:   logx.Discard(),
	})

	uuid := cryptox.MustParseUUID(fixedUUID)
	writeAsync(client, requestHeader(uuid[:], nil, cmdTCP, 443, addrTypeDomain,
		append([]byte{byte(len("example.com"))}, "example.com"...)))

	// The relay writes its response header before returning, so the client half
	// must consume it or the relay blocks on a synchronous pipe.
	readN(t, client, 2)

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Handle: %v", r.err)
		}
		if r.stream == nil {
			t.Fatal("Handle returned no error but also no stream")
		}
		defer r.stream.Close()
		if got := r.stream.Request().Target; got != "example.com:443" {
			t.Errorf("the stream target is %q, want example.com:443", got)
		}
		if got := r.stream.TransportName(); got != Name {
			t.Errorf("the stream transport is %q, want %q", got, Name)
		}
		if got := r.stream.Request().Command; got != transport.CmdConnectTCP {
			t.Errorf("the stream command is %v, want a TCP connect", got)
		}
		if got := r.stream.Request().Meta["flow"]; got != "" {
			t.Errorf("a non-Vision stream reports flow %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestHandlerParsesUDPHandshake proves the UDP command byte is translated into
// the relay's own enumeration.
func TestHandlerParsesUDPHandshake(t *testing.T) {
	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: noTLS(transport.Settings{SettingUUID: fixedUUID}),
		Timeout:  5 * time.Second,
	})

	uuid := cryptox.MustParseUUID(fixedUUID)
	writeAsync(client, requestHeader(uuid[:], nil, cmdUDP, 53, addrTypeIPv4, []byte{1, 2, 3, 4}))
	readN(t, client, 2)

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Handle: %v", r.err)
		}
		defer r.stream.Close()
		if got := r.stream.Request().Command; got != transport.CmdUDPAssociate {
			t.Errorf("the stream command is %v, want a UDP associate", got)
		}
		if got := r.stream.Request().Target; got != "1.2.3.4:53" {
			t.Errorf("the stream target is %q, want 1.2.3.4:53", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestHandlerRefusesTheMuxCommand proves a MUX request is explicitly refused
// and that the refusal is distinguishable from a generic failure.
//
// The transport deliberately does not implement VLESS MUX: the client already
// runs its own smux layer above the transport, so a MUX command here would be a
// client bug. Accepting it would silently produce a stream whose framing the
// relay does not understand, which is far worse than a clean refusal.
func TestHandlerRefusesTheMuxCommand(t *testing.T) {
	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: noTLS(transport.Settings{SettingUUID: fixedUUID}),
		Timeout:  5 * time.Second,
	})

	uuid := cryptox.MustParseUUID(fixedUUID)
	writeAsync(client, requestHeader(uuid[:], nil, cmdMux, 443, addrTypeDomain,
		append([]byte{byte(len("example.com"))}, "example.com"...)))
	readN(t, client, 2) // the relay echoes its response header before refusing

	select {
	case r := <-done:
		if r.stream != nil {
			t.Fatal("the relay handed back a stream for a MUX command")
		}
		if r.err == nil {
			t.Fatal("the relay accepted a MUX command")
		}
		if !errors.Is(r.err, transport.ErrProtocol) {
			t.Errorf("the refusal is %v, want ErrProtocol", r.err)
		}
		// The message must name MUX so an operator can tell a client bug from a
		// wire-format violation.
		if !strings.Contains(r.err.Error(), "MUX") {
			t.Errorf("the refusal does not name the MUX command: %v", r.err)
		}
		// It must not be an authentication failure, or it would be counted as a
		// credential problem rather than a protocol one.
		if errors.Is(r.err, transport.ErrAuthFailed) {
			t.Error("the MUX refusal is reported as an authentication failure")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestHandlerRefusesAnUnknownUUID proves an unauthenticated client is refused
// and never receives a stream.
func TestHandlerRefusesAnUnknownUUID(t *testing.T) {
	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: noTLS(transport.Settings{SettingUUID: fixedUUID}),
		Timeout:  5 * time.Second,
	})

	// A well-formed but different UUID: the only thing wrong with the frame is
	// the credential, so this isolates the authentication check.
	other := cryptox.MustParseUUID("b831381d-6324-4d53-ad4f-8cda48b30812")
	writeAsync(client, requestHeader(other[:], nil, cmdTCP, 443, addrTypeDomain,
		append([]byte{byte(len("example.com"))}, "example.com"...)))
	drainAsync(client)

	select {
	case r := <-done:
		if r.stream != nil {
			t.Fatal("an unknown uuid was handed a stream")
		}
		if !errors.Is(r.err, transport.ErrAuthFailed) {
			t.Fatalf("Handle returned %v, want ErrAuthFailed", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestHandlerRefusesAZeroUUID proves the all-zero identifier is not a
// wildcard.
//
// A relay whose uuid setting failed to load would have a zero wantUUID, and a
// constant-time comparison against zero must not authenticate a client that
// sends zeroes — that would turn a configuration mistake into an open proxy.
func TestHandlerRefusesAZeroUUID(t *testing.T) {
	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: noTLS(transport.Settings{SettingUUID: fixedUUID}),
		Timeout:  5 * time.Second,
	})

	writeAsync(client, requestHeader(make([]byte, 16), nil, cmdTCP, 443, addrTypeDomain,
		append([]byte{byte(len("example.com"))}, "example.com"...)))
	drainAsync(client)

	select {
	case r := <-done:
		if r.stream != nil {
			t.Fatal("the all-zero uuid authenticated")
		}
		if !errors.Is(r.err, transport.ErrAuthFailed) {
			t.Fatalf("Handle returned %v, want ErrAuthFailed", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestHandlerRefusesANonZeroVersion proves a future protocol version is refused
// rather than parsed with this build's layout.
func TestHandlerRefusesANonZeroVersion(t *testing.T) {
	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: noTLS(transport.Settings{SettingUUID: fixedUUID}),
		Timeout:  5 * time.Second,
	})

	uuid := cryptox.MustParseUUID(fixedUUID)
	frame := requestHeader(uuid[:], nil, cmdTCP, 443, addrTypeDomain,
		append([]byte{byte(len("example.com"))}, "example.com"...))
	frame[0] = 0x01 // a version this build does not implement
	writeAsync(client, frame)
	drainAsync(client)

	select {
	case r := <-done:
		if r.stream != nil {
			t.Fatal("an unsupported version was accepted")
		}
		if !errors.Is(r.err, transport.ErrProtocol) {
			t.Fatalf("Handle returned %v, want ErrProtocol", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestHandlerRejectsMissingUUIDSetting proves a relay with no uuid configured
// refuses every connection instead of authenticating everyone.
func TestHandlerRejectsMissingUUIDSetting(t *testing.T) {
	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: noTLS(nil),
		Timeout:  2 * time.Second,
	})

	_ = client.Close()

	select {
	case r := <-done:
		if r.stream != nil {
			t.Fatal("a relay with no uuid handed out a stream")
		}
		if r.err == nil || !strings.Contains(r.err.Error(), SettingUUID) {
			t.Fatalf("Handle returned %v, want an error naming the missing uuid", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestNilLoggerHandshake proves a handshake with no logger configured does not
// panic.
//
// This was a real panic in this repository: a loggerFor helper returned a nil
// interface, and the first method call on it took down the whole relay from
// inside the handshake path.
func TestNilLoggerHandshake(t *testing.T) {
	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: noTLS(transport.Settings{SettingUUID: fixedUUID}),
		Timeout:  5 * time.Second,
		Logger:   nil,
	})

	uuid := cryptox.MustParseUUID(fixedUUID)
	writeAsync(client, requestHeader(uuid[:], nil, cmdTCP, 443, addrTypeDomain,
		append([]byte{byte(len("example.com"))}, "example.com"...)))
	readN(t, client, 2)

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Handle with a nil logger: %v", r.err)
		}
		defer r.stream.Close()
		if got := r.stream.Request().Target; got != "example.com:443" {
			t.Errorf("the stream target is %q, want example.com:443", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestNilLoggerOnTheAuthenticationFailurePath proves the logging inside the
// refusal path is nil-safe too, since that is the path an unauthenticated peer
// can reach on every connection.
func TestNilLoggerOnTheAuthenticationFailurePath(t *testing.T) {
	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: noTLS(transport.Settings{SettingUUID: fixedUUID}),
		Timeout:  5 * time.Second,
		Logger:   nil,
	})

	other := cryptox.MustParseUUID("b831381d-6324-4d53-ad4f-8cda48b30812")
	writeAsync(client, requestHeader(other[:], nil, cmdTCP, 443, addrTypeDomain,
		append([]byte{byte(len("example.com"))}, "example.com"...)))
	drainAsync(client)

	select {
	case r := <-done:
		if r.err == nil {
			t.Fatal("an unknown uuid was accepted with a nil logger")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestLoggerForNilIsUsable proves the adapter returns a working logger rather
// than a nil interface, which is the fix for the panic described above.
func TestLoggerForNilIsUsable(t *testing.T) {
	log := loggerFor(nil)
	if log == nil {
		t.Fatal("loggerFor(nil) returned a nil interface, which panics on first use")
	}
	log.Debug("vless: test", "key", "value")
	log.Info("vless: test", "key", "value")
	log.Warn("vless: test", "key", "value")
	log.Error("vless: test", "key", "value")

	if got := loggerFor(logx.Discard()); got == nil {
		t.Error("loggerFor returned nil for a non-nil logger")
	}
}

// TestVisionRoundTripIsByteExact is the end-to-end proof that the Vision
// padding framing does not corrupt the payload.
//
// The relay generates random padding of a random length, so the only way to
// know the framing is right is to send a payload through and compare it byte
// for byte — a length that was announced but not written, or written but not
// skipped, shifts everything that follows.
func TestVisionRoundTripIsByteExact(t *testing.T) {
	payload := []byte("the quick brown fox jumps over the lazy dog")

	for i := 0; i < 20; i++ {
		client, server := pair(t)
		done := runHandle(server, transport.HandleRequest{
			Settings: noTLS(transport.Settings{SettingUUID: fixedUUID}),
			Timeout:  5 * time.Second,
		})

		uuid := cryptox.MustParseUUID(fixedUUID)
		addons := encodeAddons(FlowVision)
		// The client's own Vision framing: header, then a padding region it
		// chooses, then the payload. The relay must skip the padding to reach
		// the payload.
		pad := binary.BigEndian.AppendUint16(nil, 4)
		pad = append(pad, 0xDE, 0xAD, 0xBE, 0xEF)

		frame := requestHeader(uuid[:], addons, cmdTCP, 443, addrTypeDomain,
			append([]byte{byte(len("example.com"))}, "example.com"...))
		frame = append(frame, pad...)
		frame = append(frame, payload...)
		writeAsync(client, frame)

		// The relay writes its response header, and its own Vision padding
		// region, from inside Handle and before it returns. On a synchronous
		// pipe that write blocks until the client consumes it, so the client's
		// side of the exchange must run concurrently with Handle rather than
		// after it — waiting for Handle first would deadlock.
		respCh := make(chan error, 1)
		go func() { respCh <- readResponse(client, true) }()

		var stream transport.Stream
		select {
		case r := <-done:
			if r.err != nil {
				t.Fatalf("Handle: %v", r.err)
			}
			stream = r.stream
		case <-time.After(5 * time.Second):
			t.Fatal("Handle did not return")
		}

		if got := stream.Request().Meta["flow"]; got != FlowVision {
			t.Fatalf("the stream flow is %q, want %q", got, FlowVision)
		}

		// The relay echoes the response header plus its own padding region; the
		// visionStream wrapper is what strips that for the caller.
		got := make([]byte, len(payload))
		_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(stream, got); err != nil {
			stream.Close()
			t.Fatalf("read the payload on iteration %d: %v", i, err)
		}
		stream.Close()
		client.Close()

		if !bytes.Equal(got, payload) {
			t.Fatalf("iteration %d: the payload is %q, want %q", i, got, payload)
		}
		// The response header and padding must have parsed cleanly; an error
		// here means the relay's framing did not match what the client reads.
		select {
		case err := <-respCh:
			if err != nil {
				t.Fatalf("iteration %d: readResponse: %v", i, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("readResponse did not return")
		}
	}
}

// TestNonVisionRoundTripIsByteExact is the end-to-end regression test for the
// two-byte shift.
//
// The relay always writes version + addonLen, and the client must always read
// them. When it read them only under Vision, every non-Vision stream began with
// the relay's two header bytes and the payload was shifted by two — silently,
// with no error and no failed handshake. This test asserts the exact payload,
// which is the only assertion that can see it.
func TestNonVisionRoundTripIsByteExact(t *testing.T) {
	client, server := pair(t)
	done := runHandle(server, transport.HandleRequest{
		Settings: noTLS(transport.Settings{SettingUUID: fixedUUID}),
		Timeout:  5 * time.Second,
	})

	uuid := cryptox.MustParseUUID(fixedUUID)
	writeAsync(client, requestHeader(uuid[:], nil, cmdTCP, 443, addrTypeDomain,
		append([]byte{byte(len("example.com"))}, "example.com"...)))

	// The relay writes its response header from inside Handle, before it
	// returns. On a synchronous pipe that write blocks until the client reads
	// it, so the read must run concurrently with Handle.
	headCh := make(chan []byte, 1)
	go func() {
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 2)
		if _, err := io.ReadFull(client, buf); err != nil {
			headCh <- nil
			return
		}
		headCh <- buf
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Handle: %v", r.err)
		}
		defer r.stream.Close()
		if got := r.stream.Request().Meta["flow"]; got != "" {
			t.Errorf("a non-Vision stream reports flow %q", got)
		}

		head := <-headCh
		if head == nil {
			t.Fatal("the relay did not send a response header")
		}
		if head[0] != 0x00 || head[1] != 0x00 {
			t.Fatalf("the response header is % x, want 00 00", head)
		}

		// The payload must be byte-exact. The regression this guards is the
		// two-byte shift: if the client failed to consume the response header,
		// the stream would begin with the header bytes and everything after
		// would be displaced.
		payload := []byte("hello")
		writeAsync(client, payload)

		got := make([]byte, len(payload))
		_ = r.stream.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(r.stream, got); err != nil {
			t.Fatalf("read the payload: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("the payload is %q, want %q", got, payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}

// TestVisionStreamStripsPaddingOnTheFirstRead proves the wrapper removes the
// padding region exactly once.
//
// Stripping on every read would consume two payload bytes per read and stall
// the stream; stripping on none would leave the padding in the payload.
//
// Note what the wrapper does and does not consume: it skips only the padding
// region. The response header is read separately by readResponse, which the
// client's Dial calls before the stream is ever handed out. Modelling that
// distinction here matters — a test that fed the header through this wrapper
// would be asserting the wrong contract.
func TestVisionStreamStripsPaddingOnTheFirstRead(t *testing.T) {
	client, server := pair(t)

	// What the peer sends after the response header: padding length 2, two
	// padding bytes, then the payload.
	wire := []byte{0x00, 0x02, 'p', 'p'}
	wire = append(wire, []byte("first")...)
	go func() { _, _ = server.Write(wire) }()

	base := transport.NewStream(client, &transport.Request{Command: transport.CmdConnectTCP}, Name, 0)
	vs := &visionStream{Stream: base, conn: client}

	first := make([]byte, 5)
	_ = vs.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(vs, first); err != nil {
		t.Fatalf("first read: %v", err)
	}
	if string(first) != "first" {
		t.Fatalf("the first read returned %q, want \"first\"", first)
	}

	// A second read must not strip anything: the padding is already gone.
	go func() { _, _ = server.Write([]byte("second")) }()
	second := make([]byte, 6)
	_ = vs.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(vs, second); err != nil {
		t.Fatalf("second read: %v", err)
	}
	if string(second) != "second" {
		t.Fatalf("the second read returned %q, want \"second\"", second)
	}
}

// TestVisionStreamStripsZeroPadding proves a zero-length padding region still
// consumes its two length bytes and no more.
//
// This is the case that corrupts a payload most quietly: a wrapper that treated
// a zero length as "nothing to do" would leave the two length bytes in front of
// the payload, shifting every subsequent byte by two.
func TestVisionStreamStripsZeroPadding(t *testing.T) {
	client, server := pair(t)

	wire := []byte{0x00, 0x00}
	wire = append(wire, []byte("payload")...)
	go func() { _, _ = server.Write(wire) }()

	base := transport.NewStream(client, &transport.Request{Command: transport.CmdConnectTCP}, Name, 0)
	vs := &visionStream{Stream: base, conn: client}

	got := make([]byte, 7)
	_ = vs.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(vs, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "payload" {
		t.Fatalf("the read returned %q, want \"payload\"", got)
	}
}

// TestRegistrationAndMetadata proves the transport is discoverable under the
// name a configuration file would use, with the conventional port.
func TestRegistrationAndMetadata(t *testing.T) {
	if Name != "vless" {
		t.Errorf("Name = %q, want \"vless\"", Name)
	}

	f, ok := transport.Lookup(Name)
	if !ok {
		t.Fatalf("transport.Lookup(%q) found nothing", Name)
	}
	if f.DefaultPort != DefaultPort {
		t.Errorf("DefaultPort = %d, want %d", f.DefaultPort, DefaultPort)
	}
	if DefaultPort != 443 {
		t.Errorf("DefaultPort = %d, want 443", DefaultPort)
	}
	// VLESS carries the target in its own header, so the client must not also
	// exchange a PortTransit preamble; a wrong value here would make the relay
	// expect a preamble that never arrives.
	if !f.NativeHeader {
		t.Error("the factory does not declare a native header")
	}

	d, h := f.Build()
	if d == nil || h == nil {
		t.Fatal("Build returned a nil dialer or handler")
	}
	if d.Name() != Name {
		t.Errorf("the dialer is registered as %q, want %q", d.Name(), Name)
	}
	if h.Name() != Name {
		t.Errorf("the handler is registered as %q, want %q", h.Name(), Name)
	}
}

// TestSettingsKeysAreStable pins the configuration keys, because a renamed key
// is silently ignored: the relay would fall back to its default and a working
// configuration would start behaving differently with no error.
func TestSettingsKeysAreStable(t *testing.T) {
	want := map[string]string{
		SettingUUID:               "uuid",
		SettingFlow:               "flow",
		SettingServerName:         "serverName",
		SettingInsecureSkipVerify: "insecure",
		SettingCertFingerprint:    "certFingerprint",
		SettingTLS:                "tls",
		SettingCertFile:           "certFile",
		SettingKeyFile:            "keyFile",
		SettingTimeout:            "timeout",
		SettingMinVersion:         "minVersion",
		SettingDecryption:         "decryption",
	}
	for got, expected := range want {
		if got != expected {
			t.Errorf("a settings key is %q, want %q", got, expected)
		}
	}
}

// TestDialRequiresUUID proves the client refuses to open a connection with no
// credential rather than sending a header the relay would reject.
func TestDialRequiresUUID(t *testing.T) {
	_, err := Dialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: "relay.example:443",
		Request:    &transport.Request{Command: transport.CmdConnectTCP, Target: "example.com:443"},
	})
	if err == nil {
		t.Fatal("Dial accepted an empty uuid")
	}
	if !strings.Contains(err.Error(), SettingUUID) {
		t.Errorf("the error does not name the missing setting: %v", err)
	}
}

// TestDialRejectsAnInvalidUUID proves a malformed credential stops the dial
// instead of being silently zeroed into a valid-looking identifier.
func TestDialRejectsAnInvalidUUID(t *testing.T) {
	_, err := Dialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: "relay.example:443",
		Request:    &transport.Request{Command: transport.CmdConnectTCP, Target: "example.com:443"},
		Settings:   transport.Settings{SettingUUID: "not-a-uuid"},
	})
	if err == nil {
		t.Fatal("Dial accepted a malformed uuid")
	}
}

// TestDialWithNilRequestSendsAProbe is the regression test for a nil-Request
// panic in the Dial path.
//
// Dial used to read req.Request.Target before checking whether req.Request was
// nil, so a nil Request panicked with "invalid memory address or nil pointer
// dereference" and the documented probe branch below it was dead code. The
// panic only fired once the TCP dial had succeeded, which is why it was easy to
// miss: a probe against a closed port returned the dial error first.
//
// A nil Request is what a reachability probe passes, so the assertion is that
// the probe reaches the relay as an ordinary TCP request to the relay's own
// address rather than crashing the client.
func TestDialWithNilRequestSendsAProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	type observed struct {
		target string
		meta   map[string]string
	}
	got := make(chan observed, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))

		_, _, _, target, _, err := decodeRequest(c)
		if err != nil {
			got <- observed{target: "decode failed: " + err.Error()}
			return
		}
		// The client blocks in readResponse, so the relay must answer before
		// the probe can complete.
		_, _ = c.Write([]byte{0x00, 0x00})
		got <- observed{target: target}
	}()

	// SettingTLS is false so no certificate is involved: the only thing under
	// test is the request-rewriting block.
	stream, err := Dialer{}.Dial(context.Background(), transport.DialRequest{
		ServerAddr: ln.Addr().String(),
		Request:    nil,
		Settings: transport.Settings{
			SettingUUID: fixedUUID,
			SettingTLS:  false,
		},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial with a nil Request: %v", err)
	}
	t.Cleanup(func() { stream.Close() })

	select {
	case o := <-got:
		if o.target != ln.Addr().String() {
			t.Errorf("the probe target is %q, want the relay address %q", o.target, ln.Addr().String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the relay never saw the probe")
	}

	// The rewritten request must also be visible to the caller, because the
	// relay classifies a probe by this flag rather than by the target.
	if stream.Request() == nil {
		t.Fatal("the stream reports no request")
	}
	if stream.Request().Target != ln.Addr().String() {
		t.Errorf("the stream target is %q, want %q", stream.Request().Target, ln.Addr().String())
	}
	if got := stream.Request().Meta["ping"]; got != "true" {
		t.Errorf("the stream's ping flag is %q, want \"true\"", got)
	}
}

// TestMinVersionPinsTLS proves the TLS floor is honoured, since a relay that
// silently accepted TLS 1.0 would be trivially downgraded.
func TestMinVersionPinsTLS(t *testing.T) {
	if got := minVersion("1.3"); got != 0x0304 {
		t.Errorf("minVersion(\"1.3\") = %d, want TLS 1.3", got)
	}
	for _, in := range []string{"", "1.2", "garbage", "1.0"} {
		if got := minVersion(in); got != 0x0303 {
			t.Errorf("minVersion(%q) = %d, want TLS 1.2", in, got)
		}
	}
}

// TestParsePortCoversTheBoundaries proves the port parser accepts the whole
// valid range and refuses everything outside it, since a port of 0 or 70000
// would otherwise be written to the wire as a wrapped two-byte value.
func TestParsePortCoversTheBoundaries(t *testing.T) {
	for in, want := range map[string]uint16{"1": 1, "80": 80, "443": 443, "65535": 65535} {
		got, err := parsePort(in)
		if err != nil {
			t.Errorf("parsePort(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parsePort(%q) = %d, want %d", in, got, want)
		}
	}
	for _, in := range []string{"0", "65536", "-1", "", "http"} {
		if _, err := parsePort(in); err == nil {
			t.Errorf("parsePort(%q) accepted an out-of-range or non-numeric port", in)
		}
	}
	// Trailing whitespace is accepted because Sscanf stops at it. That is
	// unreachable from a real target: SplitHostPort trims the whole address
	// before the port is ever parsed, so the leniency costs nothing.
	if got, err := parsePort("443 "); err != nil || got != 443 {
		t.Logf("note: parsePort(\"443 \") = (%d, %v); the whitespace tolerance has changed", got, err)
	}
}
