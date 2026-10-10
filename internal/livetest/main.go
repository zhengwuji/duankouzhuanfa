// Command livetest drives a real end-to-end check against a running relay and
// client using only public interfaces: it connects through the client's local
// SOCKS5 proxy and verifies the bytes come back.
//
// It exists because the unit and e2e suites build the relay and client in
// process, so nothing else proves that two separately launched binaries
// interoperate over real sockets with a real configuration file.
//
// Two target arrangements are supported. By default it starts its own TCP echo
// target on this host, which suits a same-host test. With -no-echo the target
// must already be listening on -echo, which is what a cross-host test needs: a
// relay dials the target from the *relay* host, so the target has to live
// there, not here.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func main() {
	var (
		proxyAddr = flag.String("proxy", "127.0.0.1:19080", "local SOCKS5 proxy address")
		echoAddr  = flag.String("echo", "127.0.0.1:19100", "target the proxy should reach")
		payload   = flag.String("payload", "porttransit-live-check", "payload to echo")
		raw       = flag.Bool("raw", false, "treat -proxy as a plain tunnel port instead of a SOCKS5 proxy")
		udp       = flag.Bool("udp", false, "use SOCKS5 UDP ASSOCIATE instead of CONNECT; the target must echo \"udp:\"+payload")
		reuse     = flag.Int("reuse", 1, "number of sequential connections through the proxy")
		noEcho    = flag.Bool("no-echo", false, "do not start a local echo target; something must already serve -echo")
	)
	flag.Parse()

	if *raw && *udp {
		fmt.Fprintln(os.Stderr, "FAIL: -raw and -udp are mutually exclusive")
		os.Exit(2)
	}

	if *udp {
		// A UDP test cannot start its own target either: the datagram has to
		// be answered by whatever is already listening on the target address,
		// and the relay's UDP tunnel is a connected socket, so the reply must
		// come from exactly that address.
		if err := runUDP(*proxyAddr, *echoAddr, *payload, *reuse); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("PASS: %d datagrams traversed the SOCKS5 UDP association and the relay unchanged\n", *reuse)
		return
	}

	for i := 0; i < *reuse; i++ {
		p := fmt.Sprintf("%s-%d", *payload, i)
		if err := run(*proxyAddr, *echoAddr, p, *raw, *noEcho); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
			os.Exit(1)
		}
	}
	switch {
	case *raw:
		fmt.Println("PASS: the payload traversed the fixed tunnel and the relay unchanged")
	case *reuse > 1:
		fmt.Printf("PASS: %d payloads traversed the proxy and the relay unchanged\n", *reuse)
	default:
		fmt.Println("PASS: the payload traversed the proxy and the relay unchanged")
	}
}

func run(proxyAddr, echoAddr, payload string, raw, noEcho bool) error {
	// 1. A real target to reach, unless one is already being served. The
	//    target echoes whatever it receives and counts connections, so a
	//    request that never arrives is distinguishable from one that arrives
	//    and is dropped.
	accepted := make(chan struct{}, 1)
	if !noEcho {
		ln, err := net.Listen("tcp", echoAddr)
		if err != nil {
			return fmt.Errorf("listen on the target %s: %w", echoAddr, err)
		}
		defer ln.Close()

		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				accepted <- struct{}{}
				go func(c net.Conn) {
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(20 * time.Second))
					_, _ = io.Copy(c, c)
				}(conn)
			}
		}()
	}

	// 2. Reach the target. Either through the local SOCKS5 proxy, exactly as a
	//    browser would, or through a fixed tunnel that needs no negotiation.
	var conn net.Conn
	if raw {
		// A fixed tunnel maps one local port to one target, so there is
		// nothing to negotiate: the payload starts immediately.
		var err error
		conn, err = net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			return fmt.Errorf("connect to the tunnel %s: %w", proxyAddr, err)
		}
	} else {
		var err error
		conn, err = socks5Connect(proxyAddr, echoAddr)
		if err != nil {
			return err
		}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	// 3. The payload must come back byte for byte.
	if _, err := conn.Write([]byte(payload)); err != nil {
		return fmt.Errorf("send the payload: %w", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return fmt.Errorf("read the echoed payload: %w", err)
	}
	if string(got) != payload {
		return fmt.Errorf("the payload came back as %q, want %q", got, payload)
	}

	if noEcho {
		return nil
	}
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("the target never accepted a connection")
	}
	return nil
}

// runUDP drives a SOCKS5 UDP ASSOCIATE session and checks that the datagrams
// come back with the target's marker prefix, which is what proves the reply
// arrived through the association rather than from a stale socket.
func runUDP(proxyAddr, targetAddr, payload string, rounds int) error {
	ctrl, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect to the proxy %s: %w", proxyAddr, err)
	}
	defer ctrl.Close()
	_ = ctrl.SetDeadline(time.Now().Add(30 * time.Second))

	// Greeting, then a UDP ASSOCIATE request whose address is the wildcard the
	// client expects from a browser (0.0.0.0:0).
	if _, err := ctrl.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fmt.Errorf("send the greeting: %w", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, sel); err != nil {
		return fmt.Errorf("read the method selection: %w", err)
	}
	if sel[0] != 0x05 || sel[1] != 0x00 {
		return fmt.Errorf("the proxy selected method 0x%02x, want no-auth", sel[1])
	}
	if _, err := ctrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return fmt.Errorf("send the UDP ASSOCIATE request: %w", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(ctrl, reply); err != nil {
		return fmt.Errorf("read the associate reply: %w", err)
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("the proxy refused the UDP association with code 0x%02x", reply[1])
	}
	relayAddr, err := readSocksAddr(ctrl, reply[3])
	if err != nil {
		return err
	}
	// A client that binds 0.0.0.0 reports the wildcard; the datagrams must go
	// to the proxy host on the port it named.
	host, _, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		return fmt.Errorf("split the proxy address: %w", err)
	}
	_, portStr, err := net.SplitHostPort(relayAddr)
	if err != nil {
		return fmt.Errorf("split the relay address %q: %w", relayAddr, err)
	}
	udpTarget := net.JoinHostPort(host, portStr)

	// The control connection must stay open for the whole association; the
	// client closes the socket when it goes away.
	pc, err := net.Dial("udp", udpTarget)
	if err != nil {
		return fmt.Errorf("dial the UDP relay %s: %w", udpTarget, err)
	}
	defer pc.Close()

	dest, err := encodeSocksAddr(targetAddr)
	if err != nil {
		return err
	}

	for i := 0; i < rounds; i++ {
		body := fmt.Sprintf("%s-%d", payload, i)
		// RSV(2) | FRAG(1) | address | payload
		pkt := append([]byte{0, 0, 0}, dest...)
		pkt = append(pkt, []byte(body)...)
		_ = pc.SetDeadline(time.Now().Add(15 * time.Second))
		if _, err := pc.Write(pkt); err != nil {
			return fmt.Errorf("send datagram %d: %w", i, err)
		}
		buf := make([]byte, 65535)
		n, err := pc.Read(buf)
		if err != nil {
			return fmt.Errorf("read the datagram reply %d: %w", i, err)
		}
		// Skip RSV/FRAG and the address the reply names.
		if n < 4 {
			return fmt.Errorf("the reply %d is too short: %d bytes", i, n)
		}
		_, consumed, err := decodeSocksAddr(buf[3:n])
		if err != nil {
			return fmt.Errorf("parse the reply address %d: %w", i, err)
		}
		got := string(buf[3+consumed : n])
		want := "udp:" + body
		if got != want {
			return fmt.Errorf("the reply %d came back as %q, want %q", i, got, want)
		}
	}
	return nil
}

func readSocksAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		b := make([]byte, 6)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", fmt.Errorf("read the IPv4 bound address: %w", err)
		}
		return net.JoinHostPort(net.IP(b[:4]).String(), fmt.Sprint(binary.BigEndian.Uint16(b[4:]))), nil
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", fmt.Errorf("read the bound host length: %w", err)
		}
		b := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", fmt.Errorf("read the bound host: %w", err)
		}
		return net.JoinHostPort(string(b[:l[0]]), fmt.Sprint(binary.BigEndian.Uint16(b[l[0]:]))), nil
	case 0x04:
		b := make([]byte, 18)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", fmt.Errorf("read the IPv6 bound address: %w", err)
		}
		return net.JoinHostPort(net.IP(b[:16]).String(), fmt.Sprint(binary.BigEndian.Uint16(b[16:]))), nil
	default:
		return "", fmt.Errorf("the reply names an unknown address type 0x%02x", atyp)
	}
}

// encodeSocksAddr renders a host:port as a SOCKS5 address field.
func encodeSocksAddr(hostPort string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("split the target address: %w", err)
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return nil, fmt.Errorf("resolve the target port: %w", err)
	}
	out := []byte{}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		out = append(out, 0x01)
		out = append(out, ip.To4()...)
	} else if ip := net.ParseIP(host); ip != nil {
		out = append(out, 0x04)
		out = append(out, ip.To16()...)
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("the target host name is too long")
		}
		out = append(out, 0x03, byte(len(host)))
		out = append(out, host...)
	}
	return binary.BigEndian.AppendUint16(out, uint16(port)), nil
}

// decodeSocksAddr parses an address field and returns the host:port plus how
// many bytes it consumed.
func decodeSocksAddr(b []byte) (string, int, error) {
	if len(b) < 1 {
		return "", 0, fmt.Errorf("the address field is empty")
	}
	switch b[0] {
	case 0x01:
		if len(b) < 6 {
			return "", 0, fmt.Errorf("the IPv4 address field is truncated")
		}
		return net.JoinHostPort(net.IP(b[1:5]).String(), fmt.Sprint(binary.BigEndian.Uint16(b[5:7]))), 7, nil
	case 0x03:
		if len(b) < 2 {
			return "", 0, fmt.Errorf("the domain address field is truncated")
		}
		l := int(b[1])
		if len(b) < 2+l+2 {
			return "", 0, fmt.Errorf("the domain address field is truncated")
		}
		return net.JoinHostPort(string(b[2:2+l]), fmt.Sprint(binary.BigEndian.Uint16(b[2+l:]))), 2 + l + 2, nil
	case 0x04:
		if len(b) < 18 {
			return "", 0, fmt.Errorf("the IPv6 address field is truncated")
		}
		return net.JoinHostPort(net.IP(b[1:17]).String(), fmt.Sprint(binary.BigEndian.Uint16(b[17:19]))), 19, nil
	default:
		return "", 0, fmt.Errorf("unknown address type 0x%02x", b[0])
	}
}

// socks5Connect performs a full SOCKS5 session and returns a connection to the
// target, positioned so the caller's next write goes straight to it.
func socks5Connect(proxyAddr, targetAddr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to the proxy %s: %w", proxyAddr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send the greeting: %w", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read the method selection: %w", err)
	}
	if sel[0] != 0x05 || sel[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("the proxy selected method 0x%02x, want no-auth", sel[1])
	}

	// VER | CMD(CONNECT) | RSV, then the address field, which already begins
	// with its own ATYP byte.
	addr, err := encodeSocksAddr(targetAddr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	req := append([]byte{0x05, 0x01, 0x00}, addr...)
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send the CONNECT request: %w", err)
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read the CONNECT reply: %w", err)
	}
	if reply[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("the proxy refused the connection with code 0x%02x", reply[1])
	}
	// Drain the bound address so the payload starts at the right offset.
	var skip int
	switch reply[3] {
	case 0x01:
		skip = 4
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			conn.Close()
			return nil, fmt.Errorf("read the bound host length: %w", err)
		}
		skip = int(l[0])
	case 0x04:
		skip = 16
	default:
		conn.Close()
		return nil, fmt.Errorf("the reply names an unknown address type 0x%02x", reply[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, skip+2)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read the bound address: %w", err)
	}
	return conn, nil
}
