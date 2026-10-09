// Command livetest drives a real end-to-end check against a running relay and
// client using only public interfaces: it starts a TCP echo target, then
// connects through the client's local SOCKS5 proxy and verifies the bytes come
// back.
//
// It exists because the unit and e2e suites build the relay and client in
// process, so nothing else proves that two separately launched binaries
// interoperate over real sockets with a real configuration file.
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
	)
	flag.Parse()

	if err := run(*proxyAddr, *echoAddr, *payload, *raw); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	if *raw {
		fmt.Println("PASS: the payload traversed the fixed tunnel and the relay unchanged")
	} else {
		fmt.Println("PASS: the payload traversed the proxy and the relay unchanged")
	}
}

func run(proxyAddr, echoAddr, payload string, raw bool) error {
	// 1. A real target to reach. It echoes whatever it receives and counts
	//    connections, so a request that never arrives is distinguishable from
	//    one that arrives and is dropped.
	ln, err := net.Listen("tcp", echoAddr)
	if err != nil {
		return fmt.Errorf("listen on the target %s: %w", echoAddr, err)
	}
	defer ln.Close()

	accepted := make(chan struct{}, 1)
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

	// 2. Reach the target. Either through the local SOCKS5 proxy, exactly as a
	//    browser would, or through a fixed tunnel that needs no negotiation.
	var conn net.Conn
	if raw {
		// A fixed tunnel maps one local port to one target, so there is nothing
		// to negotiate: the payload starts immediately.
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

	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("the target never accepted a connection")
	}
	return nil
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

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("split the target address: %w", err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("resolve the target port: %w", err)
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append(req, 0x01)
		req = append(req, ip.To4()...)
	} else {
		if len(host) > 255 {
			conn.Close()
			return nil, fmt.Errorf("the target host name is too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
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
