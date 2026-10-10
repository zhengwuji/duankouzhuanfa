// Command echotarget is a TCP and UDP echo server used to verify a real,
// cross-host PortTransit deployment.
//
// It exists because the livetest binary starts its echo target on the *client*
// host, while a relay dials the target from the *relay* host. A genuine
// cross-border test therefore needs the target to live next to the relay, and
// needs to be able to say how many connections actually arrived — a request
// that never arrives must be distinguishable from one that arrives and is
// dropped.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:19100", "TCP address to listen on")
	udpListen := flag.String("udp", "0.0.0.0:19100", "UDP address to listen on (empty to disable)")
	flag.Parse()

	var accepted, active, udpPackets atomic.Int64

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()
	fmt.Printf("echo target tcp on %s (pid %d)\n", ln.Addr(), os.Getpid())

	if *udpListen != "" {
		pc, err := net.ListenPacket("udp", *udpListen)
		if err != nil {
			log.Fatalf("listen udp: %v", err)
		}
		defer pc.Close()
		fmt.Printf("echo target udp on %s\n", pc.LocalAddr())
		go func() {
			buf := make([]byte, 65535)
			for {
				n, addr, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				udpPackets.Add(1)
				// Echo the payload back with a marker so a reply can be told
				// apart from an unrelated datagram arriving on the same port.
				reply := append([]byte("udp:"), buf[:n]...)
				_, _ = pc.WriteTo(reply, addr)
			}
		}()
	}

	go func() {
		for range time.Tick(5 * time.Second) {
			fmt.Printf("stats accepted=%d active=%d udpPackets=%d\n",
				accepted.Load(), active.Load(), udpPackets.Load())
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted.Add(1)
		active.Add(1)
		go func(c net.Conn) {
			defer func() { active.Add(-1); c.Close() }()
			_ = c.SetDeadline(time.Now().Add(120 * time.Second))
			_, _ = io.Copy(c, c)
		}(conn)
	}
}
