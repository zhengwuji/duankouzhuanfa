package webui

import (
	"net"
	"time"
)

// dialTimeout is a small helper so the console can test reachability without
// pulling in a heavier dialer.
func dialTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return net.DialTimeout("tcp", addr, timeout)
}
