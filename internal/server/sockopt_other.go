//go:build !linux

package server

import (
	"context"
	"net"
	"time"

	"porttransit/internal/config"
)

// listenTCP on a non-Linux host ignores the socket options.
//
// TCP_FASTOPEN and MPTCP are Linux facilities; the fields exist in the config
// so a configuration written on Linux still loads elsewhere, and the relay
// serves normally without them. Silently ignoring them is the right behaviour
// because refusing to start would make a shared config file unusable, but the
// caller logs the difference so it is not a mystery.
func listenTCP(ctx context.Context, lc config.Listener) (net.Listener, error) {
	var cfg net.ListenConfig
	return cfg.Listen(ctx, "tcp", lc.Listen)
}

// dialerFor builds a net.Dialer with the relay's timeout.
func dialerFor(lc config.Listener, timeout time.Duration) net.Dialer {
	return net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
}

// socketOptionsSupported reports whether this build honours the listener's
// TCP-level options, so the caller can say so once at startup.
const socketOptionsSupported = false
