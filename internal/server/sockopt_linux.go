//go:build linux

package server

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"porttransit/internal/config"
)

// listenTCP binds a TCP listener honouring the listener's socket options.
//
// The options are applied through ListenConfig.Control rather than by setting
// them after the bind because TCP_FASTOPEN must be in place *before* the socket
// starts listening: setting it on an already-listening socket is accepted by
// the kernel but has no effect, which is a silent failure that looks like the
// option simply not helping.
func listenTCP(ctx context.Context, lc config.Listener) (net.Listener, error) {
	cfg := net.ListenConfig{}

	// MPTCP lets a single connection use several paths when both ends and the
	// network support it. Go keeps it off by default because it changes the
	// socket family, so an operator has to ask for it explicitly.
	cfg.SetMultipathTCP(lc.MPTCP)

	if lc.TCPFastOpen {
		cfg.Control = func(network, address string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				// 5 is a conservative queue depth for pending TFO data. The
				// kernel caps it at net.ipv4.tcp_max_syn_backlog, so a larger
				// value would be silently reduced anyway.
				sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN, 5)
			}); err != nil {
				return err
			}
			// A kernel without TFO support must not fail the bind: the relay
			// works fine without it, and refusing to start over an
			// optimisation is a bad trade.
			if sockErr != nil && !errors.Is(sockErr, unix.ENOPROTOOPT) && !errors.Is(sockErr, unix.EOPNOTSUPP) {
				return sockErr
			}
			return nil
		}
	}

	return cfg.Listen(ctx, "tcp", lc.Listen)
}

// dialerFor builds a net.Dialer honouring the listener's socket preferences.
//
// MPTCP is taken from the listener rather than the relay as a whole because it
// is a property of the path being used: an operator may want it on the link to
// one upstream and not another.
func dialerFor(lc config.Listener, timeout time.Duration) net.Dialer {
	d := net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	d.SetMultipathTCP(lc.MPTCP)
	return d
}

// socketOptionsSupported reports whether this build honours the listener's
// TCP-level options, so the caller can say so once at startup instead of
// leaving an operator wondering why enabling them changed nothing.
const socketOptionsSupported = true
