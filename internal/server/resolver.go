package server

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"porttransit/internal/config"
)

// resolver wraps DNS lookups for the relay's outbound dials.
//
// A relay has two reasons to resolve differently from the host it runs on.
// First, the host's resolver may be slow or poisoned, and the relay's whole
// value is a faster path to the destination. Second, the destination names are
// chosen by a remote client, so a hostile or compromised host resolver is a
// direct attack surface — pointing the relay at a trusted resolver is a
// meaningful hardening step.
//
// An empty Servers list means "use the host's resolver", which is the default
// and the behaviour every existing deployment already has.
type resolver struct {
	r       *net.Resolver
	timeout time.Duration
	// servers is kept for logging, so an operator can confirm which resolver is
	// in use rather than inferring it.
	servers []string
}

// newResolver builds the relay's resolver from configuration.
func newResolver(cfg config.ResolverConfig) *resolver {
	timeout := cfg.Timeout.Or(5 * time.Second)
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	if len(cfg.Servers) == 0 {
		// The host resolver, with the configured timeout applied by callers.
		return &resolver{r: net.DefaultResolver, timeout: timeout}
	}

	network := strings.ToLower(strings.TrimSpace(cfg.Protocol))
	if network != "tcp" && network != "udp" {
		// "udp" is the right default: a TCP fallback exists in the protocol
		// itself, and forcing TCP would add a round trip to every lookup.
		network = "udp"
	}

	servers := make([]string, 0, len(cfg.Servers))
	for _, s := range cfg.Servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// A bare address has no port; DNS is conventionally on 53.
		if _, _, err := net.SplitHostPort(s); err != nil {
			// An operator writing an IPv6 resolver is likely to bracket it out
			// of habit, as they would in a URL. JoinHostPort would then add a
			// second pair and produce "[[2001:db8::1]]:53", which dials
			// nothing — so the brackets are stripped before joining.
			host := strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
			s = net.JoinHostPort(host, "53")
		}
		servers = append(servers, s)
	}
	if len(servers) == 0 {
		return &resolver{r: net.DefaultResolver, timeout: timeout}
	}

	// A fresh Dialer per lookup, with the configured timeout: the default
	// resolver dialer has no timeout of its own, so a black-holed DNS server
	// would hang the relay's dial until the whole context expired.
	d := &net.Dialer{Timeout: timeout}

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			// Try each configured server in order, so a single dead resolver
			// degrades to the next rather than failing the lookup.
			var lastErr error
			for _, srv := range servers {
				conn, err := d.DialContext(ctx, network, srv)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, fmt.Errorf("server: no configured DNS server reachable: %w", lastErr)
		},
	}
	return &resolver{r: r, timeout: timeout, servers: servers}
}

// LookupIPAddr resolves host to addresses.
func (rv *resolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if rv == nil || rv.r == nil {
		return net.DefaultResolver.LookupIPAddr(ctx, host)
	}
	if rv.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, rv.timeout)
		defer cancel()
	}
	return rv.r.LookupIPAddr(ctx, host)
}

// describe renders the effective resolver for the log.
func (rv *resolver) describe() string {
	if rv == nil || len(rv.servers) == 0 {
		return "system"
	}
	return strings.Join(rv.servers, ",")
}
