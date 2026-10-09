package server

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"porttransit/internal/config"
	"porttransit/internal/transport"
)

// ErrDestinationDenied reports a destination the relay's policy refuses.
var ErrDestinationDenied = errors.New("server: destination denied by ACL")

// ACL is the relay's destination policy.
//
// It exists because an authenticated relay is still an open proxy to anyone
// who holds a credential, and the most damaging outcome of a compromised
// credential is not the traffic itself but the ability to reach the relay
// host's own private network — its cloud metadata service, its internal
// databases, its management plane. Blocking non-routable destinations by
// default closes that path without requiring the operator to think about it.
type ACL struct {
	allow        []string
	deny         []string
	blockPrivate bool
	blockPorts   map[int]bool
	allowPorts   map[int]bool
}

// NewACL compiles a configuration into an evaluable policy.
func NewACL(cfg config.ACLConfig) (*ACL, error) {
	a := &ACL{
		allow: cfg.Allow,
		deny:  cfg.Deny,
		// Default to blocking private destinations: an operator who wants to
		// reach an internal service can opt out explicitly, but an operator
		// who never considered the question gets the safe answer.
		blockPrivate: cfg.BlockPrivate == nil || *cfg.BlockPrivate,
	}
	if cfg.BlockPrivate != nil {
		a.blockPrivate = *cfg.BlockPrivate
	}

	for _, p := range cfg.BlockPorts {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("server: blockPorts contains %d, which is not a port", p)
		}
		if a.blockPorts == nil {
			a.blockPorts = map[int]bool{}
		}
		a.blockPorts[p] = true
	}
	for _, p := range cfg.AllowPorts {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("server: allowPorts contains %d, which is not a port", p)
		}
		if a.allowPorts == nil {
			a.allowPorts = map[int]bool{}
		}
		a.allowPorts[p] = true
	}
	return a, nil
}

// Check decides whether target may be dialed on behalf of a client.
//
// Evaluation order is deny-first, then the per-client policy, then the global
// allow-list. Deny winning over allow is the only ordering that makes a
// block-list trustworthy: an operator adding a deny entry expects it to take
// effect even if a broad allow rule already matches.
func (a *ACL) Check(target string, client *config.ClientAccount) error {
	host, portStr, err := transport.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := parsePort(portStr)
	if err != nil {
		return err
	}

	// Per-client deny wins over everything, including a global allow.
	if client != nil {
		for _, pattern := range client.DeniedTargets {
			if matchTarget(pattern, target, host) {
				return fmt.Errorf("%w: %s is denied for client %s", ErrDestinationDenied, target, client.ID)
			}
		}
	}

	if a.blockPorts[port] {
		return fmt.Errorf("%w: port %d is blocked", ErrDestinationDenied, port)
	}
	if len(a.allowPorts) > 0 && !a.allowPorts[port] {
		return fmt.Errorf("%w: port %d is not in the allowed port set", ErrDestinationDenied, port)
	}

	for _, pattern := range a.deny {
		if matchTarget(pattern, target, host) {
			return fmt.Errorf("%w: %s matches deny rule %q", ErrDestinationDenied, target, pattern)
		}
	}

	// A client allow-list narrows the global policy rather than replacing it,
	// so an operator can grant a client a subset of what the relay permits.
	if client != nil && len(client.AllowedTargets) > 0 {
		ok := false
		for _, pattern := range client.AllowedTargets {
			if matchTarget(pattern, target, host) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%w: %s is not in client %s's allowedTargets", ErrDestinationDenied, target, client.ID)
		}
	}

	if len(a.allow) > 0 {
		ok := false
		for _, pattern := range a.allow {
			if matchTarget(pattern, target, host) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%w: %s is not in the allow list", ErrDestinationDenied, target)
		}
	}

	if a.blockPrivate && isPrivateDestination(host) {
		return fmt.Errorf("%w: %s resolves into a non-routable range", ErrDestinationDenied, target)
	}
	return nil
}

// isPrivateDestination reports whether a destination must not be reachable
// through the relay.
//
// The check is by literal address only: a domain that resolves to a private
// address is caught at dial time by the same check applied to the resolved IP
// (see CheckResolved), because resolving here would add a DNS lookup to every
// request and would itself be an SSRF vector against the relay's resolver.
func isPrivateDestination(host string) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		// A domain name is allowed; CheckResolved re-checks after resolution.
		return false
	}
	return isNonRoutableIP(ip)
}

// CheckResolved re-applies the private-address rule to an address that a
// domain name resolved to, closing the DNS-rebinding path where a public name
// points at 127.0.0.1 or 169.254.169.254.
func (a *ACL) CheckResolved(target string, ip net.IP) error {
	if a == nil || !a.blockPrivate || ip == nil {
		return nil
	}
	if isNonRoutableIP(ip) {
		return fmt.Errorf("%w: %s resolved to the non-routable address %s", ErrDestinationDenied, target, ip)
	}
	return nil
}

// isNonRoutableIP reports whether an address is one a relay must never be
// able to reach on a client's behalf.
func isNonRoutableIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsUnspecified() ||
		// 100.64.0.0/10 is carrier-grade NAT: reaching it from a relay would
		// land inside the hosting provider's internal network.
		isCGNAT(ip) ||
		// 169.254.169.254 is the cloud metadata endpoint on every major
		// provider. It is link-local and already covered, but it is listed
		// explicitly because it is the single most valuable SSRF target.
		ip.Equal(net.IPv4(169, 254, 169, 254)) ||
		// 192.0.0.0/24, 198.18.0.0/15 (benchmarking) and 240.0.0.0/4
		// (reserved) are not routable on the public internet.
		isReservedV4(ip)
}

func isCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127
}

func isReservedV4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	switch {
	case v4[0] == 192 && v4[1] == 0 && v4[2] == 0:
		return true
	case v4[0] == 198 && (v4[1] == 18 || v4[1] == 19):
		return true
	case v4[0] >= 240:
		return true
	}
	return false
}

func parsePort(s string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n); err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("server: %q is not a valid port", s)
	}
	return n, nil
}
