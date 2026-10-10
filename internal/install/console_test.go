package install

import (
	"strings"
	"testing"
)

// The console URL is what an operator pastes into a browser, so a wildcard
// bind must not be reported literally: "http://0.0.0.0:8787" names no host and
// cannot be opened. That was what the one-click installer printed.

func TestConsoleURLRewritesWildcardBinds(t *testing.T) {
	// Stubbed so the test does not depend on an external service: a build must
	// not go red because ipify is unreachable.
	origPublic := PublicIP
	defer func() { PublicIP = origPublic }()
	PublicIP = func() string { return "203.0.113.7" }

	for _, listen := range []string{"0.0.0.0:8787", ":8787", "[::]:8787"} {
		got := ConsoleURL(listen, false)
		if strings.Contains(got, "0.0.0.0") || strings.Contains(got, "[::]") {
			t.Errorf("ConsoleURL(%q) = %q, which is not a browsable address", listen, got)
		}
		if !strings.HasPrefix(got, "http://") {
			t.Errorf("ConsoleURL(%q) = %q, want an http URL", listen, got)
		}
	}
}

func TestConsoleURLKeepsAnExplicitHost(t *testing.T) {
	// An explicit address is what the operator asked for and must survive
	// unchanged — rewriting it would hide a deliberate public bind.
	if got := ConsoleURL("127.0.0.1:8787", false); got != "http://127.0.0.1:8787" {
		t.Errorf("ConsoleURL = %q, want http://127.0.0.1:8787", got)
	}
	if got := ConsoleURL("10.1.2.3:8787", false); got != "http://10.1.2.3:8787" {
		t.Errorf("ConsoleURL = %q, want http://10.1.2.3:8787", got)
	}
	if got := ConsoleURL("relay.example.com:8787", false); got != "http://relay.example.com:8787" {
		t.Errorf("ConsoleURL = %q, want http://relay.example.com:8787", got)
	}
}

func TestConsoleURLHonoursTLS(t *testing.T) {
	// Reporting http for a TLS console sends the operator to a port that will
	// not answer, and reporting https for a plain one breaks the page.
	if got := ConsoleURL("127.0.0.1:8787", true); got != "https://127.0.0.1:8787" {
		t.Errorf("ConsoleURL with TLS = %q, want https://127.0.0.1:8787", got)
	}
}

func TestConsoleURLSurvivesAGarbageAddress(t *testing.T) {
	// A unix socket or a malformed value must not panic; it is reported as-is.
	if got := ConsoleURL("/run/porttransit.sock", false); got != "http:///run/porttransit.sock" {
		t.Errorf("ConsoleURL(unix socket) = %q", got)
	}
}

func TestOutboundIPIsEitherUsableOrEmpty(t *testing.T) { // The helper must never invent an address: an empty result makes
	// ConsoleURL fall back to loopback, while a wrong one would send the
	// operator to a host that is not this machine.
	ip := OutboundIP()
	if ip == "" {
		t.Skip("no outbound route on this host; the loopback fallback is covered above")
	}
	if strings.Contains(ip, ":") {
		// An IPv6 address must still be a bare address, not bracketed, so
		// JoinHostPort can add the brackets once.
		if strings.Contains(ip, "[") || strings.Contains(ip, "]") {
			t.Errorf("OutboundIP = %q, want an unbracketed address", ip)
		}
	}
}

// TestConsoleURLPrefersAPublicAddressBehindNAT pins the bug that a live host
// exposed: the interface address is private (10.1.2.3 on a NAT'd cloud
// instance), so substituting it for a wildcard bind produced a URL no browser
// outside the LAN could open — the same failure as printing 0.0.0.0.
func TestConsoleURLPrefersAPublicAddressBehindNAT(t *testing.T) {
	origPublic := PublicIP
	defer func() { PublicIP = origPublic }()
	PublicIP = func() string { return "203.0.113.7" }

	got := ConsoleURL("0.0.0.0:8787", false)
	if !strings.Contains(got, "203.0.113.7") {
		t.Errorf("ConsoleURL behind NAT = %q, want the public address 203.0.113.7", got)
	}
}

// TestConsoleURLFallsBackToTheLocalAddressWhenNATIsUnknown covers the host that
// cannot reach an external service: a private address is still correct for an
// operator on the same network, so it is reported rather than dropped.
func TestConsoleURLFallsBackToTheLocalAddressWhenNATIsUnknown(t *testing.T) {
	origPublic := PublicIP
	defer func() { PublicIP = origPublic }()
	PublicIP = func() string { return "" }

	// 10.1.2.3 is private, so the public lookup is what is being exercised.
	got := ConsoleURL("10.1.2.3:8787", false)
	if got != "http://10.1.2.3:8787" {
		t.Errorf("ConsoleURL with an explicit private host = %q, want it kept as-is", got)
	}
}

func TestIsPrivateIP(t *testing.T) {
	private := []string{
		"10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.1.1",
		"100.64.0.1", "169.254.1.1", "127.0.0.1", "::1", "fc00::1", "fe80::1",
	}
	for _, s := range private {
		if !isPrivateIP(s) {
			t.Errorf("isPrivateIP(%q) = false, want true", s)
		}
	}
	// RFC 5737 documentation ranges rather than any real host, so a
	// deployment's addresses never end up in the repository.
	public := []string{"8.8.8.8", "1.1.1.1", "203.0.113.7", "198.51.100.4", "192.0.2.10"}
	for _, s := range public {
		if isPrivateIP(s) {
			t.Errorf("isPrivateIP(%q) = true, want false", s)
		}
	}
}
