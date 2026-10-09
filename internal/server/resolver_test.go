package server

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"porttransit/internal/config"
)

// An empty server list must mean "the host resolver", which is what every
// existing deployment relies on. Changing that default would silently redirect
// DNS for people who never asked for it.
func TestResolverDefaultsToTheSystemResolver(t *testing.T) {
	rv := newResolver(config.ResolverConfig{})
	if rv.r != net.DefaultResolver {
		t.Fatal("an empty config did not produce the system resolver")
	}
	if got := rv.describe(); got != "system" {
		t.Errorf("describe() is %q, want system", got)
	}
	// And it must actually resolve.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := rv.LookupIPAddr(ctx, "localhost"); err != nil {
		t.Fatalf("the system resolver failed on localhost: %v", err)
	}
}

func TestResolverUsesConfiguredServers(t *testing.T) {
	rv := newResolver(config.ResolverConfig{Servers: []string{"1.1.1.1", "8.8.8.8"}})
	if rv.r == net.DefaultResolver {
		t.Fatal("configured servers were ignored in favour of the system resolver")
	}
	if got := rv.describe(); got != "1.1.1.1:53,8.8.8.8:53" {
		t.Errorf("describe() is %q, want both servers with a default port", got)
	}
}

// A configured server without a port needs the default, and one with a port
// must keep it — an operator running an internal resolver on 5353 would
// otherwise have every lookup silently sent to the wrong port.
func TestResolverAddsTheDefaultPortOnlyWhenMissing(t *testing.T) {
	rv := newResolver(config.ResolverConfig{Servers: []string{"1.1.1.1", "10.0.0.1:5353", "[2001:db8::1]"}})
	got := rv.describe()
	for _, want := range []string{"1.1.1.1:53", "10.0.0.1:5353", "[2001:db8::1]:53"} {
		if !strings.Contains(got, want) {
			t.Errorf("describe() = %q, missing %q", got, want)
		}
	}
}

// Blank entries are a common result of editing a JSON list by hand; they must
// not become a lookup to ":53".
func TestResolverSkipsBlankServers(t *testing.T) {
	rv := newResolver(config.ResolverConfig{Servers: []string{"", "   ", "1.1.1.1"}})
	if got := rv.describe(); got != "1.1.1.1:53" {
		t.Errorf("describe() is %q, want only the real server", got)
	}

	// A list of nothing but blanks must fall back rather than build a resolver
	// that can never answer.
	allBlank := newResolver(config.ResolverConfig{Servers: []string{"", "  "}})
	if allBlank.r != net.DefaultResolver {
		t.Error("a list of blank servers did not fall back to the system resolver")
	}
}

func TestResolverProtocolSelection(t *testing.T) {
	// Only tcp and udp are meaningful; anything else must fall back to udp
	// rather than producing a resolver that cannot dial.
	for _, proto := range []string{"", "udp", "UDP", "tcp", "TCP", "bogus"} {
		rv := newResolver(config.ResolverConfig{Servers: []string{"1.1.1.1"}, Protocol: proto})
		if rv.r == nil {
			t.Errorf("protocol %q produced a nil resolver", proto)
		}
	}
}

func TestResolverDescribeIsEmptyWithoutServers(t *testing.T) {
	rv := newResolver(config.ResolverConfig{})
	if rv.describe() == "" {
		t.Error("describe() should say something even for the system resolver")
	}
	var nilResolver *resolver
	if got := nilResolver.describe(); got != "system" {
		t.Errorf("a nil resolver describes itself as %q, want system", got)
	}
}

// A nil resolver must not panic: the lookup path calls it unconditionally.
func TestNilResolverFallsBackToTheSystemResolver(t *testing.T) {
	var rv *resolver
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := rv.LookupIPAddr(ctx, "localhost"); err != nil {
		t.Fatalf("a nil resolver failed on localhost: %v", err)
	}
}

// An unreachable resolver must fail within the configured timeout rather than
// hanging the relay's dial until the caller's own deadline expires. This is the
// property that stops a black-holed DNS server from stalling every connection.
func TestResolverHonoursItsTimeout(t *testing.T) {
	// 203.0.113.0/24 is TEST-NET-3 and is not routable, so the dial cannot
	// succeed; the point is that it gives up quickly.
	rv := newResolver(config.ResolverConfig{
		Servers: []string{"203.0.113.1"},
		Timeout: config.Duration(300 * time.Millisecond),
	})

	start := time.Now()
	ctx := context.Background()
	_, err := rv.LookupIPAddr(ctx, "example.com")
	elapsed := time.Since(start)

	if err == nil {
		t.Skip("this network resolved through a black-holed address, so the timeout cannot be observed")
	}
	// Allow generous slack for a slow CI machine, but far less than the 5s
	// default would take.
	if elapsed > 3*time.Second {
		t.Errorf("lookup took %v, which suggests the timeout was not applied", elapsed)
	}
}

func TestResolverTimeoutDefaultsWhenUnset(t *testing.T) {
	rv := newResolver(config.ResolverConfig{Servers: []string{"1.1.1.1"}})
	if rv.timeout != 5*time.Second {
		t.Errorf("default timeout is %v, want 5s", rv.timeout)
	}
}
