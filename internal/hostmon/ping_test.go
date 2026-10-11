package hostmon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// The outbound probe reports a number and the method that produced it. These
// tests pin the folding rules, because the failure mode here is not a crash: it
// is a card that presents a TCP handshake as an ICMP round trip, or averages two
// different measurements into one figure that means nothing.

// TestAggregatePingWeightsByReceivedProbes proves a target that answered once
// does not carry the same weight as one that answered every time. An unweighted
// mean over targets would let a nearly unreachable host pull the average as
// hard as a healthy one.
func TestAggregatePingWeightsByReceivedProbes(t *testing.T) {
	info := aggregatePing([]PingTarget{
		// Answered every probe, and slowly.
		{Address: "a", Method: MethodICMP, Sent: 3, Recv: 3, AvgMs: 300, MinMs: 290, MaxMs: 310},
		// Answered once out of three, and quickly.
		{Address: "b", Method: MethodICMP, Sent: 3, Recv: 1, AvgMs: 10, MinMs: 10, MaxMs: 10},
	})

	// (300*3 + 10*1) / 4 = 227.5, not (300+10)/2 = 155.
	if info.AvgMs != 227.5 {
		t.Errorf("AvgMs = %v, want 227.5: the average must be weighted by how many "+
			"probes each target actually answered", info.AvgMs)
	}
	if info.MinMs != 10 {
		t.Errorf("MinMs = %v, want 10 (the fastest single reading)", info.MinMs)
	}
	if info.MaxMs != 310 {
		t.Errorf("MaxMs = %v, want 310", info.MaxMs)
	}
	if info.LossPct != 33.3 {
		t.Errorf("LossPct = %v, want 33.3 (2 lost of 6 sent)", info.LossPct)
	}
}

// TestAggregatePingReportsMixedMethods covers the case that would otherwise
// produce a meaningless figure: one target measured by ICMP and another by TCP.
// Their round-trip times are not comparable, so the aggregate must say so
// instead of silently presenting an average of two different measurements.
func TestAggregatePingReportsMixedMethods(t *testing.T) {
	info := aggregatePing([]PingTarget{
		{Address: "a", Method: MethodICMP, Sent: 1, Recv: 1, AvgMs: 10, MinMs: 10, MaxMs: 10},
		{Address: "b", Method: MethodTCP, Sent: 1, Recv: 1, AvgMs: 20, MinMs: 20, MaxMs: 20},
	})

	if info.Method != MethodMixed {
		t.Errorf("Method = %q, want %q: an ICMP round trip and a TCP handshake are "+
			"not the same measurement and must not be averaged as if they were",
			info.Method, MethodMixed)
	}
}

// TestAggregatePingKeepsAUniformMethod proves the method is reported plainly
// when every target was measured the same way.
func TestAggregatePingKeepsAUniformMethod(t *testing.T) {
	for _, method := range []string{MethodICMP, MethodTCP} {
		info := aggregatePing([]PingTarget{
			{Address: "a", Method: method, Sent: 1, Recv: 1, AvgMs: 10, MinMs: 10, MaxMs: 10},
			{Address: "b", Method: method, Sent: 1, Recv: 1, AvgMs: 20, MinMs: 20, MaxMs: 20},
		})
		if info.Method != method {
			t.Errorf("Method = %q, want %q", info.Method, method)
		}
	}
}

// TestAggregatePingWithoutAnswers covers a host that reaches nothing. There is
// no method to report and no latency, and reporting 0 ms would read as a perfect
// network rather than as a total outage.
func TestAggregatePingWithoutAnswers(t *testing.T) {
	info := aggregatePing([]PingTarget{
		{Address: "a", Method: MethodICMP, Sent: 3, Recv: 0, Error: "i/o timeout"},
		{Address: "b", Method: MethodICMP, Sent: 3, Recv: 0, Error: "network is unreachable"},
	})

	if info.Method != "" {
		t.Errorf("Method = %q with nothing answered, want it empty", info.Method)
	}
	if info.AvgMs != 0 || info.MinMs != 0 || info.MaxMs != 0 {
		t.Errorf("latency = %v/%v/%v with nothing answered, want zeroes",
			info.MinMs, info.AvgMs, info.MaxMs)
	}
	if info.LossPct != 100 {
		t.Errorf("LossPct = %v, want 100", info.LossPct)
	}
	if info.Error == "" {
		t.Error("no error was carried up from the targets, so the card cannot say why")
	}
	if !info.Enabled {
		t.Error("Enabled = false on a round that ran")
	}
	if info.LastAt.IsZero() {
		t.Error("LastAt was not stamped")
	}
}

// TestSplitTarget covers the shapes an operator can put in the configuration:
// a bare host, a host with a port, and a bare IPv6 literal — which must not be
// split at its own colons.
func TestSplitTarget(t *testing.T) {
	cases := []struct{ in, host, port string }{
		{"1.1.1.1", "1.1.1.1", defaultPort},
		{"1.1.1.1:443", "1.1.1.1", "443"},
		{"example.com:8443", "example.com", "8443"},
		{"example.com", "example.com", defaultPort},
		{"::1", "::1", defaultPort},
		{"[2606:4700:4700::1111]:443", "2606:4700:4700::1111", "443"},
	}
	for _, c := range cases {
		host, port := splitTarget(c.in)
		if host != c.host || port != c.port {
			t.Errorf("splitTarget(%q) = (%q, %q), want (%q, %q)", c.in, host, port, c.host, c.port)
		}
	}
}

// TestLossPct covers the arithmetic and its degenerate input. A round with no
// probes sent is 0% lost, not a division by zero.
func TestLossPct(t *testing.T) {
	cases := []struct {
		sent, recv int
		want       float64
	}{
		{3, 3, 0},
		{3, 0, 100},
		{4, 1, 75},
		{3, 2, 33.3},
		{0, 0, 0},
		// A target cannot answer more probes than were sent, but a rounding or
		// accounting slip must not produce a negative loss figure.
		{1, 2, 0},
	}
	for _, c := range cases {
		if got := lossPct(c.sent, c.recv); got != c.want {
			t.Errorf("lossPct(%d, %d) = %v, want %v", c.sent, c.recv, got, c.want)
		}
	}
}

// TestLatStats covers the summary of one target's samples.
func TestLatStats(t *testing.T) {
	min, max, avg := latStats([]float64{30, 10, 20})
	if min != 10 || max != 30 || avg != 20 {
		t.Errorf("latStats = %v/%v/%v, want 10/30/20", min, max, avg)
	}
}

// TestProberRecordsTheMethodThatProducedTheNumber is the regression test for a
// card that claimed an ICMP round trip when the ICMP probe had been refused and
// the number had actually come from a TCP handshake.
//
// The two probes are injected rather than reached over the network: the point
// under test is which method gets recorded, and a real probe would depend on
// whether the machine running the test has CAP_NET_RAW and on how its network
// treats echo requests.
func TestProberRecordsTheMethodThatProducedTheNumber(t *testing.T) {
	refused := errors.New("socket: operation not permitted")

	t.Run("ICMP answers", func(t *testing.T) {
		p := prober{
			icmp: func(context.Context, string, int, time.Duration) ([]float64, error) {
				return []float64{10, 12, 11}, nil
			},
			tcp: func(context.Context, string, int, time.Duration) ([]float64, error) {
				t.Fatal("the TCP probe ran even though ICMP answered")
				return nil, nil
			},
		}
		got := p.probe(t.Context(), "1.1.1.1:443", 3, time.Second)
		if got.Method != MethodICMP {
			t.Errorf("Method = %q, want %q", got.Method, MethodICMP)
		}
		if got.Recv != 3 || got.LossPct != 0 {
			t.Errorf("Recv/LossPct = %d/%v, want 3/0", got.Recv, got.LossPct)
		}
		if got.MinMs != 10 || got.MaxMs != 12 || got.AvgMs != 11 {
			t.Errorf("latency = %v/%v/%v, want 10/12/11", got.MinMs, got.MaxMs, got.AvgMs)
		}
	})

	t.Run("ICMP refused, TCP answers", func(t *testing.T) {
		p := prober{
			icmp: func(context.Context, string, int, time.Duration) ([]float64, error) {
				return nil, refused
			},
			tcp: func(context.Context, string, int, time.Duration) ([]float64, error) {
				return []float64{40, 42, 41}, nil
			},
		}
		got := p.probe(t.Context(), "1.1.1.1:443", 3, time.Second)
		if got.Method != MethodTCP {
			t.Errorf("Method = %q, want %q: the numbers came from the handshake, so "+
				"reporting an ICMP round trip would present a different measurement "+
				"as this one", got.Method, MethodTCP)
		}
		if got.AvgMs != 41 {
			t.Errorf("AvgMs = %v, want 41", got.AvgMs)
		}
		if got.Error != "" {
			t.Errorf("Error = %q on a successful round", got.Error)
		}
	})

	t.Run("neither answers", func(t *testing.T) {
		timeout := errors.New("i/o timeout")
		p := prober{
			icmp: func(context.Context, string, int, time.Duration) ([]float64, error) {
				return nil, refused
			},
			tcp: func(context.Context, string, int, time.Duration) ([]float64, error) {
				return nil, timeout
			},
		}
		got := p.probe(t.Context(), "1.1.1.1:443", 3, time.Second)
		if got.Recv != 0 || got.LossPct != 100 {
			t.Errorf("Recv/LossPct = %d/%v, want 0/100", got.Recv, got.LossPct)
		}
		if got.AvgMs != 0 || got.MinMs != 0 || got.MaxMs != 0 {
			t.Errorf("latency = %v/%v/%v with nothing received, want zeroes: a zero "+
				"presented as a measurement reads as a perfect network",
				got.MinMs, got.AvgMs, got.MaxMs)
		}
		// Both failures are reported, because they say different things. A
		// refused ICMP socket means the probe was never allowed to run, which
		// is not evidence about the target; the handshake timing out is. Keeping
		// only the first would send an operator to look at their network when
		// the real problem is a missing capability.
		for _, want := range []string{refused.Error(), timeout.Error()} {
			if !strings.Contains(got.Error, want) {
				t.Errorf("Error = %q, want it to mention %q", got.Error, want)
			}
		}
	})

	t.Run("empty target", func(t *testing.T) {
		p := prober{
			icmp: func(context.Context, string, int, time.Duration) ([]float64, error) {
				t.Fatal("an empty target was probed")
				return nil, nil
			},
			tcp: func(context.Context, string, int, time.Duration) ([]float64, error) {
				t.Fatal("an empty target was probed")
				return nil, nil
			},
		}
		// Whitespace, not "", is what a blank configuration line actually
		// reaches the prober as.
		got := p.probe(t.Context(), "   ", 1, time.Second)
		if got.Error == "" {
			t.Error("an empty target produced no error")
		}
	})
}

// TestJoinErrors covers the failure report shown on the card.
func TestJoinErrors(t *testing.T) {
	a := errors.New("operation not permitted")
	b := errors.New("i/o timeout")

	if got := joinErrors(nil, nil); got != "" {
		t.Errorf("joinErrors(nil, nil) = %q, want empty", got)
	}
	if got := joinErrors(a, nil); got != a.Error() {
		t.Errorf("joinErrors(a, nil) = %q, want %q", got, a.Error())
	}
	if got := joinErrors(nil, b); got != b.Error() {
		t.Errorf("joinErrors(nil, b) = %q, want %q", got, b.Error())
	}
	// The same failure from both probes is one fact, not two.
	if got := joinErrors(a, errors.New(a.Error())); got != a.Error() {
		t.Errorf("joinErrors(a, a) = %q, want %q", got, a.Error())
	}
	if got := joinErrors(a, b); !strings.Contains(got, a.Error()) || !strings.Contains(got, b.Error()) {
		t.Errorf("joinErrors(a, b) = %q, want both failures", got)
	}
}

// TestProbeOneHonoursCancellation proves a cancelled context ends the round
// instead of running every probe to its own timeout.
//
// The target is a TEST-NET-1 address that a correct host will never route, and
// the injected probe checks the context itself, so this measures the plumbing
// rather than the network.
func TestProbeOneHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan PingTarget, 1)
	go func() { done <- probeOne(ctx, "192.0.2.1:9", 3, 5*time.Second) }()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("probeOne kept probing after its context was cancelled")
	}
}
