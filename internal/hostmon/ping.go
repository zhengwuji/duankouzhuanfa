package hostmon

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// The outbound probe.
//
// Two measurements are available and they answer different questions. ICMP echo
// measures the network path itself and is what an operator means by "ping"; a
// TCP handshake measures whether something is actually reachable and answering.
// ICMP is tried first and the handshake is the fallback, because a raw socket
// needs CAP_NET_RAW — present when the relay runs as a service, absent in a
// rootless container — and because plenty of hosts simply drop echo requests
// while serving traffic perfectly well.
//
// Whichever one produced the number is reported alongside it, so the console
// never presents a handshake time as if it were an ICMP round trip.

// defaultPort is used when a target names a bare host. Only the TCP fallback
// reads it; ICMP has no ports.
const defaultPort = "443"

// The probe methods, reported to the console so the number is never presented
// as a measurement it is not.
const (
	MethodICMP = "icmp"
	MethodTCP  = "tcp"
	// MethodMixed means the targets were measured with different methods, so
	// the aggregate average is not a like-for-like number.
	MethodMixed = "mixed"
)

// probeFunc measures one target and returns the round-trip times it collected.
type probeFunc func(ctx context.Context, addr string, count int, timeout time.Duration) ([]float64, error)

// prober holds the two measurements probeOne chooses between.
//
// It is a struct rather than two direct calls so the choice between them can be
// tested. The decision is the part that can be wrong in a way nobody notices —
// a card that reports an ICMP round trip when the number came from a TCP
// handshake looks perfectly healthy — and testing it through the real network
// would make the test depend on whether the host running it has raw sockets and
// on how its ISP treats echo requests.
type prober struct {
	icmp probeFunc
	tcp  probeFunc
}

// defaultProber is the real pair used in production.
var defaultProber = prober{icmp: icmpProbe, tcp: tcpProbe}

// probeOne measures a single target.
func probeOne(ctx context.Context, addr string, count int, timeout time.Duration) PingTarget {
	return defaultProber.probe(ctx, addr, count, timeout)
}

// probe runs one target through the ICMP probe and falls back to the handshake.
func (p prober) probe(ctx context.Context, addr string, count int, timeout time.Duration) PingTarget {
	t := PingTarget{Address: addr, Sent: count}

	host, port := splitTarget(addr)
	if host == "" {
		t.Error = "目标地址为空"
		return t
	}

	// The method is recorded from whichever probe produced the numbers, not
	// from whichever was tried first: an ICMP attempt that is refused and falls
	// through to TCP must not leave the card claiming an ICMP round trip.
	lat, icmpErr := p.icmp(ctx, host, count, timeout)
	if len(lat) > 0 {
		t.Method = MethodICMP
	} else {
		var tcpErr error
		lat, tcpErr = p.tcp(ctx, net.JoinHostPort(host, port), count, timeout)
		if len(lat) > 0 {
			t.Method = MethodTCP
		} else {
			t.Method = MethodICMP
			// Nothing answered. Both failures are reported, because they say
			// different things: "operation not permitted" means the ICMP probe
			// was never allowed to run, which is not evidence about the target,
			// while a timeout from the handshake is. Keeping only the first
			// would tell an operator their network is broken when the real
			// problem is that the service lacks CAP_NET_RAW.
			t.Error = joinErrors(icmpErr, tcpErr)
		}
	}
	t.Recv = len(lat)
	t.LossPct = lossPct(t.Sent, t.Recv)
	if len(lat) > 0 {
		t.MinMs, t.MaxMs, t.AvgMs = latStats(lat)
	}
	return t
}

// joinErrors combines the two probe failures into one line for the card.
func joinErrors(icmpErr, tcpErr error) string {
	switch {
	case icmpErr == nil && tcpErr == nil:
		return ""
	case tcpErr == nil:
		return icmpErr.Error()
	case icmpErr == nil:
		return tcpErr.Error()
	case icmpErr.Error() == tcpErr.Error():
		return icmpErr.Error()
	}
	return "ICMP: " + icmpErr.Error() + "；TCP: " + tcpErr.Error()
}

// tcpProbe times count TCP handshakes to addr.
func tcpProbe(ctx context.Context, addr string, count int, timeout time.Duration) ([]float64, error) {
	d := net.Dialer{Timeout: timeout}
	var out []float64
	var lastErr error

	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		default:
		}
		start := time.Now()
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			lastErr = err
		} else {
			out = append(out, float64(time.Since(start).Microseconds())/1000)
			_ = conn.Close()
		}
		if i < count-1 {
			// A short gap keeps the probes from measuring a single burst of
			// congestion, which would make the loss figure meaningless.
			time.Sleep(120 * time.Millisecond)
		}
	}
	if len(out) == 0 {
		if lastErr == nil {
			lastErr = errors.New("无应答")
		}
		return nil, lastErr
	}
	return out, nil
}

// aggregatePing folds the per-target results into one line for the card.
//
// The average is weighted by received probes so a target that answered once
// does not carry the same weight as one that answered every time.
func aggregatePing(targets []PingTarget) PingInfo {
	info := PingInfo{Enabled: true, Targets: targets, LastAt: time.Now()}

	// The aggregate method is only reported when every target that produced a
	// number used the same one. A mix of ICMP and TCP round trips averaged into
	// a single "ping" would be a number with no meaning.
	method := ""
	mixed := false

	var sum float64
	var sent, recv int
	haveMin := false
	for _, t := range targets {
		sent += t.Sent
		recv += t.Recv
		if t.Recv > 0 {
			if method == "" {
				method = t.Method
			} else if t.Method != method {
				mixed = true
			}
		}
		if t.Recv == 0 {
			if t.Error != "" && info.Error == "" {
				info.Error = t.Error
			}
			continue
		}
		sum += t.AvgMs * float64(t.Recv)
		if !haveMin || t.MinMs < info.MinMs {
			info.MinMs = t.MinMs
		}
		if !haveMin || t.MaxMs > info.MaxMs {
			info.MaxMs = t.MaxMs
		}
		haveMin = true
	}

	switch {
	case method == "":
		// Nothing answered, so there is no method to report.
	case mixed:
		info.Method = MethodMixed
	default:
		info.Method = method
	}

	if recv > 0 {
		info.AvgMs = round1(sum / float64(recv))
		info.MinMs = round1(info.MinMs)
		info.MaxMs = round1(info.MaxMs)
	}
	info.LossPct = lossPct(sent, recv)
	return info
}

// splitTarget separates a probe target into a host and a port, tolerating a
// bare host or a bare IPv6 literal.
//
// The host is trimmed before it is returned: a target that is nothing but
// whitespace reaches here as a non-empty string, and without this it would be
// dialled instead of reported as the configuration mistake it is.
func splitTarget(addr string) (host, port string) {
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return strings.TrimSpace(h), p
	}
	return strings.TrimSpace(addr), defaultPort
}

// lossPct is the share of probes that were never answered.
func lossPct(sent, recv int) float64 {
	if sent <= 0 {
		return 0
	}
	lost := sent - recv
	if lost < 0 {
		lost = 0
	}
	return round1(float64(lost) * 100 / float64(sent))
}

// latStats returns the minimum, maximum and mean of a sample set.
func latStats(samples []float64) (min, max, avg float64) {
	min, max = samples[0], samples[0]
	var sum float64
	for _, v := range samples {
		sum += v
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	return round1(min), round1(max), round1(sum / float64(len(samples)))
}
