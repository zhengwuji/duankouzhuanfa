package webui

import (
	"testing"
	"time"
)

// The throttle exists because a console exposed beyond loopback has only the
// password between the internet and control of every relay line on the host.
// These tests pin the properties that make it useful rather than merely
// present: it lets an operator mistype, it escalates against a guesser, it
// recovers, and one source cannot lock out another.

func TestLoginThrottleAllowsAFewMistakes(t *testing.T) {
	th := newLoginThrottle()
	now := time.Now()
	th.now = func() time.Time { return now }

	for i := 1; i <= loginFailureFreeAttempts; i++ {
		if wait := th.retryAfter("10.0.0.1"); wait != 0 {
			t.Fatalf("attempt %d was blocked for %v; the first %d failures must be free so an operator can mistype",
				i, wait, loginFailureFreeAttempts)
		}
		if got := th.failure("10.0.0.1"); got != 0 {
			t.Fatalf("failure %d reported a lockout of %v, want none", i, got)
		}
	}
}

func TestLoginThrottleEscalatesAfterTheFreeAttempts(t *testing.T) {
	th := newLoginThrottle()
	now := time.Now()
	th.now = func() time.Time { return now }

	for i := 0; i < loginFailureFreeAttempts; i++ {
		th.failure("10.0.0.1")
	}

	// The next failure is the first that is penalised, and it must block.
	first := th.failure("10.0.0.1")
	if first == 0 {
		t.Fatal("the failure after the free attempts was not penalised")
	}
	if wait := th.retryAfter("10.0.0.1"); wait != first {
		t.Fatalf("retryAfter = %v, want %v", wait, first)
	}

	// Each further failure doubles the wait, so a guessing loop slows down.
	second := th.failure("10.0.0.1")
	if second <= first {
		t.Fatalf("lockout did not grow: first %v, second %v", first, second)
	}
}

func TestLoginThrottleCapsTheLockout(t *testing.T) {
	th := newLoginThrottle()
	now := time.Now()
	th.now = func() time.Time { return now }

	var last time.Duration
	for i := 0; i < 100; i++ {
		last = th.failure("10.0.0.1")
	}
	if last != loginLockoutMax {
		t.Fatalf("after 100 failures the lockout is %v, want the cap %v — an uncapped doubling would lock an operator out for years",
			last, loginLockoutMax)
	}
}

func TestLoginThrottleReleasesAfterTheLockoutExpires(t *testing.T) {
	th := newLoginThrottle()
	now := time.Now()
	th.now = func() time.Time { return now }

	for i := 0; i < loginFailureFreeAttempts+3; i++ {
		th.failure("10.0.0.1")
	}
	if wait := th.retryAfter("10.0.0.1"); wait <= 0 {
		t.Fatal("a source that just failed repeatedly was not blocked")
	}

	// The lockout is measured from the last failure, so moving past it — and
	// past the failure window — must clear the block.
	now = now.Add(loginFailureWindow + time.Second)
	if wait := th.retryAfter("10.0.0.1"); wait != 0 {
		t.Fatalf("still blocked %v after the window passed; a legitimate operator must not be locked out forever", wait)
	}
}

func TestLoginThrottleSuccessClearsFailures(t *testing.T) {
	th := newLoginThrottle()
	now := time.Now()
	th.now = func() time.Time { return now }

	for i := 0; i < loginFailureFreeAttempts+2; i++ {
		th.failure("10.0.0.1")
	}
	if wait := th.retryAfter("10.0.0.1"); wait <= 0 {
		t.Fatal("expected a lockout before the successful login")
	}

	th.success("10.0.0.1")
	if wait := th.retryAfter("10.0.0.1"); wait != 0 {
		t.Fatalf("a successful login left a %v lockout in place", wait)
	}
}

func TestLoginThrottleIsolatesSources(t *testing.T) {
	th := newLoginThrottle()
	now := time.Now()
	th.now = func() time.Time { return now }

	// One attacker must not be able to lock out the operator. A shared budget
	// would make the console trivially deniable.
	for i := 0; i < loginFailureFreeAttempts+10; i++ {
		th.failure("203.0.113.9")
	}
	if wait := th.retryAfter("203.0.113.9"); wait <= 0 {
		t.Fatal("the attacker was not throttled")
	}
	if wait := th.retryAfter("198.51.100.4"); wait != 0 {
		t.Fatalf("an unrelated address was blocked for %v by another source's failures", wait)
	}
}

func TestLoginThrottleBoundsItsTable(t *testing.T) {
	th := newLoginThrottle()
	now := time.Now()
	th.now = func() time.Time { return now }

	// A flood of distinct (possibly spoofed) sources must not grow memory
	// without limit. Tracking stops at the cap; the excess degrades to
	// unthrottled rather than exhausting the host.
	for i := 0; i < loginThrottleMaxEntries+500; i++ {
		th.failure(string(rune('a'+i%26)) + "-" + time.Duration(i).String())
	}
	if got := th.size(); got > loginThrottleMaxEntries {
		t.Fatalf("throttle table holds %d entries, want at most %d", got, loginThrottleMaxEntries)
	}
}

func TestLoginThrottleIgnoresAnEmptySource(t *testing.T) {
	// clientIP can return "" when the request has no address at all; such a
	// request must not be lumped into one shared bucket with every other.
	th := newLoginThrottle()
	for i := 0; i < loginFailureFreeAttempts+10; i++ {
		if wait := th.failure(""); wait != 0 {
			t.Fatalf("an unknown source was throttled for %v", wait)
		}
	}
	if wait := th.retryAfter(""); wait != 0 {
		t.Fatalf("an unknown source was blocked for %v", wait)
	}
}
