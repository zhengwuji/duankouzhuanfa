package webui

import (
	"sync"
	"time"
)

// Login throttling.
//
// The console binds to loopback by default, but a relay operator can expose it
// deliberately, and then the login form is the only thing between the internet
// and control of every relay line on the host. Without a limit, an attacker
// simply guesses passwords as fast as the network allows; the bcrypt comparison
// slows each guess but does nothing to stop the attempt itself.
//
// The policy is a per-source-address failure count with an escalating lockout:
//
//	first loginFailureFreeAttempts failures  -> no delay
//	each failure after that            -> lockout doubles from 1s, capped
//
// The counter resets on a successful login and after the failure window passes,
// so an operator who mistypes a password a few times is never locked out for
// long, while a guessing loop is slowed to a few attempts per hour.
//
// Deliberately not a global counter: one attacker must not be able to lock out
// the legitimate operator, which is the failure mode of a shared budget.
const (
	// loginFailureFreeAttempts is how many wrong passwords a source may try
	// before any delay applies. An operator with a password manager may still
	// mistype, and a hard lockout on the first failure is hostile.
	loginFailureFreeAttempts = 5
	// loginFailureWindow is how long a failure is remembered. A source that
	// stops guessing is forgotten, so the state cannot accumulate forever.
	loginFailureWindow = 15 * time.Minute
	// loginLockoutBase is the first lockout length; it doubles per failure.
	loginLockoutBase = time.Second
	// loginLockoutMax caps the escalation. Beyond this the delay stops growing
	// so a legitimate operator who is being spoofed is not locked out for days.
	loginLockoutMax = 15 * time.Minute
	// loginThrottleMaxEntries bounds memory. Addresses beyond this are not
	// tracked, which degrades to "no throttle" for the excess rather than
	// letting a spoofed-source flood grow the map without limit.
	loginThrottleMaxEntries = 4096
)

type loginFailures struct {
	count int
	last  time.Time
}

type loginThrottle struct {
	mu      sync.Mutex
	entries map[string]*loginFailures
	now     func() time.Time
}

func newLoginThrottle() *loginThrottle {
	return &loginThrottle{entries: map[string]*loginFailures{}, now: time.Now}
}

// retryAfter reports how long the source must wait before another attempt.
// Zero means the attempt may proceed.
func (t *loginThrottle) retryAfter(remote string) time.Duration {
	if remote == "" {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.entries[remote]
	if !ok {
		return 0
	}
	now := t.now()
	if now.Sub(e.last) > loginFailureWindow {
		delete(t.entries, remote)
		return 0
	}
	if e.count <= loginFailureFreeAttempts {
		return 0
	}
	// The lockout is measured from the most recent failure, so a source that
	// keeps trying keeps pushing its own release time back.
	wait := lockoutFor(e.count)
	if elapsed := now.Sub(e.last); elapsed < wait {
		return wait - elapsed
	}
	return 0
}

// failure records a wrong password and returns the lockout that now applies.
func (t *loginThrottle) failure(remote string) time.Duration {
	if remote == "" {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	e, ok := t.entries[remote]
	if !ok || now.Sub(e.last) > loginFailureWindow {
		if !ok && len(t.entries) >= loginThrottleMaxEntries {
			// The table is full of sources that are not this one. Dropping the
			// oldest entry keeps tracking the active attacker instead of
			// refusing to track anyone.
			t.evictOldestLocked()
		}
		e = &loginFailures{}
		t.entries[remote] = e
	}
	e.count++
	e.last = now
	return lockoutFor(e.count)
}

// success clears a source's failures, so a legitimate login is never penalised
// by earlier mistypes.
func (t *loginThrottle) success(remote string) {
	if remote == "" {
		return
	}
	t.mu.Lock()
	delete(t.entries, remote)
	t.mu.Unlock()
}

// evictOldestLocked drops the least recently active entry. The caller holds mu.
func (t *loginThrottle) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for k, v := range t.entries {
		if oldestKey == "" || v.last.Before(oldest) {
			oldestKey, oldest = k, v.last
		}
	}
	if oldestKey != "" {
		delete(t.entries, oldestKey)
	}
}

// lockoutFor returns the delay after count failures: zero for the free
// attempts, then a doubling delay capped at loginLockoutMax.
func lockoutFor(count int) time.Duration {
	if count <= loginFailureFreeAttempts {
		return 0
	}
	wait := loginLockoutBase
	for i := loginFailureFreeAttempts + 1; i < count; i++ {
		wait *= 2
		if wait >= loginLockoutMax {
			return loginLockoutMax
		}
	}
	return wait
}

// size reports how many sources are tracked. Used by tests.
func (t *loginThrottle) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}
