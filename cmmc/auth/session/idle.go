package session

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// EnvIdleTimeout is the name of the operator-facing env var that
// configures the idle session threshold. Exported as a const so
// docs + tests + cmd wiring all reference the same string.
const EnvIdleTimeout = "FB_CMMC_SESSION_IDLE_TIMEOUT"

// LoadIdleConfigFromEnv parses EnvIdleTimeout and returns a ready
// *IdleTracker, or (nil, nil) when the var is unset/empty (feature
// off). Returns an error on a present-but-unparseable value so the
// operator sees a loud boot failure instead of silent drift.
func LoadIdleConfigFromEnv() (*IdleTracker, error) {
	raw := strings.TrimSpace(os.Getenv(EnvIdleTimeout))
	if raw == "" {
		return nil, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return nil, fmt.Errorf("%s=%q invalid: want a positive Go duration (e.g. 15m)", EnvIdleTimeout, raw)
	}
	return NewIdleTracker(d), nil
}

// IdleTracker records the last-activity time for each live session
// JWT jti and answers "has this session gone idle?" under a
// configurable threshold. CMMC 3.10.2 / 3.1.11 — automatic session
// termination after a period of inactivity.
//
// Stateless rolling tokens would move the idle window client-side
// where we can't enforce it; a server-side map is the only place
// a compromised-token replay window can actually be capped.
//
// In-memory by design. A process restart forces everyone to
// re-authenticate, which is the correct posture for "re-establish
// trust after an outage" (3.3.3 audit-failure / 3.14.7 system
// integrity — an unplanned restart is a trust-changing event).
// Persisting idle state through a restart would hide that signal.
type IdleTracker struct {
	mu        sync.RWMutex
	lastSeen  map[string]time.Time
	revoked   map[string]struct{}
	threshold time.Duration
}

// NewIdleTracker returns a tracker configured with the given idle
// threshold. A non-positive threshold disables enforcement — the
// tracker still records activity (Bump is a no-op on zero cost)
// but IsIdle always returns false. Use a nil *IdleTracker to mean
// "feature off" on the call site and skip the check entirely.
func NewIdleTracker(threshold time.Duration) *IdleTracker {
	return &IdleTracker{
		lastSeen:  make(map[string]time.Time),
		revoked:   make(map[string]struct{}),
		threshold: threshold,
	}
}

// Bump records a fresh activity timestamp for the jti. Called by
// the withUser middleware on every authenticated request that
// passes the other auth gates. A bump on a revoked jti is a no-op
// — revocation sticks until process restart.
func (t *IdleTracker) Bump(jti string) {
	if t == nil || jti == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, gone := t.revoked[jti]; gone {
		return
	}
	t.lastSeen[jti] = time.Now()
}

// IsIdle reports whether the jti should be treated as
// expired-due-to-inactivity. Fail-closed on all three unsafe
// conditions:
//   - nil / zero threshold → not enforced
//   - empty jti → idle (token not minted with CMMC machinery)
//   - revoked jti → idle (logout path, sticky)
//   - unknown jti → idle (post-restart token is indistinguishable
//     from a replayed one; force re-auth. The SPA catches the
//     401 and redirects to /login so UX stays smooth)
//   - past threshold → idle
func (t *IdleTracker) IsIdle(jti string) bool {
	if t == nil || t.threshold <= 0 {
		return false
	}
	if jti == "" {
		return true
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if _, gone := t.revoked[jti]; gone {
		return true
	}
	last, ok := t.lastSeen[jti]
	if !ok {
		return true
	}
	return time.Since(last) > t.threshold
}

// Revoke forcibly terminates a session by jti. Subsequent Bumps
// are no-ops; IsIdle returns true until the process restarts.
// Used at logout and by the admin "terminate session" path.
func (t *IdleTracker) Revoke(jti string) {
	if t == nil || jti == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.lastSeen, jti)
	t.revoked[jti] = struct{}{}
}

// Sweep drops lastSeen entries older than maxAge and the revoked
// entries that no longer have a matching lastSeen row. Intended to
// be called from a time.Ticker so the tracker doesn't grow
// unbounded over long uptimes. maxAge should be >= idle threshold
// so in-flight requests aren't surprised by a disappearing row.
//
// Revocation aging: Bump refuses to re-populate a revoked jti's
// lastSeen row, so once Sweep drops that row the revocation
// naturally follows on the next pass. A replayed revoked jti
// thereafter takes the unknown-jti fail-closed path in IsIdle.
func (t *IdleTracker) Sweep(maxAge time.Duration) {
	if t == nil {
		return
	}
	cutoffActivity := time.Now().Add(-maxAge)
	t.mu.Lock()
	defer t.mu.Unlock()
	for jti, ts := range t.lastSeen {
		if ts.Before(cutoffActivity) {
			delete(t.lastSeen, jti)
		}
	}
	for jti := range t.revoked {
		if _, present := t.lastSeen[jti]; !present {
			delete(t.revoked, jti)
		}
	}
}

// Size returns the current count of tracked jtis (lastSeen +
// revoked). Exposed for metrics / sweep telemetry.
func (t *IdleTracker) Size() (active, revoked int) {
	if t == nil {
		return 0, 0
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.lastSeen), len(t.revoked)
}

// Threshold returns the configured idle window. Zero/negative
// means enforcement is disabled.
func (t *IdleTracker) Threshold() time.Duration {
	if t == nil {
		return 0
	}
	return t.threshold
}
