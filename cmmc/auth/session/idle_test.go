package session

import (
	"sync"
	"testing"
	"time"
)

func TestIdleTracker_BumpThenIsIdle_UnderThreshold(t *testing.T) {
	tr := NewIdleTracker(100 * time.Millisecond)
	tr.Bump("jti-1")
	if tr.IsIdle("jti-1") {
		t.Error("freshly bumped jti reported idle under threshold")
	}
}

func TestIdleTracker_BumpThenIsIdle_OverThreshold(t *testing.T) {
	tr := NewIdleTracker(20 * time.Millisecond)
	tr.Bump("jti-1")
	time.Sleep(40 * time.Millisecond)
	if !tr.IsIdle("jti-1") {
		t.Error("jti idle past threshold not reported idle")
	}
}

func TestIdleTracker_UnknownJTI_IsIdleFailClosed(t *testing.T) {
	tr := NewIdleTracker(time.Minute)
	if !tr.IsIdle("never-seen") {
		t.Error("unknown jti must fail-closed (IsIdle=true)")
	}
}

func TestIdleTracker_EmptyJTI_IsIdleFailClosed(t *testing.T) {
	tr := NewIdleTracker(time.Minute)
	if !tr.IsIdle("") {
		t.Error("empty jti must fail-closed — caller has no CMMC session")
	}
}

func TestIdleTracker_NilReceiver_NoPanic_NoIdle(t *testing.T) {
	var tr *IdleTracker
	// Nil means "feature disabled" — none of these should panic
	// and IsIdle must return false so the middleware short-circuits.
	tr.Bump("x")
	tr.Revoke("x")
	tr.Sweep(time.Minute)
	if tr.IsIdle("x") {
		t.Error("nil tracker must treat all jtis as not-idle (feature off)")
	}
}

func TestIdleTracker_ZeroThreshold_DisablesEnforcement(t *testing.T) {
	tr := NewIdleTracker(0)
	// Even an unbumped jti should NOT be idle when threshold
	// is zero — operator switched the feature off.
	if tr.IsIdle("never-seen") {
		t.Error("zero-threshold tracker must disable enforcement")
	}
}

func TestIdleTracker_Revoke_IsSticky(t *testing.T) {
	tr := NewIdleTracker(time.Hour)
	tr.Bump("jti-revoke")
	tr.Revoke("jti-revoke")
	if !tr.IsIdle("jti-revoke") {
		t.Error("revoked jti must report idle")
	}
	// Bump after revoke is a no-op — revocation sticks.
	tr.Bump("jti-revoke")
	if !tr.IsIdle("jti-revoke") {
		t.Error("revocation must survive subsequent Bump (replay attempt)")
	}
}

func TestIdleTracker_Sweep_DropsStaleActivity(t *testing.T) {
	tr := NewIdleTracker(50 * time.Millisecond)
	tr.Bump("jti-fresh")
	tr.Bump("jti-stale")

	// Age jti-stale past the sweep cutoff by replacing its
	// timestamp directly — sleeping would be flaky.
	tr.mu.Lock()
	tr.lastSeen["jti-stale"] = time.Now().Add(-time.Hour)
	tr.mu.Unlock()

	tr.Sweep(30 * time.Minute)

	active, _ := tr.Size()
	if active != 1 {
		t.Errorf("sweep left %d active entries, want 1", active)
	}
	if !tr.IsIdle("jti-stale") {
		t.Error("swept jti should IsIdle=true")
	}
	if tr.IsIdle("jti-fresh") {
		t.Error("fresh jti swept by mistake")
	}
}

func TestIdleTracker_Concurrent_BumpAndIsIdle(t *testing.T) {
	tr := NewIdleTracker(time.Second)
	const N = 200
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			jti := "jti-" + time.Duration(i).String()
			tr.Bump(jti)
			_ = tr.IsIdle(jti)
			tr.Revoke(jti)
		}()
	}
	wg.Wait()
	// Just needs to finish without the race detector complaining.
	active, revoked := tr.Size()
	if revoked != N {
		t.Errorf("revoked count = %d, want %d", revoked, N)
	}
	_ = active
}

// TestIdleTracker_Revoke_WithoutPriorBump — reviewer-flagged
// corner: the very first post-restart request is logout, so Revoke
// runs on a jti the tracker never Bumped. The revocation must
// still stick (IsIdle=true for that jti), and the next Sweep must
// drop the orphan so the map stays bounded.
func TestIdleTracker_Revoke_WithoutPriorBump(t *testing.T) {
	tr := NewIdleTracker(time.Hour)
	tr.Revoke("jti-orphan")
	if !tr.IsIdle("jti-orphan") {
		t.Error("revoked-without-bump jti must IsIdle=true")
	}
	tr.Sweep(time.Second)
	_, revoked := tr.Size()
	if revoked != 0 {
		t.Errorf("orphan revocation not swept (revoked=%d)", revoked)
	}
	// After sweep, the jti takes the unknown-jti fail-closed path.
	if !tr.IsIdle("jti-orphan") {
		t.Error("post-sweep jti must still fail closed (unknown-jti path)")
	}
}

// TestIdleTracker_ThresholdBoundary — strictly-greater semantics.
// Under threshold (by a wide margin) is NOT idle; over threshold
// (by a wide margin) IS idle. Avoids epsilon flakiness from
// time.Now() advancing between backdate and check.
func TestIdleTracker_ThresholdBoundary(t *testing.T) {
	tr := NewIdleTracker(time.Second)
	tr.Bump("jti-1")
	// 100ms into a 1s window → not idle.
	tr.mu.Lock()
	tr.lastSeen["jti-1"] = time.Now().Add(-100 * time.Millisecond)
	tr.mu.Unlock()
	if tr.IsIdle("jti-1") {
		t.Error("age well under threshold must NOT be idle")
	}
	// 2s into a 1s window → idle.
	tr.mu.Lock()
	tr.lastSeen["jti-1"] = time.Now().Add(-2 * time.Second)
	tr.mu.Unlock()
	if !tr.IsIdle("jti-1") {
		t.Error("age well past threshold must be idle")
	}
}

// TestIdleTracker_Sweep_RaceWithBump — confirms Bump happening
// concurrently with Sweep doesn't lose the bump. Run with -race.
func TestIdleTracker_Sweep_RaceWithBump(t *testing.T) {
	tr := NewIdleTracker(time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			tr.Sweep(time.Nanosecond)
		}
	}()
	for i := 0; i < 2000; i++ {
		tr.Bump("jti-hot")
	}
	<-done
	// No assertion on final state — the race detector is the check.
	// The map MAY be empty (Sweep won) or have one entry (Bump won);
	// both outcomes are correct.
}

// TestLoadIdleConfigFromEnv — parse matrix.
func TestLoadIdleConfigFromEnv(t *testing.T) {
	for _, tc := range []struct {
		raw       string
		wantNil   bool
		wantErr   bool
		wantThres time.Duration
	}{
		{"", true, false, 0},
		{"   ", true, false, 0},
		{"15m", false, false, 15 * time.Minute},
		{"0s", false, true, 0},
		{"-1m", false, true, 0},
		{"garbage", false, true, 0},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			t.Setenv(EnvIdleTimeout, tc.raw)
			tr, err := LoadIdleConfigFromEnv()
			if tc.wantErr {
				if err == nil {
					t.Fatal("want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if tc.wantNil {
				if tr != nil {
					t.Error("want nil tracker, got non-nil")
				}
				return
			}
			if tr == nil || tr.Threshold() != tc.wantThres {
				t.Errorf("threshold = %v, want %v", tr.Threshold(), tc.wantThres)
			}
		})
	}
}

func TestIdleTracker_Threshold_RoundTrip(t *testing.T) {
	tr := NewIdleTracker(7 * time.Minute)
	if tr.Threshold() != 7*time.Minute {
		t.Errorf("Threshold() = %v", tr.Threshold())
	}
	var nilTr *IdleTracker
	if nilTr.Threshold() != 0 {
		t.Errorf("nil Threshold() = %v, want 0", nilTr.Threshold())
	}
}
