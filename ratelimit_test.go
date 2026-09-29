// Ported from mikroview's internal/auth/ratelimit_test.go, unchanged.
package gauntlet

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// A threshold below one blocks every login before a first attempt is
// even made, and a non-positive window never lets a blocked key age
// out -- both are refused rather than silently misconfiguring the
// limiter.
func TestNewLoginLimiterRefusesAnUnusableConfiguration(t *testing.T) {
	tests := []struct {
		name      string
		threshold int
		window    time.Duration
	}{
		{name: "zero threshold", threshold: 0, window: time.Minute},
		{name: "negative threshold", threshold: -1, window: time.Minute},
		{name: "zero window", threshold: 1, window: 0},
		{name: "negative window", threshold: 1, window: -time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewLoginLimiter(tc.threshold, tc.window); !errors.Is(err, ErrLimiterConfig) {
				t.Errorf("err = %v, want ErrLimiterConfig", err)
			}
		})
	}
}

func TestNewLoginLimiterAcceptsAUsableConfiguration(t *testing.T) {
	if _, err := NewLoginLimiter(1, time.Second); err != nil {
		t.Fatalf("NewLoginLimiter(1, time.Second): %v", err)
	}
}

func mustNewLoginLimiter(t *testing.T, threshold int, window time.Duration) *LoginLimiter {
	t.Helper()
	l, err := NewLoginLimiter(threshold, window)
	if err != nil {
		t.Fatalf("NewLoginLimiter: %v", err)
	}
	return l
}

func TestLoginLimiterAllowsUnderThreshold(t *testing.T) {
	l := mustNewLoginLimiter(t, 3, time.Minute)
	now := time.Now()

	for i := 0; i < 2; i++ {
		if !l.Allow("alice", now) {
			t.Fatalf("expected attempt %d to be allowed", i+1)
		}
		l.RecordFailure("alice", now)
	}
	if !l.Allow("alice", now) {
		t.Error("expected the 3rd attempt to still be allowed (threshold not yet reached)")
	}
}

func TestLoginLimiterBlocksAtThreshold(t *testing.T) {
	l := mustNewLoginLimiter(t, 3, time.Minute)
	now := time.Now()

	for i := 0; i < 3; i++ {
		l.RecordFailure("alice", now)
	}
	if l.Allow("alice", now) {
		t.Error("expected the 4th attempt to be blocked after 3 recorded failures")
	}
}

func TestLoginLimiterWindowExpires(t *testing.T) {
	l := mustNewLoginLimiter(t, 2, time.Minute)
	now := time.Now()

	l.RecordFailure("alice", now)
	l.RecordFailure("alice", now)
	if l.Allow("alice", now) {
		t.Fatal("expected the limit to be reached")
	}

	if !l.Allow("alice", now.Add(2*time.Minute)) {
		t.Error("expected attempts outside the window to no longer count")
	}
}

func TestLoginLimiterKeysAreIndependent(t *testing.T) {
	l := mustNewLoginLimiter(t, 1, time.Minute)
	now := time.Now()

	l.RecordFailure("alice", now)
	if l.Allow("alice", now) {
		t.Fatal("expected alice to be blocked")
	}
	if !l.Allow("bob", now) {
		t.Error("expected bob to be unaffected by alice's failures")
	}
}

func TestLoginLimiterEvictsOldestKeyOverCap(t *testing.T) {
	orig := maxLoginLimiterKeys
	maxLoginLimiterKeys = 2
	defer func() { maxLoginLimiterKeys = orig }()

	l := mustNewLoginLimiter(t, 10, time.Hour)
	now := time.Now()

	l.RecordFailure("alice", now)
	l.RecordFailure("bob", now.Add(time.Second))
	l.RecordFailure("carol", now.Add(2*time.Second)) // should evict alice (oldest)

	if len(l.attempts) != 2 {
		t.Fatalf("expected the tracked-key map to stay capped at 2, got %d", len(l.attempts))
	}
	if _, stillTracked := l.attempts["alice"]; stillTracked {
		t.Error("expected alice (the oldest) to have been evicted")
	}
}

// The cap must be enforced on the Reserve path too, not only
// RecordFailure: Reserve is what an unauthenticated request reaches
// first, and pruneLocked must not create a map entry as a side effect of
// pruning it, or the "!exists" eviction check below is always false.
func TestLoginLimiterCapIsEnforcedOnTheReservePath(t *testing.T) {
	orig := maxLoginLimiterKeys
	maxLoginLimiterKeys = 64
	defer func() { maxLoginLimiterKeys = orig }()

	l := mustNewLoginLimiter(t, 5, time.Hour)
	now := time.Now()

	// Each distinct key stands in for a distinct source address. Reserve
	// only -- never RecordFailure, which is the path that already worked.
	const distinctSources = 20_000
	for i := 0; i < distinctSources; i++ {
		l.Reserve(fmt.Sprintf("2001:db8::%x", i), now)
	}

	if len(l.attempts) > maxLoginLimiterKeys {
		t.Fatalf("Reserve tracked %d keys against a cap of %d -- the cap is not enforced on this path",
			len(l.attempts), maxLoginLimiterKeys)
	}
}

// pruneLocked must not leave an entry behind once a key's attempts have
// all aged out. An empty entry is one map entry per source address held
// forever, and it is also what would make the cap check above dead
// code.
func TestLoginLimiterForgetsKeysWhoseAttemptsAgedOut(t *testing.T) {
	l := mustNewLoginLimiter(t, 5, time.Minute)
	now := time.Now()

	l.RecordFailure("198.51.100.7", now)
	if len(l.attempts) != 1 {
		t.Fatalf("expected the failure to be tracked, got %d keys", len(l.attempts))
	}

	// Any call that prunes, once the window has passed.
	l.Allow("198.51.100.7", now.Add(2*time.Minute))
	if len(l.attempts) != 0 {
		t.Errorf("expected the key to be forgotten once its attempts aged out, still tracking %d", len(l.attempts))
	}
}

// A successful login releases its reservation; the last one out must not
// leave an empty entry behind either.
func TestLoginLimiterReleaseOfTheLastAttemptForgetsTheKey(t *testing.T) {
	l := mustNewLoginLimiter(t, 5, time.Hour)
	now := time.Now()

	if !l.Reserve("alice", now) {
		t.Fatal("expected the first Reserve to succeed")
	}
	l.Release("alice", now)
	if len(l.attempts) != 0 {
		t.Errorf("expected releasing the only attempt to forget the key, still tracking %d", len(l.attempts))
	}
}
