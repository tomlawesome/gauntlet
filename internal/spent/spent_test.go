package spent

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

// grace is the grace period these tests build their sets with: five
// minutes, the lifetime gate and passkey pass.
const grace = 5 * time.Minute

func TestClaimOnce(t *testing.T) {
	s := New(grace)
	if !s.Claim("a", t0.Add(time.Minute), t0) {
		t.Fatal("the first claim of a fresh key was refused")
	}
	if s.Claim("a", t0.Add(time.Minute), t0) {
		t.Fatal("a second claim of the same key was accepted")
	}
	if !s.Spent("a", t0) || s.Spent("b", t0) {
		t.Fatal("Spent disagrees with what was claimed")
	}
	if s.Spent("b", t0) || !s.Claim("b", t0.Add(time.Minute), t0) {
		t.Fatal("Spent recorded a key it was only asked about")
	}
}

// TestHeldUntilItsForgetTimePlusGrace (ruling S2 on #20): a key is still
// refused a nanosecond before forgetAt + grace -- and so at forgetAt
// itself, where gate's pending-login decode still accepts a cookie --
// and forgotten at forgetAt + grace.
func TestHeldUntilItsForgetTimePlusGrace(t *testing.T) {
	s := New(grace)
	forget := t0.Add(5 * time.Minute)
	s.Claim("a", forget, t0)
	if !s.Spent("a", forget) {
		t.Fatal("the key was forgotten at its forget time")
	}
	if s.Claim("a", forget, forget.Add(grace-time.Nanosecond)) {
		t.Fatal("the key was accepted again a nanosecond before its forget time plus grace")
	}
	if s.Spent("a", forget.Add(grace)) {
		t.Fatal("the key is still held at its forget time plus grace")
	}
	if !s.Claim("a", forget.Add(grace+5*time.Minute), forget.Add(grace)) {
		t.Fatal("the key was refused at its forget time plus grace")
	}
}

// TestALaterRequestCannotEraseAKeyAnEarlierOneIsAboutToCheck is the
// review's TestRereviewPruneByALaterRequestReopensASpentPendingLogin at
// the set level: one request read the clock just after forgetAt and
// reaches the set first; another read it at forgetAt, where its
// acceptance check still passed, and arrives second. The first must not
// have erased the key for the second.
func TestALaterRequestCannotEraseAKeyAnEarlierOneIsAboutToCheck(t *testing.T) {
	s := New(grace)
	forget := t0.Add(5 * time.Minute)
	s.Claim("a", forget, t0)
	s.Spent("other", forget.Add(time.Nanosecond)) // the later reading, pruning first
	if s.Claim("a", forget, forget) {
		t.Fatal("a request that read the clock at the forget time claimed a key a later reading had erased")
	}
}

// TestForgottenLateNeverEarly: a key claimed after a longer-lived one is
// forgotten only once that one goes -- late, never early -- and both go
// together once the head's time has passed.
func TestForgottenLateNeverEarly(t *testing.T) {
	s := New(grace)
	s.Claim("long", t0.Add(10*time.Minute), t0)
	s.Claim("short", t0.Add(time.Minute), t0)
	pastShort := t0.Add(time.Minute + grace + time.Minute)
	if !s.Spent("short", pastShort) {
		t.Fatal("a key behind a longer-lived head was forgotten before the head went")
	}
	if s.Claim("short", t0.Add(time.Hour), pastShort) {
		t.Fatal("a key behind a longer-lived head was accepted again")
	}
	later := t0.Add(10*time.Minute + grace)
	if s.Spent("long", later) || s.Spent("short", later) {
		t.Fatal("keys were held after the head's forget time plus grace")
	}
	if len(s.seen) != 0 || len(s.queue)-s.head != 0 {
		t.Errorf("after both went the set holds %d keys and %d queued", len(s.seen), len(s.queue)-s.head)
	}
}

// TestAForgetTimeAlreadyPastIsRecordedThenMayBePruned pins what happens
// when a caller passes a forget time already behind now: within the
// grace period the key is held as usual; with forgetAt + grace also
// behind now, the claim succeeds and the key is recorded, and the next
// call may prune it, so a second claim then succeeds. That is acceptable
// because both callers claim only after their acceptance check passed on
// that same forget time, a whole grace period earlier.
func TestAForgetTimeAlreadyPastIsRecordedThenMayBePruned(t *testing.T) {
	s := New(grace)
	if !s.Claim("recent", t0.Add(-time.Minute), t0) || !s.Spent("recent", t0) {
		t.Fatal("a key whose forget time passed within the grace period was not held")
	}
	s = New(grace)
	if !s.Claim("old", t0.Add(-grace-time.Minute), t0) {
		t.Fatal("the claim was refused")
	}
	if _, held := s.seen["old"]; !held {
		t.Fatal("a key with a forget time already past was not recorded")
	}
	if s.Spent("old", t0) {
		t.Fatal("the next call did not prune a key whose forget time plus grace had passed")
	}
}

// TestMonotonicNowAgainstAWallClockForgetTime: now from time.Now()
// carries a monotonic reading and a forget time from a JSON round trip
// does not. The set must compare them on the wall clock, and nothing it
// stores carries a monotonic reading.
func TestMonotonicNowAgainstAWallClockForgetTime(t *testing.T) {
	s := New(grace)
	now := time.Now()
	if !strings.Contains(now.String(), "m=") {
		t.Skip("this platform's time.Now carries no monotonic reading")
	}
	var forget time.Time
	raw, err := json.Marshal(now.Add(5 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &forget); err != nil {
		t.Fatal(err)
	}
	s.Claim("a", forget, now)
	if got := s.seen["a"]; strings.Contains(got.String(), "m=") || !got.Equal(forget.Add(grace)) {
		t.Errorf("the stored forget time is %v, want the wall-clock %v", got, forget.Add(grace))
	}
	// Reached from a monotonic reading: held a nanosecond before the
	// wall-clock forget time plus grace, gone at it.
	if !s.Spent("a", now.Add(5*time.Minute+grace-time.Nanosecond)) {
		t.Error("the key was forgotten before its wall-clock forget time plus grace")
	}
	if s.Spent("a", now.Add(5*time.Minute+grace)) {
		t.Error("the key was held at its wall-clock forget time plus grace")
	}
	// A caller that passes a forget time with a monotonic reading (a
	// test clock built on time.Now, say) gets it stored on the wall
	// clock too.
	s.Claim("b", now.Add(time.Minute), now)
	if got := s.seen["b"]; strings.Contains(got.String(), "m=") {
		t.Errorf("a monotonic forget time was stored as %v, want wall clock only", got)
	}
}

// TestConcurrentClaimsOfOneKeyHaveOneWinner: run with -race.
func TestConcurrentClaimsOfOneKeyHaveOneWinner(t *testing.T) {
	s := New(grace)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			if s.Claim("a", t0.Add(time.Minute), t0) {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Errorf("%d of 50 concurrent claims of one key won, want 1", wins.Load())
	}
}

// TestPruningReleasesTheQueue: once the dropped prefix passes half the
// queue, the live part moves to a fresh slice.
func TestPruningReleasesTheQueue(t *testing.T) {
	s := New(grace)
	for i := range 100 {
		s.Claim(fmt.Sprint(i), t0.Add(time.Duration(i+1)*time.Second), t0)
	}
	s.Spent("x", t0.Add(80*time.Second+grace))
	if s.head != 0 || len(s.queue) != 20 || len(s.seen) != 20 {
		t.Errorf("after 80 of 100 expired: head %d, queue %d, map %d; want 0, 20, 20", s.head, len(s.queue), len(s.seen))
	}
}

// TestPruningLooksOnlyAtTheHead: however many live keys the set holds, a
// prune looks at the entries it drops plus the one it stops at -- never
// the rest. (The set this replaced scanned every key under its lock.)
func TestPruningLooksOnlyAtTheHead(t *testing.T) {
	s := New(grace)
	for i := range 30000 {
		s.Claim(fmt.Sprintf("live-%d", i), t0.Add(time.Hour), t0)
	}
	if n := s.pruneLocked(t0.Add(10 * time.Minute)); n != 1 {
		t.Errorf("a prune with 30000 live keys looked at %d entries, want 1", n)
	}
	s = New(grace)
	for i := range 10 {
		s.Claim(fmt.Sprintf("old-%d", i), t0.Add(time.Second), t0)
	}
	for i := range 30000 {
		s.Claim(fmt.Sprintf("live-%d", i), t0.Add(time.Hour), t0)
	}
	if n := s.pruneLocked(t0.Add(10 * time.Minute)); n != 11 {
		t.Errorf("a prune dropping 10 keys ahead of 30000 live ones looked at %d entries, want 11", n)
	}
}

// TestTheSetStaysBoundedUnderSteadyUse: a hundred thousand claims, each
// one second after the last, forgotten five seconds after it is made
// and held for a five-second grace -- a steady stream of sign-ins --
// leave the set holding only the last few keys, and the queue's backing
// array no larger than a small multiple of that.
func TestTheSetStaysBoundedUnderSteadyUse(t *testing.T) {
	s := New(5 * time.Second)
	maxLive, maxQueue := 0, 0
	for i := range 100000 {
		now := t0.Add(time.Duration(i) * time.Second)
		if !s.Claim(fmt.Sprint(i), now.Add(5*time.Second), now) {
			t.Fatalf("claim %d of a fresh key was refused", i)
		}
		maxLive = max(maxLive, len(s.seen))
		maxQueue = max(maxQueue, cap(s.queue))
	}
	if maxLive > 11 || maxQueue > 64 {
		t.Errorf("under steady use the set held up to %d keys and a %d-entry queue, want at most 11 and 64", maxLive, maxQueue)
	}
}
