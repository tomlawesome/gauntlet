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

func TestClaimOnce(t *testing.T) {
	s := New()
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

// TestRefusedThroughItsOwnForgetTime: a key stays refused up to and at
// its forget time, and is free again only strictly after it.
func TestRefusedThroughItsOwnForgetTime(t *testing.T) {
	s := New()
	forget := t0.Add(5 * time.Minute)
	s.Claim("a", forget, t0)
	if s.Claim("a", forget, forget.Add(-time.Nanosecond)) {
		t.Fatal("the key was accepted again before its forget time")
	}
	after := forget.Add(time.Nanosecond)
	if s.Spent("a", after) {
		t.Fatal("the key is still held after its forget time")
	}
	if !s.Claim("a", forget.Add(5*time.Minute), after) {
		t.Fatal("the key was refused after its forget time")
	}
}

// TestHeldAtExactlyItsForgetTime: at the forget time itself the key is
// still held. gate's pending-login decode accepts a cookie at exactly
// IssuedAt plus its maximum age, so forgetting at that instant would let
// it be replayed there.
func TestHeldAtExactlyItsForgetTime(t *testing.T) {
	s := New()
	forget := t0.Add(5 * time.Minute)
	s.Claim("a", forget, t0)
	if !s.Spent("a", forget) {
		t.Fatal("the key was forgotten at exactly its forget time")
	}
	if s.Claim("a", forget.Add(time.Minute), forget) {
		t.Fatal("the key was claimed again at exactly its forget time")
	}
}

// TestForgottenLateNeverEarly: a key claimed after a longer-lived one is
// forgotten only once that one goes -- late, never early -- and both go
// together once the head's time has passed.
func TestForgottenLateNeverEarly(t *testing.T) {
	s := New()
	s.Claim("long", t0.Add(10*time.Minute), t0)
	s.Claim("short", t0.Add(time.Minute), t0)
	if !s.Spent("short", t0.Add(2*time.Minute)) {
		t.Fatal("a key behind a longer-lived head was forgotten before the head went")
	}
	if s.Claim("short", t0.Add(time.Hour), t0.Add(2*time.Minute)) {
		t.Fatal("a key behind a longer-lived head was accepted again")
	}
	later := t0.Add(10*time.Minute + time.Nanosecond)
	if s.Spent("long", later) || s.Spent("short", later) {
		t.Fatal("keys were held after the head's forget time")
	}
	if len(s.seen) != 0 || len(s.queue)-s.head != 0 {
		t.Errorf("after both went the set holds %d keys and %d queued", len(s.seen), len(s.queue)-s.head)
	}
}

// TestAForgetTimeAlreadyPastIsRecordedThenMayBePruned pins what happens
// when a caller passes a forget time already behind now: the claim
// succeeds and the key is recorded, and the next call may prune it, so a
// second claim then succeeds. That is acceptable because both callers
// claim only after their acceptance check passed on that same forget
// time; once it is past, the acceptance check refuses first.
func TestAForgetTimeAlreadyPastIsRecordedThenMayBePruned(t *testing.T) {
	s := New()
	if !s.Claim("a", t0.Add(-time.Minute), t0) {
		t.Fatal("the claim was refused")
	}
	if _, held := s.seen["a"]; !held || len(s.queue)-s.head != 1 {
		t.Fatal("a key with a forget time already past was not recorded")
	}
	if s.Spent("a", t0) {
		t.Fatal("the next call did not prune a key whose forget time had passed")
	}
}

// TestMonotonicNowAgainstAWallClockForgetTime: now from time.Now()
// carries a monotonic reading and a forget time from a JSON round trip
// does not. The set must compare them on the wall clock: the key is held
// before the forget time and gone at it, and nothing it stores carries a
// monotonic reading.
func TestMonotonicNowAgainstAWallClockForgetTime(t *testing.T) {
	s := New()
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
	if got := s.seen["a"]; strings.Contains(got.String(), "m=") || !got.Equal(forget) {
		t.Errorf("the stored forget time is %v, want the wall-clock %v", got, forget)
	}
	// The forget time itself, reached from a monotonic reading: on the
	// wall clock it is the forget time, so the key is still held; a
	// nanosecond later it is gone.
	if !s.Spent("a", now.Add(5*time.Minute)) {
		t.Error("the key was forgotten by its wall-clock forget time")
	}
	if s.Spent("a", now.Add(5*time.Minute+time.Nanosecond)) {
		t.Error("the key was held after its wall-clock forget time")
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
	s := New()
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
	s := New()
	for i := range 100 {
		s.Claim(fmt.Sprint(i), t0.Add(time.Duration(i+1)*time.Second), t0)
	}
	s.Spent("x", t0.Add(80*time.Second+time.Nanosecond))
	if s.head != 0 || len(s.queue) != 20 || len(s.seen) != 20 {
		t.Errorf("after 80 of 100 expired: head %d, queue %d, map %d; want 0, 20, 20", s.head, len(s.queue), len(s.seen))
	}
}

// TestPruningLooksOnlyAtTheHead: however many live keys the set holds, a
// prune looks at the entries it drops plus the one it stops at -- never
// the rest. (The set this replaced scanned every key under its lock.)
func TestPruningLooksOnlyAtTheHead(t *testing.T) {
	s := New()
	for i := range 30000 {
		s.Claim(fmt.Sprintf("live-%d", i), t0.Add(time.Hour), t0)
	}
	if n := s.pruneLocked(t0.Add(time.Minute)); n != 1 {
		t.Errorf("a prune with 30000 live keys looked at %d entries, want 1", n)
	}
	s = New()
	for i := range 10 {
		s.Claim(fmt.Sprintf("old-%d", i), t0.Add(time.Second), t0)
	}
	for i := range 30000 {
		s.Claim(fmt.Sprintf("live-%d", i), t0.Add(time.Hour), t0)
	}
	if n := s.pruneLocked(t0.Add(time.Minute)); n != 11 {
		t.Errorf("a prune dropping 10 keys ahead of 30000 live ones looked at %d entries, want 11", n)
	}
}

// TestTheSetStaysBoundedUnderSteadyUse: a hundred thousand claims, each
// one second after the last and forgotten five seconds after it is made
// -- a steady stream of sign-ins -- leave the set holding only the last
// few keys, and the queue's backing array no larger than a small
// multiple of that.
func TestTheSetStaysBoundedUnderSteadyUse(t *testing.T) {
	s := New()
	maxLive, maxQueue := 0, 0
	for i := range 100000 {
		now := t0.Add(time.Duration(i) * time.Second)
		if !s.Claim(fmt.Sprint(i), now.Add(5*time.Second), now) {
			t.Fatalf("claim %d of a fresh key was refused", i)
		}
		maxLive = max(maxLive, len(s.seen))
		maxQueue = max(maxQueue, cap(s.queue))
	}
	if maxLive > 7 || maxQueue > 64 {
		t.Errorf("under steady use the set held up to %d keys and a %d-entry queue, want at most 7 and 64", maxLive, maxQueue)
	}
}
