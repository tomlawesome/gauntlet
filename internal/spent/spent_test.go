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

// TestRefusedUntilItsOwnForgetTime: a key stays refused up to its forget
// time and is free again at it.
func TestRefusedUntilItsOwnForgetTime(t *testing.T) {
	s := New()
	forget := t0.Add(5 * time.Minute)
	s.Claim("a", forget, t0)
	if s.Claim("a", forget, forget.Add(-time.Nanosecond)) {
		t.Fatal("the key was accepted again before its forget time")
	}
	if s.Spent("a", forget) {
		t.Fatal("the key is still held at its forget time")
	}
	if !s.Claim("a", forget.Add(5*time.Minute), forget) {
		t.Fatal("the key was refused after its forget time")
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
	later := t0.Add(10 * time.Minute)
	if s.Spent("long", later) || s.Spent("short", later) {
		t.Fatal("keys were held after the head's forget time")
	}
	if len(s.seen) != 0 || len(s.queue)-s.head != 0 {
		t.Errorf("after both went the set holds %d keys and %d queued", len(s.seen), len(s.queue)-s.head)
	}
}

// TestAForgetTimeAlreadyPastIsStillRecorded: a caller may pass a forget
// time at or before now; the claim succeeds and the key is recorded, to
// be dropped at the next prune that reaches it. (Whether it should also
// be refused by a second claim at that same instant is an open question
// on #20: the prune-then-test order this package was ruled to use drops
// it first.)
func TestAForgetTimeAlreadyPastIsStillRecorded(t *testing.T) {
	s := New()
	if !s.Claim("a", t0.Add(-time.Minute), t0) {
		t.Fatal("the claim was refused")
	}
	if _, held := s.seen["a"]; !held || len(s.queue)-s.head != 1 {
		t.Fatal("a key with a forget time already past was not recorded")
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
	if !s.Spent("a", now.Add(5*time.Minute-time.Second)) {
		t.Error("the key was forgotten before its wall-clock forget time")
	}
	// The same instant as forget, but reached from a monotonic reading:
	// on the wall clock it is the forget time, so the key is gone.
	if s.Spent("a", now.Add(5*time.Minute)) {
		t.Error("the key was held at its wall-clock forget time")
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
	s.Spent("x", t0.Add(80*time.Second))
	if s.head != 0 || len(s.queue) != 20 || len(s.seen) != 20 {
		t.Errorf("after 80 of 100 expired: head %d, queue %d, map %d; want 0, 20, 20", s.head, len(s.queue), len(s.seen))
	}
}

// TestClaimCostIsFlat: the cost of a claim does not grow with the number
// of live keys (the set it replaces scanned every key under its lock).
// Compared as the best of several runs, within a generous multiple, so
// a noisy host does not fail it; a scan would be about thirty times
// slower at 30k than at 1k.
func TestClaimCostIsFlat(t *testing.T) {
	perClaim := func(n int) time.Duration {
		best := time.Duration(1 << 62)
		for run := range 5 {
			s := New()
			for i := range n {
				s.Claim(fmt.Sprintf("k-%d", i), t0.Add(time.Hour), t0)
			}
			const k = 2000
			start := time.Now()
			for i := range k {
				s.Claim(fmt.Sprintf("new-%d-%d", run, i), t0.Add(time.Hour), t0)
			}
			if d := time.Since(start) / k; d < best {
				best = d
			}
		}
		return best
	}
	small, large := perClaim(1000), perClaim(30000)
	if large > 8*small+time.Microsecond {
		t.Errorf("a claim takes %v with 30k keys held and %v with 1k; want it flat", large, small)
	}
}
