package gauntlet

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A session idle past its timeout but inside the ceiling is refused by
// Validate and kept, so it can be resumed (gauntlet#71).
func TestSessionTimedOutInsideCeilingIsRefusedButKept(t *testing.T) {
	s := NewSessionStore(time.Hour, 24*time.Hour)
	t0 := time.Now()
	sess := s.Create("user-1", t0)
	idle := t0.Add(2 * time.Hour)

	if _, ok := s.Validate(sess.ID, idle); ok {
		t.Fatal("a timed-out session authenticated")
	}
	if got, ok := s.Resumable(sess.ID, idle); !ok || got.ID != sess.ID {
		t.Fatalf("Resumable = %+v, %v; want the timed-out session", got, ok)
	}
	// Refusing it did not extend it: still refused a minute later.
	if _, ok := s.Validate(sess.ID, idle.Add(time.Minute)); ok {
		t.Error("a timed-out session authenticated after an earlier refusal")
	}
	if got := s.ListForUser("user-1", idle); len(got) != 0 {
		t.Errorf("a timed-out session was listed as live: %+v", got)
	}
}

func TestSessionResumableRefusesLiveUnknownAndPastCeiling(t *testing.T) {
	s := NewSessionStore(time.Hour, 24*time.Hour)
	t0 := time.Now()
	sess := s.Create("user-1", t0)

	if _, ok := s.Resumable(sess.ID, t0.Add(time.Minute)); ok {
		t.Error("a live session reported resumable")
	}
	if _, ok := s.Resumable("no-such-id", t0); ok {
		t.Error("an unknown ID reported resumable")
	}
	past := t0.Add(24*time.Hour + time.Second)
	if _, ok := s.Resumable(sess.ID, past); ok {
		t.Error("a session past the ceiling reported resumable")
	}
	if got := heldSessions(s); got != 0 {
		t.Errorf("%d sessions held after the ceiling found one, want it evicted", got)
	}
}

// With no ceiling nothing is resumable: the idle timeout is the end, as
// before.
func TestSessionNoCeilingMeansNoResume(t *testing.T) {
	s := NewSessionStore(time.Hour, 0)
	t0 := time.Now()
	sess := s.Create("user-1", t0)
	idle := t0.Add(2 * time.Hour)

	if _, ok := s.Resumable(sess.ID, idle); ok {
		t.Error("a session in a store with no ceiling was resumable")
	}
	if _, ok := s.Validate(sess.ID, idle); ok {
		t.Error("an idle session authenticated")
	}
	if _, ok := s.Resume(sess.ID, SessionClient{}, idle); ok {
		t.Error("Resume succeeded in a store with no ceiling")
	}
}

// Resume gives a new ID, keeps the account and the original IssuedAt
// (the ceiling does not move), ends the old ID, and never lets the new
// expiry pass the ceiling.
func TestSessionResumeKeepsAccountAndCeiling(t *testing.T) {
	s := NewSessionStore(time.Hour, 24*time.Hour)
	t0 := time.Now()
	old := s.CreateFrom("user-1", SessionClient{Address: "198.51.100.1", Unusual: 1}, t0)

	at := t0.Add(2 * time.Hour)
	got, ok := s.Resume(old.ID, SessionClient{Address: "198.51.100.2", UserAgent: "ua\x00x"}, at)
	if !ok {
		t.Fatal("Resume refused a timed-out session inside its ceiling")
	}
	if got.ID == old.ID || got.UserID != "user-1" || !got.IssuedAt.Equal(t0) {
		t.Errorf("resumed %+v from %+v: want a new ID, the same account and IssuedAt", got, old)
	}
	if !got.ExpiresAt.Equal(at.Add(time.Hour)) || !got.LastUsedAt.Equal(at) {
		t.Errorf("resumed expiry %v, last used %v; want %v and %v", got.ExpiresAt, got.LastUsedAt, at.Add(time.Hour), at)
	}
	if got.Client.Address != "198.51.100.2" || got.Client.UserAgent != "uax" || got.Client.Unusual != 1 {
		t.Errorf("resumed client %+v: want the new address and cleaned agent, and the original signals", got.Client)
	}
	if _, ok := s.Validate(old.ID, at); ok {
		t.Error("the old ID still authenticates")
	}
	if _, ok := s.Resumable(old.ID, at); ok {
		t.Error("the old ID is still resumable")
	}
	if _, ok := s.Validate(got.ID, at.Add(time.Minute)); !ok {
		t.Error("the new session does not authenticate")
	}
	if n := len(s.ListForUser("user-1", at)); n != 1 {
		t.Errorf("%d live sessions listed after a resume, want 1", n)
	}

	// Near the ceiling the new expiry is cut to it, and it ends there.
	late := t0.Add(23*time.Hour + 30*time.Minute)
	s2 := NewSessionStore(time.Hour, 24*time.Hour)
	o2 := s2.Create("user-1", t0)
	r2, ok := s2.Resume(o2.ID, SessionClient{}, late)
	if !ok {
		t.Fatal("Resume refused inside the ceiling")
	}
	if want := t0.Add(24 * time.Hour); !r2.ExpiresAt.Equal(want) {
		t.Errorf("expiry %v, want the ceiling %v", r2.ExpiresAt, want)
	}
	if _, ok := s2.Validate(r2.ID, t0.Add(24*time.Hour+time.Second)); ok {
		t.Error("a resumed session outlived the original ceiling")
	}
}

// A resumed session can itself time out and be resumed again, still
// under the one ceiling.
func TestSessionResumeTwiceThenCeilingEnds(t *testing.T) {
	s := NewSessionStore(time.Hour, 24*time.Hour)
	t0 := time.Now()
	sess := s.Create("user-1", t0)
	for i := 1; i <= 2; i++ {
		var ok bool
		sess, ok = s.Resume(sess.ID, SessionClient{}, t0.Add(time.Duration(i)*3*time.Hour))
		if !ok {
			t.Fatalf("resume %d refused", i)
		}
	}
	if _, ok := s.Resume(sess.ID, SessionClient{}, t0.Add(25*time.Hour)); ok {
		t.Error("resumed past the ceiling")
	}
}

func TestSessionResumeRefusesLiveUnknownAndSpent(t *testing.T) {
	s := NewSessionStore(time.Hour, 24*time.Hour)
	t0 := time.Now()
	sess := s.Create("user-1", t0)
	if _, ok := s.Resume(sess.ID, SessionClient{}, t0.Add(time.Minute)); ok {
		t.Error("a live session was resumed")
	}
	if _, ok := s.Resume("no-such-id", SessionClient{}, t0); ok {
		t.Error("an unknown ID was resumed")
	}
	at := t0.Add(2 * time.Hour)
	if _, ok := s.Resume(sess.ID, SessionClient{}, at); !ok {
		t.Fatal("first resume refused")
	}
	if _, ok := s.Resume(sess.ID, SessionClient{}, at); ok {
		t.Error("a second resume of the same ID succeeded")
	}
}

// A resumable session is dropped on logout and when the account's
// sessions are ended, like a live one.
func TestSessionResumableEndsOnRevoke(t *testing.T) {
	s := NewSessionStore(time.Hour, 24*time.Hour)
	t0 := time.Now()
	a := s.Create("user-1", t0)
	b := s.Create("user-1", t0)
	other := s.Create("user-2", t0)
	at := t0.Add(2 * time.Hour)

	s.Revoke(a.ID)
	if _, ok := s.Resumable(a.ID, at); ok {
		t.Error("a revoked session stayed resumable")
	}
	if n := s.RevokeAllForUserCount("user-1"); n != 1 {
		t.Errorf("RevokeAllForUserCount ended %d, want the 1 timed-out session", n)
	}
	if _, ok := s.Resumable(b.ID, at); ok {
		t.Error("a session stayed resumable after the account's sessions ended")
	}
	if _, ok := s.Resumable(other.ID, at); !ok {
		t.Error("another account's session was ended")
	}
}

// The sweep keeps a resumable session until its ceiling and drops it
// then, so the map stays bounded by the sessions of the last ceiling.
func TestSessionSweepKeepsResumableUntilCeiling(t *testing.T) {
	const n = 1000
	s := NewSessionStore(time.Hour, 24*time.Hour)
	t0 := time.Now()
	for range n {
		s.Create("user-1", t0)
	}
	// Timed out but inside the ceiling: all kept, however many sweeps.
	for range n {
		s.Create("user-2", t0.Add(2*time.Hour))
	}
	if got := heldSessions(s); got != 2*n {
		t.Errorf("%d sessions held, want the %d timed-out and %d live", got, n, n)
	}
	// Past the first batch's ceiling: it is swept, the later one is not.
	at := t0.Add(24*time.Hour + time.Minute)
	for range 2 * n {
		s.Create("user-3", at)
	}
	if got := heldSessions(s); got != 2*n+n {
		t.Errorf("%d sessions held, want the second batch (%d, timed out) and the new %d", got, n, 2*n)
	}
}

// TestSessionResumeConcurrentlyOnlyOnce: two browsers presenting the same
// timed-out cookie at once (or a request racing the password check) may
// turn it into at most one live session; a second would be a session
// nobody signed in for.
func TestSessionResumeConcurrentlyOnlyOnce(t *testing.T) {
	s := NewSessionStore(time.Hour, 24*time.Hour)
	t0 := time.Now()
	sess := s.Create("user-1", t0)
	at := t0.Add(2 * time.Hour)
	const n = 16
	var wg sync.WaitGroup
	var won atomic.Int32
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := s.Resume(sess.ID, SessionClient{}, at); ok {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := won.Load(); got != 1 {
		t.Errorf("%d of %d concurrent resumes of one session succeeded, want exactly 1", got, n)
	}
}
