package gauntlet

import (
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// The escalating lockout and the disable (#44), through the account's
// own record. These use only what an account's lockout looked like
// before #44 -- its end on the record, and whether an attempt is
// admitted -- so they say the same thing about any build.

// escalationStart is the clock every test here starts from.
var escalationStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// failWindow makes the consumers' five failed attempts on id at at, all
// admitted, and returns the end of the lockout the fifth starts.
func failWindow(t *testing.T, l *LoginLimiter, lockouts AccountLockouts, id string, at time.Time) time.Time {
	t.Helper()
	for i := range 5 {
		if !l.ReserveAccount(lockouts, id, at) {
			t.Fatalf("attempt %d of the window at %v was refused", i+1, at)
		}
	}
	return lockouts.LoginLockedUntil(id)
}

// failConsecutively makes n failed attempts in a row on id from at,
// waiting out each lockout they start, and returns a moment after the
// last of them and after any lockout it started.
func failConsecutively(t *testing.T, l *LoginLimiter, s *Store, id string, n int, at time.Time) time.Time {
	t.Helper()
	for i := range n {
		if !l.ReserveAccount(s, id, at) {
			t.Fatalf("failure %d of %d was refused at %v", i+1, n, at)
		}
		if until := s.LoginLockedUntil(id); until.After(at) {
			at = until
		}
		at = at.Add(time.Second)
	}
	return at
}

// Each lockout lasts three times the one before -- 5, 15 and 45 minutes
// at the consumers' 5 attempts per 5 minutes -- then an hour each (#70),
// and refuses every attempt until it ends. A lockout
// running out does not reset the count.
func TestEachLockoutLastsThreeTimesTheOneBefore(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := escalationStart
	// Nine lockouts: 45 failures, short of the 50 that disable sign-in.
	for n, minutes := range []time.Duration{5, 15, 45, 60, 60, 60, 60, 60, 60} {
		until := failWindow(t, l, s, id, at)
		if got, want := until.Sub(at), minutes*time.Minute; got != want {
			t.Errorf("lockout %d lasts %v, want %v", n+1, got, want)
		}
		if l.ReserveAccount(s, id, until.Add(-time.Second)) {
			t.Fatalf("lockout %d let an attempt through a second before it ended", n+1)
		}
		at = until.Add(time.Second)
	}
}

// The count of lockouts is on the account's record, so a restart -- a
// new process with a fresh limiter reading the same backend -- carries
// on from it: the third lockout is 45 minutes, not a first one again.
func TestLockoutCountSurvivesARestart(t *testing.T) {
	m := persist.NewMemory()
	s, id := openLockoutStore(t, m)
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	until := failWindow(t, l, s, id, escalationStart)
	until = failWindow(t, l, s, id, until.Add(time.Second))

	restarted, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	fresh := mustNewLoginLimiter(t, 5, 5*time.Minute)
	if fresh.ReserveAccount(restarted, id, until.Add(-time.Second)) {
		t.Fatal("a restart lifted the second lockout")
	}
	at := until.Add(time.Second)
	if got, want := failWindow(t, fresh, restarted, id, at).Sub(at), 45*time.Minute; got != want {
		t.Errorf("after a restart the third lockout lasts %v, want %v: the restart forgot the lockouts before it", got, want)
	}
}

// Fifty failed attempts in a row disable the account's sign-in: an
// attempt 22 hours later is refused, by this limiter and by a fresh one
// after a restart (it lifts itself after 24, #70: see
// lockout_disable_expiry_test.go). Forty-nine do not.
func TestFiftyConsecutiveFailuresDisableSignIn(t *testing.T) {
	t.Run("49 leave it open", func(t *testing.T) {
		s, id := openLockoutStore(t, persist.NewMemory())
		l := mustNewLoginLimiter(t, 5, 5*time.Minute)
		at := failConsecutively(t, l, s, id, MaxConsecutiveLoginFailures-1, escalationStart)
		if !l.ReserveAccount(s, id, at.Add(365*24*time.Hour)) {
			t.Error("49 failures in a row disabled sign-in; the limit is 50")
		}
	})
	t.Run("50 close it", func(t *testing.T) {
		m := persist.NewMemory()
		s, id := openLockoutStore(t, m)
		l := mustNewLoginLimiter(t, 5, 5*time.Minute)
		at := failConsecutively(t, l, s, id, MaxConsecutiveLoginFailures, escalationStart)
		later := at.Add(22 * time.Hour)
		if l.ReserveAccount(s, id, later) {
			t.Fatal("an attempt 22 hours after 50 failures in a row was admitted")
		}
		restarted, err := OpenStore(m, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if mustNewLoginLimiter(t, 5, 5*time.Minute).ReserveAccount(restarted, id, later) {
			t.Error("a restart lifted the disabled sign-in")
		}
	})
}

// A correct password alone -- the password step of an account that
// still owes a second factor (ReleaseAccount) -- is not a completed
// sign-in, and does not reset the count: the next lockout is the third.
func TestACorrectPasswordAloneDoesNotResetTheLockoutCount(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := failConsecutively(t, l, s, id, 10, escalationStart)

	if !l.ReserveAccount(s, id, at) {
		t.Fatal("the right password was refused after two lockouts had ended")
	}
	l.ReleaseAccount(s, id, at)

	at = at.Add(time.Second)
	if got, want := failWindow(t, l, s, id, at).Sub(at), 45*time.Minute; got != want {
		t.Errorf("after a correct password the next lockout lasts %v, want the third's %v", got, want)
	}
}

// A new password -- the owner's, an admin's through SetPassword, or an
// admin's reset code -- resets the count: the guesses were at the old
// password. The next lockout is a first one again. A disabled sign-in
// is not lifted by SetPassword; a reset code, an admin action, does lift
// it (TestAResetCodeLiftsADisabledSignIn).
func TestPasswordChangeResetsTheLockoutCountButNotADisable(t *testing.T) {
	changes := map[string]func(t *testing.T, s *Store, id string, at time.Time){
		"SetPassword": func(t *testing.T, s *Store, _ string, at time.Time) {
			if err := s.SetPassword("alice", "a-brand-new-password", at); err != nil {
				t.Fatal(err)
			}
		},
		"IssueResetCode": func(t *testing.T, s *Store, id string, at time.Time) {
			if _, _, err := s.IssueResetCode(id, at); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, change := range changes {
		t.Run(name+" resets the count", func(t *testing.T) {
			s, id := openLockoutStore(t, persist.NewMemory())
			l := mustNewLoginLimiter(t, 5, 5*time.Minute)
			at := failConsecutively(t, l, s, id, 10, escalationStart)
			change(t, s, id, at)
			at = at.Add(time.Second)
			if got, want := failWindow(t, l, s, id, at).Sub(at), 5*time.Minute; got != want {
				t.Errorf("after a new password the next lockout lasts %v, want a first one's %v", got, want)
			}
		})
		if name == "IssueResetCode" {
			continue // lifts it, by the owner's decision of 2026-10-02
		}
		t.Run(name+" keeps a disable", func(t *testing.T) {
			s, id := openLockoutStore(t, persist.NewMemory())
			l := mustNewLoginLimiter(t, 5, 5*time.Minute)
			at := failConsecutively(t, l, s, id, MaxConsecutiveLoginFailures, escalationStart)
			change(t, s, id, at)
			if l.ReserveAccount(s, id, at.Add(time.Hour)) {
				t.Error("a new password lifted a disabled sign-in")
			}
		})
	}
}

// A limiter given no store keeps the count of lockouts in memory, and
// escalates the same way.
func TestLockoutsEscalateWithoutAStore(t *testing.T) {
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := escalationStart
	for n, minutes := range []time.Duration{5, 15, 45} {
		for i := range 5 {
			if !l.ReserveAccount(nil, "u1", at) {
				t.Fatalf("lockout %d: attempt %d refused", n+1, i+1)
			}
		}
		end := at.Add(minutes * time.Minute)
		if l.ReserveAccount(nil, "u1", end.Add(-time.Second)) {
			t.Fatalf("lockout %d (%v) let an attempt through a second before it ended", n+1, minutes*time.Minute)
		}
		at = end.Add(time.Second)
	}
}

// A stream of wrong guesses is not a stream of writes, however far the
// lockouts escalate: each costs one save as it starts (the count of
// lockouts and, at the fiftieth failure, the disable go in that same
// save) and one as the first attempt after it clears it -- the economy
// a lockout has always had -- and none per guess. A disabled account
// costs none at all.
func TestEscalatingLockoutsCostOneWriteToStartAndOneToClear(t *testing.T) {
	b := &countingBackend{Memory: persist.NewMemory()}
	s, id := openLockoutStore(t, b)
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := escalationStart
	// Ten lockouts: the tenth starts at the fiftieth failure.
	for n := 1; n <= 10; n++ {
		start := b.saves.Load()
		for i := range 500 {
			l.ReserveAccount(s, id, at.Add(time.Duration(i)*time.Millisecond))
		}
		want := int64(2) // the clear of the lockout before, then this one's start
		if n == 1 {
			want = 1
		}
		if got := b.saves.Load() - start; got != want {
			t.Errorf("lockout %d: 500 guesses cost %d saves, want %d", n, got, want)
		}
		at = s.LoginLockedUntil(id).Add(time.Second)
	}

	start := b.saves.Load()
	for i := range 1000 {
		if l.ReserveAccount(s, id, at.Add(time.Duration(i)*time.Second)) {
			t.Fatal("a guess was admitted after 50 failures in a row")
		}
	}
	if got := b.saves.Load() - start; got != 0 {
		t.Errorf("1000 guesses at a disabled account cost %d saves, want none", got)
	}
}
