package gauntlet

import (
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// ReserveAccountDecision says why an attempt was admitted or refused
// (#45, #53): the attempt that starts a lockout, the one that disables
// sign-in, and the refusals during a lockout and a disable.

func TestReserveAccountDecisionReportsTheLockoutItStarts(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := escalationStart

	for i := range 4 {
		d := l.ReserveAccountDecision(s, id, at)
		if !d.Allowed || d.Locked || d.Disabled || d.LockoutStarted || d.DisabledNow || !d.LockedUntil.IsZero() {
			t.Fatalf("attempt %d of the window = %+v, want only Allowed", i+1, d)
		}
	}
	d := l.ReserveAccountDecision(s, id, at)
	if !d.Allowed || !d.LockoutStarted || d.Locked || d.DisabledNow {
		t.Fatalf("the attempt that fills the window = %+v, want Allowed and LockoutStarted", d)
	}
	if want := at.Add(5 * time.Minute); !d.LockedUntil.Equal(want) {
		t.Errorf("LockedUntil = %v, want %v", d.LockedUntil, want)
	}
	if d.Lockouts != 1 {
		t.Errorf("Lockouts = %d, want 1", d.Lockouts)
	}

	refused := l.ReserveAccountDecision(s, id, at.Add(time.Minute))
	if refused.Allowed || !refused.Locked || refused.Disabled || refused.LockoutStarted {
		t.Fatalf("an attempt during the lockout = %+v, want Locked", refused)
	}
	if !refused.LockedUntil.Equal(d.LockedUntil) {
		t.Errorf("refusal's LockedUntil = %v, want the lockout's end %v", refused.LockedUntil, d.LockedUntil)
	}

	// The second lockout is counted on from the first.
	at = d.LockedUntil.Add(time.Second)
	for range 4 {
		l.ReserveAccountDecision(s, id, at)
	}
	if d := l.ReserveAccountDecision(s, id, at); !d.LockoutStarted || d.Lockouts != 2 {
		t.Errorf("the second lockout's decision = %+v, want LockoutStarted with Lockouts 2", d)
	}
}

func TestReserveAccountDecisionReportsTheDisable(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := failConsecutively(t, l, s, id, MaxConsecutiveLoginFailures-1, escalationStart)

	d := l.ReserveAccountDecision(s, id, at)
	if !d.Allowed || !d.DisabledNow {
		t.Fatalf("the fiftieth failure's decision = %+v, want Allowed and DisabledNow", d)
	}
	refused := l.ReserveAccountDecision(s, id, at.Add(23*time.Hour))
	if refused.Allowed || !refused.Disabled || refused.DisabledNow {
		t.Fatalf("an attempt on a disabled account = %+v, want Disabled only", refused)
	}
}

// Neither Locked nor Disabled with Allowed false is the in-memory count
// refusing: a lockout cleared by hand while this limiter still counts
// the attempts behind it.
func TestReserveAccountDecisionInMemoryRefusal(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	failWindow(t, l, s, id, escalationStart)
	if err := s.UnlockLogin(id); err != nil {
		t.Fatal(err)
	}
	d := l.ReserveAccountDecision(s, id, escalationStart.Add(time.Second))
	if d.Allowed || d.Locked || d.Disabled {
		t.Fatalf("decision = %+v, want refused with neither Locked nor Disabled", d)
	}
}

// ReserveAccount is the decision's Allowed.
func TestReserveAccountWrapsTheDecision(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	l := mustNewLoginLimiter(t, 2, time.Minute)
	for i := range 2 {
		if !l.ReserveAccount(s, id, escalationStart) {
			t.Fatalf("attempt %d under the threshold was refused", i+1)
		}
	}
	if l.ReserveAccount(s, id, escalationStart) {
		t.Fatal("an attempt during the lockout was admitted")
	}
}

// ReserveKnownBrowserDecision reports the disable a known browser's
// failures bring on (#45), so gate audits it as it does the ordinary
// path's; ReserveKnownBrowser is its Allowed.
func TestReserveKnownBrowserDecisionReportsTheDisable(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := failConsecutively(t, l, s, id, MaxConsecutiveLoginFailures-5, escalationStart)

	for i := range 4 {
		d := l.ReserveKnownBrowserDecision(s, id, at)
		if !d.Allowed || d.DisabledNow || d.Disabled {
			t.Fatalf("known-browser attempt %d = %+v, want only Allowed", i+1, d)
		}
	}
	d := l.ReserveKnownBrowserDecision(s, id, at)
	if !d.Allowed || !d.DisabledNow || d.Lockouts != MaxConsecutiveLoginFailures/5 {
		t.Fatalf("the attempt that fills the allowance = %+v, want Allowed and DisabledNow", d)
	}
	if d := l.ReserveKnownBrowserDecision(s, id, at.Add(time.Hour)); d.Allowed || !d.Disabled || d.DisabledNow {
		t.Errorf("an attempt once disabled = %+v, want Disabled", d)
	}
	if l.ReserveKnownBrowser(s, id, at.Add(time.Hour)) {
		t.Error("ReserveKnownBrowser admitted an attempt on a disabled account")
	}
}
