package gauntlet

import (
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// The disable at MaxConsecutiveLoginFailures lifts itself
// LoginDisableDuration after it began (#70), with no unlock, and the run
// of failures starts again.

// disabledAt makes the fiftieth consecutive failure on id and returns
// when it was made, which is when the account's sign-in was disabled.
func disabledAt(t *testing.T, l *LoginLimiter, s *Store, id string) time.Time {
	t.Helper()
	at := failConsecutively(t, l, s, id, MaxConsecutiveLoginFailures-1, escalationStart)
	if !l.ReserveAccount(s, id, at) {
		t.Fatal("the fiftieth attempt was refused")
	}
	if got := mustGet(t, s, id).LoginDisabledAt; !got.Equal(at) {
		t.Fatalf("test setup: LoginDisabledAt = %v, want %v", got, at)
	}
	return at
}

func TestADisableLiftsItselfAfterTwentyFourHours(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := disabledAt(t, l, s, id)

	// In force until the last second.
	d := l.ReserveAccountDecision(s, id, at.Add(LoginDisableDuration-time.Second))
	if d.Allowed || !d.Disabled {
		t.Fatalf("a second before the disable lifts: %+v, want refused as disabled", d)
	}
	if !mustGet(t, s, id).LoginDisabled(at.Add(LoginDisableDuration - time.Second)) {
		t.Error("User.LoginDisabled is false a second before the disable lifts")
	}

	// Then the first attempt is admitted and clears the record the way
	// UnlockLogin does: no disable, no lockout, no count of lockouts.
	lifted := at.Add(LoginDisableDuration)
	if mustGet(t, s, id).LoginDisabled(lifted) {
		t.Error("User.LoginDisabled is true once the disable has lifted")
	}
	d = l.ReserveAccountDecision(s, id, lifted)
	if !d.Allowed || d.Disabled || d.DisabledNow || d.Lockouts != 0 {
		t.Fatalf("the attempt after the disable lifted: %+v, want admitted, not disabled, no lockouts", d)
	}
	u := mustGet(t, s, id)
	if !u.LoginDisabledAt.IsZero() || u.LoginLockoutCount != 0 || !u.LoginLockedUntil.IsZero() {
		t.Errorf("after the lift: disabled %v, count %d, locked until %v; want all clear",
			u.LoginDisabledAt, u.LoginLockoutCount, u.LoginLockedUntil)
	}
}

// The count restarts: a failure after the lift does not disable the
// account again at once, and it takes the whole run -- ten lockouts'
// worth -- to disable it a second time.
func TestTheCountRestartsWhenTheDisableLifts(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := disabledAt(t, l, s, id).Add(LoginDisableDuration)

	// Failures 1 to 49 of the new run are all admitted and none disables.
	end := failConsecutively(t, l, s, id, MaxConsecutiveLoginFailures-1, at)
	u := mustGet(t, s, id)
	if !u.LoginDisabledAt.IsZero() || u.LoginLockoutCount != 9 {
		t.Fatalf("after 49 failures since the lift: disabled %v, count %d; want not disabled, 9", u.LoginDisabledAt, u.LoginLockoutCount)
	}
	if !l.ReserveAccount(s, id, end) {
		t.Fatal("the fiftieth failure of the new run was refused")
	}
	if mustGet(t, s, id).LoginDisabledAt.IsZero() {
		t.Error("the fiftieth failure of the new run did not disable sign-in")
	}
}

// A restart changes nothing: the disable is on the record, so a fresh
// limiter holds it for the same 24 hours and lifts it at the same
// moment.
func TestADisableSurvivesARestartAndLiftsOnTime(t *testing.T) {
	m := persist.NewMemory()
	s, id := openLockoutStore(t, m)
	at := disabledAt(t, mustNewLoginLimiter(t, 5, 5*time.Minute), s, id)

	restarted, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	if l.ReserveAccount(restarted, id, at.Add(23*time.Hour)) {
		t.Error("a restarted process admitted an attempt 23 hours into the disable")
	}
	if !l.ReserveAccount(restarted, id, at.Add(LoginDisableDuration)) {
		t.Error("a restarted process refused an attempt once the disable had lifted")
	}
	if u := mustGet(t, restarted, id); !u.LoginDisabledAt.IsZero() || u.LoginLockoutCount != 0 {
		t.Errorf("after the lift: disabled %v, count %d; want clear", u.LoginDisabledAt, u.LoginLockoutCount)
	}
}

// A known browser's allowance is no way round a disable, and lifts with
// it.
func TestAKnownBrowserAllowanceLiftsWithTheDisable(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := disabledAt(t, l, s, id)

	if d := l.ReserveKnownBrowserDecision(s, id, at.Add(time.Hour)); d.Allowed || !d.Disabled {
		t.Fatalf("known browser during the disable: %+v, want refused as disabled", d)
	}
	d := l.ReserveKnownBrowserDecision(s, id, at.Add(LoginDisableDuration))
	if !d.Allowed || d.Disabled || d.Lockouts != 0 {
		t.Fatalf("known browser after the disable lifted: %+v, want admitted with no lockouts", d)
	}
	if u := mustGet(t, s, id); !u.LoginDisabledAt.IsZero() || u.LoginLockoutCount != 0 {
		t.Errorf("after the lift: disabled %v, count %d; want clear", u.LoginDisabledAt, u.LoginLockoutCount)
	}
}

// A limiter with no store keeps the disable in its own memory and lifts
// it the same way.
func TestAMemoryOnlyDisableLiftsToo(t *testing.T) {
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := escalationStart
	for i := range MaxConsecutiveLoginFailures {
		if !l.ReserveAccount(nil, "acct", at) {
			t.Fatalf("failure %d refused", i+1)
		}
		if i%5 == 4 {
			at = at.Add(time.Hour)
		}
	}
	disabled := at
	if d := l.ReserveAccountDecision(nil, "acct", disabled.Add(time.Hour)); !d.Disabled {
		t.Fatalf("expected the memory-only disable in force an hour on, got %+v", d)
	}
	if d := l.ReserveAccountDecision(nil, "acct", disabled.Add(LoginDisableDuration+time.Hour)); !d.Allowed || d.Lockouts != 0 {
		t.Errorf("after 24 hours: %+v, want admitted with no lockouts", d)
	}
}
