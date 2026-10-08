package gauntlet

import (
	"fmt"
	"testing"
	"time"
)

// ReserveFactorBegin (#85) counts second-step passkey begins per
// account: threshold per window, a budget of its own, apart from the
// login budget a wrong guess spends and the per-address challenge
// budget the login page's passkey sign-in spends.
func TestReserveFactorBeginThresholdThenRefused(t *testing.T) {
	now := time.Now()
	l := mustNewLoginLimiter(t, 3, 5*time.Minute)
	for i := range 3 {
		if !l.ReserveFactorBegin("u1", false, now) {
			t.Fatalf("begin %d refused under the threshold", i+1)
		}
	}
	if l.ReserveFactorBegin("u1", false, now) {
		t.Fatal("a begin past the threshold was allowed")
	}
	if !l.ReserveFactorBegin("u2", false, now) {
		t.Error("another account shares u1's budget")
	}
	if !l.Allow("ip:192.0.2.1", now) || !l.Allow("passkey-begin:192.0.2.1", now) {
		t.Error("begins spent an address's login or challenge budget")
	}
	for i := range 3 {
		if !l.ReserveAccount(nil, "u1", now) {
			t.Fatalf("begins spent the account's login budget: %d of 3 left", i)
		}
	}
	if !l.ReserveStepUpBegin("u1", now) {
		t.Error("begins spent the step-up begin budget")
	}
	if !l.ReserveFactorBegin("u1", true, now) {
		t.Error("a known browser shares the ordinary budget a stranger filled")
	}
	if !l.ReserveFactorBegin("u1", false, now.Add(5*time.Minute+time.Second)) {
		t.Error("the budget did not come back a window later")
	}
}

// A known browser's budget is bounded too.
func TestReserveFactorBeginKnownBrowserIsBounded(t *testing.T) {
	now := time.Now()
	l := mustNewLoginLimiter(t, 2, time.Hour)
	l.ReserveFactorBegin("u1", true, now)
	l.ReserveFactorBegin("u1", true, now)
	if l.ReserveFactorBegin("u1", true, now) {
		t.Fatal("a known browser's begin past the threshold was allowed")
	}
	if !l.ReserveFactorBegin("u1", false, now) {
		t.Error("a known browser's begins spent the ordinary budget")
	}
}

// The budgets live in the account map, so no flood of addresses or
// made-up names can shed them.
func TestReserveFactorBeginSurvivesAnAddressFlood(t *testing.T) {
	orig := maxLoginLimiterKeys
	maxLoginLimiterKeys = 64
	defer func() { maxLoginLimiterKeys = orig }()

	now := time.Now()
	l := mustNewLoginLimiter(t, 2, time.Hour)
	for _, known := range []bool{false, true} {
		l.ReserveFactorBegin("u1", known, now)
		l.ReserveFactorBegin("u1", known, now)
	}
	for i := range 20 * maxLoginLimiterKeys {
		l.Reserve(fmt.Sprintf("ip:2001:db8::%x", i), now)
		l.Reserve(fmt.Sprintf("user:%x", i), now)
	}
	for _, known := range []bool{false, true} {
		if l.ReserveFactorBegin("u1", known, now) {
			t.Errorf("known=%v: a flood of addresses and names reset an account's begin budget", known)
		}
	}
}

// A completed sign-in leaves the budgets alone; an admin's unlock
// empties them.
func TestFactorBeginBudgetSignedInAndUnlock(t *testing.T) {
	now := time.Now()
	l := mustNewLoginLimiter(t, 1, time.Hour)
	l.ReserveFactorBegin("u1", false, now)
	l.ReserveFactorBegin("u1", true, now)
	l.SignedIn(nil, "u1", now)
	if l.ReserveFactorBegin("u1", false, now) || l.ReserveFactorBegin("u1", true, now) {
		t.Fatal("a completed sign-in handed the begins back")
	}
	if err := l.UnlockLogin(nil, "u1"); err != nil {
		t.Fatal(err)
	}
	if !l.ReserveFactorBegin("u1", false, now) || !l.ReserveFactorBegin("u1", true, now) {
		t.Error("an unlock left the begins counted")
	}
}

// ReleaseFactorBegin hands back a begin the server failed to start, in
// the same request, on the budget it was taken from.
func TestReleaseFactorBegin(t *testing.T) {
	now := time.Now()
	l := mustNewLoginLimiter(t, 1, time.Hour)
	l.ReserveFactorBegin("u1", false, now)
	l.ReserveFactorBegin("u1", true, now)
	l.ReleaseFactorBegin("u1", true, now)
	if l.ReserveFactorBegin("u1", false, now) {
		t.Error("a known browser's release handed back the ordinary budget")
	}
	if !l.ReserveFactorBegin("u1", true, now) {
		t.Error("a released begin was still counted")
	}
}
