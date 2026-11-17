package gauntlet

import (
	"fmt"
	"testing"
	"time"
)

// ReserveStepUpBegin (#82) counts passkey step-up begins per account:
// threshold per window, its own budget, never handed back by a finish.
func TestReserveStepUpBeginThresholdThenRefused(t *testing.T) {
	now := time.Now()
	l := mustNewLoginLimiter(t, 3, 5*time.Minute)
	for i := range 3 {
		if !l.ReserveStepUpBegin("u1", now) {
			t.Fatalf("begin %d refused under the threshold", i+1)
		}
	}
	if l.ReserveStepUpBegin("u1", now) {
		t.Fatal("a begin past the threshold was allowed")
	}
	if !l.ReserveStepUpBegin("u2", now) {
		t.Error("another account shares u1's budget")
	}
	if !l.ReserveRecheck("u1", now) || !l.ReserveAccount(nil, "u1", now) {
		t.Error("begins spent the re-check or login budget")
	}
	if !l.ReserveStepUpBegin("u1", now.Add(5*time.Minute+time.Second)) {
		t.Error("the budget did not come back a window later")
	}
}

// The budget lives in the account map, so no flood of addresses or
// made-up names can shed it.
func TestReserveStepUpBeginSurvivesAnAddressFlood(t *testing.T) {
	orig := maxLoginLimiterKeys
	maxLoginLimiterKeys = 64
	defer func() { maxLoginLimiterKeys = orig }()

	now := time.Now()
	l := mustNewLoginLimiter(t, 2, time.Hour)
	l.ReserveStepUpBegin("u1", now)
	l.ReserveStepUpBegin("u1", now)
	for i := range 20 * maxLoginLimiterKeys {
		l.Reserve(fmt.Sprintf("ip:2001:db8::%x", i), now)
	}
	if l.ReserveStepUpBegin("u1", now) {
		t.Fatal("a flood of addresses reset an account's step-up begin budget")
	}
}

// ReleaseStepUpBegin hands back a begin the server failed to start, in
// the same request.
func TestReleaseStepUpBegin(t *testing.T) {
	now := time.Now()
	l := mustNewLoginLimiter(t, 1, time.Hour)
	l.ReserveStepUpBegin("u1", now)
	l.ReleaseStepUpBegin("u1", now)
	if !l.ReserveStepUpBegin("u1", now) {
		t.Fatal("a released begin was still counted")
	}
}
