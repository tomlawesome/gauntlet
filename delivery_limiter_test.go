package gauntlet

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// ReserveDelivery (#84) counts sends per account and channel: threshold
// per window, never handed back.
func TestReserveDeliveryThresholdThenRefused(t *testing.T) {
	now := time.Now()
	l := mustNewLoginLimiter(t, 3, 5*time.Minute)
	for i := range 3 {
		if !l.ReserveDelivery("confirm", "u1", now) {
			t.Fatalf("send %d refused under the threshold", i+1)
		}
	}
	if l.ReserveDelivery("confirm", "u1", now) {
		t.Fatal("a send past the threshold was allowed")
	}
	if !l.ReserveDelivery("escape", "u1", now) {
		t.Error("the escape channel shares the confirm channel's budget")
	}
	if !l.ReserveDelivery("confirm", "u2", now) {
		t.Error("another account shares u1's budget")
	}
	if !l.ReserveAccount(nil, "u1", now) || !l.Reserve("ip:192.0.2.1", now) {
		t.Error("sends spent the login budget")
	}
	if !l.ReserveDelivery("confirm", "u1", now.Add(5*time.Minute+time.Second)) {
		t.Error("the budget did not come back a window later")
	}
}

// The budget lives in the account map, so no flood of addresses or
// made-up names can shed it.
func TestReserveDeliverySurvivesAnAddressFlood(t *testing.T) {
	orig := maxLoginLimiterKeys
	maxLoginLimiterKeys = 64
	defer func() { maxLoginLimiterKeys = orig }()

	now := time.Now()
	l := mustNewLoginLimiter(t, 2, time.Hour)
	l.ReserveDelivery("confirm", "u1", now)
	l.ReserveDelivery("confirm", "u1", now)
	for i := range 20 * maxLoginLimiterKeys {
		l.Reserve(fmt.Sprintf("ip:2001:db8::%x", i), now)
	}
	if l.ReserveDelivery("confirm", "u1", now) {
		t.Fatal("a flood of addresses reset an account's send budget")
	}
}

// A completed sign-in does not refill the budget: the owner signing in
// on a known browser must not hand a stranger more sends. An admin's
// unlock does, for that account's every channel and no other account.
func TestReserveDeliverySignedInKeepsItUnlockEmptiesIt(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	now := time.Now()
	l := mustNewLoginLimiter(t, 1, time.Hour)
	l.ReserveDelivery("confirm", id, now)
	l.ReserveDelivery("escape", id, now)
	l.ReserveDelivery("confirm", "other", now)

	l.SignedIn(s, id, now)
	if l.ReserveDelivery("confirm", id, now) {
		t.Fatal("a completed sign-in refilled the send budget")
	}

	if err := l.UnlockLogin(s, id); err != nil {
		t.Fatal(err)
	}
	if !l.ReserveDelivery("confirm", id, now) || !l.ReserveDelivery("escape", id, now) {
		t.Error("UnlockLogin left the account's send budget spent")
	}
	if l.ReserveDelivery("confirm", "other", now) {
		t.Error("UnlockLogin emptied another account's send budget")
	}
}

// An unlock that fails changes nothing, the send budget included.
func TestReserveDeliveryFailedUnlockKeepsIt(t *testing.T) {
	s, _ := openLockoutStore(t, persist.NewMemory())
	now := time.Now()
	l := mustNewLoginLimiter(t, 1, time.Hour)
	l.ReserveDelivery("confirm", "no-such-account", now)
	if err := l.UnlockLogin(s, "no-such-account"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unlock = %v, want ErrUserNotFound", err)
	}
	if l.ReserveDelivery("confirm", "no-such-account", now) {
		t.Error("a failed unlock emptied the send budget")
	}
}
