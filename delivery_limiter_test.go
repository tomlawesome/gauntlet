package gauntlet

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// ReserveDelivery (#84) counts sends per account and channel: threshold
// per window, never handed back. The sends here are spaced past each
// one's cooldown (#83), so the window is what refuses the fourth.
func TestReserveDeliveryThresholdThenRefused(t *testing.T) {
	now := time.Now()
	l := mustNewLoginLimiter(t, 3, 5*time.Minute)
	last := sendSpaced(t, l, "confirm", "u1", 3, now, 2*time.Minute)
	if l.ReserveDelivery("confirm", "u1", last.Add(30*time.Second)) {
		t.Fatal("a send past the threshold was allowed")
	}
	if !l.ReserveDelivery("escape", "u1", last) {
		t.Error("the escape channel shares the confirm channel's budget")
	}
	if !l.ReserveDelivery("confirm", "u2", last) {
		t.Error("another account shares u1's budget")
	}
	if !l.ReserveAccount(nil, "u1", last) || !l.Reserve("ip:192.0.2.1", last) {
		t.Error("sends spent the login budget")
	}
	if !l.ReserveDelivery("confirm", "u1", last.Add(5*time.Minute+time.Second)) {
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
	last := sendSpaced(t, l, "confirm", "u1", 2, now, time.Minute)
	for i := range 20 * maxLoginLimiterKeys {
		l.Reserve(fmt.Sprintf("ip:2001:db8::%x", i), last)
	}
	if l.ReserveDelivery("confirm", "u1", last.Add(time.Minute)) {
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

// The resend cooldown (#83): after a send, the next on the same account
// and channel waits 30 seconds, and each further send in the hour
// doubles the wait. A refused send is not counted, so it neither spends
// the budget nor pushes the wait out.
func TestReserveDeliveryCooldownDoubles(t *testing.T) {
	now := time.Now()
	l := mustNewLoginLimiter(t, 100, 5*time.Minute)
	if !l.ReserveDelivery("confirm", "u1", now) {
		t.Fatal("the first send was refused")
	}
	at := now
	for i, wait := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute} {
		if l.ReserveDelivery("confirm", "u1", at.Add(wait-time.Second)) {
			t.Fatalf("send %d went out %v after the last, inside its %v cooldown", i+2, wait-time.Second, wait)
		}
		at = at.Add(wait)
		if !l.ReserveDelivery("confirm", "u1", at) {
			t.Fatalf("send %d refused once its %v cooldown had passed", i+2, wait)
		}
	}
	if !l.ReserveDelivery("escape", "u1", now.Add(time.Second)) {
		t.Error("the confirm channel's cooldown held back an escape code")
	}
	if !l.ReserveDelivery("confirm", "u2", now.Add(time.Second)) {
		t.Error("u1's cooldown held back another account")
	}
}

// The cooldown is never longer than maxSendCooldown, however many sends
// the hour holds.
func TestSendCooldownCapped(t *testing.T) {
	for n, want := range map[int]time.Duration{
		1: 30 * time.Second, 2: time.Minute, 5: 8 * time.Minute,
		6: maxSendCooldown, 64: maxSendCooldown, 1 << 20: maxSendCooldown,
	} {
		if got := sendCooldown(n); got != want {
			t.Errorf("sendCooldown(%d) = %v, want %v", n, got, want)
		}
	}
}

// sendSpaced makes n sends on channel for accountID, each step after
// the last (step past every cooldown), from start, failing on a refusal.
func sendSpaced(t *testing.T, l *LoginLimiter, channel, accountID string, n int, start time.Time, step time.Duration) time.Time {
	t.Helper()
	at := start
	for i := range n {
		if i > 0 {
			at = at.Add(step)
		}
		if !l.ReserveDelivery(channel, accountID, at) {
			t.Fatalf("send %d at +%v refused", i+1, at.Sub(start))
		}
	}
	return at
}

// The longer cap (#83): five sends per account and channel in any hour,
// past the cooldown and whatever the limiter's own window, so a password
// holder cannot keep a trickle going window after window. Room comes
// back as the oldest send leaves the hour.
func TestReserveDeliveryHourlyCap(t *testing.T) {
	now := time.Now()
	l := mustNewLoginLimiter(t, 100, 5*time.Minute)
	last := sendSpaced(t, l, "confirm", "u1", maxSendsPerHour, now, 10*time.Minute)
	if l.ReserveDelivery("confirm", "u1", last.Add(10*time.Minute)) {
		t.Fatal("a sixth send in the hour went out")
	}
	if !l.ReserveDelivery("escape", "u1", last.Add(10*time.Minute)) {
		t.Error("the confirm channel's cap held back an escape code")
	}
	if !l.ReserveDelivery("confirm", "u2", last.Add(10*time.Minute)) {
		t.Error("u1's cap held back another account")
	}
	if l.ReserveDelivery("confirm", "u1", now.Add(sendCapPeriod-time.Second)) {
		t.Error("a send went out before the oldest left the hour")
	}
	if !l.ReserveDelivery("confirm", "u1", now.Add(sendCapPeriod+time.Second)) {
		t.Error("no room once the oldest send left the hour")
	}
}

// The hour outlasts the limiter's window, so the sweep that drops
// expired account entries (evictOldestLocked, run by an address flood)
// must not drop sends the hour still counts.
func TestReserveDeliveryHourSurvivesTheSweep(t *testing.T) {
	orig := maxLoginLimiterKeys
	maxLoginLimiterKeys = 64
	defer func() { maxLoginLimiterKeys = orig }()

	now := time.Now()
	l := mustNewLoginLimiter(t, 100, 5*time.Minute)
	last := sendSpaced(t, l, "confirm", "u1", maxSendsPerHour, now, 10*time.Minute)
	at := last.Add(10 * time.Minute)
	for i := range 20 * maxLoginLimiterKeys {
		l.Reserve(fmt.Sprintf("ip:2001:db8::%x", i), at)
	}
	if l.ReserveDelivery("confirm", "u1", at) {
		t.Fatal("the account map's sweep dropped sends still in the hour")
	}
}

// UnlockLogin empties the cooldown and the hourly cap with the rest of
// the account's send budget; a completed sign-in leaves both.
func TestReserveDeliveryUnlockEmptiesCooldownAndCap(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	now := time.Now()
	l := mustNewLoginLimiter(t, 100, 5*time.Minute)
	last := sendSpaced(t, l, "confirm", id, maxSendsPerHour, now, 10*time.Minute)
	at := last.Add(time.Second)
	l.SignedIn(s, id, at)
	if l.ReserveDelivery("confirm", id, at) {
		t.Fatal("a completed sign-in refilled the hour's sends")
	}
	if err := l.UnlockLogin(s, id); err != nil {
		t.Fatal(err)
	}
	if !l.ReserveDelivery("confirm", id, at) {
		t.Fatal("UnlockLogin left the hourly cap spent")
	}
	if !l.ReserveDelivery("confirm", id, at.Add(30*time.Second)) {
		t.Error("UnlockLogin left the cooldown counting earlier sends")
	}
}
