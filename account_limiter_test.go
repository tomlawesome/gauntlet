package gauntlet

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// countingBackend counts saves, to pin how many writes a lockout costs.
type countingBackend struct {
	*persist.Memory
	saves atomic.Int64
}

func (b *countingBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	b.saves.Add(1)
	return b.Memory.Save(ctx, payload, expect)
}

func openLockoutStore(t *testing.T, b persist.Backend) (*Store, string) {
	t.Helper()
	s, err := OpenStore(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.Register("alice", "password123", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return s, u.ID
}

// An account's lockout is on its own record, so a restart -- a new
// process with a fresh limiter reading the same backend -- is still
// locked out until the window ends, and no longer.
func TestAccountLockoutSurvivesARestart(t *testing.T) {
	m := persist.NewMemory()
	s, id := openLockoutStore(t, m)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	l := NewLoginLimiter(3, time.Minute)
	for i := range 3 {
		if !l.ReserveAccount(s, id, now) {
			t.Fatalf("attempt %d refused under the threshold", i+1)
		}
	}
	if l.ReserveAccount(s, id, now) {
		t.Fatal("expected the account to be locked after 3 failed attempts")
	}

	restarted, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	fresh := NewLoginLimiter(3, time.Minute)
	if fresh.ReserveAccount(restarted, id, now.Add(30*time.Second)) {
		t.Fatal("a restart lifted the lockout: a fresh limiter admitted an attempt inside the window")
	}
	if !fresh.ReserveAccount(restarted, id, now.Add(61*time.Second)) {
		t.Fatal("the lockout outlived its window after a restart")
	}
}

// A persisted lockout can never end more than one window after the
// attempt that set it (ratelimit.go writes entries[0].Add(l.window)). A
// value further out than that cannot have come from this limiter under a
// sane clock -- most likely the host clock was ahead when it was
// written -- and must not be honoured: nothing else would ever clear it.
func TestFarLockoutIsHonouredForOneWindowOnly(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	window := 5 * time.Minute

	// A lockout a year out cannot have come from this limiter (it never
	// writes more than one window ahead), but it is still honoured --
	// clamped to one window from now, not wiped -- since a shortened
	// window (below) looks exactly the same on the record.
	if err := s.SetLoginLockedUntil(id, now.Add(365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	l := NewLoginLimiter(5, window)
	if l.ReserveAccount(s, id, now) {
		t.Fatal("a lockout further out than one window was not honoured at all, want it clamped")
	}
	if u := s.LoginLockedUntil(id); !u.Equal(now.Add(window)) {
		t.Fatalf("expected the record clamped to one window from now (%v), got %v", now.Add(window), u)
	}
	// One window on, the clamped lockout has ended: the next attempt
	// succeeds and clears the record like any other expired lockout.
	later := now.Add(window).Add(time.Second)
	if !l.ReserveAccount(s, id, later) {
		t.Fatal("expected the clamped lockout to have ended one window on")
	}
	if u := s.LoginLockedUntil(id); !u.IsZero() {
		t.Fatalf("expected the ended lockout to be cleared from the record, got %v", u)
	}

	// A window shortened across a restart (written at 1h, reopened at
	// 5m) must not be wiped either: it is honoured for one window from
	// now, same as the impossible-clock case above.
	s2, id2 := openLockoutStore(t, persist.NewMemory())
	if err := s2.SetLoginLockedUntil(id2, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	shrunk := NewLoginLimiter(5, window)
	if shrunk.ReserveAccount(s2, id2, now) {
		t.Fatal("a lockout from a shrunk window was not honoured at all, want it clamped")
	}
	if u := s2.LoginLockedUntil(id2); !u.Equal(now.Add(window)) {
		t.Fatalf("expected the record clamped to the new window from now (%v), got %v", now.Add(window), u)
	}
}

// The capped map is for addresses and unknown names. However many of
// those arrive, a known account's counter is not in it and is never
// displaced.
func TestAddressFloodDoesNotDisplaceAnAccountCounter(t *testing.T) {
	orig := maxLoginLimiterKeys
	maxLoginLimiterKeys = 64
	defer func() { maxLoginLimiterKeys = orig }()

	s, id := openLockoutStore(t, persist.NewMemory())
	now := time.Now()
	l := NewLoginLimiter(2, time.Hour)
	l.ReserveAccount(s, id, now)
	l.ReserveAccount(s, id, now)

	for i := range 20 * maxLoginLimiterKeys {
		l.Reserve(fmt.Sprintf("ip:2001:db8::%x", i), now)
		l.Reserve(fmt.Sprintf("user:nobody-%d", i), now)
	}
	// Clear the persisted lockout so only the in-memory counter can
	// refuse: the flood must not have displaced it.
	if err := s.SetLoginLockedUntil(id, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if l.ReserveAccount(s, id, now) {
		t.Fatal("a flood of addresses and unknown names reset a known account's counter")
	}
}

// A stream of wrong guesses is not a stream of disk writes: one save as
// the lockout begins, however many attempts follow, and one as it
// clears.
func TestLockoutWritesAreBoundedPerEpisode(t *testing.T) {
	b := &countingBackend{Memory: persist.NewMemory()}
	s, id := openLockoutStore(t, b)
	before := b.saves.Load()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	l := NewLoginLimiter(5, time.Minute)
	for i := range 500 {
		l.ReserveAccount(s, id, now.Add(time.Duration(i)*time.Millisecond))
	}
	if got := b.saves.Load() - before; got != 1 {
		t.Fatalf("expected 1 save for one lockout episode, got %d", got)
	}
	if s.LoginLockedUntil(id).IsZero() {
		t.Fatal("expected the lockout to be recorded on the account")
	}

	later := now.Add(2 * time.Minute)
	if !l.ReserveAccount(s, id, later) {
		t.Fatal("expected the lockout to have expired")
	}
	l.ReleaseAccount(s, id, later)
	if got := b.saves.Load() - before; got != 2 {
		t.Fatalf("expected 1 more save as the lockout cleared, got %d in total", got)
	}
	if !s.LoginLockedUntil(id).IsZero() {
		t.Errorf("expected the cleared lockout to be removed from the account, got %v", s.LoginLockedUntil(id))
	}
}

// A success on the attempt that reached the threshold is the owner
// getting in: the lockout that attempt recorded is cleared, not left to
// lock them out.
func TestSuccessClearsTheLockoutItsOwnAttemptRecorded(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	now := time.Now()
	l := NewLoginLimiter(2, time.Minute)

	l.ReserveAccount(s, id, now) // fails, stays counted
	if !l.ReserveAccount(s, id, now) {
		t.Fatal("expected the second attempt to be admitted")
	}
	l.ReleaseAccount(s, id, now) // it succeeded
	if !s.LoginLockedUntil(id).IsZero() {
		t.Fatalf("a successful login left the account locked until %v", s.LoginLockedUntil(id))
	}
	if !l.ReserveAccount(s, id, now) {
		t.Fatal("expected the account to be admitted after its owner signed in")
	}
}

// The password re-check bucket is per account too, and memory-only: a
// flood cannot displace it, and it writes nothing.
func TestRecheckCounterIsNotDisplacedByAFlood(t *testing.T) {
	orig := maxLoginLimiterKeys
	maxLoginLimiterKeys = 64
	defer func() { maxLoginLimiterKeys = orig }()

	now := time.Now()
	l := NewLoginLimiter(2, time.Hour)
	l.ReserveRecheck("u1", now)
	l.ReserveRecheck("u1", now)
	for i := range 20 * maxLoginLimiterKeys {
		l.Reserve(fmt.Sprintf("ip:2001:db8::%x", i), now)
	}
	if l.ReserveRecheck("u1", now) {
		t.Fatal("a flood of addresses reset an account's password re-check counter")
	}
	if l.ReserveAccount(nil, "u1", now) != true {
		t.Fatal("the re-check bucket spent the login bucket's allowance")
	}
}

// Under pressure the capped map drops everything already expired, not
// just one batch of the oldest, so live keys keep the room.
func TestCappedMapDropsEveryExpiredKeyUnderPressure(t *testing.T) {
	orig := maxLoginLimiterKeys
	maxLoginLimiterKeys = 16
	defer func() { maxLoginLimiterKeys = orig }()

	start := time.Now()
	l := NewLoginLimiter(2, time.Minute)
	for i := range maxLoginLimiterKeys - 1 {
		l.Reserve(fmt.Sprintf("ip:old-%d", i), start)
	}
	l.Reserve("ip:live", start.Add(90*time.Second))
	l.Reserve("ip:new", start.Add(100*time.Second)) // over the cap; the old ones have expired

	if len(l.attempts) != 2 {
		t.Fatalf("expected only the two live keys to remain, got %d", len(l.attempts))
	}
}

// Eviction pressure is logged, once per window rather than once per
// request, so a flood cannot turn into a flood of log lines.
func TestEvictionPressureIsLoggedOncePerWindow(t *testing.T) {
	orig := maxLoginLimiterKeys
	maxLoginLimiterKeys = 16
	defer func() { maxLoginLimiterKeys = orig }()

	var logs bytes.Buffer
	now := time.Now()
	l := NewLoginLimiter(5, time.Minute)
	l.SetLog(slog.New(slog.NewTextHandler(&logs, nil)))
	for i := range 50 * maxLoginLimiterKeys {
		l.Reserve(fmt.Sprintf("ip:%d", i), now)
	}
	if n := strings.Count(logs.String(), "evict"); n != 1 {
		t.Fatalf("expected one eviction-pressure line in the window, got %d:\n%s", n, logs.String())
	}
	for i := range 3 * maxLoginLimiterKeys {
		l.Reserve(fmt.Sprintf("ip:later-%d", i), now.Add(2*time.Minute))
	}
	if n := strings.Count(logs.String(), "evict"); n != 2 {
		t.Errorf("expected a second line once the window had passed, got %d", n)
	}
}
