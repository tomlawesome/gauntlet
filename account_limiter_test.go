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

	l := mustNewLoginLimiter(t, 3, time.Minute)
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
	fresh := mustNewLoginLimiter(t, 3, time.Minute)
	if fresh.ReserveAccount(restarted, id, now.Add(30*time.Second)) {
		t.Fatal("a restart lifted the lockout: a fresh limiter admitted an attempt inside the window")
	}
	if !fresh.ReserveAccount(restarted, id, now.Add(61*time.Second)) {
		t.Fatal("the lockout outlived its window after a restart")
	}
}

// A persisted lockout never ends more than one window after the attempt
// that set it (ratelimit.go writes entries[0].Add(l.window)). A value
// further out than that is either a clock that was ahead when it was
// written or a window shortened across a restart, so it is honoured for
// one window from now and no longer -- not wiped, which would let a
// still-valid lockout through the moment the window shrinks, and not
// honoured as written, which nothing would ever clear.
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
	l := mustNewLoginLimiter(t, 5, window)
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
	shrunk := mustNewLoginLimiter(t, 5, window)
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
	l := mustNewLoginLimiter(t, 2, time.Hour)
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

	l := mustNewLoginLimiter(t, 5, time.Minute)
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
	l := mustNewLoginLimiter(t, 2, time.Minute)

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
	l := mustNewLoginLimiter(t, 2, time.Hour)
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
	l := mustNewLoginLimiter(t, 2, time.Minute)
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
	l := mustNewLoginLimiter(t, 5, time.Minute)
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

// flakySaveBackend fails every Save while fail is set, for a backend
// that is down for a while and then recovers. It counts every Save it
// is asked for, failed or not.
type flakySaveBackend struct {
	*persist.Memory
	fail  atomic.Bool
	saves atomic.Int64
}

func (b *flakySaveBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	b.saves.Add(1)
	if b.fail.Load() {
		return 0, errTestBackendUnavailable
	}
	return b.Memory.Save(ctx, payload, expect)
}

// A lockout whose save failed is not forgotten: it stays enforced in
// memory, and a later refused attempt while it is in force saves it
// again, so a restart after the backend recovers is still locked out.
// Retries are spaced out, so a broken backend is not asked to save on
// every refused guess.
func TestUnsavedLockoutIsSavedOnALaterAttempt(t *testing.T) {
	b := &flakySaveBackend{Memory: persist.NewMemory()}
	s, id := openLockoutStore(t, b)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := mustNewLoginLimiter(t, 3, time.Minute)

	b.fail.Store(true)
	for i := range 3 {
		if !l.ReserveAccount(s, id, now) {
			t.Fatalf("attempt %d refused under the threshold", i+1)
		}
	}
	if got := s.LoginLockedUntil(id); !got.IsZero() {
		t.Fatalf("test setup: the lockout was recorded (%v) although every save failed", got)
	}
	if l.ReserveAccount(s, id, now.Add(time.Second)) {
		t.Fatal("an unsaved lockout was not enforced in memory")
	}

	b.fail.Store(false)
	if l.ReserveAccount(s, id, now.Add(time.Second+lockoutRetryInterval)) {
		t.Fatal("the retry let an attempt through a live lockout")
	}
	if got, want := s.LoginLockedUntil(id), now.Add(time.Minute); !got.Equal(want) {
		t.Fatalf("expected the retried lockout on the record, until %v; got %v", want, got)
	}

	restarted, err := OpenStore(b.Memory, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if mustNewLoginLimiter(t, 3, time.Minute).ReserveAccount(restarted, id, now.Add(30*time.Second)) {
		t.Fatal("a restart after the backend recovered lifted the lockout")
	}
}

// While the backend stays down, a stream of refused guesses is not a
// stream of save attempts: at most one per lockoutRetryInterval.
func TestUnsavedLockoutRetriesAreSpacedOut(t *testing.T) {
	b := &flakySaveBackend{Memory: persist.NewMemory()}
	s, id := openLockoutStore(t, b)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := mustNewLoginLimiter(t, 3, time.Hour)

	b.fail.Store(true)
	for range 3 {
		l.ReserveAccount(s, id, now)
	}
	start := b.saves.Load()
	for i := range 1000 {
		l.ReserveAccount(s, id, now.Add(time.Duration(i)*time.Millisecond))
	}
	if got := b.saves.Load() - start; got != 0 {
		t.Fatalf("expected no retry within a second of the failed save, got %d saves", got)
	}
	later := now.Add(lockoutRetryInterval)
	for i := range 1000 {
		l.ReserveAccount(s, id, later.Add(time.Duration(i)*time.Millisecond))
	}
	if got := b.saves.Load() - start; got != 1 {
		t.Fatalf("expected one retry once lockoutRetryInterval had passed, got %d saves", got)
	}
	l.ReserveAccount(s, id, later.Add(lockoutRetryInterval))
	if got := b.saves.Load() - start; got != 2 {
		t.Fatalf("expected a second retry one interval after the first, got %d saves", got)
	}
}

// A stored lockout further out than one window is clamped and saved
// back; while the backend is down that save is spaced out like any other
// lockout retry, not tried again on every refused guess.
func TestClampedLockoutRetriesAreSpacedOut(t *testing.T) {
	b := &flakySaveBackend{Memory: persist.NewMemory()}
	s, id := openLockoutStore(t, b)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := s.SetLoginLockedUntil(id, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)

	b.fail.Store(true)
	start := b.saves.Load()
	for i := range 100 {
		if l.ReserveAccount(s, id, now.Add(time.Duration(i)*100*time.Millisecond)) {
			t.Fatal("a guess was let through a stored lockout")
		}
	}
	if got := b.saves.Load() - start; got != 1 {
		t.Fatalf("expected one save attempt within lockoutRetryInterval, got %d", got)
	}
	l.ReserveAccount(s, id, now.Add(lockoutRetryInterval))
	if got := b.saves.Load() - start; got != 2 {
		t.Fatalf("expected a retry once lockoutRetryInterval had passed, got %d save attempts", got)
	}
}

// A successful login whose clear of the lockout fails to save does not
// leave its owner locked out by the record for the rest of the window:
// the next attempt is let through and the clear is saved again.
func TestFailedLockoutClearDoesNotLockTheOwnerOut(t *testing.T) {
	b := &flakySaveBackend{Memory: persist.NewMemory()}
	s, id := openLockoutStore(t, b)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := mustNewLoginLimiter(t, 3, time.Hour)

	l.ReserveAccount(s, id, now) // wrong
	l.ReserveAccount(s, id, now) // wrong
	if !l.ReserveAccount(s, id, now) {
		t.Fatal("test setup: the third attempt was refused")
	}
	if s.LoginLockedUntil(id).IsZero() {
		t.Fatal("test setup: expected the third attempt's lockout on the record")
	}
	b.fail.Store(true)
	l.ReleaseAccount(s, id, now) // right, but the clear fails to save
	b.fail.Store(false)

	at := now.Add(time.Second)
	if !l.ReserveAccount(s, id, at) {
		t.Fatal("the owner stayed locked out after a clear that failed to save")
	}
	l.ReleaseAccount(s, id, at)
	if got := s.LoginLockedUntil(id); !got.IsZero() {
		t.Fatalf("expected the lockout cleared from the record, got %v", got)
	}
}

// A new password -- set by its owner, by an admin through SetPassword,
// or replaced by an admin's reset code -- ends any login lockout on the
// account, in the record and in the limiter's own count: the guesses
// were against the old password, and whoever holds the new one (or the
// reset code) signs in at once.
func TestPasswordChangeEndsTheLoginLockout(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	changes := map[string]func(t *testing.T, s *Store, id string, at time.Time) string{
		"SetPassword": func(t *testing.T, s *Store, id string, at time.Time) string {
			if err := s.SetPassword("alice", "a-brand-new-password", at); err != nil {
				t.Fatal(err)
			}
			return "a-brand-new-password"
		},
		"IssueResetCode": func(t *testing.T, s *Store, id string, at time.Time) string {
			_, code, err := s.IssueResetCode(id, at)
			if err != nil {
				t.Fatal(err)
			}
			return code
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			s, id := openLockoutStore(t, persist.NewMemory())
			l := mustNewLoginLimiter(t, 3, time.Hour)
			for range 3 {
				l.ReserveAccount(s, id, now)
			}
			if l.ReserveAccount(s, id, now.Add(time.Second)) {
				t.Fatal("test setup: expected the account to be locked")
			}
			if s.LoginLockedUntil(id).IsZero() {
				t.Fatal("test setup: expected the lockout on the record")
			}

			secret := change(t, s, id, now.Add(time.Minute))
			if got := s.LoginLockedUntil(id); !got.IsZero() {
				t.Errorf("the password change left the record locked until %v", got)
			}
			at := now.Add(2 * time.Minute)
			if !l.ReserveAccount(s, id, at) {
				t.Fatal("the limiter still refused the account after its password was changed")
			}
			if _, err := s.Authenticate("alice", secret, at); err != nil {
				t.Fatalf("signing in with the new credential: %v", err)
			}
			l.ReleaseAccount(s, id, at)
		})
	}
}

// A lockout still waiting to be saved (its first save failed) belongs to
// the old password too: a password change drops it, and no retry saves
// it over the change afterwards.
func TestPasswordChangeDropsAnUnsavedLockout(t *testing.T) {
	b := &flakySaveBackend{Memory: persist.NewMemory()}
	s, id := openLockoutStore(t, b)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := mustNewLoginLimiter(t, 3, time.Hour)

	b.fail.Store(true)
	for range 3 {
		l.ReserveAccount(s, id, now)
	}
	b.fail.Store(false)
	if err := s.SetPassword("alice", "a-brand-new-password", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !l.ReserveAccount(s, id, now.Add(time.Minute+lockoutRetryInterval)) {
		t.Fatal("the limiter refused the account after its password was changed")
	}
	if got := s.LoginLockedUntil(id); !got.IsZero() {
		t.Fatalf("a lockout from before the password change was saved after it, until %v", got)
	}
	// Checked on the limiter itself: nothing a caller can do next would
	// reach a retry of the old lockout before a new count replaced it,
	// so the record alone cannot show whether it was dropped.
	l.mu.Lock()
	p, pending := l.wantLockout[id]
	l.mu.Unlock()
	if pending {
		t.Errorf("the limiter still holds the old password's unsaved lockout (until %v) for a later retry to save", p.state.until)
	}
}

// #28: a lockout whose save failed, then the admin linked to SSO while
// the retry was still spaced out. The link ends the account's sessions
// but leaves its password working, so it must not read as a password
// change: the next attempt is still refused, and its retry saves the
// lockout the backend has recovered enough to take.
func TestLinkingTheAdminKeepsAnUnsavedLockout(t *testing.T) {
	b := &flakySaveBackend{Memory: persist.NewMemory()}
	s, id := openLockoutStore(t, b)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	window := time.Hour
	l := mustNewLoginLimiter(t, 3, window)

	b.fail.Store(true)
	for range 3 {
		l.ReserveAccount(s, id, now)
	}
	if got := s.LoginLockedUntil(id); !got.IsZero() {
		t.Fatalf("test setup: the lockout's first save was meant to fail, but the record holds %v", got)
	}
	b.fail.Store(false)
	if err := s.LinkOIDCIdentity(id, "https://idp.example", "subject-1", now.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}

	if l.ReserveAccount(s, id, now.Add(lockoutRetryInterval+time.Second)) {
		t.Fatal("linking the admin to SSO ended a lockout whose save had failed")
	}
	if got, want := s.LoginLockedUntil(id), now.Add(window); !got.Equal(want) {
		t.Errorf("record locked until %v after the retry, want %v", got, want)
	}
}

// A lockout whose save lands just after a password change -- decided
// before it, written after it -- looks on the record exactly like a
// lockout the admin kept through an SSO link (see
// TestLinkingTheAdminKeepsItsLoginLockout), so it is honoured: the race
// fails closed. A second change clears it, and this time the limiter's
// count of the old guesses goes with it.
func TestLockoutSavedJustAfterAPasswordChangeIsHonoured(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	window := time.Hour
	l := mustNewLoginLimiter(t, 3, window)
	for range 3 {
		l.ReserveAccount(s, id, now)
	}
	if err := s.SetPassword("alice", "a-brand-new-password", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// The lockout's save landing after the change's write.
	if err := s.SetLoginLockedUntil(id, now.Add(window)); err != nil {
		t.Fatal(err)
	}
	if l.ReserveAccount(s, id, now.Add(2*time.Minute)) {
		t.Fatal("a lockout on the record was let through")
	}

	if err := s.SetPassword("alice", "another-new-password", now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !l.ReserveAccount(s, id, now.Add(4*time.Minute)) {
		t.Fatal("a second password change did not end the lockout")
	}
}

// A password change dated in the future -- a clock stepped back since
// (NTP, a VM restored from a snapshot), or another process whose clock
// runs ahead -- does not switch the account's limit off. Taken at face
// value it would drop every guess as "made before the change" on every
// call, and end any lockout already on the record. Until the clock
// reaches it, it is ignored: the limit fails closed, as the session
// check in gate does on the same skew.
func TestFuturePasswordChangeDoesNotTurnTheLimitOff(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	future := now.Add(10 * time.Minute)

	t.Run("guesses still count", func(t *testing.T) {
		s, id := openLockoutStore(t, persist.NewMemory())
		if err := s.SetPassword("alice", "a-brand-new-password", future); err != nil {
			t.Fatal(err)
		}
		l := mustNewLoginLimiter(t, 3, time.Hour)
		let := 0
		for i := range 100 {
			if l.ReserveAccount(s, id, now.Add(time.Duration(i)*time.Second)) {
				let++
			}
		}
		if let != 3 {
			t.Errorf("%d of 100 guesses let through, want 3", let)
		}
		if s.LoginLockedUntil(id).IsZero() {
			t.Error("no lockout on the record after 100 guesses")
		}
	})

	t.Run("a lockout on the record stays", func(t *testing.T) {
		s, id := openLockoutStore(t, persist.NewMemory())
		if err := s.SetPassword("alice", "a-brand-new-password", future); err != nil {
			t.Fatal(err)
		}
		// A lockout saved afterwards, by a process whose clock is right.
		if err := s.SetLoginLockedUntil(id, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		l := mustNewLoginLimiter(t, 3, time.Hour)
		if l.ReserveAccount(s, id, now.Add(time.Second)) {
			t.Error("a future PasswordChangedAt ended the lockout on the record")
		}
	})
}

// Linking the admin to an SSO identity ends the sessions issued before
// it, but the admin keeps its password: the guesses that locked it out
// were at a password that still works. The lockout stays, in this
// limiter and in a fresh one reading the record.
func TestLinkingTheAdminKeepsItsLoginLockout(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	if u, _ := s.ByUsername("alice"); u.Role != RoleAdmin {
		t.Fatal("test setup: expected alice to be the admin")
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := mustNewLoginLimiter(t, 3, time.Hour)
	// Spread out: the lockout runs one window from the third (#44), so
	// it ends at 1h20m.
	for i := range 3 {
		l.ReserveAccount(s, id, now.Add(time.Duration(i)*10*time.Minute))
	}
	if l.ReserveAccount(s, id, now.Add(20*time.Minute+time.Second)) {
		t.Fatal("test setup: expected the account to be locked")
	}

	if err := s.LinkOIDCIdentity(id, "https://idp.example", "subject-1", now.Add(50*time.Minute)); err != nil {
		t.Fatal(err)
	}
	at := now.Add(51 * time.Minute)
	if l.ReserveAccount(s, id, at) {
		t.Error("linking the admin ended its lockout in the limiter")
	}
	if mustNewLoginLimiter(t, 3, time.Hour).ReserveAccount(s, id, at) {
		t.Error("linking the admin ended the lockout on its record")
	}
	if s.LoginLockedUntil(id).IsZero() {
		t.Error("linking the admin cleared the lockout on its record")
	}

	// A lockout outlasts the window (#44), so once it has ended the
	// guesses that caused it have aged out with it. What the link must
	// not reset is the count of lockouts: the next full window starts
	// the second lockout, three times as long, rather than a first one
	// again.
	ended := now.Add(20*time.Minute + time.Hour + time.Second)
	for i := range 3 {
		if !l.ReserveAccount(s, id, ended) {
			t.Fatalf("attempt %d refused after the recorded lockout had ended", i+1)
		}
	}
	if u, _ := s.Get(id); u.LoginLockoutCount != 2 {
		t.Errorf("linking the admin reset its count of lockouts: the next one is number %d, want 2", u.LoginLockoutCount)
	}
	if got, want := s.LoginLockedUntil(id), ended.Add(3*time.Hour); !got.Equal(want) {
		t.Errorf("the second lockout ends at %v, want three windows on, %v", got, want)
	}
}

// AllowAfterReset (#32) passes the address limit only for an address
// that filled before the account's password changed, only while the
// record carries no lockout, and only for one sign-in per change.
func TestAllowAfterResetConditions(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := mustNewLoginLimiter(t, 3, time.Minute)
	const addr = "ip:192.0.2.1"

	if l.AllowAfterReset(addr, s, id, start) {
		t.Fatal("a pass with no password change since the address filled")
	}
	for range 2 {
		l.Reserve(addr, start)
	}
	if err := s.SetPassword("alice", "new-password-placeholder", start.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	l.Reserve(addr, start.Add(2*time.Second)) // fills the address after the change
	if l.AllowAfterReset(addr, s, id, start.Add(3*time.Second)) {
		t.Error("a pass for an address that filled only after the change")
	}

	// The address is full from before the next change, but the account
	// was never locked out: a change of its own password is not a reset
	// that ended a lockout, and earns nothing.
	if err := s.SetPassword("alice", "own-change-placeholder", start.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if l.AllowAfterReset(addr, s, id, start.Add(5*time.Second)) {
		t.Error("a pass for a password change on an account that was never locked out")
	}

	// Locked out, then reset: the pass.
	for range 3 {
		l.ReserveAccount(s, id, start.Add(6*time.Second))
	}
	if err := s.SetPassword("alice", "newer-password-placeholder", start.Add(7*time.Second)); err != nil {
		t.Fatal(err)
	}
	now := start.Add(8 * time.Second)
	if !l.AllowAfterReset(addr, s, id, now) {
		t.Fatal("no pass for an account reset out of a lockout at a full address")
	}
	if l.AllowAfterReset("ip:192.0.2.2", s, id, now) {
		t.Error("a pass for an address that never reached the limit")
	}

	// One attempt holds the pass at a time: a second, concurrent one is
	// refused until the first hands it back.
	if l.AllowAfterReset(addr, s, id, now) {
		t.Error("a second attempt got the pass while the first still held it")
	}
	l.ReleaseAfterReset(addr, id)
	if !l.AllowAfterReset(addr, s, id, now) {
		t.Error("the pass was not handed back by ReleaseAfterReset")
	}
	l.EndAfterReset(addr, id)
	l.ReleaseAfterReset(addr, id)
	if l.AllowAfterReset(addr, s, id, now) {
		t.Error("the pass outlived EndAfterReset")
	}

	// A further reset out of a lockout grants a fresh pass -- unless the
	// record carries a lockout, which a real password change would have
	// cleared.
	if err := s.SetPassword("alice", "newest-password-placeholder", start.Add(9*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLoginLockedUntil(id, start.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if l.AllowAfterReset(addr, s, id, start.Add(10*time.Second)) {
		t.Error("a pass while the record carries a lockout")
	}
	if err := s.SetLoginLockedUntil(id, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if !l.AllowAfterReset(addr, s, id, start.Add(10*time.Second)) {
		t.Error("no fresh pass after a further reset")
	}
	l.ReleaseAfterReset(addr, id)
	if l.AllowAfterReset(addr, s, id, start.Add(2*time.Minute)) {
		t.Error("a pass after the address's attempts left the window")
	}
}
