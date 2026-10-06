package gauntlet

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// The record and API side of #44: the fields a lockout writes, how a
// success hands its count back, UnlockLogin, and the run of
// second-factor failures.

func mustGet(t *testing.T, s *Store, id string) *User {
	t.Helper()
	u, ok := s.Get(id)
	if !ok {
		t.Fatalf("account %s is gone", id)
	}
	return u
}

// lockoutFor is one window, then three times the one before, capped at
// one hour (#70) -- or at the window itself, when that is longer.
func TestLockoutForEscalatesAndCaps(t *testing.T) {
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	for n, minutes := range map[int]time.Duration{
		0: 5, 1: 5, 2: 15, 3: 45, 4: 60, 5: 60, 6: 60, 7: 60, 8: 60, 1000: 60,
	} {
		if got := l.lockoutFor(n); got != minutes*time.Minute {
			t.Errorf("lockoutFor(%d) = %v, want %v", n, got, minutes*time.Minute)
		}
	}
	long := mustNewLoginLimiter(t, 5, 48*time.Hour)
	if got := long.lockoutFor(3); got != 48*time.Hour {
		t.Errorf("with a 48h window, lockoutFor(3) = %v, want the window itself", got)
	}
}

// Each lockout's start writes its number next to its end; the fiftieth
// failure, and not the forty-ninth, writes the disable too, dated at
// that attempt.
func TestLockoutRecordCarriesTheCountAndTheDisable(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := escalationStart
	for n := 1; n <= 9; n++ {
		at = failWindow(t, l, s, id, at).Add(time.Second)
		if got := mustGet(t, s, id).LoginLockoutCount; got != n {
			t.Fatalf("after lockout %d the record counts %d", n, got)
		}
	}
	for range 4 {
		l.ReserveAccount(s, id, at)
	}
	if u := mustGet(t, s, id); !u.LoginDisabledAt.IsZero() {
		t.Fatalf("49 failures disabled sign-in at %v", u.LoginDisabledAt)
	}
	fiftieth := at.Add(time.Second)
	if !l.ReserveAccount(s, id, fiftieth) {
		t.Fatal("the fiftieth attempt was refused before it was made")
	}
	u := mustGet(t, s, id)
	if !u.LoginDisabledAt.Equal(fiftieth) {
		t.Errorf("LoginDisabledAt = %v after the fiftieth failure, want %v", u.LoginDisabledAt, fiftieth)
	}
	if u.LoginLockoutCount != 10 || !u.LoginLockedUntil.Equal(fiftieth.Add(time.Hour)) {
		t.Errorf("the fiftieth failure recorded lockout %d until %v, want the tenth, an hour on", u.LoginLockoutCount, u.LoginLockedUntil)
	}
}

// A threshold that does not divide fifty disables sign-in partway
// through a window, at the fiftieth failure all the same.
func TestDisableLandsMidWindow(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	l := mustNewLoginLimiter(t, 3, time.Minute)
	at := failConsecutively(t, l, s, id, 48, escalationStart) // 16 lockouts
	if !l.ReserveAccount(s, id, at) {
		t.Fatal("failure 49 refused")
	}
	if !mustGet(t, s, id).LoginDisabledAt.IsZero() {
		t.Fatal("49 failures disabled sign-in")
	}
	if !l.ReserveAccount(s, id, at) {
		t.Fatal("failure 50 refused")
	}
	if mustGet(t, s, id).LoginDisabledAt.IsZero() {
		t.Error("50 failures, the last two mid-window, did not disable sign-in")
	}
	if l.ReserveAccount(s, id, at.Add(time.Second)) {
		t.Error("an attempt after the mid-window disable was admitted")
	}
}

// The attempt that reached a lockout, or the disable, turning out to be
// the right password undoes what it alone completed: one lockout fewer,
// no disable. It resets nothing else.
func TestASuccessHandsBackTheLockoutAndDisableItCompleted(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := failConsecutively(t, l, s, id, MaxConsecutiveLoginFailures-1, escalationStart)
	if !l.ReserveAccount(s, id, at) {
		t.Fatal("the fiftieth attempt was refused")
	}
	if mustGet(t, s, id).LoginDisabledAt.IsZero() {
		t.Fatal("test setup: the fiftieth attempt did not disable sign-in")
	}
	l.ReleaseAccount(s, id, at) // it was the right password
	u := mustGet(t, s, id)
	if !u.LoginDisabledAt.IsZero() || !u.LoginLockedUntil.IsZero() || u.LoginLockoutCount != 9 {
		t.Errorf("after a success on the fiftieth attempt: disabled %v, locked until %v, count %d; want none, none, 9",
			u.LoginDisabledAt, u.LoginLockedUntil, u.LoginLockoutCount)
	}
	// Still 49 in a row: the next failure is the fiftieth.
	if !l.ReserveAccount(s, id, at.Add(time.Second)) {
		t.Fatal("the attempt after the success was refused")
	}
	if mustGet(t, s, id).LoginDisabledAt.IsZero() {
		t.Error("the failure after a correct password alone did not count as the fiftieth")
	}
}

// A completed sign-in drops the whole count: the record's lockouts, a
// lockout or disable decided while it was in flight, and the attempts in
// the window. An ordinary sign-in, with nothing to drop, writes nothing.
func TestSignedInResetsTheWholeCount(t *testing.T) {
	b := &countingBackend{Memory: persist.NewMemory()}
	s, id := openLockoutStore(t, b)
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)

	before := b.saves.Load()
	l.ReserveAccount(s, id, escalationStart)
	l.SignedIn(s, id, escalationStart)
	if got := b.saves.Load() - before; got != 0 {
		t.Errorf("an ordinary sign-in cost %d saves, want none", got)
	}

	at := failConsecutively(t, l, s, id, 14, escalationStart) // two lockouts and 4 in the window
	if !l.ReserveAccount(s, id, at) {                         // the fifteenth: starts the third lockout
		t.Fatal("the fifteenth attempt was refused")
	}
	before = b.saves.Load()
	l.SignedIn(s, id, at)
	if got := b.saves.Load() - before; got != 1 {
		t.Errorf("the sign-in's reset cost %d saves, want 1", got)
	}
	u := mustGet(t, s, id)
	if u.LoginLockoutCount != 0 || !u.LoginLockedUntil.IsZero() || !u.LoginDisabledAt.IsZero() {
		t.Errorf("after a completed sign-in: count %d, locked until %v, disabled %v; want all clear",
			u.LoginLockoutCount, u.LoginLockedUntil, u.LoginDisabledAt)
	}
	// The window's attempts went too: four more failures start nothing.
	for range 4 {
		l.ReserveAccount(s, id, at)
	}
	if !mustGet(t, s, id).LoginLockedUntil.IsZero() {
		t.Error("attempts from before the sign-in still counted toward a lockout")
	}
	if got := failWindow(t, l, s, id, at.Add(time.Hour)).Sub(at.Add(time.Hour)); got != 5*time.Minute {
		t.Errorf("the first lockout after a sign-in lasts %v, want 5m", got)
	}
}

// UnlockLogin lifts a disable and clears the count and the lockout, in
// one write; with nothing to clear it writes nothing.
func TestUnlockLoginClearsTheDisableTheCountAndTheLockout(t *testing.T) {
	b := &countingBackend{Memory: persist.NewMemory()}
	s, id := openLockoutStore(t, b)
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := failConsecutively(t, l, s, id, MaxConsecutiveLoginFailures, escalationStart)

	before := b.saves.Load()
	if err := s.UnlockLogin(id); err != nil {
		t.Fatal(err)
	}
	if got := b.saves.Load() - before; got != 1 {
		t.Errorf("UnlockLogin cost %d saves, want 1", got)
	}
	u := mustGet(t, s, id)
	if !u.LoginDisabledAt.IsZero() || u.LoginLockoutCount != 0 || !u.LoginLockedUntil.IsZero() {
		t.Errorf("after UnlockLogin: disabled %v, count %d, locked until %v; want all clear",
			u.LoginDisabledAt, u.LoginLockoutCount, u.LoginLockedUntil)
	}
	if !mustNewLoginLimiter(t, 5, 5*time.Minute).ReserveAccount(s, id, at) {
		t.Error("a fresh limiter refused the unlocked account")
	}

	before = b.saves.Load()
	if err := s.UnlockLogin(id); err != nil {
		t.Fatal(err)
	}
	if got := b.saves.Load() - before; got != 0 {
		t.Errorf("UnlockLogin with nothing to clear cost %d saves, want none", got)
	}
	if err := s.UnlockLogin("no-such-account"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("UnlockLogin on an unknown account: %v, want ErrUserNotFound", err)
	}
}

// A disable whose save failed is enforced from memory, and saved by a
// refused attempt once the backend is back -- so a restart after that
// is still disabled.
func TestUnsavedDisableIsEnforcedAndSavedLater(t *testing.T) {
	b := &flakySaveBackend{Memory: persist.NewMemory()}
	s, id := openLockoutStore(t, b)
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := failConsecutively(t, l, s, id, MaxConsecutiveLoginFailures-1, escalationStart)

	b.fail.Store(true)
	if !l.ReserveAccount(s, id, at) {
		t.Fatal("the fiftieth attempt was refused")
	}
	if !mustGet(t, s, id).LoginDisabledAt.IsZero() {
		t.Fatal("test setup: the disable was saved although every save failed")
	}
	later := at.Add(23 * time.Hour) // still inside the 24 hours (#70)
	if l.ReserveAccount(s, id, later) {
		t.Fatal("an unsaved disable was not enforced from memory")
	}

	b.fail.Store(false)
	if l.ReserveAccount(s, id, later.Add(lockoutRetryInterval)) {
		t.Fatal("the retry let an attempt through")
	}
	if !mustGet(t, s, id).LoginDisabledAt.Equal(at) {
		t.Fatalf("the retried disable is not on the record: %v", mustGet(t, s, id).LoginDisabledAt)
	}
	restarted, err := OpenStore(b.Memory, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if mustNewLoginLimiter(t, 5, 5*time.Minute).ReserveAccount(restarted, id, later.Add(time.Minute)) {
		t.Error("a restart after the backend recovered lifted the disable")
	}
}

// A burst of concurrent attempts at the account's last window admits
// exactly the window's worth, and leaves it disabled.
func TestConcurrentAttemptsAtTheLastWindow(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := failConsecutively(t, l, s, id, MaxConsecutiveLoginFailures-5, escalationStart)

	var admitted atomic.Int64
	var wg sync.WaitGroup
	for range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.ReserveAccount(s, id, at) {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := admitted.Load(); got != 5 {
		t.Errorf("%d of 40 concurrent attempts admitted, want 5", got)
	}
	if mustGet(t, s, id).LoginDisabledAt.IsZero() {
		t.Error("the burst's fiftieth failure did not disable sign-in")
	}
}

// Five second-factor failures in a row set MustChangePassword, in one
// write; four do not, and the ones after the fifth write nothing more.
// A completed sign-in, or a new password, starts the run again.
func TestSecondFactorFailuresRequireAPasswordChange(t *testing.T) {
	t.Run("the fifth", func(t *testing.T) {
		b := &countingBackend{Memory: persist.NewMemory()}
		s, id := openLockoutStore(t, b)
		l := mustNewLoginLimiter(t, 5, 5*time.Minute)
		for i := 1; i <= 4; i++ {
			l.SecondFactorFailed(s, id, escalationStart)
		}
		if mustGet(t, s, id).MustChangePassword {
			t.Fatal("four second-factor failures required a password change")
		}
		before := b.saves.Load()
		l.SecondFactorFailed(s, id, escalationStart)
		if !mustGet(t, s, id).MustChangePassword {
			t.Fatal("five second-factor failures did not require a password change")
		}
		for range 20 {
			l.SecondFactorFailed(s, id, escalationStart)
		}
		if got := b.saves.Load() - before; got != 1 {
			t.Errorf("the run cost %d saves, want 1", got)
		}
	})
	t.Run("a sign-in starts it again", func(t *testing.T) {
		s, id := openLockoutStore(t, persist.NewMemory())
		l := mustNewLoginLimiter(t, 5, 5*time.Minute)
		for range 4 {
			l.SecondFactorFailed(s, id, escalationStart)
		}
		l.SignedIn(s, id, escalationStart)
		for range 4 {
			l.SecondFactorFailed(s, id, escalationStart)
		}
		if mustGet(t, s, id).MustChangePassword {
			t.Error("failures either side of a completed sign-in were counted as one run")
		}
	})
	t.Run("a new password starts it again", func(t *testing.T) {
		s, id := openLockoutStore(t, persist.NewMemory())
		l := mustNewLoginLimiter(t, 5, 5*time.Minute)
		for range 4 {
			l.SecondFactorFailed(s, id, escalationStart)
		}
		if err := s.SetPassword("alice", "a-brand-new-password", escalationStart.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		l.SecondFactorFailed(s, id, escalationStart.Add(2*time.Minute))
		if mustGet(t, s, id).MustChangePassword {
			t.Error("failures before a password change counted toward a run after it")
		}
	})
}

// A record that carries a lockout has a PasswordChangedAt that was not a
// password change since it (readRecord): an older build wrote an SSO
// link's time there. Dated inside a run of second-factor failures, it
// must not start the run again, or the fifth never comes.
func TestSecondFactorRunIgnoresAChangeDateUnderALockout(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	l.SecondFactorFailed(s, id, escalationStart)
	// The record a migrated SSO link leaves: a change date after the run
	// began, and a lockout still on it.
	if err := s.SetPassword("alice", "a-brand-new-password", escalationStart.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLoginLockedUntil(id, escalationStart.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for i := 2; i <= 5; i++ {
		l.SecondFactorFailed(s, id, escalationStart.Add(time.Duration(i)*time.Minute))
	}
	fifth := escalationStart.Add(5 * time.Minute)
	u := mustGet(t, s, id)
	if !u.MustChangePassword || !u.SessionsEndedAt.Equal(fifth) {
		t.Errorf("five second-factor failures under a lockout: MustChangePassword %v, SessionsEndedAt %v; want true, %v",
			u.MustChangePassword, u.SessionsEndedAt, fifth)
	}
}

// An SSO-only account has no password to change: five second-factor
// failures end its sessions but do not set MustChangePassword, which
// would shut it out behind a door that refuses it.
func TestSecondFactorFailuresOnAnSSOOnlyAccountEndSessionsOnly(t *testing.T) {
	s, _ := openLockoutStore(t, persist.NewMemory())
	u, _, err := s.FindOrCreateOIDCUser("https://idp.example", "subject-frodo", "frodo", escalationStart)
	if err != nil {
		t.Fatal(err)
	}
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	for i := 1; i <= 5; i++ {
		l.SecondFactorFailed(s, u.ID, escalationStart.Add(time.Duration(i)*time.Minute))
	}
	fifth := escalationStart.Add(5 * time.Minute)
	got := mustGet(t, s, u.ID)
	if got.MustChangePassword {
		t.Error("five second-factor failures required an SSO-only account to change a password it has not got")
	}
	if !got.SessionsEndedAt.Equal(fifth) {
		t.Errorf("SessionsEndedAt = %v, want %v", got.SessionsEndedAt, fifth)
	}
}
