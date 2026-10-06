package gauntlet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// Part 2 of #44 on the record: the forced password change ends every
// session, and a reset code lifts a disabled sign-in.

// The fifth second-factor failure in a row sets MustChangePassword and,
// in the same write, ends every session the account holds: only a fresh
// sign-in with both factors reaches the change-password door, which
// asks for no current password (owner, 2026-10-02).
func TestTheForcedPasswordChangeEndsEverySession(t *testing.T) {
	b := &countingBackend{Memory: persist.NewMemory()}
	s, id := openLockoutStore(t, b)
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	for i := 1; i <= 4; i++ {
		l.SecondFactorFailed(s, id, escalationStart.Add(time.Duration(i)*time.Second))
	}
	if got := mustGet(t, s, id).SessionCutoff(); !got.IsZero() {
		t.Fatalf("four second-factor failures moved the session cutoff to %v", got)
	}
	fifth := escalationStart.Add(5 * time.Second)
	before := b.saves.Load()
	l.SecondFactorFailed(s, id, fifth)
	u := mustGet(t, s, id)
	if !u.MustChangePassword {
		t.Fatal("five second-factor failures did not require a password change")
	}
	if !u.SessionsEndedAt.Equal(fifth) || !u.SessionCutoff().Equal(fifth) {
		t.Errorf("after the fifth failure SessionsEndedAt = %v, cutoff %v; want both %v",
			u.SessionsEndedAt, u.SessionCutoff(), fifth)
	}
	if got := b.saves.Load() - before; got != 1 {
		t.Errorf("setting the flag and ending the sessions cost %d saves, want 1", got)
	}
	// Guesses at the old password still count: ending sessions is not a
	// password change.
	if !u.PasswordChangedAt.IsZero() {
		t.Errorf("PasswordChangedAt moved to %v; ending sessions is not a password change", u.PasswordChangedAt)
	}
}

// Issuing a reset code is itself an admin action, so it lifts a
// disabled sign-in and clears the count of lockouts in the same write
// (owner, 2026-10-02): the owner signs in with the code at once.
func TestAResetCodeLiftsADisabledSignIn(t *testing.T) {
	b := &countingBackend{Memory: persist.NewMemory()}
	s, _ := openLockoutStore(t, b)
	bob, err := s.CreateUser("bob", "bob-password-1", RoleUser, escalationStart)
	if err != nil {
		t.Fatal(err)
	}
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := failConsecutively(t, l, s, bob.ID, MaxConsecutiveLoginFailures, escalationStart)
	if mustGet(t, s, bob.ID).LoginDisabledAt.IsZero() {
		t.Fatal("fifty failures did not disable sign-in")
	}

	before := b.saves.Load()
	_, code, err := s.IssueResetCode(bob.ID, at)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.saves.Load() - before; got != 1 {
		t.Errorf("IssueResetCode cost %d saves, want 1", got)
	}
	u := mustGet(t, s, bob.ID)
	if !u.LoginDisabledAt.IsZero() || u.LoginLockoutCount != 0 || !u.LoginLockedUntil.IsZero() {
		t.Errorf("after a reset code: disabled %v, count %d, locked until %v; want all clear",
			u.LoginDisabledAt, u.LoginLockoutCount, u.LoginLockedUntil)
	}
	// The same limiter, still running, lets the owner in with the code.
	if !l.ReserveAccount(s, bob.ID, at.Add(time.Second)) {
		t.Fatal("the limiter that disabled the account refused it after a reset code")
	}
	if _, err := s.Authenticate("bob", code, at.Add(time.Second)); err != nil {
		t.Errorf("signing in with the reset code: %v", err)
	}
}

// LoginLimiter.UnlockLogin clears the record as Store.UnlockLogin does,
// and also this limiter's own count of the window's attempts: after a
// store-only unlock, the limiter that counted the guesses still refuses
// the account until that window passes.
func TestLimiterUnlockLoginAlsoClearsItsOwnCount(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	failWindow(t, l, s, id, escalationStart)

	if err := s.UnlockLogin(id); err != nil {
		t.Fatal(err)
	}
	at := escalationStart.Add(time.Minute) // inside the window
	if l.ReserveAccount(s, id, at) {
		t.Fatal("precondition: a store-only unlock was expected to leave the limiter's count refusing the account")
	}

	failWindow(t, l, s, id, at.Add(10*time.Minute))
	if err := l.UnlockLogin(s, id); err != nil {
		t.Fatal(err)
	}
	if !l.ReserveAccount(s, id, at.Add(11*time.Minute)) {
		t.Error("the limiter refused the account it had just unlocked")
	}
	if u := mustGet(t, s, id); !u.LoginLockedUntil.IsZero() || u.LoginLockoutCount != 0 {
		t.Errorf("after LoginLimiter.UnlockLogin: locked until %v, count %d; want clear", u.LoginLockedUntil, u.LoginLockoutCount)
	}
	if err := l.UnlockLogin(s, "no-such-account"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("unlocking an unknown account: %v, want ErrUserNotFound", err)
	}
}

// A disable this limiter decided but could not save is dropped by its
// UnlockLogin, so no later retry writes it back over the unlock.
func TestLimiterUnlockLoginDropsAnUnsavedDisable(t *testing.T) {
	b := &flakySaveBackend{Memory: persist.NewMemory()}
	s, id := openLockoutStore(t, b)
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := failConsecutively(t, l, s, id, MaxConsecutiveLoginFailures-1, escalationStart)
	b.fail.Store(true)
	if !l.ReserveAccount(s, id, at) {
		t.Fatal("the fiftieth attempt was refused")
	}
	if !mustGet(t, s, id).LoginDisabledAt.IsZero() {
		t.Fatal("precondition: the disable was expected to fail to save")
	}
	b.fail.Store(false)
	if err := l.UnlockLogin(s, id); err != nil {
		t.Fatal(err)
	}
	later := at.Add(time.Hour)
	if !l.ReserveAccount(s, id, later) {
		t.Error("an unsaved disable outlived the unlock")
	}
	if !mustGet(t, s, id).LoginDisabledAt.IsZero() {
		t.Error("an unsaved disable was written back after the unlock")
	}
}

// An unlock whose save fails leaves the limiter's disable in place: the
// admin is told the unlock failed, so guessing must not resume. Once a
// save succeeds, the unlock clears it.
func TestLimiterUnlockLoginThatFailsToSaveKeepsTheDisable(t *testing.T) {
	b := &flakySaveBackend{Memory: persist.NewMemory()}
	s, id := openLockoutStore(t, b)
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := failConsecutively(t, l, s, id, MaxConsecutiveLoginFailures-1, escalationStart)
	b.fail.Store(true)
	if !l.ReserveAccount(s, id, at) {
		t.Fatal("the fiftieth attempt was refused")
	}
	if !mustGet(t, s, id).LoginDisabledAt.IsZero() {
		t.Fatal("precondition: the disable was expected to fail to save")
	}

	if err := l.UnlockLogin(s, id); err == nil {
		t.Fatal("UnlockLogin reported success although its save failed")
	}
	later := at.Add(time.Hour)
	if l.ReserveAccount(s, id, later) {
		t.Fatal("a failed unlock let guessing resume")
	}

	b.fail.Store(false)
	if err := l.UnlockLogin(s, id); err != nil {
		t.Fatal(err)
	}
	if !l.ReserveAccount(s, id, later.Add(time.Minute)) {
		t.Error("the limiter refused the account it had just unlocked")
	}
}

// A disable the limiter decided but could not save, then a password
// change once saves work again. A reset code is the admin lifting the
// disable (owner, 2026-10-02), so the code is let in and no retry writes
// the stale disable back over the reset. A password set through
// SetPassword lifts nothing: the disable is still enforced, and saved.
func TestAResetCodeLiftsAnUnsavedDisable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, s *Store, id string, at time.Time)
		lifts  bool
	}{
		{"IssueResetCode", func(t *testing.T, s *Store, id string, at time.Time) {
			if _, _, err := s.IssueResetCode(id, at); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"SetPassword", func(t *testing.T, s *Store, _ string, at time.Time) {
			if err := s.SetPassword("alice", "a-brand-new-password", at); err != nil {
				t.Fatal(err)
			}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &flakySaveBackend{Memory: persist.NewMemory()}
			s, id := openLockoutStore(t, b)
			l := mustNewLoginLimiter(t, 5, 5*time.Minute)
			at := failConsecutively(t, l, s, id, MaxConsecutiveLoginFailures-1, escalationStart)
			b.fail.Store(true)
			if !l.ReserveAccount(s, id, at) {
				t.Fatal("the fiftieth attempt was refused")
			}
			if !mustGet(t, s, id).LoginDisabledAt.IsZero() {
				t.Fatal("precondition: the disable was expected to fail to save")
			}
			b.fail.Store(false)
			tc.change(t, s, id, at.Add(time.Second))

			// Past the retry interval, so a pending disable is saved.
			later := at.Add(time.Second + lockoutRetryInterval)
			if got := l.ReserveAccountDecision(s, id, later).Allowed; got != tc.lifts {
				t.Errorf("first attempt after %s admitted = %v, want %v", tc.name, got, tc.lifts)
			}
			l.ReserveAccount(s, id, later.Add(lockoutRetryInterval))
			disabled := !mustGet(t, s, id).LoginDisabledAt.IsZero()
			if disabled == tc.lifts {
				t.Errorf("after %s and a retry the record's disable is %v, want %v", tc.name, disabled, !tc.lifts)
			}
		})
	}
}

// disabledAdminBackend returns a backend holding one admin, "alice",
// whose sign-in fifty failures have disabled, with a second factor and
// a non-admin "bob"; and alice's ID.
func disabledAdminBackend(t *testing.T) (*persist.Memory, string) {
	t.Helper()
	m := persist.NewMemory()
	s, id := openLockoutStore(t, m)
	setSecondFactorForTest(t, s, id, escalationStart)
	if _, err := s.CreateUser("bob", "bob-password-1", RoleUser, escalationStart); err != nil {
		t.Fatal(err)
	}
	failConsecutively(t, mustNewLoginLimiter(t, 5, 5*time.Minute), s, id, MaxConsecutiveLoginFailures, escalationStart)
	disabledAt := mustGet(t, s, id).LoginDisabledAt
	if disabledAt.IsZero() {
		t.Fatal("fifty failures did not disable the admin")
	}
	// The unlock code reads the disable against its own clock: an hour
	// in, so it is still in force for the rest of the test.
	setUnlockCodeNow(t, disabledAt.Add(time.Hour))
	return m, id
}

// setUnlockCodeNow sets the unlock code's clock to at for the rest of t.
func setUnlockCodeNow(t *testing.T, at time.Time) {
	t.Helper()
	was := unlockCodeNow
	unlockCodeNow = func() time.Time { return at }
	t.Cleanup(func() { unlockCodeNow = was })
}

// openLockoutBackend is a backend holding openLockoutStore's admin,
// alice, with nothing disabled.
func openLockoutBackend(t *testing.T) *persist.Memory {
	t.Helper()
	m := persist.NewMemory()
	openLockoutStore(t, m)
	return m
}

// openWithUnlockHook opens b, capturing the unlock code it announces.
func openWithUnlockHook(t *testing.T, b persist.Backend) (s *Store, username, code string) {
	t.Helper()
	s, err := OpenStore(b, Options{OnUnlockCode: UnlockCodeFunc(func(u, c string) { username, code = u, c })})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	return s, username, code
}

// A store that opens with its admin disabled announces an unlock code
// for that admin; one whose admin is not disabled, or where only a
// non-admin is, announces none.
func TestUnlockCodeIssuedOnlyForADisabledAdmin(t *testing.T) {
	m, _ := disabledAdminBackend(t)
	_, username, code := openWithUnlockHook(t, m)
	if username != "alice" || !setupCodeShape.MatchString(code) {
		t.Fatalf("opening with the admin disabled announced (%q, %q), want alice and a xxxx-xxxx-xxxx-xxxx code", username, code)
	}

	if _, u, c := openWithUnlockHook(t, openLockoutBackend(t)); c != "" {
		t.Errorf("an admin whose sign-in is not disabled got an unlock code (%q, %q)", u, c)
	}

	m2 := persist.NewMemory()
	s2, _ := openLockoutStore(t, m2)
	bob, err := s2.CreateUser("bob", "bob-password-1", RoleUser, escalationStart)
	if err != nil {
		t.Fatal(err)
	}
	failConsecutively(t, mustNewLoginLimiter(t, 5, 5*time.Minute), s2, bob.ID, MaxConsecutiveLoginFailures, escalationStart)
	if _, u, c := openWithUnlockHook(t, m2); c != "" {
		t.Errorf("a disabled non-admin got an unlock code (%q, %q); the admin can unlock that account", u, c)
	}

	if _, u, c := openWithUnlockHook(t, persist.NewMemory()); c != "" {
		t.Errorf("an empty store announced an unlock code (%q, %q)", u, c)
	}
}

// A disable lifts itself LoginDisableDuration after it began (#70): a
// store opening 25 hours after its admin was disabled issues no code,
// since the admin can sign in as normal.
func TestNoUnlockCodeOnceTheDisableHasLifted(t *testing.T) {
	m, id := disabledAdminBackend(t)
	s, _, code := openWithUnlockHook(t, m)
	disabledAt := mustGet(t, s, id).LoginDisabledAt
	setUnlockCodeNow(t, disabledAt.Add(25*time.Hour))
	if _, u, c := openWithUnlockHook(t, m); c != "" {
		t.Errorf("a disable that began 25 hours ago got an unlock code (%q, %q)", u, c)
	}
	if code == "" {
		t.Error("the same store an hour into the disable issued no code")
	}
}

// The rule is that no admin able to unlock the account remains: a
// second admin who can still sign in means no code. The store holds one
// admin today (ErrSingleAdmin), so this is checked on the state itself.
func TestNoUnlockCodeWhileAnotherAdminCanSignIn(t *testing.T) {
	disabled := &User{ID: "a", Username: "alice", Role: RoleAdmin, LoginDisabledAt: escalationStart}
	other := &User{ID: "b", Username: "bob", Role: RoleAdmin}
	st := &storeState{byID: map[string]*User{"a": disabled, "b": other}}
	if got := st.lockedOutAdmin(escalationStart.Add(time.Hour)); got != nil {
		t.Errorf("with another admin able to sign in, %s is reported locked out", got.Username)
	}
	other.LoginDisabledAt = escalationStart
	if got := st.lockedOutAdmin(escalationStart.Add(time.Hour)); got == nil || got.ID != "a" {
		t.Errorf("with every admin disabled, lockedOutAdmin = %v, want alice (first by username)", got)
	}
	st = &storeState{byID: map[string]*User{"a": {ID: "a", Username: "alice", Role: RoleAdmin}}}
	if got := st.lockedOutAdmin(escalationStart.Add(time.Hour)); got != nil {
		t.Error("an admin whose sign-in is not disabled is reported locked out")
	}
}

// With no hook the code goes to the log as one Warn line naming the
// admin; it never reaches the document.
func TestUnlockCodeLoggedAndNeverSaved(t *testing.T) {
	m, _ := disabledAdminBackend(t)
	var buf bytes.Buffer
	if _, err := OpenStore(m, Options{Log: slog.New(slog.NewTextHandler(&buf, nil))}); err != nil {
		t.Fatal(err)
	}
	line := buf.String()
	code := regexp.MustCompile(`[A-Z2-9]{4}(-[A-Z2-9]{4}){3}`).FindString(line)
	if code == "" || !strings.Contains(line, "level=WARN") || !strings.Contains(line, `\"alice\"`) {
		t.Fatalf("log = %q, want one Warn line naming alice with the code", line)
	}

	s, _, code2 := openWithUnlockHook(t, m)
	if err := s.SetPassword("bob", "bob-password-2", escalationStart); err != nil { // any write
		t.Fatal(err)
	}
	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{code, code2, NormaliseResetCode(code2)} {
		if bytes.Contains(snap.Payload, []byte(secret)) {
			t.Errorf("the accounts document contains the unlock code %q", secret)
		}
	}
	sum := sha256.Sum256([]byte(NormaliseResetCode(code2)))
	if bytes.Contains(snap.Payload, []byte(hex.EncodeToString(sum[:]))) || bytes.Contains(snap.Payload, sum[:]) {
		t.Error("the accounts document contains the unlock code's hash")
	}
}

// The right code with the admin's username is accepted, in any case and
// with or without dashes; everything else is refused with the one error,
// whatever is wrong.
func TestUnlockCodeChecked(t *testing.T) {
	m, id := disabledAdminBackend(t)
	s, _, code := openWithUnlockHook(t, m)

	for _, typed := range []string{code, strings.ToLower(strings.ReplaceAll(code, "-", ""))} {
		u, err := s.CheckUnlockCode("ALICE", typed)
		if err != nil || u.ID != id {
			t.Errorf("CheckUnlockCode(alice, %q) = %v, %v; want alice", typed, u, err)
		}
		if u != nil && (u.PasswordHash != "" || u.TOTPSecret != "") {
			t.Error("CheckUnlockCode returned the account's credentials")
		}
	}
	near := []byte(NormaliseResetCode(code))
	near[len(near)-1] = map[bool]byte{true: 'B', false: 'A'}[near[len(near)-1] == 'A']
	for _, c := range []struct{ username, code string }{
		{"alice", string(near)},
		{"alice", ""},
		{"bob", code},
		{"nobody", code},
		{"", code},
	} {
		if _, err := s.CheckUnlockCode(c.username, c.code); !errors.Is(err, ErrUnlockCodeInvalid) {
			t.Errorf("CheckUnlockCode(%q, %q) = %v, want ErrUnlockCodeInvalid", c.username, c.code, err)
		}
	}
	if _, err := openTestStoreWithAdmin(t).CheckUnlockCode("setup-admin", code); !errors.Is(err, ErrUnlockCodeInvalid) {
		t.Errorf("a store with no code outstanding: %v, want ErrUnlockCodeInvalid", err)
	}
}

// Redeeming the code lifts only the disable: the password and the
// second factor are as they were, and the code is spent. Used again, it
// is refused like any wrong code.
func TestUnlockCodeLiftsOnlyTheDisableAndIsSingleUse(t *testing.T) {
	m, id := disabledAdminBackend(t)
	s, _, code := openWithUnlockHook(t, m)
	before := mustGet(t, s, id)
	beforeHash := before.PasswordHash

	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	u, err := s.CheckUnlockCode("alice", code)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.UnlockLogin(s, u.ID); err != nil {
		t.Fatal(err)
	}
	after := mustGet(t, s, id)
	if !after.LoginDisabledAt.IsZero() || after.LoginLockoutCount != 0 {
		t.Errorf("after the unlock code: disabled %v, count %d; want clear", after.LoginDisabledAt, after.LoginLockoutCount)
	}
	if after.PasswordHash != beforeHash || after.MustChangePassword || !after.HasSecondFactor() ||
		!after.SessionCutoff().Equal(before.SessionCutoff()) || after.Role != RoleAdmin {
		t.Error("the unlock code changed more than the disable: password, forced change, second factor, sessions or role")
	}
	if _, err := s.Authenticate("alice", "password-placeholder-1", time.Now()); err != nil {
		t.Errorf("the admin's existing password after the unlock: %v", err)
	}
	if _, err := s.CheckUnlockCode("alice", code); !errors.Is(err, ErrUnlockCodeInvalid) {
		t.Errorf("the code used a second time: %v, want ErrUnlockCodeInvalid", err)
	}

	// Disabled again later, the spent code stays dead.
	failConsecutively(t, l, s, id, MaxConsecutiveLoginFailures, escalationStart.Add(30*24*time.Hour))
	if _, err := s.CheckUnlockCode("alice", code); !errors.Is(err, ErrUnlockCodeInvalid) {
		t.Errorf("a spent code after a second disable: %v, want ErrUnlockCodeInvalid", err)
	}
}

// An unlock by other means ends the code: through this store, and
// through another process sharing the backend.
func TestUnlockCodeDiesWhenTheAdminIsUnlockedOtherwise(t *testing.T) {
	t.Run("this process", func(t *testing.T) {
		m, id := disabledAdminBackend(t)
		s, _, code := openWithUnlockHook(t, m)
		if err := s.UnlockLogin(id); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CheckUnlockCode("alice", code); !errors.Is(err, ErrUnlockCodeInvalid) {
			t.Errorf("after Store.UnlockLogin: %v, want ErrUnlockCodeInvalid", err)
		}
	})
	t.Run("another process", func(t *testing.T) {
		m, id := disabledAdminBackend(t)
		s, _, code := openWithUnlockHook(t, m)
		cli, err := OpenStore(m, Options{OnUnlockCode: UnlockCodeFunc(func(string, string) {})})
		if err != nil {
			t.Fatal(err)
		}
		if err := cli.UnlockLogin(id); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CheckUnlockCode("alice", code); !errors.Is(err, ErrUnlockCodeInvalid) {
			t.Errorf("after another process unlocked the admin: %v, want ErrUnlockCodeInvalid", err)
		}
	})
}

// A store with no backend has nothing to unlock and makes no code.
func TestNoUnlockCodeWithoutPersistence(t *testing.T) {
	s, err := OpenStore(nil, Options{OnUnlockCode: UnlockCodeFunc(func(u, c string) {
		t.Errorf("an unpersisted store announced an unlock code for %q", u)
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CheckUnlockCode("alice", "AAAA-AAAA-AAAA-AAAA"); !errors.Is(err, ErrUnlockCodeInvalid) {
		t.Errorf("CheckUnlockCode on an unpersisted store: %v, want ErrUnlockCodeInvalid", err)
	}
}
