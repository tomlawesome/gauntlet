package gauntlet

import (
	"errors"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// An administrator's allowance of an account's next sign-in (#81): the
// window it records, and everything that ends it.

func TestAllowNextSignInRecordsTheWindow(t *testing.T) {
	s, id, _ := openJudgeStore(t)
	at := escalationStart

	got, err := s.AllowNextSignIn(id, at)
	if err != nil {
		t.Fatalf("AllowNextSignIn: %v", err)
	}
	want := at.Add(SignInAllowanceLifetime)
	if !got.SignInAllowedUntil.Equal(want) {
		t.Errorf("returned window ends %v, want %v", got.SignInAllowedUntil, want)
	}
	if got.PasswordHash != "" || got.ResetCodeHash != "" || got.TOTPSecret != "" {
		t.Errorf("the returned copy carries credentials: %+v", got)
	}
	if u := mustGet(t, s, id); !u.SignInAllowedUntil.Equal(want) {
		t.Errorf("stored window ends %v, want %v", u.SignInAllowedUntil, want)
	}

	// A second call starts a fresh window, replacing the first.
	later := at.Add(4 * time.Minute)
	if _, err := s.AllowNextSignIn(id, later); err != nil {
		t.Fatal(err)
	}
	u := mustGet(t, s, id)
	if want := later.Add(SignInAllowanceLifetime); !u.SignInAllowedUntil.Equal(want) {
		t.Errorf("after a second call the window ends %v, want %v", u.SignInAllowedUntil, want)
	}

	end := u.SignInAllowedUntil
	if !u.SignInAllowanceLive(end.Add(-time.Nanosecond)) {
		t.Error("SignInAllowed is false just before the window ends")
	}
	if u.SignInAllowanceLive(end) {
		t.Error("SignInAllowed is true at the instant the window ends")
	}
	if (&User{}).SignInAllowanceLive(at) {
		t.Error("an account with no allowance is allowed")
	}

	if _, err := s.AllowNextSignIn("no-such-id", at); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("unknown account: %v, want ErrUserNotFound", err)
	}
	mem, err := OpenStore(nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mem.AllowNextSignIn("any-id", at); !errors.Is(err, ErrNotPersisted) {
		t.Errorf("a store with no backend: %v, want ErrNotPersisted", err)
	}
}

// The window is saved on the account's record, so a restart -- a new
// store over the same backend -- still has it.
func TestAllowanceSurvivesAReopen(t *testing.T) {
	m := persist.NewMemory()
	s, id := openLockoutStore(t, m)
	at := escalationStart
	if _, err := s.AllowNextSignIn(id, at); err != nil {
		t.Fatal(err)
	}
	again, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if u := mustGet(t, again, id); !u.SignInAllowedUntil.Equal(at.Add(SignInAllowanceLifetime)) {
		t.Errorf("after a reopen the window ends %v", u.SignInAllowedUntil)
	}
}

// Any completed sign-in spends the allowance, in the one write that
// remembers it, whichever browser it came from.
func TestRememberSignInSpendsTheAllowance(t *testing.T) {
	s, id, b := openJudgeStore(t)
	at := escalationStart
	if _, err := s.AllowNextSignIn(id, at); err != nil {
		t.Fatal(err)
	}
	before := b.saves.Load()
	mustRememberSignIn(t, s, id, "", "GB", nil, at.Add(time.Minute))
	if n := b.saves.Load() - before; n != 1 {
		t.Errorf("RememberSignIn made %d writes, want 1", n)
	}
	if u := mustGet(t, s, id); !u.SignInAllowedUntil.IsZero() {
		t.Errorf("after a completed sign-in the window ends %v, want none", u.SignInAllowedUntil)
	}
}

// Wherever known browsers are cleared, the allowance goes with them.
func TestAllowanceIsClearedWithKnownBrowsers(t *testing.T) {
	s, id, b := openJudgeStore(t)
	at := escalationStart

	// Only the allowance is set: still something to clear, so a write.
	if _, err := s.AllowNextSignIn(id, at); err != nil {
		t.Fatal(err)
	}
	if u := mustGet(t, s, id); len(u.KnownBrowsers) != 0 || u.SeenCountries != nil || u.LastPlace != nil {
		t.Fatalf("precondition: the account remembers %+v %+v %+v", u.KnownBrowsers, u.SeenCountries, u.LastPlace)
	}
	before := b.saves.Load()
	if err := s.ClearKnownBrowsers(id); err != nil {
		t.Fatal(err)
	}
	if b.saves.Load() != before+1 {
		t.Errorf("ClearKnownBrowsers with only an allowance made %d writes, want 1", b.saves.Load()-before)
	}
	if u := mustGet(t, s, id); !u.SignInAllowedUntil.IsZero() {
		t.Errorf("ClearKnownBrowsers left the window ending %v", u.SignInAllowedUntil)
	}

	if _, err := s.AllowNextSignIn(id, at); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.IssueResetCode(id, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if u := mustGet(t, s, id); !u.SignInAllowedUntil.IsZero() {
		t.Errorf("IssueResetCode left the window ending %v", u.SignInAllowedUntil)
	}
}
