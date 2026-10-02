package gauntlet

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// The known-browser allowance (#44), on the record and in the limiter.

func mustRemember(t *testing.T, s *Store, id, replacing string, at time.Time) string {
	t.Helper()
	token, err := s.RememberBrowser(id, replacing, at)
	if err != nil {
		t.Fatalf("RememberBrowser: %v", err)
	}
	return token
}

// A remembered browser's token is known to its account only, in the
// shape it was issued; the record holds its SHA-256, never the token.
func TestRememberBrowserIssuesATokenOnlyItsAccountKnows(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	bob, err := s.CreateUser("bob", "password456", RoleUser, escalationStart)
	if err != nil {
		t.Fatal(err)
	}
	token := mustRemember(t, s, id, "", escalationStart)

	if !s.KnowsBrowser(id, token, escalationStart.Add(time.Hour)) {
		t.Fatal("the account does not know the browser it just remembered")
	}
	u := mustGet(t, s, id)
	if len(u.KnownBrowsers) != 1 || u.KnownBrowsers[0].Hash != knownBrowserHash(token) || strings.Contains(u.KnownBrowsers[0].Hash, token) {
		t.Fatalf("record = %+v, want one entry holding the token's SHA-256", u.KnownBrowsers)
	}
	if !u.KnownBrowsers[0].IssuedAt.Equal(escalationStart) {
		t.Errorf("IssuedAt = %v, want %v", u.KnownBrowsers[0].IssuedAt, escalationStart)
	}

	forged := newKnownBrowserToken()
	for name, c := range map[string]struct{ id, token string }{
		"another account":           {bob.ID, token},
		"an unknown account":        {"no-such-id", token},
		"a forged token":            {id, forged},
		"the stored hash as token":  {id, u.KnownBrowsers[0].Hash},
		"a truncated token":         {id, token[:len(token)-1]},
		"a token with bad encoding": {id, strings.Repeat("!", len(token))},
		"no token":                  {id, ""},
	} {
		if s.KnowsBrowser(c.id, c.token, escalationStart.Add(time.Hour)) {
			t.Errorf("%s is known", name)
		}
	}
	if _, err := s.RememberBrowser("no-such-id", "", escalationStart); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("remembering for an unknown account: %v, want ErrUserNotFound", err)
	}
}

// Each sign-in rotates the browser's token: the one it carried leaves
// the record in the same write, so it stops working and the browser
// holds one entry, renewed.
func TestRememberBrowserRotatesTheBrowsersToken(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	first := mustRemember(t, s, id, "", escalationStart)
	later := escalationStart.Add(40 * 24 * time.Hour)
	second := mustRemember(t, s, id, first, later)

	if first == second {
		t.Fatal("rotation handed back the same token")
	}
	if s.KnowsBrowser(id, first, later) {
		t.Error("the replaced token still works")
	}
	if !s.KnowsBrowser(id, second, later.Add(44*24*time.Hour)) {
		t.Error("the rotated token does not last its own 45 days")
	}
	if n := len(mustGet(t, s, id).KnownBrowsers); n != 1 {
		t.Errorf("the record holds %d entries for one browser, want 1", n)
	}
}

// An account remembers at most MaxKnownBrowsers (3); a fourth evicts the
// one remembered longest ago.
func TestRememberBrowserKeepsThreeAndEvictsTheOldest(t *testing.T) {
	if MaxKnownBrowsers != 3 {
		t.Fatalf("MaxKnownBrowsers = %d, want 3 (owner, 2026-10-02)", MaxKnownBrowsers)
	}
	s, id := openLockoutStore(t, persist.NewMemory())
	var tokens []string
	for i := range 4 {
		tokens = append(tokens, mustRemember(t, s, id, "", escalationStart.Add(time.Duration(i)*time.Hour)))
	}
	now := escalationStart.Add(4 * time.Hour)
	if s.KnowsBrowser(id, tokens[0], now) {
		t.Error("the oldest browser was not evicted by the fourth")
	}
	for i, token := range tokens[1:] {
		if !s.KnowsBrowser(id, token, now) {
			t.Errorf("browser %d of the newest three is not known", i+2)
		}
	}
	if n := len(mustGet(t, s, id).KnownBrowsers); n != MaxKnownBrowsers {
		t.Errorf("the record holds %d, want %d", n, MaxKnownBrowsers)
	}
}

// The lifetime is 45 days from the sign-in, checked on the server: a
// 44-day-old entry is known, a 45- or 46-day-old one grants nothing,
// whatever the cookie's own Max-Age. One dated ahead of now is refused
// until now reaches it. The next remember drops the expired.
func TestAKnownBrowserExpiresAfterFortyFiveDays(t *testing.T) {
	if KnownBrowserLifetime != 45*24*time.Hour {
		t.Fatalf("KnownBrowserLifetime = %v, want 45 days (owner, 2026-10-02)", KnownBrowserLifetime)
	}
	s, id := openLockoutStore(t, persist.NewMemory())
	token := mustRemember(t, s, id, "", escalationStart)
	day := 24 * time.Hour
	if !s.KnowsBrowser(id, token, escalationStart.Add(44*day)) {
		t.Error("a 44-day-old entry is not known")
	}
	for _, days := range []time.Duration{45, 46, 400} {
		if s.KnowsBrowser(id, token, escalationStart.Add(days*day)) {
			t.Errorf("a %d-day-old entry is still known", days/day)
		}
	}
	if s.KnowsBrowser(id, token, escalationStart.Add(-time.Second)) {
		t.Error("an entry dated ahead of now is known")
	}

	other := mustRemember(t, s, id, "", escalationStart.Add(46*day))
	u := mustGet(t, s, id)
	if len(u.KnownBrowsers) != 1 || u.KnownBrowsers[0].Hash != knownBrowserHash(other) {
		t.Errorf("after a remember 46 days on, the record = %+v, want only the new entry", u.KnownBrowsers)
	}
}

// ClearKnownBrowsers forgets them all; IssueResetCode does too, in its
// own write.
func TestClearKnownBrowsersAndResetCodeForgetThemAll(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	token := mustRemember(t, s, id, "", escalationStart)
	if err := s.ClearKnownBrowsers(id); err != nil {
		t.Fatal(err)
	}
	if s.KnowsBrowser(id, token, escalationStart) || len(mustGet(t, s, id).KnownBrowsers) != 0 {
		t.Error("ClearKnownBrowsers left a browser known")
	}
	if err := s.ClearKnownBrowsers(id); err != nil {
		t.Errorf("clearing nothing: %v", err)
	}
	if err := s.ClearKnownBrowsers("no-such-id"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("clearing an unknown account: %v, want ErrUserNotFound", err)
	}

	token = mustRemember(t, s, id, "", escalationStart)
	if _, _, err := s.IssueResetCode(id, escalationStart.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if s.KnowsBrowser(id, token, escalationStart.Add(time.Minute)) {
		t.Error("a reset code left a browser known")
	}
}

// List blanks each hash and keeps when it was remembered, without
// touching the account's own record.
func TestListBlanksKnownBrowserHashes(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	token := mustRemember(t, s, id, "", escalationStart)
	for _, u := range s.List() {
		if u.ID != id {
			continue
		}
		if len(u.KnownBrowsers) != 1 || u.KnownBrowsers[0].Hash != "" || !u.KnownBrowsers[0].IssuedAt.Equal(escalationStart) {
			t.Errorf("List's copy = %+v, want one entry, hash blanked, IssuedAt kept", u.KnownBrowsers)
		}
	}
	if !s.KnowsBrowser(id, token, escalationStart) {
		t.Error("List blanked the stored record")
	}
}

// failKnown makes n attempts through the known browser's allowance at
// at, all admitted.
func failKnown(t *testing.T, l *LoginLimiter, s *Store, id string, n int, at time.Time) {
	t.Helper()
	for i := range n {
		if !l.ReserveKnownBrowser(s, id, at) {
			t.Fatalf("known-browser attempt %d at %v was refused", i+1, at)
		}
	}
}

// During a lockout the account's ordinary budget refuses everything,
// while the known browser has threshold attempts per window of its own.
// The attempt that fills that budget closes it for one window and adds
// one lockout's worth to the account's count -- the lockout's end left
// as it was -- and it opens again a window later, with no escalation.
func TestKnownBrowserAllowanceOutlastsALockoutWithoutEscalating(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	start := failConsecutively(t, l, s, id, 15, escalationStart) // three lockouts, waited out
	failWindow(t, l, s, id, start)                               // a fourth, 135 minutes from start
	locked := mustGet(t, s, id)
	now := start.Add(time.Minute)
	if l.ReserveAccount(s, id, now) {
		t.Fatal("the ordinary budget admitted an attempt during the lockout")
	}

	failKnown(t, l, s, id, 5, now)
	if l.ReserveKnownBrowser(s, id, now.Add(4*time.Minute)) {
		t.Fatal("a sixth known-browser attempt inside the window was admitted")
	}
	u := mustGet(t, s, id)
	if u.LoginLockoutCount != locked.LoginLockoutCount+1 || !u.LoginLockedUntil.Equal(locked.LoginLockedUntil) {
		t.Errorf("after the known budget filled: count %d, until %v; want count %d, until unchanged %v",
			u.LoginLockoutCount, u.LoginLockedUntil, locked.LoginLockoutCount+1, locked.LoginLockedUntil)
	}
	failKnown(t, l, s, id, 5, now.Add(5*time.Minute+time.Second))
}

// It is no way round the disable: refused outright once the account is
// disabled, and the failures through it bring the disable on, at the
// fiftieth exactly.
func TestKnownBrowserFailuresCountTowardTheDisable(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := failConsecutively(t, l, s, id, 40, escalationStart)
	failWindow(t, l, s, id, at) // 45, locked out
	at = at.Add(time.Second)

	failKnown(t, l, s, id, 4, at)
	if u := mustGet(t, s, id); !u.LoginDisabledAt.IsZero() {
		t.Fatal("49 failures disabled the account")
	}
	failKnown(t, l, s, id, 1, at)
	if u := mustGet(t, s, id); u.LoginDisabledAt.IsZero() {
		t.Fatal("the fiftieth failure, through the known browser, did not disable the account")
	}
	if l.ReserveKnownBrowser(s, id, at.Add(time.Hour)) {
		t.Error("the known browser was admitted on a disabled account")
	}
}

// A right password through the allowance hands its count back; if its
// failure had filled the budget, the lockout's worth and the disable it
// brought are undone too, but an ordinary lockout in force is left. A
// completed sign-in drops the allowance's count, and so does an unlock.
func TestReleaseKnownBrowserAndSignedInHandTheCountBack(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := failConsecutively(t, l, s, id, 40, escalationStart)
	failWindow(t, l, s, id, at) // 45, locked out
	locked := mustGet(t, s, id)
	now := at.Add(time.Second)
	if !now.Before(locked.LoginLockedUntil) {
		t.Fatal("precondition: the ordinary lockout is not in force")
	}

	failKnown(t, l, s, id, 5, now) // the fifth disables
	l.ReleaseKnownBrowser(s, id, now)
	u := mustGet(t, s, id)
	if !u.LoginDisabledAt.IsZero() || u.LoginLockoutCount != locked.LoginLockoutCount || !u.LoginLockedUntil.Equal(locked.LoginLockedUntil) {
		t.Fatalf("after the release: disabled %v, count %d, until %v; want none, %d, %v",
			u.LoginDisabledAt, u.LoginLockoutCount, u.LoginLockedUntil, locked.LoginLockoutCount, locked.LoginLockedUntil)
	}
	failKnown(t, l, s, id, 1, now) // the slot it handed back

	l.SignedIn(s, id, now)
	failKnown(t, l, s, id, 4, now) // the allowance's own count is gone
	if err := l.UnlockLogin(s, id); err != nil {
		t.Fatal(err)
	}
	failKnown(t, l, s, id, 4, now)
}

// A password change ends the allowance's count of guesses before it, as
// it ends the ordinary one's.
func TestKnownBrowserGuessesBeforeAPasswordChangeStopCounting(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	failKnown(t, l, s, id, 5, escalationStart)
	if l.ReserveKnownBrowser(s, id, escalationStart) {
		t.Fatal("the known budget was not full")
	}
	if err := s.SetPassword("alice", "a-new-password", escalationStart.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	failKnown(t, l, s, id, 5, escalationStart.Add(2*time.Second))
}
