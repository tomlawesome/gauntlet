package gauntlet

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/blocklist"
	"github.com/tomlawesome/gauntlet/persist"
)

// fakeList is an injected common-password list (#43). The real embedded
// list is a placeholder that blocks nothing until the first signed CI
// run (ADR-0005), so every test of the check brings its own.
type fakeList map[string]bool

func (l fakeList) Contains(password string) bool { return l[password] }

// fakeBreach stands in for the live HIBP check. breached holds the
// passwords it reports as breached; err, when set, is what every call
// returns, as an unreachable HIBP would; hang, when set, blocks every
// call until it is closed, ignoring the context, as a checker that
// does not honour its deadline would.
type fakeBreach struct {
	mu       sync.Mutex
	breached map[string]bool
	err      error
	hang     chan struct{}
	calls    []string
}

func (f *fakeBreach) Breached(ctx context.Context, password string) (bool, error) {
	f.mu.Lock()
	f.calls = append(f.calls, password)
	hang, err, hit := f.hang, f.err, f.breached[password]
	f.mu.Unlock()
	if hang != nil {
		<-hang
	}
	if err != nil {
		return false, err
	}
	return hit, nil
}

func (f *fakeBreach) set(breached map[string]bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.breached, f.err = breached, err
}

func (f *fakeBreach) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

var errHIBPUnreachable = errors.New("dial tcp: connection refused")

// openCheckedStore opens a store over a fresh memory backend with opts,
// logging to the returned buffer, and registers the first admin.
func openCheckedStore(t *testing.T, opts Options) (*Store, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	opts.Log = slog.New(slog.NewTextHandler(&logs, nil))
	opts.OnSetupCode = SetupCodeFunc(func(string) {})
	s, err := OpenStore(persist.NewMemory(), opts)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if _, err := s.Register("setup-admin", "a long first-admin passphrase", time.Now()); err != nil {
		t.Fatalf("registering the first admin: %v", err)
	}
	return s, &logs
}

// setPasswordPaths are the ways a local password is chosen after the
// first account; Register, which only ever makes the first, is
// registerWith.
var setPasswordPaths = map[string]func(s *Store, username, password string) error{
	"CreateUser": func(s *Store, username, password string) error {
		_, err := s.CreateUser(username, password, RoleUser, time.Now())
		return err
	},
	"SetPassword": func(s *Store, username, password string) error {
		if _, ok := s.ByUsername(username); !ok {
			if _, err := s.CreateUser(username, "an unremarkable passphrase", RoleUser, time.Now()); err != nil {
				return err
			}
		}
		return s.SetPassword(username, password, time.Now())
	},
}

// registerWith opens an empty store with opts and registers username.
func registerWith(t *testing.T, opts Options, username, password string) (*Store, error) {
	t.Helper()
	opts.OnSetupCode = SetupCodeFunc(func(string) {})
	s, err := OpenStore(persist.NewMemory(), opts)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	_, err = s.Register(username, password, time.Now())
	return s, err
}

// eachPath runs check once per way a password is set, with a store
// opened with opts, and fails unless setting password for username
// returns want.
func eachPath(t *testing.T, opts Options, username, password string, want error) {
	t.Helper()
	t.Run("Register", func(t *testing.T) {
		if _, err := registerWith(t, opts, username, password); !errors.Is(err, want) {
			t.Errorf("Register(%q, %q) = %v, want %v", username, password, err, want)
		}
	})
	for _, name := range []string{"CreateUser", "SetPassword"} {
		t.Run(name, func(t *testing.T) {
			s, _ := openCheckedStore(t, opts)
			if err := setPasswordPaths[name](s, username, password); !errors.Is(err, want) {
				t.Errorf("%s(%q, %q) = %v, want %v", name, username, password, err, want)
			}
		})
	}
}

func TestACommonPasswordIsRefusedEverywhereOneIsSet(t *testing.T) {
	opts := Options{PasswordBlocklist: fakeList{"password123": true, "letmein!!": true}}
	eachPath(t, opts, "alice", "password123", ErrPasswordBlocked)
	// Case-insensitive: a capital letter does not take it off the list.
	eachPath(t, opts, "alice", "PassWord123", ErrPasswordBlocked)
	eachPath(t, opts, "alice", "LETMEIN!!", ErrPasswordBlocked)
	// A long passphrase is not on it, and is accepted.
	eachPath(t, opts, "alice", "correct horse battery staple", nil)
}

func TestAContextSpecificPasswordIsRefused(t *testing.T) {
	opts := Options{
		PasswordBlocklist: fakeList{},
		ProductName:       "Birdcage",
	}
	refused := []string{
		"birdcage",      // the product name
		"Birdcage2026!", // with digits and a symbol on the end
		"!!BIRDCAGE!!",  // with symbols around it, any case
		"aliceliddell",  // the username itself
		"AliceLiddell1", // the username with a digit
		"alice.liddell", // the username with its punctuation moved
		"2024aliceliddell",
	}
	for _, pw := range refused {
		eachPath(t, opts, "alice_liddell", pw, ErrPasswordContext)
	}
	// Whole-string only: a passphrase that contains either name is fine.
	for _, pw := range []string{
		"alice liddell went down the rabbit hole",
		"my birdcage has a blue door",
	} {
		eachPath(t, opts, "alice_liddell", pw, nil)
	}
}

func TestPasswordMatchesContext(t *testing.T) {
	cases := []struct {
		password string
		words    []string
		want     bool
	}{
		{"Gate Test Suite", []string{"gate test suite"}, true},
		{"gatetestsuite99", []string{"Gate Test Suite"}, true},
		{"bob1990!", []string{"bob1990"}, true},
		{"bob", []string{"bob1990"}, true},
		{"12345678", []string{"12345678"}, true},
		{"12345678", []string{"bob"}, false},
		{"bobby1990", []string{"bob1990"}, false},
		{"anything", []string{""}, false},
		{"anything", nil, false},
		{"!!!!!!!!", []string{"!!!"}, false},
	}
	for _, c := range cases {
		if got := PasswordMatchesContext(c.password, c.words...); got != c.want {
			t.Errorf("PasswordMatchesContext(%q, %q) = %v, want %v", c.password, c.words, got, c.want)
		}
	}
}

func TestTheDefaultListIsTheEmbeddedOne(t *testing.T) {
	s := openTestStore(t)
	if got, ok := s.passwordList.(*blocklist.List); !ok || got != blocklist.Embedded() {
		t.Errorf("a store opened with no PasswordBlocklist checks against %T %p, want blocklist.Embedded()", s.passwordList, s.passwordList)
	}
}

func TestABreachedPasswordIsRefused(t *testing.T) {
	hibp := &fakeBreach{breached: map[string]bool{"Tr0ub4dor&3xyz": true}}
	eachPath(t, Options{PasswordBlocklist: fakeList{}, BreachCheck: hibp}, "alice", "Tr0ub4dor&3xyz", ErrPasswordBlocked)
}

func TestACleanBreachCheckAcceptsAndLeavesNoMark(t *testing.T) {
	hibp := &fakeBreach{}
	s, _ := openCheckedStore(t, Options{PasswordBlocklist: fakeList{}, BreachCheck: hibp})
	before := hibp.callCount()
	u, err := s.CreateUser("alice", "correct horse battery staple", RoleUser, time.Now())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if hibp.callCount() != before+1 {
		t.Errorf("the breach check ran %d times for one password, want 1", hibp.callCount()-before)
	}
	if u.BreachCheckPending {
		t.Error("a password HIBP answered for is marked as still to be checked")
	}
}

func TestTheCheapChecksRunBeforeTheBreachCheck(t *testing.T) {
	hibp := &fakeBreach{}
	s, _ := openCheckedStore(t, Options{PasswordBlocklist: fakeList{"password123": true}, BreachCheck: hibp})
	before := hibp.callCount()
	for _, pw := range []string{"short", "password123", "alice2024"} {
		if _, err := s.CreateUser("alice", pw, RoleUser, time.Now()); err == nil {
			t.Fatalf("CreateUser(%q) succeeded", pw)
		}
	}
	if n := hibp.callCount() - before; n != 0 {
		t.Errorf("a password already refused locally went to HIBP %d times", n)
	}
}

func TestAnUnreachableBreachCheckAcceptsLogsAndMarks(t *testing.T) {
	for name, path := range map[string]func(*Store) (*User, error){
		"CreateUser": func(s *Store) (*User, error) {
			return s.CreateUser("alice", "correct horse battery staple", RoleUser, time.Now())
		},
		"SetPassword": func(s *Store) (*User, error) {
			if _, err := s.CreateUser("alice", "an unremarkable passphrase", RoleUser, time.Now()); err != nil {
				return nil, err
			}
			if err := s.SetPassword("alice", "correct horse battery staple", time.Now()); err != nil {
				return nil, err
			}
			u, _ := s.ByUsername("alice")
			return u, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			hibp := &fakeBreach{}
			s, logs := openCheckedStore(t, Options{PasswordBlocklist: fakeList{}, BreachCheck: hibp})
			hibp.set(nil, errHIBPUnreachable)
			u, err := path(s)
			if err != nil {
				t.Fatalf("an unreachable HIBP refused the password: %v", err)
			}
			if !u.BreachCheckPending {
				t.Error("the account is not marked for a breach check at its next sign-in")
			}
			stored, _ := s.ByUsername("alice")
			if !stored.BreachCheckPending {
				t.Error("the mark was not saved")
			}
			if !strings.Contains(logs.String(), "alice") || !strings.Contains(logs.String(), "connection refused") {
				t.Errorf("the miss was not logged with the account and the reason:\n%s", logs.String())
			}
			if strings.Contains(logs.String(), "correct horse") {
				t.Errorf("the log carries the password:\n%s", logs.String())
			}
		})
	}
}

func TestAHungBreachCheckDoesNotHangThePasswordChange(t *testing.T) {
	hibp := &fakeBreach{}
	s, _ := openCheckedStore(t, Options{PasswordBlocklist: fakeList{}, BreachCheck: hibp})
	s.breachTimeout = 50 * time.Millisecond
	hang := make(chan struct{})
	defer close(hang)
	hibp.mu.Lock()
	hibp.hang = hang
	hibp.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		_, err := s.CreateUser("alice", "correct horse battery staple", RoleUser, time.Now())
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CreateUser is still waiting on a breach check that will never answer")
	}
	if u, _ := s.ByUsername("alice"); !u.BreachCheckPending {
		t.Error("a check that timed out did not mark the account")
	}
}

// pendingAccount makes alice with a password HIBP could not be asked
// about, so her account is marked, then makes HIBP answer again.
func pendingAccount(t *testing.T, password string) (*Store, *fakeBreach, *bytes.Buffer) {
	t.Helper()
	hibp := &fakeBreach{}
	s, logs := openCheckedStore(t, Options{PasswordBlocklist: fakeList{}, BreachCheck: hibp})
	hibp.set(nil, errHIBPUnreachable)
	if _, err := s.CreateUser("alice", password, RoleUser, time.Now()); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u, _ := s.ByUsername("alice"); !u.BreachCheckPending {
		t.Fatal("fixture: alice is not marked")
	}
	hibp.set(nil, nil)
	return s, hibp, logs
}

func TestSignInRechecksAMarkedAccountAndForcesAChangeOnAHit(t *testing.T) {
	const pw = "correct horse battery staple"
	s, hibp, _ := pendingAccount(t, pw)
	hibp.set(map[string]bool{pw: true}, nil)

	now := time.Now().Add(time.Minute)
	u, err := s.Authenticate("alice", pw, now)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !u.MustChangePassword {
		t.Error("a breached password found at sign-in did not force a change")
	}
	stored, _ := s.ByUsername("alice")
	if !stored.MustChangePassword || stored.BreachCheckPending {
		t.Errorf("saved: MustChangePassword %v, BreachCheckPending %v; want true, false",
			stored.MustChangePassword, stored.BreachCheckPending)
	}
	// The change-password door asks for no current password while the
	// flag is set, so every session from before has to end with it.
	if !stored.SessionsEndedAt.Equal(now) {
		t.Errorf("SessionsEndedAt = %v, want the sign-in's %v", stored.SessionsEndedAt, now)
	}
}

func TestSignInClearsTheMarkOnACleanRecheck(t *testing.T) {
	const pw = "correct horse battery staple"
	s, hibp, _ := pendingAccount(t, pw)
	before := hibp.callCount()

	u, err := s.Authenticate("alice", pw, time.Now())
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if u.MustChangePassword || u.BreachCheckPending {
		t.Errorf("after a clean recheck: MustChangePassword %v, BreachCheckPending %v; want both false",
			u.MustChangePassword, u.BreachCheckPending)
	}
	if stored, _ := s.ByUsername("alice"); stored.BreachCheckPending {
		t.Error("the cleared mark was not saved")
	}
	if n := hibp.callCount() - before; n != 1 {
		t.Errorf("the sign-in asked HIBP %d times, want once", n)
	}

	// Cleared means not asked again.
	if _, err := s.Authenticate("alice", pw, time.Now()); err != nil {
		t.Fatal(err)
	}
	if n := hibp.callCount() - before; n != 1 {
		t.Errorf("a cleared account was rechecked again: %d calls since the mark", n)
	}
}

func TestSignInKeepsTheMarkWhileHIBPIsStillUnreachable(t *testing.T) {
	const pw = "correct horse battery staple"
	s, hibp, logs := pendingAccount(t, pw)
	hibp.set(nil, errHIBPUnreachable)

	u, err := s.Authenticate("alice", pw, time.Now())
	if err != nil {
		t.Fatalf("an unreachable HIBP refused the sign-in: %v", err)
	}
	if !u.BreachCheckPending || u.MustChangePassword {
		t.Errorf("BreachCheckPending %v, MustChangePassword %v; want true, false", u.BreachCheckPending, u.MustChangePassword)
	}
	if strings.Count(logs.String(), "connection refused") < 2 {
		t.Errorf("the failed recheck was not logged:\n%s", logs.String())
	}
}

func TestAWrongPasswordIsNeverSentForARecheck(t *testing.T) {
	s, hibp, _ := pendingAccount(t, "correct horse battery staple")
	before := hibp.callCount()
	if _, err := s.Authenticate("alice", "a wrong guess entirely", time.Now()); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Authenticate with a wrong password: %v", err)
	}
	if hibp.callCount() != before {
		t.Error("a wrong password was sent to the breach check")
	}
}

func TestAnUnmarkedAccountIsNotRechecked(t *testing.T) {
	hibp := &fakeBreach{}
	s, _ := openCheckedStore(t, Options{PasswordBlocklist: fakeList{}, BreachCheck: hibp})
	if _, err := s.CreateUser("alice", "correct horse battery staple", RoleUser, time.Now()); err != nil {
		t.Fatal(err)
	}
	before := hibp.callCount()
	if _, err := s.Authenticate("alice", "correct horse battery staple", time.Now()); err != nil {
		t.Fatal(err)
	}
	if hibp.callCount() != before {
		t.Error("sign-in sent an account's password to HIBP with no recheck pending")
	}
}

func TestSettingAPasswordClearsTheMark(t *testing.T) {
	s, _, _ := pendingAccount(t, "correct horse battery staple")
	if err := s.SetPassword("alice", "another long passphrase", time.Now()); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.ByUsername("alice"); u.BreachCheckPending {
		t.Error("a password HIBP answered for left the old mark in place")
	}
}

func TestSSOAccountsAreNeverChecked(t *testing.T) {
	hibp := &fakeBreach{breached: map[string]bool{}}
	s, _ := openCheckedStore(t, Options{PasswordBlocklist: fakeList{}, BreachCheck: hibp})
	hibp.set(nil, errHIBPUnreachable)
	before := hibp.callCount()

	u, created, err := s.FindOrCreateOIDCUser("https://idp.example", "subject-1", "carol", time.Now())
	if err != nil || !created {
		t.Fatalf("FindOrCreateOIDCUser: %v, created %v", err, created)
	}
	if hibp.callCount() != before {
		t.Error("provisioning an SSO account sent something to the breach check")
	}
	if u.BreachCheckPending {
		t.Error("an SSO account with no local password is marked for a breach check")
	}

	// A local account going SSO-only loses its password, and the mark
	// with it: there is nothing left to recheck.
	pending, _, _ := pendingAccount(t, "correct horse battery staple")
	bob, _ := pending.ByUsername("alice")
	if err := pending.LinkOIDCIdentity(bob.ID, "https://idp.example", "subject-2", time.Now()); err != nil {
		t.Fatal(err)
	}
	if u, _ := pending.ByUsername("alice"); u.BreachCheckPending {
		t.Error("an account gone SSO-only kept its breach-check mark")
	}
}

func TestAResetCodeEndsTheMark(t *testing.T) {
	s, _, _ := pendingAccount(t, "correct horse battery staple")
	u, _ := s.ByUsername("alice")
	if _, _, err := s.IssueResetCode(u.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.ByUsername("alice"); u.BreachCheckPending {
		t.Error("the mark outlived the password a reset code replaced")
	}
}

func TestARecheckThatCannotBeSavedIsStillOwed(t *testing.T) {
	const pw = "correct horse battery staple"
	hibp := &fakeBreach{}
	var logs bytes.Buffer
	// Two saves: the first admin and alice. Every write after fails.
	s, err := OpenStore(&saveBudgetBackend{left: 2}, Options{
		Log:               slog.New(slog.NewTextHandler(&logs, nil)),
		OnSetupCode:       SetupCodeFunc(func(string) {}),
		PasswordBlocklist: fakeList{},
		BreachCheck:       hibp,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register("setup-admin", "a long first-admin passphrase", time.Now()); err != nil {
		t.Fatal(err)
	}
	hibp.set(nil, errHIBPUnreachable)
	if _, err := s.CreateUser("alice", pw, RoleUser, time.Now()); err != nil {
		t.Fatal(err)
	}
	hibp.set(map[string]bool{pw: true}, nil)

	u, err := s.Authenticate("alice", pw, time.Now())
	if err != nil {
		t.Fatalf("a recheck that could not be saved failed the sign-in: %v", err)
	}
	if !u.BreachCheckPending {
		t.Error("a recheck that was never saved cleared the mark")
	}
	if stored, _ := s.ByUsername("alice"); !stored.BreachCheckPending {
		t.Error("the store forgot a recheck it could not save")
	}
	if !strings.Contains(logs.String(), "still owed") {
		t.Errorf("the failed save was not logged:\n%s", logs.String())
	}
}

func TestARecheckDoesNotTouchAPasswordChangedSince(t *testing.T) {
	const pw = "correct horse battery staple"
	s, hibp, _ := pendingAccount(t, pw)
	stale, _ := s.ByUsername("alice")
	// HIBP is unreachable again, so the new password is marked too:
	// the recheck below must leave that mark, which is the new
	// password's, alone.
	hibp.set(nil, errHIBPUnreachable)
	if err := s.SetPassword("alice", "another long passphrase", time.Now()); err != nil {
		t.Fatal(err)
	}
	hibp.set(map[string]bool{pw: true}, nil)

	got := s.recheckBreach(stale, pw, time.Now())
	if got != stale {
		t.Error("a recheck of a replaced password returned a changed account")
	}
	u, _ := s.ByUsername("alice")
	if u.MustChangePassword || !u.BreachCheckPending {
		t.Errorf("a recheck of the old password changed the new one's state: MustChangePassword %v, BreachCheckPending %v",
			u.MustChangePassword, u.BreachCheckPending)
	}
}
