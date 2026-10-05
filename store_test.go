// Ported from mikroview's internal/auth/store_test.go: the account
// (not token/session/TOTP-flow) coverage for Register, CreateUser,
// DeleteUser, Authenticate, SetPassword, List, persistence and reload,
// concurrency, and Role.AtLeast. Adapted throughout: Open(path) ->
// openTestStore(t); raw-JSON fixtures prime a persist.Memory directly
// instead of writing a temp file; failingSaveBackend/saveBudgetBackend
// moved to testhelpers_test.go since other files share them.
//
// mikroview's TOTP-method tests (SetPendingTOTPSecret, ConfirmTOTP,
// ClearTOTP and friends) live in totp_test.go instead.
// TestUnconfirmedTOTPSecretIsNotAnActiveFactor stays here, with the
// Store.HasActiveTOTP(userID) assertions dropped, since this package has
// no such wrapper (see totp.go's package comment).

package gauntlet

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

func TestOpenEmptyBackendIsUsableButNotPersisted(t *testing.T) {
	s, err := OpenStore(nil, Options{})
	if err != nil {
		t.Fatalf("OpenStore(nil): %v", err)
	}
	if s.Persisted() {
		t.Error("expected a nil backend to leave the store unpersisted")
	}
	if s.Count() != 0 {
		t.Errorf("expected 0 users, got %d", s.Count())
	}
}

func TestRegisterRefusesWhenNotPersisted(t *testing.T) {
	s, _ := OpenStore(nil, Options{})
	if _, err := s.Register("admin", "password-placeholder-1", time.Now()); err != ErrNotPersisted {
		t.Errorf("expected ErrNotPersisted, got %v", err)
	}
}

func TestRegisterCreatesAdminAndClosesAfterFirstUser(t *testing.T) {
	s := openTestStore(t)

	u, err := s.Register("admin", "password-placeholder-1", time.Now())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if u.Role != RoleAdmin {
		t.Errorf("expected the first user to be RoleAdmin, got %v", u.Role)
	}
	if s.Count() != 1 {
		t.Errorf("expected 1 user, got %d", s.Count())
	}

	if _, err := s.Register("second", "password456", time.Now()); err != ErrRegistrationClosed {
		t.Errorf("expected ErrRegistrationClosed for a second Register call, got %v", err)
	}
}

func TestPasswordTooShortRejectedOnRegisterCreateAndReset(t *testing.T) {
	s := openTestStore(t)

	if _, err := s.Register("admin", "short1", time.Now()); err != ErrPasswordTooShort {
		t.Errorf("Register: expected ErrPasswordTooShort for a %d-char password, got %v", len("short1"), err)
	}
	if s.Count() != 0 {
		t.Fatalf("expected no account to have been created, got %d", s.Count())
	}

	if _, err := s.Register("admin", "password-placeholder-1", time.Now()); err != nil {
		t.Fatalf("Register with a long-enough password should succeed, got %v", err)
	}
	if _, err := s.CreateUser("second", "tiny", RoleUser, time.Now()); err != ErrPasswordTooShort {
		t.Errorf("CreateUser: expected ErrPasswordTooShort, got %v", err)
	}
	if err := s.SetPassword("admin", "abc", time.Now()); err != ErrPasswordTooShort {
		t.Errorf("SetPassword: expected ErrPasswordTooShort, got %v", err)
	}
}

func TestCreateUserAddsAdditionalAccounts(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Register("admin", "password-placeholder-1", time.Now())

	u, err := s.CreateUser("viewer", "password789", RoleUser, time.Now())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.Role != RoleUser {
		t.Errorf("expected RoleUser, got %v", u.Role)
	}
	if s.Count() != 2 {
		t.Errorf("expected 2 users, got %d", s.Count())
	}
}

// TestCreateUserAcceptsViewer: RoleViewer is a valid role for
// CreateUser, same as RoleUser.
func TestCreateUserAcceptsViewer(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Register("admin", "password-placeholder-1", time.Now())

	u, err := s.CreateUser("watcher", "password789", RoleViewer, time.Now())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.Role != RoleViewer {
		t.Errorf("expected RoleViewer, got %v", u.Role)
	}
}

// TestCreateUserRejectsUnknownRole: a role that is none of the three
// CreateUser grants is refused, not coerced to a lesser one.
func TestCreateUserRejectsUnknownRole(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Register("admin", "password-placeholder-1", time.Now())

	if _, err := s.CreateUser("someone", "password789", Role("owner"), time.Now()); !errors.Is(err, ErrInvalidRole) {
		t.Errorf("expected ErrInvalidRole for an unrecognized role, got %v", err)
	}
}

func TestCreateUserRejectsDuplicateUsernameCaseInsensitive(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Register("Admin", "password-placeholder-1", time.Now())

	if _, err := s.CreateUser("admin", "different", RoleUser, time.Now()); err != ErrUsernameTaken {
		t.Errorf("expected ErrUsernameTaken for a case-insensitive duplicate, got %v", err)
	}
}

func TestAuthenticateSucceedsAndFails(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Register("admin", "correct-password", time.Now())

	if _, err := s.Authenticate("admin", "correct-password", time.Now()); err != nil {
		t.Errorf("expected valid credentials to succeed, got %v", err)
	}
	if _, err := s.Authenticate("admin", "wrong-password", time.Now()); err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials for a wrong password, got %v", err)
	}
	if _, err := s.Authenticate("nobody", "anything", time.Now()); err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials for an unknown username, got %v", err)
	}
}

func TestAuthenticateUpdatesLastLogin(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Register("admin", "password-placeholder-1", time.Now())

	now := time.Now().Add(time.Hour).UTC().Truncate(time.Millisecond)
	u, err := s.Authenticate("admin", "password-placeholder-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if !u.LastLogin.Equal(now) {
		t.Errorf("LastLogin = %v, want %v", u.LastLogin, now)
	}
}

// TestAuthenticateSavesLastLoginAtMostHourly: moving LastLogin is not
// worth a whole-document save on every login. It is saved when the
// saved value is more than lastLoginGranularity old, and otherwise kept
// in memory -- where Get still sees it -- until the next save of any
// kind. The third login checks the comparison is against the saved
// value, not the in-memory one: logins a minute apart must not push the
// next save back for ever.
func TestAuthenticateSavesLastLoginAtMostHourly(t *testing.T) {
	b := &countingBackend{Memory: persist.NewMemory()}
	s, id := openLockoutStore(t, b)
	start := time.Now().UTC().Truncate(time.Millisecond)

	login := func(at time.Time) {
		t.Helper()
		if _, err := s.Authenticate("alice", "password-placeholder-1", at); err != nil {
			t.Fatalf("Authenticate at %v: %v", at, err)
		}
	}

	before := b.saves.Load()
	login(start)
	if got := b.saves.Load() - before; got != 1 {
		t.Fatalf("first login caused %d saves, want 1", got)
	}
	login(start.Add(time.Minute))
	if got := b.saves.Load() - before; got != 1 {
		t.Errorf("two logins a minute apart caused %d saves, want 1", got)
	}
	if u, _ := s.Get(id); !u.LastLogin.Equal(start.Add(time.Minute)) {
		t.Errorf("LastLogin = %v in memory, want the second login's %v", u.LastLogin, start.Add(time.Minute))
	}

	// Half an hour on: still within the hour of the saved value.
	login(start.Add(lastLoginGranularity/2 + time.Minute))
	if got := b.saves.Load() - before; got != 1 {
		t.Errorf("a login within the hour caused %d saves in all, want 1", got)
	}
	// Another half hour: only half an hour since the last login, but
	// more than an hour since the saved one.
	later := start.Add(lastLoginGranularity + time.Minute)
	login(later)
	if got := b.saves.Load() - before; got != 2 {
		t.Errorf("a login %v after the saved one caused %d saves in all, want 2", lastLoginGranularity+time.Minute, got)
	}
	reopened, err := OpenStore(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := reopened.Get(id); !u.LastLogin.Equal(later) {
		t.Errorf("saved LastLogin = %v, want %v", u.LastLogin, later)
	}
}

func TestSetPasswordChangesCredentials(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Register("admin", "old-password", time.Now())

	if err := s.SetPassword("admin", "new-password", time.Now()); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if _, err := s.Authenticate("admin", "old-password", time.Now()); err == nil {
		t.Error("expected the old password to stop working")
	}
	if _, err := s.Authenticate("admin", "new-password", time.Now()); err != nil {
		t.Errorf("expected the new password to work, got %v", err)
	}
}

// TestSetPasswordMovesBothTimestamps: a new password is a password
// change (PasswordChangedAt, which the login limiter reads) and ends
// every session issued before it (SessionsEndedAt, #28).
func TestSetPasswordMovesBothTimestamps(t *testing.T) {
	s := openTestStore(t)
	u, _ := s.Register("admin", "old-password", time.Now().Add(-time.Hour))
	at := time.Now().UTC().Truncate(time.Millisecond)
	if err := s.SetPassword("admin", "new-password", at); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	got, _ := s.Get(u.ID)
	if !got.PasswordChangedAt.Equal(at) || !got.SessionsEndedAt.Equal(at) {
		t.Errorf("PasswordChangedAt = %v, SessionsEndedAt = %v; want both %v",
			got.PasswordChangedAt, got.SessionsEndedAt, at)
	}
}

// TestSessionCutoffIsTheLaterTimestamp: a session must have been issued
// after both the last password change and the last time the account's
// sessions were ended. A document written before SessionsEndedAt
// existed -- gauntlet v0.2.0, or mikroview, both of which record an SSO
// link in PasswordChangedAt -- has only the first, and still cuts off
// there.
func TestSessionCutoffIsTheLaterTimestamp(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	cases := []struct {
		name           string
		changed, ended time.Time
		want           time.Time
	}{
		{"neither", time.Time{}, time.Time{}, time.Time{}},
		{"only the password change (an older document)", t0, time.Time{}, t0},
		{"only sessions ended", time.Time{}, t0, t0},
		{"sessions ended later", t0, t1, t1},
		{"password changed later", t1, t0, t1},
	}
	for _, tc := range cases {
		u := User{PasswordChangedAt: tc.changed, SessionsEndedAt: tc.ended}
		if got := u.SessionCutoff(); !got.Equal(tc.want) {
			t.Errorf("%s: SessionCutoff() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestSetPasswordLeavesTheOldPasswordWorkingWhenPersistFails: a password
// change that cannot be saved must not take effect in memory either, or
// a restart before the next good write would silently restore a
// credential the operator was told was already dead.
func TestSetPasswordLeavesTheOldPasswordWorkingWhenPersistFails(t *testing.T) {
	// Register below persists too (createAccount persists as well), so
	// the fixture needs a backend that saves once before failing, not
	// one that fails outright.
	s, err := OpenStore(&saveBudgetBackend{left: 1}, Options{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if _, err := s.Register("admin", "old-password", time.Now()); err != nil {
		t.Fatal(err)
	}

	if err := s.SetPassword("admin", "new-password", time.Now()); err == nil {
		t.Fatal("SetPassword against a backend that cannot save = nil error, want one")
	}

	if _, err := s.Authenticate("admin", "old-password", time.Now()); err != nil {
		t.Errorf("expected the old password to still work after a failed persist, got %v", err)
	}
	if _, err := s.Authenticate("admin", "new-password", time.Now()); err == nil {
		t.Error("expected the new password to not have taken effect after a failed persist")
	}
}

// An SSO-provisioned account starts with HasLocalPassword explicitly
// false. If it is ever given a real password, that flag has to move
// with it -- otherwise the account holds a working password while still
// reporting itself SSO-only.
func TestSetPasswordMarksTheAccountAsHavingALocalPassword(t *testing.T) {
	s := openTestStoreWithAdmin(t)

	u, created, err := s.FindOrCreateOIDCUser("https://idp.example", "subject-1", "sso-user", time.Now())
	if err != nil || !created {
		t.Fatalf("FindOrCreateOIDCUser: created=%v err=%v", created, err)
	}
	if u.LocalPassword() {
		t.Fatal("an SSO-provisioned account reports a local password before the test even starts")
	}

	if err := s.SetPassword(u.Username, "new-password", time.Now()); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	got, _ := s.ByUsername(u.Username)
	if !got.LocalPassword() {
		t.Error("an account that was just given a password reports no local password")
	}
}

func TestSetPasswordUnknownUserReturnsNotFound(t *testing.T) {
	s := openTestStore(t)
	if err := s.SetPassword("nobody", "irrelevant", time.Now()); err != ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

func TestListNeverIncludesPasswordHashes(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Register("admin", "password-placeholder-1", time.Now())
	_, _ = s.CreateUser("viewer", "password456", RoleUser, time.Now())

	list := s.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 users, got %d", len(list))
	}
	for _, u := range list {
		if u.PasswordHash != "" {
			t.Errorf("expected List() to never include a password hash, got one for %s", u.Username)
		}
	}
	if list[0].Username != "admin" || list[1].Username != "viewer" {
		t.Errorf("expected alphabetical order, got %s, %s", list[0].Username, list[1].Username)
	}
}

// TestListAnswersHasActiveTOTPWithoutTheSecret: List blanks TOTPSecret,
// but an admin's account list still has to show who has an active
// authenticator app. HasActiveTOTP on a listed copy must give the same
// answer as on Get's copy -- for an active factor, a pending one and
// none -- without the secret itself leaving List, in Go or in JSON.
func TestListAnswersHasActiveTOTPWithoutTheSecret(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	active, _ := s.Register("active", "password-placeholder-1", now)
	pending, _ := s.CreateUser("pending", "password-placeholder-1", RoleUser, now)
	none, _ := s.CreateUser("none", "password-placeholder-1", RoleUser, now)
	setTOTPForTest(t, s, active.ID, testTOTPSecret, now, 0)
	setTOTPForTest(t, s, pending.ID, testTOTPSecret, time.Time{}, 0)

	want := map[string]bool{active.ID: true, pending.ID: false, none.ID: false}
	for _, u := range s.List() {
		if u.TOTPSecret != "" {
			t.Errorf("List returned %s's TOTP secret", u.Username)
		}
		if got := u.HasActiveTOTP(); got != want[u.ID] {
			t.Errorf("listed %s: HasActiveTOTP = %v, want %v", u.Username, got, want[u.ID])
		}
		if full, _ := s.Get(u.ID); full.HasActiveTOTP() != want[u.ID] {
			t.Errorf("Get %s: HasActiveTOTP = %v, want %v", u.Username, full.HasActiveTOTP(), want[u.ID])
		}
		data, err := json.Marshal(u)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), testTOTPSecret) {
			t.Errorf("listed %s serialises its TOTP secret: %s", u.Username, data)
		}
	}

	// A factor cleared after listing reads as gone on a fresh list.
	if err := s.ClearTOTP(active.ID); err != nil {
		t.Fatalf("ClearTOTP: %v", err)
	}
	for _, u := range s.List() {
		if u.ID == active.ID && u.HasActiveTOTP() {
			t.Error("listed account still reports an active factor after ClearTOTP")
		}
	}
}

// TestListAnswersHasSecondFactorForPasskeyOnlyAccounts: List blanks
// Passkeys, but an admin list or a second-factor check built from it
// must still see a passkey-only account as having a second factor --
// the same answer Get gives.
func TestListAnswersHasSecondFactorForPasskeyOnlyAccounts(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	passkey, _ := s.Register("passkey", "password-placeholder-1", now)
	none, _ := s.CreateUser("none", "password-placeholder-1", RoleUser, now)
	if _, err := s.AddPasskey(passkey.ID, testPasskey(1, "")); err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{passkey.ID: true, none.ID: false}
	for _, u := range s.List() {
		if u.Passkeys != nil {
			t.Errorf("List returned %s's passkeys", u.Username)
		}
		full, _ := s.Get(u.ID)
		if full.HasSecondFactor() != want[u.ID] {
			t.Errorf("Get %s: HasSecondFactor = %v, want %v", u.Username, full.HasSecondFactor(), want[u.ID])
		}
		if got := u.HasSecondFactor(); got != full.HasSecondFactor() {
			t.Errorf("listed %s: HasSecondFactor = %v, Get says %v", u.Username, got, full.HasSecondFactor())
		}
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	m := persist.NewMemory()

	s1, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	_, _ = s1.Register("admin", "password-placeholder-1", now)
	_, _ = s1.CreateUser("viewer", "password456", RoleUser, now)

	s2, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatalf("re-opening the persisted store failed: %v", err)
	}
	if s2.Count() != 2 {
		t.Fatalf("expected 2 persisted users, got %d", s2.Count())
	}
	if _, err := s2.Authenticate("admin", "password-placeholder-1", time.Now()); err != nil {
		t.Errorf("expected the persisted admin's password to still verify, got %v", err)
	}
}

func TestGetReturnsCopyNotSharedPointer(t *testing.T) {
	s := openTestStore(t)
	registered, _ := s.Register("admin", "password-placeholder-1", time.Now())

	got, ok := s.Get(registered.ID)
	if !ok {
		t.Fatal("expected Get to find the registered user")
	}
	got.Username = "tampered"

	got2, _ := s.Get(registered.ID)
	if got2.Username == "tampered" {
		t.Error("expected Get to return an independent copy, not a shared pointer into the store")
	}
}

// TestSeparateProcessPasswordResetIsPickedUpByRunningStore reproduces
// the cross-process scenario a CLI recovery tool depends on: two
// independent Store instances (standing in for two separate process
// invocations) opened against the same backend. A change made through
// one must be visible through the other on its next read, without
// requiring a restart.
func TestSeparateProcessPasswordResetIsPickedUpByRunningStore(t *testing.T) {
	m := persist.NewMemory()

	serverStore, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = serverStore.Register("admin", "old-password", time.Now())

	if _, err := serverStore.Authenticate("admin", "old-password", time.Now()); err != nil {
		t.Fatalf("expected the old password to work before the reset: %v", err)
	}

	// A second, independent Store against the same backend -- standing
	// in for a CLI tool's own separate process.
	cliStore, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := cliStore.SetPassword("admin", "new-password", time.Now()); err != nil {
		t.Fatal(err)
	}

	if _, err := serverStore.Authenticate("admin", "new-password", time.Now()); err != nil {
		t.Errorf("expected the running store to pick up the externally-reset password, got %v", err)
	}
	if _, err := serverStore.Authenticate("admin", "old-password", time.Now()); err == nil {
		t.Error("expected the old password to stop working after the external reset")
	}
}

// A JSON array containing null is syntactically valid, so it unmarshals
// without error into a slice with a nil *User element -- before the
// equivalent fix in mikroview, the next line (indexing u.ID) paniced.
func TestOpenSkipsNilArrayElements(t *testing.T) {
	m := persist.NewMemory()
	data := `{"users":[null,{"id":"u1","username":"admin","passwordHash":"$argon2id$fake","role":"admin","createdAt":"2026-01-01T00:00:00Z"},null]}`
	primeMemory(t, m, data)

	s, err := OpenStore(m, Options{}) // must not panic
	if err != nil {
		t.Fatalf("OpenStore() returned an unexpected error: %v", err)
	}
	if s.Count() != 1 {
		t.Fatalf("expected the one real user to survive, got %d", s.Count())
	}
	if u, ok := s.ByUsername("admin"); !ok || u.ID != "u1" {
		t.Errorf("expected the real user's data to be intact, got %+v, %v", u, ok)
	}
}

// TestOpenCountsOnlyRealAccountsWhenRefusingNoAdmin: a document of only
// `null` entries is still refused -- something wrote a non-empty list,
// so it is not a fresh install -- but the message must not call a null
// an account, or an operator goes looking for one that isn't there.
func TestOpenCountsOnlyRealAccountsWhenRefusingNoAdmin(t *testing.T) {
	m := persist.NewMemory()
	primeMemory(t, m, `{"users":[null]}`)

	_, err := OpenStore(m, Options{})
	if !errors.Is(err, errNoAdmin) {
		t.Fatalf("OpenStore = %v, want the no-admin refusal", err)
	}
	if want := "found 0 accounts and 1 null entries"; !strings.Contains(err.Error(), want) {
		t.Errorf("refusal message %q does not contain %q", err.Error(), want)
	}
}

// Same bug, reached through the other code path that parses a
// storeFile: reloadIfStale, which a live server calls on every read once
// a separate process (a CLI recovery tool) has touched the backend.
func TestReloadIfStaleSkipsNilArrayElements(t *testing.T) {
	m := persist.NewMemory()

	s, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}

	data := `{"users":[null,{"id":"u1","username":"admin","passwordHash":"$argon2id$fake","role":"admin","createdAt":"2026-01-01T00:00:00Z"}]}`
	if _, err := m.Save(context.Background(), []byte(data), 0); err != nil {
		t.Fatal(err)
	}

	if u, ok := s.ByUsername("admin"); !ok || u.ID != "u1" { // triggers reloadIfStale; must not panic
		t.Errorf("expected the externally-written user to be picked up, got %+v, %v", u, ok)
	}
}

func TestOpenReadsNewObjectFormat(t *testing.T) {
	m := persist.NewMemory()
	// Round-trip through the store's own writer -- the true contract is
	// "whatever Store.mutate writes, OpenStore can read back."
	s1, _ := OpenStore(m, Options{})
	if _, err := s1.Register("admin", "password-placeholder-1", time.Now()); err != nil {
		t.Fatal(err)
	}

	s2, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if u, ok := s2.ByUsername("admin"); !ok || u.Role != RoleAdmin {
		t.Errorf("expected the object-format document to round-trip the admin account, got %+v, %v", u, ok)
	}
}

// TestOpenLeavesAnEmptyRoleFailingClosed pins the rule that replaced a
// pre-roles default: an accounts document whose account carries no
// "role" key can now only have been hand-edited, so the empty Role is
// loaded as-is and rank() denies it every gate -- not even viewer.
// Silently promoting an unassigned role to RoleUser is the wrong
// direction for a value nobody legitimately wrote. The fixture also
// carries an admin account, otherwise OpenStore would refuse the whole
// document for a different reason (no admin) before the roleless
// account is even considered.
func TestOpenLeavesAnEmptyRoleFailingClosed(t *testing.T) {
	m := persist.NewMemory()
	data := `{"users":[` +
		`{"id":"u1","username":"someone","passwordHash":"$argon2id$fake","createdAt":"2026-01-01T00:00:00Z"},` +
		`{"id":"u2","username":"admin","passwordHash":"$argon2id$fake","role":"admin","createdAt":"2026-01-01T00:00:00Z"}]}`
	primeMemory(t, m, data)

	s, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatalf("OpenStore() returned an unexpected error: %v", err)
	}
	u, ok := s.ByUsername("someone")
	if !ok {
		t.Fatal("expected the roleless account to load")
	}
	if u.Role != "" {
		t.Errorf("expected the empty on-disk role to be preserved, got %q", u.Role)
	}
	for _, min := range []Role{RoleViewer, RoleUser, RoleAdmin} {
		if u.Role.AtLeast(min) {
			t.Errorf("expected a roleless account to be denied %q, but AtLeast granted it", min)
		}
	}
}

// TestReloadIfStaleLeavesAnEmptyRoleFailingClosed is the same behaviour
// reached through reloadIfStale, which a live server calls on every read
// once a separate process has touched the backend. The fixture also
// carries an admin account, otherwise reloadIfStale would refuse the
// whole document for a different reason (no admin) before the roleless
// account is even considered.
func TestReloadIfStaleLeavesAnEmptyRoleFailingClosed(t *testing.T) {
	m := persist.NewMemory()

	s, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}

	data := `{"users":[` +
		`{"id":"u1","username":"someone","passwordHash":"$argon2id$fake","createdAt":"2026-01-01T00:00:00Z"},` +
		`{"id":"u2","username":"admin","passwordHash":"$argon2id$fake","role":"admin","createdAt":"2026-01-01T00:00:00Z"}]}`
	if _, err := m.Save(context.Background(), []byte(data), 0); err != nil {
		t.Fatal(err)
	}

	u, ok := s.ByUsername("someone") // triggers reloadIfStale
	if !ok {
		t.Fatal("expected the externally-written account to be picked up")
	}
	if u.Role != "" {
		t.Errorf("expected the empty on-disk role to be preserved, got %q", u.Role)
	}
	for _, min := range []Role{RoleViewer, RoleUser, RoleAdmin} {
		if u.Role.AtLeast(min) {
			t.Errorf("expected a roleless account to be denied %q, but AtLeast granted it", min)
		}
	}
}

// A deployment that took mikroview's removed no-auth option has
// "disabled": true in its accounts document and no accounts. The key is
// no longer read at all, so it must load as an ordinary undecided
// store -- setup required, which is the safe direction -- rather than
// failing to parse.
func TestAStoreLeftByTheRemovedNoAuthModeRequiresSetup(t *testing.T) {
	m := persist.NewMemory()
	primeMemory(t, m, `{"disabled":true,"users":[]}`)

	s, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatalf("a store left by the no-auth mode must still load, got %v", err)
	}
	if s.Count() != 0 {
		t.Fatalf("expected no accounts, got %d", s.Count())
	}
	// Registration has to be open, or the deployment is stranded: there
	// is no account to sign in with and no way to make one.
	if _, err := s.Register("admin", "password-placeholder-1", time.Now()); err != nil {
		t.Fatalf("expected setup to be available on a previously-disabled store, got %v", err)
	}

	// And the marker must not survive the write -- nothing reads it, so
	// leaving it stored is just a misleading artefact.
	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(snap.Payload), "disabled") {
		t.Errorf("the no-auth marker was written back out:\n%s", snap.Payload)
	}
}

// TestConcurrentRegisterCreatesExactlyOneAdmin is the regression test
// for the first-run registration race. Before the equivalent fix in
// mikroview, Register checked Count() outside the lock and createAccount
// only re-checked for a username collision under it -- so N concurrent
// registrations with distinct usernames all succeeded, every one of
// them landing RoleAdmin. Measured 8/8 succeeding, reproducibly, there.
//
// The window was wide, not theoretical: HashPassword (Argon2id, ~100ms
// by design) runs before the lock is taken, so a real attacker racing
// the operator through the unauthenticated first-run screen had a
// comfortable margin, not a microsecond one.
func TestConcurrentRegisterCreatesExactlyOneAdmin(t *testing.T) {
	s := openTestStore(t)

	names := []string{"alice", "bob", "carol", "dave", "eve", "frank", "grace", "heidi"}
	results := make([]error, len(names))
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			<-start
			_, results[i] = s.Register(name, "correct horse battery staple", time.Now())
		}(i, name)
	}
	close(start)
	wg.Wait()

	succeeded := 0
	for i, err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrRegistrationClosed):
			// expected for every loser of the race
		default:
			t.Errorf("Register(%q) failed with an unexpected error: %v", names[i], err)
		}
	}
	if succeeded != 1 {
		t.Errorf("%d concurrent Register calls succeeded, want exactly 1", succeeded)
	}
	if got := s.Count(); got != 1 {
		t.Errorf("store holds %d accounts after the race, want exactly 1", got)
	}
}

func TestDeleteUserRefusesTheLastAdmin(t *testing.T) {
	s := openTestStore(t)
	admin, _ := s.Register("alice", "password-placeholder-1", time.Now())

	if _, err := s.DeleteUser(admin.ID); err != ErrCannotDeleteAdmin {
		t.Fatalf("expected ErrCannotDeleteAdmin, got %v", err)
	}
	if s.Admin() == nil {
		t.Error("the admin account is gone after a refused delete")
	}
}

func TestDeleteUserRemovesTheAccountAndFreesItsIdentifiers(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Register("alice", "password-placeholder-1", time.Now())
	bob, err := s.CreateUser("bob", "password456", RoleUser, time.Now())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := s.LinkOIDCIdentity(bob.ID, "https://idp.example", "sub-bob", time.Now()); err != nil {
		t.Fatalf("LinkOIDCIdentity: %v", err)
	}

	deleted, err := s.DeleteUser(bob.ID)
	if err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if deleted.PasswordHash != "" {
		t.Error("DeleteUser returned the account's password hash")
	}
	if _, ok := s.ByUsername("bob"); ok {
		t.Error("the deleted account is still resolvable by username")
	}

	// The username and the SSO identity must both be reusable, or a
	// deleted account silently blocks re-creating the person's access.
	if _, err := s.CreateUser("bob", "password789", RoleUser, time.Now()); err != nil {
		t.Errorf("expected the freed username to be reusable, got %v", err)
	}
	replacement, created, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-bob", "bob2", time.Now())
	if err != nil {
		t.Fatalf("FindOrCreateOIDCUser: %v", err)
	}
	if !created || replacement.ID == bob.ID {
		t.Error("the deleted account's SSO identity still maps to the old account")
	}
}

func TestDeleteUserUnknownIDReturnsNotFound(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Register("alice", "password-placeholder-1", time.Now())

	if _, err := s.DeleteUser("no-such-id"); err != ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

// giveEveryCredential puts every credential-bearing field on userID's
// account: a password (already there), an outstanding reset code, an
// active TOTP secret, recovery codes and a passkey.
func giveEveryCredential(t *testing.T, s *Store, userID string, now time.Time) {
	t.Helper()
	if _, _, err := s.IssueResetCode(userID, now); err != nil {
		t.Fatalf("IssueResetCode: %v", err)
	}
	setTOTPForTest(t, s, userID, testTOTPSecret, now, 0)
	if _, err := s.GenerateRecoveryCodes(userID, now); err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if _, err := s.AddPasskey(userID, testPasskey(1, "")); err != nil {
		t.Fatalf("AddPasskey: %v", err)
	}
}

// requireNoCredentials fails if a copy a Store method handed back still
// carries any credential, while HasActiveTOTP and HasSecondFactor give
// the answers the stored account would.
func requireNoCredentials(t *testing.T, what string, u *User) {
	t.Helper()
	for field, present := range map[string]bool{
		"PasswordHash":  u.PasswordHash != "",
		"ResetCodeHash": u.ResetCodeHash != "",
		"TOTPSecret":    u.TOTPSecret != "",
		"RecoveryCodes": u.RecoveryCodes != nil,
		"Passkeys":      u.Passkeys != nil,
	} {
		if present {
			t.Errorf("%s returned the account's %s", what, field)
		}
	}
	if !u.HasActiveTOTP() || !u.HasSecondFactor() {
		t.Errorf("%s: the copy no longer reports the account's second factor", what)
	}
}

// TestDeleteUserReturnsNoCredentials: the deleted account is returned
// for the caller to log and clean up after, so it must carry none of
// the account's credentials.
func TestDeleteUserReturnsNoCredentials(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	_, _ = s.Register("alice", "password-placeholder-1", now)
	bob, err := s.CreateUser("bob", "password456", RoleUser, now)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	giveEveryCredential(t, s, bob.ID, now)

	deleted, err := s.DeleteUser(bob.ID)
	if err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	requireNoCredentials(t, "DeleteUser", deleted)
}

// TestTransferAdminReturnsNoCredentials: both accounts TransferAdmin
// hands back are for the caller's audit trail, so neither may carry
// credentials.
func TestTransferAdminReturnsNoCredentials(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	alice, _ := s.Register("alice", "password-placeholder-1", now)
	bob, err := s.CreateUser("bob", "password456", RoleUser, now)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	giveEveryCredential(t, s, alice.ID, now)
	giveEveryCredential(t, s, bob.ID, now)

	from, to, err := s.TransferAdmin("bob", now)
	if err != nil {
		t.Fatalf("TransferAdmin: %v", err)
	}
	requireNoCredentials(t, "TransferAdmin (from)", from)
	requireNoCredentials(t, "TransferAdmin (to)", to)
}

// TestDeleteUserLeavesTheAccountInPlaceWhenPersistFails: a deletion that
// cannot be saved must not remove the account from memory either, or a
// restart before the next good write would bring it back while the
// caller has already revoked its sessions and tokens on the strength of
// a deletion that never took hold.
func TestDeleteUserLeavesTheAccountInPlaceWhenPersistFails(t *testing.T) {
	// Register and CreateUser below each persist too, so the fixture
	// needs a backend that saves twice before failing, not one that
	// fails outright.
	s, err := OpenStore(&saveBudgetBackend{left: 2}, Options{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if _, err := s.Register("alice", "password-placeholder-1", time.Now()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	bob, err := s.CreateUser("bob", "password456", RoleUser, time.Now())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if _, err := s.DeleteUser(bob.ID); err == nil {
		t.Fatal("DeleteUser against a backend that cannot save = nil error, want one")
	}

	got, ok := s.ByUsername("bob")
	if !ok || got.ID != bob.ID {
		t.Error("expected the account to still be there after a failed persist")
	}
}

// TestRegisterAndCreateUserReportPersistFailure: an account that cannot
// be saved must not exist in memory either, or a restart before the
// next good write would erase it while the caller has already handed
// out a session or told an operator it was created.
func TestRegisterAndCreateUserReportPersistFailure(t *testing.T) {
	t.Run("Register", func(t *testing.T) {
		s, err := OpenStore(failingSaveBackend{}, Options{})
		if err != nil {
			t.Fatalf("OpenStore: %v", err)
		}
		if _, err := s.Register("alice", "password-placeholder-1", time.Now()); err == nil {
			t.Fatal("Register against a backend that cannot save = nil error, want one")
		}
		if s.Count() != 0 {
			t.Errorf("Count() = %d after a failed persist, want 0", s.Count())
		}
		if _, ok := s.ByUsername("alice"); ok {
			t.Error("the account is resolvable after a failed persist")
		}
	})

	t.Run("CreateUser", func(t *testing.T) {
		// Register below persists too, so the fixture needs a backend
		// that saves once before failing, not one that fails outright.
		s, err := OpenStore(&saveBudgetBackend{left: 1}, Options{})
		if err != nil {
			t.Fatalf("OpenStore: %v", err)
		}
		if _, err := s.Register("alice", "password-placeholder-1", time.Now()); err != nil {
			t.Fatalf("Register: %v", err)
		}
		if _, err := s.CreateUser("bob", "password456", RoleUser, time.Now()); err == nil {
			t.Fatal("CreateUser against a backend that cannot save = nil error, want one")
		}
		if _, ok := s.ByUsername("bob"); ok {
			t.Error("bob is resolvable after a failed persist")
		}
		if s.Count() != 1 {
			t.Errorf("Count() = %d after a failed persist, want 1 (alice only)", s.Count())
		}
	})
}

// TestRoleAtLeastStacksTheThreeTiers pins the ordering: admin implies
// user implies viewer, an unrecognized or empty role outranks nothing --
// not even itself as a min, which is deliberate: there is no legitimate
// call site that ever passes one as min, so what it denies doesn't
// matter, only that it never grants.
func TestRoleAtLeastStacksTheThreeTiers(t *testing.T) {
	cases := []struct {
		role Role
		min  Role
		want bool
	}{
		{RoleAdmin, RoleAdmin, true},
		{RoleAdmin, RoleUser, true},
		{RoleAdmin, RoleViewer, true},
		{RoleUser, RoleAdmin, false},
		{RoleUser, RoleUser, true},
		{RoleUser, RoleViewer, true},
		{RoleViewer, RoleUser, false},
		{RoleViewer, RoleViewer, true},
		{RoleViewer, RoleAdmin, false},
		{Role(""), RoleViewer, false},
		{Role("bogus"), RoleViewer, false},
	}
	for _, c := range cases {
		if got := c.role.AtLeast(c.min); got != c.want {
			t.Errorf("Role(%q).AtLeast(%q) = %v, want %v", c.role, c.min, got, c.want)
		}
	}
}

// setTOTPForTest sets userID's TOTPSecret/TOTPConfirmedAt/TOTPLastCounter
// directly and persists them, for fixture states the real methods
// (SetPendingTOTPSecret, ConfirmTOTP) cannot reach in one step: a given
// counter on a confirmed or pending secret, or a secret replaced in
// place. A test about enrolment itself uses the real methods.
func setTOTPForTest(t *testing.T, s *Store, userID, secret string, confirmedAt time.Time, counter uint64) {
	t.Helper()
	err := s.mutate(func(st *storeState) error {
		u, ok := st.byID[userID]
		if !ok {
			return ErrUserNotFound
		}
		u.TOTPSecret = secret
		u.TOTPConfirmedAt = confirmedAt
		u.TOTPLastCounter = counter
		return nil
	})
	if err != nil {
		t.Fatalf("setTOTPForTest: persisting fixture for %q: %v", userID, err)
	}
}

// TestUnconfirmedTOTPSecretIsNotAnActiveFactor pins the distinction the
// design calls out explicitly: a secret generated mid-setup (e.g. to
// show a QR code) and never confirmed must not count as an active
// factor.
func TestUnconfirmedTOTPSecretIsNotAnActiveFactor(t *testing.T) {
	s := openTestStore(t)
	u, err := s.Register("admin", "password-placeholder-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if u.HasActiveTOTP() {
		t.Error("a freshly registered user claims an active TOTP factor")
	}

	// A secret with no confirmation -- mid-setup, or an abandoned one.
	if err := s.SetPendingTOTPSecret(u.ID, "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Get(u.ID)
	if !ok {
		t.Fatal("expected the user to still exist")
	}
	if got.HasActiveTOTP() {
		t.Error("an unconfirmed secret counts as an active factor")
	}

	// Confirming it is what activates it.
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := s.ConfirmTOTP(u.ID, now, 5); err != nil {
		t.Fatal(err)
	}
	got2, ok := s.Get(u.ID)
	if !ok {
		t.Fatal("expected the user to still exist")
	}
	if !got2.HasActiveTOTP() {
		t.Error("a confirmed secret does not count as an active factor")
	}
}

// Not from mikroview (the audit for #1 found no direct test of it): an
// unknown username must still pay for one Argon2id verification against
// dummyHash, or response time tells an attacker which usernames exist.
// Proved without timing: with every hash slot taken, an unknown-user
// Authenticate has to wait for a slot rather than return at once.
func TestAuthenticateUnknownUserStillRunsTheHash(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.Register("admin", "correct-password", time.Now()); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < maxConcurrentHashes; i++ {
		select {
		case hashSlots <- struct{}{}:
		case <-time.After(30 * time.Second):
			t.Fatal("could not take every hash slot")
		}
	}
	drained := 0
	defer func() {
		for ; drained < maxConcurrentHashes; drained++ {
			<-hashSlots
		}
	}()

	done := make(chan error, 1)
	go func() {
		_, err := s.Authenticate("nobody", "anything", time.Now())
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("unknown-user Authenticate returned (%v) without waiting for a hash slot: it skipped the dummy hash", err)
	case <-time.After(200 * time.Millisecond):
	}

	<-hashSlots
	drained++
	select {
	case err := <-done:
		if err != ErrInvalidCredentials {
			t.Errorf("got %v, want ErrInvalidCredentials", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("unknown-user Authenticate never finished once a slot was free")
	}
}

// TestWritesPickUpAnotherProcessesAccountFirst covers the three write
// paths that once wrote away an account a CLI tool (a second process)
// had added since this store last loaded: a whole-document save is built
// from what this process holds. It checks the outcome -- the other
// process's account survives the write -- not how: today each method
// reloads before deciding, but the save-conflict replay (mutate) would
// keep the account even without that reload, so this passes either way.
func TestWritesPickUpAnotherProcessesAccountFirst(t *testing.T) {
	cases := []struct {
		name  string
		write func(t *testing.T, server *Store)
	}{
		{"CreateUser", func(t *testing.T, server *Store) {
			if _, err := server.CreateUser("dave", "password789", RoleUser, time.Now()); err != nil {
				t.Fatal(err)
			}
		}},
		{"SetPassword", func(t *testing.T, server *Store) {
			if err := server.SetPassword("admin", "new-password", time.Now()); err != nil {
				t.Fatal(err)
			}
		}},
		{"TransferAdmin", func(t *testing.T, server *Store) {
			if _, _, err := server.TransferAdmin("bob", time.Now()); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := persist.NewMemory()
			server, err := OpenStore(m, Options{})
			if err != nil {
				t.Fatal(err)
			}
			_, _ = server.Register("admin", "password-placeholder-1", time.Now())
			if _, err := server.CreateUser("bob", "password456", RoleUser, time.Now()); err != nil {
				t.Fatal(err)
			}

			// A second, independent Store against the same backend --
			// standing in for a CLI tool's own separate process.
			cli, err := OpenStore(m, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cli.CreateUser("carol", "password456", RoleUser, time.Now()); err != nil {
				t.Fatal(err)
			}

			tc.write(t, server)

			// Read what is on disk through a fresh store, not the one
			// that just wrote: the question is what survived the save.
			after, err := OpenStore(m, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := after.ByUsername("carol"); !ok {
				t.Errorf("%s wrote over the account another process had just added", tc.name)
			}
		})
	}
}
