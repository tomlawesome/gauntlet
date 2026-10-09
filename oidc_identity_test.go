// Ported from mikroview's internal/auth/oidc_identity_test.go. Adapted:
// Open(path) -> newTestOIDCStore(t)/openTestStore(t); the reopen test
// shares one persist.Memory backend between two Store instances instead
// of two Opens of the same file path.

package gauntlet

import (
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// newTestOIDCStore holds the first admin already: SSO never creates the
// first account (issue #37), so every provisioning test starts after it.
func newTestOIDCStore(t *testing.T) *Store {
	t.Helper()
	return openTestStoreWithAdmin(t)
}

func TestFindOrCreateOIDCUserProvisionsAnOrdinaryUser(t *testing.T) {
	s := newTestOIDCStore(t)

	u, created, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "alice", time.Now())
	if err != nil {
		t.Fatalf("FindOrCreateOIDCUser: %v", err)
	}
	if !created {
		t.Error("expected created=true for a brand-new identity")
	}
	if u.Role != RoleUser {
		t.Errorf("Role = %q, want user (never the admin: the first admin is local)", u.Role)
	}
	if u.OIDCIssuer != "https://idp.example" || u.OIDCSubject != "sub-1" {
		t.Errorf("identity not recorded: %+v", u)
	}
	if u.Username != "alice" {
		t.Errorf("Username = %q, want alice (hint was free)", u.Username)
	}
}

func TestFindOrCreateOIDCUserSecondIdentityIsRegularUser(t *testing.T) {
	s := newTestOIDCStore(t)
	now := time.Now()

	if _, _, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "alice", now); err != nil {
		t.Fatalf("first FindOrCreateOIDCUser: %v", err)
	}
	u, created, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-2", "bob", now)
	if err != nil {
		t.Fatalf("second FindOrCreateOIDCUser: %v", err)
	}
	if !created {
		t.Error("expected created=true")
	}
	if u.Role != RoleUser {
		t.Errorf("Role = %q, want user (not the first account)", u.Role)
	}
}

func TestFindOrCreateOIDCUserReusesExistingIdentity(t *testing.T) {
	s := newTestOIDCStore(t)
	now := time.Now()

	first, created, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "alice", now)
	if err != nil || !created {
		t.Fatalf("first call: user=%+v created=%v err=%v", first, created, err)
	}

	later := now.Add(time.Hour)
	second, created, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "alice", later)
	if err != nil {
		t.Fatalf("second FindOrCreateOIDCUser: %v", err)
	}
	if created {
		t.Error("expected created=false on a repeat login for the same identity")
	}
	if second.ID != first.ID {
		t.Errorf("second call returned a different user: %+v vs %+v", second, first)
	}
	if !second.LastLogin.Equal(later) {
		t.Errorf("LastLogin = %v, want %v (repeat login should update it)", second.LastLogin, later)
	}
	if s.Count() != 2 {
		t.Errorf("Count() = %d, want 2 (the admin and this one) -- a repeat login must not create a second account", s.Count())
	}
}

// TestFindOrCreateOIDCUserSavesLastLoginAtMostHourly: a returning SSO
// sign-in follows Authenticate's rule (TestAuthenticateSavesLastLoginAtMostHourly)
// -- LastLogin is saved only once the saved value is more than
// lastLoginGranularity old, and otherwise kept in memory where Get sees
// it, so SSO sign-ins do not each rewrite every account.
func TestFindOrCreateOIDCUserSavesLastLoginAtMostHourly(t *testing.T) {
	b := &countingBackend{Memory: persist.NewMemory()}
	s, _ := openLockoutStore(t, b)
	start := time.Now().UTC().Truncate(time.Millisecond)

	signIn := func(at time.Time) *User {
		t.Helper()
		u, _, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "bob", at)
		if err != nil {
			t.Fatalf("FindOrCreateOIDCUser at %v: %v", at, err)
		}
		return u
	}

	first := signIn(start) // provisions the account: one save
	before := b.saves.Load()
	if u := signIn(start.Add(time.Minute)); !u.LastLogin.Equal(start.Add(time.Minute)) {
		t.Errorf("returned LastLogin = %v, want %v", u.LastLogin, start.Add(time.Minute))
	}
	if got := b.saves.Load() - before; got != 0 {
		t.Errorf("a returning sign-in a minute after the saved one caused %d saves, want 0", got)
	}
	if u, _ := s.Get(first.ID); !u.LastLogin.Equal(start.Add(time.Minute)) {
		t.Errorf("LastLogin = %v in memory, want the second sign-in's %v", u.LastLogin, start.Add(time.Minute))
	}

	later := start.Add(lastLoginGranularity + time.Minute)
	signIn(later)
	if got := b.saves.Load() - before; got != 1 {
		t.Errorf("a sign-in %v after the saved one caused %d saves, want 1", lastLoginGranularity+time.Minute, got)
	}
	reopened, err := OpenStore(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := reopened.Get(first.ID); !u.LastLogin.Equal(later) {
		t.Errorf("saved LastLogin = %v, want %v", u.LastLogin, later)
	}
}

func TestFindOrCreateOIDCUserNeverAutoLinksByUsernameHint(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()

	// A local password account already owns the username "alice".
	if _, err := s.Register("alice", "password-placeholder-345", now); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// A completely unrelated OIDC identity that happens to present the
	// same preferred_username must NOT attach to that existing account
	// -- identity is (issuer, subject) only.
	u, created, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-999", "alice", now)
	if err != nil {
		t.Fatalf("FindOrCreateOIDCUser: %v", err)
	}
	if !created {
		t.Fatal("expected a new account to be provisioned, not attached to the existing 'alice'")
	}
	if u.Username == "alice" {
		t.Fatal("OIDC user was given the exact username of an unrelated existing local account")
	}
	if u.OIDCIssuer == "" {
		t.Error("expected the synthetic-username account to still carry the OIDC identity")
	}
	if s.Count() != 2 {
		t.Errorf("Count() = %d, want 2 (local alice + the new synthetic-username OIDC account)", s.Count())
	}
}

func TestFindOrCreateOIDCUserSyntheticUsernameIsStableAcrossRetries(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()

	if _, err := s.Register("bob", "password-placeholder-345", now); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Same (issuer, subject) + colliding hint, called twice -- the
	// second call must resolve to the exact same account (via the
	// oidcIndex lookup), not generate a second synthetic username.
	a, created, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "bob", now)
	if err != nil || !created {
		t.Fatalf("first call: user=%+v created=%v err=%v", a, created, err)
	}
	b, created, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "bob", now)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if created {
		t.Error("second call for the same identity should not create a new account")
	}
	if a.ID != b.ID || a.Username != b.Username {
		t.Errorf("retried provisioning diverged: %+v vs %+v", a, b)
	}
}

func TestFindOrCreateOIDCUserEmptyHintGetsSyntheticUsername(t *testing.T) {
	s := newTestOIDCStore(t)
	u, _, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "", time.Now())
	if err != nil {
		t.Fatalf("FindOrCreateOIDCUser: %v", err)
	}
	if u.Username == "" {
		t.Fatal("expected a non-empty synthetic username when the hint is empty")
	}
}

func TestFindOrCreateOIDCUserNotGatedByClosedLocalRegistration(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()

	if _, err := s.Register("first-admin", "password-placeholder-345", now); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Local self-registration is now closed (Count() > 0) -- JIT OIDC
	// provisioning must be unaffected, unlike Register.
	if _, err := s.Register("second-local", "password-placeholder-345", now); err != ErrRegistrationClosed {
		t.Fatalf("expected local Register to be closed, got %v", err)
	}

	u, created, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "someone", now)
	if err != nil {
		t.Fatalf("FindOrCreateOIDCUser after local registration closed: %v", err)
	}
	if !created || u == nil {
		t.Fatal("expected JIT provisioning to succeed regardless of Register's one-time gate")
	}
}

func TestFindOrCreateOIDCUserRefusesWhenNotPersisted(t *testing.T) {
	s, _ := OpenStore(nil, Options{})
	if _, _, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "someone", time.Now()); err != ErrNotPersisted {
		t.Errorf("expected ErrNotPersisted, got %v", err)
	}
}

// TestOIDCOnlyUserPasswordHashIsUnmatchableNotEmpty guards against a
// real timing side-channel found during mikroview's design review: an
// empty PasswordHash would make VerifyPassword's malformed-hash guard
// return false *before* running Argon2id at all, responding measurably
// faster than either a real password mismatch or an unknown username
// (both of which always pay the Argon2id cost) -- letting a local-login
// attempt distinguish "this username is SSO-only" purely from response
// time.
func TestOIDCOnlyUserPasswordHashIsUnmatchableNotEmpty(t *testing.T) {
	s := newTestOIDCStore(t)
	now := time.Now()
	u, _, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "sso-only", now)
	if err != nil {
		t.Fatalf("FindOrCreateOIDCUser: %v", err)
	}

	stored, ok := s.byID[u.ID]
	if !ok {
		t.Fatal("provisioned user not found in store")
	}
	if stored.PasswordHash == "" {
		t.Fatal("OIDC-only user has an empty PasswordHash -- this is the timing side-channel the design review flagged")
	}

	requireUnmatchableHash(t, stored.PasswordHash)

	// A local-login attempt against this username must go through the
	// same real Argon2id comparison path as any other account (and
	// fail, since there's no real password) -- not the fast malformed-
	// hash rejection.
	if _, err := s.Authenticate(u.Username, "whatever-password", now); err != ErrInvalidCredentials {
		t.Errorf("Authenticate against an OIDC-only user = %v, want ErrInvalidCredentials", err)
	}
}

func TestByOIDCIdentityFindsProvisionedUser(t *testing.T) {
	s := newTestOIDCStore(t)
	now := time.Now()
	created, _, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "alice", now)
	if err != nil {
		t.Fatalf("FindOrCreateOIDCUser: %v", err)
	}

	found, ok := s.ByOIDCIdentity("https://idp.example", "sub-1")
	if !ok {
		t.Fatal("ByOIDCIdentity did not find the provisioned user")
	}
	if found.ID != created.ID {
		t.Errorf("found ID %q, want %q", found.ID, created.ID)
	}

	if _, ok := s.ByOIDCIdentity("https://idp.example", "sub-does-not-exist"); ok {
		t.Error("ByOIDCIdentity found a user for an identity that was never provisioned")
	}
}

func TestLinkOIDCIdentityAttachesToExistingLocalUser(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	u, err := s.Register("alice", "password-placeholder-345", now)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := s.LinkOIDCIdentity(u.ID, "https://idp.example", "sub-1", now); err != nil {
		t.Fatalf("LinkOIDCIdentity: %v", err)
	}

	found, ok := s.ByOIDCIdentity("https://idp.example", "sub-1")
	if !ok || found.ID != u.ID {
		t.Fatalf("ByOIDCIdentity after linking = %+v, %v -- want user %q", found, ok, u.ID)
	}

	relogin, created, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "alice", now)
	if err != nil {
		t.Fatalf("FindOrCreateOIDCUser after linking: %v", err)
	}
	if created {
		t.Error("logging in with a linked identity must reuse the linked account, not create a new one")
	}
	if relogin.ID != u.ID {
		t.Errorf("linked login resolved to %q, want the local account %q", relogin.ID, u.ID)
	}
}

func TestLinkOIDCIdentityIsIdempotentForSameUser(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	u, err := s.Register("alice", "password-placeholder-345", now)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := s.LinkOIDCIdentity(u.ID, "https://idp.example", "sub-1", now); err != nil {
		t.Fatalf("first LinkOIDCIdentity: %v", err)
	}
	if err := s.LinkOIDCIdentity(u.ID, "https://idp.example", "sub-1", now); err != nil {
		t.Fatalf("second LinkOIDCIdentity (same user, should be idempotent): %v", err)
	}
}

func TestLinkOIDCIdentityRefusesWhenTakenByDifferentUser(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	a, err := s.Register("alice", "password-placeholder-345", now)
	if err != nil {
		t.Fatalf("Register alice: %v", err)
	}
	b, err := s.CreateUser("bob", "password-placeholder-345", RoleUser, now)
	if err != nil {
		t.Fatalf("CreateUser bob: %v", err)
	}
	if err := s.LinkOIDCIdentity(a.ID, "https://idp.example", "sub-1", now); err != nil {
		t.Fatalf("LinkOIDCIdentity(a): %v", err)
	}
	if err := s.LinkOIDCIdentity(b.ID, "https://idp.example", "sub-1", now); err != ErrOIDCIdentityTaken {
		t.Errorf("LinkOIDCIdentity(b, already taken) = %v, want ErrOIDCIdentityTaken", err)
	}
}

func TestOIDCIdentityPersistsAndReloadsAcrossStoreOpen(t *testing.T) {
	m := persist.NewMemory()
	s1, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	now := time.Now()
	if _, err := s1.Register("setup-admin", "setup-admin-password", now); err != nil {
		t.Fatalf("Register: %v", err)
	}
	created, _, err := s1.FindOrCreateOIDCUser("https://idp.example", "sub-1", "alice", now)
	if err != nil {
		t.Fatalf("FindOrCreateOIDCUser: %v", err)
	}

	s2, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatalf("re-OpenStore: %v", err)
	}
	found, ok := s2.ByOIDCIdentity("https://idp.example", "sub-1")
	if !ok {
		t.Fatal("OIDC identity did not survive a Store re-open")
	}
	if found.ID != created.ID {
		t.Errorf("reloaded ID %q, want %q", found.ID, created.ID)
	}
}

// TestFindOrCreateOIDCUserRollsBackOnPersistFailure: a JIT-provisioned
// account that cannot be saved must not exist in memory either, or a
// restart before the next good write would leave a session referencing
// an account ID that vanished, and a retried login would silently mint
// a second account for the same identity.
func TestFindOrCreateOIDCUserRollsBackOnPersistFailure(t *testing.T) {
	// An admin has to exist first, or FindOrCreateOIDCUser refuses with
	// ErrSetupRequired before it saves anything and the rollback is never
	// reached. The one save the budget allows is that registration.
	s, err := OpenStore(&saveBudgetBackend{left: 1}, Options{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if _, err := s.Register("setup-admin", "setup-admin-password", time.Now()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	u, created, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "alice", time.Now())
	if !errors.Is(err, errTestBackendUnavailable) {
		t.Fatalf("FindOrCreateOIDCUser against a backend that cannot save = %v, want the backend's save error", err)
	}
	if created {
		t.Error("created=true after a failed persist")
	}
	if u != nil {
		t.Errorf("returned user = %+v, want nil after a failed persist", u)
	}
	if s.Count() != 1 {
		t.Errorf("Count() = %d after a failed persist, want 1 (the admin) -- the account must not exist in memory either", s.Count())
	}
	if _, ok := s.ByOIDCIdentity("https://idp.example", "sub-1"); ok {
		t.Error("the identity index still resolves an account that was never durably created")
	}
}

const ssoRolesIssuer = "https://idp.example"

func signInWithRole(t *testing.T, s *Store, subject string, role Role, at time.Time) OIDCSignIn {
	t.Helper()
	in, err := s.FindOrCreateOIDCUserWithRole(ssoRolesIssuer, subject, subject, role, at)
	if err != nil {
		t.Fatalf("FindOrCreateOIDCUserWithRole(%q, %q): %v", subject, role, err)
	}
	return in
}

func TestFindOrCreateOIDCUserWithRoleCreatesAtThatRole(t *testing.T) {
	s := newTestOIDCStore(t)

	in := signInWithRole(t, s, "guest", RoleViewer, time.Now())
	if !in.Created || in.User.Role != RoleViewer || in.RoleBefore != RoleViewer || in.SessionsEnded {
		t.Errorf("got %+v, want created viewer with no change", in)
	}
	if u, _ := s.Get(in.User.ID); u.Role != RoleViewer {
		t.Errorf("stored role = %q, want viewer", u.Role)
	}
}

func TestFindOrCreateOIDCUserWithRoleUpgradeKeepsSessions(t *testing.T) {
	s := newTestOIDCStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	signInWithRole(t, s, "guest", RoleViewer, now)

	later := now.Add(2 * time.Hour)
	in := signInWithRole(t, s, "guest", RoleUser, later)
	if in.Created || in.RoleBefore != RoleViewer || in.User.Role != RoleUser {
		t.Errorf("got %+v, want viewer -> user on an existing account", in)
	}
	if in.SessionsEnded || !in.User.SessionsEndedAt.IsZero() {
		t.Error("an upgrade ended the account's sessions")
	}
	if !in.User.RoleChangedAt.Equal(later) {
		t.Errorf("RoleChangedAt = %v, want %v", in.User.RoleChangedAt, later)
	}
}

func TestFindOrCreateOIDCUserWithRoleDowngradeEndsSessions(t *testing.T) {
	s := newTestOIDCStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	signInWithRole(t, s, "staff", RoleUser, now)

	// Inside lastLoginGranularity: the role change is still saved, not
	// folded into the best-effort LastLogin path.
	later := now.Add(time.Minute)
	in := signInWithRole(t, s, "staff", RoleViewer, later)
	if in.RoleBefore != RoleUser || in.User.Role != RoleViewer || !in.SessionsEnded {
		t.Errorf("got %+v, want user -> viewer with sessions ended", in)
	}
	if !in.User.SessionsEndedAt.Equal(later) || !in.User.RoleChangedAt.Equal(later) {
		t.Errorf("SessionsEndedAt %v, RoleChangedAt %v, want both %v", in.User.SessionsEndedAt, in.User.RoleChangedAt, later)
	}
	if u, _ := s.Get(in.User.ID); u.Role != RoleViewer || !u.SessionsEndedAt.Equal(later) {
		t.Errorf("stored account = %+v, want viewer with sessions ended at %v", u, later)
	}
}

func TestFindOrCreateOIDCUserWithRoleNeverTouchesAnAdmin(t *testing.T) {
	s := newTestOIDCStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	in := signInWithRole(t, s, "boss", RoleUser, now)
	if _, _, err := s.SetRole(in.User.ID, RoleAdmin, now); err != nil {
		t.Fatal(err)
	}

	got := signInWithRole(t, s, "boss", RoleViewer, now.Add(time.Minute))
	if got.User.Role != RoleAdmin || got.RoleBefore != RoleAdmin || got.SessionsEnded {
		t.Errorf("got %+v, want the admin untouched", got)
	}
	if u, _ := s.Get(in.User.ID); u.Role != RoleAdmin {
		t.Errorf("stored role = %q, want admin", u.Role)
	}
}

func TestFindOrCreateOIDCUserWithRoleEmptyLeavesTheRoleAlone(t *testing.T) {
	s := newTestOIDCStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	signInWithRole(t, s, "guest", RoleViewer, now)

	got := signInWithRole(t, s, "guest", "", now.Add(time.Minute))
	if got.User.Role != RoleViewer || got.RoleBefore != RoleViewer || got.SessionsEnded {
		t.Errorf("got %+v, want the viewer left alone", got)
	}
	// And a never-seen identity is an ordinary user, as before.
	if in := signInWithRole(t, s, "new", "", now); in.User.Role != RoleUser {
		t.Errorf("new account role = %q, want user", in.User.Role)
	}
}

func TestFindOrCreateOIDCUserWithRoleUnchangedWritesNothing(t *testing.T) {
	b := &countingBackend{Memory: persist.NewMemory()}
	s, _ := openLockoutStore(t, b)
	now := time.Now().UTC().Truncate(time.Millisecond)
	signInWithRole(t, s, "guest", RoleViewer, now)

	before := b.saves.Load()
	in := signInWithRole(t, s, "guest", RoleViewer, now.Add(time.Minute))
	if in.SessionsEnded || in.RoleBefore != RoleViewer {
		t.Errorf("got %+v, want no change", in)
	}
	if got := b.saves.Load() - before; got != 0 {
		t.Errorf("a sign-in at the same role caused %d saves, want 0", got)
	}
}

func TestFindOrCreateOIDCUserWithRoleRefusesAdminAndUnknown(t *testing.T) {
	s := newTestOIDCStore(t)
	for _, role := range []Role{RoleAdmin, "root"} {
		if _, err := s.FindOrCreateOIDCUserWithRole(ssoRolesIssuer, "x", "x", role, time.Now()); err != ErrInvalidRole {
			t.Errorf("role %q: err = %v, want ErrInvalidRole", role, err)
		}
	}
	if s.Count() != 1 {
		t.Errorf("Count() = %d, want 1: a refused call provisioned an account", s.Count())
	}
}

// A returning SSO sign-in whose role changes is a write, but not a new
// account: it must not pay for the unmatchable password hash a new one
// gets (~100 ms of Argon2id and 64 MiB) only to throw it away -- and
// under the store's lock, where every other request waits for it.
// Measured as allocation, as TestClosedRegistrationDoesNotHash does, at
// the production cost.
func TestFindOrCreateOIDCUserWithRoleChangeDoesNotHash(t *testing.T) {
	useProductionHashCost(t)
	s := newTestOIDCStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	signInWithRole(t, s, "staff", RoleUser, now)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	in := signInWithRole(t, s, "staff", RoleViewer, now.Add(time.Minute))
	runtime.ReadMemStats(&after)

	if in.Created || in.User.Role != RoleViewer {
		t.Fatalf("got %+v, want the existing account moved to viewer", in)
	}
	const ceiling = 16 << 20 // one hash is 64 MiB
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > ceiling {
		t.Errorf("a role-changing SSO sign-in allocated %.1f MiB; want well under %d MiB -- it hashed a password it never stores",
			float64(allocated)/(1<<20), ceiling>>20)
	}
}
