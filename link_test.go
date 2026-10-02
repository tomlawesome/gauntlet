// Ported from mikroview's internal/auth/link_test.go. Adapted:
// Open(path) -> openTestStore(t); OpenWithBackend -> OpenStore.

package gauntlet

import (
	"errors"
	"testing"
	"time"
)

// Linking is a one-way, destructive conversion for every role but
// admin. The account becomes SSO-only in the same operation, because a
// dual-mode account -- local password still works, SSO also works --
// keeps the weaker local attack surface alive on an account that is
// supposed to have moved past it.
//
// The invariant lives inside LinkOIDCIdentity rather than at a caller's
// own API layer, so these test the store directly.
func TestLinkingDestroysANonAdminsLocalPassword(t *testing.T) {
	s := openTestStore(t)

	if _, err := s.Register("alice", "password123", time.Now()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	u, err := s.CreateUser("bob", "password456", RoleUser, time.Now())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := s.Authenticate("bob", "password456", time.Now()); err != nil {
		t.Fatalf("the password should work before linking: %v", err)
	}

	if err := s.LinkOIDCIdentity(u.ID, "https://idp.example", "subject-1", time.Now()); err != nil {
		t.Fatalf("LinkOIDCIdentity: %v", err)
	}

	if _, err := s.Authenticate("bob", "password456", time.Now()); err == nil {
		t.Error("the old password still works after linking -- the account is dual-mode")
	}
	linked, _ := s.ByUsername("bob")
	if linked.LocalPassword() {
		t.Error("the linked account still reports a local password")
	}
	if linked.OIDCIssuer != "https://idp.example" || linked.OIDCSubject != "subject-1" {
		t.Errorf("identity not attached: %+v", linked)
	}
}

// The admin is the exception, and the reason mikroview #1252 exists: the
// admin must always be able to sign in, even with the identity provider
// down. This package never authenticates to the provider on its own
// behalf, so a provider that cannot answer means nobody gets in --
// unless the one account that can fix it kept a password. SSO is added
// to that account, not swapped for it.
func TestLinkingKeepsTheAdminsLocalPassword(t *testing.T) {
	s := openTestStore(t)

	admin, err := s.Register("alice", "password123", time.Now())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if admin.Role != RoleAdmin {
		t.Fatalf("Role = %q, want admin -- this test is not set up as it thinks", admin.Role)
	}

	if err := s.LinkOIDCIdentity(admin.ID, "https://idp.example", "subject-1", time.Now()); err != nil {
		t.Fatalf("LinkOIDCIdentity: %v", err)
	}

	// The password itself, not just the flag: a link that left
	// HasLocalPassword true over an unmatchable hash would report a way
	// in that does not exist.
	if _, err := s.Authenticate("alice", "password123", time.Now()); err != nil {
		t.Errorf("the admin's password stopped working after linking: %v", err)
	}
	linked, _ := s.ByUsername("alice")
	if !linked.LocalPassword() {
		t.Error("the linked admin reports no local password")
	}
	if linked.OIDCIssuer != "https://idp.example" || linked.OIDCSubject != "subject-1" {
		t.Errorf("identity not attached: %+v", linked)
	}
	if !s.HasLocalAdmin() {
		t.Error("the deployment lost its way in that does not need the provider")
	}
}

// The replacement hash must be a real Argon2id hash, not "". An empty
// or malformed hash short-circuits VerifyPassword before Argon2id runs,
// so a login attempt against an SSO-only account would return
// measurably faster than one against a password account -- telling an
// attacker which accounts are worth attacking locally.
func TestLinkingLeavesARealUnmatchableHash(t *testing.T) {
	s := openTestStore(t)
	// An ordinary user: the admin keeps its real hash now (#1252), so
	// the replacement only happens here.
	_, _ = s.Register("alice", "password123", time.Now())
	u, _ := s.CreateUser("bob", "password456", RoleUser, time.Now())

	before, _ := s.Get(u.ID)
	if err := s.LinkOIDCIdentity(u.ID, "https://idp.example", "subject-1", time.Now()); err != nil {
		t.Fatalf("LinkOIDCIdentity: %v", err)
	}
	after, _ := s.Get(u.ID)

	if after.PasswordHash == "" {
		t.Fatal("password hash was blanked rather than replaced")
	}
	if after.PasswordHash == before.PasswordHash {
		t.Fatal("password hash was left untouched")
	}
	if VerifyPassword(after.PasswordHash, "anything-at-all") {
		t.Error("the replacement hash matched a guess")
	}
}

// Every session issued before the link has to die: the account's
// credentials just changed fundamentally. True of the admin too, whose
// password survives the link (#1252) -- a second way into the account
// was still just attached, and a caller's own login-completion path
// hands the browser that did it a fresh session.
func TestLinkingInvalidatesEarlierSessions(t *testing.T) {
	s := openTestStore(t)
	u, _ := s.Register("alice", "password123", time.Now())

	linkedAt := time.Now()
	if err := s.LinkOIDCIdentity(u.ID, "https://idp.example", "subject-1", linkedAt); err != nil {
		t.Fatalf("LinkOIDCIdentity: %v", err)
	}

	after, _ := s.Get(u.ID)
	if !after.PasswordChangedAt.Equal(linkedAt) {
		t.Errorf("PasswordChangedAt = %v, want %v -- sessions issued before the link stay valid",
			after.PasswordChangedAt, linkedAt)
	}
}

// Refusing a taken identity is what stops someone attaching their own
// IdP account to a colleague's -- or to the admin's.
func TestLinkingRefusesAnIdentityHeldByAnotherAccount(t *testing.T) {
	s := openTestStore(t)
	alice, _ := s.Register("alice", "password123", time.Now())
	bob, _ := s.CreateUser("bob", "password456", RoleUser, time.Now())

	if err := s.LinkOIDCIdentity(alice.ID, "https://idp.example", "shared-subject", time.Now()); err != nil {
		t.Fatalf("first link: %v", err)
	}
	if err := s.LinkOIDCIdentity(bob.ID, "https://idp.example", "shared-subject", time.Now()); err != ErrOIDCIdentityTaken {
		t.Fatalf("expected ErrOIDCIdentityTaken, got %v", err)
	}

	// And the refusal must be total -- bob keeps his password rather
	// than being half-converted by a link that didn't happen.
	if _, err := s.Authenticate("bob", "password456", time.Now()); err != nil {
		t.Errorf("a refused link destroyed the account's password anyway: %v", err)
	}
	stillBob, _ := s.ByUsername("bob")
	if !stillBob.LocalPassword() || stillBob.OIDCIssuer != "" {
		t.Errorf("a refused link mutated the account: %+v", stillBob)
	}
}

// Only reachable since #1252: before it, a linked account had no local
// password and a caller's link route refuses those, so nothing could
// ask for a second link. The admin keeps its password now, so it can --
// and a second identity must not be accepted quietly, because the first
// would stay in the index and go on signing in as this account.
func TestLinkingRefusesASecondIdentityForTheSameAccount(t *testing.T) {
	s := openTestStore(t)
	admin, _ := s.Register("alice", "password123", time.Now())

	if err := s.LinkOIDCIdentity(admin.ID, "https://idp.example", "subject-1", time.Now()); err != nil {
		t.Fatalf("first link: %v", err)
	}
	if err := s.LinkOIDCIdentity(admin.ID, "https://idp.example", "subject-2", time.Now()); err != ErrOIDCAlreadyLinked {
		t.Fatalf("second link = %v, want ErrOIDCAlreadyLinked", err)
	}

	linked, _ := s.ByUsername("alice")
	if linked.OIDCSubject != "subject-1" {
		t.Errorf("OIDCSubject = %q, want the first identity untouched", linked.OIDCSubject)
	}
	if u, ok := s.ByOIDCIdentity("https://idp.example", "subject-2"); ok {
		t.Errorf("the refused identity signs in as %q anyway", u.Username)
	}
}

func TestLinkingIsIdempotentForTheSameAccount(t *testing.T) {
	s := openTestStore(t)
	u, _ := s.Register("alice", "password123", time.Now())

	if err := s.LinkOIDCIdentity(u.ID, "https://idp.example", "subject-1", time.Now()); err != nil {
		t.Fatalf("first link: %v", err)
	}
	if err := s.LinkOIDCIdentity(u.ID, "https://idp.example", "subject-1", time.Now()); err != nil {
		t.Errorf("re-linking the same identity to the same account failed: %v", err)
	}
}

// After linking, a non-admin account holds no credential this package
// can reset, so recovery is the identity provider's job. Worth pinning
// so a future change to LocalPassword() can't silently re-open local
// recovery for an account that has none.
func TestALinkedNonAdminIsNotLocallyRecoverable(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Register("alice", "password123", time.Now())
	u, _ := s.CreateUser("bob", "password456", RoleUser, time.Now())
	if err := s.LinkOIDCIdentity(u.ID, "https://idp.example", "subject-1", time.Now()); err != nil {
		t.Fatalf("LinkOIDCIdentity: %v", err)
	}

	linked, ok := s.ByUsername("bob")
	if !ok {
		t.Fatal("the account vanished")
	}
	if linked.LocalPassword() {
		t.Error("a linked account still reports as locally recoverable")
	}
}

// TestLinkOIDCIdentityLeavesThePasswordWorkingWhenPersistFails: a link
// that cannot be saved must not destroy the account's local password or
// attach the identity in memory either, or a restart before the next
// good write would silently un-link the account while its old password
// (which linking replaced with an unmatchable hash) has already stopped
// working for the operator.
func TestLinkOIDCIdentityLeavesThePasswordWorkingWhenPersistFails(t *testing.T) {
	// Register and CreateUser below each persist too (createAccount
	// persists as well), so the fixture needs a backend that saves
	// twice before failing, not one that fails outright. bob must be a
	// non-admin: linking keeps the admin's password unconditionally
	// (#1252), so only a non-admin actually exercises the rollback.
	s, err := OpenStore(&saveBudgetBackend{left: 2}, Options{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if _, err := s.Register("alice", "password123", time.Now()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	u, err := s.CreateUser("bob", "password456", RoleUser, time.Now())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if err := s.LinkOIDCIdentity(u.ID, "https://idp.example", "subject-1", time.Now()); err == nil {
		t.Fatal("LinkOIDCIdentity against a backend that cannot save = nil error, want one")
	}

	if _, err := s.Authenticate("bob", "password456", time.Now()); err != nil {
		t.Errorf("expected the old password to still work after a failed persist, got %v", err)
	}
	if _, ok := s.ByOIDCIdentity("https://idp.example", "subject-1"); ok {
		t.Error("the identity index still resolves an account whose link was never durably saved")
	}
	got, ok := s.ByUsername("bob")
	if !ok {
		t.Fatal("expected the account to still be there")
	}
	if !got.LocalPassword() {
		t.Error("expected the account to still report as locally recoverable after a failed link")
	}
}

// TestLinkingKillsAnOutstandingResetCode: an admin reset code stands in
// for the password (Authenticate redeems it as one), so converting a
// non-admin to SSO-only has to end it with the password -- otherwise
// whoever saw the code keeps a local way into an account that is meant
// to have none, and the forced-change flag then doors an account with
// no password to change.
func TestLinkingKillsAnOutstandingResetCode(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	_, _ = s.Register("alice", "password123", now)
	u, _ := s.CreateUser("bob", "password456", RoleUser, now)
	_, code, err := s.IssueResetCode(u.ID, now)
	if err != nil {
		t.Fatalf("IssueResetCode: %v", err)
	}

	if err := s.LinkOIDCIdentity(u.ID, "https://idp.example", "subject-1", now); err != nil {
		t.Fatalf("LinkOIDCIdentity: %v", err)
	}

	if _, err := s.Authenticate("bob", code, now); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Authenticate with the reset code after linking = %v, want %v", err, ErrInvalidCredentials)
	}
	linked, _ := s.Get(u.ID)
	if linked.ResetCodeHash != "" || !linked.ResetCodeExpiresAt.IsZero() {
		t.Error("the reset code survived linking")
	}
	if linked.MustChangePassword {
		t.Error("a linked non-admin is still flagged to change a password it no longer has")
	}
}
