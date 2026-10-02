package gauntlet

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// The tests in this file are the invariant half of #21: a write whose
// save is refused because another process wrote first is replayed
// against the fresh document, and every check that protects an
// invariant has to be made again against that document, not carried
// over from the one this process decided on. Each test slips the other
// process's write in just before this store's save (otherProcessBackend,
// mutate_test.go) and changes exactly the fact the check decides on.

// openRacingStores opens a store over an otherProcessBackend and a
// second store on the same document, after setup has run on the first:
// the second is the other process, and has seen everything setup did.
func openRacingStores(t *testing.T, setup func(s *Store)) (s *Store, b *otherProcessBackend, other *Store) {
	t.Helper()
	m := persist.NewMemory()
	b = &otherProcessBackend{Memory: m}
	s, err := OpenStore(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if setup != nil {
		setup(s)
	}
	other, err = OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return s, b, other
}

// TestGenerateRecoveryCodesIfAbsentRedecidesOnReplay: another process
// mints alice's recovery codes after this one checked and found none.
// The replay must find that set and report alreadyIssued, leaving the
// codes the other process showed its user working -- not replace them
// with a set nobody will ever see.
func TestGenerateRecoveryCodesIfAbsentRedecidesOnReplay(t *testing.T) {
	now := time.Now()
	var aliceID string
	s, b, other := openRacingStores(t, func(s *Store) {
		alice, err := s.Register("alice", "password123", now)
		if err != nil {
			t.Fatal(err)
		}
		aliceID = alice.ID
	})

	var otherCodes []string
	b.beforeSave = func() {
		codes, already, err := other.GenerateRecoveryCodesIfAbsent(aliceID, now)
		if err != nil || already {
			t.Errorf("the other process's GenerateRecoveryCodesIfAbsent = %v, %v", already, err)
		}
		otherCodes = codes
	}

	codes, already, err := s.GenerateRecoveryCodesIfAbsent(aliceID, now)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodesIfAbsent across a conflicting write: %v", err)
	}
	if !already || codes != nil {
		t.Fatalf("GenerateRecoveryCodesIfAbsent = %d codes, alreadyIssued %v; want none and true -- the other process issued a set first", len(codes), already)
	}
	if len(otherCodes) == 0 {
		t.Fatal("the other process minted nothing")
	}
	reopened, err := OpenStore(b.Memory, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := reopened.BurnRecoveryCode(aliceID, otherCodes[0], now); err != nil || !ok {
		t.Errorf("a code the other process showed its user no longer works (ok %v, err %v): its set was replaced", ok, err)
	}
}

// reopenAccounts opens a fresh store on the document as saved -- which
// fails if the saved document breaks the single-admin rule.
func reopenAccounts(t *testing.T, b *otherProcessBackend) *Store {
	t.Helper()
	s, err := OpenStore(b.Memory, Options{})
	if err != nil {
		t.Fatalf("reopening the saved document: %v", err)
	}
	return s
}

// TestRegisterRedecidesRegistrationOpenOnReplay: two processes on an
// empty store, each about to register the first account. The other one
// gets there first. This store's replay must find registration closed,
// not add a second admin to the document the other process wrote.
func TestRegisterRedecidesRegistrationOpenOnReplay(t *testing.T) {
	s, b, other := openRacingStores(t, nil)
	b.beforeSave = func() {
		if _, err := other.Register("alice", "password123", time.Now()); err != nil {
			t.Errorf("the other process's Register: %v", err)
		}
	}

	if _, err := s.Register("bob", "password456", time.Now()); !errors.Is(err, ErrRegistrationClosed) {
		t.Fatalf("Register after another process registered first = %v, want ErrRegistrationClosed", err)
	}
	if got := usernamesIn(t, b.Memory); strings.Join(got, ",") != "alice" {
		t.Errorf("saved document holds %v, want [alice]", got)
	}
}

// TestCreateUserRedecidesUsernameOnReplay: another process creates
// carol after this one checked the name was free. The replay must find
// it taken -- case-insensitively, as the check always is -- rather than
// add a second carol whose index entry shadows the first.
func TestCreateUserRedecidesUsernameOnReplay(t *testing.T) {
	s, b, other := openRacingStores(t, func(s *Store) {
		if _, err := s.Register("alice", "password123", time.Now()); err != nil {
			t.Fatal(err)
		}
	})
	b.beforeSave = func() {
		if _, err := other.CreateUser("carol", "password789", RoleUser, time.Now()); err != nil {
			t.Errorf("the other process's CreateUser: %v", err)
		}
	}

	if _, err := s.CreateUser("Carol", "password456", RoleUser, time.Now()); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("CreateUser of a name another process took first = %v, want ErrUsernameTaken", err)
	}
	if got := usernamesIn(t, b.Memory); strings.Join(got, ",") != "alice,carol" {
		t.Errorf("saved document holds %v, want [alice carol]", got)
	}
}

// TestTransferAdminRedecidesTheCurrentAdminOnReplay: alice is the admin
// when this process decides to hand the role to bob, but another
// process hands it to carol first. The replay must take the role from
// carol -- the admin in the document it saves -- leaving exactly one
// admin, bob, not demote alice a second time and leave carol an admin
// alongside him.
func TestTransferAdminRedecidesTheCurrentAdminOnReplay(t *testing.T) {
	s, b, other := openRacingStores(t, func(s *Store) {
		now := time.Now()
		if _, err := s.Register("alice", "password123", now); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"bob", "carol"} {
			if _, err := s.CreateUser(name, "password456", RoleUser, now); err != nil {
				t.Fatal(err)
			}
		}
	})
	b.beforeSave = func() {
		if _, _, err := other.TransferAdmin("carol", time.Now()); err != nil {
			t.Errorf("the other process's TransferAdmin: %v", err)
		}
	}

	from, to, err := s.TransferAdmin("bob", time.Now())
	if err != nil {
		t.Fatalf("TransferAdmin across a conflicting transfer: %v", err)
	}
	if from.Username != "carol" || to.Username != "bob" {
		t.Errorf("TransferAdmin moved the role from %q to %q, want from carol (the admin by then) to bob", from.Username, to.Username)
	}
	admin := reopenAccounts(t, b).Admin()
	if admin == nil || admin.Username != "bob" {
		t.Errorf("saved admin = %+v, want bob", admin)
	}
}

// TestFindOrCreateOIDCUserRedecidesUsernameOnReplay: the hint "bob" is
// free when an identity signs in for the first time. Another process
// creates bob first. The replay must make the account under a name that
// is not bob.
func TestFindOrCreateOIDCUserRedecidesUsernameOnReplay(t *testing.T) {
	s, b, other := openRacingStores(t, func(s *Store) {
		if _, err := s.Register("alice", "password123", time.Now()); err != nil {
			t.Fatal(err)
		}
	})
	b.beforeSave = func() {
		if _, err := other.CreateUser("bob", "password456", RoleUser, time.Now()); err != nil {
			t.Errorf("the other process's CreateUser: %v", err)
		}
	}

	u, created, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "bob", time.Now())
	if err != nil {
		t.Fatalf("FindOrCreateOIDCUser across a conflicting write: %v", err)
	}
	if !created {
		t.Error("created = false for an identity nobody had provisioned")
	}
	if u.Role != RoleUser {
		t.Errorf("role = %q, want %q", u.Role, RoleUser)
	}
	if strings.EqualFold(u.Username, "bob") {
		t.Errorf("username = %q, which the other process had already taken", u.Username)
	}
	reopened := reopenAccounts(t, b)
	if n := reopened.Count(); n != 3 {
		t.Errorf("saved document holds %d accounts, want 3", n)
	}
	if got, ok := reopened.ByOIDCIdentity("https://idp.example", "sub-1"); !ok || got.ID != u.ID {
		t.Errorf("the identity does not resolve to the account returned (%+v, %v)", got, ok)
	}
}

// TestFindOrCreateOIDCUserRefusesOnReplayAgainstAnEmptiedDocument: this
// store holds the admin when an identity signs in, so the cheap check
// before the hash lets it through. Another process empties the document
// first (a restore of an empty file). The replay must refuse against
// that document -- the first account is never an SSO one (#37) -- rather
// than carry over the "not the first account" decision and save an
// SSO-only user into a document with no admin.
func TestFindOrCreateOIDCUserRefusesOnReplayAgainstAnEmptiedDocument(t *testing.T) {
	s, b, other := openRacingStores(t, func(s *Store) {
		if _, err := s.Register("alice", "password123", time.Now()); err != nil {
			t.Fatal(err)
		}
	})
	b.beforeSave = func() {
		if _, err := b.Memory.Save(t.Context(), []byte(`{"version":1,"users":[]}`), other.version); err != nil {
			t.Errorf("the other process emptying the document: %v", err)
		}
	}

	_, created, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "bob", time.Now())
	if !errors.Is(err, ErrSetupRequired) {
		t.Fatalf("FindOrCreateOIDCUser against an emptied document = (created=%v, %v), want ErrSetupRequired", created, err)
	}
	if n := reopenAccounts(t, b).Count(); n != 0 {
		t.Errorf("saved document holds %d accounts, want 0: the refused provisioning was saved", n)
	}
}

// TestFindOrCreateOIDCUserFindsTheAccountAnotherProcessProvisioned: the
// same identity signs in through two processes at once. The other one
// provisions it first; the replay here must sign in to that account,
// not provision a second one for the same identity.
func TestFindOrCreateOIDCUserFindsTheAccountAnotherProcessProvisioned(t *testing.T) {
	s, b, other := openRacingStores(t, func(s *Store) {
		if _, err := s.Register("alice", "password123", time.Now()); err != nil {
			t.Fatal(err)
		}
	})
	var theirs *User
	b.beforeSave = func() {
		u, _, err := other.FindOrCreateOIDCUser("https://idp.example", "sub-1", "bob", time.Now())
		if err != nil {
			t.Errorf("the other process's FindOrCreateOIDCUser: %v", err)
		}
		theirs = u
	}

	u, created, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "bob", time.Now())
	if err != nil {
		t.Fatalf("FindOrCreateOIDCUser across a conflicting write: %v", err)
	}
	if created {
		t.Error("created = true for an identity the other process had already provisioned")
	}
	if theirs == nil || u.ID != theirs.ID {
		t.Errorf("signed in to %q, want the other process's account", u.ID)
	}
	if n := reopenAccounts(t, b).Count(); n != 2 {
		t.Errorf("saved document holds %d accounts, want 2 (alice and one for the identity)", n)
	}
}

// TestAuthenticateRefusesAnAccountAnotherProcessDeletedMidLogin: bob's
// password checks out, and the LastLogin bump is about to be saved
// when another process deletes bob. That bump is best-effort, and
// before this fix a failed one was re-applied to memory -- memory that
// still held bob -- and the login succeeded on an account the document
// no longer had. The store must take the fresh document instead and
// refuse the login.
func TestAuthenticateRefusesAnAccountAnotherProcessDeletedMidLogin(t *testing.T) {
	var bobID string
	s, b, other := openRacingStores(t, func(s *Store) {
		now := time.Now()
		if _, err := s.Register("alice", "password123", now); err != nil {
			t.Fatal(err)
		}
		bob, err := s.CreateUser("bob", "password456", RoleUser, now)
		if err != nil {
			t.Fatal(err)
		}
		bobID = bob.ID
	})
	b.beforeSave = func() {
		if _, err := other.DeleteUser(bobID); err != nil {
			t.Errorf("the other process's DeleteUser: %v", err)
		}
	}

	if _, err := s.Authenticate("bob", "password456", time.Now()); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Authenticate as an account another process deleted = %v, want ErrInvalidCredentials", err)
	}
	if storeHas(s, "bob") {
		t.Error("bob is still in memory after the document without him was loaded")
	}
}

// TestTokenAuthenticateRefusesATokenAnotherProcessRevokedMidUse is the
// same for API tokens, where it matters most: the LastUsedAt bump is
// about to be saved when the CLI revokes the token. The server must
// not hand back the revoked token as valid from its stale memory.
func TestTokenAuthenticateRefusesATokenAnotherProcessRevokedMidUse(t *testing.T) {
	m := persist.NewMemory()
	b := &otherProcessBackend{Memory: m}
	server, err := OpenTokenStore(b, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	raw, tok, err := server.Create("a", TokenKindAPI, "", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b.beforeSave = func() {
		if err := cli.Revoke(tok.ID); err != nil {
			t.Errorf("the CLI's Revoke: %v", err)
		}
	}

	if got, ok := server.Authenticate(raw, TokenKindAPI, time.Now()); ok {
		t.Fatalf("Authenticate = %+v, true for a token another process revoked while its use was being recorded", got)
	}
	if n := len(server.List()); n != 0 {
		t.Errorf("List() = %d tokens after the revoke was met, want 0", n)
	}
}

// TestFindOrCreateOIDCUserDoesNotSignInToAnAccountAnotherProcessDeleted:
// the identity's account is deleted by another process while this
// sign-in's LastLogin bump is being saved. The deleted account must not
// be handed back; the store takes the fresh document and, finding no
// account for the identity, provisions one as a first sign-in would.
func TestFindOrCreateOIDCUserDoesNotSignInToAnAccountAnotherProcessDeleted(t *testing.T) {
	var oldID string
	s, b, other := openRacingStores(t, func(s *Store) {
		now := time.Now()
		if _, err := s.Register("alice", "password123", now); err != nil {
			t.Fatal(err)
		}
		u, _, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "bob", now)
		if err != nil {
			t.Fatal(err)
		}
		oldID = u.ID
	})
	b.beforeSave = func() {
		if _, err := other.DeleteUser(oldID); err != nil {
			t.Errorf("the other process's DeleteUser: %v", err)
		}
	}

	u, created, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "bob", time.Now().Add(2*time.Hour))
	if err != nil {
		t.Fatalf("FindOrCreateOIDCUser across a conflicting delete: %v", err)
	}
	if u.ID == oldID {
		t.Fatal("signed in to the account another process deleted")
	}
	if !created || u.Role != RoleUser {
		t.Errorf("created %v, role %q; want a freshly provisioned ordinary user", created, u.Role)
	}
	if n := reopenAccounts(t, b).Count(); n != 2 {
		t.Errorf("saved document holds %d accounts, want 2 (alice and the new one)", n)
	}
}

// refuseNextSave makes the other process write a document this store
// refuses (two admins) just before this store's next save, so the
// replay is refused outright: the op's first run, against memory, is
// the only one that happened, and its result was never saved.
func refuseNextSave(t *testing.T, b *otherProcessBackend) {
	t.Helper()
	b.beforeSave = func() {
		snap, err := b.Load(context.Background())
		if err != nil {
			t.Error(err)
			return
		}
		// b.Memory, not b: b's own Save is the one that runs this hook.
		if _, err := b.Memory.Save(context.Background(), []byte(twoAdminsDocument), snap.Version); err != nil {
			t.Error(err)
		}
	}
}

// TestVerifyAndRecordTOTPRefusesAMatchItCouldNotRecord: the code
// matches on the op's first run, against memory, and then the replay
// is refused. ok was set true by that first run; it must not come
// back true, since the counter advance it stands for was never saved
// and the same code would win a second login. The handler trusts a
// true ok even with an error (gate/login_handler.go), so the method is
// where this has to hold.
func TestVerifyAndRecordTOTPRefusesAMatchItCouldNotRecord(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	var id string
	s, b, _ := openRacingStores(t, func(s *Store) {
		u, err := s.Register("alice", "password123", now)
		if err != nil {
			t.Fatal(err)
		}
		id = u.ID
		setTOTPForTest(t, s, id, EncodeTOTPSecret(secret), now, 30)
	})
	refuseNextSave(t, b)

	code := GenerateTOTPCode(secret, totpCounter(now, totpStep)+1)
	ok, err := s.VerifyAndRecordTOTP(id, code, now)
	if err == nil {
		t.Fatal("VerifyAndRecordTOTP whose replay was refused = nil error, want one")
	}
	if ok {
		t.Error("VerifyAndRecordTOTP = true from a run that was never saved: the code is still live for a second login")
	}
	s.mu.RLock()
	counter := s.byID[id].TOTPLastCounter
	s.mu.RUnlock()
	if counter != 30 {
		t.Errorf("TOTPLastCounter = %d in memory after a refused write, want the stored 30", counter)
	}
}

// TestRecordPasskeyAssertionIfFreshRefusesAnAssertionItCouldNotRecord
// is the same for the passkey sign count: accepted is only the final,
// saved run's answer.
func TestRecordPasskeyAssertionIfFreshRefusesAnAssertionItCouldNotRecord(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	var id string
	s, b, _ := openRacingStores(t, func(s *Store) {
		u, err := s.Register("alice", "password123", now)
		if err != nil {
			t.Fatal(err)
		}
		id = u.ID
		if _, err := s.AddPasskey(id, testPasskey(1, "keeper")); err != nil {
			t.Fatal(err)
		}
	})
	refuseNextSave(t, b)

	accepted, err := s.RecordPasskeyAssertionIfFresh(id, []byte{1}, 5, now)
	if err == nil {
		t.Fatal("RecordPasskeyAssertionIfFresh whose replay was refused = nil error, want one")
	}
	if accepted {
		t.Error("RecordPasskeyAssertionIfFresh = true from a run that was never saved")
	}
}

// TestAuthenticateRedecidesTheResetCodeOnReplay: bob signs in with an
// admin-issued reset code, and the code checks out against what this
// process holds. Before the spend is saved, bob sets a new password
// through another process, which ends the reset. The replay must find
// the code dead and refuse the login, not spend a code the saved
// document no longer has.
func TestAuthenticateRedecidesTheResetCodeOnReplay(t *testing.T) {
	var bobID string
	var code string
	s, b, other := openRacingStores(t, func(s *Store) {
		now := time.Now()
		if _, err := s.Register("alice", "password123", now); err != nil {
			t.Fatal(err)
		}
		bob, err := s.CreateUser("bob", "password456", RoleUser, now)
		if err != nil {
			t.Fatal(err)
		}
		bobID = bob.ID
		if _, code, err = s.IssueResetCode(bob.ID, now); err != nil {
			t.Fatal(err)
		}
	})
	b.beforeSave = func() {
		if err := other.SetPassword("bob", "brand-new-password", time.Now()); err != nil {
			t.Errorf("the other process's SetPassword: %v", err)
		}
	}

	if _, err := s.Authenticate("bob", code, time.Now()); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Authenticate with a reset code another process ended = %v, want ErrInvalidCredentials", err)
	}
	reopened := reopenAccounts(t, b)
	got, _ := reopened.Get(bobID)
	if got.MustChangePassword || got.ResetCodeHash != "" {
		t.Errorf("bob's saved account is back in a reset (MustChangePassword %v): the replay wrote over the other process's password change", got.MustChangePassword)
	}
	if _, err := reopened.Authenticate("bob", "brand-new-password", time.Now()); err != nil {
		t.Errorf("bob's new password does not work after the replay: %v", err)
	}
}

// TestAuthenticateRefusesAResetCodeReplacedOnReplay: bob signs in with
// an admin-issued reset code that checks out against what this process
// holds. Before the spend is saved, an admin in another process issues
// bob a new code, which replaces the first. The replay finds a live
// code still on the account, but not the one bob typed: it must refuse
// the login and leave the new code unspent, not let the replaced code
// in by spending its successor.
func TestAuthenticateRefusesAResetCodeReplacedOnReplay(t *testing.T) {
	var bobID, code, newCode string
	s, b, other := openRacingStores(t, func(s *Store) {
		now := time.Now()
		if _, err := s.Register("alice", "password123", now); err != nil {
			t.Fatal(err)
		}
		bob, err := s.CreateUser("bob", "password456", RoleUser, now)
		if err != nil {
			t.Fatal(err)
		}
		bobID = bob.ID
		if _, code, err = s.IssueResetCode(bob.ID, now); err != nil {
			t.Fatal(err)
		}
	})
	b.beforeSave = func() {
		var err error
		if _, newCode, err = other.IssueResetCode(bobID, time.Now()); err != nil {
			t.Errorf("the other process's IssueResetCode: %v", err)
		}
	}

	if _, err := s.Authenticate("bob", code, time.Now()); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Authenticate with a reset code another process replaced = %v, want ErrInvalidCredentials", err)
	}
	reopened := reopenAccounts(t, b)
	if _, err := reopened.Authenticate("bob", newCode, time.Now()); err != nil {
		t.Errorf("the replacement code does not work after the replay: %v -- the replaced code spent it", err)
	}
}

// lateWriteBackend is a persist.Memory whose next version check
// answers with the version as it stood, and only then lets afterVersion
// write: a reloadIfStale that read the version just before the CLI's
// write landed, and so did not reload.
type lateWriteBackend struct {
	*persist.Memory
	afterVersion func()
}

func (b *lateWriteBackend) Version(ctx context.Context) (int64, bool, error) {
	v, exists, err := b.Memory.Version(ctx)
	if f := b.afterVersion; f != nil {
		b.afterVersion = nil
		f()
	}
	return v, exists, err
}

// TestRevokeAllCreatedByFindsATokenThisStoreHadNotLoaded: the CLI
// creates a token for bob after this store's staleness check, so memory
// has no token of bob's and the op finds nothing to revoke. That
// decision was made on stale memory; the store must check it against
// the document as it is now and revoke the token, not report (0, nil)
// while it keeps authenticating.
func TestRevokeAllCreatedByFindsATokenThisStoreHadNotLoaded(t *testing.T) {
	m := persist.NewMemory()
	b := &lateWriteBackend{Memory: m}
	server, err := OpenTokenStore(b, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	bob := &User{ID: "bob-id", Username: "bob"}
	var raw string
	b.afterVersion = func() {
		if raw, _, err = cli.Create("bob's", TokenKindAPI, "", bob, time.Now()); err != nil {
			t.Errorf("the CLI's Create: %v", err)
		}
	}

	n, err := server.RevokeAllCreatedBy(bob.ID)
	if err != nil {
		t.Fatalf("RevokeAllCreatedBy: %v", err)
	}
	if n != 1 {
		t.Errorf("RevokeAllCreatedBy = %d, want 1: the CLI's token for bob was missed", n)
	}
	reopened, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Authenticate(raw, TokenKindAPI, time.Now()); ok {
		t.Error("bob's token still authenticates after his tokens were revoked")
	}
}

// TestVerifyAndRecordTOTPRechecksTheCodeOnReplay: the same code is
// submitted to two processes at once. This store matches it against
// memory, but the other process records it first. The replay must
// check the code again against the counter the other process saved and
// refuse it, not let one code win two logins.
func TestVerifyAndRecordTOTPRechecksTheCodeOnReplay(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	var id string
	s, b, other := openRacingStores(t, func(s *Store) {
		u, err := s.Register("alice", "password123", now)
		if err != nil {
			t.Fatal(err)
		}
		id = u.ID
		setTOTPForTest(t, s, id, EncodeTOTPSecret(secret), now, 30)
	})
	code := GenerateTOTPCode(secret, totpCounter(now, totpStep)+1)
	b.beforeSave = func() {
		if ok, err := other.VerifyAndRecordTOTP(id, code, now); err != nil || !ok {
			t.Errorf("the other process's VerifyAndRecordTOTP = %v, %v; want true", ok, err)
		}
	}

	ok, err := s.VerifyAndRecordTOTP(id, code, now)
	if err != nil {
		t.Fatalf("VerifyAndRecordTOTP across a conflicting write: %v", err)
	}
	if ok {
		t.Error("VerifyAndRecordTOTP = true for a code another process had already recorded: one code won two logins")
	}
}

// TestSetPendingTOTPSecretRechecksTheActiveFactorOnReplay: alice starts
// enrolling an authenticator app in this process while, in another,
// she finishes enrolling one. The replay must find the factor now
// active and refuse, not overwrite the confirmed secret with a pending
// one -- which would leave her authenticator producing codes for a
// secret the account no longer holds.
func TestSetPendingTOTPSecretRechecksTheActiveFactorOnReplay(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	var id string
	s, b, other := openRacingStores(t, func(s *Store) {
		u, err := s.Register("alice", "password123", now)
		if err != nil {
			t.Fatal(err)
		}
		id = u.ID
	})
	otherSecret := mustEncodedTOTPSecret(t)
	b.beforeSave = func() {
		if err := other.SetPendingTOTPSecret(id, otherSecret); err != nil {
			t.Errorf("the other process's SetPendingTOTPSecret: %v", err)
		}
		if err := other.ConfirmTOTP(id, now, 1); err != nil {
			t.Errorf("the other process's ConfirmTOTP: %v", err)
		}
	}

	if err := s.SetPendingTOTPSecret(id, mustEncodedTOTPSecret(t)); !errors.Is(err, ErrTOTPAlreadyActive) {
		t.Fatalf("SetPendingTOTPSecret across another process's enrolment = %v, want ErrTOTPAlreadyActive", err)
	}
	got, _ := reopenAccounts(t, b).Get(id)
	if got.TOTPSecret != otherSecret || got.TOTPConfirmedAt.IsZero() {
		t.Errorf("the saved factor is not the one the other process confirmed (confirmed at %v)", got.TOTPConfirmedAt)
	}
}

// TestConfirmTOTPRechecksThePendingSecretOnReplay: the same pending
// secret is confirmed in two processes at once. This one sees it still
// pending, but the other confirms it first. The replay must refuse with
// ErrNoPendingTOTP and keep the other's confirmation, not confirm it a
// second time over the counter that confirmation recorded.
func TestConfirmTOTPRechecksThePendingSecretOnReplay(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	var id string
	s, b, other := openRacingStores(t, func(s *Store) {
		u, err := s.Register("alice", "password123", now)
		if err != nil {
			t.Fatal(err)
		}
		id = u.ID
		if err := s.SetPendingTOTPSecret(id, mustEncodedTOTPSecret(t)); err != nil {
			t.Fatal(err)
		}
	})
	b.beforeSave = func() {
		if err := other.ConfirmTOTP(id, now, 5); err != nil {
			t.Errorf("the other process's ConfirmTOTP: %v", err)
		}
	}

	if err := s.ConfirmTOTP(id, now.Add(time.Second), 3); !errors.Is(err, ErrNoPendingTOTP) {
		t.Fatalf("ConfirmTOTP of a secret another process confirmed first = %v, want ErrNoPendingTOTP", err)
	}
	got, _ := reopenAccounts(t, b).Get(id)
	if !got.TOTPConfirmedAt.Equal(now) || got.TOTPLastCounter != 5 {
		t.Errorf("saved confirmation = %v at counter %d, want the other process's %v at 5", got.TOTPConfirmedAt, got.TOTPLastCounter, now)
	}
}

// mustEncodedTOTPSecret is a fresh secret in the form the store keeps.
func mustEncodedTOTPSecret(t *testing.T) string {
	t.Helper()
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	return EncodeTOTPSecret(secret)
}

// removedAfterVersionBackend is a persist.Memory whose document is gone
// once the store has checked its version: a file moved aside between the
// staleness check and the write.
type removedAfterVersionBackend struct {
	*persist.Memory
	removed bool
}

func (b *removedAfterVersionBackend) Version(ctx context.Context) (int64, bool, error) {
	v, exists, err := b.Memory.Version(ctx)
	b.removed = true
	return v, exists, err
}

func (b *removedAfterVersionBackend) Load(ctx context.Context) (persist.Snapshot, error) {
	if b.removed {
		return persist.Snapshot{}, nil
	}
	return b.Memory.Load(ctx)
}

// TestNothingToChangeAgainstARemovedDocumentIsAnError: the store has a
// saved document, decides a revoke has nothing to do, and then finds the
// document gone when it checks that decision. It cannot know what the
// document held, so it must report the removal rather than (0, nil).
func TestNothingToChangeAgainstARemovedDocumentIsAnError(t *testing.T) {
	m := persist.NewMemory()
	seed, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	alice := &User{ID: "alice-id", Username: "alice"}
	if _, _, err := seed.Create("alice's", TokenKindAPI, "", alice, time.Now()); err != nil {
		t.Fatal(err)
	}
	b := &removedAfterVersionBackend{Memory: m}
	server, err := OpenTokenStore(b, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}

	n, err := server.RevokeAllCreatedBy("bob-id")
	if !errors.Is(err, ErrDocumentRemoved) {
		t.Fatalf("RevokeAllCreatedBy = (%d, %v), want ErrDocumentRemoved: the decision was never checked against a document", n, err)
	}
}

// TestNothingToChangeOnANeverSavedStoreIsFine: a store that has never
// written anything finds no document, and that is not a removal.
func TestNothingToChangeOnANeverSavedStoreIsFine(t *testing.T) {
	server, err := OpenTokenStore(persist.NewMemory(), TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := server.RevokeAllCreatedBy("nobody"); n != 0 || err != nil {
		t.Fatalf("RevokeAllCreatedBy on an empty store = (%d, %v), want (0, nil)", n, err)
	}
}
