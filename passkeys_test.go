// Ported from mikroview's internal/auth/passkeys_test.go. Adapted:
// Open(path)/OpenWithBackend(budget) -> openTestStore(t)/OpenStore(budget,
// Options{}); s.HasActiveTOTP(id) -> Get(id) then .HasActiveTOTP().
// testPasskey lives in testhelpers_test.go, shared with any other file
// that needs a fixture credential.
//
// Dropped, both because this package does not carry mikroview's
// two-step RecordPasskeyAssertion (see passkeys.go's package comment --
// only RecordPasskeyAssertionIfFresh is here):
//   - TestRecordPasskeyAssertionOnlyMovesSignCountForward and
//     TestRecordPasskeyAssertionUnknownCredentialReturnsNotFound,
//     replaced below by the *IfFresh equivalents.
//   - TestConcurrentGetDuringRenameAndAssertionIsRaceFree, which called
//     RecordPasskeyAssertion directly. reload_test.go's
//     TestReloadIfStaleDoesNotRevertAConcurrentWrite already exercises
//     the concurrent-write race this package cares about at the store
//     level; RenamePasskey and RecordPasskeyAssertionIfFresh use the
//     same "replace the whole slice" pattern this proved safe for.
//
// Also dropped: TestAnyPasskeysExist (AnyPasskeysExist is not carried
// over -- see passkeys.go's package comment).
package gauntlet

import (
	"errors"
	"testing"
	"time"
)

func TestAddPasskeyNormalisesAnEmptyNameToANumberedDefault(t *testing.T) {
	s := openTestStore(t)
	u, err := s.Register("admin", "password123", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.AddPasskey(u.ID, testPasskey(1, ""))
	if err != nil {
		t.Fatalf("AddPasskey: %v", err)
	}
	if got.Name != "Passkey 1" {
		t.Errorf("Name = %q, want %q", got.Name, "Passkey 1")
	}

	got2, err := s.AddPasskey(u.ID, testPasskey(2, "  "))
	if err != nil {
		t.Fatalf("AddPasskey (second): %v", err)
	}
	if got2.Name != "Passkey 2" {
		t.Errorf("Name = %q, want %q", got2.Name, "Passkey 2")
	}

	stored, ok := s.Get(u.ID)
	if !ok || len(stored.Passkeys) != 2 {
		t.Fatalf("expected 2 stored passkeys, got %+v", stored)
	}
}

func TestAddPasskeyTrimsAndBoundsAGivenName(t *testing.T) {
	s := openTestStore(t)
	u, err := s.Register("admin", "password123", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	pk := testPasskey(1, "  YubiKey  ")
	got, err := s.AddPasskey(u.ID, pk)
	if err != nil {
		t.Fatalf("AddPasskey: %v", err)
	}
	if got.Name != "YubiKey" {
		t.Errorf("Name = %q, want trimmed %q", got.Name, "YubiKey")
	}

	long := make([]rune, maxPasskeyNameLength+40)
	for i := range long {
		long[i] = 'x'
	}
	pk2 := testPasskey(2, string(long))
	got2, err := s.AddPasskey(u.ID, pk2)
	if err != nil {
		t.Fatalf("AddPasskey (long name): %v", err)
	}
	if len(got2.Name) != maxPasskeyNameLength {
		t.Errorf("Name length = %d, want %d", len(got2.Name), maxPasskeyNameLength)
	}
}

func TestAddPasskeyRefusesADuplicateCredentialID(t *testing.T) {
	s := openTestStore(t)
	u, err := s.Register("admin", "password123", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(u.ID, testPasskey(9, "first")); err != nil {
		t.Fatalf("AddPasskey: %v", err)
	}

	if _, err := s.AddPasskey(u.ID, testPasskey(9, "second")); !errors.Is(err, ErrPasskeyDuplicate) {
		t.Errorf("AddPasskey with a duplicate credential ID = %v, want %v", err, ErrPasskeyDuplicate)
	}
	stored, _ := s.Get(u.ID)
	if len(stored.Passkeys) != 1 {
		t.Errorf("a duplicate add changed the stored count to %d, want 1", len(stored.Passkeys))
	}
}

func TestAddPasskeyRefusesAnEleventhCredential(t *testing.T) {
	s := openTestStore(t)
	u, err := s.Register("admin", "password123", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxPasskeysPerAccount; i++ {
		if _, err := s.AddPasskey(u.ID, testPasskey(byte(i), "")); err != nil {
			t.Fatalf("AddPasskey #%d: %v", i, err)
		}
	}

	if _, err := s.AddPasskey(u.ID, testPasskey(200, "eleventh")); !errors.Is(err, ErrPasskeyLimitReached) {
		t.Errorf("AddPasskey past the cap = %v, want %v", err, ErrPasskeyLimitReached)
	}
	stored, _ := s.Get(u.ID)
	if len(stored.Passkeys) != maxPasskeysPerAccount {
		t.Errorf("stored count after refusal = %d, want %d", len(stored.Passkeys), maxPasskeysPerAccount)
	}
}

// TestAddPasskeyAtTheLimitReportsADuplicateAsDuplicate pins current
// behaviour where both refusals apply: an account already at
// maxPasskeysPerAccount is shown one of its own credentials again.
// AddPasskey checks the duplicate first (its doc comment says so), so
// the caller hears "already registered", not "remove one first" --
// advice that would be wrong for a key the account already holds.
func TestAddPasskeyAtTheLimitReportsADuplicateAsDuplicate(t *testing.T) {
	s := openTestStore(t)
	u, err := s.Register("admin", "password123", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxPasskeysPerAccount; i++ {
		if _, err := s.AddPasskey(u.ID, testPasskey(byte(i), "")); err != nil {
			t.Fatalf("AddPasskey #%d: %v", i, err)
		}
	}

	_, err = s.AddPasskey(u.ID, testPasskey(3, "again"))
	if !errors.Is(err, ErrPasskeyDuplicate) {
		t.Errorf("AddPasskey of a held credential at the limit = %v, want %v", err, ErrPasskeyDuplicate)
	}
	if errors.Is(err, ErrPasskeyLimitReached) {
		t.Errorf("AddPasskey of a held credential at the limit also matched %v", ErrPasskeyLimitReached)
	}
	stored, _ := s.Get(u.ID)
	if len(stored.Passkeys) != maxPasskeysPerAccount {
		t.Errorf("stored count after refusal = %d, want %d", len(stored.Passkeys), maxPasskeysPerAccount)
	}
}

func TestAddPasskeyUnknownUserReturnsNotFound(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.AddPasskey("no-such-user", testPasskey(1, "")); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("AddPasskey on an unknown user = %v, want %v", err, ErrUserNotFound)
	}
}

func TestAddPasskeyRefusesWhenNotPersisted(t *testing.T) {
	s, err := OpenStore(nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey("whoever", testPasskey(1, "")); !errors.Is(err, ErrNotPersisted) {
		t.Errorf("AddPasskey on an unpersisted store = %v, want %v", err, ErrNotPersisted)
	}
}

func TestRenamePasskeyChangesTheStoredName(t *testing.T) {
	s := openTestStore(t)
	u, err := s.Register("admin", "password123", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(u.ID, testPasskey(1, "original")); err != nil {
		t.Fatal(err)
	}

	got, err := s.RenamePasskey(u.ID, []byte{1}, "  renamed  ")
	if err != nil {
		t.Fatalf("RenamePasskey: %v", err)
	}
	if got.Name != "renamed" {
		t.Errorf("Name = %q, want %q", got.Name, "renamed")
	}
	stored, _ := s.Get(u.ID)
	if stored.Passkeys[0].Name != "renamed" {
		t.Errorf("stored Name = %q, want %q", stored.Passkeys[0].Name, "renamed")
	}
}

func TestRenamePasskeyUnknownCredentialReturnsNotFound(t *testing.T) {
	s := openTestStore(t)
	u, err := s.Register("admin", "password123", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RenamePasskey(u.ID, []byte{99}, "x"); !errors.Is(err, ErrPasskeyNotFound) {
		t.Errorf("RenamePasskey on an unknown credential = %v, want %v", err, ErrPasskeyNotFound)
	}
}

// TestDeletePasskeyKeepsRecoveryCodesWhileAnotherFactorRemains and
// TestDeletePasskeyClearsRecoveryCodesWhenItWasTheLastFactor are the two
// halves of the shared-recovery-codes clear-conditional rule -- the
// exact pair of tests a careless "always clear" or "never clear"
// implementation would still pass one of.
func TestDeletePasskeyKeepsRecoveryCodesWhileAnotherFactorRemains(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password123", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(u.ID, testPasskey(1, "one")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(u.ID, testPasskey(2, "two")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GenerateRecoveryCodes(u.ID, now); err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}

	if _, err := s.DeletePasskey(u.ID, []byte{1}); err != nil {
		t.Fatalf("DeletePasskey: %v", err)
	}
	got, _ := s.Get(u.ID)
	if len(got.Passkeys) != 1 {
		t.Errorf("passkey count after delete = %d, want 1", len(got.Passkeys))
	}
	if len(got.RecoveryCodes) != 10 {
		t.Errorf("recovery codes after deleting one of two passkeys = %d, want 10 (kept)", len(got.RecoveryCodes))
	}
}

func TestDeletePasskeyClearsRecoveryCodesWhenItWasTheLastFactor(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password123", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(u.ID, testPasskey(1, "only")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GenerateRecoveryCodes(u.ID, now); err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}

	if _, err := s.DeletePasskey(u.ID, []byte{1}); err != nil {
		t.Fatalf("DeletePasskey: %v", err)
	}
	got, _ := s.Get(u.ID)
	if len(got.Passkeys) != 0 {
		t.Errorf("passkey count after deleting the only one = %d, want 0", len(got.Passkeys))
	}
	if len(got.RecoveryCodes) != 0 {
		t.Errorf("recovery codes after deleting the last factor = %d, want 0 (cleared)", len(got.RecoveryCodes))
	}
}

// TestDeletePasskeyWithActiveTOTPKeepsRecoveryCodes covers the same rule
// from ClearTOTP's ledger: TOTP is still active, so removing the only
// passkey does not clear the codes it also backs.
func TestDeletePasskeyWithActiveTOTPKeepsRecoveryCodes(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password123", now)
	if err != nil {
		t.Fatal(err)
	}
	setTOTPForTest(t, s, u.ID, "JBSWY3DPEHPK3PXP", now, 1)
	if _, err := s.AddPasskey(u.ID, testPasskey(1, "only")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GenerateRecoveryCodes(u.ID, now); err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}

	if _, err := s.DeletePasskey(u.ID, []byte{1}); err != nil {
		t.Fatalf("DeletePasskey: %v", err)
	}
	got, _ := s.Get(u.ID)
	if len(got.RecoveryCodes) != 10 {
		t.Errorf("recovery codes after removing the only passkey while TOTP stays active = %d, want 10 (kept)", len(got.RecoveryCodes))
	}
}

func TestDeletePasskeyUnknownCredentialReturnsNotFound(t *testing.T) {
	s := openTestStore(t)
	u, err := s.Register("admin", "password123", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeletePasskey(u.ID, []byte{99}); !errors.Is(err, ErrPasskeyNotFound) {
		t.Errorf("DeletePasskey on an unknown credential = %v, want %v", err, ErrPasskeyNotFound)
	}
}

// TestClearTOTPKeepsRecoveryCodesWhileAPasskeyRemains pins the rule
// ClearTOTP documents: with a passkey still active, dropping the codes
// here would orphan that passkey's own fallback.
func TestClearTOTPKeepsRecoveryCodesWhileAPasskeyRemains(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password123", now)
	if err != nil {
		t.Fatal(err)
	}
	setTOTPForTest(t, s, u.ID, "JBSWY3DPEHPK3PXP", now, 1)
	if _, err := s.AddPasskey(u.ID, testPasskey(1, "backup key")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GenerateRecoveryCodes(u.ID, now); err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}

	if err := s.ClearTOTP(u.ID); err != nil {
		t.Fatalf("ClearTOTP: %v", err)
	}
	got, _ := s.Get(u.ID)
	if got.HasActiveTOTP() {
		t.Error("ClearTOTP left the authenticator-app factor active")
	}
	if len(got.RecoveryCodes) != 10 {
		t.Errorf("recovery codes after ClearTOTP with a passkey still active = %d, want 10 (kept)", len(got.RecoveryCodes))
	}
}

// TestClearTOTPWithNoPasskeysStillClearsRecoveryCodes pins the case
// where no passkey ever existed, so clearing TOTP is clearing the
// account's last factor.
func TestClearTOTPWithNoPasskeysStillClearsRecoveryCodes(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password123", now)
	if err != nil {
		t.Fatal(err)
	}
	setTOTPForTest(t, s, u.ID, "JBSWY3DPEHPK3PXP", now, 1)
	if _, err := s.GenerateRecoveryCodes(u.ID, now); err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}

	if err := s.ClearTOTP(u.ID); err != nil {
		t.Fatalf("ClearTOTP: %v", err)
	}
	got, _ := s.Get(u.ID)
	if len(got.RecoveryCodes) != 0 {
		t.Errorf("recovery codes after ClearTOTP with no passkeys = %d, want 0 (cleared)", len(got.RecoveryCodes))
	}
}

func TestClearPasskeysRemovesAllAndAppliesTheSameConditionalRule(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password123", now)
	if err != nil {
		t.Fatal(err)
	}
	setTOTPForTest(t, s, u.ID, "JBSWY3DPEHPK3PXP", now, 1)
	if _, err := s.AddPasskey(u.ID, testPasskey(1, "one")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(u.ID, testPasskey(2, "two")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GenerateRecoveryCodes(u.ID, now); err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}

	if err := s.ClearPasskeys(u.ID); err != nil {
		t.Fatalf("ClearPasskeys: %v", err)
	}
	got, _ := s.Get(u.ID)
	if len(got.Passkeys) != 0 {
		t.Errorf("passkeys after ClearPasskeys = %d, want 0", len(got.Passkeys))
	}
	// TOTP is still active, so the shared codes must survive.
	if len(got.RecoveryCodes) != 10 {
		t.Errorf("recovery codes after ClearPasskeys with TOTP still active = %d, want 10 (kept)", len(got.RecoveryCodes))
	}

	if err := s.ClearTOTP(u.ID); err != nil {
		t.Fatalf("ClearTOTP: %v", err)
	}
	got, _ = s.Get(u.ID)
	if len(got.RecoveryCodes) != 0 {
		t.Errorf("recovery codes after clearing the last remaining factor = %d, want 0", len(got.RecoveryCodes))
	}
}

func TestClearPasskeysUnknownUserReturnsNotFound(t *testing.T) {
	s := openTestStore(t)
	if err := s.ClearPasskeys("no-such-user"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("ClearPasskeys on an unknown user = %v, want %v", err, ErrUserNotFound)
	}
}

// TestClearAllSecondFactorsClearsEverythingUnconditionally is the
// "I've lost everything" path: unlike ClearTOTP/DeletePasskey/
// ClearPasskeys, there is no factor-remaining case to keep codes for --
// everything goes together.
func TestClearAllSecondFactorsClearsEverythingUnconditionally(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password123", now)
	if err != nil {
		t.Fatal(err)
	}
	setTOTPForTest(t, s, u.ID, "JBSWY3DPEHPK3PXP", now, 1)
	if _, err := s.AddPasskey(u.ID, testPasskey(1, "one")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(u.ID, testPasskey(2, "two")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GenerateRecoveryCodes(u.ID, now); err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if active, _ := s.Get(u.ID); !active.HasActiveTOTP() {
		t.Fatal("test setup: expected an active TOTP factor")
	}

	if err := s.ClearAllSecondFactors(u.ID); err != nil {
		t.Fatalf("ClearAllSecondFactors: %v", err)
	}
	got, _ := s.Get(u.ID)
	if got.HasActiveTOTP() {
		t.Error("ClearAllSecondFactors left TOTP active")
	}
	if len(got.Passkeys) != 0 {
		t.Errorf("passkeys after ClearAllSecondFactors = %d, want 0", len(got.Passkeys))
	}
	if len(got.RecoveryCodes) != 0 {
		t.Errorf("recovery codes after ClearAllSecondFactors = %d, want 0", len(got.RecoveryCodes))
	}
	if got.HasSecondFactor() {
		t.Error("HasSecondFactor is still true after ClearAllSecondFactors")
	}
}

func TestClearAllSecondFactorsUnknownUserReturnsNotFound(t *testing.T) {
	s := openTestStore(t)
	if err := s.ClearAllSecondFactors("no-such-user"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("ClearAllSecondFactors on an unknown user = %v, want %v", err, ErrUserNotFound)
	}
}

// TestRecordPasskeyAssertionIfFreshAcceptsAndAdvances mirrors
// TestVerifyAndRecordTOTPAcceptsOnceThenRefusesReplay's shape for the
// passkey side: a fresh, nonzero count is accepted and advances the
// guard; the same count again is refused; LastUsedAt still moves for a
// count-0 authenticator.
func TestRecordPasskeyAssertionIfFreshAcceptsAndAdvances(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password123", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(u.ID, testPasskey(1, "")); err != nil {
		t.Fatal(err)
	}

	accepted, err := s.RecordPasskeyAssertionIfFresh(u.ID, []byte{1}, 5, now)
	if err != nil || !accepted {
		t.Fatalf("first assertion: accepted=%v err=%v, want true, nil", accepted, err)
	}
	got, _ := s.Get(u.ID)
	if got.Passkeys[0].SignCount != 5 {
		t.Fatalf("SignCount = %d after first assertion, want 5", got.Passkeys[0].SignCount)
	}

	later := now.Add(time.Hour)
	if accepted, err := s.RecordPasskeyAssertionIfFresh(u.ID, []byte{1}, 5, later); err != nil || accepted {
		t.Errorf("replaying signCount 5: accepted=%v err=%v, want false, nil -- a stale, nonzero count is a possible clone", accepted, err)
	}
	if accepted, err := s.RecordPasskeyAssertionIfFresh(u.ID, []byte{1}, 3, later); err != nil || accepted {
		t.Errorf("signCount 3 after 5: accepted=%v err=%v, want false, nil", accepted, err)
	}
	got, _ = s.Get(u.ID)
	if got.Passkeys[0].SignCount != 5 {
		t.Fatalf("a refused assertion wound SignCount back to %d", got.Passkeys[0].SignCount)
	}
	if !got.Passkeys[0].LastUsedAt.Equal(now) {
		t.Errorf("LastUsedAt moved on a refused assertion: %v, want unchanged at %v", got.Passkeys[0].LastUsedAt, now)
	}

	// Zero is exempt from the regression check -- an authenticator that
	// always reports 0 must still be able to log in.
	if accepted, err := s.RecordPasskeyAssertionIfFresh(u.ID, []byte{1}, 0, later); err != nil || !accepted {
		t.Fatalf("signCount 0: accepted=%v err=%v, want true, nil", accepted, err)
	}
	got, _ = s.Get(u.ID)
	if got.Passkeys[0].SignCount != 5 {
		t.Errorf("a count-0 assertion changed SignCount to %d, want it left at 5", got.Passkeys[0].SignCount)
	}
	if !got.Passkeys[0].LastUsedAt.Equal(later) {
		t.Errorf("LastUsedAt after a count-0 assertion = %v, want %v", got.Passkeys[0].LastUsedAt, later)
	}
}

func TestRecordPasskeyAssertionIfFreshUnknownCredentialReturnsNotFound(t *testing.T) {
	s := openTestStore(t)
	u, err := s.Register("admin", "password123", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordPasskeyAssertionIfFresh(u.ID, []byte{99}, 1, time.Now()); !errors.Is(err, ErrPasskeyNotFound) {
		t.Errorf("RecordPasskeyAssertionIfFresh on an unknown credential = %v, want %v", err, ErrPasskeyNotFound)
	}
}

func TestHasSecondFactorCoversEveryCombination(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password123", now)
	if err != nil {
		t.Fatal(err)
	}

	got, _ := s.Get(u.ID)
	if got.HasSecondFactor() {
		t.Error("a freshly registered account reports a second factor it doesn't have")
	}

	setTOTPForTest(t, s, u.ID, "JBSWY3DPEHPK3PXP", now, 1)
	got, _ = s.Get(u.ID)
	if !got.HasSecondFactor() {
		t.Error("an active TOTP factor is not reported by HasSecondFactor")
	}

	if err := s.ClearTOTP(u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(u.ID, testPasskey(1, "")); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Get(u.ID)
	if !got.HasSecondFactor() {
		t.Error("a passkey alone is not reported by HasSecondFactor")
	}

	setTOTPForTest(t, s, u.ID, "JBSWY3DPEHPK3PXP", now, 1)
	got, _ = s.Get(u.ID)
	if !got.HasSecondFactor() {
		t.Error("TOTP and a passkey together are not reported by HasSecondFactor")
	}
}

// TestListBlanksPasskeysAndPasskeyCountReadsTheLiveData is the trap
// PasskeyCount exists to avoid: a naive len() on List()'s output would
// read zero for every account, because List() blanks Passkeys the same
// way it blanks TOTPSecret.
func TestListBlanksPasskeysAndPasskeyCountReadsTheLiveData(t *testing.T) {
	s := openTestStore(t)
	u, err := s.Register("admin", "password123", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(u.ID, testPasskey(1, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(u.ID, testPasskey(2, "")); err != nil {
		t.Fatal(err)
	}

	list := s.List()
	if len(list) != 1 {
		t.Fatalf("List() returned %d users, want 1", len(list))
	}
	if list[0].Passkeys != nil {
		t.Errorf("List()'s copy carries Passkeys (%v), want it blanked to nil", list[0].Passkeys)
	}

	if got := s.PasskeyCount(u.ID); got != 2 {
		t.Errorf("PasskeyCount = %d, want 2 -- it must read live data, not a List() copy", got)
	}
	if got := s.PasskeyCount("no-such-user"); got != 0 {
		t.Errorf("PasskeyCount for an unknown user = %d, want 0", got)
	}
}

// TestPasskeyWritesLeaveStateWhenPersistFails holds every write in this
// file to the restore-on-persist-failure contract: a change that cannot
// be durably saved must not be reported as done, and must not leave
// memory ahead of disk.
func TestPasskeyWritesLeaveStateWhenPersistFails(t *testing.T) {
	budget := &saveBudgetBackend{left: 1}
	s, err := OpenStore(budget, Options{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password123", now)
	if err != nil {
		t.Fatal(err)
	}

	budget.left = 1
	if _, err := s.AddPasskey(u.ID, testPasskey(1, "keeper")); err != nil {
		t.Fatalf("AddPasskey (fixture): %v", err)
	}
	budget.left = 1
	if _, err := s.GenerateRecoveryCodes(u.ID, now); err != nil {
		t.Fatalf("GenerateRecoveryCodes (fixture): %v", err)
	}

	budget.left = 0
	if _, err := s.AddPasskey(u.ID, testPasskey(2, "should not stick")); err == nil {
		t.Fatal("AddPasskey against a backend that cannot save = nil error, want one")
	}
	if got, _ := s.Get(u.ID); len(got.Passkeys) != 1 {
		t.Errorf("AddPasskey's in-memory state changed even though the write failed: %d passkeys, want 1", len(got.Passkeys))
	}

	if _, err := s.RenamePasskey(u.ID, []byte{1}, "renamed"); err == nil {
		t.Fatal("RenamePasskey against a backend that cannot save = nil error, want one")
	}
	if got, _ := s.Get(u.ID); got.Passkeys[0].Name != "keeper" {
		t.Errorf("RenamePasskey's in-memory state changed even though the write failed: Name = %q", got.Passkeys[0].Name)
	}

	if accepted, err := s.RecordPasskeyAssertionIfFresh(u.ID, []byte{1}, 99, now.Add(time.Hour)); err == nil {
		t.Fatal("RecordPasskeyAssertionIfFresh against a backend that cannot save = nil error, want one")
	} else if accepted {
		t.Error("RecordPasskeyAssertionIfFresh reported the assertion as accepted, even though its record was never saved -- see VerifyAndRecordTOTP's contract")
	}
	if got, _ := s.Get(u.ID); got.Passkeys[0].SignCount != 0 || !got.Passkeys[0].LastUsedAt.IsZero() {
		t.Errorf("RecordPasskeyAssertionIfFresh's in-memory state changed even though the write failed: %+v", got.Passkeys[0])
	}

	if _, err := s.DeletePasskey(u.ID, []byte{1}); err == nil {
		t.Fatal("DeletePasskey against a backend that cannot save = nil error, want one")
	}
	if got, _ := s.Get(u.ID); len(got.Passkeys) != 1 || len(got.RecoveryCodes) != 10 {
		t.Errorf("DeletePasskey's in-memory state changed even though the write failed: %d passkeys, %d codes", len(got.Passkeys), len(got.RecoveryCodes))
	}

	if err := s.ClearPasskeys(u.ID); err == nil {
		t.Fatal("ClearPasskeys against a backend that cannot save = nil error, want one")
	}
	if got, _ := s.Get(u.ID); len(got.Passkeys) != 1 || len(got.RecoveryCodes) != 10 {
		t.Errorf("ClearPasskeys' in-memory state changed even though the write failed: %d passkeys, %d codes", len(got.Passkeys), len(got.RecoveryCodes))
	}

	if err := s.ClearAllSecondFactors(u.ID); err == nil {
		t.Fatal("ClearAllSecondFactors against a backend that cannot save = nil error, want one")
	}
	if got, _ := s.Get(u.ID); len(got.Passkeys) != 1 || len(got.RecoveryCodes) != 10 {
		t.Errorf("ClearAllSecondFactors' in-memory state changed even though the write failed: %d passkeys, %d codes", len(got.Passkeys), len(got.RecoveryCodes))
	}
}
