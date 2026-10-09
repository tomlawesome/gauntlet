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
package gauntlet

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

func TestAddPasskeyNormalisesAnEmptyNameToANumberedDefault(t *testing.T) {
	s := openTestStore(t)
	u, err := s.Register("admin", "password-placeholder-1", time.Now())
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
	u, err := s.Register("admin", "password-placeholder-1", time.Now())
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
	u, err := s.Register("admin", "password-placeholder-1", time.Now())
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
	u, err := s.Register("admin", "password-placeholder-1", time.Now())
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
	u, err := s.Register("admin", "password-placeholder-1", time.Now())
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

// TestAddPasskeyKeepsNoSliceTheCallerHolds: the stored credential
// shares no slice with the value passed in or the value handed back, so
// a caller reusing either buffer cannot change the stored passkey.
func TestAddPasskeyKeepsNoSliceTheCallerHolds(t *testing.T) {
	s := openTestStore(t)
	u, err := s.Register("admin", "password-placeholder-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	in := testPasskey(1, "")
	got, err := s.AddPasskey(u.ID, in)
	if err != nil {
		t.Fatalf("AddPasskey: %v", err)
	}
	want := testPasskey(1, "")

	in.ID[0], in.PublicKey[0], in.Transports[0] = 9, 9, "usb"
	stored, _ := s.Get(u.ID)
	pk := stored.Passkeys[0]
	if !bytes.Equal(pk.ID, want.ID) || !bytes.Equal(pk.PublicKey, want.PublicKey) || pk.Transports[0] != "internal" {
		t.Errorf("changing the passed-in passkey changed the stored one: %+v", pk)
	}

	got.ID[0], got.PublicKey[0], got.Transports[0] = 8, 8, "nfc"
	stored, _ = s.Get(u.ID)
	pk = stored.Passkeys[0]
	if !bytes.Equal(pk.ID, want.ID) || !bytes.Equal(pk.PublicKey, want.PublicKey) || pk.Transports[0] != "internal" {
		t.Errorf("changing the returned passkey changed the stored one: %+v", pk)
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
	u, err := s.Register("admin", "password-placeholder-1", time.Now())
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
	u, err := s.Register("admin", "password-placeholder-1", time.Now())
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
	u, err := s.Register("admin", "password-placeholder-1", now)
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
	u, err := s.Register("admin", "password-placeholder-1", now)
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
	u, err := s.Register("admin", "password-placeholder-1", now)
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
	u, err := s.Register("admin", "password-placeholder-1", time.Now())
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
	u, err := s.Register("admin", "password-placeholder-1", now)
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
	u, err := s.Register("admin", "password-placeholder-1", now)
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
	u, err := s.Register("admin", "password-placeholder-1", now)
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

// TestClearPasskeysWithNothingToClearWritesNothing: an account with no
// passkeys answers ErrNoPasskeys, and the store makes no write -- the
// backend here has no saves left, so a write would fail instead.
func TestClearPasskeysWithNothingToClearWritesNothing(t *testing.T) {
	budget := &saveBudgetBackend{left: 1}
	s, err := OpenStore(budget, Options{})
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.Register("admin", "password-placeholder-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ClearPasskeys(u.ID); !errors.Is(err, ErrNoPasskeys) {
		t.Errorf("ClearPasskeys with no passkeys = %v, want %v", err, ErrNoPasskeys)
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
	u, err := s.Register("admin", "password-placeholder-1", now)
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
	u, err := s.Register("admin", "password-placeholder-1", now)
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

	// A passkey that has counted and now reports 0 is refused too: the
	// WebAuthn spec treats a counter going back to 0 as a possible
	// cloned authenticator (#36).
	if accepted, err := s.RecordPasskeyAssertionIfFresh(u.ID, []byte{1}, 0, later); err != nil || accepted {
		t.Errorf("signCount 0 after 5: accepted=%v err=%v, want false, nil", accepted, err)
	}
	got, _ = s.Get(u.ID)
	if got.Passkeys[0].SignCount != 5 || !got.Passkeys[0].LastUsedAt.Equal(now) {
		t.Errorf("a refused count-0 assertion changed the passkey: %+v", got.Passkeys[0])
	}
}

// TestRecordPasskeyAssertionIfFreshAcceptsAPasskeyThatNeverCounts: an
// authenticator that always reports 0 (most platform passkeys) logs in
// every time, and each login moves LastUsedAt.
func TestRecordPasskeyAssertionIfFreshAcceptsAPasskeyThatNeverCounts(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password-placeholder-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(u.ID, testPasskey(1, "")); err != nil {
		t.Fatal(err)
	}
	for i, at := range []time.Time{now, now.Add(time.Hour)} {
		if accepted, err := s.RecordPasskeyAssertionIfFresh(u.ID, []byte{1}, 0, at); err != nil || !accepted {
			t.Fatalf("count-0 login %d: accepted=%v err=%v, want true, nil", i+1, accepted, err)
		}
		got, _ := s.Get(u.ID)
		if got.Passkeys[0].SignCount != 0 || !got.Passkeys[0].LastUsedAt.Equal(at) {
			t.Errorf("after count-0 login %d: %+v, want SignCount 0 and LastUsedAt %v", i+1, got.Passkeys[0], at)
		}
	}
}

// TestRecordPasskeyAssertionIfFreshWhileStorageFails (#36): with every
// save failing, a passkey that has never counted and presents 0 is let
// in, its LastUsedAt kept in memory and the failed save logged -- that
// save protects nothing, as LastLogin's does not for a password login.
// A count that has to be saved to refuse the next replay (0 -> 5,
// 5 -> 6) is still refused with the error.
func TestRecordPasskeyAssertionIfFreshWhileStorageFails(t *testing.T) {
	var logs bytes.Buffer
	budget := &saveBudgetBackend{left: 1}
	s, err := OpenStore(budget, Options{Log: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password-placeholder-1", now)
	if err != nil {
		t.Fatal(err)
	}
	budget.left = 2
	if _, err := s.AddPasskey(u.ID, testPasskey(1, "never counts")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(u.ID, testPasskey(2, "counts")); err != nil {
		t.Fatal(err)
	}
	budget.left = 1
	if accepted, err := s.RecordPasskeyAssertionIfFresh(u.ID, []byte{2}, 5, now); err != nil || !accepted {
		t.Fatalf("fixture: count 5 on the counting passkey: accepted=%v err=%v", accepted, err)
	}
	budget.left = 0
	later := now.Add(time.Hour)

	// 0 -> 0: accepted, kept in memory, logged.
	accepted, err := s.RecordPasskeyAssertionIfFresh(u.ID, []byte{1}, 0, later)
	if err != nil || !accepted {
		t.Fatalf("0 -> 0 while saves fail: accepted=%v err=%v, want true, nil", accepted, err)
	}
	if got, _ := s.Get(u.ID); !got.Passkeys[0].LastUsedAt.Equal(later) {
		t.Errorf("0 -> 0 while saves fail: LastUsedAt = %v in memory, want %v", got.Passkeys[0].LastUsedAt, later)
	}
	if !strings.Contains(logs.String(), "only in memory") {
		t.Errorf("0 -> 0 whose save failed was not logged; log = %q", logs.String())
	}

	// 0 -> 5 and 5 -> 6: refused with the error, nothing changed.
	cases := []struct {
		cred  byte
		count uint32
		want  uint32
	}{{1, 5, 0}, {2, 6, 5}}
	for _, c := range cases {
		accepted, err := s.RecordPasskeyAssertionIfFresh(u.ID, []byte{c.cred}, c.count, later)
		if err == nil || accepted {
			t.Errorf("%d -> %d while saves fail: accepted=%v err=%v, want false and an error", c.want, c.count, accepted, err)
		}
		if got, _ := s.Get(u.ID); got.Passkeys[c.cred-1].SignCount != c.want {
			t.Errorf("%d -> %d while saves fail: SignCount = %d in memory, want %d", c.want, c.count, got.Passkeys[c.cred-1].SignCount, c.want)
		}
	}
}

func TestRecordPasskeyAssertionIfFreshUnknownCredentialReturnsNotFound(t *testing.T) {
	s := openTestStore(t)
	u, err := s.Register("admin", "password-placeholder-1", time.Now())
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
	u, err := s.Register("admin", "password-placeholder-1", now)
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
	u, err := s.Register("admin", "password-placeholder-1", time.Now())
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

// TestUserPasskeyCountReadsTrueOnAListCopy is gauntlet #42's guard: an
// admin-facing accounts list reads User.PasskeyCount off each List()
// entry instead of calling Store.PasskeyCount per account, so
// User.PasskeyCount itself must answer truly on a blanked copy -- for
// zero, one and two passkeys -- and HasSecondFactor must keep doing so
// too, the same trap TestListBlanksPasskeysAndPasskeyCountReadsTheLiveData
// covers for the Store method.
func TestUserPasskeyCountReadsTrueOnAListCopy(t *testing.T) {
	s := openTestStore(t)

	none, err := s.Register("admin", "password-placeholder-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	one, err := s.CreateUser("one", "password456", RoleUser, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(one.ID, testPasskey(1, "")); err != nil {
		t.Fatal(err)
	}
	two, err := s.CreateUser("two", "password789", RoleUser, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(two.ID, testPasskey(2, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(two.ID, testPasskey(3, "")); err != nil {
		t.Fatal(err)
	}

	byID := make(map[string]User)
	for _, u := range s.List() {
		byID[u.ID] = u
	}

	cases := []struct {
		name string
		id   string
		want int
	}{
		{"no passkeys", none.ID, 0},
		{"one passkey", one.ID, 1},
		{"two passkeys", two.ID, 2},
	}
	for _, c := range cases {
		cp, ok := byID[c.id]
		if !ok {
			t.Fatalf("%s: List() did not return this account", c.name)
		}
		if cp.Passkeys != nil {
			t.Errorf("%s: List()'s copy carries Passkeys (%v), want it blanked to nil", c.name, cp.Passkeys)
		}
		if got := cp.PasskeyCount(); got != c.want {
			t.Errorf("%s: PasskeyCount() on the List() copy = %d, want %d", c.name, got, c.want)
		}
		wantSecondFactor := c.want > 0
		if got := cp.HasSecondFactor(); got != wantSecondFactor {
			t.Errorf("%s: HasSecondFactor() on the List() copy = %v, want %v", c.name, got, wantSecondFactor)
		}
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
	u, err := s.Register("admin", "password-placeholder-1", now)
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

// TestAnyPasskeysExist is ported from mikroview's test of the same name:
// false on a fresh store and on an account whose only factor is TOTP,
// true once any account holds a passkey, false again once the last one
// is removed.
func TestAnyPasskeysExist(t *testing.T) {
	s := openTestStore(t)
	if s.AnyPasskeysExist() {
		t.Error("a fresh store reports a passkey that doesn't exist")
	}

	admin, err := s.Register("admin", "password-placeholder-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	setTOTPForTest(t, s, admin.ID, "JBSWY3DPEHPK3PXP", time.Now(), 1)
	if s.AnyPasskeysExist() {
		t.Error("an account with a TOTP factor but no passkey reports one existing")
	}

	other, err := s.CreateUser("bilbo", "password-placeholder-1", RoleUser, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(other.ID, testPasskey(1, "")); err != nil {
		t.Fatal(err)
	}
	if !s.AnyPasskeysExist() {
		t.Error("an account holding a passkey must make AnyPasskeysExist true")
	}

	if _, err := s.DeletePasskey(other.ID, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if s.AnyPasskeysExist() {
		t.Error("AnyPasskeysExist should go false again once the only passkey is removed")
	}
}

// TestAnyPasskeysExistReadsAnotherProcessesWrite: a passkey added by a
// second store on the same backend -- another process -- is seen
// without a restart, as every read on the store sees such writes.
func TestAnyPasskeysExistReadsAnotherProcessesWrite(t *testing.T) {
	m := persist.NewMemory()
	server, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	u, err := server.Register("admin", "password-placeholder-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if server.AnyPasskeysExist() {
		t.Fatal("a fresh account reports a passkey")
	}
	other, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.AddPasskey(u.ID, testPasskey(1, "added elsewhere")); err != nil {
		t.Fatal(err)
	}
	if !server.AnyPasskeysExist() {
		t.Error("the running store did not see a passkey another process added")
	}
}

// An account with nothing to clear is told so, and nothing is written:
// a caller (an "I've lost everything" CLI) must not report every second
// factor removed, or audit a removal, when there was none (#80), as
// ClearPasskeys answers ErrNoPasskeys.
func TestClearAllSecondFactorsWithNothingToClear(t *testing.T) {
	b := &countingBackend{Memory: persist.NewMemory()}
	s, id := openLockoutStore(t, b)
	before := b.saves.Load()
	if err := s.ClearAllSecondFactors(id); !errors.Is(err, ErrNoSecondFactors) {
		t.Errorf("ClearAllSecondFactors on an account with no factor = %v, want ErrNoSecondFactors", err)
	}
	if got := b.saves.Load() - before; got != 0 {
		t.Errorf("clearing nothing caused %d saves, want 0", got)
	}

	// A pending (scanned, unconfirmed) authenticator app is something
	// to clear.
	if err := s.SetPendingTOTPSecretAt(id, testTOTPSecret, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearAllSecondFactors(id); err != nil {
		t.Errorf("clearing a pending app: %v", err)
	}
	if u, _ := s.Get(id); u.TOTPSecret != "" {
		t.Error("the pending app secret survived")
	}
}

// unprintablePasskeyNames are names a passkey must never carry (#89): each
// holds a control (Cc) or format (Cf) character, the line or paragraph
// separator (Zl, Zp), or is not valid UTF-8. The refusal comes before the
// name is trimmed, cut or defaulted, so a name that would have been
// trimmed or defaulted to "Passkey <n>" is refused too.
var unprintablePasskeyNames = []struct{ label, name string }{
	{"NUL", "Yubi\x00Key"},
	{"BEL", "Yubi\x07Key"},
	{"ESC", "Yubi\x1bKey"},
	{"DEL", "Yubi\x7fKey"},
	{"C1 NEL", "Yubi\u0085Key"},
	{"zero-width space", "Yubi\u200bKey"},
	{"left-to-right mark", "Yubi\u200eKey"},
	{"right-to-left override", "Yubi\u202eKey"},
	{"left-to-right isolate", "Yubi\u2066Key"},
	{"byte order mark", "Yubi\ufeffKey"},
	{"soft hyphen", "Yubi\u00adKey"},
	{"line separator", "Yubi\u2028Key"},
	{"paragraph separator", "Yubi\u2029Key"},
	{"trailing newline", "YubiKey\n"},
	{"tab", "Yubi\tKey"},
	{"only a newline, which would default", "\n"},
	{"spaces around a control, which would trim", "  \x07  "},
	{"invalid byte", "Yubi\xffKey"},
	{"truncated multi-byte sequence", "Yubi\xe2\x82Key"},
	{"past the length cut", strings.Repeat("x", 70) + "\x07"},
}

// acceptedPasskeyNames stay accepted, unchanged by trimming: letters of
// every script, accents, emoji and ordinary spaces are not unprintable.
var acceptedPasskeyNames = []string{"Clé de Zoë 🔑", "鍵", "مفتاح", "My  work key"}

func TestAddPasskeyRefusesAnUnprintableName(t *testing.T) {
	for _, tc := range unprintablePasskeyNames {
		t.Run(tc.label, func(t *testing.T) {
			s, b, id := openHoldStore(t)
			saves := b.saves.Load()

			_, err := s.AddPasskey(id, testPasskey(1, tc.name))
			if !errors.Is(err, ErrPasskeyNameInvalid) {
				t.Fatalf("AddPasskey(%q) = %v, want ErrPasskeyNameInvalid", tc.name, err)
			}
			u, _ := s.Get(id)
			if len(u.Passkeys) != 0 {
				t.Errorf("a refused name still stored %d passkeys: %+v", len(u.Passkeys), u.Passkeys)
			}
			if got := b.saves.Load(); got != saves {
				t.Errorf("a refused name wrote to the backend (%d saves, was %d)", got, saves)
			}
		})
	}
}

func TestAddPasskeyKeepsLettersAccentsAndEmojiInAName(t *testing.T) {
	for i, name := range acceptedPasskeyNames {
		s := openTestStore(t)
		u, err := s.Register("admin", "password-placeholder-1", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.AddPasskey(u.ID, testPasskey(byte(i+1), name))
		if err != nil {
			t.Fatalf("AddPasskey(%q): %v", name, err)
		}
		if got.Name != name {
			t.Errorf("AddPasskey(%q) stored the name %q", name, got.Name)
		}
		stored, _ := s.Get(u.ID)
		if len(stored.Passkeys) != 1 || stored.Passkeys[0].Name != name {
			t.Errorf("stored passkeys after AddPasskey(%q) = %+v", name, stored.Passkeys)
		}
	}
}

// A blank name still becomes "Passkey <n>" and a long one is still cut
// to 64 characters (runes, not bytes), on every path that names a
// passkey (#89 leaves both as they were).
func TestAddPasskeyStillDefaultsABlankNameAndCutsALongOneToSixtyFourRunes(t *testing.T) {
	s := openTestStore(t)
	u, err := s.Register("admin", "password-placeholder-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.AddPasskey(u.ID, testPasskey(1, "   "))
	if err != nil {
		t.Fatalf("AddPasskey(blank): %v", err)
	}
	if got.Name != "Passkey 1" {
		t.Errorf("a blank name became %q, want %q", got.Name, "Passkey 1")
	}

	long := strings.Repeat("鍵", 70)
	got, err = s.AddPasskey(u.ID, testPasskey(2, long))
	if err != nil {
		t.Fatalf("AddPasskey(70 runes): %v", err)
	}
	if want := strings.Repeat("鍵", 64); got.Name != want {
		t.Errorf("a 70-rune name became %d runes (%q), want the first 64", len([]rune(got.Name)), got.Name)
	}
}

func TestRenamePasskeyRefusesAnUnprintableName(t *testing.T) {
	for _, tc := range unprintablePasskeyNames {
		t.Run(tc.label, func(t *testing.T) {
			s, b, id := openHoldStore(t)
			if _, err := s.AddPasskey(id, testPasskey(1, "original")); err != nil {
				t.Fatal(err)
			}
			saves := b.saves.Load()

			_, err := s.RenamePasskey(id, []byte{1}, tc.name)
			if !errors.Is(err, ErrPasskeyNameInvalid) {
				t.Fatalf("RenamePasskey(%q) = %v, want ErrPasskeyNameInvalid", tc.name, err)
			}
			u, _ := s.Get(id)
			if len(u.Passkeys) != 1 || u.Passkeys[0].Name != "original" {
				t.Errorf("a refused rename changed the passkeys to %+v", u.Passkeys)
			}
			if got := b.saves.Load(); got != saves {
				t.Errorf("a refused rename wrote to the backend (%d saves, was %d)", got, saves)
			}
		})
	}
}

func TestRenamePasskeyKeepsLettersAccentsAndEmojiAndStillDefaultsAndCuts(t *testing.T) {
	s := openTestStore(t)
	u, err := s.Register("admin", "password-placeholder-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(u.ID, testPasskey(1, "original")); err != nil {
		t.Fatal(err)
	}
	for _, name := range acceptedPasskeyNames {
		got, err := s.RenamePasskey(u.ID, []byte{1}, name)
		if err != nil {
			t.Fatalf("RenamePasskey(%q): %v", name, err)
		}
		if got.Name != name {
			t.Errorf("RenamePasskey(%q) stored the name %q", name, got.Name)
		}
	}
	got, err := s.RenamePasskey(u.ID, []byte{1}, "  ")
	if err != nil {
		t.Fatalf("RenamePasskey(blank): %v", err)
	}
	if got.Name != "Passkey 1" {
		t.Errorf("a blank rename became %q, want %q", got.Name, "Passkey 1")
	}
	got, err = s.RenamePasskey(u.ID, []byte{1}, strings.Repeat("鍵", 70))
	if err != nil {
		t.Fatalf("RenamePasskey(70 runes): %v", err)
	}
	if want := strings.Repeat("鍵", 64); got.Name != want {
		t.Errorf("a 70-rune rename became %d runes, want 64", len([]rune(got.Name)))
	}
}

// A3b-R1 (#80). The invariant: an account with at least one live second
// factor (authenticator app or passkey) holds recovery codes, and one
// with none holds none. Standard pattern: check-and-set -- the decision
// ("was that the last factor?") and the write happen in one store
// operation under the store's lock, so no interleaving of a removal with
// another factor change can break it.

// wantCodesToMatchFactors fails unless id holds recovery codes exactly
// when it has a live second factor.
func wantCodesToMatchFactors(t *testing.T, s *Store, id, when string) {
	t.Helper()
	u, ok := s.Get(id)
	if !ok {
		t.Fatalf("%s: the account vanished", when)
	}
	if factor, codes := u.HasSecondFactor(), len(u.RecoveryCodes) > 0; factor != codes {
		t.Errorf("%s: live second factor = %v but recovery codes held = %v (totp=%v passkeys=%d codes=%d)",
			when, factor, codes, u.HasActiveTOTP(), len(u.Passkeys), len(u.RecoveryCodes))
	}
}

// raceStart runs a and b on goroutines released at the same moment.
func raceStart(a, b func()) {
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, f := range []func(){a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			f()
		}()
	}
	close(start)
	wg.Wait()
}

const factorRaceRounds = 200

// seedPasskeyWithCodes gives id one live passkey and the recovery codes
// that back it.
func seedPasskeyWithCodes(t *testing.T, s *Store, id string, now time.Time) {
	t.Helper()
	if _, err := s.AddPasskey(id, testPasskey(1, "only")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GenerateRecoveryCodes(id, now); err != nil {
		t.Fatal(err)
	}
}

// seedTOTPWithCodes gives id a live authenticator app and its codes.
func seedTOTPWithCodes(t *testing.T, s *Store, id string, now time.Time) {
	t.Helper()
	if err := s.SetPendingTOTPSecretAt(id, testTOTPSecret, now); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmTOTP(id, now, 42); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GenerateRecoveryCodes(id, now); err != nil {
		t.Fatal(err)
	}
}

// resetFactors takes id back to no second factor at all.
func resetFactors(t *testing.T, s *Store, id string) {
	t.Helper()
	if err := s.ClearAllSecondFactors(id); err != nil && !errors.Is(err, ErrNoSecondFactors) {
		t.Fatalf("resetting factors: %v", err)
	}
}

// Both orders of "remove the last passkey" and "confirm a pending
// authenticator app" are legal; the second one to run must see what the
// first did. Run in order, as a lock would let them, the codes must
// still match the factors after the removal-first order too.
func TestRemovingTheLastPasskeyThenConfirmingTOTPKeepsRecoveryCodesConsistent(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password-placeholder-1", now)
	if err != nil {
		t.Fatal(err)
	}
	seedPasskeyWithCodes(t, s, u.ID, now)
	if err := s.SetPendingTOTPSecretAt(u.ID, testTOTPSecret, now); err != nil {
		t.Fatal(err)
	}

	if _, err := s.DeletePasskey(u.ID, []byte{1}); err != nil {
		t.Fatalf("DeletePasskey: %v", err)
	}
	// With no other live factor the add side refuses, under the lock.
	if err := s.ConfirmLaterTOTP(u.ID, now, 42); !errors.Is(err, ErrNoOtherSecondFactor) {
		t.Errorf("ConfirmLaterTOTP after the last factor went = %v, want ErrNoOtherSecondFactor", err)
	}
	wantCodesToMatchFactors(t, s, u.ID, "passkey removed, then the app confirmed")
}

// The same hole from the other side: clearing the only authenticator app
// strips the codes, and a passkey added after that must not go live
// without any.
func TestClearingTheLastTOTPThenAddingAPasskeyKeepsRecoveryCodesConsistent(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password-placeholder-1", now)
	if err != nil {
		t.Fatal(err)
	}
	seedTOTPWithCodes(t, s, u.ID, now)

	if err := s.ClearTOTP(u.ID); err != nil {
		t.Fatalf("ClearTOTP: %v", err)
	}
	if _, err := s.AddLaterPasskey(u.ID, testPasskey(2, "late")); !errors.Is(err, ErrNoOtherSecondFactor) {
		t.Errorf("AddLaterPasskey after the last factor went = %v, want ErrNoOtherSecondFactor", err)
	}
	wantCodesToMatchFactors(t, s, u.ID, "app cleared, then a passkey added")
}

func TestConcurrentFactorChangesKeepRecoveryCodesConsistent(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	cases := []struct {
		name string
		// seed puts the account in its starting state; a and b are the
		// two changes released together. mustSucceed is whether both
		// have to return nil (two removals of factors that stand).
		seed        func(t *testing.T, s *Store, id string)
		a, b        func(s *Store, id string) error
		mustSucceed bool
	}{
		{
			name: "remove the last passkey while confirming an authenticator app",
			seed: func(t *testing.T, s *Store, id string) {
				seedPasskeyWithCodes(t, s, id, now)
				if err := s.SetPendingTOTPSecretAt(id, testTOTPSecret, now); err != nil {
					t.Fatal(err)
				}
			},
			a: func(s *Store, id string) error { _, err := s.DeletePasskey(id, []byte{1}); return err },
			b: func(s *Store, id string) error { return s.ConfirmLaterTOTP(id, now, 42) },
		},
		{
			name: "clear the only authenticator app while adding a passkey",
			seed: func(t *testing.T, s *Store, id string) { seedTOTPWithCodes(t, s, id, now) },
			a:    func(s *Store, id string) error { return s.ClearTOTP(id) },
			b: func(s *Store, id string) error {
				_, err := s.AddLaterPasskey(id, testPasskey(2, "late"))
				return err
			},
		},
		{
			name: "remove the app and the passkey, each the other's backup",
			seed: func(t *testing.T, s *Store, id string) {
				seedTOTPWithCodes(t, s, id, now)
				if _, err := s.AddPasskey(id, testPasskey(1, "only")); err != nil {
					t.Fatal(err)
				}
			},
			a:           func(s *Store, id string) error { return s.ClearTOTP(id) },
			b:           func(s *Store, id string) error { _, err := s.DeletePasskey(id, []byte{1}); return err },
			mustSucceed: true,
		},
		{
			name: "clear the app and clear all passkeys",
			seed: func(t *testing.T, s *Store, id string) {
				seedTOTPWithCodes(t, s, id, now)
				if _, err := s.AddPasskey(id, testPasskey(1, "one")); err != nil {
					t.Fatal(err)
				}
				if _, err := s.AddPasskey(id, testPasskey(2, "two")); err != nil {
					t.Fatal(err)
				}
			},
			a:           func(s *Store, id string) error { return s.ClearTOTP(id) },
			b:           func(s *Store, id string) error { return s.ClearPasskeys(id) },
			mustSucceed: true,
		},
		{
			name: "remove two passkeys of a passkey-only account",
			seed: func(t *testing.T, s *Store, id string) {
				if _, err := s.AddPasskey(id, testPasskey(1, "one")); err != nil {
					t.Fatal(err)
				}
				if _, err := s.AddPasskey(id, testPasskey(2, "two")); err != nil {
					t.Fatal(err)
				}
				if _, err := s.GenerateRecoveryCodes(id, now); err != nil {
					t.Fatal(err)
				}
			},
			a:           func(s *Store, id string) error { _, err := s.DeletePasskey(id, []byte{1}); return err },
			b:           func(s *Store, id string) error { _, err := s.DeletePasskey(id, []byte{2}); return err },
			mustSucceed: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := openTestStore(t)
			u, err := s.Register("admin", "password-placeholder-1", now)
			if err != nil {
				t.Fatal(err)
			}
			for round := range factorRaceRounds {
				resetFactors(t, s, u.ID)
				tc.seed(t, s, u.ID)
				var errA, errB error
				raceStart(
					func() { errA = tc.a(s, u.ID) },
					func() { errB = tc.b(s, u.ID) },
				)
				if tc.mustSucceed && (errA != nil || errB != nil) {
					t.Fatalf("round %d: both removals stand to succeed, got %v and %v", round, errA, errB)
				}
				wantCodesToMatchFactors(t, s, u.ID, fmt.Sprintf("round %d (a: %v, b: %v)", round, errA, errB))
				if t.Failed() {
					return
				}
			}
		})
	}
}

// The additional-factor path: AddLaterPasskey stores a passkey, and
// ConfirmLaterTOTP makes a pending app live, only beside a live second
// factor -- decided under the store's lock -- and refuse with
// ErrNoOtherSecondFactor, storing nothing, otherwise.
func TestAddLaterPasskeySucceedsBesideALiveFactor(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password-placeholder-1", now)
	if err != nil {
		t.Fatal(err)
	}
	seedTOTPWithCodes(t, s, u.ID, now)
	before, _ := s.Get(u.ID)

	pk, err := s.AddLaterPasskey(u.ID, testPasskey(5, "later"))
	if err != nil {
		t.Fatalf("AddLaterPasskey beside a live app: %v", err)
	}
	if pk.Name != "later" || len(pk.ID) != 1 || pk.ID[0] != 5 {
		t.Errorf("returned passkey = %+v, want the one added", pk)
	}
	got, _ := s.Get(u.ID)
	if len(got.Passkeys) != 1 || !got.HasActiveTOTP() {
		t.Errorf("passkeys=%d totp=%v, want the new passkey beside the app", len(got.Passkeys), got.HasActiveTOTP())
	}
	if !reflect.DeepEqual(before.RecoveryCodes, got.RecoveryCodes) {
		t.Error("adding a later passkey changed the recovery codes")
	}
}

func TestAddLaterPasskeyRefusesWithoutALiveFactorAndStoresNothing(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password-placeholder-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddLaterPasskey(u.ID, testPasskey(5, "later")); !errors.Is(err, ErrNoOtherSecondFactor) {
		t.Fatalf("AddLaterPasskey on an account with no factor = %v, want ErrNoOtherSecondFactor", err)
	}
	got, _ := s.Get(u.ID)
	if len(got.Passkeys) != 0 || len(got.RecoveryCodes) != 0 || got.HeldEnrolment != nil {
		t.Errorf("a refused add stored something: passkeys=%d codes=%d held=%+v", len(got.Passkeys), len(got.RecoveryCodes), got.HeldEnrolment)
	}
}

func TestConfirmLaterTOTPSucceedsBesideALiveFactor(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password-placeholder-1", now)
	if err != nil {
		t.Fatal(err)
	}
	seedPasskeyWithCodes(t, s, u.ID, now)
	if err := s.SetPendingTOTPSecretAt(u.ID, testTOTPSecret, now); err != nil {
		t.Fatal(err)
	}
	before, _ := s.Get(u.ID)

	if err := s.ConfirmLaterTOTP(u.ID, now, 42); err != nil {
		t.Fatalf("ConfirmLaterTOTP beside a live passkey: %v", err)
	}
	got, _ := s.Get(u.ID)
	if !got.HasActiveTOTP() || len(got.Passkeys) != 1 {
		t.Errorf("totp=%v passkeys=%d, want the app live beside the passkey", got.HasActiveTOTP(), len(got.Passkeys))
	}
	if !reflect.DeepEqual(before.RecoveryCodes, got.RecoveryCodes) {
		t.Error("confirming a later app changed the recovery codes")
	}
}

func TestConfirmLaterTOTPRefusesWithoutALiveFactorAndLeavesItPending(t *testing.T) {
	s := openTestStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	u, err := s.Register("admin", "password-placeholder-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetPendingTOTPSecretAt(u.ID, testTOTPSecret, now); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmLaterTOTP(u.ID, now, 42); !errors.Is(err, ErrNoOtherSecondFactor) {
		t.Fatalf("ConfirmLaterTOTP on an account with no factor = %v, want ErrNoOtherSecondFactor", err)
	}
	got, _ := s.Get(u.ID)
	if got.HasActiveTOTP() || len(got.RecoveryCodes) != 0 {
		t.Errorf("a refused confirm went live: totp=%v codes=%d", got.HasActiveTOTP(), len(got.RecoveryCodes))
	}
	if got.TOTPSecret != testTOTPSecret || got.TOTPPendingSince.IsZero() || !got.TOTPConfirmedAt.IsZero() {
		t.Errorf("the pending secret did not stay pending: secret=%q pendingSince=%v confirmedAt=%v",
			got.TOTPSecret, got.TOTPPendingSince, got.TOTPConfirmedAt)
	}
}
