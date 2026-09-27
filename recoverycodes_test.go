// Ported from mikroview's internal/auth/recoverycodes_test.go. Adapted:
// Open(path)/OpenWithBackend(budget) -> openTestStore(t)/OpenStore(budget,
// Options{}); the plaintext-leak check reads persist.Memory's Load
// instead of os.ReadFile. TestGenerateRecoveryCodesIfAbsent* are new --
// mikroview has no internal/auth-level test for that method (it is
// exercised only through internal/api's TOTP-confirm/passkey-register
// handlers), so this is gauntlet's own coverage for it.

package gauntlet

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// newRecoveryTestStore returns a persisted store holding one account,
// with its ID -- the shape every test below starts from.
func newRecoveryTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	s := openTestStore(t)
	u, err := s.Register("admin", "admin-password-placeholder", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return s, u.ID
}

func TestGenerateRecoveryCodesReturnsTenDistinctCodes(t *testing.T) {
	s, id := newRecoveryTestStore(t)
	codes, err := s.GenerateRecoveryCodes(id, time.Now())
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if len(codes) != recoveryCodeCount {
		t.Fatalf("got %d codes, want %d", len(codes), recoveryCodeCount)
	}
	seen := make(map[string]bool, len(codes))
	for _, c := range codes {
		if seen[c] {
			t.Errorf("code %q was generated twice", c)
		}
		seen[c] = true
	}
}

func TestGenerateRecoveryCodesOnlyHashesArePersisted(t *testing.T) {
	m := persist.NewMemory()
	s, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.Register("admin", "admin-password-placeholder", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	codes, err := s.GenerateRecoveryCodes(u.ID, time.Now())
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}

	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw := string(snap.Payload)
	for _, c := range codes {
		if strings.Contains(raw, c) || strings.Contains(raw, NormaliseRecoveryCode(c)) {
			t.Fatalf("recovery code %q was written to the accounts document in clear", c)
		}
	}

	got, ok := s.Get(u.ID)
	if !ok {
		t.Fatal("expected the user to still exist")
	}
	if len(got.RecoveryCodes) != recoveryCodeCount {
		t.Fatalf("got %d stored codes, want %d", len(got.RecoveryCodes), recoveryCodeCount)
	}
	for i, rc := range got.RecoveryCodes {
		if !strings.HasPrefix(rc.Hash, "argon2id$") {
			t.Errorf("code %d: hash %q is not an Argon2id hash", i, rc.Hash)
		}
		if !rc.UsedAt.IsZero() {
			t.Errorf("code %d: a freshly generated code is already marked used", i)
		}
	}
}

func TestGenerateRecoveryCodesReplacesAnExistingSet(t *testing.T) {
	s, id := newRecoveryTestStore(t)
	first, err := s.GenerateRecoveryCodes(id, time.Now())
	if err != nil {
		t.Fatalf("first GenerateRecoveryCodes: %v", err)
	}
	second, err := s.GenerateRecoveryCodes(id, time.Now())
	if err != nil {
		t.Fatalf("second GenerateRecoveryCodes: %v", err)
	}

	// A code from the replaced set must not still work.
	if ok, err := s.BurnRecoveryCode(id, first[0], time.Now()); err != nil || ok {
		t.Errorf("a code from the replaced set still worked: ok=%v err=%v", ok, err)
	}
	// A code from the new set must.
	if ok, err := s.BurnRecoveryCode(id, second[0], time.Now()); err != nil || !ok {
		t.Errorf("a code from the current set did not work: ok=%v err=%v", ok, err)
	}
}

func TestGenerateRecoveryCodesUnknownUserReturnsNotFound(t *testing.T) {
	s, _ := newRecoveryTestStore(t)
	if _, err := s.GenerateRecoveryCodes("no-such-user", time.Now()); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("GenerateRecoveryCodes on an unknown user = %v, want %v", err, ErrUserNotFound)
	}
}

func TestGenerateRecoveryCodesRefusedWhenNotPersisted(t *testing.T) {
	s, err := OpenStore(nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GenerateRecoveryCodes("anyone", time.Now()); !errors.Is(err, ErrNotPersisted) {
		t.Errorf("GenerateRecoveryCodes on an unpersisted store = %v, want %v", err, ErrNotPersisted)
	}
}

// TestGenerateRecoveryCodesLeavesOldSetWhenPersistFails follows the same
// restore-on-failure contract as SetPassword/IssueResetCode: a set that
// only exists in memory must not be reported as issued.
func TestGenerateRecoveryCodesLeavesOldSetWhenPersistFails(t *testing.T) {
	// Budget covers Register (1) and the first GenerateRecoveryCodes
	// call (1); the second call below is what runs out of budget.
	budget := &saveBudgetBackend{left: 2}
	s, err := OpenStore(budget, Options{})
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.Register("admin", "admin-password-placeholder", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.GenerateRecoveryCodes(u.ID, time.Now())
	if err != nil {
		t.Fatalf("first GenerateRecoveryCodes: %v", err)
	}

	budget.left = 0
	if _, err := s.GenerateRecoveryCodes(u.ID, time.Now()); err == nil {
		t.Fatal("GenerateRecoveryCodes against a backend that cannot save = nil error, want one")
	}

	// The first set must still work: the failed second call must not
	// have replaced it in memory. One more save for BurnRecoveryCode's
	// own persist (marking the code used).
	budget.left = 1
	if ok, err := s.BurnRecoveryCode(u.ID, first[0], time.Now()); err != nil {
		t.Fatalf("BurnRecoveryCode: %v", err)
	} else if !ok {
		t.Error("the pre-failure set of codes stopped working after a failed regeneration")
	}
}

func TestRecoveryCodeWorksOnceThenIsRefused(t *testing.T) {
	s, id := newRecoveryTestStore(t)
	codes, err := s.GenerateRecoveryCodes(id, time.Now())
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}

	ok, err := s.BurnRecoveryCode(id, codes[0], time.Now())
	if err != nil || !ok {
		t.Fatalf("first use: ok=%v err=%v, want ok=true err=nil", ok, err)
	}

	ok, err = s.BurnRecoveryCode(id, codes[0], time.Now())
	if err != nil || ok {
		t.Fatalf("second use: ok=%v err=%v, want ok=false err=nil", ok, err)
	}

	// The account's other nine codes are unaffected by burning this one.
	ok, err = s.BurnRecoveryCode(id, codes[1], time.Now())
	if err != nil || !ok {
		t.Fatalf("an unrelated unused code: ok=%v err=%v, want ok=true err=nil", ok, err)
	}
}

func TestBurnRecoveryCodeRefusals(t *testing.T) {
	tests := []struct {
		name    string
		code    func(codes []string) string
		wantOK  bool
		wantErr error
	}{
		{
			name:   "a code that was never issued",
			code:   func(codes []string) string { return "ZZZZZ-ZZZZZ" },
			wantOK: false,
		},
		{
			name:   "the same code with different casing and no dash",
			code:   func(codes []string) string { return strings.ToLower(strings.ReplaceAll(codes[2], "-", "")) },
			wantOK: true,
		},
		{
			name:   "the same code with stray whitespace",
			code:   func(codes []string) string { return "  " + codes[3] + "  " },
			wantOK: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, id := newRecoveryTestStore(t)
			codes, err := s.GenerateRecoveryCodes(id, time.Now())
			if err != nil {
				t.Fatalf("GenerateRecoveryCodes: %v", err)
			}
			ok, err := s.BurnRecoveryCode(id, tc.code(codes), time.Now())
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestBurnRecoveryCodeUnknownUserReturnsNotFound(t *testing.T) {
	s, _ := newRecoveryTestStore(t)
	if ok, err := s.BurnRecoveryCode("no-such-user", "ANYTHING", time.Now()); ok || !errors.Is(err, ErrUserNotFound) {
		t.Errorf("BurnRecoveryCode on an unknown user = (%v, %v), want (false, %v)", ok, err, ErrUserNotFound)
	}
}

// TestBurnRecoveryCodeLeavesCodeUnspentWhenPersistFails mirrors
// TestResetCodeStaysUnspentWhenTheSpendCannotBeSaved (resetcode_test.go):
// a spend that only lands in memory must not be reported as successful,
// and the code must still be usable once the backend recovers.
func TestBurnRecoveryCodeLeavesCodeUnspentWhenPersistFails(t *testing.T) {
	budget := &saveBudgetBackend{left: 1}
	s, err := OpenStore(budget, Options{})
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.Register("admin", "admin-password-placeholder", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// GenerateRecoveryCodes needs its own save; give it a fresh budget of
	// one, then starve the store before the burn under test.
	budget.left = 1
	codes, err := s.GenerateRecoveryCodes(u.ID, time.Now())
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	budget.left = 0

	ok, err := s.BurnRecoveryCode(u.ID, codes[0], time.Now())
	if err == nil {
		t.Fatal("BurnRecoveryCode against a backend that cannot save = nil error, want one")
	}
	if ok {
		t.Error("BurnRecoveryCode reported success despite the failed persist")
	}

	got, _ := s.Get(u.ID)
	if !got.RecoveryCodes[0].UsedAt.IsZero() {
		t.Error("the code is marked used in memory even though the write failed")
	}
}

// TestGenerateRecoveryCodesIfAbsentMintsOnlyOnce covers the mint-if-
// absent contract itself: a first call mints and returns codes, a
// second returns alreadyIssued and leaves the first set working.
func TestGenerateRecoveryCodesIfAbsentMintsOnlyOnce(t *testing.T) {
	s, id := newRecoveryTestStore(t)

	first, alreadyIssued, err := s.GenerateRecoveryCodesIfAbsent(id, time.Now())
	if err != nil {
		t.Fatalf("first GenerateRecoveryCodesIfAbsent: %v", err)
	}
	if alreadyIssued {
		t.Fatal("alreadyIssued = true on the first call, want false")
	}
	if len(first) != recoveryCodeCount {
		t.Fatalf("got %d codes, want %d", len(first), recoveryCodeCount)
	}

	second, alreadyIssued, err := s.GenerateRecoveryCodesIfAbsent(id, time.Now())
	if err != nil {
		t.Fatalf("second GenerateRecoveryCodesIfAbsent: %v", err)
	}
	if !alreadyIssued {
		t.Fatal("alreadyIssued = false on the second call, want true -- an existing set must not be replaced")
	}
	if second != nil {
		t.Errorf("codes = %v on the alreadyIssued path, want nil", second)
	}

	// The first set must still be the live one.
	if ok, err := s.BurnRecoveryCode(id, first[0], time.Now()); err != nil || !ok {
		t.Errorf("the first set stopped working after a second, no-op call: ok=%v err=%v", ok, err)
	}
}

func TestGenerateRecoveryCodesIfAbsentUnknownUserReturnsNotFound(t *testing.T) {
	s, _ := newRecoveryTestStore(t)
	if _, _, err := s.GenerateRecoveryCodesIfAbsent("no-such-user", time.Now()); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("GenerateRecoveryCodesIfAbsent on an unknown user = %v, want %v", err, ErrUserNotFound)
	}
}

func TestGenerateRecoveryCodesIfAbsentRefusedWhenNotPersisted(t *testing.T) {
	s, err := OpenStore(nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.GenerateRecoveryCodesIfAbsent("anyone", time.Now()); !errors.Is(err, ErrNotPersisted) {
		t.Errorf("GenerateRecoveryCodesIfAbsent on an unpersisted store = %v, want %v", err, ErrNotPersisted)
	}
}

// TestGenerateRecoveryCodesIfAbsentLeavesNothingWhenPersistFails follows
// the same restore-on-failure contract as GenerateRecoveryCodes: a mint
// that only exists in memory must not be reported as issued.
func TestGenerateRecoveryCodesIfAbsentLeavesNothingWhenPersistFails(t *testing.T) {
	budget := &saveBudgetBackend{left: 1} // Register only
	s, err := OpenStore(budget, Options{})
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.Register("admin", "admin-password-placeholder", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	budget.left = 0
	if _, _, err := s.GenerateRecoveryCodesIfAbsent(u.ID, time.Now()); err == nil {
		t.Fatal("GenerateRecoveryCodesIfAbsent against a backend that cannot save = nil error, want one")
	}
	got, _ := s.Get(u.ID)
	if len(got.RecoveryCodes) != 0 {
		t.Errorf("RecoveryCodes in memory after a failed mint = %d, want 0", len(got.RecoveryCodes))
	}
}
