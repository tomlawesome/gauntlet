package gauntlet

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Guards for #90 group E: the recovery-code and reset-code helpers, the
// username fold and the sign-in fold index are being tidied with no change
// in behaviour.

// The two normalisers are one rule: whatever a person types, both give
// the same canonical form.
func TestRecoveryAndResetNormalisersAgree(t *testing.T) {
	tests := []struct {
		name  string
		typed string
	}{
		{"as displayed", "ABCD-EFGH-JKLM-NPQR"},
		{"lower case", "abcd-efgh-jklm-npqr"},
		{"mixed case", "AbCd-eFgH-JkLm-nPqR"},
		{"dashes only", "----"},
		{"no separators", "abcdefghjklmnpqr"},
		{"spaces", "ABCD EFGH  JKLM NPQR"},
		{"tabs", "ABCD\tEFGH\t\tJKLM-NPQR"},
		{"every separator at once", " \tab-cd \t- ef\tgh "},
		{"a stray bang", "ABCD!EFGH-jklm"},
		{"a bang among separators", "ab-cd !\tef"},
		{"empty", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, res := NormaliseRecoveryCode(tc.typed), NormaliseResetCode(tc.typed)
			if rec != res {
				t.Errorf("NormaliseRecoveryCode(%q) = %q but NormaliseResetCode = %q, want the same", tc.typed, rec, res)
			}
		})
	}
}

// Display grouping as shipped: recovery codes in fives, reset codes in
// fours, dashes only.
func TestFormatCodeGroupSizes(t *testing.T) {
	if got, want := FormatRecoveryCode("ABCDEFGHJK"), "ABCDE-FGHJK"; got != want {
		t.Errorf("FormatRecoveryCode = %q, want %q", got, want)
	}
	if got, want := FormatResetCode("ABCDEFGHJKLMNPQR"), "ABCD-EFGH-JKLM-NPQR"; got != want {
		t.Errorf("FormatResetCode = %q, want %q", got, want)
	}
	// A generated code formats and normalises back to itself.
	display, canonical := NewOneTimeCode()
	if got := strings.Count(display, "-"); got != 3 || len(canonical) != 16 {
		t.Errorf("NewOneTimeCode = %q, %q, want four groups of four", display, canonical)
	}
	if got := NormaliseResetCode(FormatResetCode(canonical)); got != canonical {
		t.Errorf("format then normalise = %q, want %q", got, canonical)
	}
}

// Usernames are looked up case-insensitively through every store entry
// point that takes one.
func TestMixedCaseUsernamesResolveToOneAccount(t *testing.T) {
	s := openTestStore(t)
	admin, err := s.Register("Admin", "admin-password-placeholder", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bob, err := s.CreateUser("BoBsMiTh", "bob-password-placeholder", RoleUser, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	for _, typed := range []string{"BoBsMiTh", "bobsmith", "BOBSMITH", "bObSmItH"} {
		if u, ok := s.ByUsername(typed); !ok || u.ID != bob.ID {
			t.Errorf("ByUsername(%q) = %v, %t, want bob's account", typed, u, ok)
		}
		if u, err := s.Authenticate(typed, "bob-password-placeholder", time.Now()); err != nil || u.ID != bob.ID {
			t.Errorf("Authenticate(%q) = %v, %v, want bob's account", typed, u, err)
		}
		if err := s.ValidateNewAccount(typed, "another-password-placeholder"); err == nil {
			t.Errorf("ValidateNewAccount(%q) accepted a name that differs only in case", typed)
		}
		if _, err := s.CreateUser(typed, "another-password-placeholder", RoleUser, time.Now()); err != ErrUsernameTaken {
			t.Errorf("CreateUser(%q) = %v, want ErrUsernameTaken", typed, err)
		}
	}

	if err := s.SetPassword("BOBSMITH", "bob-new-password-placeholder", time.Now()); err != nil {
		t.Fatalf("SetPassword in another case: %v", err)
	}
	if _, err := s.Authenticate("bobsmith", "bob-new-password-placeholder", time.Now()); err != nil {
		t.Errorf("the password set through another case does not sign bob in: %v", err)
	}

	_, to, err := s.TransferAdmin("bOBsMITH", time.Now())
	if err != nil {
		t.Fatalf("TransferAdmin in another case: %v", err)
	}
	if to.ID != bob.ID || admin.ID == bob.ID {
		t.Errorf("TransferAdmin went to %s, want bob's account %s", to.ID, bob.ID)
	}
}

// The fold index never holds more than its cap, however many distinct
// sources arrive, and the newest source still folds.
func TestSignInHistoryFoldIndexNeverExceedsItsCap(t *testing.T) {
	was := maxSignInFoldKeys
	maxSignInFoldKeys = 4
	t.Cleanup(func() { maxSignInFoldKeys = was })
	h := openTestHistory(t, nil, SignInHistoryOptions{})

	at := signInBase
	for i := range 200 {
		at = at.Add(time.Second)
		h.Record(successFrom("u1", "bob", fmt.Sprintf("192.0.2.%d", i)), at)
		if n := len(h.fold); n > maxSignInFoldKeys {
			t.Fatalf("after %d distinct sources the fold index holds %d keys, cap %d", i+1, n, maxSignInFoldKeys)
		}
	}
	before, _ := h.Summary()
	h.Record(successFrom("u1", "bob", "192.0.2.199"), at.Add(time.Second))
	if after, _ := h.Summary(); after != before {
		t.Errorf("a repeat of the newest source added a row (%d to %d), want it folded", before, after)
	}
}
