package gauntlet

import (
	"errors"
	"testing"
	"time"
)

// RegenerateRecoveryCodes (#94) is GenerateRecoveryCodes with one more
// rule, checked inside the same locked write: the account must hold a
// live second factor (a confirmed authenticator app or a live passkey).
// A pending app or a held enrolment is not live. A refusal stores
// nothing.

// storedCodeHashes returns the hashes of the account's stored recovery
// codes, in order.
func storedCodeHashes(t *testing.T, s *Store, id string) []string {
	t.Helper()
	u, ok := s.Get(id)
	if !ok {
		t.Fatal("the account vanished")
	}
	hashes := make([]string, 0, len(u.RecoveryCodes))
	for _, rc := range u.RecoveryCodes {
		hashes = append(hashes, rc.Hash)
	}
	return hashes
}

// wantSameHashes fails unless got and want are the same hashes in the
// same order.
func wantSameHashes(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("stored %d recovery codes, want %d unchanged", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("stored recovery code %d changed by a refused regeneration", i)
		}
	}
}

func TestRegenerateRecoveryCodesRefusedWithNoFactor(t *testing.T) {
	s, id := newRecoveryTestStore(t)
	old, err := s.GenerateRecoveryCodes(id, time.Now())
	if err != nil {
		t.Fatalf("seeding recovery codes: %v", err)
	}
	before := storedCodeHashes(t, s, id)

	codes, err := s.RegenerateRecoveryCodes(id)
	if !errors.Is(err, ErrNoSecondFactors) {
		t.Fatalf("RegenerateRecoveryCodes with no second factor = %v, want ErrNoSecondFactors", err)
	}
	if len(codes) != 0 {
		t.Errorf("a refused regeneration returned %d codes", len(codes))
	}
	wantSameHashes(t, storedCodeHashes(t, s, id), before)
	if ok, err := s.BurnRecoveryCode(id, old[0], time.Now()); err != nil || !ok {
		t.Errorf("an original code after a refused regeneration: ok=%v err=%v, want it to work", ok, err)
	}
}

func TestRegenerateRecoveryCodesRefusedWithOnlyAPendingTOTP(t *testing.T) {
	s, id := newRecoveryTestStore(t)
	if _, err := s.GenerateRecoveryCodes(id, time.Now()); err != nil {
		t.Fatalf("seeding recovery codes: %v", err)
	}
	before := storedCodeHashes(t, s, id)
	if err := s.SetPendingTOTPSecret(id, testTOTPSecret); err != nil {
		t.Fatalf("SetPendingTOTPSecret: %v", err)
	}

	if _, err := s.RegenerateRecoveryCodes(id); !errors.Is(err, ErrNoSecondFactors) {
		t.Fatalf("RegenerateRecoveryCodes with only a pending authenticator app = %v, want ErrNoSecondFactors", err)
	}
	wantSameHashes(t, storedCodeHashes(t, s, id), before)
}

func TestRegenerateRecoveryCodesRefusedWithOnlyAHeldEnrolment(t *testing.T) {
	now := time.Now()
	t.Run("passkey", func(t *testing.T) {
		s, id := newRecoveryTestStore(t)
		if _, _, err := s.HoldFirstPasskey(id, testPasskey(7, "held"), now); err != nil {
			t.Fatalf("HoldFirstPasskey: %v", err)
		}
		before := storedCodeHashes(t, s, id)

		if _, err := s.RegenerateRecoveryCodes(id); !errors.Is(err, ErrNoSecondFactors) {
			t.Fatalf("RegenerateRecoveryCodes with only a held passkey = %v, want ErrNoSecondFactors", err)
		}
		wantSameHashes(t, storedCodeHashes(t, s, id), before)
		if u, _ := s.Get(id); u.HasSecondFactor() || len(u.RecoveryCodes) != 0 {
			t.Errorf("a refused regeneration made the held enrolment live (factor=%v codes=%d)", u.HasSecondFactor(), len(u.RecoveryCodes))
		}
	})
	t.Run("totp", func(t *testing.T) {
		s, id := newRecoveryTestStore(t)
		if err := s.SetPendingTOTPSecret(id, testTOTPSecret); err != nil {
			t.Fatalf("SetPendingTOTPSecret: %v", err)
		}
		if _, err := s.HoldFirstTOTP(id, testTOTPSecret, 1, now); err != nil {
			t.Fatalf("HoldFirstTOTP: %v", err)
		}
		before := storedCodeHashes(t, s, id)

		if _, err := s.RegenerateRecoveryCodes(id); !errors.Is(err, ErrNoSecondFactors) {
			t.Fatalf("RegenerateRecoveryCodes with only a held authenticator app = %v, want ErrNoSecondFactors", err)
		}
		wantSameHashes(t, storedCodeHashes(t, s, id), before)
		if u, _ := s.Get(id); u.HasSecondFactor() || len(u.RecoveryCodes) != 0 {
			t.Errorf("a refused regeneration made the held enrolment live (factor=%v codes=%d)", u.HasSecondFactor(), len(u.RecoveryCodes))
		}
	})
}

// wantRegenerationReplacesTheSet regenerates for an account that already
// holds a live factor and codes, and checks the ten new codes replaced
// the stored set.
func wantRegenerationReplacesTheSet(t *testing.T, s *Store, id string, old []string) {
	t.Helper()
	before := storedCodeHashes(t, s, id)
	codes, err := s.RegenerateRecoveryCodes(id)
	if err != nil {
		t.Fatalf("RegenerateRecoveryCodes: %v", err)
	}
	if len(codes) != recoveryCodeCount {
		t.Fatalf("got %d codes, want %d", len(codes), recoveryCodeCount)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Errorf("code %q was generated twice", c)
		}
		seen[c] = true
	}
	after := storedCodeHashes(t, s, id)
	if len(after) != recoveryCodeCount {
		t.Fatalf("stored %d codes, want %d", len(after), recoveryCodeCount)
	}
	oldHash := map[string]bool{}
	for _, h := range before {
		oldHash[h] = true
	}
	for i, h := range after {
		if oldHash[h] {
			t.Errorf("stored code %d is still a hash from the replaced set", i)
		}
	}
	if ok, err := s.BurnRecoveryCode(id, old[0], time.Now()); err != nil || ok {
		t.Errorf("a code from the replaced set still worked: ok=%v err=%v", ok, err)
	}
	if ok, err := s.BurnRecoveryCode(id, codes[0], time.Now()); err != nil || !ok {
		t.Errorf("a code from the new set did not work: ok=%v err=%v", ok, err)
	}
}

func TestRegenerateRecoveryCodesSucceedsBesideALiveApp(t *testing.T) {
	s, id := newRecoveryTestStore(t)
	now := time.Now()
	if err := s.SetPendingTOTPSecret(id, testTOTPSecret); err != nil {
		t.Fatalf("SetPendingTOTPSecret: %v", err)
	}
	if err := s.ConfirmTOTP(id, now, 42); err != nil {
		t.Fatalf("ConfirmTOTP: %v", err)
	}
	old, err := s.GenerateRecoveryCodes(id, now)
	if err != nil {
		t.Fatalf("seeding recovery codes: %v", err)
	}
	wantRegenerationReplacesTheSet(t, s, id, old)
}

func TestRegenerateRecoveryCodesSucceedsBesideALivePasskey(t *testing.T) {
	s, id := newRecoveryTestStore(t)
	now := time.Now()
	if _, err := s.AddPasskey(id, testPasskey(1, "YubiKey")); err != nil {
		t.Fatalf("AddPasskey: %v", err)
	}
	old, err := s.GenerateRecoveryCodes(id, now)
	if err != nil {
		t.Fatalf("seeding recovery codes: %v", err)
	}
	wantRegenerationReplacesTheSet(t, s, id, old)
}
