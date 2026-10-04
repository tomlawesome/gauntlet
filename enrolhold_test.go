package gauntlet

import (
	"errors"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// The hold-until-confirmed rule (#58): an account's first second factor
// and its ten recovery codes are saved together in one write, on hold,
// and only become live when ConfirmHeldEnrolment takes them off hold.
// An enrolment not confirmed within HeldEnrolmentLifetime is deleted.

// openHoldStore opens a store over a counting backend with one account,
// "alice", which holds no second factor.
func openHoldStore(t *testing.T) (*Store, *countingBackend, string) {
	t.Helper()
	b := &countingBackend{Memory: persist.NewMemory()}
	s, id := openLockoutStore(t, b)
	return s, b, id
}

func TestHoldFirstPasskeySavesThePasskeyAndItsCodesInOneWrite(t *testing.T) {
	s, b, id := openHoldStore(t)
	now := time.Now().UTC().Truncate(time.Millisecond)

	before := b.saves.Load()
	held, codes, err := s.HoldFirstPasskey(id, testPasskey(7, "YubiKey"), now)
	if err != nil {
		t.Fatalf("HoldFirstPasskey: %v", err)
	}
	if got := b.saves.Load() - before; got != 1 {
		t.Errorf("holding the first passkey took %d saves, want exactly 1", got)
	}
	if held.Name != "YubiKey" || len(held.ID) != 1 || held.ID[0] != 7 {
		t.Errorf("held passkey = %+v, want the one registered", held)
	}
	if len(codes) != recoveryCodeCount {
		t.Fatalf("got %d recovery codes, want %d", len(codes), recoveryCodeCount)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Errorf("recovery code %q issued twice", c)
		}
		seen[c] = true
	}

	u, _ := s.Get(id)
	if len(u.Passkeys) != 0 || len(u.RecoveryCodes) != 0 {
		t.Errorf("a held enrolment is live: %d passkeys, %d recovery codes", len(u.Passkeys), len(u.RecoveryCodes))
	}
	if u.HasSecondFactor() || u.PasskeyCount() != 0 || s.PasskeyCount(id) != 0 || s.AnyPasskeysExist() {
		t.Error("a held passkey counts as a second factor")
	}
	if !u.EnrolmentHeld(now) {
		t.Error("EnrolmentHeld is false straight after the hold")
	}
	h := u.HeldEnrolment
	if h == nil || h.Kind != HeldFactorPasskey || h.Passkey == nil || len(h.RecoveryCodes) != recoveryCodeCount {
		t.Fatalf("HeldEnrolment = %+v, want the passkey and ten codes", h)
	}
	if !h.HeldUntil.Equal(now.Add(HeldEnrolmentLifetime)) {
		t.Errorf("HeldUntil = %v, want %v", h.HeldUntil, now.Add(HeldEnrolmentLifetime))
	}
}

func TestHoldFirstPasskeyRefusals(t *testing.T) {
	s, _, id := openHoldStore(t)
	now := time.Now()

	if _, _, err := s.HoldFirstPasskey("nobody", testPasskey(1, "k"), now); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("unknown account: %v, want ErrUserNotFound", err)
	}
	if _, _, err := s.HoldFirstPasskey(id, testPasskey(1, "k"), now); err != nil {
		t.Fatal(err)
	}
	// One at a time: a second hold is refused while the first stands.
	if _, _, err := s.HoldFirstPasskey(id, testPasskey(2, "k2"), now.Add(time.Minute)); !errors.Is(err, ErrEnrolmentHeld) {
		t.Errorf("a second hold: %v, want ErrEnrolmentHeld", err)
	}
	if _, err := s.HoldFirstTOTP(id, testTOTPSecret, 1, now); !errors.Is(err, ErrEnrolmentHeld) {
		t.Errorf("an app hold beside a passkey hold: %v, want ErrEnrolmentHeld", err)
	}
	if err := s.SetPendingTOTPSecretAt(id, testTOTPSecret, now); !errors.Is(err, ErrEnrolmentHeld) {
		t.Errorf("starting an app enrolment beside a held passkey: %v, want ErrEnrolmentHeld", err)
	}

	// An account that already has a live factor is never held: a later
	// factor is added live and keeps the account's codes.
	other, err := s.CreateUser("bob", "password-placeholder-2", RoleUser, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(other.ID, testPasskey(3, "live")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.HoldFirstPasskey(other.ID, testPasskey(4, "second"), now); !errors.Is(err, ErrSecondFactorExists) {
		t.Errorf("holding on an account with a factor: %v, want ErrSecondFactorExists", err)
	}

	mem, err := OpenStore(nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := mem.HoldFirstPasskey(id, testPasskey(1, "k"), now); !errors.Is(err, ErrNotPersisted) {
		t.Errorf("an unpersisted store: %v, want ErrNotPersisted", err)
	}
}

func TestAHeldPasskeyCannotSignInAndItsCodesCannotBeRedeemed(t *testing.T) {
	s, _, id := openHoldStore(t)
	now := time.Now()
	held, codes, err := s.HoldFirstPasskey(id, testPasskey(9, "k"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordPasskeyAssertionIfFresh(id, held.ID, 1, now); !errors.Is(err, ErrPasskeyNotFound) {
		t.Errorf("an assertion from the held passkey: %v, want ErrPasskeyNotFound", err)
	}
	if ok, err := s.BurnRecoveryCode(id, codes[0], now); err != nil || ok {
		t.Errorf("redeeming a held recovery code: ok=%v err=%v, want refused", ok, err)
	}
}

func TestConfirmHeldEnrolmentMakesThePasskeyAndCodesLiveInOneWrite(t *testing.T) {
	s, b, id := openHoldStore(t)
	now := time.Now().UTC()
	held, codes, err := s.HoldFirstPasskey(id, testPasskey(5, "phone"), now)
	if err != nil {
		t.Fatal(err)
	}

	before := b.saves.Load()
	got, err := s.ConfirmHeldEnrolment(id, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("ConfirmHeldEnrolment: %v", err)
	}
	if n := b.saves.Load() - before; n != 1 {
		t.Errorf("confirming took %d saves, want 1", n)
	}
	if got.Kind != HeldFactorPasskey || got.Passkey == nil || got.Passkey.Name != "phone" || got.RecoveryCodes != nil {
		t.Errorf("confirmed = %+v, want the passkey and no code hashes", got)
	}

	u, _ := s.Get(id)
	if u.HeldEnrolment != nil {
		t.Error("the enrolment is still on hold after confirming")
	}
	if !u.HasSecondFactor() || len(u.Passkeys) != 1 || len(u.RecoveryCodes) != recoveryCodeCount {
		t.Fatalf("after confirming: factor=%v passkeys=%d codes=%d", u.HasSecondFactor(), len(u.Passkeys), len(u.RecoveryCodes))
	}
	if ok, err := s.RecordPasskeyAssertionIfFresh(id, held.ID, 1, now); err != nil || !ok {
		t.Errorf("the confirmed passkey signing in: ok=%v err=%v", ok, err)
	}
	if ok, err := s.BurnRecoveryCode(id, codes[3], now); err != nil || !ok {
		t.Errorf("redeeming a confirmed recovery code: ok=%v err=%v", ok, err)
	}
	if _, err := s.ConfirmHeldEnrolment(id, now); !errors.Is(err, ErrNoHeldEnrolment) {
		t.Errorf("confirming twice: %v, want ErrNoHeldEnrolment", err)
	}
}

func TestConfirmHeldEnrolmentWithNothingHeld(t *testing.T) {
	s, _, id := openHoldStore(t)
	if _, err := s.ConfirmHeldEnrolment(id, time.Now()); !errors.Is(err, ErrNoHeldEnrolment) {
		t.Errorf("nothing held: %v, want ErrNoHeldEnrolment", err)
	}
	if _, err := s.ConfirmHeldEnrolment("nobody", time.Now()); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("unknown account: %v, want ErrUserNotFound", err)
	}
}

func TestAHeldEnrolmentExpiresAndIsDeleted(t *testing.T) {
	s, b, id := openHoldStore(t)
	now := time.Now().UTC()
	if _, _, err := s.HoldFirstPasskey(id, testPasskey(5, "phone"), now); err != nil {
		t.Fatal(err)
	}
	late := now.Add(HeldEnrolmentLifetime)
	if u, _ := s.Get(id); u.EnrolmentHeld(late) {
		t.Error("EnrolmentHeld is still true at the expiry")
	}

	before := b.saves.Load()
	if _, err := s.ConfirmHeldEnrolment(id, late); !errors.Is(err, ErrHeldEnrolmentExpired) {
		t.Fatalf("confirming at the expiry: %v, want ErrHeldEnrolmentExpired", err)
	}
	if n := b.saves.Load() - before; n != 1 {
		t.Errorf("deleting the expired enrolment took %d saves, want 1", n)
	}
	u, _ := s.Get(id)
	if u.HeldEnrolment != nil || len(u.Passkeys) != 0 || len(u.RecoveryCodes) != 0 {
		t.Errorf("the expired enrolment survived: held=%+v passkeys=%d codes=%d", u.HeldEnrolment, len(u.Passkeys), len(u.RecoveryCodes))
	}
	if _, err := s.ConfirmHeldEnrolment(id, late); !errors.Is(err, ErrNoHeldEnrolment) {
		t.Errorf("confirming after the deletion: %v, want ErrNoHeldEnrolment", err)
	}
}

// The next write that starts an enrolment deletes an expired hold
// itself, rather than refusing until something else clears it.
func TestAnExpiredHoldIsDeletedByTheNextEnrolment(t *testing.T) {
	s, _, id := openHoldStore(t)
	now := time.Now().UTC()
	if _, _, err := s.HoldFirstPasskey(id, testPasskey(5, "old"), now); err != nil {
		t.Fatal(err)
	}
	late := now.Add(HeldEnrolmentLifetime + time.Second)
	held, _, err := s.HoldFirstPasskey(id, testPasskey(6, "new"), late)
	if err != nil {
		t.Fatalf("holding again after the first expired: %v", err)
	}
	u, _ := s.Get(id)
	if u.HeldEnrolment == nil || u.HeldEnrolment.Passkey.Name != held.Name || held.Name != "new" {
		t.Errorf("HeldEnrolment = %+v, want the new passkey", u.HeldEnrolment)
	}

	// And an expired passkey hold does not stop an app enrolment.
	later := late.Add(HeldEnrolmentLifetime)
	if err := s.SetPendingTOTPSecretAt(id, testTOTPSecret, later); err != nil {
		t.Fatalf("starting an app enrolment after the hold expired: %v", err)
	}
	if u, _ := s.Get(id); u.HeldEnrolment != nil {
		t.Error("the expired hold survived the app enrolment's write")
	}
}

func TestHoldFirstTOTPThenConfirm(t *testing.T) {
	s, b, id := openHoldStore(t)
	now := time.Now().UTC()
	if err := s.SetPendingTOTPSecretAt(id, testTOTPSecret, now); err != nil {
		t.Fatal(err)
	}

	before := b.saves.Load()
	codes, err := s.HoldFirstTOTP(id, testTOTPSecret, 77, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("HoldFirstTOTP: %v", err)
	}
	if n := b.saves.Load() - before; n != 1 {
		t.Errorf("holding the app took %d saves, want 1", n)
	}
	if len(codes) != recoveryCodeCount {
		t.Fatalf("got %d codes, want %d", len(codes), recoveryCodeCount)
	}
	u, _ := s.Get(id)
	if u.HasActiveTOTP() || u.HasSecondFactor() || len(u.RecoveryCodes) != 0 {
		t.Fatal("a held authenticator app is live")
	}
	if u.HeldEnrolment == nil || u.HeldEnrolment.Kind != HeldFactorTOTP || u.HeldEnrolment.Passkey != nil {
		t.Fatalf("HeldEnrolment = %+v, want an app hold", u.HeldEnrolment)
	}
	// A held app verifies no code, at sign-in or anywhere else.
	secret, _ := DecodeTOTPSecret(testTOTPSecret)
	code := GenerateTOTPCode(secret, totpCounter(now.Add(2*time.Minute), totpStep))
	if ok, err := s.VerifyAndRecordTOTP(id, code, now.Add(2*time.Minute)); err != nil || ok {
		t.Errorf("a held app verifying a code: ok=%v err=%v, want refused", ok, err)
	}
	if ok, _ := s.BurnRecoveryCode(id, codes[0], now); ok {
		t.Error("a held recovery code was redeemed")
	}
	if err := s.ConfirmTOTP(id, now, 80); !errors.Is(err, ErrEnrolmentHeld) {
		t.Errorf("confirming the held app live: %v, want ErrEnrolmentHeld", err)
	}

	got, err := s.ConfirmHeldEnrolment(id, now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("ConfirmHeldEnrolment: %v", err)
	}
	if got.Kind != HeldFactorTOTP {
		t.Errorf("confirmed kind = %q, want totp", got.Kind)
	}
	u, _ = s.Get(id)
	if !u.HasActiveTOTP() || len(u.RecoveryCodes) != recoveryCodeCount || u.HeldEnrolment != nil {
		t.Fatalf("after confirming: active=%v codes=%d held=%+v", u.HasActiveTOTP(), len(u.RecoveryCodes), u.HeldEnrolment)
	}
	if u.TOTPLastCounter != 77 {
		t.Errorf("TOTPLastCounter = %d, want the counter that proved the enrolment (77)", u.TOTPLastCounter)
	}
	if !u.TOTPPendingSince.IsZero() {
		t.Error("TOTPPendingSince is still set on a confirmed app")
	}
}

func TestAnExpiredTOTPHoldDeletesTheSecretToo(t *testing.T) {
	s, _, id := openHoldStore(t)
	now := time.Now().UTC()
	if err := s.SetPendingTOTPSecretAt(id, testTOTPSecret, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HoldFirstTOTP(id, testTOTPSecret, 3, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmHeldEnrolment(id, now.Add(HeldEnrolmentLifetime)); !errors.Is(err, ErrHeldEnrolmentExpired) {
		t.Fatalf("confirming an expired app: %v, want ErrHeldEnrolmentExpired", err)
	}
	u, _ := s.Get(id)
	if u.TOTPSecret != "" || u.TOTPLastCounter != 0 || !u.TOTPPendingSince.IsZero() || u.HeldEnrolment != nil {
		t.Errorf("the expired app survived: secret=%q counter=%d since=%v held=%+v", u.TOTPSecret, u.TOTPLastCounter, u.TOTPPendingSince, u.HeldEnrolment)
	}
}

func TestHoldFirstTOTPRefusals(t *testing.T) {
	s, _, id := openHoldStore(t)
	now := time.Now().UTC()
	if _, err := s.HoldFirstTOTP(id, testTOTPSecret, 1, now); !errors.Is(err, ErrNoPendingTOTP) {
		t.Errorf("nothing pending: %v, want ErrNoPendingTOTP", err)
	}
	if err := s.SetPendingTOTPSecretAt(id, testTOTPSecret, now); err != nil {
		t.Fatal(err)
	}
	// The code was checked against a different secret than the one now
	// pending (another enrolment replaced it in between).
	if _, err := s.HoldFirstTOTP(id, "MZXW6YTBOI", 1, now); !errors.Is(err, ErrNoPendingTOTP) {
		t.Errorf("a replaced secret: %v, want ErrNoPendingTOTP", err)
	}
	// A pending secret older than TOTPPendingLifetime is treated as
	// absent.
	if _, err := s.HoldFirstTOTP(id, testTOTPSecret, 1, now.Add(TOTPPendingLifetime)); !errors.Is(err, ErrNoPendingTOTP) {
		t.Errorf("an expired pending secret: %v, want ErrNoPendingTOTP", err)
	}
	if _, err := s.AddPasskey(id, testPasskey(1, "live")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HoldFirstTOTP(id, testTOTPSecret, 1, now); !errors.Is(err, ErrSecondFactorExists) {
		t.Errorf("an account with a passkey: %v, want ErrSecondFactorExists", err)
	}
}

// A scanned but unconfirmed authenticator-app secret expires
// TOTPPendingLifetime after it was set, and is then treated as absent.
func TestAPendingTOTPSecretExpires(t *testing.T) {
	s, _, id := openHoldStore(t)
	now := time.Now().UTC()
	if err := s.SetPendingTOTPSecretAt(id, testTOTPSecret, now); err != nil {
		t.Fatal(err)
	}
	u, _ := s.Get(id)
	if !u.TOTPPendingSince.Equal(now) {
		t.Errorf("TOTPPendingSince = %v, want %v", u.TOTPPendingSince, now)
	}
	if !u.TOTPPending(now.Add(TOTPPendingLifetime - time.Second)) {
		t.Error("the pending secret is not live inside its lifetime")
	}
	if u.TOTPPending(now.Add(TOTPPendingLifetime)) {
		t.Error("the pending secret is still live at its expiry")
	}
	if err := s.ConfirmTOTP(id, now.Add(TOTPPendingLifetime), 1); !errors.Is(err, ErrNoPendingTOTP) {
		t.Errorf("confirming an expired pending secret: %v, want ErrNoPendingTOTP", err)
	}
	if err := s.ConfirmTOTP(id, now.Add(time.Minute), 1); err != nil {
		t.Errorf("confirming inside the lifetime: %v", err)
	}
}

func TestClearingAFactorClearsItsHold(t *testing.T) {
	now := time.Now().UTC()
	t.Run("passkeys", func(t *testing.T) {
		s, _, id := openHoldStore(t)
		if _, _, err := s.HoldFirstPasskey(id, testPasskey(1, "k"), now); err != nil {
			t.Fatal(err)
		}
		if err := s.ClearTOTP(id); err != nil {
			t.Fatal(err)
		}
		if u, _ := s.Get(id); u.HeldEnrolment == nil {
			t.Error("clearing the app dropped a held passkey")
		}
		if err := s.ClearPasskeys(id); err != nil {
			t.Fatal(err)
		}
		if u, _ := s.Get(id); u.HeldEnrolment != nil {
			t.Error("clearing every passkey left a held one")
		}
	})
	t.Run("app", func(t *testing.T) {
		s, _, id := openHoldStore(t)
		if err := s.SetPendingTOTPSecretAt(id, testTOTPSecret, now); err != nil {
			t.Fatal(err)
		}
		if _, err := s.HoldFirstTOTP(id, testTOTPSecret, 1, now); err != nil {
			t.Fatal(err)
		}
		if err := s.ClearPasskeys(id); err != nil {
			t.Fatal(err)
		}
		if u, _ := s.Get(id); u.HeldEnrolment == nil {
			t.Error("clearing passkeys dropped a held app")
		}
		if err := s.ClearTOTP(id); err != nil {
			t.Fatal(err)
		}
		if u, _ := s.Get(id); u.HeldEnrolment != nil || u.TOTPSecret != "" || !u.TOTPPendingSince.IsZero() {
			t.Errorf("clearing the app left its hold: %+v", u.HeldEnrolment)
		}
	})
	t.Run("everything", func(t *testing.T) {
		s, _, id := openHoldStore(t)
		if _, _, err := s.HoldFirstPasskey(id, testPasskey(1, "k"), now); err != nil {
			t.Fatal(err)
		}
		if err := s.ClearAllSecondFactors(id); err != nil {
			t.Fatal(err)
		}
		if u, _ := s.Get(id); u.HeldEnrolment != nil {
			t.Error("ClearAllSecondFactors left a held passkey")
		}
	})
}

// A hold that could not be saved is not held: nothing in memory either.
func TestAHoldThatCannotBeSavedHoldsNothing(t *testing.T) {
	b := &saveBudgetBackend{left: 1}
	s, err := OpenStore(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.Register("alice", "password-placeholder-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.HoldFirstPasskey(u.ID, testPasskey(1, "k"), time.Now()); err == nil {
		t.Fatal("a hold whose save failed reported success")
	}
	if got, _ := s.Get(u.ID); got.HeldEnrolment != nil {
		t.Error("a hold whose save failed is held in memory")
	}
}

func TestListBlanksAHeldEnrolment(t *testing.T) {
	s, _, id := openHoldStore(t)
	if _, _, err := s.HoldFirstPasskey(id, testPasskey(1, "k"), time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, u := range s.List() {
		if u.HeldEnrolment != nil {
			t.Errorf("List carried %s's held enrolment", u.Username)
		}
	}
}
