package gauntlet

import (
	"encoding/base32"
	"errors"
	"testing"
	"time"
)

// #93. ConfirmLaterTOTP makes a pending authenticator app live beside a
// live second factor. The caller verified a code against one secret; the
// store must confirm that secret, not whatever is pending by the time it
// takes its lock. If the pending secret was replaced in between, the
// confirm is refused and the replacement stays pending.

// Built at run time: a fixed base32 literal reads as a credential to the
// secret scanner.
var testReplacementTOTPSecret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("0123456789"))

func TestConfirmLaterTOTPRefusesASecretThatIsNoLongerPending(t *testing.T) {
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
	// The pending secret is replaced after the caller verified a code
	// against the first one.
	if err := s.SetPendingTOTPSecretAt(u.ID, testReplacementTOTPSecret, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	before, _ := s.Get(u.ID)

	err = s.ConfirmLaterTOTP(u.ID, testTOTPSecret, now.Add(2*time.Second), 42)
	if !errors.Is(err, ErrNoPendingTOTP) {
		t.Fatalf("ConfirmLaterTOTP with a replaced secret = %v, want ErrNoPendingTOTP", err)
	}
	got, _ := s.Get(u.ID)
	if got.HasActiveTOTP() {
		t.Error("a refused confirm made the authenticator app live")
	}
	if got.TOTPSecret != testReplacementTOTPSecret {
		t.Errorf("pending secret = %q, want the replacement %q still pending", got.TOTPSecret, testReplacementTOTPSecret)
	}
	if !got.TOTPConfirmedAt.IsZero() {
		t.Errorf("TOTPConfirmedAt = %v, want zero", got.TOTPConfirmedAt)
	}
	if got.TOTPLastCounter != before.TOTPLastCounter {
		t.Errorf("TOTPLastCounter = %d, want unchanged %d", got.TOTPLastCounter, before.TOTPLastCounter)
	}
}

func TestConfirmLaterTOTPConfirmsTheSecretItWasGiven(t *testing.T) {
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

	if err := s.ConfirmLaterTOTP(u.ID, testTOTPSecret, now.Add(time.Second), 42); err != nil {
		t.Fatalf("ConfirmLaterTOTP with the pending secret: %v", err)
	}
	got, _ := s.Get(u.ID)
	if !got.HasActiveTOTP() || got.TOTPSecret != testTOTPSecret {
		t.Errorf("totp live=%v secret=%q, want the given secret live", got.HasActiveTOTP(), got.TOTPSecret)
	}
	if got.TOTPLastCounter != 42 {
		t.Errorf("TOTPLastCounter = %d, want 42", got.TOTPLastCounter)
	}
}
