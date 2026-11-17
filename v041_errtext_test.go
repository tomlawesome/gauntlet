package gauntlet

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// v0.4.1 (A3q-Q1): ErrNoSecondFactors is returned by both
// ClearAllSecondFactors (nothing to clear) and RegenerateRecoveryCodes
// (no live second factor to back new codes), so its text has to fit
// both.

const v041NoSecondFactorsText = "gauntlet: this account has no second factor"

func TestV041ErrNoSecondFactorsText(t *testing.T) {
	if got := ErrNoSecondFactors.Error(); got != v041NoSecondFactorsText {
		t.Errorf("ErrNoSecondFactors text = %q, want %q", got, v041NoSecondFactorsText)
	}
}

func TestV041RegenerateRecoveryCodesRefusalDoesNotTalkOfClearing(t *testing.T) {
	s := openTestStore(t)
	u, err := s.Register("admin", "admin-password-placeholder", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.RegenerateRecoveryCodes(u.ID)
	if !errors.Is(err, ErrNoSecondFactors) {
		t.Fatalf("RegenerateRecoveryCodes with no second factor = %v, want ErrNoSecondFactors", err)
	}
	if strings.Contains(err.Error(), "clear") {
		t.Errorf("RegenerateRecoveryCodes refusal text = %q, must not mention clearing", err.Error())
	}
}
