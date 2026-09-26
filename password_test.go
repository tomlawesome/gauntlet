// Ported from mikroview's internal/auth/password_test.go, unchanged.

package gauntlet

import "testing"

func TestHashAndVerifyPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !VerifyPassword("correct-horse-battery-staple", hash) {
		t.Error("expected the correct password to verify")
	}
	if VerifyPassword("wrong-password", hash) {
		t.Error("expected an incorrect password to fail verification")
	}
}

func TestHashPasswordProducesUniqueSaltPerCall(t *testing.T) {
	h1, _ := HashPassword("same-password")
	h2, _ := HashPassword("same-password")
	if h1 == h2 {
		t.Error("expected two hashes of the same password to differ (random salt per call)")
	}
	if !VerifyPassword("same-password", h1) || !VerifyPassword("same-password", h2) {
		t.Error("expected both independently-salted hashes to still verify")
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	cases := []string{"", "not-a-hash", "argon2id$bad", "bcrypt$v=1$m=1,t=1,p=1$c2FsdA$aGFzaA"}
	for _, c := range cases {
		if VerifyPassword("anything", c) {
			t.Errorf("expected malformed hash %q to never verify", c)
		}
	}
}
