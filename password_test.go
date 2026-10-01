// Ported from mikroview's internal/auth/password_test.go, unchanged.

package gauntlet

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// Every other test here hashes at the cheap test cost (TestMain); this
// one runs the real one and checks the hash records it, so the
// production parameters are pinned by a test, not just by the
// constants.
func TestHashPasswordUsesTheProductionCost(t *testing.T) {
	useProductionHashCost(t)
	hash, err := HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	want := fmt.Sprintf("argon2id$v=%d$m=65536,t=3,p=4$", argon2.Version)
	if !strings.HasPrefix(hash, want) {
		t.Errorf("hash = %q, want it to start %q", hash, want)
	}
	if !VerifyPassword("correct-horse-battery-staple", hash) {
		t.Error("expected the production-cost hash to verify")
	}
	if dk := DefaultKDFParams(); dk.Memory != 65536 || dk.Time != 3 || dk.Threads != 4 {
		t.Errorf("DefaultKDFParams() = %+v, want the same 64 MiB, 3 passes, 4 threads", dk)
	}
}

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

// Not from mikroview (issue #12): a stored hash is data this module did
// not necessarily write, so VerifyPassword must refuse -- without
// hashing, panicking or keeping a hash slot -- any cost setting or
// length outside what HashPassword could have produced.
func TestVerifyPasswordRejectsOutOfRangeStoredHash(t *testing.T) {
	const salt, key = "AAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	cases := map[string]string{
		"zero_rounds":      "argon2id$v=19$m=65536,t=0,p=4$" + salt + "$" + key,
		"zero_threads":     "argon2id$v=19$m=65536,t=3,p=0$" + salt + "$" + key,
		"empty_key":        "argon2id$v=19$m=65536,t=3,p=4$" + salt + "$",
		"empty_salt":       "argon2id$v=19$m=65536,t=3,p=4$$" + key,
		"wrong_version":    "argon2id$v=16$m=65536,t=3,p=4$" + salt + "$" + key,
		"memory_too_small": "argon2id$v=19$m=8,t=3,p=4$" + salt + "$" + key,
		"huge_memory":      "argon2id$v=19$m=4294967295,t=3,p=4$" + salt + "$" + key,
		"huge_rounds":      "argon2id$v=19$m=65536,t=4294967295,p=4$" + salt + "$" + key,
		"huge_key":         "argon2id$v=19$m=65536,t=3,p=4$" + salt + "$" + strings.Repeat("A", 1<<20),
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			before := len(hashSlots)
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("VerifyPassword panicked: %v", r)
					}
				}()
				if VerifyPassword("anything", encoded) {
					t.Error("expected an out-of-range stored hash to never verify")
				}
			}()
			if after := len(hashSlots); after != before {
				t.Errorf("hash slots in use went from %d to %d: a slot leaked", before, after)
			}
		})
	}
}
