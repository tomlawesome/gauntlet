// Partly ported from mikroview's internal/auth/password_test.go: the
// round-trip, unique-salt and malformed-hash tests are mikroview's.
// TestHashPasswordUsesTheProductionCost and
// TestVerifyPasswordRejectsOutOfRangeStoredHash (#12) were written here.

package gauntlet

import (
	"fmt"
	"strings"
	"testing"
	"time"

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

// TestVerifyPasswordRejectsOutOfRangeThreadCount is gauntlet#58 SEC2:
// memory, time, salt and key length are all bounded against a stored
// hash's declared cost, but threads was not, so a stored hash someone
// edited (or corrupted into) could ask for far more parallelism than
// HashPassword ever produces.
//
// A high but otherwise in-bounds thread count does not make the real
// computation take noticeably longer or crash, so a plain
// VerifyPassword(...) == false assertion cannot tell "refused before
// hashing" apart from "hashed and simply didn't match". Instead this
// saturates every hash slot first: a call that is refused by its
// thread count never reaches acquireHashSlot and returns at once;
// one that is not refused blocks on the channel forever, since nothing
// here ever frees a slot.
func TestVerifyPasswordRejectsOutOfRangeThreadCount(t *testing.T) {
	const salt, key = "AAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	encoded := "argon2id$v=19$m=65536,t=3,p=255$" + salt + "$" + key

	for range maxConcurrentHashes {
		hashSlots <- struct{}{}
	}
	defer func() {
		for range maxConcurrentHashes {
			<-hashSlots
		}
	}()

	done := make(chan bool, 1)
	go func() { done <- VerifyPassword("anything", encoded) }()

	select {
	case got := <-done:
		if got {
			t.Error("expected an out-of-range thread count to never verify")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("VerifyPassword blocked waiting for a hash slot -- the oversized thread count was not refused before hashing")
	}
}

// Valid bounds the cost from above as well as below: a damaged or edited
// lock document must not be able to drive DeriveKey into a gigabytes-wide
// allocation or a pass count that holds a hash slot for minutes.
func TestKDFParamsValidBounds(t *testing.T) {
	ok := DefaultKDFParams()
	cases := []struct {
		name string
		p    KDFParams
		want bool
	}{
		{"default", ok, true},
		{"memory at floor", KDFParams{Memory: 8 * 1024, Time: 1, Threads: 1}, true},
		{"memory below floor", KDFParams{Memory: 8*1024 - 1, Time: 1, Threads: 1}, false},
		{"memory at ceiling", KDFParams{Memory: 1 << 20, Time: ok.Time, Threads: ok.Threads}, true},
		{"memory over ceiling", KDFParams{Memory: 1<<20 + 1, Time: ok.Time, Threads: ok.Threads}, false},
		{"time zero", KDFParams{Memory: ok.Memory, Time: 0, Threads: ok.Threads}, false},
		{"time at ceiling", KDFParams{Memory: ok.Memory, Time: 64, Threads: ok.Threads}, true},
		{"time over ceiling", KDFParams{Memory: ok.Memory, Time: 65, Threads: ok.Threads}, false},
		{"threads zero", KDFParams{Memory: ok.Memory, Time: ok.Time, Threads: 0}, false},
		{"threads at ceiling", KDFParams{Memory: ok.Memory, Time: ok.Time, Threads: 32}, true},
		{"threads over ceiling", KDFParams{Memory: ok.Memory, Time: ok.Time, Threads: 33}, false},
	}
	for _, c := range cases {
		if got := c.p.Valid(); got != c.want {
			t.Errorf("%s: %+v.Valid() = %v, want %v", c.name, c.p, got, c.want)
		}
	}
}
