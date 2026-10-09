// The known-browser token's shape, written once (#90 item 8): what the
// root store issues and what the gate accepts back from a cookie are the
// same rule, so they cannot drift apart.
//
// This is an external test package on purpose: the root package imports
// browsertoken, and a test inside browsertoken that imports the root
// package back would be an import cycle.
package browsertoken_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/internal/browsertoken"
	"github.com/tomlawesome/gauntlet/persist"
)

func TestBytesIs32(t *testing.T) {
	if browsertoken.Bytes != 32 {
		t.Errorf("Bytes = %d, want 32", browsertoken.Bytes)
	}
}

// A new token is well-formed every time and never repeats: 32 random
// bytes, unpadded base64url, so 43 characters.
func TestNewIsWellFormedAndDistinct(t *testing.T) {
	seen := make(map[string]bool)
	for range 2000 {
		tok := browsertoken.New()
		if !browsertoken.WellFormed(tok) {
			t.Fatalf("New() = %q is not well-formed", tok)
		}
		if len(tok) != 43 {
			t.Fatalf("New() = %q has %d characters, want 43", tok, len(tok))
		}
		raw, err := base64.RawURLEncoding.DecodeString(tok)
		if err != nil || len(raw) != browsertoken.Bytes {
			t.Fatalf("New() = %q decodes to %d bytes (err %v), want %d", tok, len(raw), err, browsertoken.Bytes)
		}
		if again := base64.RawURLEncoding.EncodeToString(raw); again != tok {
			t.Fatalf("New() = %q is not the canonical spelling of its bytes (%q)", tok, again)
		}
		if seen[tok] {
			t.Fatalf("New() repeated %q", tok)
		}
		seen[tok] = true
	}
}

func TestWellFormedRefusals(t *testing.T) {
	good := browsertoken.New()
	// 43 characters that are all in the base64url alphabet.
	forty3 := strings.Repeat("A", 43)
	if !browsertoken.WellFormed(forty3) {
		t.Fatalf("control: %q (43 base64url characters) was refused", forty3)
	}
	if canonical := strings.Repeat("A", 42) + "Q"; !browsertoken.WellFormed(canonical) {
		t.Fatalf("control: %q (trailing bits zero) was refused", canonical)
	}

	for name, s := range map[string]string{
		"padded":               good + "=",
		"padded to a multiple": good + "===",
		"42 characters":        good[:42],
		"44 characters":        good + "A",
		// 43 characters carry 258 bits for 256 of data: the last
		// character's low two bits must be zero. A lenient decoder drops
		// them silently, so two spellings would name one token.
		"nonzero trailing bits":    strings.Repeat("A", 42) + "B",
		"all-ones trailing bits":   good[:42] + "_",
		"empty":                    "",
		"standard-alphabet plus":   "+" + good[1:],
		"standard-alphabet slash":  good[:20] + "/" + good[21:],
		"leading space":            " " + good[1:],
		"trailing space":           good[:42] + " ",
		"embedded space":           good[:20] + " " + good[21:],
		"newline":                  good[:42] + "\n",
		"tab":                      good[:20] + "\t" + good[21:],
		"43 that is not base64":    strings.Repeat("!", 43),
		"43 with one bad char":     good[:20] + "!" + good[21:],
		"43 with a dot":            good[:20] + "." + good[21:],
		"43 with a non-ASCII rune": good[:20] + "é" + good[21:], // 44 bytes, 43 runes
	} {
		if browsertoken.WellFormed(s) {
			t.Errorf("WellFormed(%s: %q) = true, want false", name, s)
		}
	}
}

// What the store issues is what WellFormed accepts, and what the store
// does not issue in that shape is refused: the rule the gate applies to a
// cookie part is the rule the store applies to its own tokens.
func TestWhatTheStoreIssuesIsWellFormed(t *testing.T) {
	s, err := gauntlet.OpenStore(persist.NewMemory(), gauntlet.Options{})
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.Register("alice", "password-placeholder-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	prev := ""
	for i := range 20 {
		tok, err := s.RememberBrowser(u.ID, prev, time.Now())
		if err != nil {
			t.Fatalf("RememberBrowser: %v", err)
		}
		if !browsertoken.WellFormed(tok) {
			t.Fatalf("token %d from the store, %q, is not well-formed", i, tok)
		}
		prev = tok
	}
}
