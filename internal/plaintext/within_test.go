package plaintext

import (
	"strings"
	"testing"
)

// ValidWithin is the rule for a name a person chooses (#90): valid UTF-8,
// no unprintable character, no U+FFFD, and at most maxChars characters,
// each code point counting as one whatever its width in bytes.

func TestValidWithin(t *testing.T) {
	const max = 64
	for _, tc := range []struct {
		label string
		in    string
		max   int
		want  bool
	}{
		{"empty", "", max, true},
		{"empty with a zero limit", "", 0, true},
		{"one character with a zero limit", "a", 0, false},
		{"plain", "YubiKey", max, true},
		{"spaces inside", "My  work key", max, true},
		{"accents and emoji", "Clé de Zoë 🔑", max, true},

		{"exactly the limit of Latin", strings.Repeat("a", max), max, true},
		{"one over the limit of Latin", strings.Repeat("a", max+1), max, false},
		{"exactly the limit of two-byte letters", strings.Repeat("é", max), max, true},
		{"one over the limit of two-byte letters", strings.Repeat("é", max+1), max, false},
		{"exactly the limit of CJK", strings.Repeat("鍵", max), max, true},
		{"one over the limit of CJK", strings.Repeat("鍵", max+1), max, false},
		{"exactly the limit of emoji", strings.Repeat("🔑", max), max, true},
		{"one over the limit of emoji", strings.Repeat("🔑", max+1), max, false},
		{"mixed widths at the limit", strings.Repeat("a鍵🔑é", max/4), max, true},
		{"mixed widths one over", strings.Repeat("a鍵🔑é", max/4) + "x", max, false},
		{"a different limit, at it", "日本語", 3, true},
		{"a different limit, one over", "日本語x", 3, false},
		{"a combining mark is its own character", "é", 1, false},
		{"a combining mark within the limit", "é", 2, true},

		{"U+FFFD alone", "\uFFFD", max, false},
		{"U+FFFD at the start", "\uFFFDKey", max, false},
		{"U+FFFD in the middle", "Yubi\uFFFDKey", max, false},
		{"U+FFFD at the end", "Key\uFFFD", max, false},
		{"U+FFFD within CJK", "鍵\uFFFD鍵", max, false},

		{"invalid byte", "Yubi\xffKey", max, false},
		{"lone invalid byte", "\xff", max, false},
		{"truncated multi-byte sequence", "Key\xe9\x8d", max, false},
		{"encoded surrogate", "Key\xed\xa0\x80", max, false},
		{"overlong encoding", "Key\xc0\xaf", max, false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			if got := ValidWithin(tc.in, tc.max); got != tc.want {
				t.Errorf("ValidWithin(%q, %d) = %v, want %v", tc.in, tc.max, got, tc.want)
			}
		})
	}
}

func TestValidWithinRefusesEachUnprintableClass(t *testing.T) {
	for _, tc := range unprintableRunes {
		for _, in := range []string{
			string(tc.r),
			"a" + string(tc.r),
			string(tc.r) + "a",
			"a" + string(tc.r) + "b",
		} {
			if ValidWithin(in, 64) {
				t.Errorf("ValidWithin(%q, 64) = true for %s (U+%04X), want false", in, tc.label, tc.r)
			}
		}
	}
}

func TestValidWithinAcceptsEachPrintableClass(t *testing.T) {
	for _, tc := range printableRunes {
		in := "a" + string(tc.r) + "b"
		if !ValidWithin(in, 64) {
			t.Errorf("ValidWithin(%q, 64) = false for %s (U+%04X), want true", in, tc.label, tc.r)
		}
	}
}

// An unprintable or broken character is refused however short the text:
// the limit is an extra rule, not a replacement for the character rules.
func TestValidWithinKeepsTheCharacterRulesUnderTheLimit(t *testing.T) {
	for _, in := range []string{"a\nb", "a\uFFFDb", "a\xffb", "a\u202eb"} {
		if ValidWithin(in, 1000) {
			t.Errorf("ValidWithin(%q, 1000) = true, want false", in)
		}
	}
}
