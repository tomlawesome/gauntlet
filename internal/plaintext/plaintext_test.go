package plaintext

import (
	"strings"
	"testing"
)

// unprintableRunes are the characters the rule names: controls (Cc),
// format characters (Cf) and the line and paragraph separators (Zl, Zp).
var unprintableRunes = []struct {
	label string
	r     rune
}{
	{"NUL", 0x0000},
	{"BEL", 0x0007},
	{"tab", 0x0009},
	{"line feed", 0x000a},
	{"carriage return", 0x000d},
	{"ESC", 0x001b},
	{"DEL", 0x007f},
	{"C1 NEL", 0x0085},
	{"soft hyphen", 0x00ad},
	{"zero-width space", 0x200b},
	{"left-to-right mark", 0x200e},
	{"right-to-left override", 0x202e},
	{"left-to-right isolate", 0x2066},
	{"byte order mark", 0xfeff},
	{"line separator", 0x2028},
	{"paragraph separator", 0x2029},
}

// printableRunes are not: ordinary spaces and letters of any script,
// accents, digits, punctuation and emoji.
var printableRunes = []struct {
	label string
	r     rune
}{
	{"space", ' '},
	{"letter", 'a'},
	{"digit", '7'},
	{"hyphen", '-'},
	{"accented letter", 'é'},
	{"CJK", '鍵'},
	{"Arabic", 'م'},
	{"emoji", '🔑'},
	{"no-break space", 0x00a0},
	{"ideographic space", 0x3000},
}

func TestUnprintableNamesTheControlFormatAndSeparatorCharacters(t *testing.T) {
	for _, tc := range unprintableRunes {
		if !Unprintable(tc.r) {
			t.Errorf("Unprintable(%s U+%04X) = false, want true", tc.label, tc.r)
		}
	}
}

func TestUnprintableLeavesOrdinaryTextAlone(t *testing.T) {
	for _, tc := range printableRunes {
		if Unprintable(tc.r) {
			t.Errorf("Unprintable(%s U+%04X) = true, want false", tc.label, tc.r)
		}
	}
}

func TestValid(t *testing.T) {
	for _, tc := range []struct {
		label string
		in    string
		want  bool
	}{
		{"empty", "", true},
		{"plain", "YubiKey", true},
		{"spaces inside", "My  work key", true},
		{"accents and emoji", "Clé de Zoë 🔑", true},
		{"CJK", "鍵", true},
		{"Arabic", "مفتاح", true},
		{"NUL", "a\x00b", false},
		{"BEL", "a\x07b", false},
		{"ESC", "a\x1bb", false},
		{"DEL", "a\x7fb", false},
		{"C1 control", "a\u0085b", false},
		{"zero-width space", "a\u200bb", false},
		{"left-to-right mark", "a\u200eb", false},
		{"right-to-left override", "a\u202eb", false},
		{"left-to-right isolate", "a\u2066b", false},
		{"byte order mark", "a\ufeffb", false},
		{"line separator", "a\u2028b", false},
		{"paragraph separator", "a\u2029b", false},
		{"trailing newline", "name\n", false},
		{"only a control", "\x00", false},
		{"invalid byte", "a\xffb", false},
		{"only an invalid byte", "\xff", false},
		{"truncated multi-byte sequence", "a\xe2\x82", false},
		{"unprintable after the last good rune", "鍵鍵鍵\u200b", false},
	} {
		if got := Valid(tc.in); got != tc.want {
			t.Errorf("Valid(%s %q) = %v, want %v", tc.label, tc.in, got, tc.want)
		}
	}
}

func TestClean(t *testing.T) {
	for _, tc := range []struct {
		label string
		in    string
		want  string
	}{
		{"empty", "", ""},
		{"plain text is unchanged", "YubiKey", "YubiKey"},
		{"spaces are kept as they are", "  My  work key  ", "  My  work key  "},
		{"accents and emoji are kept", "Clé de Zoë 🔑", "Clé de Zoë 🔑"},
		{"CJK and Arabic are kept", "鍵 مفتاح", "鍵 مفتاح"},
		{"NUL", "a\x00b", "ab"},
		{"BEL", "a\x07b", "ab"},
		{"ESC", "a\x1bb", "ab"},
		{"DEL", "a\x7fb", "ab"},
		{"C1 control", "a\u0085b", "ab"},
		{"zero-width space", "a\u200bb", "ab"},
		{"left-to-right mark", "a\u200eb", "ab"},
		{"right-to-left override", "a\u202eb", "ab"},
		{"left-to-right isolate", "a\u2066b", "ab"},
		{"byte order mark", "a\ufeffb", "ab"},
		{"line separator", "a\u2028b", "ab"},
		{"paragraph separator", "a\u2029b", "ab"},
		{"trailing newline", "name\n", "name"},
		{"invalid byte", "a\xffb", "ab"},
		{"only an invalid byte", "\xff", ""},
		{"truncated multi-byte sequence", "a\xe2\x82b", "ab"},
		{"everything removable", "\x00\x07\u200b\u2028\xff", ""},
		{"order of what is kept", "W\u202eo\x00r\u200bk \xffK\x7fe\ny\u2029 1", "Work Key 1"},
		{"unprintable between wide letters", "鍵\u200b鍵\u202e🔑", "鍵鍵🔑"},
	} {
		if got := Clean(tc.in); got != tc.want {
			t.Errorf("Clean(%s %q) = %q, want %q", tc.label, tc.in, got, tc.want)
		}
	}
}

// Whatever goes in, Clean's answer is valid, and cleaning it again
// changes nothing; Valid and Clean agree about what is clean.
func TestCleanAlwaysAnswersAValidStringAndIsIdempotent(t *testing.T) {
	inputs := []string{
		"", "plain", "a\x00b", "\xff\xfe", "Clé 🔑\n", "\u2028\u2029", "x\xe2\x82",
		strings.Repeat("鍵\u200b", 40), "\x1b[31mred\x1b[0m",
	}
	for _, tc := range unprintableRunes {
		inputs = append(inputs, "a"+string(tc.r)+"b")
	}
	for _, in := range inputs {
		got := Clean(in)
		if !Valid(got) {
			t.Errorf("Valid(Clean(%q)) = false (Clean gave %q)", in, got)
		}
		if again := Clean(got); again != got {
			t.Errorf("Clean(Clean(%q)) = %q, want %q", in, again, got)
		}
		if Valid(in) && got != in {
			t.Errorf("Clean(%q) = %q, but the input was already valid", in, got)
		}
	}
}

func TestValidAgreesWithUnprintableOnEveryRune(t *testing.T) {
	for r := rune(0); r < 0x3000; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue // not runes: a lone surrogate is not valid UTF-8
		}
		if got, want := Valid("a"+string(r)+"b"), !Unprintable(r); got != want {
			t.Errorf("Valid(a U+%04X b) = %v, but Unprintable = %v", r, got, !want)
		}
	}
}
