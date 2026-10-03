package gauntlet

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// MaskUnknownUsername (#53, owner 2026-10-02): a name that matched no
// account keeps its first two characters and its length, unless it is
// one of the names probes try, which are kept as typed.
func TestMaskUnknownUsername(t *testing.T) {
	cases := []struct{ name, typed, want string }{
		{"password-like", "Hunter2024", "Hu••••••••"},
		{"empty stays empty", "", ""},
		{"one rune unchanged", "x", "x"},
		{"two runes unchanged", "xy", "xy"},
		{"three runes", "xyz", "xy•"},
		{"probe name in full", "admin", "admin"},
		{"probe name any case, as typed", "ROOT", "ROOT"},
		{"probe name mixed case", "SysAdmin", "SysAdmin"},
		{"probe name trimmed", "  postgres\t", "postgres"},
		{"probe prefix is masked", "admin123", "ad••••••"},
		{"control characters stripped", "ad\x00m\x1bin", "admin"},
		{"newline stripped before masking", "bo\nb-secret", "bo••••••••"},
		{"bidi override stripped", "\u202Eadmin", "admin"},
		{"zero-width stripped", "ro\u200Bot", "root"},
		{"multi-byte runes counted as runes", "ñandú-pass", "ña••••••••"},
		{"invalid UTF-8 dropped", "ab\xffcd", "ab••"},
		{"only whitespace", "   ", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MaskUnknownUsername(tc.typed); got != tc.want {
				t.Errorf("MaskUnknownUsername(%q) = %q, want %q", tc.typed, got, tc.want)
			}
		})
	}
}

// A paste of 300 runes is cut to 64 before masking: the length shown is
// the cut length.
func TestMaskUnknownUsernameCutsToTheUsernameLimit(t *testing.T) {
	got := MaskUnknownUsername(strings.Repeat("é", 300))
	if n := utf8.RuneCountInString(got); n != maxUsernameLength {
		t.Fatalf("masked a 300-rune paste to %d runes, want %d", n, maxUsernameLength)
	}
	if want := "éé" + strings.Repeat("•", maxUsernameLength-2); got != want {
		t.Errorf("masked = %q, want %q", got, want)
	}
}

// Every name on the probe list is kept in full, and nothing past its
// first two runes of any other name survives.
func TestMaskUnknownUsernameProbeList(t *testing.T) {
	for _, name := range []string{"root", "admin", "administrator", "sysadmin", "superuser", "super", "sa",
		"system", "operator", "support", "guest", "test", "user", "demo", "service", "postgres", "mysql",
		"oracle", "ubuntu", "pi"} {
		if got := MaskUnknownUsername(name); got != name {
			t.Errorf("probe name %q masked to %q", name, got)
		}
	}
	secret := "correct-horse-battery"
	if got := MaskUnknownUsername(secret); strings.Contains(got, secret[2:5]) {
		t.Errorf("masked %q to %q, which still shows the name past its first two characters", secret, got)
	}
}
