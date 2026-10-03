package gauntlet

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// probeUsernames are the names an attacker tries against any login
// form. One of them typed in full says what was being tried and cannot
// be someone's password, so MaskUnknownUsername keeps it as typed. A
// fixed list, matched exactly after lowercasing: applications cannot
// extend it in this release (owner, 2026-10-02).
var probeUsernames = map[string]bool{
	"root": true, "admin": true, "administrator": true, "sysadmin": true, "superuser": true,
	"super": true, "sa": true, "system": true, "operator": true, "support": true, "guest": true,
	"test": true, "user": true, "demo": true, "service": true, "postgres": true, "mysql": true,
	"oracle": true, "ubuntu": true, "pi": true,
}

// maskRune replaces every hidden character of a masked name.
const maskRune = '•'

// MaskUnknownUsername is how a sign-in attempt whose name matched no
// account records that name (#45, #53): never as typed, since a
// password typed into the username box is the commonest such name.
// Applied before the name reaches an audit record, a log line or a
// stored row, so the typed name exists only in the request.
//
// Control (Cc) and format (Cf) characters and invalid UTF-8 are
// dropped, surrounding white space trimmed, and the result cut to the
// username length limit (64 characters). A name on the fixed probe list
// (root, admin, postgres and the like, matched exactly in any case) is
// returned as it now stands: an exact match only, so "admin123" is
// masked. Any other name keeps its first two characters and shows the
// rest as one • each -- "Hunter2024" becomes "Hu••••••••" -- so an
// admin can tell a mistyped username from a password without seeing
// either. One- and two-character names are returned whole; an empty
// name stays empty.
//
// A name that matched an account is not unknown and is recorded as the
// account's own username, whatever its role (owner, 2026-10-02).
func MaskUnknownUsername(typed string) string {
	var b strings.Builder
	for len(typed) > 0 {
		r, size := utf8.DecodeRuneInString(typed)
		typed = typed[size:]
		if r == utf8.RuneError && size == 1 {
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		b.WriteRune(r)
	}
	runes := []rune(strings.TrimSpace(b.String()))
	if len(runes) > maxUsernameLength {
		runes = runes[:maxUsernameLength]
	}
	name := string(runes)
	if len(runes) <= 2 || probeUsernames[strings.ToLower(name)] {
		return name
	}
	return string(runes[:2]) + strings.Repeat(string(maskRune), len(runes)-2)
}
