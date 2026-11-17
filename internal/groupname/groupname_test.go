package groupname

import "testing"

// Match is strings.EqualFold after strings.TrimSpace on both sides: the
// rule SSO group names are compared by, for who may sign in
// (oidc.Policy.AllowedGroups) and for which role they get
// (oidc.Policy.RoleFromGroups), written once (#90 item 6).
func TestMatch(t *testing.T) {
	for _, c := range []struct {
		name string
		a, b string
		want bool
	}{
		{"identical", "admins", "admins", true},
		{"case differs", "Admins", "admins", true},
		{"space and case differ", "Admins", " admins ", true},
		{"tabs and newlines trimmed", "\tadmins\n", "ADMINS", true},
		{"both padded differently", "  staff", "staff   ", true},
		{"a prefix is not a match", "admins", "admin", false},
		{"a suffix is not a match", "admins", "dadmins", false},
		{"different names", "admins", "guests", false},
		{"inner space is kept", "net ops", "netops", false},
		{"inner space matches itself", "Net Ops", "net ops", true},
		{"unicode case folding", "ÄRZTE", "ärzte", true},
		{"unicode differs", "ÄRZTE", "arzte", false},
		{"sharp s is kept", "straße", "STRAßE", true},
		{"sharp s is not ss", "straße", "strasse", false},
		{"kelvin sign folds to k", "Kids", "kids", true}, // EqualFold's simple folding
		{"unicode space is trimmed", " admins ", "admins", true},
		// Chosen by applying the definition as written: once both sides
		// are trimmed, "" and "  " are the same empty string, and
		// EqualFold says empty equals empty. It is the specified rule,
		// not a case picked for a purpose.
		{"empty and blank", "", "  ", true},
		{"empty and empty", "", "", true},
		{"empty and a name", "", "admins", false},
		{"blank and a name", "  ", "admins", false},
	} {
		if got := Match(c.a, c.b); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v (%s)", c.a, c.b, got, c.want, c.name)
		}
		if got := Match(c.b, c.a); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v (%s, swapped)", c.b, c.a, got, c.want, c.name)
		}
	}
}
