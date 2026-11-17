// Package groupname is the rule SSO group names are compared by,
// written once (#90 item 6): oidc.Policy.AllowedGroups decides who may
// sign in by it, and gate's role map (oidc.Policy.RoleFromGroups)
// decides which role they get by it. Were the two written separately, a
// fix to one could let a person in under a spelling the other does not
// recognise, and they would get the fallback role instead of the one
// configured for their group.
package groupname

import "strings"

// Match reports whether a and b name the same group: equal once
// surrounding white space is trimmed from both, ignoring case.
// Providers and operators both pad and capitalise group names
// inconsistently ("Admins" in one, "admins " in another), and neither
// is a difference anyone means. Inner space is kept: "net ops" and
// "netops" are different groups. Case is strings.EqualFold's simple
// Unicode folding, so "ß" is not "ss".
func Match(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
