// Copied from mikroview's internal/auth/username.go, unchanged except
// for the error message prefix ("gauntlet:" in place of "auth:").

package gauntlet

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A username is not just a label. It is written into the audit trail,
// printed to an operator's terminal, and shown in an admin's account
// list -- three places where the wrong characters stop being text and
// start being instructions or disguises. So it is validated at creation
// rather than escaped at each of those sites, which is the arrangement
// that stays correct when a fourth site is added.
const (
	// maxUsernameLength bounds what any of those surfaces has to render.
	// Long enough for an email address, which is what most identity
	// providers send as preferred_username.
	maxUsernameLength = 64
	minUsernameLength = 1
)

var (
	// ErrUsernameInvalid is returned for a username containing characters
	// that would be unsafe or misleading downstream.
	ErrUsernameInvalid = errors.New("gauntlet: username contains characters that are not allowed")
	// ErrUsernameLength is returned for an empty or over-long username.
	ErrUsernameLength = fmt.Errorf("gauntlet: username must be between %d and %d characters", minUsernameLength, maxUsernameLength)
	// ErrUsernameIsEmail is returned by ValidateLocalUsername for a
	// locally-created account named as an email address.
	ErrUsernameIsEmail = errors.New("gauntlet: a local account's username may not be an email address")
)

// unprintable reports whether r is a character this package refuses or
// drops in text a person or a client chose: a control (Cc) or format
// (Cf) character, or the Unicode line or paragraph separator (Zl, Zp),
// which some mail and chat clients start a new line at, as at a newline
// (#80). Usernames, token names, device IDs and the client details a
// session, a sign-in record and a notice carry all use it.
func unprintable(r rune) bool {
	return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}

// ValidateUsername rejects a username that would be unsafe downstream.
//
// Three things are refused, each for a specific reason:
//
//   - Control characters (C0, C1, DEL). An ANSI escape in a username is
//     executed by an operator's terminal when they list users, and a
//     newline forges a whole extra line in the audit trail. This is the
//     defect behind CVE-2025-55754 (Tomcat, ANSI escapes reaching
//     console output) and CVE-2025-48432 (Django, crafted input reaching
//     logs unescaped).
//
//   - Unicode format characters (category Cf). These include the bidi
//     overrides -- U+202E RIGHT-TO-LEFT OVERRIDE and friends -- which
//     let a username render as something other than what it is. In an
//     account list whose whole purpose is telling the admin who holds
//     access, an account that displays as another account's name is a
//     real problem.
//
//   - Leading or trailing whitespace. " admin" and "admin" look
//     identical in a list, and the store's uniqueness check is on the
//     lowercased string, so both can exist at once.
//
// Deliberately not an allowlist of ASCII. Plenty of legitimate people
// have non-ASCII names, and refusing them to save a validation function
// is not a security decision.
//
// The "no email addresses" rule is deliberately *not* here: an identity
// provider's preferred_username claim is usually an email, and this
// function is what sanitiseUsernameHint runs over that claim. It lives
// in ValidateLocalUsername instead, which only local account creation
// calls.
func ValidateUsername(username string) error {
	if !utf8.ValidString(username) {
		return ErrUsernameInvalid
	}
	if username != strings.TrimSpace(username) {
		return ErrUsernameInvalid
	}
	n := utf8.RuneCountInString(username)
	if n < minUsernameLength || n > maxUsernameLength {
		return ErrUsernameLength
	}
	for _, r := range username {
		if unprintable(r) {
			return ErrUsernameInvalid
		}
	}
	return nil
}

// ValidateLocalUsername is ValidateUsername plus the one rule that
// applies to an account the application creates itself: its username
// may not be an email address (mikroview #1252).
//
// The reason is that it makes a clash impossible rather than checkable.
// An SSO-provisioned account is usually named by the provider's
// preferred_username or email claim, which is an email address; a local
// account never is; so the two namespaces are disjoint and nothing ever
// has to compare an address to decide whether a returning identity is
// "the same person" as an existing local account.
//
// Any "@" is refused, not just a well-formed address. The purpose is a
// namespace that cannot overlap with what providers send, so something
// half-way to an address ("tom@", "tom@corp") is refused too; there is
// no legitimate local name that needs one.
//
// Called from createAccount -- the single funnel for Register and
// CreateUser -- and so at creation only. It is never applied at
// sign-in: an account created before this rule and named as an email
// keeps working, because refusing it then would lock out someone who
// cannot fix it.
func ValidateLocalUsername(username string) error {
	if err := ValidateUsername(username); err != nil {
		return err
	}
	if strings.ContainsRune(username, '@') {
		return ErrUsernameIsEmail
	}
	return nil
}

// sanitiseUsernameHint applies ValidateUsername -- not
// ValidateLocalUsername -- to an identity provider's
// preferred_username/email claim, returning "" if it is not usable as a
// username.
//
// The email rule is deliberately skipped here. An SSO-provisioned
// account being named by its email claim is the normal case and what
// keeps the two namespaces disjoint (see ValidateLocalUsername);
// refusing it would rename half of an operator's people to
// `oidc-<hash>` for no gain.
//
// Returning "" rather than an error is the point. The claim is
// controlled by the identity provider, and the person signing in has
// already authenticated successfully -- refusing the login because
// their IdP sent an awkward display name would lock out someone who did
// nothing wrong and cannot fix it. An empty hint makes
// uniqueUsername fall back to its deterministic `oidc-<hash>`
// name, so they still get a stable account.
func sanitiseUsernameHint(hint string) string {
	hint = strings.TrimSpace(hint)
	if ValidateUsername(hint) != nil {
		return ""
	}
	return hint
}
