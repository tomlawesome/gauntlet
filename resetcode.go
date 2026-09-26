package gauntlet

import (
	"strings"
	"time"
)

// This file carries only the half of mikroview's internal/auth/resetcode.go
// that Store.Authenticate needs to redeem a reset code that is already
// live on a User (docs/design.md §1.3: "Authenticate ... also redeems a
// live reset code"). Issuing one (IssueResetCode), its alphabet and
// display formatting (FormatResetCode) are a later slice (G4): nothing
// in G2 ever sets ResetCodeHash, but a document loaded from a fixture,
// or written by a later slice, can already carry one, and Authenticate
// must redeem it correctly either way.

// NormaliseResetCode turns whatever a person typed into the canonical
// form a stored hash was computed over: upper case, with the dashes and
// spaces they may have copied (or added themselves) removed.
//
// Only separators are dropped. A character that is not in the alphabet
// is left exactly where it is rather than deleted, so a mistyped code
// stays a mistyped code -- silently discarding unknown characters would
// make "abcd!efgh" and "abcdefgh" the same secret.
func NormaliseResetCode(typed string) string {
	var b strings.Builder
	b.Grow(len(typed))
	for _, r := range typed {
		switch r {
		case '-', ' ', '\t':
			continue
		}
		b.WriteRune(r)
	}
	return strings.ToUpper(b.String())
}

// resetCodeLive reports whether u is currently holding an unexpired,
// unspent reset code. Both halves matter: the hash is cleared the
// moment the code is redeemed or a new password is set (single use),
// and the expiry is what ends an unspent one 24 hours later.
func (u *User) resetCodeLive(now time.Time) bool {
	return u.ResetCodeHash != "" && now.Before(u.ResetCodeExpiresAt)
}
