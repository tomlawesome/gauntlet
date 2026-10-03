// Copied from mikroview's internal/auth/resetcode.go, names kept
// (docs/design.md §1.3). This is the admin-issued one-time reset code:
// mikroview sends no mail of any kind, so there is no "reset link in
// your inbox" to fall back on -- an admin resets an account and reads
// the code out to its owner in person or over a call they trust.
// Everything about the shape below follows from that: it is a string a
// human dictates and another human types, once, under a deadline.
//
// Store.Authenticate's redemption of a live code (the part that had to
// exist from G2 onward, since a whole-document store must round-trip
// ResetCodeHash regardless of who last set it) predates this file's
// IssueResetCode; see Authenticate's own doc comment in store.go.
package gauntlet

import (
	"crypto/rand"
	"errors"
	"strings"
	"time"
)

// resetCodeAlphabet is deliberately 32 characters with every ambiguous
// pair removed: no 0/O, no 1/I/l. A code that is read aloud or copied
// off a screen must not have a "was that a one or an ell" in it, since
// the person retyping it has no way to check and gets a flat "invalid
// username or password" when they guess wrong.
//
// Exactly 32 (2^5) is also what lets newResetCode below index the
// alphabet with a five-bit mask rather than a modulo, so every character
// is uniformly likely without rejection sampling.
const resetCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

const (
	// resetCodeLength is the number of alphabet characters in a code,
	// excluding the grouping dashes. 16 characters over a 32-character
	// alphabet is 80 bits -- far beyond anything the login rate limiter
	// would let an attacker work through inside the 24-hour window, and
	// still short enough to read out in four short runs.
	resetCodeLength = 16
	// resetCodeGroup is how many characters sit between dashes in the
	// form a human sees: xxxx-xxxx-xxxx-xxxx.
	resetCodeGroup = 4
)

// ResetCodeTTL is how long an issued code stays usable: 24 hours,
// single use. "Single use" means the login that redeems it spends it,
// whether or not the forced password change is then completed; see
// Store.Authenticate's doc comment.
const ResetCodeTTL = 24 * time.Hour

// ErrNoLocalPassword is returned by IssueResetCode for an account that
// signs in only through its identity provider. Its provider owns the
// password; minting a local credential for it here would quietly
// re-open the local attack surface that provisioning (or linking) it
// through OIDC deliberately closed -- the same reasoning
// LinkOIDCIdentity's doc comment sets out.
var ErrNoLocalPassword = errors.New("gauntlet: this account signs in through its identity provider, so there is no local password to reset")

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

// newResetCode returns a fresh code in its canonical form -- the raw
// resetCodeLength characters, no dashes. That is the form that gets
// hashed; FormatResetCode below is only ever applied on the way to a
// human.
func newResetCode() string {
	b := make([]byte, resetCodeLength)
	if _, err := rand.Read(b); err != nil {
		// Same stance as newID: a CSPRNG that cannot produce bytes is
		// not a condition to degrade gracefully from when the output is
		// about to stand in for someone's password.
		panic("gauntlet: crypto/rand unavailable: " + err.Error())
	}
	out := make([]byte, resetCodeLength)
	for i, v := range b {
		out[i] = resetCodeAlphabet[v&31]
	}
	return string(out)
}

// FormatResetCode groups a canonical code for display:
// xxxx-xxxx-xxxx-xxxx. The dashes are presentation only --
// NormaliseResetCode strips them again on the way back in, so someone
// who types the code with them, without them, or in lower case is
// accepted either way.
func FormatResetCode(code string) string {
	var b strings.Builder
	for i, r := range code {
		if i > 0 && i%resetCodeGroup == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// IssueResetCode mints a one-time code for userID, replaces that
// account's password with an unmatchable hash, and returns the code --
// grouped for display -- exactly once. It is not recoverable afterwards:
// only its hash is kept, so an admin who loses the code issues another,
// which kills the first.
//
// The old password dies the moment this returns, before the person has
// used the code for anything. That is the point rather than a side
// effect: an admin resets an account because they believe the current
// credential is in the wrong hands, and a reset that left it working
// until the owner got round to the code would leave the window open for
// precisely as long as it mattered.
//
// PasswordChangedAt and SessionsEndedAt are bumped as SetPassword bumps
// them: the password was replaced, and SessionsEndedAt is what
// invalidates sessions issued before this point, including ones held in
// another process (see User.SessionCutoff). The caller
// is still expected to drop the live ones it can reach; this is the
// part that works across a process boundary and a restart.
//
// The account's lockout, its count of lockouts and a disabled sign-in
// (#44) are all cleared in the same write, so the owner can use the code
// at once. So are the browsers it remembers (KnownBrowsers, #44): a
// browser the old credentials reached keeps no allowance past the
// reset. A running LoginLimiter drops its own count of the guesses
// before it by PasswordChangedAt, and, seeing the code on the record,
// any disable it decided but has not managed to save (only while saves
// are failing) too, so no retry writes it back over the reset. The
// reset route must not call LoginLimiter.UnlockLogin for that: it would
// also drop the limiter's count of the guesses before the reset, which
// is what lets the reset account past its address's limit
// (AllowAfterReset, #32).
//
// Refused with ErrNoLocalPassword for an SSO-only account. Refusing an
// admin's *own* account is the caller's job, not this method's: the
// store has no notion of who is asking.
func (s *Store) IssueResetCode(userID string, now time.Time) (*User, string, error) {
	if !s.Persisted() {
		return nil, "", ErrNotPersisted
	}

	// Both derivations happen before the lock, for the reason
	// LinkOIDCIdentity documents: HashPassword is ~100ms by design and
	// holding the write lock across it would serialize every reader.
	code := newResetCode()
	codeHash, err := HashPassword(code)
	if err != nil {
		return nil, "", err
	}
	unmatchable, err := unmatchablePasswordHash()
	if err != nil {
		return nil, "", err
	}

	s.reloadIfStale()

	// The old password must still work and no code must be live unless
	// the reset is saved: a reset that only exists in memory but is
	// reported as issued would leave the admin reading out a code that
	// a restart before the next good write silently un-issues. mutate
	// installs it only once it is saved.
	var issued User
	err = s.mutate(func(st *storeState) error {
		u, ok := st.byID[userID]
		if !ok {
			return ErrUserNotFound
		}
		if !u.HasLocalPassword {
			return ErrNoLocalPassword
		}
		u.PasswordHash = unmatchable
		u.ResetCodeHash = codeHash
		u.ResetCodeExpiresAt = now.Add(ResetCodeTTL)
		u.MustChangePassword = true
		u.PasswordChangedAt = now
		u.SessionsEndedAt = now
		// The password a breach recheck was owed for is gone; the one
		// chosen after the code gets its own check (#43).
		u.BreachCheckPending = false
		// The reset code is the account's password now, so a lockout
		// earned by guessing at the old one ends here, as in
		// SetPassword: otherwise the owner could not use the code until
		// it ran out. So does the count of lockouts before it (#44).
		//
		// Unlike SetPassword, a disabled sign-in is lifted too (owner,
		// 2026-10-02): issuing the code is itself an admin action, the
		// one UnlockLogin stands for, and a code the owner could not use
		// until a second admin action would be no way back at all. A
		// new password the owner sets for themselves still lifts
		// nothing.
		u.LoginLockedUntil = time.Time{}
		u.LoginLockoutCount = 0
		u.LoginDisabledAt = time.Time{}
		// Every remembered browser is forgotten (#44): an admin resets
		// an account because its credentials may be in the wrong hands,
		// and a browser remembered before the reset may be too. The
		// owner's browser is remembered again at the sign-in the code
		// leads to.
		u.KnownBrowsers = nil
		issued = *u
		return nil
	})
	if err != nil {
		return nil, "", err
	}

	// The copy handed back is for the caller's audit entry and response
	// envelope, neither of which has any business with a credential
	// verifier -- the same blanking List does.
	issued.blankCredentials()
	return &issued, FormatResetCode(code), nil
}
