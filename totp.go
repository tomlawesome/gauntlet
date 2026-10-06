// TOTP is mikroview's authenticator-app second factor (#1249): RFC
// 6238's Time-based One-Time Password, built on RFC 4226's HOTP.
// Everything here is standard library only -- crypto/hmac, crypto/sha1,
// encoding/base32, crypto/rand -- per docs/design.md §1.6: "Stdlib
// only... adding a third-party TOTP library is not on the table."
//
// Copied from mikroview's internal/auth/totp.go (the algorithm: secret
// generation, the enrolment URI, code generation and verification) and
// internal/auth/store.go (the four Store methods that wire it to a
// User: SetPendingTOTPSecret, ConfirmTOTP, VerifyAndRecordTOTP,
// ClearTOTP -- docs/design.md §1.3). Two divergences:
//
//   - TOTPEnrollmentURI takes a productName parameter instead of
//     mikroview's hard-coded "MikroView" label. docs/design.md §1.5
//     calls this out explicitly as a string that "must not leak into
//     birdcage" -- gate.Config.ProductName exists for exactly this
//     call.
//   - VerifyAndRecordTOTP is the only login-time entry point; mikroview's
//     separate RecordTOTPCounter (call VerifyTOTP, then record what
//     matched, as two store calls) is not carried over. mikroview added
//     VerifyAndRecordTOTP after finding that two-call version let two
//     concurrent submissions of the same code both verify against the
//     same not-yet-advanced counter and both win a session -- doing both
//     under one lock closes it. There is no reason for a new caller to
//     have the unsafe two-call option available at all.
//   - There is no Store.HasActiveTOTP(userID) convenience wrapper. A
//     caller calls the User method on what Get or List returns: List
//     blanks TOTPSecret, but HasActiveTOTP still answers truly on the
//     blanked copy (see User.totpSecretBlanked), so listing accounts
//     with their authenticator-app status needs no Get per account.
package gauntlet

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// totpSecretLen is 20 bytes (160 bits) -- RFC 4226 §4's recommended
	// shared-secret length for HMAC-SHA1, and conveniently also the
	// exact size of a SHA-1 output.
	totpSecretLen = 20
	// totpStep is RFC 6238's default time step. Every authenticator app
	// in practice assumes 30 seconds; a gauntlet-specific value would
	// just make this account impossible to enrol in a normal app.
	totpStep = 30 * time.Second
	// totpDigits is the code length every consumer authenticator app
	// displays (RFC 6238's own worked examples use 8; this is 6).
	totpDigits = 6
	// totpWindow is how many steps on either side of the current one a
	// submitted code is checked against: the current step and ±1,
	// rejecting ±2. The allowance exists for clock drift and for the
	// second or two between a code being read off a phone and typed in;
	// it is deliberately small so a stolen code has a short shelf life.
	totpWindow = 1
)

var (
	// ErrTOTPAlreadyActive is returned by SetPendingTOTPSecret when the
	// account already holds a confirmed factor. Enrolling again would
	// silently replace a factor its owner is still using -- and if they
	// abandoned the new enrolment halfway, HasActiveTOTP would keep
	// answering true against a secret their authenticator app no longer
	// holds, locking them out of their own account. Turning a factor off
	// is its own deliberate step (ClearTOTP), never a side effect of
	// starting a new one.
	ErrTOTPAlreadyActive = errors.New("gauntlet: this account already has an authenticator app -- remove it before enrolling another")
	// ErrNoPendingTOTP is returned by ConfirmTOTP when there is no
	// unconfirmed secret to confirm: either enrolment never started, or
	// it already finished. Confirming is what activates a factor, so
	// there is nothing safe to do with a code that arrives without one.
	ErrNoPendingTOTP = errors.New("gauntlet: no authenticator-app enrolment is waiting to be confirmed")
	// ErrNoTOTP is returned by ClearTOTP when the account has no
	// authenticator app to remove: no secret, pending or confirmed, and
	// none on hold. Nothing is written. A caller tells this apart from a
	// removal so that a second "Disable" click does not audit, notify or
	// sign anyone out over a change that never happened.
	ErrNoTOTP = errors.New("gauntlet: this account has no authenticator app")
)

// GenerateTOTPSecret returns a fresh 20-byte shared secret from
// crypto/rand, suitable for both computing codes (GenerateTOTPCode,
// VerifyTOTP) and building an enrolment URI (TOTPEnrollmentURI, via
// EncodeTOTPSecret). The caller is responsible for persisting it, via
// SetPendingTOTPSecret -- this function itself holds no state.
func GenerateTOTPSecret() ([]byte, error) {
	b := make([]byte, totpSecretLen)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("gauntlet: generate TOTP secret: %w", err)
	}
	return b, nil
}

// EncodeTOTPSecret base32-encodes secret with RFC 4648's standard
// alphabet and no padding -- the form both an otpauth:// URI and
// VerifyTOTP expect, and the form authenticator apps show when a secret
// is entered by hand instead of scanned.
func EncodeTOTPSecret(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// DecodeTOTPSecret reverses EncodeTOTPSecret. It also tolerates a
// lower-case, padded, or space-separated secret -- forms a person might
// paste in by hand, or that another implementation's encoder produces
// -- so a secret round-trips regardless of how it is typed. Anything
// that still fails to decode, or decodes to zero bytes, is an error: an
// empty secret is not a usable one.
func DecodeTOTPSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	s = strings.TrimRight(s, "=")
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("gauntlet: malformed TOTP secret: %w", err)
	}
	if len(b) == 0 {
		return nil, errors.New("gauntlet: empty TOTP secret")
	}
	return b, nil
}

// totpLabelEscape percent-encodes every byte of s outside RFC 3986's
// "unreserved" set (letters, digits, '-', '_', '.', '~').
//
// url.PathEscape is deliberately not used here: it treats ':' and '@'
// as safe in a path segment (RFC 3986's pchar allows them), which is
// exactly wrong for this one field. The otpauth:// label is
// "Issuer:AccountName" with a single literal colon as the separator
// (Google's "Key URI Format", the de facto standard every authenticator
// app follows -- RFC 6238 itself defines no URI). If a username
// contained its own colon, PathEscape would pass it through unescaped
// and an app parsing the label would no longer agree with us on where
// the issuer ends and the account name begins. Escaping to the stricter
// unreserved set removes that ambiguity for any character, not just
// ':' -- including a space, which some scanners fail to turn back into
// a space if it arrives as PathEscape's '%20' mixed with an unescaped
// ':' nearby, and multi-byte UTF-8, which this walks and escapes one
// byte at a time.
func totpLabelEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// TOTPEnrollmentURI builds the otpauth:// URI an authenticator app
// scans (as a QR code) or accepts pasted, for a fresh enrolment of
// username against secret:
// otpauth://totp/<productName>:<username>?secret=…&issuer=<productName>.
//
// productName replaces mikroview's hard-coded "MikroView" -- see this
// file's package comment. productName and username are both escaped by
// totpLabelEscape rather than left to a generic URL escaper, so a name
// holding a space or a colon still produces a URI an app parses the way
// we intend -- see that function's comment.
//
// The query is built by hand, not with url.Values: url.Values encodes a
// space as '+', the HTML form convention, which the Key URI format does
// not define, so an issuer of "Home Router" reached apps as
// "Home+Router" or failed to scan at all. totpLabelEscape writes a
// space as %20, which every app decodes. The secret needs no escaping:
// base32 is letters and digits only.
func TOTPEnrollmentURI(productName, username string, secret []byte) string {
	issuer := totpLabelEscape(productName)
	label := issuer + ":" + totpLabelEscape(username)
	return "otpauth://totp/" + label + "?secret=" + EncodeTOTPSecret(secret) + "&issuer=" + issuer
}

// totpCounter returns the RFC 6238 time-step counter for t: the number
// of step-sized intervals since the Unix epoch. Both sides of the
// protocol hash this counter instead of t itself, which is what makes a
// code valid for a whole step rather than one instant, and lets the two
// clocks disagree by anything under a step and still agree on the
// counter.
//
// Clamped at zero for any t before the epoch, so a caller passing a
// zero time.Time (Go's time.Time zero value, year 1) cannot underflow
// the uint64 that carries it everywhere else in this file.
func totpCounter(t time.Time, step time.Duration) uint64 {
	secs := t.Unix()
	if secs < 0 {
		secs = 0
	}
	return uint64(secs) / uint64(step/time.Second)
}

// GenerateTOTPCode returns the totpDigits-digit decimal code for secret
// at counter -- RFC 4226 §5.3's HOTP algorithm (HMAC-SHA1 of the
// big-endian counter, then dynamic truncation), which RFC 6238 layers
// TOTP on top of by feeding it totpCounter's output instead of an
// incrementing counter.
//
// Takes the already-decoded secret, not the base32 string a person or a
// store would hold -- DecodeTOTPSecret sits between the two, and is
// where a malformed secret is caught. This function has no error case
// of its own: crypto/hmac never fails, including for a zero-length key,
// so returning an error here would be dead code every caller still has
// to handle.
func GenerateTOTPCode(secret []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation, RFC 4226 §5.3: the low nibble of the last byte
	// picks a 4-byte window (0..15, and sum is 20 bytes long, so
	// offset+4 never runs past the end); the top bit of that window is
	// cleared to keep the result a positive 31-bit int.
	offset := sum[len(sum)-1] & 0x0f
	code := uint32(sum[offset]&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	mod := uint32(1)
	for range totpDigits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, code%mod)
}

// VerifyTOTP reports whether code is currently valid for encodedSecret
// (as produced by EncodeTOTPSecret) at now, within totpWindow steps
// either side, and has not already been consumed.
//
// lastUsedCounter is the counter of the most recently accepted code for
// this secret, or 0 if none has ever been accepted -- 0 itself can never
// be a real match for any date after 1970-01-01T00:00:30Z, so it is a
// safe "never used" sentinel, the same way Token.LastUsedAt's zero
// time.Time means "never used". Any candidate counter <= lastUsedCounter
// is skipped even when its code is correct: that is the replay guard,
// enforced here rather than at each call site, so a caller cannot
// forget it. On acceptance, matchedCounter is the counter that matched;
// VerifyAndRecordTOTP persists it as the new lastUsedCounter, which is
// what makes the guard advance instead of permanently wedging the
// account once a code is used.
//
// A malformed or empty encodedSecret, or a code that is not exactly
// totpDigits decimal digits, is refused (ok == false) rather than
// causing an error or a panic -- there is nothing a caller can usefully
// do differently, the same stance VerifyPassword takes for a malformed
// hash.
func VerifyTOTP(encodedSecret, code string, now time.Time, lastUsedCounter uint64) (matchedCounter uint64, ok bool) {
	if len(code) != totpDigits {
		return 0, false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return 0, false
		}
	}

	secret, err := DecodeTOTPSecret(encodedSecret)
	if err != nil {
		return 0, false
	}

	current := totpCounter(now, totpStep)
	for d := -totpWindow; d <= totpWindow; d++ {
		var c uint64
		if d < 0 {
			if uint64(-d) > current {
				continue // would underflow: before the epoch's first step
			}
			c = current - uint64(-d)
		} else {
			c = current + uint64(d)
		}
		if c <= lastUsedCounter {
			continue // already spent (or older than what was spent)
		}
		want := GenerateTOTPCode(secret, c)
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return c, true
		}
	}
	return 0, false
}

// SetPendingTOTPSecret is SetPendingTOTPSecretAt at time.Now(), for
// callers written before the pending secret had a lifetime (#58).
func (s *Store) SetPendingTOTPSecret(userID, encodedSecret string) error {
	return s.SetPendingTOTPSecretAt(userID, encodedSecret, time.Now())
}

// SetPendingTOTPSecretAt stores a freshly generated, not-yet-confirmed
// secret for userID, set at now, replacing any earlier enrolment that
// was started and abandoned. The factor is not active afterwards:
// confirming it (ConfirmTOTP, or HoldFirstTOTP then
// ConfirmHeldEnrolment for an account's first factor) is what activates
// it, so an enrolment interrupted at the QR code leaves the account
// signing in exactly as it did before. It can be confirmed for
// TOTPPendingLifetime after now (#58), and is treated as absent after
// that.
//
// Refuses with ErrTOTPAlreadyActive when a confirmed factor is already
// in place -- see that error for why replacing one silently is a
// lockout waiting to happen -- and with ErrEnrolmentHeld while another
// enrolment is on hold (one at a time). An expired hold is deleted
// first.
//
// The replay counter is reset alongside the secret. A counter is only
// meaningful against the secret it was accepted for: carried over to a
// new secret it would refuse that secret's early codes for as long as
// the old factor had been in use, which reads to the person enrolling
// as an authenticator app that simply does not work.
func (s *Store) SetPendingTOTPSecretAt(userID, encodedSecret string, now time.Time) error {
	if !s.Persisted() {
		return ErrNotPersisted
	}
	s.reloadIfStale()

	// An enrolment that only exists in memory must not be reported as
	// started: the caller is about to show a QR code the user scans into
	// their phone, and a restart before the next good write would leave
	// the store with no secret to confirm that app's codes against.
	// mutate installs the secret only once it is saved.
	return s.mutate(func(st *storeState) error {
		u, ok := st.byID[userID]
		if !ok {
			return ErrUserNotFound
		}
		dropExpiredHold(u, now)
		if u.HasActiveTOTP() {
			return ErrTOTPAlreadyActive
		}
		if u.HeldEnrolment != nil {
			return ErrEnrolmentHeld
		}
		u.TOTPSecret = encodedSecret
		u.TOTPLastCounter = 0
		u.TOTPPendingSince = now
		return nil
	})
}

// ConfirmTOTP activates the pending secret for userID, recording when
// its owner proved they could produce a code from it and the counter of
// the code that proved it. Passing the matching counter rather than
// starting the guard at zero closes the obvious replay: the code just
// used to enrol must not also work as the first sign-in.
//
// Returns ErrNoPendingTOTP when there is nothing unconfirmed to
// activate, which covers "enrolment never started", "already confirmed"
// and "set more than TOTPPendingLifetime before confirmedAt" -- none is
// a state where accepting a code should change anything -- and
// ErrEnrolmentHeld while an enrolment is on hold.
//
// This makes the app live at once, with no recovery codes: what gate
// does for an account that already has a second factor (a passkey),
// whose codes stand. An account's first factor is held instead, with
// its codes, until confirmed (HoldFirstTOTP, ConfirmHeldEnrolment;
// #58). Verifying the code is the caller's job (VerifyTOTP above); this
// only records the outcome.
func (s *Store) ConfirmTOTP(userID string, confirmedAt time.Time, matchedCounter uint64) error {
	if !s.Persisted() {
		return ErrNotPersisted
	}
	s.reloadIfStale()

	// A confirmation that only exists in memory must not be reported as
	// done: the caller is about to tell its user the factor is on and
	// hand them recovery codes, and a restart would drop the account
	// back to password-only underneath that claim. mutate installs it
	// only once it is saved.
	return s.mutate(func(st *storeState) error {
		u, ok := st.byID[userID]
		if !ok {
			return ErrUserNotFound
		}
		dropExpiredHold(u, confirmedAt)
		if u.HeldEnrolment != nil {
			return ErrEnrolmentHeld
		}
		if !u.TOTPPending(confirmedAt) {
			return ErrNoPendingTOTP
		}
		u.TOTPConfirmedAt = confirmedAt
		u.TOTPLastCounter = matchedCounter
		u.TOTPPendingSince = time.Time{}
		return nil
	})
}

// VerifyAndRecordTOTP checks code against userID's active TOTP secret
// and, only when it matches, advances the replay counter -- both under
// the same lock acquisition. This is deliberately the only login-time
// entry point (see this file's package comment): checking with
// VerifyTOTP and recording separately as two calls leaves a window
// where two concurrent submissions of the same code both verify against
// the same not-yet-advanced counter and both win a session. Doing both
// under one lock closes it -- whichever request gets the lock second
// sees the first request's already-advanced counter, so VerifyTOTP
// itself (its own doc comment: "any candidate counter <= lastUsedCounter
// is skipped even when its code is correct") refuses the replay.
//
// ok is true only when code matched and the counter's advance was
// saved. A match whose advance could not be saved is refused -- ok
// false, with the error -- rather than let in on the strength of the
// match: the advance is what stops the same code winning a second
// login, and one that lives nowhere (the failed attempt is dropped, not
// kept in memory) leaves the code live for whoever else holds it. That
// is the stance the reset-code login (Authenticate) and BurnRecoveryCode
// take for their spends. It replaces mikroview's RecordTOTPCounter
// stance, which granted the login and logged the failure: under the
// replay loop a match can be made against memory the document has
// moved past, so a result from a run that was not saved is not one to
// trust. Nothing is lost by refusing -- the person enters the next code
// once the backend answers again.
func (s *Store) VerifyAndRecordTOTP(userID, code string, now time.Time) (ok bool, err error) {
	if !s.Persisted() {
		return false, ErrNotPersisted
	}
	s.reloadIfStale()

	// The code is checked inside the op, against the counter in the
	// document being saved: a replay after another process's write --
	// another login with the same code -- must see that counter and
	// refuse the code, not advance past it a second time.
	err = s.mutate(func(st *storeState) error {
		ok = false
		u, found := st.byID[userID]
		if !found {
			return ErrUserNotFound
		}
		// Only a confirmed secret is a factor. A pending one (set by
		// SetPendingTOTPSecret, never confirmed) is mid-setup, and an
		// account that reaches this step through another factor -- a
		// passkey -- must not be let in by a code from it: whoever
		// started that enrolment and stopped would hold a working
		// second factor the account owner never activated.
		if !u.HasActiveTOTP() {
			return errNoChange
		}
		matched, matchedOK := VerifyTOTP(u.TOTPSecret, code, now, u.TOTPLastCounter)
		if !matchedOK {
			return errNoChange
		}
		u.TOTPLastCounter = matched
		ok = true
		return nil
	})
	if err != nil {
		// ok may be true from a run the loop then threw away -- the
		// first, against memory, before a replay was refused. A result
		// is only the final run's when mutate returns nil.
		return false, err
	}
	return ok, nil
}

// ClearTOTP removes userID's authenticator-app factor entirely: the
// secret, its confirmation and the replay counter, always. The
// account's recovery codes go the same way, but only if this was the
// account's last second factor: they are shared between the
// authenticator app and passkeys (docs/design.md §1.6), so stripping
// them here while a passkey remains would silently orphan that
// passkey's fallback. See DeletePasskey/ClearPasskeys (passkeys.go) for
// the same rule applied from the passkey side. An authenticator app on
// hold (#58) goes too, with the codes held for it; a held passkey is
// left alone.
//
// Returns ErrNoTOTP, writing nothing, when there is no authenticator app
// to remove.
func (s *Store) ClearTOTP(userID string) error {
	if !s.Persisted() {
		return ErrNotPersisted
	}
	s.reloadIfStale()

	// A clear that only exists in memory must not be reported as done:
	// the caller tells its operator the authenticator app is off, and a
	// restart before the next good write would silently bring back the
	// old secret, counter and (if it was cleared) recovery codes
	// underneath that claim. mutate installs it only once it is saved.
	return s.mutate(func(st *storeState) error {
		u, ok := st.byID[userID]
		if !ok {
			return ErrUserNotFound
		}
		heldTOTP := u.HeldEnrolment != nil && u.HeldEnrolment.Kind == HeldFactorTOTP
		// Not errNoChange, which mutate answers with nil: the caller
		// must hear that nothing was removed, not a success.
		if u.TOTPSecret == "" && !heldTOTP {
			return ErrNoTOTP
		}
		if heldTOTP {
			u.HeldEnrolment = nil
		}
		clearTOTPFields(u)
		if len(u.Passkeys) == 0 {
			u.RecoveryCodes = nil
		}
		return nil
	})
}
