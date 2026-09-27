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
//     birdcage" -- gate.Config gains ProductName for exactly this call,
//     a later slice (G6).
//   - VerifyAndRecordTOTP is the only login-time entry point; mikroview's
//     separate RecordTOTPCounter (call VerifyTOTP, then record what
//     matched, as two store calls) is not carried over. mikroview added
//     VerifyAndRecordTOTP after finding that two-call version let two
//     concurrent submissions of the same code both verify against the
//     same not-yet-advanced counter and both win a session -- doing both
//     under one lock closes it. There is no reason for a new caller to
//     have the unsafe two-call option available at all.
//   - There is no Store.HasActiveTOTP(userID) convenience wrapper.
//     Store.Get already returns an unblanked *User (unlike List), so a
//     caller checking activity calls Get then the User method directly;
//     mikroview's version predates that shape and is now redundant with
//     it.
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
	"net/url"
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
// file's package comment. username is escaped by totpLabelEscape rather
// than left to a generic URL escaper, specifically so a username
// holding a space or a colon still produces a URI an app parses the way
// we intend -- see that function's comment. secret and productName go
// through url.Values, which escapes the query string correctly on its
// own.
func TOTPEnrollmentURI(productName, username string, secret []byte) string {
	label := productName + ":" + totpLabelEscape(username)
	v := url.Values{}
	v.Set("secret", EncodeTOTPSecret(secret))
	v.Set("issuer", productName)
	return "otpauth://totp/" + label + "?" + v.Encode()
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

// SetPendingTOTPSecret stores a freshly generated, not-yet-confirmed
// secret for userID, replacing any earlier enrolment that was started
// and abandoned. The factor is not active afterwards: ConfirmTOTP is
// what activates it, so an enrolment interrupted at the QR code leaves
// the account signing in exactly as it did before.
//
// Refuses with ErrTOTPAlreadyActive when a confirmed factor is already
// in place -- see that error for why replacing one silently is a
// lockout waiting to happen.
//
// The replay counter is reset alongside the secret. A counter is only
// meaningful against the secret it was accepted for: carried over to a
// new secret it would refuse that secret's early codes for as long as
// the old factor had been in use, which reads to the person enrolling
// as an authenticator app that simply does not work.
func (s *Store) SetPendingTOTPSecret(userID, encodedSecret string) error {
	if !s.Persisted() {
		return ErrNotPersisted
	}
	s.reloadIfStale()

	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.byID[userID]
	if !ok {
		return ErrUserNotFound
	}
	if u.HasActiveTOTP() {
		return ErrTOTPAlreadyActive
	}

	prevSecret := u.TOTPSecret
	prevCounter := u.TOTPLastCounter

	u.TOTPSecret = encodedSecret
	u.TOTPLastCounter = 0
	if err := s.tryPersistLocked(); err != nil {
		// An enrolment that only exists in memory must not be reported
		// as started: the caller is about to show a QR code the user
		// scans into their phone, and a restart before the next good
		// write would leave the store with no secret to confirm that
		// app's codes against.
		u.TOTPSecret = prevSecret
		u.TOTPLastCounter = prevCounter
		return fmt.Errorf("saving accounts: %w", err)
	}
	return nil
}

// ConfirmTOTP activates the pending secret for userID, recording when
// its owner proved they could produce a code from it and the counter of
// the code that proved it. Passing the matching counter rather than
// starting the guard at zero closes the obvious replay: the code just
// used to enrol must not also work as the first sign-in.
//
// Returns ErrNoPendingTOTP when there is nothing unconfirmed to
// activate, which covers both "enrolment never started" and "already
// confirmed" -- neither is a state where accepting a code should change
// anything.
//
// Verifying the code is the caller's job (VerifyTOTP above); this only
// records the outcome. The recovery codes that accompany a confirmed
// factor are minted separately, by GenerateRecoveryCodes/
// GenerateRecoveryCodesIfAbsent (recoverycodes.go).
func (s *Store) ConfirmTOTP(userID string, confirmedAt time.Time, matchedCounter uint64) error {
	if !s.Persisted() {
		return ErrNotPersisted
	}
	s.reloadIfStale()

	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.byID[userID]
	if !ok {
		return ErrUserNotFound
	}
	if u.TOTPSecret == "" || !u.TOTPConfirmedAt.IsZero() {
		return ErrNoPendingTOTP
	}

	prevConfirmedAt := u.TOTPConfirmedAt
	prevCounter := u.TOTPLastCounter

	u.TOTPConfirmedAt = confirmedAt
	u.TOTPLastCounter = matchedCounter
	if err := s.tryPersistLocked(); err != nil {
		// A confirmation that only exists in memory must not be
		// reported as done: the caller is about to tell its user the
		// factor is on and hand them recovery codes, and a restart
		// would drop the account back to password-only underneath that
		// claim.
		u.TOTPConfirmedAt = prevConfirmedAt
		u.TOTPLastCounter = prevCounter
		return fmt.Errorf("saving accounts: %w", err)
	}
	return nil
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
// ok reports whether code matched; err is only ever a persistence
// failure on a match -- the code that just matched earned the login
// regardless of whether the counter's advance made it to disk, the same
// degraded-but-not-locked-out stance mikroview's RecordTOTPCounter took.
func (s *Store) VerifyAndRecordTOTP(userID, code string, now time.Time) (ok bool, err error) {
	if !s.Persisted() {
		return false, ErrNotPersisted
	}
	s.reloadIfStale()

	s.mu.Lock()
	defer s.mu.Unlock()

	u, found := s.byID[userID]
	if !found {
		return false, ErrUserNotFound
	}

	matched, matchedOK := VerifyTOTP(u.TOTPSecret, code, now, u.TOTPLastCounter)
	if !matchedOK {
		return false, nil
	}

	prevCounter := u.TOTPLastCounter
	u.TOTPLastCounter = matched
	if err := s.tryPersistLocked(); err != nil {
		u.TOTPLastCounter = prevCounter
		return true, fmt.Errorf("saving accounts: %w", err)
	}
	return true, nil
}

// ClearTOTP removes userID's authenticator-app factor entirely: the
// secret, its confirmation and the replay counter, always. The
// account's recovery codes go the same way, but only if this was the
// account's last second factor: they are shared between the
// authenticator app and passkeys (docs/design.md §1.6), so stripping
// them here while a passkey remains would silently orphan that
// passkey's fallback. See DeletePasskey/ClearPasskeys (passkeys.go) for
// the same rule applied from the passkey side.
func (s *Store) ClearTOTP(userID string) error {
	if !s.Persisted() {
		return ErrNotPersisted
	}
	s.reloadIfStale()

	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.byID[userID]
	if !ok {
		return ErrUserNotFound
	}

	prevSecret := u.TOTPSecret
	prevConfirmedAt := u.TOTPConfirmedAt
	prevCounter := u.TOTPLastCounter
	prevCodes := u.RecoveryCodes

	u.TOTPSecret = ""
	u.TOTPConfirmedAt = time.Time{}
	u.TOTPLastCounter = 0
	if len(u.Passkeys) == 0 {
		u.RecoveryCodes = nil
	}
	if err := s.tryPersistLocked(); err != nil {
		// A clear that only exists in memory must not be reported as
		// done: the caller tells its operator the authenticator app is
		// off, and a restart before the next good write would silently
		// bring back the old secret, counter and (if it was cleared)
		// recovery codes underneath that claim.
		u.TOTPSecret = prevSecret
		u.TOTPConfirmedAt = prevConfirmedAt
		u.TOTPLastCounter = prevCounter
		u.RecoveryCodes = prevCodes
		return fmt.Errorf("saving accounts: %w", err)
	}
	return nil
}
