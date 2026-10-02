// Copied from mikroview's internal/auth/recoverycodes.go, names kept
// (docs/design.md §1.3). Recovery codes are the fallback for signing in
// when the authenticator app itself is unavailable -- phone lost, app
// uninstalled, TOTP secret unreachable. Ten are minted together, each
// usable exactly once, and never stored anywhere but hashed: this store
// never again has enough information to show one back to its owner,
// only to check a guess against it. They are shared between the
// authenticator app and passkeys (docs/design.md §1.6): minted on
// whichever factor activates first, cleared only when the account's
// last second factor of either kind goes -- see ClearTOTP (totp.go) and
// DeletePasskey/ClearPasskeys (passkeys.go), which own that clearing
// rule from each side.
package gauntlet

import (
	"crypto/rand"
	"strings"
	"time"
)

const (
	// recoveryCodeCount is how many codes GenerateRecoveryCodes mints,
	// and how many User.RecoveryCodes holds afterward.
	recoveryCodeCount = 10
	// recoveryCodeAlphabet reuses the reset code's alphabet: no 0/O, no
	// 1/I/l, so a code copied off a screen (or read aloud) has no
	// ambiguous character.
	recoveryCodeAlphabet = resetCodeAlphabet
	// recoveryCodeLength is characters per code, excluding the grouping
	// dash. Ten characters over the 32-character alphabet above is 50
	// bits -- ample for a hashed, single-use, backup-only credential a
	// person copies out of a list once and keeps offline; the reset
	// code is longer only because it stands in for a whole password
	// indefinitely, while a recovery code is checked once and then
	// dead.
	recoveryCodeLength = 10
	// recoveryCodeGroup is how many characters sit between dashes in the
	// form shown to a person: xxxxx-xxxxx.
	recoveryCodeGroup = 5
)

// RecoveryCode is one hashed recovery code, held on User.RecoveryCodes.
// Hash is Argon2id via HashPassword -- the same treatment a password
// gets -- never the plain code, which exists in clear only for the
// instant GenerateRecoveryCodes/GenerateRecoveryCodesIfAbsent returns it
// to its caller. UsedAt is zero until BurnRecoveryCode spends it, and is
// never cleared afterward: a spent code stays spent.
type RecoveryCode struct {
	Hash   string    `json:"hash"`
	UsedAt time.Time `json:"usedAt,omitzero"`
}

// newRecoveryCode returns a fresh code in its canonical (dashless) form
// -- the form that gets hashed, mirroring newResetCode.
func newRecoveryCode() string {
	b := make([]byte, recoveryCodeLength)
	if _, err := rand.Read(b); err != nil {
		// Same stance as newID/newResetCode: a CSPRNG that cannot
		// produce bytes is not a condition to degrade from gracefully
		// when the output is about to stand in for a login credential.
		panic("gauntlet: crypto/rand unavailable: " + err.Error())
	}
	out := make([]byte, recoveryCodeLength)
	for i, v := range b {
		out[i] = recoveryCodeAlphabet[v&31]
	}
	return string(out)
}

// FormatRecoveryCode groups a canonical code for display: xxxxx-xxxxx.
// The dash is presentation only -- NormaliseRecoveryCode strips it again
// on the way back in.
func FormatRecoveryCode(code string) string {
	var b strings.Builder
	for i, r := range code {
		if i > 0 && i%recoveryCodeGroup == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// NormaliseRecoveryCode turns whatever a person typed into the canonical
// form a stored hash was computed over: upper case, with dashes, spaces
// and tabs they may have copied (or added themselves) removed. Mirrors
// NormaliseResetCode exactly, for the same reasons.
func NormaliseRecoveryCode(typed string) string {
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

// GenerateRecoveryCodes mints a fresh set of ten single-use codes for
// userID, replacing any set already on the account, and returns them in
// clear -- grouped for display -- exactly once. The caller must show
// them to the user immediately and must never itself persist the
// returned strings; only the hashes this writes to the store survive.
//
// now is unused: a recovery code records no issue time. It stays so the
// signature matches mikroview's and gauntlet v0.1.0's.
func (s *Store) GenerateRecoveryCodes(userID string, now time.Time) ([]string, error) {
	if !s.Persisted() {
		return nil, ErrNotPersisted
	}

	// Hashing happens before the lock, same reasoning as createAccount
	// and IssueResetCode: HashPassword is ~100ms of Argon2id by design,
	// and ten of them held under the store's write lock would serialize
	// every reader for the better part of a second.
	clear := make([]string, recoveryCodeCount)
	hashed := make([]RecoveryCode, recoveryCodeCount)
	for i := range hashed {
		code := newRecoveryCode()
		hash, err := HashPassword(code)
		if err != nil {
			return nil, err
		}
		clear[i] = FormatRecoveryCode(code)
		hashed[i] = RecoveryCode{Hash: hash}
	}

	s.reloadIfStale()

	// A set that only exists in memory must not be reported as issued:
	// the caller is about to show these to the user as their only way
	// back in, and a restart before the next good write would revert to
	// whatever set (if any) existed before, leaving the shown codes
	// unable to verify against anything. mutate installs the set only
	// once it is saved.
	err := s.mutate(func(st *storeState) error {
		u, ok := st.byID[userID]
		if !ok {
			return ErrUserNotFound
		}
		u.RecoveryCodes = hashed
		return nil
	})
	if err != nil {
		return nil, err
	}
	return clear, nil
}

// GenerateRecoveryCodesIfAbsent is GenerateRecoveryCodes' mint-if-absent
// sibling, for a caller that must never replace a set an earlier
// first-factor confirmation already minted and showed its user (e.g.
// confirming TOTP after a passkey already minted the shared set, or the
// reverse). Checking len(u.RecoveryCodes) on a snapshot taken before the
// call and then calling GenerateRecoveryCodes unconditionally would
// leave a window where two concurrent first enrolments -- two browser
// tabs, or a TOTP confirm racing a passkey registration -- both see no
// codes yet and both mint, the second silently invalidating whatever the
// first had just shown. Checking and minting under the same lock closes
// it.
//
// alreadyIssued is true, and codes nil, when the account already held a
// set by the time the lock was acquired -- including one minted by a
// concurrent call to this same method that got there first. codes is
// the freshly minted set, in clear, exactly once, only when
// alreadyIssued is false.
//
// The ten codes are hashed before the write lock is taken, the same
// trade GenerateRecoveryCodes makes and for the same reason. The usual
// alreadyIssued case is answered first, under the read lock, so it
// costs no hashing at all; only a call that loses a race to a
// concurrent first enrolment hashes ten codes and throws them away.
//
// now is unused, as in GenerateRecoveryCodes.
func (s *Store) GenerateRecoveryCodesIfAbsent(userID string, now time.Time) (codes []string, alreadyIssued bool, err error) {
	if !s.Persisted() {
		return nil, false, ErrNotPersisted
	}

	s.reloadIfStale()

	// A fast path, not the correctness boundary: the same check is made
	// again below with the write lock held, which is what stops two
	// concurrent first enrolments both minting.
	s.mu.RLock()
	u, ok := s.byID[userID]
	has := ok && len(u.RecoveryCodes) > 0
	s.mu.RUnlock()
	if !ok {
		return nil, false, ErrUserNotFound
	}
	if has {
		return nil, true, nil
	}

	clear := make([]string, recoveryCodeCount)
	hashed := make([]RecoveryCode, recoveryCodeCount)
	for i := range hashed {
		code := newRecoveryCode()
		hash, err := HashPassword(code)
		if err != nil {
			return nil, false, err
		}
		clear[i] = FormatRecoveryCode(code)
		hashed[i] = RecoveryCode{Hash: hash}
	}

	s.reloadIfStale()

	// The decision is made again inside the op, against the document
	// being saved: a replay after another process minted a set -- the
	// same person's other tab, through a CLI or a second server -- must
	// find that set and leave it alone, not replace codes its user has
	// already been shown.
	var issued bool
	err = s.mutate(func(st *storeState) error {
		u, ok := st.byID[userID]
		if !ok {
			return ErrUserNotFound
		}
		if len(u.RecoveryCodes) > 0 {
			issued = true
			return errNoChange
		}
		issued = false
		u.RecoveryCodes = hashed
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	if issued {
		return nil, true, nil
	}
	return clear, false, nil
}

// BurnRecoveryCode verifies code against userID's unused recovery codes
// and, on a match, marks that one used so it cannot be redeemed again.
//
// Returns false, not an error, for a wrong code or one already used;
// callers must not distinguish those to whoever is attempting login, the
// same reasoning ErrInvalidCredentials documents for a bad password.
// ErrUserNotFound is returned only for an unknown userID -- a caller
// error, since a login flow only reaches this after already resolving
// the account.
//
// Every unused code is checked even after a match is found, rather than
// stopping at the first: the time a check takes should not tell an
// observer which of the ten codes (by position) just matched.
//
// Those checks are up to ten Argon2id comparisons, so they run against a
// snapshot taken under the read lock, not under the write lock -- same
// reasoning as Authenticate. The write lock is taken only to spend the
// matched code, and re-checks it first: a concurrent burn of the same
// code, or a fresh set replacing this one, must win over a match made
// against the snapshot.
func (s *Store) BurnRecoveryCode(userID, code string, now time.Time) (bool, error) {
	normalised := NormaliseRecoveryCode(code)

	s.reloadIfStale()

	s.mu.RLock()
	u, ok := s.byID[userID]
	var snapshot []RecoveryCode
	if ok {
		snapshot = append(snapshot, u.RecoveryCodes...)
	}
	s.mu.RUnlock()
	if !ok {
		return false, ErrUserNotFound
	}

	matchHash := ""
	for _, rc := range snapshot {
		if !rc.UsedAt.IsZero() {
			continue
		}
		if VerifyPassword(normalised, rc.Hash) {
			matchHash = rc.Hash
		}
	}
	if matchHash == "" {
		return false, nil
	}

	// The spend is decided inside the op, against the document being
	// saved, and the code found there by its hash, not its position:
	// a concurrent burn of the same code (in this process or, on a
	// replay, another one), or a fresh set replacing this one, must win
	// over a match made against the snapshot. Each hash carries its own
	// salt, so no two codes share one.
	//
	// A spend that only lands in memory is undone by a restart, and the
	// code is live again for whoever presented it -- so a spend that
	// cannot be saved refuses the login, the same stance Authenticate's
	// reset-code path takes. mutate installs it only once it is saved.
	var burned bool
	err := s.mutate(func(st *storeState) error {
		burned = false
		u, ok := st.byID[userID]
		if !ok {
			return ErrUserNotFound
		}
		matchIdx := -1
		for i, rc := range u.RecoveryCodes {
			if rc.Hash == matchHash && rc.UsedAt.IsZero() {
				matchIdx = i
			}
		}
		if matchIdx == -1 {
			return errNoChange
		}
		// In place: the account the op is handed is mutate's deep copy,
		// so no reader's copy of the User shares this slice.
		u.RecoveryCodes[matchIdx].UsedAt = now
		burned = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return burned, nil
}
