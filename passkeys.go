// Copied from mikroview's internal/auth/passkeys.go, names kept
// (docs/design.md §1.3). This file is the store-layer half only -- it
// holds what a WebAuthn registration or login ceremony produced, and
// never performs the ceremony itself. That work (talking to
// go-webauthn, building the RP config, sealing session data into
// cookies) is deferred to the gauntlet/passkey package (G8, per
// docs/design.md §1.6); this package does not import go-webauthn and
// must not gain a reason to. Passkey.Transports and Passkey.Flags below
// reproduce the shapes of two go-webauthn types for exactly that
// reason -- see their doc comments.
//
// One divergence from mikroview: RecordPasskeyAssertion, the two-step
// "verify with go-webauthn, then record" method, is not carried over.
// Only RecordPasskeyAssertionIfFresh is (docs/design.md §1.3) -- the
// version mikroview added after finding that the two-step form let two
// concurrent submissions of the same assertion both clear against the
// same not-yet-advanced stored count and both win a session, the
// passkey shape of totp.go's VerifyAndRecordTOTP race. There is no
// reason for a new caller to have the unsafe two-step option. Likewise
// not carried over: AnyPasskeysExist, mikroview's own start-up check for
// whether its RelyingParty configuration can still serve existing
// credentials -- an application concern once the passkey ceremony
// exists (G8), not this package's.
package gauntlet

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	// maxPasskeysPerAccount bounds AddPasskey -- see
	// ErrPasskeyLimitReached. Ten is generous for "a phone, a security
	// key, a couple of spares" while still keeping the list an account
	// owner has to review, to know what can sign in as them, from
	// growing without bound.
	maxPasskeysPerAccount = 10
	// maxPasskeyNameLength bounds a passkey's display name in runes --
	// generous for "YubiKey 5C NFC (backup)" while keeping the list
	// readable and the stored document small.
	maxPasskeyNameLength = 64
)

var (
	// ErrPasskeyNotFound is returned by RenamePasskey, DeletePasskey and
	// RecordPasskeyAssertionIfFresh when credID matches none of userID's
	// stored passkeys -- covers both "never existed" and "already
	// removed"; a caller has no legitimate reason to tell those apart.
	ErrPasskeyNotFound = errors.New("gauntlet: no such passkey on this account")
	// ErrPasskeyLimitReached is returned by AddPasskey once an account
	// already holds maxPasskeysPerAccount credentials.
	ErrPasskeyLimitReached = fmt.Errorf("gauntlet: an account may hold at most %d passkeys -- remove one before adding another", maxPasskeysPerAccount)
	// ErrPasskeyDuplicate is returned by AddPasskey when the credential
	// ID being added already exists on the account -- the same
	// authenticator (or a replayed registration ceremony) offered
	// twice. Checked before ErrPasskeyLimitReached, so a re-presented
	// credential is never reported as "limit reached" merely because
	// the account happens to be full.
	ErrPasskeyDuplicate = errors.New("gauntlet: this passkey is already registered to this account")
)

// Passkey is one registered WebAuthn credential, held on User.Passkeys.
type Passkey struct {
	// ID is the credential ID the registration ceremony returned -- the
	// value every later assertion presents to say "this is the same
	// credential". JSON as base64, the standard encoding for a []byte
	// field.
	ID []byte `json:"id"`
	// PublicKey is the COSE-encoded public key the authenticator proved
	// it holds the matching private key for at registration -- needed to
	// verify every later assertion's signature. Not secret the way a
	// private key would be, but still credential material, not something
	// an admin-facing account list should serialize -- see Store.List.
	PublicKey []byte `json:"publicKey"`
	// SignCount is the authenticator's signature counter as of the most
	// recently accepted assertion (registration supplies the first
	// value). Forward-only, advanced only through
	// RecordPasskeyAssertionIfFresh below.
	SignCount uint32 `json:"signCount"`
	// Transports is what the authenticator reported it can be reached
	// over (usb, nfc, ble, internal, hybrid, ...) at registration.
	Transports []string `json:"transports,omitempty"`
	// Flags carries the four authenticator flags a real WebAuthn
	// credential exposes, reproduced here as PasskeyFlags so this
	// package does not depend on a WebAuthn library for the data shape.
	Flags PasskeyFlags `json:"flags"`
	// RPID is the relying-party ID (essentially the registered domain)
	// this credential was created against -- carried here so a later
	// caller can compare it against the server's current RPID to decide
	// whether the credential is stale.
	RPID string `json:"rpId"`
	// Name is the operator-chosen label shown in the passkey list --
	// never empty once stored.
	Name string `json:"name"`
	// CreatedAt is when this credential was registered.
	CreatedAt time.Time `json:"createdAt"`
	// LastUsedAt is when this credential last completed a login -- zero
	// until the first one.
	LastUsedAt time.Time `json:"lastUsedAt,omitzero"`
}

// clone copies the credential with its own byte and string slices, so
// a change to the copy cannot reach the original -- see User.clone.
func (p Passkey) clone() Passkey {
	cp := p
	cp.ID = slices.Clone(p.ID)
	cp.PublicKey = slices.Clone(p.PublicKey)
	cp.Transports = slices.Clone(p.Transports)
	return cp
}

// PasskeyFlags mirrors the four authenticator flags a WebAuthn
// credential carries. Field names and JSON tags match mikroview's
// internal/auth/passkeys.go exactly, so a caller's conversion to and
// from a WebAuthn library type is a straight field-by-field copy, not a
// translation.
type PasskeyFlags struct {
	UserPresent    bool `json:"userPresent"`
	UserVerified   bool `json:"userVerified"`
	BackupEligible bool `json:"backupEligible"`
	BackupState    bool `json:"backupState"`
}

// normalisePasskeyName trims name, bounds it to maxPasskeyNameLength
// runes, and falls back to a numbered default ("Passkey <n>") if what's
// left is empty. Shared by AddPasskey and RenamePasskey so a stored
// Name is never blank and the two rules can't drift apart. n is the
// 1-based number to use in the fallback.
func normalisePasskeyName(name string, n int) string {
	trimmed := strings.TrimSpace(name)
	// Bounded on runes, not bytes: a byte-index slice of a UTF-8 string
	// can cut a multi-byte character in half and leave invalid UTF-8
	// stored right in the accounts document.
	if r := []rune(trimmed); len(r) > maxPasskeyNameLength {
		trimmed = string(r[:maxPasskeyNameLength])
	}
	if trimmed == "" {
		return fmt.Sprintf("Passkey %d", n)
	}
	return trimmed
}

// findPasskeyIndex returns the index of the passkey on u matching
// credID by exact bytes, or -1. Shared by every method below that acts
// on one specific credential.
func findPasskeyIndex(u *User, credID []byte) int {
	for i, pk := range u.Passkeys {
		if bytes.Equal(pk.ID, credID) {
			return i
		}
	}
	return -1
}

// AddPasskey registers a new WebAuthn credential on userID's account --
// the store-layer half of the registration ceremony an application's
// own WebAuthn wiring drives (G8). pk arrives fully populated by the
// caller.
//
// The credential ID is checked against every passkey already on the
// account before the account's capacity is: ErrPasskeyDuplicate takes
// priority over ErrPasskeyLimitReached, so an authenticator presented
// twice against a full account is told it's already registered rather
// than that the account is full. Name is normalised (see
// normalisePasskeyName) before it's stored. Returns the stored Passkey,
// with its normalised name, so the caller's response doesn't have to
// re-derive it.
func (s *Store) AddPasskey(userID string, pk Passkey) (Passkey, error) {
	if !s.Persisted() {
		return Passkey{}, ErrNotPersisted
	}
	s.reloadIfStale()

	// A registration that only exists in memory must not be reported as
	// done: the caller is about to tell its user the passkey was added
	// -- and, on a first factor, mint recovery codes and revoke other
	// sessions around that claim -- and a restart before the next good
	// write would drop the credential while nothing else remembers it
	// ever existed. mutate installs it only once it is saved, and the
	// duplicate and capacity checks run against the document being
	// saved, so a replay sees a passkey another process added first.
	var added Passkey
	err := s.mutate(func(st *storeState) error {
		u, ok := st.byID[userID]
		if !ok {
			return ErrUserNotFound
		}
		if findPasskeyIndex(u, pk.ID) != -1 {
			return ErrPasskeyDuplicate
		}
		if len(u.Passkeys) >= maxPasskeysPerAccount {
			return ErrPasskeyLimitReached
		}
		p := pk
		p.Name = normalisePasskeyName(pk.Name, len(u.Passkeys)+1)
		u.Passkeys = append(u.Passkeys, p)
		added = p
		return nil
	})
	if err != nil {
		return Passkey{}, err
	}
	return added, nil
}

// RenamePasskey changes the display name of one of userID's passkeys,
// found by credential ID. No password check here -- a rename is
// cosmetic and reversible, unlike DeletePasskey below. Runs the same
// normalisation AddPasskey does, so a rename to blank or to something
// absurdly long behaves the same way giving that name at registration
// would have.
func (s *Store) RenamePasskey(userID string, credID []byte, name string) (Passkey, error) {
	if !s.Persisted() {
		return Passkey{}, ErrNotPersisted
	}
	s.reloadIfStale()

	// In place: the account the op is handed is mutate's deep copy, so
	// no reader's copy of the User shares its Passkeys.
	var renamed Passkey
	err := s.mutate(func(st *storeState) error {
		u, ok := st.byID[userID]
		if !ok {
			return ErrUserNotFound
		}
		idx := findPasskeyIndex(u, credID)
		if idx == -1 {
			return ErrPasskeyNotFound
		}
		u.Passkeys[idx].Name = normalisePasskeyName(name, idx+1)
		renamed = u.Passkeys[idx].clone()
		return nil
	})
	if err != nil {
		return Passkey{}, err
	}
	return renamed, nil
}

// DeletePasskey removes one of userID's passkeys, found by credential
// ID, and -- in the same locked write -- clears RecoveryCodes too if
// that removal leaves the account with no second factor of either kind
// (User.HasSecondFactor). That conditional clear is the load-bearing
// part of the shared-recovery-codes design (docs/design.md §1.6): codes
// minted for a passkey must survive removing a *different* passkey, or
// an authenticator app that isn't the last factor standing, and must
// not survive the account actually going back to password-only.
// Getting this wrong in either direction either orphans a still-active
// factor's fallback, or leaves stale codes able to sign in to an
// account that looks, from the outside, like it has no second factor at
// all. ClearTOTP (totp.go) makes the same call from the other
// direction.
//
// Returns the removed Passkey, so a caller building an audit entry
// doesn't have to look it up separately beforehand.
func (s *Store) DeletePasskey(userID string, credID []byte) (Passkey, error) {
	if !s.Persisted() {
		return Passkey{}, ErrNotPersisted
	}
	s.reloadIfStale()

	// A removal that only exists in memory must not be reported as
	// done: the caller is about to tell its user this credential no
	// longer works (and, if it was the last factor, that recovery codes
	// are gone too), and a restart before the next good write would
	// silently bring both back. mutate installs it only once it is
	// saved, and the "last factor standing" check runs against the
	// document being saved.
	var removed Passkey
	err := s.mutate(func(st *storeState) error {
		u, ok := st.byID[userID]
		if !ok {
			return ErrUserNotFound
		}
		idx := findPasskeyIndex(u, credID)
		if idx == -1 {
			return ErrPasskeyNotFound
		}
		removed = u.Passkeys[idx].clone()
		u.Passkeys = slices.Delete(u.Passkeys, idx, idx+1)
		if !u.HasSecondFactor() {
			u.RecoveryCodes = nil
		}
		return nil
	})
	if err != nil {
		return Passkey{}, err
	}
	return removed, nil
}

// RecordPasskeyAssertionIfFresh advances userID's credID passkey after
// a login assertion, and -- under the same lock acquisition -- decides
// whether the login is accepted. See this file's package comment for
// why this is the only entry point: a separate verify-then-record pair
// left a race where two concurrent submissions of the same assertion
// both won a session.
//
// SignCount is forward-only, the same stance VerifyAndRecordTOTP
// (totp.go) takes for its counter. LastUsedAt is set to now on every
// accepted login, so the passkey list can show "last used" for an
// authenticator that never advances its counter at all.
//
// accepted is false when signCount is not fresh: at or below what's
// already stored, and not the 0-to-0 case below. That includes a
// passkey that has counted and now reports 0, which the WebAuthn spec
// treats like any other regression: a possible cloned authenticator
// (docs/design.md §4, "Second factors"). Nothing is saved for a
// refused assertion.
//
// Zero is exempt only while the passkey has never counted: an
// authenticator that always reports 0 (most platform passkeys) has a
// stored count of 0 and presents 0 every time, and must not be locked
// out after its first login. Such a login carries no counter-based
// replay protection here, so the caller must have claimed its
// single-use WebAuthn challenge before calling this: for these
// passkeys that claim is the whole replay defence.
//
// A login is accepted only once its record is saved -- the saved count
// is what refuses a replay of 0 -> 5 or 5 -> 6 -- except in that 0-to-0
// case, where the save protects nothing. There it is best-effort, like
// LastLogin in Authenticate: a save that fails is logged through
// Options.Log, LastUsedAt is kept in memory, and the login is accepted
// with a nil error. accepted is never true alongside an error.
//
// The caller is expected to have already verified the assertion's
// signature (an application's own WebAuthn wiring, G8) before calling
// this -- this method only decides freshness and records the outcome.
func (s *Store) RecordPasskeyAssertionIfFresh(userID string, credID []byte, signCount uint32, now time.Time) (accepted bool, err error) {
	if !s.Persisted() {
		return false, ErrNotPersisted
	}
	s.reloadIfStale()

	// Freshness is decided inside the op, against the count in the
	// document being saved: a replay after another process recorded the
	// same assertion must see the advanced count and refuse it. So is
	// whether the save matters (bestEffort), for the same reason.
	var bestEffort bool
	op := func(st *storeState) error {
		accepted, bestEffort = false, false
		u, ok := st.byID[userID]
		if !ok {
			return ErrUserNotFound
		}
		idx := findPasskeyIndex(u, credID)
		if idx == -1 {
			return ErrPasskeyNotFound
		}
		stored := u.Passkeys[idx].SignCount
		bothZero := stored == 0 && signCount == 0
		if signCount <= stored && !bothZero {
			return errNoChange
		}
		// In place: the account the op is handed is mutate's deep copy,
		// or the live state on the best-effort path below.
		u.Passkeys[idx].SignCount = signCount
		u.Passkeys[idx].LastUsedAt = now
		accepted, bestEffort = true, bothZero
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	err = s.mutateLocked(op)
	if err != nil && bestEffort {
		// The last run decided 0-to-0 and only the save failed. Decide
		// again against the live state, as mutateBestEffortLocked does,
		// and keep the change there if it is still 0-to-0.
		if opErr := op(&s.storeState); opErr == nil && bestEffort {
			if s.log != nil && !errors.Is(err, ErrDocumentRemoved) { // reported once already
				s.log.Error(fmt.Sprintf("%v -- this passkey's last-used time exists only in memory and will be lost on restart", err))
			}
			return true, nil
		}
	}
	if err != nil {
		// Same as VerifyAndRecordTOTP: accepted may be true from a run
		// the loop threw away, so it counts only when mutate saved.
		return false, err
	}
	return accepted, nil
}

// ClearPasskeys removes every passkey on userID's account in one write.
// Same conditional recovery-code clear as DeletePasskey: codes survive
// if the account still has an active authenticator-app factor, and are
// cleared only if this was the account's last second factor.
func (s *Store) ClearPasskeys(userID string) error {
	if !s.Persisted() {
		return ErrNotPersisted
	}
	s.reloadIfStale()

	return s.mutate(func(st *storeState) error {
		u, ok := st.byID[userID]
		if !ok {
			return ErrUserNotFound
		}
		u.Passkeys = nil
		if !u.HasSecondFactor() {
			u.RecoveryCodes = nil
		}
		return nil
	})
}

// ClearAllSecondFactors removes every second factor on userID's
// account -- the authenticator app and every passkey -- and the
// recovery codes that backed them, all in the one write. Meant for an
// "I've lost everything" recovery path: unlike DeletePasskey,
// ClearPasskeys and ClearTOTP there is no factor-remaining check to make
// here -- there is nothing left standing after this call, by
// construction.
func (s *Store) ClearAllSecondFactors(userID string) error {
	if !s.Persisted() {
		return ErrNotPersisted
	}
	s.reloadIfStale()

	// A clear that only exists in memory must not be reported as done:
	// the caller tells its operator every second factor is off, and a
	// restart before the next good write would silently bring all of it
	// back underneath that claim. mutate installs it only once it is
	// saved.
	return s.mutate(func(st *storeState) error {
		u, ok := st.byID[userID]
		if !ok {
			return ErrUserNotFound
		}
		u.TOTPSecret = ""
		u.TOTPConfirmedAt = time.Time{}
		u.TOTPLastCounter = 0
		u.Passkeys = nil
		u.RecoveryCodes = nil
		return nil
	})
}

// PasskeyCount reports how many passkeys userID's account holds. It
// exists because List() blanks Passkeys entirely on every copy it
// returns (see List's doc comment in store.go), so len(copy.Passkeys)
// on a List() result always reads zero -- this is the guard against
// that mistake for an admin-facing users list's passkey count. An
// unknown user answers 0 rather than erroring, the same yes/no-gate
// stance User.HasActiveTOTP takes.
func (s *Store) PasskeyCount(userID string) int {
	s.reloadIfStale()
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[userID]
	if !ok {
		return 0
	}
	return len(u.Passkeys)
}
