// Copied from mikroview's internal/auth/passkeys.go, names kept
// (docs/design.md §1.3). This file is the store-layer half, plus the
// seam the ceremony half is driven through. The ceremony itself
// (talking to go-webauthn, building the relying party from the
// application's public URL, sealing ceremony state for the browser to
// carry) lives in the gauntlet/passkey package (G8, ADR-0004), which
// implements PasskeyCeremony below; gate drives it through that
// interface. This package does not import go-webauthn and must not gain
// a reason to: every value crossing PasskeyCeremony is a type from this
// package, a string or raw JSON. Passkey.Transports and Passkey.Flags
// below reproduce the shapes of two go-webauthn types for exactly that
// reason -- see their doc comments.
//
// One divergence from mikroview: RecordPasskeyAssertion, the two-step
// "verify with go-webauthn, then record" method, is not carried over.
// Only RecordPasskeyAssertionIfFresh is (docs/design.md §1.3) -- the
// version mikroview added after finding that the two-step form let two
// concurrent submissions of the same assertion both clear against the
// same not-yet-advanced stored count and both win a session, the
// passkey shape of totp.go's VerifyAndRecordTOTP race. There is no
// reason for a new caller to have the unsafe two-step option.
// AnyPasskeysExist is carried over (owner, #20 question 5): the
// start-up decision it feeds stays the application's, but the question
// it answers is about the store.

package gauntlet

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/tomlawesome/gauntlet/internal/plaintext"
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
	// maxPasskeyTransports and maxPasskeyTransportLength bound what is
	// kept of a passkey's Transports (see boundTransports): WebAuthn
	// defines six values, so eight leaves room for new ones, and the
	// longest defined value, "smart-card", is ten bytes.
	maxPasskeyTransports      = 8
	maxPasskeyTransportLength = 32
)

var (
	// ErrPasskeyNotFound is returned by RenamePasskey, DeletePasskey and
	// RecordPasskeyAssertionIfFresh when credID matches none of userID's
	// stored passkeys -- covers both "never existed" and "already
	// removed"; a caller has no legitimate reason to tell those apart.
	ErrPasskeyNotFound = errors.New("gauntlet: no such passkey on this account")
	// ErrNoPasskeys is returned by ClearPasskeys when the account has no
	// passkey to remove, on the account or on hold. Nothing is written,
	// so a caller can answer without auditing or notifying a removal
	// that never happened.
	ErrNoPasskeys = errors.New("gauntlet: this account has no passkeys")
	// ErrNoSecondFactors is returned by ClearAllSecondFactors when the
	// account has nothing to clear: no authenticator app (live or
	// pending), no passkey, no recovery codes and nothing on hold; and
	// by RegenerateRecoveryCodes when it has no live second factor (#94).
	// Nothing is written.
	ErrNoSecondFactors = errors.New("gauntlet: this account has no second factor to clear")
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
	// ErrPasskeyNameInvalid is returned by AddPasskey, RenamePasskey and
	// HoldFirstPasskey for a name holding a control or format character,
	// a line or paragraph separator, invalid UTF-8 (#89) or U+FFFD
	// (#90): a name is
	// plain text, shown in lists and in notices to the account's owner.
	// Nothing is stored or changed. A blank name is not an error; it
	// becomes "Passkey <n>".
	ErrPasskeyNameInvalid = errors.New("gauntlet: passkey name contains characters that are not allowed")
	// ErrPasskeyCeremonyInvalid is wrapped by gauntlet/passkey's
	// FinishRegistration and FinishLogin (PasskeyCeremony), and FinishSignIn (PasskeySignIn), whenever the
	// sealed ceremony state is unusable: it fails the authentication
	// tag, is malformed, was sealed for the other ceremony or by another
	// process, has expired, or its challenge was already used. Such a
	// ceremony can never succeed, so the caller starts again; gate
	// matches it with errors.Is to answer "start again" and clear the
	// ceremony cookie. Any other Finish error means the browser's
	// response itself was refused, and a corrected one may still finish
	// the same ceremony.
	ErrPasskeyCeremonyInvalid = errors.New("gauntlet: passkey ceremony expired, was tampered with, belongs to the other ceremony, or was already used")
)

// PasskeyStatus reports whether an application can offer passkeys at
// all, and why not when it cannot -- the answer
// PasskeyCeremony.Status gives. A passkey is bound to a domain name
// (the relying-party ID) and an origin, so it needs the application to
// have a usable public web address; an application reached only by IP
// address has none, and that is a reported state rather than a startup
// failure (ADR-0004 decision 4).
type PasskeyStatus string

const (
	// PasskeyStatusReady: the public URL is an https address (or http
	// on localhost) with a domain-name host. Passkeys work.
	PasskeyStatusReady PasskeyStatus = "ready"
	// PasskeyStatusUnset: no public URL was configured, or it is not an
	// absolute URL.
	PasskeyStatusUnset PasskeyStatus = "unset"
	// PasskeyStatusIP: the public URL's host is an IP address. Browsers
	// refuse to create a passkey for one.
	PasskeyStatusIP PasskeyStatus = "ip"
	// PasskeyStatusInsecure: the public URL's scheme is not https (and
	// it is not http on localhost). Browsers run a passkey ceremony only
	// from a secure context.
	PasskeyStatusInsecure PasskeyStatus = "insecure"
)

// PasskeyCeremony runs the two WebAuthn ceremonies -- registration,
// which makes a passkey, and login (assertion), which proves one -- for
// an application with one relying party. gauntlet/passkey implements it
// (passkey.New); gate drives it through Deps.Passkeys, and never sees
// the WebAuthn library's own types. It is not meant to be implemented
// anywhere else, and a method added to it would break every
// implementer, so it will not grow: a later need is a second, optional
// interface (ADR-0004).
//
// Each Begin returns the options to hand the browser (the W3C
// PublicKeyCredential creation or request options, as JSON) and the
// ceremony state sealed into an opaque string the browser carries back
// unchanged, in a cookie; the matching Finish takes that sealed string
// and the browser's response. Ceremony state never touches the store.
// Every method except Status, RPID and Origin refuses while Status is
// not PasskeyStatusReady.
type PasskeyCeremony interface {
	// Status says whether passkeys work here, and why not when they
	// do not.
	Status() PasskeyStatus
	// RPID is the relying-party ID (a domain name) passkeys are
	// registered under, and the value stored on Passkey.RPID. "" unless
	// Status is PasskeyStatusReady.
	RPID() string
	// Origin is the one origin (scheme://host[:port]) ceremonies are
	// accepted from. "" unless Status is PasskeyStatusReady.
	Origin() string
	// BeginRegistration starts registering a new passkey on u, excluding
	// every passkey u already holds under the current RPID.
	BeginRegistration(u *User) (options json.RawMessage, sealed string, err error)
	// FinishRegistration verifies the browser's response to
	// BeginRegistration's options and returns the new credential for
	// Store.AddPasskey. Name and CreatedAt are left for the caller. An
	// error wrapping ErrPasskeyCeremonyInvalid means the sealed state is
	// dead; any other means the credential was refused.
	FinishRegistration(u *User, sealed string, credential json.RawMessage) (Passkey, error)
	// BeginLogin starts a login ceremony allowing only u's passkeys
	// registered under the current RPID.
	BeginLogin(u *User) (options json.RawMessage, sealed string, err error)
	// FinishLogin verifies the browser's assertion against the ceremony
	// BeginLogin started. A nil error means the signature checked out;
	// the caller still refuses a CloneWarning and records the count
	// through Store.RecordPasskeyAssertionIfFresh. An error wrapping
	// ErrPasskeyCeremonyInvalid means the sealed state is dead; any other
	// means the assertion was refused.
	FinishLogin(u *User, sealed string, assertion json.RawMessage) (PasskeyAssertion, error)
}

// PasskeyAssertion is what a verified login assertion reports -- the
// arguments Store.RecordPasskeyAssertionIfFresh takes, plus whether the
// WebAuthn library suspects a cloned authenticator.
type PasskeyAssertion struct {
	// CredentialID is the ID of the passkey that signed.
	CredentialID []byte
	// SignCount is the counter the authenticator presented in this
	// assertion -- the value RecordPasskeyAssertionIfFresh checks for
	// freshness and stores. With CloneWarning set it is the presented
	// (regressed) value; the stored one is still on the User's Passkey.
	SignCount uint32
	// CloneWarning is set when the presented counter is at or below the
	// stored one and either is non-zero -- never for 0 -> 0, which is how
	// most platform passkeys behave. A caller refuses the login on it.
	CloneWarning bool
	// UserVerified is the authenticator's user-verification flag for this
	// assertion: it checked the person (a PIN or a biometric) as well as
	// their presence. FinishLogin reports what it saw; FinishSignIn
	// refuses an assertion without it, so it is always true there (#77).
	UserVerified bool
}

// PasskeySignIn is the optional second interface beside PasskeyCeremony
// (ADR-0004 said a later need would be one): signing in with a passkey
// alone, no password first (#77, ADR-0012). gauntlet/passkey's
// RelyingParty implements both; gate offers the routes only when
// Deps.Passkeys also implements this and Config.PasskeySignIn is set.
// Every method refuses while Status is not PasskeyStatusReady.
//
// It is a client-side discoverable credential login (WebAuthn Level 3):
// no username is typed, the browser offers the passkeys it holds for
// this relying party, and the one chosen names its account through the
// user handle -- the account ID, as FinishRegistration's user supplies
// it. User verification is required, not preferred.
type PasskeySignIn interface {
	// BeginSignIn starts a discoverable login ceremony: options for
	// navigator.credentials.get() with no allowed list and user
	// verification required, and the sealed state. The sealed state is
	// for this ceremony only; it cannot finish a login of the second-step
	// kind or a registration.
	BeginSignIn() (options json.RawMessage, sealed string, err error)
	// FinishSignIn verifies the browser's assertion. It reads the user
	// handle out of the assertion and calls lookup with it, before the
	// signature is checked, so the caller can find the account and apply
	// its own limits; lookup returns false for a handle that names no
	// account it will sign in, and the assertion is then refused. The
	// signature is checked against that account's passkeys under the
	// current RPID, and user verification is required: an assertion
	// without it is refused.
	//
	// It returns the account lookup gave for the verified assertion, and
	// the assertion as FinishLogin reports it, UserVerified included. As
	// with FinishLogin, the caller refuses a CloneWarning and records the
	// count through Store.RecordPasskeyAssertionIfFresh, and an error
	// wrapping ErrPasskeyCeremonyInvalid means the sealed state is dead.
	FinishSignIn(lookup func(userHandle []byte) (*User, bool), sealed string, assertion json.RawMessage) (*User, PasskeyAssertion, error)
}

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
	// over (usb, nfc, ble, internal, hybrid, ...) at registration --
	// at most eight well-formed entries once stored (boundTransports).
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

// checkPasskeyName refuses a name that is not plain text, U+FFFD
// included (plaintext.ValidWithin, #90), before normalisePasskeyName
// trims, cuts or defaults it: an unprintable character past the 64th
// would otherwise be cut off unseen, and one among spaces trimmed away,
// so the answer would depend on where it sat. Shared by AddPasskey,
// RenamePasskey and HoldFirstPasskey so the three can't drift apart.
//
// The limit given is len(name), which no name's character count can
// pass: a long name is cut to maxPasskeyNameLength, not refused.
func checkPasskeyName(name string) error {
	if !plaintext.ValidWithin(name, len(name)) {
		return ErrPasskeyNameInvalid
	}
	return nil
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

// storedPasskey is the credential as AddPasskey and HoldFirstPasskey
// store it: a copy of pk sharing no slice with the caller's value, its
// name normalised (n as in normalisePasskeyName) and its transports
// bounded. The one place a passkey record is built, so the two
// registration paths cannot drift apart.
func storedPasskey(pk Passkey, n int) Passkey {
	p := pk.clone()
	p.Name = normalisePasskeyName(pk.Name, n)
	p.Transports = boundTransports(pk.Transports)
	return p
}

// boundTransports keeps at most maxPasskeyTransports entries of in,
// each 1 to maxPasskeyTransportLength bytes of printable ASCII (0x21 to
// 0x7e), first-seen order kept, and drops every other entry and every
// repeat; a dropped entry takes no place in the eight. WebAuthn Level 3
// s5.8.4 (AuthenticatorTransport) defines six values and has clients
// ignore ones they do not know, so the list is only a hint sent back in
// allowCredentials: an entry is dropped, never a registration refused.
// The bound is what stops a registration storing an unbounded list of
// arbitrary strings in the accounts document.
func boundTransports(in []string) []string {
	var out []string
	for _, t := range in {
		if len(out) == maxPasskeyTransports {
			break
		}
		if len(t) == 0 || len(t) > maxPasskeyTransportLength || slices.Contains(out, t) {
			continue
		}
		printable := true
		for i := range len(t) {
			if t[i] < 0x21 || t[i] > 0x7e {
				printable = false
				break
			}
		}
		if printable {
			out = append(out, t)
		}
	}
	return out
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
// the store-layer half of the registration ceremony gauntlet/passkey
// runs (PasskeyCeremony.FinishRegistration). pk arrives fully populated
// by the caller. The passkey is live at once and no recovery codes are
// minted, unconditionally: on an account with no other second factor
// that leaves a live passkey with no recovery codes, so gate uses
// AddLaterPasskey, which refuses that case. An account's first factor
// is held with its codes instead, until confirmed (HoldFirstPasskey,
// ConfirmHeldEnrolment; #58).
//
// The credential ID is checked against every passkey already on the
// account before the account's capacity is: ErrPasskeyDuplicate takes
// priority over ErrPasskeyLimitReached, so an authenticator presented
// twice against a full account is told it's already registered rather
// than that the account is full. Before either, a name that is not
// plain text is refused with ErrPasskeyNameInvalid and nothing is
// stored. Name is normalised (see normalisePasskeyName) and
// Transports bounded (see boundTransports) before it's stored. Returns
// the stored Passkey, with its normalised name, so the caller's
// response doesn't have to re-derive it.
func (s *Store) AddPasskey(userID string, pk Passkey) (Passkey, error) {
	return s.addPasskey(userID, pk, false)
}

// AddLaterPasskey is AddPasskey for a passkey added beside a live
// second factor, whose recovery codes stand: it refuses with
// ErrNoOtherSecondFactor, storing nothing, when the account has none.
// That is decided in the same locked write that adds the passkey
// (check-and-set, as HoldFirstPasskey's ErrSecondFactorExists is), so a
// factor removed after the caller looked -- which took the codes with
// it -- cannot leave this passkey live with no codes (#80). The caller
// starts again on the first-factor path, HoldFirstPasskey.
func (s *Store) AddLaterPasskey(userID string, pk Passkey) (Passkey, error) {
	return s.addPasskey(userID, pk, true)
}

// addPasskey is AddPasskey, and with later set AddLaterPasskey.
func (s *Store) addPasskey(userID string, pk Passkey, later bool) (Passkey, error) {
	if err := checkPasskeyName(pk.Name); err != nil {
		return Passkey{}, err
	}
	if !s.Persisted() {
		return Passkey{}, ErrNotPersisted
	}
	s.reloadIfStale()

	// A registration that only exists in memory must not be reported as
	// done: the caller is about to tell its user the passkey was added,
	// and a restart before the next good write would drop the credential
	// while nothing else remembers it ever existed. mutate installs it only once it is saved, and the
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
		if later && !u.HasSecondFactor() {
			return ErrNoOtherSecondFactor
		}
		// Copied in and out, as the other passkey methods do: the
		// stored credential must not share its ID, PublicKey or
		// Transports with the caller's value or with what is returned
		// (storedPasskey copies in).
		p := storedPasskey(pk, len(u.Passkeys)+1)
		u.Passkeys = append(u.Passkeys, p)
		added = p.clone()
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
// would have. A name that is not plain text is refused with
// ErrPasskeyNameInvalid and the stored name is left as it was.
func (s *Store) RenamePasskey(userID string, credID []byte, name string) (Passkey, error) {
	if err := checkPasskeyName(name); err != nil {
		return Passkey{}, err
	}
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
// signature (PasskeyCeremony.FinishLogin) before calling this -- this
// method only decides freshness and records the outcome.
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
// cleared only if this was the account's last second factor. A passkey
// on hold (#58) goes too, with the codes held for it.
//
// Returns ErrNoPasskeys, writing nothing, when there is no passkey to
// remove, on the account or on hold.
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
		heldPasskey := u.HeldEnrolment != nil && u.HeldEnrolment.Kind == HeldFactorPasskey
		// Not errNoChange, which mutate answers with nil: the caller
		// must hear that nothing was removed, not a success.
		if len(u.Passkeys) == 0 && !heldPasskey {
			return ErrNoPasskeys
		}
		u.Passkeys = nil
		if heldPasskey {
			u.HeldEnrolment = nil
		}
		if !u.HasSecondFactor() {
			u.RecoveryCodes = nil
		}
		return nil
	})
}

// ClearAllSecondFactors removes every second factor on userID's
// account -- the authenticator app and every passkey, an enrolment on
// hold (#58) included -- and the recovery codes that backed them, all in
// the one write. Meant for an
// "I've lost everything" recovery path: unlike DeletePasskey,
// ClearPasskeys and ClearTOTP there is no factor-remaining check to make
// here -- there is nothing left standing after this call, by
// construction. An account with nothing to clear is ErrNoSecondFactors,
// and nothing is written.
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
		// Not errNoChange, which mutate answers with nil: the caller
		// must hear that nothing was removed, not a success.
		if u.TOTPSecret == "" && len(u.Passkeys) == 0 && len(u.RecoveryCodes) == 0 && u.HeldEnrolment == nil {
			return ErrNoSecondFactors
		}
		clearTOTPFields(u)
		u.Passkeys = nil
		u.RecoveryCodes = nil
		u.HeldEnrolment = nil
		return nil
	})
}

// PasskeyCount reports how many passkeys userID's account holds, read
// live from the Store. A caller that already holds a User -- a
// Store.List() entry, say -- should call User.PasskeyCount instead: List
// blanks Passkeys entirely on every copy it returns (see List's doc
// comment in store.go), so len(copy.Passkeys) on a List() result always
// reads zero, but User.PasskeyCount still answers truly on that copy,
// with no further Store call. This method remains for a caller that
// only has an ID, not a User -- a bearer-token endpoint, or a caller
// confirming the account's current state right after a write. An
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

// AnyPasskeysExist reports whether any account on this store holds at
// least one passkey, stale ones included. It is for an application's
// start-up check: mikroview refuses to start when accounts hold passkeys
// but its relying party is not ready (gauntlet.PasskeyCeremony's Status
// is unset, ip or insecure), rather than booting with credentials that
// can never complete a login. That decision is the application's;
// gauntlet/passkey always builds and only reports its status (ADR-0004
// decision 4). An install with no passkeys starts the same whatever the
// status. Reads the current document first, like every read here.
func (s *Store) AnyPasskeysExist() bool {
	s.reloadIfStale()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.byID {
		if len(u.Passkeys) > 0 {
			return true
		}
	}
	return false
}
