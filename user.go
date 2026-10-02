// Package gauntlet implements local username/password authentication:
// user accounts and roles (this file), Argon2id password hashing
// (password.go), username validation (username.go), and random id
// generation (id.go). It also owns OIDC/SSO identity storage and
// just-in-time provisioning (Store.FindOrCreateOIDCUser) -- the OIDC
// protocol itself lives in the separate gauntlet/oidc package, which
// this package doesn't import.
//
// The types here start from mikroview's internal/auth/store.go, with
// its names kept (docs/adr/0001-shared-auth-module.md decision 3;
// docs/design.md §1.3), plus what gauntlet added: User.clone for the
// copy-then-save writes (Store.mutate) and the unexported
// totpSecretBlanked mark and blankedPasskeyCount count that let a
// blanked copy still answer HasActiveTOTP, HasSecondFactor and
// PasskeyCount. The stored fields are
// mikroview's, byte for byte, plus gauntlet's own that mikroview's
// documents lack and read as zero: loginLockedUntil (#19),
// sessionsEndedAt (#28), and loginLockoutCount and loginDisabledAt
// (#44). User carries every field mikroview's own
// User carries -- including TOTP, recovery codes, reset codes and
// passkeys -- because Store persists the whole document on every save
// (docs/design.md Summary): a field this package didn't know about would
// be silently dropped on the first write. The methods that generate, verify or
// clear those fields live beside them: totp.go, recoverycodes.go,
// resetcode.go and passkeys.go; the predicates docs/design.md §1.3
// lists (LocalPassword, HasActiveTOTP, HasSecondFactor) are below.
package gauntlet

import (
	"slices"
	"time"
)

// Role is an account's privilege tier.
type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
	// RoleViewer is the lowest tier: read access to everything an
	// operator sees, but nothing that changes the deployment. Stacks
	// below RoleUser, which stacks below RoleAdmin -- see Role.AtLeast.
	RoleViewer Role = "viewer"
)

// rank orders roles from lowest privilege to highest, backing
// Role.AtLeast. An unrecognized Role -- including the zero value -- ranks
// below RoleViewer, so it is refused everything AtLeast ever gates for a
// legitimate min. The only way one reaches a live User.Role is a
// document written outside this package -- a hand-edited accounts file.
// That account then fails closed, denied by every role gate, which is
// the right direction for a role nobody legitimately assigned.
func (r Role) rank() int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleUser:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether r's tier is at or above min: admin ⊇ user ⊇
// viewer. Every access gate built on this package should compare roles
// through AtLeast rather than comparing Role values directly, so there
// is exactly one place "who outranks whom" is decided.
func (r Role) AtLeast(min Role) bool {
	return r.rank() >= min.rank()
}

// User is one local account. PasswordHash is never exposed outside this
// package's JSON persistence -- a caller must never serialize a User
// directly into an HTTP response; see Store.List, which blanks every
// credential field before returning copies.
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"passwordHash"`
	Role         Role      `json:"role"`
	CreatedAt    time.Time `json:"createdAt"`
	LastLogin    time.Time `json:"lastLogin,omitzero"`
	// PasswordChangedAt is when the password itself last changed
	// (SetPassword, IssueResetCode). The login limiter reads it as the
	// moment guesses at the old password stop counting (lockoutRecorder),
	// and it is one of SessionCutoff's two inputs: documents written
	// before SessionsEndedAt existed record an SSO link here too.
	PasswordChangedAt time.Time `json:"passwordChangedAt,omitzero"`
	// SessionsEndedAt is when every session issued before it was ended,
	// whatever ended them: a new password, a reset code, an SSO link
	// (#28). It lets a session be invalidated by a change that happens
	// in a *different process* -- a CLI recovery tool has no access to a
	// running server's in-memory SessionStore -- since a session's
	// IssuedAt is compared against it through the persisted store (see
	// SessionCutoff). Gauntlet's own field: mikroview's documents lack
	// it, and read it as zero.
	SessionsEndedAt time.Time `json:"sessionsEndedAt,omitzero"`
	// OIDCIssuer/OIDCSubject identify this account's linked SSO identity,
	// if any -- both empty for a purely local-password account. Together
	// they're the immutable identity key FindOrCreateOIDCUser matches
	// on, deliberately never email or username. A local-password account
	// can also carry these (see LinkOIDCIdentity) once linked to an SSO
	// identity, in which case both login paths reach the same account.
	OIDCIssuer  string `json:"oidcIssuer,omitempty"`
	OIDCSubject string `json:"oidcSubject,omitempty"`
	// HasLocalPassword distinguishes a real, user-chosen password from
	// the random unmatchable hash FindOrCreateOIDCUser issues to an
	// SSO-provisioned account. The hashes themselves cannot be told
	// apart -- both are valid Argon2id strings -- so this has to be
	// recorded rather than inferred from the credential.
	HasLocalPassword bool `json:"hasLocalPassword"`
	// RoleChangedAt records the last admin transfer touching this
	// account, on both sides of it. For the audit trail and the UI only:
	// authorization always reads Role, never this.
	RoleChangedAt time.Time `json:"roleChangedAt,omitzero"`
	// ResetCodeHash is the Argon2id hash of the one-time code an admin
	// issued for this account -- the same hash function and parameters a
	// password gets, because for as long as it is live this *is* the
	// account's password. Empty whenever no reset is outstanding, and
	// cleared wherever the reset ends: Authenticate spends it (single
	// use), SetPassword replaces it with a real password, and
	// LinkOIDCIdentity voids it for a non-admin going SSO-only, since
	// there is no local password left to reset. IssueResetCode
	// (resetcode.go) issues one; Authenticate redeems a live one (§1.3).
	ResetCodeHash string `json:"resetCodeHash,omitempty"`
	// ResetCodeExpiresAt ends an unspent code, 24 hours after it was
	// issued. Checked against, never the only check -- see
	// User.resetCodeLive.
	ResetCodeExpiresAt time.Time `json:"resetCodeExpiresAt,omitzero"`
	// MustChangePassword is set by an admin reset, and by a LoginLimiter
	// once a run of second-factor failures shows someone else knows the
	// password (SecondFactorFailed, #44). It is cleared only where a new
	// password ends it: SetPassword (a real password is chosen), or
	// LinkOIDCIdentity voiding it for a non-admin going SSO-only, where
	// there is no local password left to force a change on. Recorded on
	// the account rather than on the session: the flag has to survive the
	// login that redeems the code, and outlive a restart (sessions do
	// not).
	MustChangePassword bool `json:"mustChangePassword,omitempty"`
	// LoginLockedUntil is when a login lockout on this account ends, zero
	// when none is in force. Written by a LoginLimiter only as a lockout
	// begins or clears, never per failed attempt (see ReserveAccount), so
	// a lockout survives a restart without every wrong guess becoming a
	// disk write. A new password (SetPassword, IssueResetCode) clears it
	// in the same write; LinkOIDCIdentity, which ends sessions but leaves
	// the admin's password working, does not.
	LoginLockedUntil time.Time `json:"loginLockedUntil,omitzero"`
	// LoginLockoutCount is how many login lockouts this account has had
	// since its last completed sign-in (#44): each lasts three times as
	// long as the one before (ReserveAccount). Written in the same write
	// that starts a lockout, never per attempt. A completed sign-in
	// (LoginLimiter.SignedIn), a new password (SetPassword,
	// IssueResetCode) and UnlockLogin set it back to zero; a lockout
	// running out does not. Gauntlet's own field: older documents lack
	// it and read it as zero.
	LoginLockoutCount int `json:"loginLockoutCount,omitempty"`
	// LoginDisabledAt is when this account's local sign-in was disabled
	// after MaxConsecutiveLoginFailures failures in a row (#44), zero
	// while it is not. A disabled account is refused at the password step
	// exactly as a locked one is, for good: it does not time out, no
	// sign-in can complete while it is in force, and a new password does
	// not lift it. Only UnlockLogin does. It disables the local password sign-in, not
	// the account's sessions, its SSO identity or its second factors.
	LoginDisabledAt time.Time `json:"loginDisabledAt,omitzero"`
	// TOTPSecret is the shared secret behind the authenticator-app second
	// factor, stored in the clear -- unlike a password or a recovery
	// code, it has to be reversible: verifying a 30-second code means
	// recomputing HMAC-SHA1 over it, not comparing a hash. RFC 6238 code
	// verification is in totp.go.
	//
	// A non-empty secret alone is not an active factor: see
	// TOTPConfirmedAt and HasActiveTOTP.
	TOTPSecret string `json:"totpSecret,omitempty"`
	// TOTPConfirmedAt is when the account owner proved they could produce
	// a valid code from TOTPSecret, which is what activates the factor.
	// Zero means a secret exists but was never confirmed, and
	// HasActiveTOTP is false until this is set.
	TOTPConfirmedAt time.Time `json:"totpConfirmedAt,omitzero"`
	// TOTPLastCounter is the RFC 6238 30-second time-step counter of the
	// most recently accepted code, so that code (or an earlier one still
	// inside the verification window) cannot be replayed.
	TOTPLastCounter uint64 `json:"totpLastCounter,omitzero"`
	// RecoveryCodes are the single-use fallback codes for signing in
	// without the authenticator app -- hashed with HashPassword, the same
	// Argon2id treatment a password gets, never stored in clear.
	// Generation and redemption are in recoverycodes.go.
	RecoveryCodes []RecoveryCode `json:"recoveryCodes,omitempty"`
	// Passkeys are this account's registered WebAuthn credentials -- zero
	// or more, unlike TOTPSecret's single shared secret. The ceremony
	// (passkey/, G8) is not part of this module in v0.1.0; this package
	// only stores what it would produce.
	Passkeys []Passkey `json:"passkeys,omitempty"`

	// totpSecretBlanked is set only on a copy blankCredentials has
	// blanked, and only when it blanked a TOTPSecret that was there, so
	// HasActiveTOTP on that copy gives the answer it would have given
	// before the blanking. Unexported, so it never reaches JSON; it says
	// that a secret exists, never what it is.
	totpSecretBlanked bool
	// blankedPasskeyCount is the same for Passkeys, but a count rather
	// than a flag: how many passkeys blankCredentials has stripped from
	// this copy, accumulated across repeated blanking so it is never
	// lost. It is what PasskeyCount and HasSecondFactor read once
	// Passkeys itself has been blanked to nil. Unexported, so it never
	// reaches JSON: it says how many credentials existed, never what
	// they were.
	blankedPasskeyCount int
}

// blankCredentials clears every credential and credential verifier on
// u, which must be a copy on its way out of the Store, never the stored
// account. Every Store method that hands an account back for a caller to
// list, log or audit (List, IssueResetCode, DeleteUser, TransferAdmin)
// goes through here, so a new credential field only has to be added
// once to stay out of all of them.
func (u *User) blankCredentials() {
	// The password hash and the reset-code hash are both verifiers for
	// the account's password -- for as long as a reset is live, the
	// code *is* the password.
	u.PasswordHash = ""
	u.ResetCodeHash = ""
	// TOTPSecret is worse than a verifier hash if it leaked -- it's the
	// actual shared secret, good for minting valid codes indefinitely,
	// not just checking one. RecoveryCodes are hashes only, same
	// category as ResetCodeHash. HasActiveTOTP still answers truly on
	// the copy (see totpSecretBlanked), so a caller showing who has an
	// authenticator app needs no extra Get.
	u.totpSecretBlanked = u.totpSecretBlanked || u.TOTPSecret != ""
	u.TOTPSecret = ""
	u.RecoveryCodes = nil
	// Passkeys carries each credential's PublicKey -- not a secret the
	// way a private key would be, but still credential material nothing
	// outside the Store has business serializing. Blanked wholesale
	// rather than per-field: a caller that needs a count reads
	// PasskeyCount instead of len(this copy's Passkeys), which always
	// reads zero once blanked. HasSecondFactor and PasskeyCount both
	// still answer truly on the copy (see blankedPasskeyCount).
	u.blankedPasskeyCount += len(u.Passkeys)
	u.Passkeys = nil
}

// clone deep-copies the account, including the slices a plain struct
// copy would share -- what Store.mutate changes and may throw away.
func (u *User) clone() *User {
	cp := *u
	cp.RecoveryCodes = slices.Clone(u.RecoveryCodes)
	if u.Passkeys != nil {
		cp.Passkeys = make([]Passkey, len(u.Passkeys))
		for i := range u.Passkeys {
			cp.Passkeys[i] = u.Passkeys[i].clone()
		}
	}
	return &cp
}

// SessionCutoff is the moment before which every session for this
// account is dead: the later of SessionsEndedAt and PasswordChangedAt,
// zero when neither is set. A session issued before it must be refused.
//
// PasswordChangedAt is still an input because documents written before
// SessionsEndedAt existed -- by gauntlet v0.2.0 and by mikroview, whose
// SSO link records itself there -- carry the only record of when their
// sessions ended in it.
func (u *User) SessionCutoff() time.Time {
	if u.SessionsEndedAt.After(u.PasswordChangedAt) {
		return u.SessionsEndedAt
	}
	return u.PasswordChangedAt
}

// LocalPassword reports whether this account has a real, user-chosen
// password that may be reset.
func (u *User) LocalPassword() bool { return u.HasLocalPassword }

// HasActiveTOTP reports whether u's authenticator-app factor is
// confirmed and therefore active. A secret alone is not enough: a
// generated-but-never-confirmed secret (TOTPSecret set, TOTPConfirmedAt
// zero) is mid-setup, not something that should ever gate a sign-in --
// see TOTPConfirmedAt's doc comment.
//
// It answers the same on a Store.List copy, whose TOTPSecret is blanked,
// as on the account itself -- see totpSecretBlanked.
func (u *User) HasActiveTOTP() bool {
	hasSecret := u.TOTPSecret != "" || u.totpSecretBlanked
	return hasSecret && !u.TOTPConfirmedAt.IsZero()
}

// HasSecondFactor reports whether u has any active second factor at
// all -- authenticator app or at least one passkey.
//
// Every passkey counts here regardless of whether it's stale: staleness
// only affects whether a passkey can complete a *login*, not whether the
// account is considered to have a second factor at all.
func (u *User) HasSecondFactor() bool {
	return u.HasActiveTOTP() || u.PasskeyCount() > 0
}

// PasskeyCount reports how many passkeys u holds. It answers truly on a
// Store.List() copy, whose Passkeys field List blanks the same way it
// blanks TOTPSecret (see blankCredentials): len(u.Passkeys) on such a
// copy always reads zero, but this adds back blankedPasskeyCount, so a
// caller already holding a List entry -- an admin-facing accounts list,
// say -- gets the real count without a separate Store.PasskeyCount call
// per account.
func (u *User) PasskeyCount() int {
	return len(u.Passkeys) + u.blankedPasskeyCount
}
