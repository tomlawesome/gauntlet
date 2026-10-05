package passkey

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/tomlawesome/gauntlet"
)

// webauthnUser adapts an account to the library's User interface: its
// ID, its username, and whichever of its passkeys the ceremony at hand
// may use. It carries no policy about which passkeys those are -- each
// call site decides (current RP ID only, see usable).
type webauthnUser struct {
	id          []byte
	username    string
	credentials []webauthn.Credential
}

func (u webauthnUser) WebAuthnID() []byte                         { return u.id }
func (u webauthnUser) WebAuthnName() string                       { return u.username }
func (u webauthnUser) WebAuthnDisplayName() string                { return u.username }
func (u webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// passkeyToCredential converts a stored gauntlet.Passkey into the
// library's Credential. A field-by-field copy: gauntlet.Passkey mirrors
// the library's shapes so the root package need not import it.
func passkeyToCredential(pk gauntlet.Passkey) webauthn.Credential {
	var transports []protocol.AuthenticatorTransport
	if len(pk.Transports) > 0 {
		transports = make([]protocol.AuthenticatorTransport, len(pk.Transports))
		for i, t := range pk.Transports {
			transports[i] = protocol.AuthenticatorTransport(t)
		}
	}
	return webauthn.Credential{
		ID:        pk.ID,
		PublicKey: pk.PublicKey,
		Transport: transports,
		Flags: webauthn.CredentialFlags{
			UserPresent:    pk.Flags.UserPresent,
			UserVerified:   pk.Flags.UserVerified,
			BackupEligible: pk.Flags.BackupEligible,
			BackupState:    pk.Flags.BackupState,
		},
		Authenticator: webauthn.Authenticator{SignCount: pk.SignCount},
	}
}

// credentialToPasskey is passkeyToCredential's inverse, building the
// record Store.AddPasskey stores from a just-completed registration.
// rpID is always the current one -- a passkey is only ever created
// against the relying party it is being created on. Name and CreatedAt
// are left for the caller (gauntlet.PasskeyCeremony.FinishRegistration).
func credentialToPasskey(cred webauthn.Credential, rpID string) gauntlet.Passkey {
	transports := make([]string, len(cred.Transport))
	for i, t := range cred.Transport {
		transports[i] = string(t)
	}
	return gauntlet.Passkey{
		ID:         cred.ID,
		PublicKey:  cred.PublicKey,
		SignCount:  cred.Authenticator.SignCount,
		Transports: transports,
		Flags: gauntlet.PasskeyFlags{
			UserPresent:    cred.Flags.UserPresent,
			UserVerified:   cred.Flags.UserVerified,
			BackupEligible: cred.Flags.BackupEligible,
			BackupState:    cred.Flags.BackupState,
		},
		RPID: rpID,
	}
}

// usable returns the library credentials for u's passkeys registered
// under the current RP ID. A passkey registered under an earlier public
// URL is stale: it can never complete a ceremony here, so it is left out
// of login's allowed list and registration's exclude list alike, while
// gate still lists it and lets it be removed.
func (rp *RelyingParty) usable(u *gauntlet.User) []webauthn.Credential {
	var out []webauthn.Credential
	for _, pk := range u.Passkeys {
		if pk.RPID == rp.rpID {
			out = append(out, passkeyToCredential(pk))
		}
	}
	return out
}

func (rp *RelyingParty) user(u *gauntlet.User, creds []webauthn.Credential) webauthnUser {
	return webauthnUser{id: []byte(u.ID), username: u.Username, credentials: creds}
}

// seal stamps sd with the ceremony's expiry and seals it. The library
// sets Expires itself only when its timeout enforcement is on, which it
// is not here, so Begin sets it, as mikroview does.
func seal(c *sessionCodec, sd *webauthn.SessionData, options any) (json.RawMessage, string, error) {
	sd.Expires = time.Now().Add(ceremonyLifetime)
	sealed, err := c.encode(*sd)
	if err != nil {
		return nil, "", err
	}
	raw, err := json.Marshal(options)
	if err != nil {
		return nil, "", fmt.Errorf("passkey: encoding ceremony options: %w", err)
	}
	return raw, sealed, nil
}

// open decodes sealed and refuses a ceremony past its expiry. The
// library makes the same expiry check, but its error cannot be told
// apart from any other refusal; checked here first, an expired ceremony
// is reported as gauntlet.ErrPasskeyCeremonyInvalid like every other
// unusable one.
func open(c *sessionCodec, sealed string) (webauthn.SessionData, error) {
	sd, err := c.decode(sealed)
	if err != nil {
		return webauthn.SessionData{}, err
	}
	if sd.Expires.IsZero() || !time.Now().Before(sd.Expires) {
		return webauthn.SessionData{}, fmt.Errorf("passkey: ceremony expired: %w", gauntlet.ErrPasskeyCeremonyInvalid)
	}
	return sd, nil
}

// BeginRegistration starts registering a new passkey on u. Every passkey
// u already holds under the current RP ID is excluded, so an
// authenticator cannot be registered twice.
func (rp *RelyingParty) BeginRegistration(u *gauntlet.User) (json.RawMessage, string, error) {
	if !rp.ready() {
		return nil, "", ErrNotReady
	}
	var exclude []protocol.CredentialDescriptor
	for _, cred := range rp.usable(u) {
		exclude = append(exclude, cred.Descriptor())
	}
	// Preferred, never required, on every registration (ADR-0012): a
	// passkey a platform authenticator makes is discoverable anyway, one
	// that cannot be still registers as a second factor, and only a
	// discoverable one can sign in alone.
	creation, sd, err := rp.wa.BeginRegistration(rp.user(u, nil),
		webauthn.WithExclusions(exclude),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred))
	if err != nil {
		return nil, "", fmt.Errorf("passkey: beginning registration: %w", err)
	}
	return seal(registerCodec, sd, creation)
}

// FinishRegistration verifies the browser's response to the options
// BeginRegistration returned and gives back the credential to store.
//
// The challenge is not claimed here: registrations are spent by gate,
// by the sealed cookie's hash, where the store decides (ruling S1 on
// #20) -- it claims the ceremony once this returns a credential and
// before Store.AddPasskey writes, so one begin stores at most one
// passkey. A response this refuses (a wrong origin, a bad signature, a
// malformed body) leaves the ceremony open for a corrected one.
func (rp *RelyingParty) FinishRegistration(u *gauntlet.User, sealed string, credential json.RawMessage) (gauntlet.Passkey, error) {
	if !rp.ready() {
		return gauntlet.Passkey{}, ErrNotReady
	}
	sd, err := open(registerCodec, sealed)
	if err != nil {
		return gauntlet.Passkey{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(credential)
	if err != nil {
		return gauntlet.Passkey{}, fmt.Errorf("passkey: parsing the registration response: %w", err)
	}
	cred, err := rp.wa.CreateCredential(rp.user(u, nil), sd, parsed)
	if err != nil {
		return gauntlet.Passkey{}, fmt.Errorf("passkey: verifying the registration response: %w", err)
	}
	return credentialToPasskey(*cred, rp.rpID), nil
}

// BeginLogin starts a login ceremony allowing only u's passkeys under
// the current RP ID -- the second step behind a password, never a
// discoverable login (BeginSignIn is that one).
func (rp *RelyingParty) BeginLogin(u *gauntlet.User) (json.RawMessage, string, error) {
	if !rp.ready() {
		return nil, "", ErrNotReady
	}
	creds := rp.usable(u)
	if len(creds) == 0 {
		return nil, "", ErrNoUsablePasskey
	}
	assertion, sd, err := rp.wa.BeginLogin(rp.user(u, creds))
	if err != nil {
		return nil, "", fmt.Errorf("passkey: beginning login: %w", err)
	}
	// The allowed list goes to the browser in the options, where it does
	// its work, but not into the sealed state (ruling R3 on #20). A
	// credential ID may be up to 1023 bytes, so a sealed list would cap
	// an account at a handful of passkeys before the cookie outgrew a
	// browser's limit, and it is a copy of what the store already holds.
	// With no sealed list the library requires the asserted credential
	// to be one the user adapter supplies (validateLogin, step 3), and
	// FinishLogin supplies exactly the account's usable passkeys, read at
	// finish -- the same check, and fresher: a passkey deleted mid-
	// ceremony is refused.
	sd.AllowedCredentialIDs = nil
	return seal(assertCodec, sd, assertion)
}

// FinishLogin verifies the browser's assertion against the ceremony
// BeginLogin started. A nil error means the signature checked out for
// one of u's usable passkeys. UserVerified reports whether the
// authenticator also checked the person; this ceremony asks for that
// but does not require it.
//
// CloneWarning comes from the library: set when the presented counter
// is at or below the stored one and either is non-zero, never for
// 0 -> 0. A clone-warned assertion does not claim the challenge -- the
// caller refuses it, and the ceremony stays open for an authenticator
// that is not suspect, as in mikroview. Every other verified assertion
// claims its challenge, so the same sealed state and assertion cannot
// sign in twice, whatever the counter says.
func (rp *RelyingParty) FinishLogin(u *gauntlet.User, sealed string, assertion json.RawMessage) (gauntlet.PasskeyAssertion, error) {
	if !rp.ready() {
		return gauntlet.PasskeyAssertion{}, ErrNotReady
	}
	sd, err := open(assertCodec, sealed)
	if err != nil {
		return gauntlet.PasskeyAssertion{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(assertion)
	if err != nil {
		return gauntlet.PasskeyAssertion{}, fmt.Errorf("passkey: parsing the assertion: %w", err)
	}
	cred, err := rp.wa.ValidateLogin(rp.user(u, rp.usable(u)), sd, parsed)
	if err != nil {
		return gauntlet.PasskeyAssertion{}, fmt.Errorf("passkey: verifying the assertion: %w", err)
	}
	out := gauntlet.PasskeyAssertion{
		CredentialID: cred.ID,
		SignCount:    parsed.Response.AuthenticatorData.Counter,
		CloneWarning: cred.Authenticator.CloneWarning,
		UserVerified: parsed.Response.AuthenticatorData.Flags.HasUserVerified(),
	}
	if out.CloneWarning {
		return out, nil
	}
	if !spentLoginChallenges.Claim(sd.Challenge, sd.Expires, time.Now()) {
		return gauntlet.PasskeyAssertion{}, fmt.Errorf("passkey: challenge already used: %w", gauntlet.ErrPasskeyCeremonyInvalid)
	}
	return out, nil
}

// BeginSignIn starts a client-side discoverable login (WebAuthn Level 3):
// no account is named and no credential allowed, so the browser offers
// whichever passkeys it holds for this relying party, and user
// verification is required (NIST SP 800-63B-4: a multi-factor
// cryptographic authenticator, AAL2). Its sealed state is under its own
// key (signInCodec), so it finishes nothing but FinishSignIn.
func (rp *RelyingParty) BeginSignIn() (json.RawMessage, string, error) {
	if !rp.ready() {
		return nil, "", ErrNotReady
	}
	assertion, sd, err := rp.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, "", fmt.Errorf("passkey: beginning sign-in: %w", err)
	}
	return seal(signInCodec, sd, assertion)
}

// errUnknownUserHandle is what the library is told when lookup names no
// account for the assertion's user handle; the caller already knows,
// from lookup, and it is only ever read from the log.
var errUnknownUserHandle = errors.New("passkey: the user handle names no account that can sign in")

// FinishSignIn verifies the browser's assertion for a discoverable
// login. The account is whoever the user handle names: lookup is called
// with it once the assertion is parsed and before the signature is
// checked, so gate can apply the account's limits first, and what it
// returns is the account whose usable passkeys (current RP ID only) the
// signature is checked against. An assertion with no user handle, or one
// that did not verify the user, is refused -- the library's session
// requires it and the flag is read again here from what the
// authenticator signed.
//
// As FinishLogin does: a clone-warned assertion is returned, not spent,
// for the caller to refuse; every other verified assertion claims its
// challenge so the same one cannot sign in twice.
func (rp *RelyingParty) FinishSignIn(lookup func(userHandle []byte) (*gauntlet.User, bool), sealed string, assertion json.RawMessage) (*gauntlet.User, gauntlet.PasskeyAssertion, error) {
	if !rp.ready() {
		return nil, gauntlet.PasskeyAssertion{}, ErrNotReady
	}
	sd, err := open(signInCodec, sealed)
	if err != nil {
		return nil, gauntlet.PasskeyAssertion{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(assertion)
	if err != nil {
		return nil, gauntlet.PasskeyAssertion{}, fmt.Errorf("passkey: parsing the assertion: %w", err)
	}
	if len(parsed.Response.UserHandle) == 0 {
		return nil, gauntlet.PasskeyAssertion{}, errors.New("passkey: the assertion carries no user handle")
	}
	var found *gauntlet.User
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		u, ok := lookup(userHandle)
		if !ok || u == nil {
			return nil, errUnknownUserHandle
		}
		found = u
		return rp.user(u, rp.usable(u)), nil
	}
	_, cred, err := rp.wa.ValidatePasskeyLogin(handler, sd, parsed)
	if err != nil {
		return nil, gauntlet.PasskeyAssertion{}, fmt.Errorf("passkey: verifying the sign-in assertion: %w", err)
	}
	flags := parsed.Response.AuthenticatorData.Flags
	if !flags.HasUserVerified() {
		return nil, gauntlet.PasskeyAssertion{}, errors.New("passkey: the sign-in assertion did not verify the user")
	}
	out := gauntlet.PasskeyAssertion{
		CredentialID: cred.ID,
		SignCount:    parsed.Response.AuthenticatorData.Counter,
		CloneWarning: cred.Authenticator.CloneWarning,
		UserVerified: true,
	}
	if out.CloneWarning {
		return found, out, nil
	}
	if !spentLoginChallenges.Claim(sd.Challenge, sd.Expires, time.Now()) {
		return nil, gauntlet.PasskeyAssertion{}, fmt.Errorf("passkey: challenge already used: %w", gauntlet.ErrPasskeyCeremonyInvalid)
	}
	return found, out, nil
}
