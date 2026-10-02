package gate

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// -- Passkeys (G8, docs/adr/0004-passkey-ceremony.md) --------------------
//
// Ported from mikroview's internal/api/passkey.go: the same paths and
// bodies, so its frontend moves onto Routes without edits. The WebAuthn
// ceremony itself runs behind Deps.Passkeys (gauntlet.PasskeyCeremony,
// implemented by gauntlet/passkey); this file never imports the
// WebAuthn library or gauntlet/passkey. It owns everything either side
// of the ceremony: the two cookies (passkey_cookie.go), sessions,
// recovery codes, the login limiter and audit, in the shape the TOTP
// routes (totp_handler.go) already have.
//
// Divergences from mikroview, each deliberate (ADR-0004):
//   - Deps.Passkeys nil answers 404 on every passkey route, as OIDC-off
//     does; mikroview never runs without a relying party.
//   - A relying party that is not ready answers 409 naming its status,
//     where mikroview answers 503: on every gate route 503 already means
//     "setup required". Mikroview's frontend reads the reason from the
//     session body's passkeys.status, not from this code.
//   - register/begin takes {password} and re-checks it (ruling R1 on
//     #20), which mikroview does not: mikroview's add-passkey screen
//     needs a password field first. login/factor/begin decodes no body.
//   - The admin refusal does not name a console tool, as the TOTP one
//     does not.
//
// As in totp_handler.go, every handler that acts on something another
// request wrote re-reads the account through g.deps.Users rather than
// trusting UserFromContext's copy.

// passkeysOff answers 404 when this application has no passkeys
// (Deps.Passkeys nil), and reports whether it did.
func (g *Gate) passkeysOff(w http.ResponseWriter, r *http.Request) bool {
	if g.deps.Passkeys == nil {
		http.NotFound(w, r)
		return true
	}
	return false
}

// passkeysReady is false while Deps.Passkeys is nil or not ready.
func (g *Gate) passkeysReady() bool {
	return g.deps.Passkeys != nil && g.deps.Passkeys.Status() == gauntlet.PasskeyStatusReady
}

// writePasskeysNotReady is the 409 every ceremony-starting route and the
// assertion step give while the relying party is not ready. The status
// word travels in the message; a frontend reads it from GET
// /api/auth/session's passkeys.status, so this only has to be
// diagnosable.
func (g *Gate) writePasskeysNotReady(w http.ResponseWriter) {
	http.Error(w, fmt.Sprintf("passkeys are not available on this deployment (%s)", g.deps.Passkeys.Status()), http.StatusConflict)
}

// usablePasskeyCount is how many of u's passkeys are registered under
// the relying party's current RP ID -- 0 whenever it is not ready. A
// passkey registered under an earlier public URL is stale: still listed
// and removable, never offered at login.
func (g *Gate) usablePasskeyCount(u *gauntlet.User) int {
	if !g.passkeysReady() {
		return 0
	}
	rpID := g.deps.Passkeys.RPID()
	n := 0
	for _, pk := range u.Passkeys {
		if pk.RPID == rpID {
			n++
		}
	}
	return n
}

// -- GET /api/auth/passkeys ----------------------------------------------

// passkeySummary is one row of the passkey list, and the shape every
// route returning a passkey uses.
type passkeySummary struct {
	// ID is the credential ID, base64url without padding -- the {id} the
	// rename and delete routes take.
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"createdAt"`
	LastUsedAt time.Time `json:"lastUsedAt,omitzero"`
	Transports []string  `json:"transports,omitempty"`
	// Stale is true only when the relying party is ready and this
	// passkey was registered under a different RP ID (the public URL
	// changed since). While the relying party is not ready at all, that
	// is a deployment-wide state reported on the session body, not every
	// passkey going stale at once, so Stale stays false.
	Stale bool   `json:"stale"`
	RPID  string `json:"rpId"`
}

func toPasskeySummary(pk gauntlet.Passkey, currentRPID string) passkeySummary {
	return passkeySummary{
		ID:         base64.RawURLEncoding.EncodeToString(pk.ID),
		Name:       pk.Name,
		CreatedAt:  pk.CreatedAt,
		LastUsedAt: pk.LastUsedAt,
		Transports: pk.Transports,
		Stale:      currentRPID != "" && pk.RPID != currentRPID,
		RPID:       pk.RPID,
	}
}

// handlePasskeysList answers the caller's own passkeys, stale ones
// included. UserFromContext's copy is fresh enough: nothing earlier in
// this request wrote to it.
func (g *Gate) handlePasskeysList(w http.ResponseWriter, r *http.Request) {
	if g.passkeysOff(w, r) {
		return
	}
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, "sign in first")
		return
	}
	currentRPID := g.deps.Passkeys.RPID()
	out := make([]passkeySummary, 0, len(user.Passkeys))
	for _, pk := range user.Passkeys {
		out = append(out, toPasskeySummary(pk, currentRPID))
	}
	writeJSON(w, http.StatusOK, out)
}

// -- POST /api/auth/passkeys/register/begin -------------------------------

type passkeyRegisterBeginRequest struct {
	Password string `json:"password"`
}

// handlePasskeyRegisterBegin starts registering a passkey on the
// caller's own account and answers the W3C creation options the browser
// hands to navigator.credentials.create().
//
// Password-gated through recheckPassword, as TOTP enrolment is (ruling
// R1 on #20): a factor planted by someone holding only a stolen session
// cookie would lock the owner out at their next login, hand the planter
// the recovery codes and end the owner's sessions, and the password is
// the one thing a cookie does not carry. Checked here rather than at
// finish so a refusal comes before anyone touches their key; finish's
// sealed cookie is proof that this check passed within five minutes.
//
// The order is deliberate: an account with no local password is told
// 409 before any body is read (ruling R4 -- its identity provider owns
// its identity, and a local factor behind no local password protects
// nothing); then the password, before readiness, so the refusal costs
// the same whether or not passkeys work here.
func (g *Gate) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if g.passkeysOff(w, r) {
		return
	}
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, "sign in first")
		return
	}
	if !user.LocalPassword() {
		http.Error(w, "this account signs in through your identity provider -- a passkey is not offered", http.StatusConflict)
		return
	}
	var req passkeyRegisterBeginRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	// The freshly authenticated copy is also the re-read the exclude
	// list needs: this account's passkeys as of now, not as of Protect's
	// session check.
	current, ok := g.recheckPassword(w, user, req.Password, "incorrect password", g.now())
	if !ok {
		return
	}
	if !g.passkeysReady() {
		g.writePasskeysNotReady(w)
		return
	}
	options, sealed, err := g.deps.Passkeys.BeginRegistration(current)
	if err != nil {
		g.logError("beginning passkey registration for " + current.Username + ": " + err.Error())
		http.Error(w, "unable to start passkey registration", http.StatusInternalServerError)
		return
	}
	g.setPasskeyRegisterCookie(w, sealed)
	writeJSON(w, http.StatusOK, options)
}

// -- POST /api/auth/passkeys/register/finish ------------------------------

type passkeyRegisterFinishRequest struct {
	// Credential is the browser's PublicKeyCredential JSON, handed to the
	// ceremony unchanged.
	Credential json.RawMessage `json:"credential"`
	Name       string          `json:"name"`
}

type passkeyRegisterFinishResponse struct {
	Passkey passkeySummary `json:"passkey"`
	// RecoveryCodes is null except when this was the account's first
	// second factor of either kind. No omitempty: the frontend contract
	// is `recoveryCodes: [...]|null`, not an absent key.
	RecoveryCodes []string `json:"recoveryCodes"`
	// AlreadyIssued is true when the account already held recovery codes
	// -- totpConfirmResponse's field of the same name and meaning. A mint
	// failure is its own 500, so null here only ever means "already
	// issued".
	AlreadyIssued bool `json:"alreadyIssued,omitempty"`
}

// handlePasskeyRegisterFinish completes the registration register/begin
// started: verify, AddPasskey, and -- on the account's first factor --
// revoke every session, reissue this browser's, and mint recovery codes.
//
// The ceremony ends at the first finish the library accepts (ruling S1
// on #20): one password-proved begin stores at most one passkey. Its
// sealed cookie's hash is claimed in spentRegistrations after
// FinishRegistration accepts and before AddPasskey writes, so of two
// finishes racing on one cookie only one can store; a stored passkey
// (200), a store refusal (409 duplicate or limit, 500 on a failed save)
// and a lost race all end it, and the cookie is cleared with the answer.
// A cookie already spent is refused before the body is read.
//
// Refusals that do not end the ceremony are the library's, told apart
// from a dead ceremony by gauntlet.ErrPasskeyCeremonyInvalid: a dead
// ceremony (the cookie is missing, expired, tampered with or sealed for
// the other ceremony) answers 401 "start registration again" and clears
// the cookie, since it can never succeed; a refused credential (wrong
// origin, bad signature, malformed) answers 400 and keeps the cookie, so
// a corrected response can finish inside the same five minutes.
//
// A malformed body is refused (400) before the ceremony cookie is
// examined, since only the ceremony can judge the cookie and it needs
// the body to do so; a dead cookie sent with a malformed body is left
// for the next request to clear (ruling R5 on #20, accepted: no
// frontend sends such a body).
func (g *Gate) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if g.passkeysOff(w, r) {
		return
	}
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, "sign in first")
		return
	}
	if !g.passkeysReady() {
		g.writePasskeysNotReady(w)
		return
	}
	cookie, err := r.Cookie(passkeyRegisterCookieName)
	if err != nil {
		g.clearPasskeyRegisterCookie(w)
		writeUnauthorized(w, "start registration again")
		return
	}
	now := g.now()
	key := registrationKey(cookie.Value)
	if spentRegistrations.Spent(key, now) {
		g.clearPasskeyRegisterCookie(w)
		writeUnauthorized(w, "start registration again")
		return
	}

	var req passkeyRegisterFinishRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Re-read: whether this is the first factor depends on what other
	// requests have written since Protect resolved the session.
	current, ok := g.deps.Users.Get(user.ID)
	if !ok {
		writeUnauthorized(w, "sign in first")
		return
	}

	pk, err := g.deps.Passkeys.FinishRegistration(current, cookie.Value, req.Credential)
	if errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		g.clearPasskeyRegisterCookie(w)
		writeUnauthorized(w, "start registration again")
		return
	}
	if err != nil {
		http.Error(w, "that passkey couldn't be registered -- try again", http.StatusBadRequest)
		return
	}
	// The library accepted it: from here the ceremony is spent, whatever
	// the store says. Forgotten one cookie lifetime after the claim (gate
	// cannot read the sealed Expires, which under a steady clock is never
	// later), plus the set's grace of another lifetime.
	if !spentRegistrations.Claim(key, now.Add(passkeyCeremonyCookieMaxAge), now) {
		g.clearPasskeyRegisterCookie(w)
		writeUnauthorized(w, "start registration again")
		return
	}

	pk.Name = req.Name
	pk.CreatedAt = now
	wasFirstFactor := !current.HasSecondFactor()

	stored, err := g.deps.Users.AddPasskey(current.ID, pk)
	if err != nil {
		g.clearPasskeyRegisterCookie(w) // the ceremony is spent: begin again
		status := http.StatusInternalServerError
		if errors.Is(err, gauntlet.ErrPasskeyDuplicate) || errors.Is(err, gauntlet.ErrPasskeyLimitReached) {
			status = http.StatusConflict
		}
		g.writeAuthError(w, r, err, status)
		return
	}

	// Mint-if-absent under the store's lock -- never re-mint, and never
	// let two first factors racing each other both mint (see
	// handleTOTPConfirm's identical call).
	codes, alreadyIssued, mintErr := g.deps.Users.GenerateRecoveryCodesIfAbsent(current.ID, now)

	// The passkey is live from AddPasskey on, so rotation and the audit
	// record happen whether or not the mint worked: no retry could do
	// them later, since begin now excludes this passkey.
	if wasFirstFactor {
		g.deps.Sessions.RevokeAllForUser(current.ID)
		g.issueSession(w, r, current.ID, now)
	}
	g.clearPasskeyRegisterCookie(w)
	detail := "name=" + stored.Name
	if mintErr != nil {
		detail += "; recovery codes could not be saved"
	}
	g.audit(current.Username, "account.passkey_added", current.Username, detail)

	if mintErr != nil {
		// Not answered like "already issued" (null codes, 200): nothing
		// was ever issued for this account to fall back on.
		g.logError("generating recovery codes for " + current.Username + " after registering a passkey: " + mintErr.Error())
		http.Error(w, "the passkey is now active, but recovery codes could not be saved -- generate a new set from account settings", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, passkeyRegisterFinishResponse{
		Passkey:       toPasskeySummary(stored, g.deps.Passkeys.RPID()),
		RecoveryCodes: codes,
		AlreadyIssued: alreadyIssued,
	})
}

// -- PATCH /api/auth/passkeys/{id} ----------------------------------------

type passkeyRenameRequest struct {
	Name string `json:"name"`
}

// handlePasskeyRename renames one of the caller's own passkeys. Cosmetic
// and reversible, so no password (see Store.RenamePasskey), and not
// audited.
func (g *Gate) handlePasskeyRename(w http.ResponseWriter, r *http.Request) {
	if g.passkeysOff(w, r) {
		return
	}
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, "sign in first")
		return
	}
	var req passkeyRenameRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	credID, err := base64.RawURLEncoding.DecodeString(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid passkey id", http.StatusBadRequest)
		return
	}
	pk, err := g.deps.Users.RenamePasskey(user.ID, credID, req.Name)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, gauntlet.ErrPasskeyNotFound) {
			status = http.StatusNotFound
		}
		g.writeAuthError(w, r, err, status)
		return
	}
	writeJSON(w, http.StatusOK, toPasskeySummary(pk, g.deps.Passkeys.RPID()))
}

// -- DELETE /api/auth/passkeys/{id} ---------------------------------------

type passkeyDeleteRequest struct {
	Password string `json:"password"`
}

// handlePasskeyDelete removes one of the caller's own passkeys, gated by
// their password through recheckPassword, as handleTOTPDelete is. When
// that leaves the account with no second factor, every session on it is
// revoked and signedOut says so -- the store has already cleared the
// recovery codes in the same write.
func (g *Gate) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	if g.passkeysOff(w, r) {
		return
	}
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, "sign in first")
		return
	}
	var req passkeyDeleteRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	credID, err := base64.RawURLEncoding.DecodeString(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid passkey id", http.StatusBadRequest)
		return
	}

	now := g.now()
	if _, ok := g.recheckPassword(w, user, req.Password, "incorrect password", now); !ok {
		return
	}

	removed, err := g.deps.Users.DeletePasskey(user.ID, credID)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, gauntlet.ErrPasskeyNotFound) {
			status = http.StatusNotFound
		}
		g.writeAuthError(w, r, err, status)
		return
	}

	signedOut := false
	if updated, ok := g.deps.Users.Get(user.ID); ok && !updated.HasSecondFactor() {
		g.deps.Sessions.RevokeAllForUser(user.ID)
		signedOut = true
	}

	g.audit(user.Username, "account.passkey_removed", user.Username, "name="+removed.Name)
	writeJSON(w, http.StatusOK, map[string]any{"removed": true, "signedOut": signedOut})
}

// -- POST /api/auth/login/factor/begin ------------------------------------

// handleLoginFactorBegin starts the passkey half of the second login
// step. It is reached with the pending-login cookie handleLogin set,
// before any session exists (exemptPaths).
//
// It takes the same login-limiter reservations as login/factor -- the
// address and the account, with the pending login's AfterReset honoured
// -- and keeps them, so a password alone cannot mint challenges without
// limit. login/factor gives them back when the assertion this begin
// mints signs the user in; a server-side failure here gives them back at
// once.
func (g *Gate) handleLoginFactorBegin(w http.ResponseWriter, r *http.Request) {
	if g.passkeysOff(w, r) {
		return
	}
	now := g.now()
	st, ok := g.pendingLogin(w, r, now)
	if !ok {
		return
	}
	user, ok := g.deps.Users.Get(st.UserID)
	if !ok {
		g.clearPendingLoginCookie(w)
		writeUnauthorized(w, "sign in again")
		return
	}
	if !g.passkeysReady() {
		g.writePasskeysNotReady(w)
		return
	}
	if g.usablePasskeyCount(user) == 0 {
		http.Error(w, "this account has no passkey usable at this address", http.StatusConflict)
		return
	}

	res, ok := g.reserveLogin(w, r, user.ID, user.Username, st.AfterReset, now)
	if !ok {
		return
	}
	defer g.releaseAfterReset(res)

	options, sealed, err := g.deps.Passkeys.BeginLogin(user)
	if err != nil {
		// This server's failure, not the caller's attempt.
		g.releaseLogin(res, now)
		g.logError("beginning passkey sign-in for " + user.Username + ": " + err.Error())
		http.Error(w, "unable to start passkey sign-in", http.StatusInternalServerError)
		return
	}
	g.setPasskeyAssertCookie(w, sealed)
	writeJSON(w, http.StatusOK, options)
}

// -- the passkey branch of POST /api/auth/login/factor --------------------

// passkeyNotVerified is the one message every refused assertion gets:
// which check failed is not something a caller needs back.
const passkeyNotVerified = "that passkey couldn't be verified -- use another way in"

// passkeyStartAgain is the answer to a dead login ceremony: nothing
// sent on it can ever succeed, so the frontend begins again.
const passkeyStartAgain = "start passkey sign-in again"

// verifyPasskeyAssertion is handleLoginFactor's passkey branch, called
// with the reservations res already held. It writes its own response on
// every refusal and returns false; on success it writes nothing and
// returns true, and the caller completes the login.
//
// A refused assertion keeps the reservations, like a wrong code. A
// clone warning -- the library's verdict that the counter failed to
// advance (never for 0 -> 0, how most platform passkeys behave) --
// refuses the login, is audited with both counts, leaves the stored
// count alone and leaves the ceremony cookie in place. Otherwise
// RecordPasskeyAssertionIfFresh decides and records under the store's
// lock, so two copies of one assertion cannot both win.
//
// Every refusal answers 401, keeps the reservations and counts toward
// the account's run of second-factor failures (secondFactorFailed): the
// caller holds a pending login, so had the right password. A dead ceremony
// (the cookie missing, or gauntlet.ErrPasskeyCeremonyInvalid: expired,
// tampered with, already used) answers "start passkey sign-in again" and
// clears the cookie, since it can never succeed; anything else answers
// passkeyNotVerified and keeps it, so a corrected assertion can still
// finish inside the window.
func (g *Gate) verifyPasskeyAssertion(w http.ResponseWriter, r *http.Request, user *gauntlet.User, assertion json.RawMessage, res loginReservation, now time.Time) bool {
	refuse := func(msg string) bool {
		g.endAfterReset(res)
		g.secondFactorFailed(user, now)
		writeUnauthorized(w, msg)
		return false
	}
	if !g.passkeysReady() {
		g.writePasskeysNotReady(w)
		return false
	}
	cookie, err := r.Cookie(passkeyAssertCookieName)
	if err != nil {
		g.clearPasskeyAssertCookie(w)
		return refuse(passkeyStartAgain)
	}

	verified, err := g.deps.Passkeys.FinishLogin(user, cookie.Value, assertion)
	if errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		g.clearPasskeyAssertCookie(w)
		return refuse(passkeyStartAgain)
	}
	if err != nil {
		return refuse(passkeyNotVerified)
	}

	if verified.CloneWarning {
		// "unknown" when the passkey was removed between FinishLogin's
		// read of the account and this one.
		stored := "unknown"
		for _, pk := range user.Passkeys {
			if bytes.Equal(pk.ID, verified.CredentialID) {
				stored = fmt.Sprint(pk.SignCount)
			}
		}
		g.audit(user.Username, "account.passkey_clone_suspected", user.Username,
			fmt.Sprintf("credential=%s presentedCount=%d storedCount=%s",
				base64.RawURLEncoding.EncodeToString(verified.CredentialID), verified.SignCount, stored))
		return refuse(passkeyNotVerified)
	}

	accepted, err := g.deps.Users.RecordPasskeyAssertionIfFresh(user.ID, verified.CredentialID, verified.SignCount, now)
	switch {
	case errors.Is(err, gauntlet.ErrPasskeyNotFound), errors.Is(err, gauntlet.ErrUserNotFound):
		// Removed since FinishLogin read the account: nothing to sign in
		// with any more.
		return refuse(passkeyNotVerified)
	case err != nil:
		// A counter that could not be saved is refused (accepted is
		// false), but as the backend failing, not a wrong guess -- the
		// same stance as the TOTP branch's VerifyAndRecordTOTP error. A
		// failed save on a 0 -> 0 login never gets here: the store logs
		// it and accepts. Both reservations go back -- this request's and
		// the one login/factor/begin took for the challenge -- or a
		// backend outage would cost an attempt per try and end in a 429
		// for an owner who never guessed wrong.
		g.releaseLogin(res, now)
		g.releaseLogin(res, now)
		g.logError("recording passkey assertion for " + user.Username + ": " + err.Error())
		http.Error(w, "unable to complete sign-in", http.StatusInternalServerError)
		return false
	case !accepted:
		return refuse(passkeyNotVerified)
	}

	g.clearPasskeyAssertCookie(w)
	return true
}

// -- DELETE /api/auth/users/{id}/passkeys ---------------------------------

// handlePasskeysAdminClear lets an admin remove every passkey on another
// user's account -- handleTOTPAdminClear's twin, including refusing the
// caller's own account: an admin who lost their own factor has no
// console tool in this module (docs/design.md §1.7). ClearPasskeys drops
// the recovery codes only when no factor of either kind is left.
func (g *Gate) handlePasskeysAdminClear(w http.ResponseWriter, r *http.Request) {
	if g.passkeysOff(w, r) {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "user id is required", http.StatusBadRequest)
		return
	}
	if caller := UserFromContext(r); caller != nil && caller.ID == id {
		http.Error(w, "an administrator cannot clear their own passkeys here", http.StatusConflict)
		return
	}

	target, ok := g.deps.Users.Get(id)
	if !ok {
		http.Error(w, "no such user", http.StatusNotFound)
		return
	}
	if err := g.deps.Users.ClearPasskeys(id); err != nil {
		g.writeAuthError(w, r, err, http.StatusInternalServerError)
		return
	}

	g.audit(auditActor(r), "user.passkeys_cleared", target.Username, "passkeys removed by admin")
	writeJSON(w, http.StatusOK, map[string]any{"username": target.Username, "cleared": true})
}
