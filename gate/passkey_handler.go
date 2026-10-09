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
	"github.com/tomlawesome/gauntlet/internal/plaintext"
)

// -- Passkeys (G8, docs/adr/0004-passkey-ceremony.md) --------------------
//
// Ported from mikroview's internal/api/passkey.go: the same paths and
// bodies, so its frontend moves onto Routes without edits. The WebAuthn
// ceremony itself runs behind Deps.Passkeys (gauntlet.PasskeyCeremony,
// implemented by gauntlet/passkey); this file never imports the
// WebAuthn library or gauntlet/passkey. It owns everything either side
// of the ceremony: the two cookies (passkey_cookie.go), sessions,
// recovery codes (held with the account's first factor until confirmed,
// #58), the login limiter and audit, in the shape the TOTP routes
// (totp_handler.go) already have.
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
		writeProblem(w, http.StatusNotFound, classNotFound, "", nil)
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
	writeProblem(w, http.StatusConflict, classConflict, fmt.Sprintf("passkeys are not available on this deployment (%s)", g.deps.Passkeys.Status()), nil)
}

// usablePasskeyCount is how many of u's passkeys are registered under
// the relying party's current RP ID -- 0 whenever it is not ready. A
// passkey registered under an earlier public URL is stale: still listed
// and removable, never offered at login. A passkey on hold (#58) is not
// in u.Passkeys at all, so never counts.
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
// included. A passkey on hold (#58) is left out: it is not live until
// its recovery codes are confirmed, and the list, the session body's
// count and sign-in all agree on that. UserFromContext's copy is fresh
// enough: nothing earlier in this request wrote to it.
func (g *Gate) handlePasskeysList(w http.ResponseWriter, r *http.Request) {
	if g.passkeysOff(w, r) {
		return
	}
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, classSignInRequired, "sign in first")
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
// the same whether or not passkeys work here. An account with a first
// factor on hold (#58) is told 409 after the password: one enrolment at
// a time.
func (g *Gate) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if g.passkeysOff(w, r) {
		return
	}
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
	}
	if !user.LocalPassword() {
		writeProblem(w, http.StatusConflict, classConflict, "this account signs in through your identity provider -- a passkey is not offered", nil)
		return
	}
	var req passkeyRegisterBeginRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}
	// The freshly authenticated copy is also the re-read the exclude
	// list needs: this account's passkeys as of now, not as of Protect's
	// session check.
	now := g.now()
	current, ok := g.recheckPassword(w, r, user, req.Password, "incorrect password", now)
	if !ok {
		return
	}
	// One enrolment at a time (#58): a first factor held for its codes
	// to be confirmed is confirmed or expires before another starts.
	if current.EnrolmentHeld(now) {
		g.writeAuthError(w, r, gauntlet.ErrEnrolmentHeld, http.StatusConflict, classConflict)
		return
	}
	if !g.passkeysReady() {
		g.writePasskeysNotReady(w)
		return
	}
	options, sealed, err := g.deps.Passkeys.BeginRegistration(current)
	if err != nil {
		g.logError("beginning passkey registration for " + current.Username + ": " + err.Error())
		writeProblem(w, http.StatusInternalServerError, classServerError, "unable to start passkey registration", nil)
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
	// second factor of either kind: then the ten codes, in clear,
	// exactly once, saved with the passkey and held with it until
	// POST /api/auth/recovery-codes/confirm (#58). No omitempty: the
	// frontend contract is `recoveryCodes: [...]|null`, not an absent
	// key.
	RecoveryCodes []string `json:"recoveryCodes"`
	// PendingConfirmation is true when the passkey and RecoveryCodes are
	// on hold: not live, not listed and not a sign-in factor until the
	// caller confirms the codes were saved. Unconfirmed after
	// gauntlet.HeldEnrolmentLifetime, both are deleted.
	PendingConfirmation bool `json:"pendingConfirmation,omitempty"`
	// AlreadyIssued is true when the passkey was added live to an
	// account that already had a second factor: the account keeps the
	// one set of recovery codes it has, so none are issued.
	AlreadyIssued bool `json:"alreadyIssued,omitempty"`
}

// handlePasskeyRegisterFinish completes the registration register/begin
// started. On the account's first second factor (#58) the passkey and
// ten new recovery codes are saved together, in one write, on hold
// (gauntlet.Store.HoldFirstPasskey), and the codes are answered once:
// nothing goes live, no session is rotated and nothing is audited until
// the caller confirms the codes were saved (handleEnrolmentConfirm).
// On an account that already has a second factor the passkey is added
// live at once (AddLaterPasskey), with no codes, and audited here; if
// that factor has gone by the time of the write, the passkey is held
// with codes instead, as a first factor (#80).
//
// The ceremony ends at the first finish the library accepts (ruling S1
// on #20): one password-proved begin stores at most one passkey. Its
// sealed cookie's hash is claimed in spentRegistrations after
// FinishRegistration accepts and before the store writes, so of two
// finishes racing on one cookie only one can store; a stored passkey
// (200), a store refusal (409 duplicate, limit or an enrolment already
// on hold; 500 on a failed save) and a lost race all end it, and the
// cookie is cleared with the answer. A cookie already spent is refused
// once the body has been read.
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
//
// A name that is not plain text (#89) is refused (400) before the
// cookie too, so the ceremony stays live and the same credential can be
// finished again with a good name.
func (g *Gate) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if g.passkeysOff(w, r) {
		return
	}
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
	}
	if !g.passkeysReady() {
		g.writePasskeysNotReady(w)
		return
	}
	// The body first, as handleLoginFactor does: a malformed one is the
	// caller's mistake whatever the cookie holds, so it answers 400 and
	// leaves a live ceremony alone instead of reporting it dead.
	var req passkeyRegisterFinishRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}
	// The name next, for the same reason: a bad name is the caller's
	// mistake whatever the cookie holds, and refusing it here leaves the
	// ceremony live (nothing is claimed), so the same credential can be
	// finished again with a good name (#89).
	if !validPasskeyName(req.Name) {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, passkeyNameInvalidMessage, nil)
		return
	}

	cookie, err := r.Cookie(passkeyRegisterCookieName)
	if err != nil {
		g.clearPasskeyRegisterCookie(w)
		writeUnauthorized(w, classStepExpired, "start registration again")
		return
	}
	now := g.now()
	key := registrationKey(cookie.Value)
	if spentRegistrations.Spent(key, now) {
		g.clearPasskeyRegisterCookie(w)
		writeUnauthorized(w, classStepExpired, "start registration again")
		return
	}

	// Re-read: whether this is the first factor depends on what other
	// requests have written since Protect resolved the session.
	current, ok := g.deps.Users.Get(user.ID)
	if !ok {
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
	}

	pk, err := g.deps.Passkeys.FinishRegistration(current, cookie.Value, req.Credential)
	if errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		g.clearPasskeyRegisterCookie(w)
		writeUnauthorized(w, classStepExpired, "start registration again")
		return
	}
	if err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "that passkey couldn't be registered -- try again", nil)
		return
	}
	// The library accepted it: from here the ceremony is spent, whatever
	// the store says. Forgotten one cookie lifetime after the claim (gate
	// cannot read the sealed Expires, which under a steady clock is never
	// later), plus the set's grace of another lifetime.
	if !spentRegistrations.Claim(key, now.Add(passkeyCeremonyCookieMaxAge), now) {
		g.clearPasskeyRegisterCookie(w)
		writeUnauthorized(w, classStepExpired, "start registration again")
		return
	}
	g.clearPasskeyRegisterCookie(w) // spent whatever the store answers: begin again

	pk.Name = req.Name
	pk.CreatedAt = now
	rpID := g.deps.Passkeys.RPID()

	// The first factor: held with its codes, in one write. The store
	// decides again under its lock, so of two first factors racing only
	// one is held, and one that lost to a factor going live in between
	// is added live below instead.
	holdFirst := func() (done bool) {
		held, codes, err := g.deps.Users.HoldFirstPasskey(current.ID, pk, now)
		if err == nil {
			writeJSON(w, http.StatusOK, passkeyRegisterFinishResponse{
				Passkey:             toPasskeySummary(held, rpID),
				RecoveryCodes:       codes,
				PendingConfirmation: true,
			})
			return true
		}
		if !errors.Is(err, gauntlet.ErrSecondFactorExists) {
			g.writePasskeyStoreError(w, r, err)
			return true
		}
		return false
	}
	triedFirst := !current.HasSecondFactor()
	if triedFirst && holdFirst() {
		return
	}

	// Beside a live factor, whose codes stand. The store refuses under
	// its lock if that factor has gone since (taking the codes with it),
	// so this passkey never goes live without codes (#80): it is held
	// with its own instead, once. A factor that went live again in
	// between ends the ceremony with a 409.
	stored, err := g.deps.Users.AddLaterPasskey(current.ID, pk)
	if errors.Is(err, gauntlet.ErrNoOtherSecondFactor) {
		if !triedFirst && holdFirst() {
			return
		}
		g.writeAuthError(w, r, gauntlet.ErrSecondFactorExists, http.StatusConflict, classConflict)
		return
	}
	if err != nil {
		g.writePasskeyStoreError(w, r, err)
		return
	}
	// Quoted, as from= and the other user-supplied fields are: the name
	// is the user's own text, and a newline or terminal escape in it
	// must not forge or hide a line in the audit log.
	g.audit(r, current.Username, "account.passkey_added", current.Username, fmt.Sprintf("name=%q", stored.Name))
	writeJSON(w, http.StatusOK, passkeyRegisterFinishResponse{
		Passkey:       toPasskeySummary(stored, rpID),
		RecoveryCodes: nil,
		AlreadyIssued: true,
	})
	g.notify(r.Context(), &AccountNotice{
		Kind: NoticeSecondFactorAdded, UserID: current.ID, Username: current.Username, Role: current.Role, At: now,
		SecondFactor: &SecondFactorDetail{Method: "passkey", Name: plaintext.Clean(stored.Name)},
	})
}

// writePasskeyStoreError answers a refused passkey save: 409 for a
// duplicate, a full account or an enrolment already on hold, 500
// otherwise.
func (g *Gate) writePasskeyStoreError(w http.ResponseWriter, r *http.Request, err error) {
	status, class := http.StatusInternalServerError, classServerError
	if errors.Is(err, gauntlet.ErrPasskeyDuplicate) || errors.Is(err, gauntlet.ErrPasskeyLimitReached) || errors.Is(err, gauntlet.ErrEnrolmentHeld) {
		status, class = http.StatusConflict, classConflict
	}
	if errors.Is(err, gauntlet.ErrPasskeyNameInvalid) { // a backstop: the handler checked first
		status, class = http.StatusBadRequest, classInvalidRequest
	}
	g.writeAuthError(w, r, err, status, class)
}

// validPasskeyName is the root store's checkPasskeyName rule, applied
// before the ceremony is claimed or the passkey looked up: plain text
// with no U+FFFD (plaintext.ValidWithin, #89, #90). The limit given is
// len(name), which no name's character count can pass: a long name is
// cut by the store, not refused.
func validPasskeyName(name string) bool {
	return plaintext.ValidWithin(name, len(name))
}

// passkeyNameInvalidMessage is the plain-English 400 for a passkey name
// holding a control or format character, a line or paragraph separator
// (#89) or U+FFFD (#90).
const passkeyNameInvalidMessage = "that passkey name has characters that can't be shown as text -- use letters, numbers, spaces and punctuation"

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
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
	}
	var req passkeyRenameRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}
	if !validPasskeyName(req.Name) {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, passkeyNameInvalidMessage, nil)
		return
	}
	credID, err := base64.RawURLEncoding.DecodeString(r.PathValue("id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid passkey id", nil)
		return
	}
	pk, err := g.deps.Users.RenamePasskey(user.ID, credID, req.Name)
	if err != nil {
		status, class := http.StatusInternalServerError, classServerError
		if errors.Is(err, gauntlet.ErrPasskeyNotFound) {
			status, class = http.StatusNotFound, classNotFound
		}
		// The check above is the one that answers; the store's own is a
		// backstop, so a name it refuses is still the caller's mistake.
		if errors.Is(err, gauntlet.ErrPasskeyNameInvalid) {
			status, class = http.StatusBadRequest, classInvalidRequest
		}
		g.writeAuthError(w, r, err, status, class)
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
//
// While the admin passkey rule is on (#82 decision 3), an admin's own
// last usable passkey is refused with 409 before the password is
// checked (isLastUsableAdminPasskey): the person removing it is present
// and can register another first, as GitHub and Google ask of a last
// second factor. A stale passkey is always deletable, and another
// admin's clear-all (handlePasskeysAdminClear) stays open as the way
// back for a lost one. The door is the invariant: two concurrent
// deletes that leave none hold the account at its next request.
func (g *Gate) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	if g.passkeysOff(w, r) {
		return
	}
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
	}
	var req passkeyDeleteRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}
	credID, err := base64.RawURLEncoding.DecodeString(r.PathValue("id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid passkey id", nil)
		return
	}
	// Before the password re-check, so it costs no re-check budget: the
	// refusal does not depend on the password.
	if g.isLastUsableAdminPasskey(user, credID) {
		writeProblem(w, http.StatusConflict, classConflict,
			"this is the only passkey that can sign this admin account in -- register another passkey first", nil)
		return
	}

	now := g.now()
	if _, ok := g.recheckPassword(w, r, user, req.Password, "incorrect password", now); !ok {
		return
	}

	removed, err := g.deps.Users.DeletePasskey(user.ID, credID)
	if err != nil {
		status, class := http.StatusInternalServerError, classServerError
		if errors.Is(err, gauntlet.ErrPasskeyNotFound) {
			status, class = http.StatusNotFound, classNotFound
		}
		g.writeAuthError(w, r, err, status, class)
		return
	}

	signedOut := false
	if updated, ok := g.deps.Users.Get(user.ID); ok && !updated.HasSecondFactor() {
		g.deps.Sessions.RevokeAllForUser(user.ID)
		signedOut = true
	}

	g.audit(r, user.Username, "account.passkey_removed", user.Username, fmt.Sprintf("name=%q", removed.Name))
	writeJSON(w, http.StatusOK, map[string]any{"removed": true, "signedOut": signedOut})
	g.notify(r.Context(), &AccountNotice{
		Kind: NoticeSecondFactorRemoved, UserID: user.ID, Username: user.Username, Role: user.Role, At: now,
		SecondFactor: &SecondFactorDetail{Method: "passkey", Name: plaintext.Clean(removed.Name)},
	})
}

// isLastUsableAdminPasskey reports whether credID is user's only
// passkey usable under the current RP ID, user is an admin, and the
// admin passkey rule is on (#82).
func (g *Gate) isLastUsableAdminPasskey(user *gauntlet.User, credID []byte) bool {
	if !g.adminPasskeyRuleOn() || user.Role != gauntlet.RoleAdmin || !g.passkeysReady() {
		return false
	}
	// The caller's copy from context is fresh enough: nothing earlier in
	// this request wrote the account.
	rpID := g.deps.Passkeys.RPID()
	for _, pk := range user.Passkeys {
		if bytes.Equal(pk.ID, credID) {
			return pk.RPID == rpID && g.usablePasskeyCount(user) == 1
		}
	}
	return false
}

// reservePasskeyBegin is what each begin of a passkey step that follows
// the credentials does before a challenge exists: login/factor/begin's
// (#85) and login/prove/begin's (#80). It refuses a banned address and a
// locked account unless the browser is one the account remembers, and a
// disabled account always, reading the lockout from user's record
// without reserving anything; then it counts the begin on the account's
// begin budget (gauntlet.LoginLimiter.ReserveFactorBegin), falling back
// to a remembered browser's own budget when the ordinary one is full.
// On a refusal it records the attempt, answers 429 and reports ok
// false. onKnown says which budget took the begin, for
// ReleaseFactorBegin when the server then fails to start the ceremony.
func (g *Gate) reservePasskeyBegin(w http.ResponseWriter, r *http.Request, user *gauntlet.User, now time.Time) (onKnown, ok bool) {
	// The cookie is read at most once, and only when a refusal turns on
	// it, as reserveLogin reads it.
	knownRead, known := false, false
	isKnown := func() bool {
		if !knownRead {
			knownRead, known = true, g.isKnownBrowser(r, user.ID, now)
		}
		return known
	}
	res := loginReservation{address: g.cfg.ClientIP(r)}
	_, banned := g.deps.Limiter.AddressBanned(res.address, now)
	switch {
	case banned && !isKnown():
		res.refusal = gauntlet.SignInRateLimited
	case user.LoginDisabled(now):
		res.refusal = gauntlet.SignInDisabled
	case user.LoginLockedUntil.After(now) && !isKnown():
		// Read, not reserved: nothing to hand back. The finishing
		// step's reservation stays the authority; this only spares the
		// owner a passkey prompt that could not sign in.
		res.refusal, res.lockedUntil = gauntlet.SignInLocked, user.LoginLockedUntil
	}
	if res.refusal == "" && !g.deps.Limiter.ReserveFactorBegin(user.ID, false, now) {
		if onKnown = isKnown(); !onKnown || !g.deps.Limiter.ReserveFactorBegin(user.ID, true, now) {
			res.refusal = gauntlet.SignInRateLimited
		}
	}
	if res.refusal != "" {
		g.recordSignIn(r, loginEvent(user, "", res.refusal, gauntlet.SignInMethodPasskey), res, now)
		writeProblem(w, http.StatusTooManyRequests, classRateLimited, "too many attempts, try again later", nil)
		return false, false
	}
	return onKnown, true
}

// -- POST /api/auth/login/factor/begin ------------------------------------

// handleLoginFactorBegin starts the passkey half of the second login
// step. It is reached with the pending-login cookie handleLogin set,
// before any session exists (exemptPaths).
//
// Each begin is counted on the account's own begin budget
// (gauntlet.LoginLimiter.ReserveFactorBegin, #85), so a password alone
// mints at most the limiter's threshold of challenges per window,
// however many addresses it comes from. It takes nothing from the login
// budget a wrong guess is limited by and is never handed back by
// login/factor, so no request returns a reservation another took
// (docs/design.md, "One rule for every budget"); a server-side failure
// here hands it back at once. Not the address's
// challenge budget the login page's passkey sign-in spends
// (passkeyBeginKey): filling that must not refuse an account's second
// step.
//
// When the budget is full, a browser the account remembers begins on
// a budget of its own, as reserveLogin gives it one past a lockout
// (#44): a stranger holding the password cannot keep the owner's own
// browser from its passkey. A banned address is refused here as
// reserveLogin refuses it, with the same known-browser exception.
//
// The account's lockout and disable are read from its record, not
// reserved, so there is nothing to hand back: a locked account is
// refused here (429, recorded as locked) unless the browser is one it
// remembers, and a disabled one always, as reserveLogin would refuse
// them, so nobody is asked to touch a passkey for a sign-in that cannot
// complete. login/factor's reservation stays the authority, and also
// sees a lockout this process decided but could not save.
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
		writeUnauthorized(w, classStepExpired, "sign in again")
		return
	}
	if !g.passkeysReady() {
		g.writePasskeysNotReady(w)
		return
	}
	if g.usablePasskeyCount(user) == 0 {
		writeProblem(w, http.StatusConflict, classConflict, "this account has no passkey usable at this address", nil)
		return
	}

	onKnown, ok := g.reservePasskeyBegin(w, r, user, now)
	if !ok {
		return
	}

	options, sealed, err := g.deps.Passkeys.BeginLogin(user)
	if err != nil {
		// This server's failure, not the caller's attempt.
		g.deps.Limiter.ReleaseFactorBegin(user.ID, onKnown, now)
		g.logError("beginning passkey sign-in for " + user.Username + ": " + err.Error())
		writeProblem(w, http.StatusInternalServerError, classServerError, "unable to start passkey sign-in", nil)
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
// A refused assertion keeps this request's reservations, like a wrong
// code. A clone warning -- the library's verdict that the counter
// failed to advance (never for 0 -> 0, how most platform passkeys behave) --
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
	refuse := func(class problemClass, msg string) bool {
		g.secondFactorFailed(user, now)
		g.recordSignIn(r, loginEvent(user, "", gauntlet.SignInFactorRefused, gauntlet.SignInMethodPasskey), res, now)
		writeUnauthorized(w, class, msg)
		return false
	}
	if !g.passkeysReady() {
		g.writePasskeysNotReady(w)
		return false
	}
	cookie, err := r.Cookie(passkeyAssertCookieName)
	if err != nil {
		g.clearPasskeyAssertCookie(w)
		return refuse(classStepExpired, passkeyStartAgain)
	}

	verified, err := g.deps.Passkeys.FinishLogin(user, cookie.Value, assertion)
	if errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		g.clearPasskeyAssertCookie(w)
		return refuse(classStepExpired, passkeyStartAgain)
	}
	if err != nil {
		return refuse(classInvalidCredentials, passkeyNotVerified)
	}

	switch g.recordVerifiedAssertion(r, user, verified, now) {
	case assertionRefused:
		return refuse(classInvalidCredentials, passkeyNotVerified)
	case assertionBackendFailed:
		// This request's reservation goes back, or a backend outage
		// would cost an attempt per try and end in a 429 for an owner
		// who never guessed wrong. login/factor/begin took none on
		// these buckets.
		g.releaseLogin(res, now)
		writeProblem(w, http.StatusInternalServerError, classServerError, "unable to complete sign-in", nil)
		return false
	}

	g.clearPasskeyAssertCookie(w)
	return true
}

// assertionOutcome is how recordVerifiedAssertion ended.
type assertionOutcome int

const (
	// assertionAccepted: the count is recorded; the assertion may sign in.
	assertionAccepted assertionOutcome = iota
	// assertionRefused: a clone warning, a passkey removed since the
	// ceremony read the account, or a counter that did not advance.
	assertionRefused
	// assertionBackendFailed: the counter could not be saved. Not the
	// caller's doing: the request is answered 500 and its reservations
	// handed back.
	assertionBackendFailed
)

// recordVerifiedAssertion is what both passkey sign-in paths do once the
// ceremony has said the signature checked out (verified): refuse a clone
// warning -- the library's verdict that the counter failed to advance
// (never for 0 -> 0, how most platform passkeys behave) -- auditing it
// with both counts and leaving the stored count alone, and otherwise let
// RecordPasskeyAssertionIfFresh decide and record under the store's lock,
// so two copies of one assertion cannot both win. It writes no response
// and touches no reservation: each caller decides what a refusal costs.
func (g *Gate) recordVerifiedAssertion(r *http.Request, user *gauntlet.User, verified gauntlet.PasskeyAssertion, now time.Time) assertionOutcome {
	if verified.CloneWarning {
		// "unknown" when the passkey was removed between the ceremony's
		// read of the account and this one.
		stored := "unknown"
		for _, pk := range user.Passkeys {
			if bytes.Equal(pk.ID, verified.CredentialID) {
				stored = fmt.Sprint(pk.SignCount)
			}
		}
		g.audit(r, user.Username, "account.passkey_clone_suspected", user.Username,
			fmt.Sprintf("credential=%s presentedCount=%d storedCount=%s",
				base64.RawURLEncoding.EncodeToString(verified.CredentialID), verified.SignCount, stored))
		return assertionRefused
	}

	accepted, err := g.deps.Users.RecordPasskeyAssertionIfFresh(user.ID, verified.CredentialID, verified.SignCount, now)
	switch {
	case errors.Is(err, gauntlet.ErrPasskeyNotFound), errors.Is(err, gauntlet.ErrUserNotFound):
		// Removed since the ceremony read the account: nothing to sign
		// in with any more.
		return assertionRefused
	case err != nil:
		// A counter that could not be saved is refused (accepted is
		// false), but as the backend failing, not a wrong guess -- the
		// same stance as the TOTP branch's VerifyAndRecordTOTP error. A
		// failed save on a 0 -> 0 login never gets here: the store logs
		// it and accepts.
		g.logError("recording passkey assertion for " + user.Username + ": " + err.Error())
		return assertionBackendFailed
	case !accepted:
		return assertionRefused
	}
	return assertionAccepted
}

// -- DELETE /api/auth/users/{id}/passkeys ---------------------------------

// handlePasskeysAdminClear lets an admin remove every passkey on another
// user's account -- handleTOTPAdminClear's twin, including refusing the
// caller's own account: an admin who lost their own factor has no
// console tool in this module (docs/design.md §1.7). ClearPasskeys drops
// the recovery codes only when no factor of either kind is left. The
// caller's own password is asked for again on the request (#72). An
// account with no passkeys is answered 200 with cleared false, and
// nothing is recorded or sent. While the admin passkey rule is on, an
// admin target is held at the passkey door afterwards (#82), and the
// audit detail says so.
func (g *Gate) handlePasskeysAdminClear(w http.ResponseWriter, r *http.Request) {
	if g.passkeysOff(w, r) {
		return
	}
	var req adminStepUpRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "user id is required", nil)
		return
	}
	if caller := UserFromContext(r); caller != nil && caller.ID == id {
		writeProblem(w, http.StatusConflict, classConflict, "an administrator cannot clear their own passkeys here", nil)
		return
	}
	if !g.recheckAdminPassword(w, r, req.Password, g.now()) {
		return
	}

	target, ok := g.deps.Users.Get(id)
	if !ok {
		writeProblem(w, http.StatusNotFound, classNotFound, "no such user", nil)
		return
	}
	if err := g.deps.Users.ClearPasskeys(id); err != nil {
		// The account is already in the state asked for, so this is a
		// success, but one that changed nothing: no record and no notice
		// of a removal that did not happen.
		if errors.Is(err, gauntlet.ErrNoPasskeys) {
			writeJSON(w, http.StatusOK, map[string]any{"username": target.Username, "cleared": false})
			return
		}
		g.writeAuthError(w, r, err, http.StatusInternalServerError, classServerError)
		return
	}

	by := auditActor(r)
	detail := "passkeys removed by admin"
	// The way back for an admin who lost a passkey stays open (#82
	// decision 3): the account is held at the passkey door from its
	// next request until it registers one.
	if g.adminPasskeyRuleOn() && target.Role == gauntlet.RoleAdmin {
		detail += "; admin held for a passkey"
	}
	g.audit(r, by, "user.passkeys_cleared", target.Username, detail)
	writeJSON(w, http.StatusOK, map[string]any{"username": target.Username, "cleared": true})
	g.notify(r.Context(), &AccountNotice{
		Kind: NoticeSecondFactorRemoved, UserID: target.ID, Username: target.Username, Role: target.Role, At: g.now(), By: by,
		SecondFactor: &SecondFactorDetail{Method: "passkey", All: true},
	})
}
