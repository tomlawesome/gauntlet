package gate

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// -- Step-up with a passkey (#82 decision 6, ADR-0015) --------------------
//
// Every route that asks a signed-in caller for their password and a
// current second factor (recheckStepUp: granting admin, creating an
// admin, the admin's own unlock) takes password + assertion as the
// alternative to password + code. The assertion comes from a login
// ceremony started here, for the caller's own passkeys, so a passkey-only
// admin no longer spends a recovery code per grant. The ceremony runs
// through Deps.Passkeys (gauntlet.PasskeyCeremony), never gauntlet/passkey
// itself: the leaf rule holds (ADR-0004).

// stepUpStartAgain is the answer to a dead step-up ceremony: nothing
// sent on it can ever succeed, so the frontend begins again.
const stepUpStartAgain = "start passkey step-up again"

// handleStepUpPasskeyBegin starts a passkey step-up for the signed-in
// caller: the W3C request options allowing only the caller's passkeys
// usable here, with the sealed ceremony in the gate_passkey_stepup
// cookie. Session-gated, so Protect has already checked the session and
// the CSRF header. Takes no body.
//
// It reserves one re-check on the caller's budget and keeps it, as a
// code would be counted, so a session cookie alone cannot mint
// challenges without limit; a successful finish (recheckPasskey) hands it
// back. Refuses with 404 while the application has no passkeys, 409 for
// a caller with no local password (refuseWithoutLocalPassword: the
// password half of the step-up could never pass), 409 while the relying
// party is not ready, and 409 for a caller holding no passkey usable
// here.
func (g *Gate) handleStepUpPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	if g.passkeysOff(w, r) {
		return
	}
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
	}
	if refuseWithoutLocalPassword(w, user) {
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
	now := g.now()
	if !g.deps.Limiter.ReserveRecheck(user.ID, now) {
		g.recheckRefused(r, user)
		writeProblem(w, http.StatusTooManyRequests, classRateLimited, "too many attempts, try again later", nil)
		return
	}
	options, sealed, err := g.deps.Passkeys.BeginLogin(user)
	if err != nil {
		// This server's failure, not the caller's attempt.
		g.deps.Limiter.ReleaseRecheck(user.ID, now)
		g.logError("beginning passkey step-up for " + user.Username + ": " + err.Error())
		writeProblem(w, http.StatusInternalServerError, classServerError, "unable to start passkey step-up", nil)
		return
	}
	g.setPasskeyStepUpCookie(w, sealed)
	writeJSON(w, http.StatusOK, options)
}

// recheckPasskey is recheckSecondFactor for a passkey: assertion is the
// browser's answer to the options handleStepUpPasskeyBegin gave, finished
// against the ceremony in the gate_passkey_stepup cookie for user -- the
// caller -- so another account's passkey cannot verify. Call it only
// after recheckPassword has passed.
//
// A missing cookie or a dead ceremony (gauntlet.ErrPasskeyCeremonyInvalid:
// expired, tampered with, already used) is 401 step-expired and clears
// the cookie. An assertion that does not verify, or that the clone check
// or the counter refuses (recordVerifiedAssertion, which audits a clone
// warning), is 401 invalid-credentials carrying wrongMsg and counts as a
// failed re-check: the reservation the begin took is kept. Success clears
// the cookie and hands that reservation back. A counter that could not be
// saved is the backend failing, not a wrong guess: 500, and the
// reservation goes back too.
//
// Writes every refusal itself.
func (g *Gate) recheckPasskey(w http.ResponseWriter, r *http.Request, user *gauntlet.User, assertion json.RawMessage, wrongMsg string, now time.Time) bool {
	if g.passkeysOff(w, r) {
		return false
	}
	if !g.passkeysReady() {
		g.writePasskeysNotReady(w)
		return false
	}
	cookie, err := r.Cookie(passkeyStepUpCookieName)
	if err != nil {
		g.clearPasskeyStepUpCookie(w)
		writeUnauthorized(w, classStepExpired, stepUpStartAgain)
		return false
	}
	refuse := func() bool {
		g.recheckFailed(r, user, gauntlet.SignInFactorRefused, gauntlet.SignInMethodPasskey)
		writeUnauthorized(w, classInvalidCredentials, wrongMsg)
		return false
	}
	verified, err := g.deps.Passkeys.FinishLogin(user, cookie.Value, assertion)
	if errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		g.clearPasskeyStepUpCookie(w)
		writeUnauthorized(w, classStepExpired, stepUpStartAgain)
		return false
	}
	if err != nil {
		return refuse()
	}
	switch g.recordVerifiedAssertion(r, user, verified, now) {
	case assertionRefused:
		return refuse()
	case assertionBackendFailed:
		g.deps.Limiter.ReleaseRecheck(user.ID, now)
		writeProblem(w, http.StatusInternalServerError, classServerError, "unable to check the passkey", nil)
		return false
	}
	g.clearPasskeyStepUpCookie(w)
	g.deps.Limiter.ReleaseRecheck(user.ID, now)
	return true
}
