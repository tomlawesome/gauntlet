package gate

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// The prove step (#65, docs/adr/0009-unusual-sign-ins.md): under the
// prove action an unusual sign-in is not finished. It is held on the
// confirm ticket (confirmlogin.go, Prove set, no code) until the browser
// answers a passkey assertion for the same account -- step-up
// authentication with a phishing-resistant factor. The ceremony is the
// existing non-discoverable one (BeginLogin/FinishLogin, user
// verification preferred, not required: possession of an origin-bound
// key is the point), so a security key without a PIN qualifies. Until
// then the browser holds a sealed ticket, never a session.

// startProve mints a prove ticket for user's sign-in, sets its cookie
// and records confirm_sent with the signals -- nothing is delivered
// anywhere and nothing is written to the account. It reports whether the
// ticket was made; when it was not (the random source or the sealing
// failed) no cookie exists and the caller refuses the attempt
// (prove-failed).
func (g *Gate) startProve(w http.ResponseWriter, r *http.Request, user *gauntlet.User, res loginReservation, method gauntlet.SignInMethod, signals gauntlet.SignInSignals, now time.Time) bool {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		g.logError("gate: generating a prove ticket id: " + err.Error())
		return false
	}
	ticket, err := confirmLoginCodec.seal(confirmLoginState{
		UserID: user.ID, IssuedAt: now, ID: hex.EncodeToString(id),
		Signals: signals, Method: method, Prove: true,
	})
	if err != nil {
		g.logError(err.Error())
		return false
	}
	g.writeCookie(w, confirmLoginCookieName, ticket, confirmLoginCookiePath, int(ConfirmCodeLifetime.Seconds()))
	ev := loginEvent(user, "", gauntlet.SignInConfirmSent, method)
	ev.Client.Unusual = signals
	g.recordSignIn(r, ev, res, now)
	return true
}

// openProveTicket reads the prove ticket the request carries and the
// account it names. A missing, invalid, expired, spent or non-prove
// ticket, or one whose account is gone, is 401 step-expired with the
// cookie cleared, written here; ok is false.
func (g *Gate) openProveTicket(w http.ResponseWriter, r *http.Request, now time.Time) (st confirmLoginState, user *gauntlet.User, ok bool) {
	expired := func() {
		g.clearConfirmLoginCookie(w)
		writeUnauthorized(w, classStepExpired, "sign in again")
	}
	cookie, err := r.Cookie(confirmLoginCookieName)
	if err != nil {
		expired()
		return st, nil, false
	}
	st, ok = decodeConfirmLogin(cookie.Value, now)
	if !ok || !st.Prove || spentConfirmLogins.Spent(st.ID, now) {
		expired()
		return st, nil, false
	}
	user, ok = g.deps.Users.Get(st.UserID)
	if !ok {
		expired()
		return st, nil, false
	}
	return st, user, true
}

// handleLoginProveBegin starts the passkey ceremony a held sign-in owes
// and answers the W3C request options for navigator.credentials.get(),
// allowing only the account's passkeys usable here. It reads no body.
// Session-exempt, like login; it needs the prove ticket. 404 without
// passkeys, 409 while the relying party is not ready or the account has
// no passkey usable here (a passkey removed since the sign-in was held).
// Each begin is counted, and a locked or disabled account or a banned
// address refused early, as login/factor/begin does (reservePasskeyBegin,
// #80): the ticket proves the credentials, but must not mint challenges
// without limit for its life, nor ask the owner to touch a key for a
// sign-in that cannot complete. Past the budget, or so refused, begin is
// 429. The finish step's reservation stays the authority.
func (g *Gate) handleLoginProveBegin(w http.ResponseWriter, r *http.Request) {
	if g.passkeysOff(w, r) {
		return
	}
	now := g.now()
	_, user, ok := g.openProveTicket(w, r, now)
	if !ok {
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
		g.logError("beginning passkey proof for " + user.Username + ": " + err.Error())
		writeProblem(w, http.StatusInternalServerError, classServerError, "unable to start passkey sign-in", nil)
		return
	}
	g.setPasskeyAssertCookie(w, sealed)
	writeJSON(w, http.StatusOK, options)
}

// loginProveRequest is POST /api/auth/login/prove's body.
type loginProveRequest struct {
	// Assertion is the browser's PublicKeyCredential JSON from
	// navigator.credentials.get(), handed to the ceremony unchanged.
	Assertion json.RawMessage `json:"assertion"`
}

// handleLoginProve completes a sign-in held for a passkey (#65), as
// handleLoginConfirm completes one held for a code. Session-exempt; the
// CSRF header is required as on every POST. A missing, invalid, expired
// or spent ticket (or one that is not a prove ticket), or one whose
// account is gone, is 401 step-expired and the cookie is cleared. The
// attempt is reserved on the account and address as any login step (429
// past the limit). A refused assertion -- a wrong passkey, another
// account's, a clone warning, a counter that did not advance -- is 401
// invalid-credentials, keeps the reservation, which counts the failure,
// and counts toward the run of second-factor failures, as confirm's
// wrong code does; a dead ceremony (no cookie, expired, already used) is
// 401 step-expired but leaves the ticket, so begin can be asked again.
// A right assertion completes the sign-in: the session carries the
// ticket's signals, the history row is a success marked confirmed
// (completeHeldSignIn).
func (g *Gate) handleLoginProve(w http.ResponseWriter, r *http.Request) {
	if g.passkeysOff(w, r) {
		return
	}
	var req loginProveRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil || len(req.Assertion) == 0 {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}
	now := g.now()
	st, user, ok := g.openProveTicket(w, r, now)
	if !ok {
		return
	}
	if !g.passkeysReady() {
		g.writePasskeysNotReady(w)
		return
	}
	res, ok := g.reserveLogin(w, r, user.ID, user.Username, gauntlet.SignInMethodPasskey, now)
	if !ok {
		return
	}

	refuse := func(class problemClass, msg string) {
		g.secondFactorFailed(user, now)
		g.recordSignIn(r, loginEvent(user, "", gauntlet.SignInConfirmRefused, gauntlet.SignInMethodPasskey), res, now)
		writeUnauthorized(w, class, msg)
	}
	cookie, err := r.Cookie(passkeyAssertCookieName)
	if err != nil {
		g.clearPasskeyAssertCookie(w)
		refuse(classStepExpired, passkeyStartAgain)
		return
	}
	verified, err := g.deps.Passkeys.FinishLogin(user, cookie.Value, req.Assertion)
	if errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		g.clearPasskeyAssertCookie(w)
		refuse(classStepExpired, passkeyStartAgain)
		return
	}
	if err != nil {
		refuse(classInvalidCredentials, passkeyNotVerified)
		return
	}
	switch g.recordVerifiedAssertion(r, user, verified, now) {
	case assertionRefused:
		refuse(classInvalidCredentials, passkeyNotVerified)
		return
	case assertionBackendFailed:
		// The credential was right but could not be recorded: not a
		// failure to count.
		g.releaseLogin(res, now)
		writeProblem(w, http.StatusInternalServerError, classServerError, "unable to complete sign-in", nil)
		return
	}
	// One-shot, as confirm's: of two completions racing on one ticket,
	// the loser is a replay and is told to sign in again.
	if !spentConfirmLogins.Claim(st.ID, st.IssuedAt.Add(ConfirmCodeLifetime), now) {
		g.clearConfirmLoginCookie(w)
		writeUnauthorized(w, classStepExpired, "sign in again")
		return
	}
	g.clearPasskeyAssertCookie(w)
	g.completeHeldSignIn(w, r, user, res, st, UnusualSignInProve, now)
}
