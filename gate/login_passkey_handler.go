package gate

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// -- Signing in with a passkey alone (#77, docs/adr/0012-passkey-alone-sign-in.md)
//
// A WebAuthn Level 3 client-side discoverable credential login: nobody
// types a username, the browser offers the passkeys it holds for this
// relying party, and the one chosen names its account through the user
// handle (the account ID). User verification is required, so the passkey
// is a multi-factor cryptographic authenticator on its own (NIST SP
// 800-63B-4, AAL2) and replaces the password -- at sign-in only: every
// account keeps its password.
//
// The ceremony runs behind gauntlet.PasskeySignIn, an optional second
// interface on Deps.Passkeys (gauntlet/passkey implements it), and the
// routes are offered only when Config.PasskeySignIn is set. This file
// owns what goes around it: the cookie, the login limiter, the
// unusual-sign-in judgement, the session, the history and the audit.

// passkeySignIn is Deps.Passkeys as a gauntlet.PasskeySignIn when
// Config.PasskeySignIn is set and it implements one.
func (g *Gate) passkeySignIn() (gauntlet.PasskeySignIn, bool) {
	if !g.cfg.PasskeySignIn || g.deps.Passkeys == nil {
		return nil, false
	}
	ps, ok := g.deps.Passkeys.(gauntlet.PasskeySignIn)
	return ps, ok
}

// passkeySignInOn is true when this application offers passkey sign-in
// and its relying party is ready: what the session body's signIn says.
func (g *Gate) passkeySignInOn() bool {
	_, ok := g.passkeySignIn()
	return ok && g.passkeysReady()
}

// passkeySignInOrNotFound answers 404 when passkey sign-in is not
// offered, as every passkey route does when there are no passkeys.
func (g *Gate) passkeySignInOrNotFound(w http.ResponseWriter) (gauntlet.PasskeySignIn, bool) {
	ps, ok := g.passkeySignIn()
	if !ok {
		writeProblem(w, http.StatusNotFound, classNotFound, "", nil)
	}
	return ps, ok
}

// -- POST /api/auth/login/passkey/begin -----------------------------------

// handleLoginPasskeyBegin starts a passkey-alone sign-in and answers the
// W3C request options for navigator.credentials.get(), with no allowed
// list: the browser offers its own passkeys, or its autofill does
// (conditional mediation). It reads no body, and is reached with no
// session and no cookie.
//
// Nothing names an account yet, so it reserves one attempt on the
// address alone, keeping it until a sign-in completes, so a stranger
// cannot mint challenges without limit; the finish step takes the
// address's and the account's own reservations, and gives all of them
// back when the sign-in completes. A banned address or one at its begin
// limit is refused 429 here; the known-browser allowance, which belongs
// to an account, applies at the finish.
//
// The begin attempt is on a bucket of its own (passkeyBeginKey), not the
// address bucket a password is tried on. A browser asks for a challenge
// on every load of a login page that offers passkey autofill and after
// every prompt the user dismisses, and a challenge costs the caller
// nothing to mint and guesses nothing: on the shared bucket, a few page
// views would leave the address at its limit and every way of signing
// in from it answering 429. It must still be bounded, so it gets the
// same limit on its own.
func (g *Gate) handleLoginPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	ps, ok := g.passkeySignInOrNotFound(w)
	if !ok {
		return
	}
	if !g.passkeysReady() {
		g.writePasskeysNotReady(w)
		return
	}
	now := g.now()
	address := g.cfg.ClientIP(r)
	beginKey := passkeyBeginKey(address)
	res := loginReservation{address: address}
	if _, banned := g.deps.Limiter.AddressBanned(address, now); banned || !g.deps.Limiter.Reserve(beginKey, now) {
		res.refusal = gauntlet.SignInRateLimited
		g.recordSignIn(r, gauntlet.SignInEvent{Outcome: res.refusal, Method: gauntlet.SignInMethodPasskeyAlone}, res, now)
		writeProblem(w, http.StatusTooManyRequests, classRateLimited, "too many attempts, try again later", nil)
		return
	}
	options, sealed, err := ps.BeginSignIn()
	if err != nil {
		// This server's failure, not the caller's attempt.
		g.deps.Limiter.Release(beginKey, now)
		g.logError("beginning passkey-alone sign-in: " + err.Error())
		writeProblem(w, http.StatusInternalServerError, classServerError, "unable to start passkey sign-in", nil)
		return
	}
	g.setPasskeySignInCookie(w, sealed)
	writeJSON(w, http.StatusOK, options)
}

// passkeyBeginKey is the limiter bucket login/passkey/begin reserves on
// for address: its own, so asking for challenges spends none of the
// address's sign-in attempts (see handleLoginPasskeyBegin). Whatever
// hands the begin step's reservation back releases this key.
func passkeyBeginKey(address string) string {
	return "passkey-begin:" + address
}

// -- the assertion check both finishes share ------------------------------

// signInAssertionOutcome is how checkSignInAssertion ended.
type signInAssertionOutcome int

const (
	// signInAssertionAccepted: verified, user verified, count recorded.
	signInAssertionAccepted signInAssertionOutcome = iota
	// signInAssertionDead: the ceremony can never succeed (no usable
	// state: expired, tampered with, already used, sealed for another
	// ceremony). The caller clears the cookie.
	signInAssertionDead
	// signInAssertionRefused: the assertion was not accepted, for any
	// reason a caller need not tell apart -- a handle lookup declined,
	// a wrong or unknown credential, no user verification, a clone
	// warning, a counter that did not advance.
	signInAssertionRefused
	// signInAssertionBackendFailed: the counter could not be saved.
	signInAssertionBackendFailed
)

// checkSignInAssertion runs the ceremony's FinishSignIn with lookup and
// then what any passkey sign-in owes after it: the user-verified flag
// read again (the ceremony requires it too; defence in depth) and
// recordVerifiedAssertion. It writes no response and touches no
// reservation. The account is the one lookup returned for the verified
// assertion, nil unless the outcome is accepted.
func (g *Gate) checkSignInAssertion(r *http.Request, ps gauntlet.PasskeySignIn, sealed string, assertion json.RawMessage, lookup func([]byte) (*gauntlet.User, bool), now time.Time) (*gauntlet.User, signInAssertionOutcome) {
	user, verified, err := ps.FinishSignIn(lookup, sealed, assertion)
	if errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		return nil, signInAssertionDead
	}
	if err != nil || user == nil || !verified.UserVerified {
		return nil, signInAssertionRefused
	}
	switch g.recordVerifiedAssertion(r, user, verified, now) {
	case assertionRefused:
		return nil, signInAssertionRefused
	case assertionBackendFailed:
		return nil, signInAssertionBackendFailed
	}
	return user, signInAssertionAccepted
}

// -- POST /api/auth/login/passkey ------------------------------------------

type loginPasskeyRequest struct {
	// Assertion is the browser's PublicKeyCredential JSON from
	// navigator.credentials.get(), handed to the ceremony unchanged.
	Assertion json.RawMessage `json:"assertion"`
}

// handleLoginPasskey completes a passkey-alone sign-in. It is judged
// like any completed sign-in (#55: method passkey_alone reaches Decide,
// so an application may relax it) and answers the Account, or the
// ConfirmationChallenge when the policy asks for a confirmation code.
//
// The account is named by the assertion's user handle, read before the
// signature is checked (the ceremony calls lookup first), and from that
// moment it is treated as a password attempt on it would be: reserveLogin
// applies the account's lockout and disable, the address ban and limit
// and the known-browser allowance (#70, #44) -- a refusal is the 429 and
// the signature is never checked. Everything after keeps the
// reservation, which is what counts a failure: a refused or
// non-user-verified assertion is factor_refused, an unknown handle (or
// one this account cannot sign in with) no_such_user. Unlike a wrong
// second factor after a password, none of them counts toward the
// account's run of second-factor failures: the caller holds no
// password, and letting anyone holding an account ID force a password
// change would be a denial of service.
//
// Every refusal answers 401 invalid-credentials, saying nothing of which
// check failed. A dead ceremony (no cookie, expired, tampered with,
// already used) answers 401 step-expired and clears the cookie. An
// account with no local password -- single sign-on owns its identity
// (ruling R4 on #20) -- cannot be signed into this way, as it cannot
// resume a session.
func (g *Gate) handleLoginPasskey(w http.ResponseWriter, r *http.Request) {
	ps, ok := g.passkeySignInOrNotFound(w)
	if !ok {
		return
	}
	if !g.passkeysReady() {
		g.writePasskeysNotReady(w)
		return
	}
	var req loginPasskeyRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil || len(req.Assertion) == 0 {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}
	cookie, err := r.Cookie(passkeySignInCookieName)
	if err != nil {
		g.clearPasskeySignInCookie(w)
		writeUnauthorized(w, classStepExpired, passkeyStartAgain)
		return
	}
	now := g.now()

	// The begin step's reservation (passkeyBeginKey) is kept until this
	// completes. res is the address alone until the user handle names an
	// account, then the address's and the account's, as reserveLogin
	// takes them.
	address := g.cfg.ClientIP(r)
	res := loginReservation{ipKey: addressKey(address), address: address}
	var (
		named    *gauntlet.User // the account the handle named, once admitted
		reserved bool
		limited  bool
	)
	lookup := func(handle []byte) (*gauntlet.User, bool) {
		u, ok := g.deps.Users.Get(string(handle))
		if !ok {
			return nil, false
		}
		admitted := false
		res, admitted = g.reserveLogin(w, r, u.ID, u.Username, gauntlet.SignInMethodPasskeyAlone, now)
		if !admitted {
			limited = true
			return nil, false
		}
		reserved, named = true, u
		if !u.LocalPassword() {
			return nil, false
		}
		return u, true
	}
	user, outcome := g.checkSignInAssertion(r, ps, cookie.Value, req.Assertion, lookup, now)
	if limited {
		return // reserveLogin wrote the 429 and recorded it
	}

	// A refusal keeps the reservations -- that is what counts the
	// failure. Only a handle that named an account holds the account's;
	// every other refusal is on the address alone and recorded as
	// no_such_user. A dead ceremony with no account named checked no
	// credential, so records nothing.
	refuse := func(class problemClass, msg string, record bool) {
		switch {
		case reserved && record:
			g.recordSignIn(r, loginEvent(named, "", gauntlet.SignInFactorRefused, gauntlet.SignInMethodPasskeyAlone), res, now)
		case record:
			g.recordSignIn(r, loginEvent(nil, "", gauntlet.SignInNoSuchUser, gauntlet.SignInMethodPasskeyAlone), res, now)
		}
		writeUnauthorized(w, class, msg)
	}
	switch outcome {
	case signInAssertionDead:
		g.clearPasskeySignInCookie(w)
		refuse(classStepExpired, passkeyStartAgain, reserved)
		return
	case signInAssertionRefused:
		refuse(classInvalidCredentials, passkeyNotVerified, true)
		return
	case signInAssertionBackendFailed:
		// The credential was right but could not be recorded: this
		// request's reservations and the begin step's go back, as
		// login/factor's do.
		g.releaseLogin(res, now)
		g.deps.Limiter.Release(passkeyBeginKey(address), now)
		writeProblem(w, http.StatusInternalServerError, classServerError, "unable to complete sign-in", nil)
		return
	}

	// Every credential has passed: judge the sign-in (#55) before any
	// session exists. The ceremony is spent either way.
	g.clearPasskeySignInCookie(w)
	g.deps.Limiter.Release(passkeyBeginKey(address), now) // the begin step's reservation
	place := g.placeOf(r, res.address)
	verdict := g.judgeSignIn(r, user, gauntlet.SignInMethodPasskeyAlone, place, now)
	if verdict.stopsSignIn() {
		// The credential was right, so the attempt is handed back rather
		// than completed; nothing completed, so the account's count is
		// not reset.
		g.releaseLogin(res, now)
		out, notice := g.stopSignIn(w, r, user, res, gauntlet.SignInMethodPasskeyAlone, place, verdict, now)
		g.answerStopped(w, r, verdict, out, notice)
		return
	}
	g.completeLogin(res, now)
	// The session this browser already held for the account ends here,
	// as for every sign-in (ASVS 7.2.4; see revokeReplacedSession).
	notice := g.completeSignIn(w, r, user, res, gauntlet.SignInMethodPasskeyAlone, place, verdict, now)
	writeJSON(w, http.StatusOK, map[string]any{"username": user.Username, "role": user.Role})
	g.notify(r.Context(), notice)
}
