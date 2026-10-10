package gate

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// reauthenticateRequest is the body of POST /api/auth/reauthenticate:
// the password, or -- when passkey sign-in is offered (#77) -- a passkey
// assertion from POST /api/auth/login/passkey/begin, and nothing else.
// The account is the timed-out session's.
type reauthenticateRequest struct {
	Password  string          `json:"password"`
	Assertion json.RawMessage `json:"assertion,omitempty"`
}

// resumableSession resolves r's session cookie to a session that has
// timed out through inactivity inside its lifetime ceiling and that its
// account may still resume (#71), with the account. It reports false for
// anything else, and the caller answers all of those alike -- no cookie,
// an unknown or live or past-ceiling session, an account that is gone,
// a session ended since by a password change or an end-all
// (User.SessionCutoff, as sessionUser applies it), an account with no
// local password (an SSO-only account has nothing to resume with), and
// one that owes a password change.
func (g *Gate) resumableSession(r *http.Request, now time.Time) (gauntlet.Session, *gauntlet.User, bool) {
	cookie, err := r.Cookie(g.sessionCookieName())
	if err != nil {
		return gauntlet.Session{}, nil, false
	}
	sess, ok := g.deps.Sessions.Resumable(cookie.Value, now)
	if !ok {
		return gauntlet.Session{}, nil, false
	}
	user, ok := g.deps.Users.Get(sess.UserID)
	if !ok {
		g.deps.Sessions.Revoke(sess.ID)
		return gauntlet.Session{}, nil, false
	}
	if sess.IssuedAt.Before(user.SessionCutoff()) {
		g.deps.Sessions.Revoke(sess.ID)
		return gauntlet.Session{}, nil, false
	}
	if !user.LocalPassword() || user.MustChangePassword {
		return gauntlet.Session{}, nil, false
	}
	return sess, user, true
}

// handleReauthenticate resumes a session that timed out through
// inactivity with the account's password alone, while its 24-hour
// ceiling has not passed (#71). The standard pattern is NIST SP
// 800-63B-4 section 2.2.3: after an inactivity timeout and before the
// overall timeout the verifier MAY accept a password in conjunction with
// the session secret (the timed-out session's cookie), with the session
// ID regenerated on re-authentication (ASVS 7.2.4).
//
// A passkey that verified the user resumes it too (#77), and is the
// stronger proof: a multi-factor authenticator where the password is one
// factor. The body then carries {assertion} from the passkey sign-in
// begin route instead of {password} -- both is a 400 -- and the user
// handle must name the timed-out session's own account; another
// account's passkey resumes nothing. The route answers 404 for an
// assertion unless passkey sign-in is offered.
//
// It is a sign-in attempt for the limiter: the same reservation as a
// password sign-in (reserveLogin), so the account's lockout and disable,
// the address ban and limit and the known-browser allowance all apply,
// and a wrong password is a failed sign-in, counted. It is not judged
// as an unusual sign-in (#55): it continues a session already judged,
// the new one keeping the old one's signals. Nor does it reset the
// account's count (completeLogin), remember the browser or end other
// sessions -- a password alone proves less than the sign-in it
// continues, so it clears nothing a full sign-in would.
//
// On success the old session ID ends and a new one is issued for the same
// account with the original sign-in time, so the ceiling does not move,
// and the cookie expires at it. Anything not resumable is a 401
// sign-in-required, whatever the reason.
func (g *Gate) handleReauthenticate(w http.ResponseWriter, r *http.Request) {
	var req reauthenticateRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}

	var ps gauntlet.PasskeySignIn
	if len(req.Assertion) > 0 {
		if req.Password != "" {
			writeProblem(w, http.StatusBadRequest, classInvalidRequest, "send a password or an assertion, not both", nil)
			return
		}
		var ok bool
		if ps, ok = g.passkeySignInOrNotFound(w); !ok {
			return
		}
	}

	now := g.now()
	_, user, ok := g.resumableSession(r, now)
	if !ok {
		writeUnauthorized(w, classSignInRequired, "sign in again")
		return
	}
	res, ok := g.reserveLogin(w, r, user.ID, user.Username, gauntlet.SignInMethodResume, now)
	if !ok {
		return
	}

	if ps != nil {
		g.resumeWithPasskey(w, r, ps, user, res, req.Assertion, now)
		return
	}
	authed, err := g.deps.Users.Authenticate(user.Username, req.Password, now)
	if err != nil && !errors.Is(err, gauntlet.ErrInvalidCredentials) {
		g.releaseLogin(res, now)
		g.logError("recording resume for " + user.Username + ": " + err.Error())
		writeProblem(w, http.StatusInternalServerError, classServerError, "unable to complete sign-in", nil)
		return
	}
	if err != nil {
		// Reservations stay claimed: that is what counts the failure.
		g.recordSignIn(r, loginEvent(user, "", gauntlet.SignInWrongPassword, gauntlet.SignInMethodResume), res, now)
		writeUnauthorized(w, classInvalidCredentials, "incorrect password")
		return
	}
	// The password is right but the account now owes a change (a breach
	// check at Authenticate, say): a full sign-in takes it to that door.
	if authed.MustChangePassword {
		g.releaseLogin(res, now)
		writeUnauthorized(w, classSignInRequired, "sign in again")
		return
	}
	g.finishResume(w, r, user, res, gauntlet.SignInMethodPassword, now)
}

// resumeWithPasskey is handleReauthenticate's passkey branch (#77), with
// the reservation res already held for the session's account. The
// ceremony's lookup accepts only the session's own account's handle, so
// the signature is never checked for another account's passkey, and
// checkSignInAssertion requires the user-verified flag.
//
// A refusal -- another account's passkey, a wrong credential, no user
// verification, a clone warning -- keeps the reservation, as a wrong
// password does, and is recorded as factor_refused with method resume.
// When the handle is the session's own account and that account knows
// no passkey with the credential ID (credentialToForget), the refusal
// names it in unknownCredential, as login/passkey's does (#92); another
// account's handle is never named, as its passkey may be good there.
// A dead ceremony (no cookie, expired, already used) checked nothing, so
// the reservation goes back and the answer is 401 step-expired. The
// reservation the begin step took (passkeyBeginKey) is handed back once
// the credential is right.
func (g *Gate) resumeWithPasskey(w http.ResponseWriter, r *http.Request, ps gauntlet.PasskeySignIn, user *gauntlet.User, res loginReservation, assertion json.RawMessage, now time.Time) {
	dead := func() {
		g.releaseLogin(res, now)
		g.clearPasskeySignInCookie(w)
		writeUnauthorized(w, classStepExpired, passkeyStartAgain)
	}
	if !g.passkeysReady() {
		g.releaseLogin(res, now)
		g.writePasskeysNotReady(w)
		return
	}
	cookie, err := r.Cookie(passkeySignInCookieName)
	if err != nil {
		dead()
		return
	}
	var forget []byte // the credential the refusal names (#92), nil for none
	lookup := func(handle []byte) (*gauntlet.User, bool) {
		if string(handle) != user.ID {
			return nil, false
		}
		forget = credentialToForget(user, assertion)
		return user, true
	}
	_, outcome := g.checkSignInAssertion(r, ps, cookie.Value, assertion, lookup, now)
	switch outcome {
	case signInAssertionDead:
		dead()
		return
	case signInAssertionRefused:
		g.recordSignIn(r, loginEvent(user, "", gauntlet.SignInFactorRefused, gauntlet.SignInMethodResume), res, now)
		writeUnauthorizedWith(w, classInvalidCredentials, passkeyNotVerified, g.unknownCredentialMember(forget))
		return
	case signInAssertionBackendFailed:
		g.releaseLogin(res, now)
		g.deps.Limiter.Release(passkeyBeginKey(res.address), now) // the begin step's reservation
		writeProblem(w, http.StatusInternalServerError, classServerError, "unable to complete sign-in", nil)
		return
	}
	g.clearPasskeySignInCookie(w)
	g.deps.Limiter.Release(passkeyBeginKey(res.address), now) // the begin step's reservation
	g.finishResume(w, r, user, res, gauntlet.SignInMethodPasskey, now)
}

// finishResume is the end of a resume whose credential -- the password
// or the passkey -- checked out: end the timed-out session, start one
// for the same account under a new ID, set its cookie, record it and
// answer. Anything that went wrong since resumableSession is a 401
// sign-in-required. credential is the one that checked out,
// gauntlet.SignInMethodPassword or SignInMethodPasskey: the history row's
// method is resume either way, so the audit record is what says which.
func (g *Gate) finishResume(w http.ResponseWriter, r *http.Request, user *gauntlet.User, res loginReservation, credential gauntlet.SignInMethod, now time.Time) {
	cookie, _ := r.Cookie(g.sessionCookieName())
	sess, ok := g.deps.Sessions.Resume(cookie.Value, g.signInClient(r, res.address), now)
	if !ok {
		// Resumed by another request, or ended, while the password was
		// being checked.
		g.releaseLogin(res, now)
		writeUnauthorized(w, classSignInRequired, "sign in again")
		return
	}
	g.releaseLogin(res, now)
	g.setResumedSessionCookie(w, sess, now)
	note := ""
	if credential == gauntlet.SignInMethodPasskey {
		note = resumedWithPasskeyNote
	}
	g.recordSignInNote(r, loginEvent(user, "", gauntlet.SignInSuccess, gauntlet.SignInMethodResume), res, note, now)
	writeJSON(w, http.StatusOK, map[string]any{"username": user.Username, "role": user.Role})
}
