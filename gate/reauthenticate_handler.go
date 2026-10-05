package gate

import (
	"errors"
	"net/http"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// reauthenticateRequest is the body of POST /api/auth/reauthenticate:
// the password, and nothing else. The account is the timed-out session's.
type reauthenticateRequest struct {
	Password string `json:"password"`
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

	now := g.now()
	_, user, ok := g.resumableSession(r, now)
	if !ok {
		writeUnauthorized(w, classSignInRequired, "sign in again")
		return
	}
	res, ok := g.reserveLogin(w, r, user.ID, user.Username, gauntlet.SignInMethodResume, false, now)
	if !ok {
		return
	}
	defer g.releaseAfterReset(res)

	// Passkey resume (#77) plugs in here: a verified passkey assertion
	// with user verification, whose credential belongs to user, resumes
	// the session in place of the password -- same reservation, same
	// Resume call below. Nothing is built for it yet.
	authed, err := g.deps.Users.Authenticate(user.Username, req.Password, now)
	if err != nil && !errors.Is(err, gauntlet.ErrInvalidCredentials) {
		g.releaseLogin(res, now)
		g.logError("recording resume for " + user.Username + ": " + err.Error())
		writeProblem(w, http.StatusInternalServerError, classServerError, "unable to complete sign-in", nil)
		return
	}
	if err != nil {
		// Reservations stay claimed: that is what counts the failure.
		g.endAfterReset(res)
		g.recordSignIn(r, loginEvent(user, "", gauntlet.SignInWrongPassword, gauntlet.SignInMethodResume), res, now)
		writeUnauthorized(w, classInvalidCredentials, "incorrect password")
		return
	}
	// The password is right but the account now owes a change (a breach
	// check at Authenticate, say): a full sign-in takes it to that door.
	if authed.MustChangePassword {
		g.releaseLogin(res, now)
		g.endAfterReset(res)
		writeUnauthorized(w, classSignInRequired, "sign in again")
		return
	}
	cookie, _ := r.Cookie(g.sessionCookieName())
	sess, ok := g.deps.Sessions.Resume(cookie.Value, g.signInClient(r, res.address), now)
	if !ok {
		// Resumed by another request, or ended, while the password was
		// being checked.
		g.releaseLogin(res, now)
		g.endAfterReset(res)
		writeUnauthorized(w, classSignInRequired, "sign in again")
		return
	}
	g.releaseLogin(res, now)
	g.endAfterReset(res)
	g.setResumedSessionCookie(w, sess, now)
	g.recordSignIn(r, loginEvent(user, "", gauntlet.SignInSuccess, gauntlet.SignInMethodResume), res, now)
	writeJSON(w, http.StatusOK, map[string]any{"username": user.Username, "role": user.Role})
}
