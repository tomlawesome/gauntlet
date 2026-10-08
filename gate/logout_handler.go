package gate

import (
	"errors"
	"io"
	"net/http"
)

// handleLogout ends the caller's own session, if any -- calling it with
// no session is a harmless no-op, not worth a 401 for (see exemptPaths).
func (g *Gate) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(g.sessionCookieName()); err == nil {
		g.deps.Sessions.Revoke(cookie.Value)
	}
	g.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"loggedOut": true})
}

// logoutAllRequest is POST /api/auth/logout-all's body: the caller's own
// password, for an account that has one. An SSO-only account sends no
// body, or one without a password.
type logoutAllRequest struct {
	Password string `json:"password"`
}

// handleLogoutAll ends every session the caller holds, on every device
// ("sign out everywhere"), then issues a fresh session and cookie so the
// device the call was made from is not itself logged out by it --
// mikroview's #677/handleAuthLogoutAll. The fresh session continues the
// caller's (issueContinuedSession): the password re-check below proves
// the password, not a whole sign-in, and an SSO-only account gives no
// credential at all, so it keeps the original sign-in's lifetime
// ceiling. User-tier: it acts only on the caller's own sessions, resolved
// from the session cookie, never from a body field naming someone else.
//
// An account with a local password gives it again (recheckPassword,
// 401 or 429 as on every re-check route) before any session ends. It
// also forgets every browser the account remembers
// (gauntlet.Store.ClearKnownBrowsers, #44): someone signing out
// everywhere suspects a device they no longer control, and that device
// should keep no allowance during a lockout either. The browser making
// the call is remembered again as its new session is issued. Without
// the password, a stolen cookie could wipe the account's unusual
// sign-in baseline and leave the thief's browser the only one
// remembered, so that under a block policy the owner would be refused
// on their own devices.
//
// An SSO-only account has no password to ask for. Its sessions still
// end, but the remembered browsers, countries and last place are kept:
// the identity provider is what protects that account, and a cookie
// alone must not reset what the account trusts. Its calling browser is
// still remembered as the new session is issued, which refreshes only
// that one entry. The audit detail says which happened.
//
// A clear that cannot be saved is logged, and the sign-out goes on: the
// sessions are what the caller asked to end, and they are already gone.
func (g *Gate) handleLogoutAll(w http.ResponseWriter, r *http.Request) {
	now := g.now()
	user, ok := g.sessionUser(r, now)
	if !ok {
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
	}
	var req logoutAllRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}
	localPassword := user.LocalPassword()
	if localPassword {
		if _, ok := g.recheckPassword(w, r, user, req.Password, "incorrect password", now); !ok {
			return
		}
	}

	// Read before the sessions end: the new session continues this one,
	// keeping its sign-in time, so this route can never push the
	// lifetime ceiling back. Gone already means another request ended it
	// since sessionUser read it, and nothing is issued then.
	old, ok := g.callerSession(r, user.ID, now)
	if !ok {
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
	}
	g.deps.Sessions.RevokeAllForUser(user.ID)
	detail := "sessions ended: all, via sign out everywhere; remembered browsers kept: no local password"
	if localPassword {
		detail = "sessions ended: all, via sign out everywhere; remembered browsers forgotten"
		if err := g.deps.Users.ClearKnownBrowsers(user.ID); err != nil {
			g.logError("forgetting the browsers account " + user.ID + " remembers: " + err.Error())
			detail = "sessions ended: all, via sign out everywhere; remembered browsers could not be forgotten"
		}
	}
	g.audit(r, user.Username, "account.sessions_ended", user.Username, detail)

	g.issueContinuedSession(w, r, old, now)
	writeJSON(w, http.StatusOK, map[string]any{"signedOutEverywhere": true})
}
