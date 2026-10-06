package gate

import "net/http"

// handleLogout ends the caller's own session, if any -- calling it with
// no session is a harmless no-op, not worth a 401 for (see exemptPaths).
func (g *Gate) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(g.sessionCookieName()); err == nil {
		g.deps.Sessions.Revoke(cookie.Value)
	}
	g.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"loggedOut": true})
}

// handleLogoutAll ends every session the caller holds, on every device
// ("sign out everywhere"), then issues a fresh session and cookie so the
// device the call was made from is not itself logged out by it --
// mikroview's #677/handleAuthLogoutAll. The fresh session continues the
// caller's (issueContinuedSession): no credential is asked for here, so
// it keeps the original sign-in's lifetime ceiling. User-tier: it acts
// only on the caller's own sessions, resolved from the session cookie,
// never from a body field naming someone else.
//
// It also forgets every browser the account remembers
// (gauntlet.Store.ClearKnownBrowsers, #44): someone signing out
// everywhere suspects a device they no longer control, and that device
// should keep no allowance during a lockout either. The browser making
// the call is remembered again as its new session is issued. A clear
// that cannot be saved is logged, and the sign-out goes on: the
// sessions are what the caller asked to end, and they are already gone.
func (g *Gate) handleLogoutAll(w http.ResponseWriter, r *http.Request) {
	now := g.now()
	user, ok := g.sessionUser(r, now)
	if !ok {
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
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
	detail := "sessions ended: all, via sign out everywhere; remembered browsers forgotten"
	if err := g.deps.Users.ClearKnownBrowsers(user.ID); err != nil {
		g.logError("forgetting the browsers account " + user.ID + " remembers: " + err.Error())
		detail = "sessions ended: all, via sign out everywhere; remembered browsers could not be forgotten"
	}
	g.audit(r, user.Username, "account.sessions_ended", user.Username, detail)

	g.issueContinuedSession(w, r, old, now)
	writeJSON(w, http.StatusOK, map[string]any{"signedOutEverywhere": true})
}
