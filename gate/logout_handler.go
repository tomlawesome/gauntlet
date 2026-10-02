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
// mikroview's #677/handleAuthLogoutAll. User-tier: it acts only on the
// caller's own sessions, resolved from the session cookie, never from a
// body field naming someone else.
func (g *Gate) handleLogoutAll(w http.ResponseWriter, r *http.Request) {
	now := g.now()
	user, ok := g.sessionUser(r, now)
	if !ok {
		writeUnauthorized(w, "sign in first")
		return
	}

	g.deps.Sessions.RevokeAllForUser(user.ID)
	g.audit(user.Username, "account.sessions_ended", user.Username, "sessions ended: all, via sign out everywhere")

	sess := g.deps.Sessions.Create(user.ID, now)
	g.setSessionCookie(w, sess.ID)
	writeJSON(w, http.StatusOK, map[string]any{"signedOutEverywhere": true})
}
