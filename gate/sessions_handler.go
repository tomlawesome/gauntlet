package gate

import (
	"net/http"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// A person's own session list (ASVS 7.5.2, gauntlet#48): every session
// their account holds, and a way to end any one of them. Both routes act
// only on the caller's own account, resolved from the session Protect
// put in context; there is no admin view of anyone else's sessions and
// no admin route to end one (owner, 2026-10-02). An admin already ends
// every session of an account with a reset code or by deleting it
// (ASVS 7.4.5), and showing one person's addresses and browsers to
// another would widen what an admin learns about people, not what they
// can stop.

// maxSessionRows caps how many sessions GET /api/auth/sessions lists.
// Sessions per account are not limited -- a script that signs in per
// poll can hold thousands for a day -- and the body is built per
// request, so without a cap one such account would make every listing
// as large as its history. sessionListResponse.Total still counts every
// live session, so the cap is visible rather than silent.
const maxSessionRows = 100

// sessionRow is one session in GET /api/auth/sessions -- a closed
// shape, so nothing about a session reaches a page unless it is named
// here. It never carries the session ID: that is the cookie, and a
// page that rendered it would hand a copy of every session to anything
// that can read the page. Ref (gauntlet.Session.Ref) names the session
// instead.
type sessionRow struct {
	Ref string `json:"ref"`
	// Current marks the session this request was made with -- ending it
	// signs this browser out.
	Current    bool      `json:"current"`
	SignedInAt time.Time `json:"signedInAt"`
	LastUsedAt time.Time `json:"lastUsedAt"`
	// Address and UserAgent are as the browser presented them at sign-in
	// (gauntlet.SessionClient), absent when none was recorded. Country
	// is the one looked up for Address at sign-in (#54), absent when no
	// lookup was configured or nothing was known for it.
	Address   string `json:"address,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`
	Country   string `json:"country,omitempty"`
	// Unusual is the unusual-sign-in signals the session arrived with
	// (#55), as an array of names; absent for an ordinary sign-in.
	Unusual gauntlet.SignInSignals `json:"unusual,omitzero"`
	// Method is how the sign-in was made (#77): password and code for a
	// password then a second-factor code, passkey for a password then a
	// passkey, passkey_alone for a passkey on its own, sso. Absent when
	// the session recorded none. A resumed or rotated session keeps the
	// method of the sign-in it continues.
	Method gauntlet.SignInMethod `json:"method,omitempty"`
}

// sessionListResponse is GET /api/auth/sessions's body: an object
// rather than a bare array, so a field can be added later without
// breaking a reader.
type sessionListResponse struct {
	// Sessions is newest sign-in first, at most maxSessionRows.
	Sessions []sessionRow `json:"sessions"`
	// Total is how many live sessions the account holds, which exceeds
	// len(Sessions) only when the cap cut the list.
	Total int `json:"total"`
}

// sessionEndedResponse is DELETE /api/auth/sessions/{ref}'s body.
type sessionEndedResponse struct {
	Ended bool `json:"ended"`
	// SignedOut is true when the session ended was the one the request
	// was made with: the cookie has been cleared, and the frontend should
	// treat this browser as signed out.
	SignedOut bool `json:"signedOut"`
}

// liveSessions is user's sessions as sessionUser would judge them:
// gauntlet.SessionStore.ListForUser already drops the expired ones, and
// any issued before user.SessionCutoff -- a password change, reset or
// SSO link since -- is revoked here rather than listed, exactly as
// sessionUser revokes one presented to it. Without this a list would
// show sessions the account's next request through them would refuse.
func (g *Gate) liveSessions(user *gauntlet.User, now time.Time) []gauntlet.Session {
	all := g.deps.Sessions.ListForUser(user.ID, now)
	cutoff := user.SessionCutoff()
	live := all[:0]
	for _, sess := range all {
		if sess.IssuedAt.Before(cutoff) {
			g.deps.Sessions.Revoke(sess.ID)
			continue
		}
		live = append(live, sess)
	}
	return live
}

// currentSessionID is the session ID r's cookie carries, or "" -- the
// session Protect has just validated for this request.
func (g *Gate) currentSessionID(r *http.Request) string {
	if cookie, err := r.Cookie(g.sessionCookieName()); err == nil {
		return cookie.Value
	}
	return ""
}

// handleSessionsList lists the caller's own live sessions, newest first,
// at most maxSessionRows of them. Session-gated, not exempt: unlike GET
// /api/auth/session, which reports state to anyone, this answers 401
// without a session.
func (g *Gate) handleSessionsList(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
	}
	live := g.liveSessions(user, g.now())
	current := g.currentSessionID(r)
	resp := sessionListResponse{Sessions: make([]sessionRow, 0, min(len(live), maxSessionRows)), Total: len(live)}
	for _, sess := range live[:min(len(live), maxSessionRows)] {
		resp.Sessions = append(resp.Sessions, sessionRow{
			Ref:        sess.Ref(),
			Current:    sess.ID == current,
			SignedInAt: sess.IssuedAt,
			LastUsedAt: sess.LastUsedAt,
			Address:    sess.Client.Address,
			UserAgent:  sess.Client.UserAgent,
			Country:    sess.Client.Country,
			Unusual:    sess.Client.Unusual,
			Method:     sess.Client.Method,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleSessionEnd ends one of the caller's own sessions, named by its
// ref from the list. Ending the session the request was made with
// clears the cookie and says so in SignedOut.
//
// It asks for no password, unlike the routes that change how an account
// signs in (recheckPassword) and unlike ASVS 7.5.2, which asks for
// re-authentication first. Owner decision, 2026-10-02: signing out is a
// safe direction. The worst a stolen session can do here is end
// sessions. Sign out everywhere (POST /api/auth/logout-all) ends them
// too, behind a password re-check for an account with a local password
// and none for one signed in only through SSO, which has no password to
// give; this route ends one at a time and asks for nothing. It ends the
// gauntlet session only: the identity provider's own session is not
// touched (owner, 2026-10-02).
//
// Any ref that does not name one of the caller's live sessions answers
// 404 -- malformed, unknown, expired, issued before the account's
// SessionCutoff, or belonging to another account alike, and in every
// case nothing ends. Never 403: a refusal that differed for another
// account's session would confirm that session exists.
func (g *Gate) handleSessionEnd(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
	}
	ref := r.PathValue("ref")
	now := g.now()

	// Checked against the live list first, so a session the account
	// could no longer use -- expired, or before SessionCutoff -- is a
	// 404, not a reported success. This comparison is plain: the
	// caller can list their own refs, so how fast it fails tells them
	// nothing. RevokeRef then does the ending, and it is what
	// guarantees the session ended belongs to this account.
	listed := false
	for _, sess := range g.liveSessions(user, now) {
		if sess.Ref() == ref {
			listed = true
			break
		}
	}
	if !listed {
		writeProblem(w, http.StatusNotFound, classNotFound, "no such session", nil)
		return
	}
	ended, ok := g.deps.Sessions.RevokeRef(user.ID, ref)
	if !ok {
		// Ended between the two steps, by another request or expiry.
		writeProblem(w, http.StatusNotFound, classNotFound, "no such session", nil)
		return
	}

	signedOut := ended.ID == g.currentSessionID(r)
	if signedOut {
		g.clearSessionCookie(w)
	}
	// The ref, never the ended session's agent or address: the audit log
	// is read by operators, and what a person's browser calls itself is
	// theirs. (The caller's own address is appended, as to every record.)
	g.audit(r, user.Username, "account.sessions_ended", user.Username, "sessions ended: one, ref="+ref+", via session list")
	writeJSON(w, http.StatusOK, sessionEndedResponse{Ended: true, SignedOut: signedOut})
}
