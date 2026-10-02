package gate

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"unicode"
)

// MaxSessionEndReason bounds the reason an admin may give for ending
// another account's sessions, in bytes. It reaches the audit log and,
// through Config.Notify, the account owner's mail, so it is short and
// plain: control and format characters are refused, not stripped.
const MaxSessionEndReason = 200

// adminLogoutAllRequest is POST /api/auth/users/{id}/logout-all's
// optional body.
type adminLogoutAllRequest struct {
	Reason string `json:"reason,omitempty"`
}

// adminLogoutAllResponse is its answer.
type adminLogoutAllResponse struct {
	Username string `json:"username"`
	// Ended is how many live sessions ended.
	Ended int `json:"ended"`
	// Notified is true when Config.Notify was asked to tell the account's
	// owner -- asked, not delivered (Notifier).
	Notified bool `json:"notified"`
}

// validSessionEndReason reports whether reason is short enough and
// carries no control or format character. (JSON decoding has already
// replaced any invalid UTF-8 with U+FFFD.)
func validSessionEndReason(reason string) bool {
	if len(reason) > MaxSessionEndReason {
		return false
	}
	for _, r := range reason {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// handleAdminLogoutAll is an admin ending every session another account
// holds (#53, owner 2026-10-02: all of them, no per-session admin
// route), and with them every browser the account remembers --
// "everywhere means everywhere", as the account's own sign out
// everywhere does (handleLogoutAll). A clear that cannot be saved is
// logged and the sign-out stands. It ends gauntlet's sessions only,
// never the identity provider's.
//
// The caller's own account is refused with 409: they have POST
// /api/auth/logout-all, which keeps the browser they are using signed
// in. 404 for no such account; 400 for a reason over
// MaxSessionEndReason bytes, or holding a control or format character.
// The body is optional.
//
// Once the response is written, Config.Notify, if set, is asked to tell
// the account's owner (notifySessionsEnded); "notified" in the response
// says it was asked.
func (g *Gate) handleAdminLogoutAll(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req adminLogoutAllRequest
	if err := decodeJSONBody(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if !validSessionEndReason(req.Reason) {
		http.Error(w, fmt.Sprintf("the reason must be at most %d bytes of plain text", MaxSessionEndReason), http.StatusBadRequest)
		return
	}
	caller := UserFromContext(r)
	if caller != nil && caller.ID == id {
		http.Error(w, "use sign out everywhere for your own sessions", http.StatusConflict)
		return
	}
	target, ok := g.deps.Users.Get(id)
	if !ok {
		http.Error(w, "no such user", http.StatusNotFound)
		return
	}

	now := g.now()
	// Counted as the account's own list counts them: a session issued
	// before its cutoff is no longer live, and is not one this ended.
	ended := len(g.liveSessions(target, now))
	g.deps.Sessions.RevokeAllForUser(target.ID)
	browsers := "remembered browsers forgotten"
	if err := g.deps.Users.ClearKnownBrowsers(target.ID); err != nil {
		g.logError("forgetting the browsers account " + target.ID + " remembers: " + err.Error())
		browsers = "remembered browsers could not be forgotten"
	}

	notified := g.cfg.Notify != nil
	notify := "none"
	if notified {
		notify = "requested"
	}
	g.audit(auditActor(r), "user.sessions_ended", target.Username,
		fmt.Sprintf("sessions ended: all (n=%d), reason=%q, notify=%s, %s", ended, req.Reason, notify, browsers))
	writeJSON(w, http.StatusOK, adminLogoutAllResponse{Username: target.Username, Ended: ended, Notified: notified})

	if notified {
		g.notifySessionsEnded(r.Context(), SessionsEndedNotice{
			UserID:   target.ID,
			Username: target.Username,
			EndedBy:  auditActor(r),
			Reason:   req.Reason,
			Ended:    ended,
			At:       now,
		})
	}
}
