package gate

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/tomlawesome/gauntlet/internal/plaintext"
)

// MaxSessionEndReason bounds the reason an admin may give for ending
// another account's sessions, in characters (runes): what the API
// document's maxLength counts, so a reason it accepts is never refused
// for being written in accented or non-Latin letters. It reaches the
// audit log and, through Config.Notify, the account owner's mail, so it
// is short and plain: control and format characters, the line and
// paragraph separators and U+FFFD are refused, not stripped.
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

// validSessionEndReason reports whether reason is at most
// MaxSessionEndReason characters of plain text (plaintext.ValidWithin):
// no control or format character, no line or paragraph separator and no
// U+FFFD (#90), which is what JSON decoding turns invalid UTF-8 into.
func validSessionEndReason(reason string) bool {
	return plaintext.ValidWithin(reason, MaxSessionEndReason)
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
// MaxSessionEndReason characters, or holding a control or format
// character, a line or paragraph separator or U+FFFD.
// The body is optional.
//
// Once the response is written, Config.Notices, or the deprecated
// Config.Notify, if either is set, is asked to tell the account's owner
// (notifySessionsEnded); "notified" in the response says it was asked.
func (g *Gate) handleAdminLogoutAll(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req adminLogoutAllRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}
	if !validSessionEndReason(req.Reason) {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, fmt.Sprintf("the reason must be at most %d characters of plain text", MaxSessionEndReason), nil)
		return
	}
	caller := UserFromContext(r)
	if caller != nil && caller.ID == id {
		writeProblem(w, http.StatusConflict, classConflict, "use sign out everywhere for your own sessions", nil)
		return
	}
	target, ok := g.deps.Users.Get(id)
	if !ok {
		writeProblem(w, http.StatusNotFound, classNotFound, "no such user", nil)
		return
	}

	now := g.now()
	// Dropped first, as the account's own session list drops them: a
	// session issued before its cutoff is no longer live and should not
	// be reported as one this ended. The count itself comes from
	// EndSessionsForUser below, under the same lock as the revoke --
	// counting separately beforehand would miss a session a login lands
	// between the count and the revoke (gauntlet#58 R5). It counts only
	// sessions still live at now, so a session that timed out and is
	// kept only to be resumed is ended but not reported, as the list
	// does not show it either.
	_ = g.liveSessions(target, now)
	ended := g.deps.Sessions.EndSessionsForUser(target.ID, now)
	browsers := "remembered browsers forgotten"
	if err := g.deps.Users.ClearKnownBrowsers(target.ID); err != nil {
		g.logError("forgetting the browsers account " + target.ID + " remembers: " + err.Error())
		browsers = "remembered browsers could not be forgotten"
	}

	notified := g.cfg.Notify != nil || g.cfg.Notices != nil
	notify := "none"
	if notified {
		notify = "requested"
	}
	g.audit(r, auditActor(r), "user.sessions_ended", target.Username,
		fmt.Sprintf("sessions ended: all (n=%d), reason=%q, notify=%s, %s", ended, req.Reason, notify, browsers))
	writeJSON(w, http.StatusOK, adminLogoutAllResponse{Username: target.Username, Ended: ended, Notified: notified})

	if notified {
		g.notifySessionsEnded(r.Context(), target.Role, SessionsEndedNotice{
			UserID:   target.ID,
			Username: target.Username,
			EndedBy:  auditActor(r),
			Reason:   req.Reason,
			Ended:    ended,
			At:       now,
		})
	}
}
