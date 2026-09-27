package gate

import (
	"net/http"
	"strings"

	"github.com/tomlawesome/gauntlet"
)

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// passwordRecheckLimiterKey is the bucket for re-verifying a signed-in
// caller's own current password -- kept separate from login's own
// buckets (loginLimiterKeys) for the reason mikroview's own comment on
// this gives: gauntlet allows exactly one admin, so spending login's
// allowance on a run of typos here could leave nobody able to sign back
// in.
func passwordRecheckLimiterKey(username string) string {
	return "password-recheck:" + strings.ToLower(username)
}

// handleChangePassword lets a signed-in caller change their own
// password (mikroview's #294 item 4).
func (g *Gate) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	now := g.now()
	user, ok := g.sessionUser(r, now)
	if !ok {
		writeUnauthorized(w, "sign in first")
		return
	}

	var req changePasswordRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// An SSO-only account has no local password to change, and inventing
	// one here would quietly create a second way into an account whose
	// owner believes it is federated.
	if !user.LocalPassword() {
		http.Error(w, "this account signs in through your identity provider and has no local password to change", http.StatusConflict)
		return
	}

	// After an admin reset there is no current password to supply -- see
	// mikroview's own handleAuthChangePassword for the full reasoning.
	// gauntlet's admin-reset flow (IssueResetCode) is not in this stage,
	// but MustChangePassword itself is a plain User field a hand-built
	// fixture or a later stage can already set, so the skip is kept.
	if !user.MustChangePassword {
		userKey := passwordRecheckLimiterKey(user.Username)
		if !g.deps.Limiter.Reserve(userKey, now) {
			http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
			return
		}
		if _, err := g.deps.Users.Authenticate(user.Username, req.CurrentPassword, now); err != nil {
			writeUnauthorized(w, "current password is incorrect")
			return
		}
		g.deps.Limiter.Release(userKey, now)

		if req.NewPassword == req.CurrentPassword {
			http.Error(w, "the new password is the same as the current one", http.StatusBadRequest)
			return
		}
	}
	if err := g.deps.Users.SetPassword(user.Username, req.NewPassword, now); err != nil {
		if err == gauntlet.ErrPasswordTooShort {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "could not change the password", http.StatusInternalServerError)
		return
	}

	// Every session issued before now is dead by PasswordChangedAt, but
	// that is only enforced on the next request each one makes -- dropped
	// here so they are gone immediately.
	g.deps.Sessions.RevokeAllForUser(user.ID)

	detail := "sessions ended: all"
	if user.MustChangePassword {
		detail += ", after an administrator's reset"
	}
	g.audit(user.Username, "account.password_changed", user.Username, detail)

	sess := g.deps.Sessions.Create(user.ID, now)
	g.setSessionCookie(w, sess.ID)
	writeJSON(w, http.StatusOK, map[string]any{"changed": true, "otherSessionsEnded": true})
}
