package gate

import (
	"net/http"
	"time"

	"github.com/tomlawesome/gauntlet"
)

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// handleChangePassword lets a signed-in caller change their own
// password (mikroview's #294 item 4).
func (g *Gate) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	now := g.now()
	user := UserFromContext(r)
	if user == nil {
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
	// An admin reset (POST /api/auth/users/{id}/reset-password, which
	// calls IssueResetCode) is what sets MustChangePassword.
	if !user.MustChangePassword {
		// Throttled and re-checked by recheckPassword.
		if _, ok := g.recheckPassword(w, user, req.CurrentPassword, "current password is incorrect", now); !ok {
			return
		}

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
		// The 500 tells the caller nothing by design; the log is the
		// only place an operator can find out why.
		g.logError("changing the password for " + user.Username + ": " + err.Error())
		http.Error(w, "could not change the password", http.StatusInternalServerError)
		return
	}

	// Every session issued before now is dead by SessionCutoff, but
	// that is only enforced on the next request each one makes -- dropped
	// here so they are gone immediately.
	g.deps.Sessions.RevokeAllForUser(user.ID)

	detail := "sessions ended: all"
	if user.MustChangePassword {
		detail += ", after an administrator's reset"
	}
	g.audit(user.Username, "account.password_changed", user.Username, detail)

	g.issueSession(w, r, user.ID, now)
	writeJSON(w, http.StatusOK, map[string]any{"changed": true, "otherSessionsEnded": true})
}

// recheckPassword asks a signed-in caller for their password again
// before a route that changes how the account is protected (password
// change, TOTP enrol and delete, recovery-code regenerate). The caller
// already holds a session, which is exactly what a stolen cookie gives
// an attacker; the password is the one thing a cookie does not carry.
//
// Rate-limited on the per-account password re-check bucket
// (ReserveRecheck), reserve-then-release like handleLogin: a guess made
// from behind a cookie is still a guess at a live credential, so
// without the bucket each of these routes would be an unthrottled
// password oracle. A wrong password keeps the reservation -- that is
// what counts the failure -- and only a correct one releases it.
//
// Writes the 429, or the 401 carrying wrongMsg, itself; on success it
// returns the freshly authenticated copy of the account.
func (g *Gate) recheckPassword(w http.ResponseWriter, user *gauntlet.User, password, wrongMsg string, now time.Time) (*gauntlet.User, bool) {
	if !g.deps.Limiter.ReserveRecheck(user.ID, now) {
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
		return nil, false
	}
	current, err := g.deps.Users.Authenticate(user.Username, password, now)
	if err != nil {
		writeUnauthorized(w, wrongMsg)
		return nil, false
	}
	g.deps.Limiter.ReleaseRecheck(user.ID, now)
	return current, true
}
