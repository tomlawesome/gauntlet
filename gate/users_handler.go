package gate

import (
	"fmt"
	"net/http"
	"time"

	"github.com/tomlawesome/gauntlet"
)

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// userSummary is what the account list exposes -- deliberately not
// gauntlet.User, which carries PasswordHash and the other credential
// fields List already blanks; serializing it directly is exactly the
// mistake this type exists to make impossible.
type userSummary struct {
	ID               string    `json:"id"`
	Username         string    `json:"username"`
	Role             string    `json:"role"`
	CreatedAt        time.Time `json:"createdAt"`
	LastLogin        time.Time `json:"lastLogin,omitzero"`
	HasLocalPassword bool      `json:"hasLocalPassword"`
	SSO              bool      `json:"sso"`
	// HasTOTP mirrors mikroview's admin-list pill: true once this
	// account holds a confirmed authenticator-app factor. Filled in by
	// re-reading each account through Store.Get (see
	// handleListUsers below) rather than trusting u.HasActiveTOTP() on
	// a List entry -- List blanks TOTPSecret on every copy it returns,
	// so that would read false for every account regardless of the
	// truth (totp.go's own doc comment names this exact trap; there is
	// no Store.HasActiveTOTP(id) convenience wrapper, since Get already
	// gives a caller an unblanked copy to call the User method on
	// directly).
	HasTOTP bool `json:"hasTOTP"`
}

// handleCreateUser lets an existing admin add another account -- the
// only way to create a user once self-registration has closed.
func (g *Gate) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Role == string(gauntlet.RoleAdmin) {
		g.writeAuthError(w, r, gauntlet.ErrSingleAdmin, http.StatusBadRequest)
		return
	}
	var role gauntlet.Role
	switch req.Role {
	case "", string(gauntlet.RoleUser):
		role = gauntlet.RoleUser
	case string(gauntlet.RoleViewer):
		role = gauntlet.RoleViewer
	default:
		g.writeAuthError(w, r, gauntlet.ErrInvalidRole, http.StatusBadRequest)
		return
	}

	user, err := g.deps.Users.CreateUser(req.Username, req.Password, role, g.now())
	if err != nil {
		status := http.StatusInternalServerError
		switch err {
		case gauntlet.ErrUsernameTaken:
			status = http.StatusConflict
		case gauntlet.ErrPasswordTooShort, gauntlet.ErrSingleAdmin, gauntlet.ErrInvalidRole,
			gauntlet.ErrUsernameInvalid, gauntlet.ErrUsernameLength, gauntlet.ErrUsernameIsEmail:
			status = http.StatusBadRequest
		}
		g.writeAuthError(w, r, err, status)
		return
	}
	g.audit(auditActor(r), "user.create", user.Username, "role="+string(user.Role))
	writeJSON(w, http.StatusCreated, map[string]any{"username": user.Username, "role": user.Role})
}

// handleListUsers backs the admin-facing account list. Admin-only (via
// Routes' RequireRole wrapping), and there is no empty-list fallback:
// the gate refuses the whole request before this handler ever runs for
// a non-admin caller.
func (g *Gate) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users := g.deps.Users.List()
	out := make([]userSummary, 0, len(users))
	for _, u := range users {
		// Asked of the store directly rather than of u, deliberately --
		// see userSummary.HasTOTP's own doc comment for the trap this
		// avoids. Get returns an unblanked copy, so HasActiveTOTP on it
		// reads the real value; a failed lookup (the account was
		// deleted between List and this call) just leaves it false.
		hasTOTP := false
		if current, ok := g.deps.Users.Get(u.ID); ok {
			hasTOTP = current.HasActiveTOTP()
		}
		out = append(out, userSummary{
			ID:               u.ID,
			Username:         u.Username,
			Role:             string(u.Role),
			CreatedAt:        u.CreatedAt,
			LastLogin:        u.LastLogin,
			HasLocalPassword: u.LocalPassword(),
			SSO:              u.OIDCIssuer != "",
			HasTOTP:          hasTOTP,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDeleteUser removes an account and everything it can still be
// used with: a live session cookie and a bearer token neither re-check
// that the account still exists on every request, so both would outlive
// the deletion if not revoked here.
func (g *Gate) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "user id is required", http.StatusBadRequest)
		return
	}

	user, err := g.deps.Users.DeleteUser(id)
	if err != nil {
		status := http.StatusInternalServerError
		switch err {
		case gauntlet.ErrUserNotFound:
			status = http.StatusNotFound
		case gauntlet.ErrCannotDeleteAdmin:
			status = http.StatusConflict
		}
		g.writeAuthError(w, r, err, status)
		return
	}

	// Deletion first, revocations only once it has committed -- the
	// reverse order would sign a user out and destroy their tokens on
	// the way to a deletion that can still be refused.
	g.deps.Sessions.RevokeAllForUser(user.ID)
	revokedTokens, err := g.deps.Tokens.RevokeAllCreatedBy(user.ID)
	if err != nil {
		// The account deletion already committed, so this request still
		// succeeds -- but a failed revoke here leaves this user's tokens
		// durably intact, so it is said out loud server-side rather than
		// reported as done: the response reflects what actually
		// persisted (zero), not what was attempted.
		g.logError(fmt.Sprintf("revoking tokens for deleted user %s: %v", user.ID, err))
		revokedTokens = 0
	}

	g.audit(auditActor(r), "user.delete", user.Username,
		fmt.Sprintf("role=%s tokensRevoked=%d", user.Role, revokedTokens))
	writeJSON(w, http.StatusOK, map[string]any{
		"username":      user.Username,
		"tokensRevoked": revokedTokens,
	})
}

// resetPasswordResponse is the only place an issued reset code exists in
// clear. Nothing persists it, nothing logs it, and no later request can
// retrieve it: an admin who loses it issues another, which kills this
// one.
type resetPasswordResponse struct {
	Username string `json:"username"`
	// Code is grouped xxxx-xxxx-xxxx-xxxx for reading aloud. The server
	// accepts it back in any case, with or without the dashes.
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// handleResetPassword is the admin's way back in for somebody who has
// lost their password. gauntlet sends no mail, so there is no reset
// link: the admin resets the account, reads the returned code out to
// its owner in person or over a call they trust, and the owner types it
// into the password box once and chooses a new password on the spot.
//
// Two accounts are refused, both with 409:
//
//   - the caller's own. An admin locked out of their own account cannot
//     bootstrap themselves back in with a code they mint for themselves
//     -- that is POST /api/auth/password if they still know the current
//     one. gauntlet holds exactly one admin (ErrSingleAdmin), so this is
//     also what keeps the admin account out of this route entirely.
//   - an SSO-only account. Its identity provider owns the credential --
//     see gauntlet.ErrNoLocalPassword.
//
// The account's live sessions go with the reset, twice over: the store
// bumps PasswordChangedAt (which ends them across processes and
// restarts) and this drops the ones in memory immediately, the same
// pattern handleDeleteUser and handleChangePassword use.
func (g *Gate) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "user id is required", http.StatusBadRequest)
		return
	}
	if caller := UserFromContext(r); caller != nil && caller.ID == id {
		http.Error(w, "an administrator cannot reset their own password here -- change it from the account menu", http.StatusConflict)
		return
	}

	now := g.now()
	user, code, err := g.deps.Users.IssueResetCode(id, now)
	if err != nil {
		status := http.StatusInternalServerError
		switch err {
		case gauntlet.ErrUserNotFound:
			status = http.StatusNotFound
		case gauntlet.ErrNoLocalPassword:
			status = http.StatusConflict
		case gauntlet.ErrNotPersisted:
			status = http.StatusServiceUnavailable
		}
		g.writeAuthError(w, r, err, status)
		return
	}

	g.deps.Sessions.RevokeAllForUser(user.ID)

	// Who reset whom, and never the code -- not here, not in any log
	// line. The detail records the deadline instead, which is what an
	// operator reading this entry later actually needs.
	g.audit(auditActor(r), "user.password_reset", user.Username,
		fmt.Sprintf("one-time code issued, expires %s; sessions ended: all",
			user.ResetCodeExpiresAt.Format(time.RFC3339)))

	writeJSON(w, http.StatusOK, resetPasswordResponse{
		Username:  user.Username,
		Code:      code,
		ExpiresAt: user.ResetCodeExpiresAt,
	})
}
