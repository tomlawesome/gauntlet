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
	// HasTOTP mirrors mikroview's admin-list pill, and is always false
	// in this stage: gauntlet.Store.List blanks TOTPSecret on every copy
	// it returns, so User.HasActiveTOTP would read false for every
	// account regardless of the truth (the same trap mikroview's own
	// handleAuthListUsers avoids by asking the store directly through a
	// dedicated accessor -- Store has none in this stage). Left false
	// rather than silently wrong; a stage-2 accessor fixes it properly.
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
		out = append(out, userSummary{
			ID:               u.ID,
			Username:         u.Username,
			Role:             string(u.Role),
			CreatedAt:        u.CreatedAt,
			LastLogin:        u.LastLogin,
			HasLocalPassword: u.LocalPassword(),
			SSO:              u.OIDCIssuer != "",
			// List's own doc comment: TOTPSecret is blanked on every
			// copy it hands back, so u.HasActiveTOTP() would read false
			// for every account here regardless of the truth -- the same
			// trap mikroview's own handleAuthListUsers names, which it
			// avoids by asking the store directly (auth.Store has no
			// HasActiveTOTP(id) accessor; gate does not add one in this
			// stage, so this list's hasTOTP is left unset rather than
			// silently wrong). A stage-2 accessor on Store fixes this
			// properly.
			HasTOTP: false,
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
