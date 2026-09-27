package gate

import (
	"net/http"

	"github.com/tomlawesome/gauntlet"
)

// credentialsRequest is the body of both login and first-run
// registration: the username and password, and nothing else. Mikroview's
// own shape (internal/api/auth.go).
type credentialsRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleRegister creates the first (and only ever self-service) account,
// always as admin -- see gauntlet.Store.Register.
func (g *Gate) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req credentialsRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	now := g.now()
	user, err := g.deps.Users.Register(req.Username, req.Password, now)
	if err != nil {
		status := http.StatusInternalServerError
		switch err {
		case gauntlet.ErrRegistrationClosed:
			status = http.StatusConflict
		case gauntlet.ErrNotPersisted:
			status = http.StatusServiceUnavailable
		case gauntlet.ErrPasswordTooShort, gauntlet.ErrUsernameInvalid, gauntlet.ErrUsernameLength, gauntlet.ErrUsernameIsEmail:
			status = http.StatusBadRequest
		}
		g.writeAuthError(w, r, err, status)
		return
	}

	sess := g.deps.Sessions.Create(user.ID, now)
	g.setSessionCookie(w, sess.ID)
	g.audit(user.Username, "user.register", user.Username, "role="+string(user.Role))
	writeJSON(w, http.StatusCreated, map[string]any{"username": user.Username, "role": user.Role})
}
