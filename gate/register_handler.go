package gate

import (
	"fmt"
	"net/http"

	"github.com/tomlawesome/gauntlet"
)

// credentialsRequest is the body of login: the username and password,
// and nothing else. Mikroview's own shape (internal/api/auth.go).
type credentialsRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// registerRequest is the body of first-run registration: the
// credentials plus the one-time setup code the server announced in its
// log (gauntlet.Store.CheckSetupCode, issue #37).
type registerRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	SetupCode string `json:"setupCode"`
}

// handleRegister creates the first (and only ever self-service) account,
// always as admin -- see gauntlet.Store.Register -- and only for a
// caller who shows the setup code from the server's log.
//
// Order matters: the attempt is reserved against the client address
// first (the same limiter and budget as login, so probing for the code
// is noticed and throttled), then the code is checked, and only then is
// the password hashed -- a wrong code costs the server one hash
// comparison, never 64 MiB of Argon2. The reservation is released once
// the code is right, whatever happens after it: the budget guards the
// code, not the operator's typing of a username or password.
func (g *Gate) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	now := g.now()
	ipKey := "ip:" + g.cfg.ClientIP(r)
	if !g.deps.Limiter.Reserve(ipKey, now) {
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
		return
	}
	if err := g.deps.Users.CheckSetupCode(req.SetupCode); err != nil {
		status := http.StatusInternalServerError
		switch err {
		case gauntlet.ErrSetupCodeInvalid:
			// The address is quoted: it comes from the application's
			// ClientIP, which may read a proxy header a client controls.
			g.logWarn(fmt.Sprintf("refused first-run registration for %q from %q: wrong setup code", req.Username, g.cfg.ClientIP(r)))
			writeUnauthorized(w, "invalid setup code -- the current one is in the server's log")
			return
		case gauntlet.ErrRegistrationClosed:
			status = http.StatusConflict
		case gauntlet.ErrNotPersisted:
			status = http.StatusServiceUnavailable
		}
		g.deps.Limiter.Release(ipKey, now)
		g.writeAuthError(w, r, err, status)
		return
	}
	g.deps.Limiter.Release(ipKey, now)

	if g.refuseProductName(w, r, req.Password) {
		return
	}
	user, err := g.deps.Users.Register(req.Username, req.Password, now)
	if err != nil {
		status := http.StatusInternalServerError
		switch err {
		case gauntlet.ErrRegistrationClosed:
			status = http.StatusConflict
		case gauntlet.ErrNotPersisted:
			status = http.StatusServiceUnavailable
		case gauntlet.ErrPasswordTooShort, gauntlet.ErrPasswordBlocked, gauntlet.ErrPasswordContext,
			gauntlet.ErrUsernameInvalid, gauntlet.ErrUsernameLength, gauntlet.ErrUsernameIsEmail:
			status = http.StatusBadRequest
		}
		g.writeAuthError(w, r, err, status)
		return
	}

	g.issueSession(w, r, user.ID, now)
	g.audit(user.Username, "user.register", user.Username, "role="+string(user.Role))
	writeJSON(w, http.StatusCreated, map[string]any{"username": user.Username, "role": user.Role})
}
