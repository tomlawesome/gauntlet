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
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}

	now := g.now()
	ipKey := "ip:" + g.cfg.ClientIP(r)
	if !g.deps.Limiter.Reserve(ipKey, now) {
		writeProblem(w, http.StatusTooManyRequests, classRateLimited, "too many attempts, try again later", nil)
		return
	}
	if err := g.deps.Users.CheckSetupCode(req.SetupCode); err != nil {
		status := http.StatusInternalServerError
		class := classServerError
		switch err {
		case gauntlet.ErrSetupCodeInvalid:
			// The address is quoted: it comes from the application's
			// ClientIP, which may read a proxy header a client controls.
			g.logWarn(fmt.Sprintf("refused first-run registration for %q from %q: wrong setup code", req.Username, g.cfg.ClientIP(r)))
			writeUnauthorized(w, classInvalidCredentials, "invalid setup code -- the current one is in the server's log")
			return
		case gauntlet.ErrRegistrationClosed:
			status, class = http.StatusConflict, classConflict
		case gauntlet.ErrNotPersisted:
			status, class = http.StatusServiceUnavailable, classNotPersisted
		}
		g.deps.Limiter.Release(ipKey, now)
		g.writeAuthError(w, r, err, status, class)
		return
	}
	g.deps.Limiter.Release(ipKey, now)

	if g.refuseProductName(w, r, req.Password) {
		return
	}
	user, err := g.deps.Users.Register(req.Username, req.Password, now)
	if err != nil {
		if err == gauntlet.ErrRegistrationClosed {
			// Reached only after CheckSetupCode already passed, so the
			// code this caller showed was valid at that instant --
			// this process's own view was just momentarily stale (a
			// lagging reload), and another registration using the same
			// code saved the first admin first. No second admin was
			// created; the generic "registration is closed" message
			// above would read as the code itself being wrong, when
			// it was in fact spent, elsewhere, between the two checks.
			writeProblem(w, http.StatusConflict, classConflict, "the setup code was already used to create the first admin", nil)
			return
		}
		status := http.StatusInternalServerError
		class := classServerError
		switch err {
		case gauntlet.ErrNotPersisted:
			status, class = http.StatusServiceUnavailable, classNotPersisted
		case gauntlet.ErrPasswordTooShort, gauntlet.ErrPasswordBlocked, gauntlet.ErrPasswordContext,
			gauntlet.ErrUsernameInvalid, gauntlet.ErrUsernameLength, gauntlet.ErrUsernameIsEmail:
			status, class = http.StatusBadRequest, classInvalidRequest
		}
		g.writeAuthError(w, r, err, status, class)
		return
	}

	g.issueSession(w, r, user.ID, gauntlet.SignInMethodPassword, now)
	g.audit(r, user.Username, "user.register", user.Username, "role="+string(user.Role))
	writeJSON(w, http.StatusCreated, map[string]any{"username": user.Username, "role": user.Role})
}
