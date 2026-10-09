package gate

import (
	"fmt"
	"net/http"
)

// unlockCodeRequest is the body of the lone-admin unlock route: the
// admin's username and the one-time code the server wrote to its log
// (gauntlet.Store.CheckUnlockCode, #44).
type unlockCodeRequest struct {
	Username   string `json:"username"`
	UnlockCode string `json:"unlockCode"`
}

// handleUnlockCode redeems the lone-admin unlock code: when the admin's
// sign-in has been disabled after a run of failed attempts and no other
// admin can unlock it, a store that opens in that state writes a
// one-time code to the server's log. Showing it here, with the admin's
// username, lifts the disable -- and nothing else (owner, 2026-10-02).
// It is not a sign-in: no session is issued, and the admin then signs
// in as normal with their existing password and second factor. Nor is
// it a password reset, an account reset or an admin transfer.
//
// It mirrors first-run registration's handling of the setup code
// (handleRegister): the attempt is reserved against the client address
// first, on the login limiter's budget, so probing for the code is
// noticed and throttled; a wrong code keeps the reservation; a right
// one releases it. Every refusal of the code is the same 401 with the
// same body, whatever was wrong -- the username, the code, no code
// outstanding, or an admin who is not disabled -- so the route says
// nothing about which account is the admin or what state it is in.
//
// The unlock goes through gauntlet.LoginLimiter.UnlockLogin, as the
// admin route's does, so this process's own count of the guesses goes
// with the disable; and the code dies with it (single use).
func (g *Gate) handleUnlockCode(w http.ResponseWriter, r *http.Request) {
	var req unlockCodeRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}

	now := g.now()
	ipKey := addressKey(g.cfg.ClientIP(r))
	if !g.deps.Limiter.Reserve(ipKey, now) {
		writeProblem(w, http.StatusTooManyRequests, classRateLimited, "too many attempts, try again later", nil)
		return
	}
	user, err := g.deps.Users.CheckUnlockCode(req.Username, req.UnlockCode)
	if err != nil {
		// gauntlet.ErrUnlockCodeInvalid, the only error CheckUnlockCode
		// returns. The username and
		// address are quoted: one is typed by a stranger, the other may
		// come from a proxy header a client controls.
		g.logWarn(fmt.Sprintf("refused an unlock code for %q from %q", req.Username, g.cfg.ClientIP(r)))
		writeUnauthorized(w, classInvalidCredentials, "invalid username or unlock code -- the current code, if any, is in the server's log")
		return
	}
	g.deps.Limiter.Release(ipKey, now)

	if err := g.deps.Limiter.UnlockLogin(g.deps.Users, user.ID); err != nil {
		g.writeAuthError(w, r, err, http.StatusInternalServerError, classServerError)
		return
	}

	g.audit(r, user.Username, "account.unlock_code_used", user.Username,
		"sign-in disable lifted with the one-time unlock code from the server's log; password, second factors and sessions unchanged")
	writeJSON(w, http.StatusOK, map[string]any{"username": user.Username, "unlocked": true})
}
