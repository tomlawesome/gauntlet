package gate

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// allowSignInResponse is the allow-sign-in route's answer: the account,
// and when the allowance ends unless a completed sign-in spends it
// first.
type allowSignInResponse struct {
	Username     string    `json:"username"`
	AllowedUntil time.Time `json:"allowedUntil"`
}

// handleAllowSignIn is POST /api/auth/users/{id}/allow-sign-in (#81,
// ADR-0009 decision 11): an admin allows the account's next sign-in for
// gauntlet.SignInAllowanceLifetime (ten minutes), so a sign-in the
// unusual-sign-in policy would hold or refuse -- a new browser or place
// -- completes instead, and is remembered as any completed sign-in is.
// The pattern is Microsoft Entra's "confirm user safe": the admin has
// checked out of band that the person is who they say, and the policy
// stands down once, before they sign in again. Nothing is held and
// released; the person signs in normally inside the window.
//
// For another account the body is the caller's password
// (adminStepUpRequest, recheckAdminPassword), as reset-password takes
// (#72): the route hands out access to an account, so a stolen session
// cookie alone must not do it. For the caller's own account it is the
// password and a current second factor, code or passkey
// (unlockSelfRequest, recheckStepUp), as own unlock takes (#82): the
// lone admin with a new laptop, phone in hand, is who needs it.
//
// It writes one field (gauntlet.Store.AllowNextSignIn), replacing any
// earlier window, so a repeat call starts a fresh ten minutes. It
// changes no credential, session, lockout or disable: a locked or
// disabled account is still refused at the password step, and the admin
// unlocks it as well. An SSO-only account needs nothing local: its SSO
// callback completes inside the window. The window ends at the clock, at
// the account's next completed sign-in from any browser, and wherever
// the account's known browsers are cleared (a reset code, sign out
// everywhere).
//
// Audited as user.sign_in_allowed; the account holder is told
// (NoticeSignInAllowed) once the response is written. 404 for an
// unknown account.
func (g *Gate) handleAllowSignIn(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "user id is required", nil)
		return
	}
	now := g.now()
	caller := UserFromContext(r)
	own := caller != nil && caller.ID == id
	var selfAssertion json.RawMessage
	if own {
		var req unlockSelfRequest
		if err := g.decodeJSONBody(w, r, &req); err != nil {
			writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
			return
		}
		if !g.recheckStepUp(w, r, caller, req.Password, req.Code, req.Assertion, now,
			"allowing your own next sign-in needs your password and either a code from your authenticator app or a recovery code, or your passkey (password, code or assertion)") {
			return
		}
		selfAssertion = req.Assertion
	} else {
		var req adminStepUpRequest
		if err := g.decodeJSONBody(w, r, &req); err != nil {
			writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
			return
		}
		if !g.recheckAdminPassword(w, r, req.Password, now) {
			return
		}
	}

	target, err := g.deps.Users.AllowNextSignIn(id, now)
	if err != nil {
		status, class := http.StatusInternalServerError, classServerError
		switch {
		case errors.Is(err, gauntlet.ErrUserNotFound):
			status, class = http.StatusNotFound, classNotFound
		case errors.Is(err, gauntlet.ErrNotPersisted):
			status, class = http.StatusServiceUnavailable, classNotPersisted
		}
		g.writeAuthError(w, r, err, status, class)
		return
	}

	until := target.SignInAllowedUntil
	detail := fmt.Sprintf("next sign-in allowed until %s from any browser or place; password, second factors, sessions, lockout and disable unchanged",
		until.Format(time.RFC3339))
	if own {
		detail += "; own account, password and " + stepUpFactor(selfAssertion) + " re-entered"
	}
	by := auditActor(r)
	g.audit(r, by, "user.sign_in_allowed", target.Username, detail)
	writeJSON(w, http.StatusOK, allowSignInResponse{Username: target.Username, AllowedUntil: until})
	g.notify(r.Context(), &AccountNotice{
		Kind: NoticeSignInAllowed, UserID: target.ID, Username: target.Username, Role: target.Role, At: now, By: by,
		SignInAllowed: &SignInAllowedDetail{Until: until},
	})
}
