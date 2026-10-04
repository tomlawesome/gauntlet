package gate

import (
	"errors"
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
	// account holds a confirmed authenticator-app factor. Read from the
	// List entry itself: List blanks TOTPSecret on every copy it
	// returns, but HasActiveTOTP still answers truly on a blanked copy
	// (see gauntlet.User's totpSecretBlanked), so no second read per
	// account is needed.
	HasTOTP bool `json:"hasTOTP"`
	// PasskeyCount is how many passkeys this account holds, from
	// gauntlet.User.PasskeyCount -- List blanks Passkeys on every copy
	// it returns, so len(u.Passkeys) there always reads zero, but
	// PasskeyCount still answers truly on that same copy (gauntlet #42:
	// a separate Store.PasskeyCount call per account, each paying its
	// own staleness reload against the backend, made this list as slow
	// as the backend's worst stall times the account count). Present
	// whether or not the application wires passkeys: an account carried
	// over from mikroview's documents may hold some either way.
	PasskeyCount int `json:"passkeyCount"`
}

// handleCreateUser lets an existing admin add another account -- the
// only way to create a user once self-registration has closed.
func (g *Gate) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}
	if req.Role == string(gauntlet.RoleAdmin) {
		g.writeAuthError(w, r, gauntlet.ErrSingleAdmin, http.StatusBadRequest, classInvalidRequest)
		return
	}
	var role gauntlet.Role
	switch req.Role {
	case "", string(gauntlet.RoleUser):
		role = gauntlet.RoleUser
	case string(gauntlet.RoleViewer):
		role = gauntlet.RoleViewer
	default:
		g.writeAuthError(w, r, gauntlet.ErrInvalidRole, http.StatusBadRequest, classInvalidRequest)
		return
	}

	if g.refuseProductName(w, r, req.Password) {
		return
	}
	user, err := g.deps.Users.CreateUser(req.Username, req.Password, role, g.now())
	if err != nil {
		status, class := http.StatusInternalServerError, classServerError
		switch err {
		case gauntlet.ErrUsernameTaken:
			status, class = http.StatusConflict, classConflict
		case gauntlet.ErrNotPersisted:
			status, class = http.StatusServiceUnavailable, classNotPersisted
		case gauntlet.ErrPasswordTooShort, gauntlet.ErrPasswordBlocked, gauntlet.ErrPasswordContext,
			gauntlet.ErrSingleAdmin, gauntlet.ErrInvalidRole,
			gauntlet.ErrUsernameInvalid, gauntlet.ErrUsernameLength, gauntlet.ErrUsernameIsEmail:
			status, class = http.StatusBadRequest, classInvalidRequest
		}
		g.writeAuthError(w, r, err, status, class)
		return
	}
	g.audit(r, auditActor(r), "user.create", user.Username, "role="+string(user.Role))
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
			HasTOTP:          u.HasActiveTOTP(),
			PasskeyCount:     u.PasskeyCount(),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDeleteUser removes an account and everything it can still be
// used with: a live session cookie and a bearer token neither re-check
// that the account still exists on every request, so both would outlive
// the deletion if not revoked here.
//
// Divergence from mikroview (gauntlet #15): when RevokeAllCreatedBy
// fails, mikroview's handleAuthDeleteUser logs it and still answers 200
// with tokensRevoked=0 -- indistinguishable, on the wire, from "this
// user held no tokens". gate answers 500 instead, with a JSON body
// naming the account and what went wrong, and records the failure in
// the audit detail too. The account is already gone by this point and
// there is no undoing the delete to retry the revoke, so a quiet 200
// would be the only signal lost, not the fix: the tokens themselves are
// exactly as revocable after a 500 as after a 200 -- an admin just has
// to be told to go do it by hand.
func (g *Gate) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "user id is required", nil)
		return
	}

	user, err := g.deps.Users.DeleteUser(id)
	if err != nil {
		status, class := http.StatusInternalServerError, classServerError
		switch err {
		case gauntlet.ErrUserNotFound:
			status, class = http.StatusNotFound, classNotFound
		case gauntlet.ErrCannotDeleteAdmin:
			status, class = http.StatusConflict, classConflict
		}
		g.writeAuthError(w, r, err, status, class)
		return
	}

	// Deletion first, revocations only once it has committed -- the
	// reverse order would sign a user out and destroy their tokens on
	// the way to a deletion that can still be refused.
	g.deps.Sessions.RevokeAllForUser(user.ID)
	revokedTokens, err := g.deps.Tokens.RevokeAllCreatedBy(user.ID)
	if err != nil {
		// The account deletion already committed and cannot be undone
		// from here, but that is not a reason to answer as if this part
		// succeeded too -- see this handler's doc comment.
		g.logError(fmt.Sprintf("revoking tokens for deleted user %s: %v", user.ID, err))
		g.audit(r, auditActor(r), "user.delete", user.Username,
			fmt.Sprintf("role=%s tokensRevoked=0 tokenRevokeFailed=true", user.Role))
		writeProblem(w, http.StatusInternalServerError, classPartiallyCompleted,
			"the account was deleted, but its API tokens could not be revoked -- check the server log and revoke them by hand",
			map[string]any{"username": user.Username})
		return
	}

	g.audit(r, auditActor(r), "user.delete", user.Username,
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
// bumps SessionsEndedAt (which ends them across processes and
// restarts) and this drops the ones in memory immediately, the same
// pattern handleDeleteUser and handleChangePassword use.
func (g *Gate) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "user id is required", nil)
		return
	}
	if caller := UserFromContext(r); caller != nil && caller.ID == id {
		writeProblem(w, http.StatusConflict, classConflict, "an administrator cannot reset their own password here -- change it from the account menu", nil)
		return
	}

	now := g.now()
	user, code, err := g.deps.Users.IssueResetCode(id, now)
	if err != nil {
		status, class := http.StatusInternalServerError, classServerError
		switch err {
		case gauntlet.ErrUserNotFound:
			status, class = http.StatusNotFound, classNotFound
		case gauntlet.ErrNoLocalPassword:
			status, class = http.StatusConflict, classConflict
		case gauntlet.ErrNotPersisted:
			status, class = http.StatusServiceUnavailable, classNotPersisted
		}
		g.writeAuthError(w, r, err, status, class)
		return
	}

	g.deps.Sessions.RevokeAllForUser(user.ID)

	// Who reset whom, and never the code -- not here, not in any log
	// line. The detail records the deadline instead, which is what an
	// operator reading this entry later actually needs.
	g.audit(r, auditActor(r), "user.password_reset", user.Username,
		fmt.Sprintf("one-time code issued, expires %s; sessions ended: all; sign-in lockout and any disable lifted",
			user.ResetCodeExpiresAt.Format(time.RFC3339)))

	writeJSON(w, http.StatusOK, resetPasswordResponse{
		Username:  user.Username,
		Code:      code,
		ExpiresAt: user.ResetCodeExpiresAt,
	})
}

// unlockUserResponse is the admin unlock route's answer: what the
// account's record held before the unlock, for the admin's own
// confirmation. Both false is the idempotent case -- there was nothing
// to lift, and still 200.
type unlockUserResponse struct {
	Username string `json:"username"`
	// WasDisabled is true when the account's sign-in had been disabled
	// after gauntlet.MaxConsecutiveLoginFailures failures in a row.
	WasDisabled bool `json:"wasDisabled"`
	// WasLockedOut is true when a login lockout was in force.
	WasLockedOut bool `json:"wasLockedOut"`
}

// unlockSelfRequest is the body of the admin unlock route when the
// account is the caller's own: the password and a current second factor
// -- a TOTP code or a recovery code -- entered again (owner,
// 2026-10-02). Another account's unlock takes no body.
type unlockSelfRequest struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

// handleUnlockUser is the admin's way to lift a disabled sign-in on
// another account (#44), or on their own (recheckUnlockSelf), and with
// it any lockout and the count of lockouts: the account then signs in as one that never failed, with
// the password and second factor it already has. Nothing else about the
// account changes -- not its password, factors, sessions or a pending
// forced password change.
//
// It goes through gauntlet.LoginLimiter.UnlockLogin rather than the
// store's UnlockLogin alone, so this process's own count of the
// account's recent wrong guesses, and any lockout decision it has yet to
// save, go too; otherwise the account could stay refused here until that
// window passed.
//
// The caller's own account takes the password and a current second
// factor as well (recheckUnlockSelf). 404 for an unknown account.
func (g *Gate) handleUnlockUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "user id is required", nil)
		return
	}
	now := g.now()
	if caller := UserFromContext(r); caller != nil && caller.ID == id {
		// Only the caller's own unlock reads a body; another account's
		// takes none, as before.
		var req unlockSelfRequest
		if err := g.decodeJSONBody(w, r, &req); err != nil {
			writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
			return
		}
		if !g.recheckUnlockSelf(w, r, caller, req, now) {
			return
		}
	}

	target, ok := g.deps.Users.Get(id)
	if !ok {
		writeProblem(w, http.StatusNotFound, classNotFound, "no such user", nil)
		return
	}
	resp := unlockUserResponse{
		Username:     target.Username,
		WasDisabled:  !target.LoginDisabledAt.IsZero(),
		WasLockedOut: now.Before(target.LoginLockedUntil),
	}
	if err := g.deps.Limiter.UnlockLogin(g.deps.Users, id); err != nil {
		status, class := http.StatusInternalServerError, classServerError
		if errors.Is(err, gauntlet.ErrUserNotFound) {
			status, class = http.StatusNotFound, classNotFound // deleted since the read above
		}
		g.writeAuthError(w, r, err, status, class)
		return
	}

	how := "sign-in unlocked by admin"
	if caller := UserFromContext(r); caller != nil && caller.ID == id {
		how = "own sign-in unlocked by admin, password and second factor re-entered"
	}
	g.audit(r, auditActor(r), "user.unlock", target.Username,
		fmt.Sprintf("%s; wasDisabled=%t wasLockedOut=%t; lockout count cleared", how, resp.WasDisabled, resp.WasLockedOut))
	writeJSON(w, http.StatusOK, resp)
}

// recheckUnlockSelf is the admin unlock route's extra step when the
// account is the caller's own (owner, 2026-10-02): an admin whose
// sign-in is disabled may still hold a live session -- the disable stops
// new sign-ins, not sessions -- and may lift it from there, but only by
// entering their password and a current second factor again. The
// session alone is what a stolen cookie gives, and it must not be enough
// to undo a disable that a run of guesses at this very account brought
// on: the password and the code are the two things the cookie does not
// carry.
//
// The password is checked first (recheckPassword), then the code
// (recheckSecondFactor), each on the account's re-check budget: a wrong
// one is refused with 401 and counted there, and nothing is unlocked. A
// request missing either is 400 and checks nothing. Writes every
// refusal itself; the caller has already refused a body that does not
// decode.
//
// The one-time unlock code in the server's log (POST /api/auth/unlock)
// remains the way back for an admin with no session left.
func (g *Gate) recheckUnlockSelf(w http.ResponseWriter, r *http.Request, caller *gauntlet.User, req unlockSelfRequest, now time.Time) bool {
	if req.Password == "" || req.Code == "" {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "unlocking your own account needs your password and a code from your authenticator app or a recovery code", nil)
		return false
	}
	if _, ok := g.recheckPassword(w, r, caller, req.Password, "incorrect password or code", now); !ok {
		return false
	}
	return g.recheckSecondFactor(w, r, caller, req.Code, "incorrect password or code", now)
}
