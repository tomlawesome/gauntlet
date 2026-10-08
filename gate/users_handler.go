package gate

import (
	"encoding/json"
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
	// AdminPassword and AdminCode are the creating admin's own password
	// and a current second factor, entered again: required, and read,
	// only when Role is "admin" (#67). They are not Password, which is
	// the new account's.
	AdminPassword string `json:"adminPassword,omitempty"`
	AdminCode     string `json:"adminCode,omitempty"`
	// AdminAssertion is the creating admin's passkey, the alternative to
	// AdminCode (#82): the browser's answer to the options POST
	// /api/auth/step-up/passkey/begin gave.
	AdminAssertion json.RawMessage `json:"adminAssertion,omitempty"`
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
	// HeldForPasskey is true when the admin passkey rule is on (#82) and
	// this is an admin holding no passkey usable here: Protect holds it
	// at the passkey door (or, with no local password, the password door
	// first), so an admin sees who is stuck.
	HeldForPasskey bool `json:"heldForPasskey"`
}

// heldForPasskey reports whether u, read with its passkeys (Users.Get,
// not a List copy, which blanks them), is an admin the passkey door
// holds for want of a passkey usable here (#82).
func (g *Gate) heldForPasskey(u *gauntlet.User) bool {
	return g.adminPasskeyRuleOn() && u.Role == gauntlet.RoleAdmin && g.usablePasskeyCount(u) == 0
}

// heldForPasskeyByID is heldForPasskey for an account known by ID, read
// again with its passkeys. Only an admin is read, and only while the
// rule is on, so the users list costs nothing extra otherwise
// (gauntlet #42).
func (g *Gate) heldForPasskeyByID(id string, role gauntlet.Role) bool {
	if !g.adminPasskeyRuleOn() || role != gauntlet.RoleAdmin {
		return false
	}
	u, ok := g.deps.Users.Get(id)
	return ok && g.heldForPasskey(u)
}

// handleCreateUser lets an existing admin add another account -- the
// only way to create a user once self-registration has closed. Creating
// an admin (#67) also takes the caller's own password and a current
// second factor (adminPassword, and adminCode or adminAssertion), checked
// as a role grant is (recheckStepUp): a stolen session alone cannot make
// its holder permanent.
func (g *Gate) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}
	var role gauntlet.Role
	switch req.Role {
	case "", string(gauntlet.RoleUser):
		role = gauntlet.RoleUser
	case string(gauntlet.RoleViewer):
		role = gauntlet.RoleViewer
	case string(gauntlet.RoleAdmin):
		role = gauntlet.RoleAdmin
	default:
		g.writeAuthError(w, r, gauntlet.ErrInvalidRole, http.StatusBadRequest, classInvalidRequest)
		return
	}

	if g.refuseProductName(w, r, req.Password) {
		return
	}
	now := g.now()
	// The step-up is the last check before the write, after every
	// refusal that costs the caller nothing, so a recovery code is not
	// spent on a request that was always going to be refused. That
	// includes the new account's own username and password:
	// ValidateNewAccount makes CreateUser's checks of them up front.
	if role == gauntlet.RoleAdmin {
		caller := UserFromContext(r)
		if caller == nil {
			writeUnauthorized(w, classSignInRequired, "sign in first")
			return
		}
		if err := g.deps.Users.ValidateNewAccount(req.Username, req.Password); err != nil {
			g.writeCreateUserError(w, r, err)
			return
		}
		if !g.recheckStepUp(w, r, caller, req.AdminPassword, req.AdminCode, req.AdminAssertion, now,
			"creating an admin needs your own password and either a code from your authenticator app or a recovery code, or your passkey (adminPassword, adminCode or adminAssertion)") {
			return
		}
	}
	user, err := g.deps.Users.CreateUser(req.Username, req.Password, role, now)
	if err != nil {
		g.writeCreateUserError(w, r, err)
		return
	}
	detail := "role=" + string(user.Role)
	if user.Role == gauntlet.RoleAdmin {
		detail += "; granting admin's password and " + stepUpFactor(req.AdminAssertion) + " re-entered"
	}
	// A new account holds no passkey, so a new admin is held at the
	// passkey door from its first request while the rule is on (#82).
	held := g.heldForPasskey(user)
	if held {
		detail += "; held for a passkey"
	}
	g.audit(r, auditActor(r), "user.create", user.Username, detail)
	writeJSON(w, http.StatusCreated, map[string]any{"username": user.Username, "role": user.Role, "heldForPasskey": held})
	if user.Role == gauntlet.RoleAdmin {
		g.notify(r.Context(), &AccountNotice{
			Kind: NoticeRoleChanged, UserID: user.ID, Username: user.Username, Role: user.Role, At: now, By: auditActor(r),
			RoleChanged: &RoleChangeDetail{To: user.Role},
		})
	}
}

// writeCreateUserError answers an error from CreateUser, or from
// ValidateNewAccount ahead of it, with its status and class.
func (g *Gate) writeCreateUserError(w http.ResponseWriter, r *http.Request, err error) {
	status, class := http.StatusInternalServerError, classServerError
	switch err {
	case gauntlet.ErrUsernameTaken:
		status, class = http.StatusConflict, classConflict
	case gauntlet.ErrNotPersisted:
		status, class = http.StatusServiceUnavailable, classNotPersisted
	case gauntlet.ErrPasswordTooShort, gauntlet.ErrPasswordBlocked, gauntlet.ErrPasswordContext,
		gauntlet.ErrInvalidRole,
		gauntlet.ErrUsernameInvalid, gauntlet.ErrUsernameLength, gauntlet.ErrUsernameIsEmail:
		status, class = http.StatusBadRequest, classInvalidRequest
	}
	g.writeAuthError(w, r, err, status, class)
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
			HeldForPasskey:   g.heldForPasskeyByID(u.ID, u.Role),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDeleteUser removes an account and everything it can still be
// used with: a live session cookie and a bearer token neither re-check
// that the account still exists on every request, so both would outlive
// the deletion if not revoked here.
//
// The last admin cannot be deleted (409 last-admin, #67), nor can the
// caller's own account while other admins exist (409 conflict). The
// caller's own password is asked for again on the request (#72, ASVS
// 7.5.3), after those two refusals and before anything is deleted.
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
	var req adminStepUpRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "user id is required", nil)
		return
	}

	// Nobody deletes the account they are signed in with. For the last
	// admin the store's own refusal, with its own class, is the better
	// answer, so that case is left to it.
	if caller := UserFromContext(r); caller != nil && caller.ID == id && len(g.deps.Users.Admins()) > 1 {
		writeProblem(w, http.StatusConflict, classConflict, "an administrator cannot delete their own account -- ask another admin to", nil)
		return
	}

	if !g.recheckAdminPassword(w, r, req.Password, g.now()) {
		return
	}

	user, err := g.deps.Users.DeleteUser(id)
	if err != nil {
		status, class := http.StatusInternalServerError, classServerError
		switch {
		case errors.Is(err, gauntlet.ErrUserNotFound):
			status, class = http.StatusNotFound, classNotFound
		case errors.Is(err, gauntlet.ErrLastAdmin):
			status, class = http.StatusConflict, classLastAdmin
		case errors.Is(err, gauntlet.ErrLastLocalAdmin):
			writeLastLocalAdmin(w)
			return
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
//     one. Another admin's account is not excluded since #67: a second
//     admin is how a locked-out admin gets back in.
//   - an SSO-only account. Its identity provider owns the credential --
//     see gauntlet.ErrNoLocalPassword.
//
// The account's live sessions go with the reset, twice over: the store
// bumps SessionsEndedAt (which ends them across processes and
// restarts) and this drops the ones in memory immediately, the same
// pattern handleDeleteUser and handleChangePassword use.
//
// The caller's own password is asked for again on the request (#72,
// ASVS 7.5.3): the code this route returns is a way into any other
// account, and a stolen session cookie must not be enough to get one.
func (g *Gate) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var req adminStepUpRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}
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
	if !g.recheckAdminPassword(w, r, req.Password, now) {
		return
	}
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

	by := auditActor(r)
	writeJSON(w, http.StatusOK, resetPasswordResponse{
		Username:  user.Username,
		Code:      code,
		ExpiresAt: user.ResetCodeExpiresAt,
	})
	g.notify(r.Context(), &AccountNotice{
		Kind: NoticePasswordReset, UserID: user.ID, Username: user.Username, Role: user.Role, At: now, By: by,
		PasswordReset: &PasswordResetDetail{ExpiresAt: user.ResetCodeExpiresAt},
	})
}

// unlockUserResponse is the admin unlock route's answer: what the
// account's record held before the unlock, for the admin's own
// confirmation. Both false is the idempotent case -- there was nothing
// to lift, and still 200.
type unlockUserResponse struct {
	Username string `json:"username"`
	// WasDisabled is true when the account's sign-in was disabled, and
	// had not yet lifted itself (gauntlet.LoginDisableDuration), after
	// gauntlet.MaxConsecutiveLoginFailures failures in a row.
	WasDisabled bool `json:"wasDisabled"`
	// WasLockedOut is true when a login lockout was in force.
	WasLockedOut bool `json:"wasLockedOut"`
}

// unlockSelfRequest is the body of the admin unlock route when the
// account is the caller's own: the password and a current second factor
// -- a TOTP code or a recovery code, or since #82 a passkey -- entered
// again (owner, 2026-10-02). Another account's unlock takes no body.
type unlockSelfRequest struct {
	Password string `json:"password"`
	Code     string `json:"code,omitempty"`
	// Assertion is a passkey, the alternative to Code (#82).
	Assertion json.RawMessage `json:"assertion,omitempty"`
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
	var selfAssertion json.RawMessage
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
		selfAssertion = req.Assertion
	}

	target, ok := g.deps.Users.Get(id)
	if !ok {
		writeProblem(w, http.StatusNotFound, classNotFound, "no such user", nil)
		return
	}
	resp := unlockUserResponse{
		Username:     target.Username,
		WasDisabled:  target.LoginDisabled(now),
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
		how = "own sign-in unlocked by admin, password and " + stepUpFactor(selfAssertion) + " re-entered"
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
// (recheckSecondFactor) or the passkey (recheckPasskey), each on the
// account's re-check budget: a wrong one is refused with 401 and counted
// there, and nothing is unlocked. A request missing the password, or
// carrying neither or both of code and assertion, is 400 and checks
// nothing. Writes every refusal itself; the caller has already refused a
// body that does not decode.
//
// The one-time unlock code in the server's log (POST /api/auth/unlock)
// remains the way back for an admin with no session left.
func (g *Gate) recheckUnlockSelf(w http.ResponseWriter, r *http.Request, caller *gauntlet.User, req unlockSelfRequest, now time.Time) bool {
	return g.recheckStepUp(w, r, caller, req.Password, req.Code, req.Assertion, now,
		"unlocking your own account needs your password and either a code from your authenticator app or a recovery code, or your passkey (password, code or assertion)")
}

// writeLastLocalAdmin is the 409 last-admin answer to
// gauntlet.ErrLastLocalAdmin: the change would leave every admin
// signing in only through the identity provider. Written here rather
// than through writeAuthError, whose table of messages does not carry
// it.
func writeLastLocalAdmin(w http.ResponseWriter) {
	writeProblem(w, http.StatusConflict, classLastAdmin,
		"this is the last admin that can sign in without the identity provider -- give another admin a local password first", nil)
}

// recheckStepUp is the step-up shared by every admin route that needs the
// caller's password and a current second factor on the request itself
// (#67; ASVS 7.5.3): the unlock of the caller's own account above,
// granting the admin role and creating an admin. The second factor is
// either code (a TOTP or recovery code) or, since #82, assertion (a
// passkey, from POST /api/auth/step-up/passkey/begin): exactly one of the
// two. missing is the 400's detail when the password is empty or the
// request carries neither or both, which checks nothing. Otherwise the
// password is checked first, then the code or the passkey, each on the
// account's re-check budget (recheckPassword, recheckSecondFactor,
// recheckPasskey), a wrong one 401 with one message for all so a caller
// learns nothing about which was wrong. A caller with no local password
// is 409 before any of that (refuseWithoutLocalPassword). Writes every
// refusal itself.
func (g *Gate) recheckStepUp(w http.ResponseWriter, r *http.Request, caller *gauntlet.User, password, code string, assertion json.RawMessage, now time.Time, missing string) bool {
	if refuseWithoutLocalPassword(w, caller) {
		return false
	}
	if password == "" || (code == "") == (len(assertion) == 0) {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, missing, nil)
		return false
	}
	if _, ok := g.recheckPassword(w, r, caller, password, "incorrect password or code", now); !ok {
		return false
	}
	if len(assertion) > 0 {
		return g.recheckPasskey(w, r, caller, assertion, "incorrect password or code", now)
	}
	return g.recheckSecondFactor(w, r, caller, code, "incorrect password or code", now)
}

// stepUpFactor names, for an audit detail, the second factor a step-up
// that passed was given: a passkey when assertion is set, a code
// otherwise.
func stepUpFactor(assertion json.RawMessage) string {
	if len(assertion) > 0 {
		return "passkey"
	}
	return "second factor"
}

// setRoleRequest is the body of PUT /api/auth/users/{id}/role. Password
// and Code or Assertion are the caller's own, as in unlockSelfRequest,
// and are read only when Role is "admin".
type setRoleRequest struct {
	Role     string `json:"role"`
	Password string `json:"password,omitempty"`
	Code     string `json:"code,omitempty"`
	// Assertion is a passkey, the alternative to Code (#82).
	Assertion json.RawMessage `json:"assertion,omitempty"`
}

// setRoleResponse is what the role route answers: the account and the
// role it held and holds now.
type setRoleResponse struct {
	Username string `json:"username"`
	From     string `json:"from"`
	To       string `json:"to"`
	// SessionsEnded is true when the change was a downgrade, which ends
	// every session the account held.
	SessionsEnded bool `json:"sessionsEnded"`
	// HeldForPasskey is true when the account is now an admin holding no
	// passkey usable here while the admin passkey rule is on (#82): the
	// role is granted, and Protect holds the account at the passkey door
	// from its next request until it registers one.
	HeldForPasskey bool `json:"heldForPasskey"`
}

// roleManagedBySSO reports whether the identity provider's groups decide
// u's role: u is linked to SSO, this deployment maps groups to roles, and
// u is not an admin (the map never touches one). Computed, not stored, so
// it follows the configuration and an admin's grant or demotion.
func (g *Gate) roleManagedBySSO(u *gauntlet.User) bool {
	return u.OIDCIssuer != "" && len(g.deps.OIDCPolicy.RoleFromGroups) > 0 && u.Role != gauntlet.RoleAdmin
}

// handleSetRole is the one route for every role change among admin,
// user and viewer (#67, #75). Granting admin takes the caller's own
// password and a current second factor (recheckStepUp); any other
// change takes none. An SSO account whose role the identity provider's
// groups decide cannot be set to user or viewer (409
// role-managed-by-sso, #76). The last admin cannot be demoted (409
// last-admin);
// an account already holding the role is 409 conflict. A downgrade ends
// the account's sessions: the store records SessionsEndedAt, which ends
// them across processes, and this drops the ones held in memory at
// once. Audited as user.role_changed with actor, from and to, and the
// application is told through Config.Notices (NoticeRoleChanged).
func (g *Gate) handleSetRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "user id is required", nil)
		return
	}
	caller := UserFromContext(r)
	if caller == nil {
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
	}
	var req setRoleRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}
	role := gauntlet.Role(req.Role)
	if role != gauntlet.RoleAdmin && role != gauntlet.RoleUser && role != gauntlet.RoleViewer {
		g.writeAuthError(w, r, gauntlet.ErrInvalidRole, http.StatusBadRequest, classInvalidRequest)
		return
	}
	target, ok := g.deps.Users.Get(id)
	if !ok {
		writeProblem(w, http.StatusNotFound, classNotFound, "no such user", nil)
		return
	}
	// Refused before the step-up, so a recovery code is not spent on a
	// request that changes nothing.
	if target.Role == role {
		g.writeAuthError(w, r, gauntlet.ErrRoleUnchanged, http.StatusConflict, classConflict)
		return
	}
	// An SSO account whose role the groups decide is not changed here to
	// user or viewer: the identity provider would overwrite it at the
	// next sign-in, so the change would be a promise nobody keeps
	// (ADR-0013 decision 2). Granting admin is not refused -- the map
	// never touches an admin -- and neither is demoting one. Before the
	// step-up for the same reason as the check above.
	if role != gauntlet.RoleAdmin && g.roleManagedBySSO(target) {
		writeProblem(w, http.StatusConflict, classRoleManagedBySSO,
			"this account's role comes from its groups at the identity provider; change the group there", nil)
		return
	}
	now := g.now()
	if role == gauntlet.RoleAdmin &&
		!g.recheckStepUp(w, r, caller, req.Password, req.Code, req.Assertion, now,
			"granting the admin role needs your own password and either a code from your authenticator app or a recovery code, or your passkey (password, code or assertion)") {
		return
	}

	changed, from, err := g.deps.Users.SetRole(id, role, now)
	if err != nil {
		status, class := http.StatusInternalServerError, classServerError
		switch {
		case errors.Is(err, gauntlet.ErrUserNotFound):
			status, class = http.StatusNotFound, classNotFound // deleted since the read above
		case errors.Is(err, gauntlet.ErrLastAdmin):
			status, class = http.StatusConflict, classLastAdmin
		case errors.Is(err, gauntlet.ErrLastLocalAdmin):
			writeLastLocalAdmin(w)
			return
		case errors.Is(err, gauntlet.ErrRoleUnchanged):
			status, class = http.StatusConflict, classConflict
		case errors.Is(err, gauntlet.ErrNotPersisted):
			status, class = http.StatusServiceUnavailable, classNotPersisted
		}
		g.writeAuthError(w, r, err, status, class)
		return
	}

	// from != to here (ErrRoleUnchanged otherwise), so "from is at least
	// to" is exactly a downgrade.
	ended := from.AtLeast(changed.Role)
	if ended {
		g.deps.Sessions.RevokeAllForUser(changed.ID)
	}
	by := auditActor(r)
	detail := fmt.Sprintf("from=%s to=%s", from, changed.Role)
	if role == gauntlet.RoleAdmin {
		detail += "; granting admin's password and " + stepUpFactor(req.Assertion) + " re-entered"
	}
	if ended {
		detail += "; sessions ended: all"
	}
	// SetRole's copy has its passkeys blanked, so the account is read
	// again to tell a usable passkey from a stale one.
	held := g.heldForPasskeyByID(changed.ID, changed.Role)
	if held {
		detail += "; held for a passkey"
	}
	g.audit(r, by, "user.role_changed", changed.Username, detail)
	writeJSON(w, http.StatusOK, setRoleResponse{
		Username: changed.Username, From: string(from), To: string(changed.Role), SessionsEnded: ended,
		HeldForPasskey: held,
	})
	g.notify(r.Context(), &AccountNotice{
		Kind: NoticeRoleChanged, UserID: changed.ID, Username: changed.Username, Role: changed.Role, At: now, By: by,
		RoleChanged: &RoleChangeDetail{From: from, To: changed.Role},
	})
}
