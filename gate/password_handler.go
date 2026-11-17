package gate

import (
	"fmt"
	"net/http"
	"time"

	"github.com/tomlawesome/gauntlet"
)

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// firstLocalPasswordWindow is how recent the caller's single sign-on
// must be for an SSO-only admin to set its first local password (see
// handleChangePassword).
const firstLocalPasswordWindow = 10 * time.Minute

// handleChangePassword lets a signed-in caller change their own
// password (mikroview's #294 item 4).
func (g *Gate) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	now := g.now()
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
	}

	var req changePasswordRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}

	// An SSO-only account has no local password to change, and inventing
	// one here would quietly create a second way into an account whose
	// owner believes it is federated.
	//
	// An admin is the exception: every admin keeps a local way in, so
	// the deployment is not locked out when the identity provider is
	// down (ADR-0010). An SSO-only account promoted to admin sets its
	// first password here, with no current one to check because there
	// is none. Once it has a password the forced second-factor enrolment
	// door (Protect) applies to it like any other local account.
	firstLocalPassword := !user.LocalPassword() && user.Role == gauntlet.RoleAdmin
	if !user.LocalPassword() && !firstLocalPassword {
		writeProblem(w, http.StatusConflict, classConflict, "this account signs in through your identity provider and has no local password to change", nil)
		return
	}
	// With no current password to ask for, the session cookie alone
	// would be enough -- and the cookie is exactly what a thief has,
	// who could then give the account a permanent password and second
	// factor of their own. A fresh sign-in through the identity provider
	// is the one proof this account can give, so the session must have
	// come from one, within firstLocalPasswordWindow.
	if firstLocalPassword {
		sess, ok := g.callerSession(r, user.ID, now)
		if !ok || sess.Client.Method != gauntlet.SignInMethodSSO || now.Sub(sess.IssuedAt) > firstLocalPasswordWindow {
			writeProblem(w, http.StatusConflict, classConflict, "sign in again through your identity provider, then set the password within ten minutes", nil)
			return
		}
	}

	// After an admin reset there is no current password to supply -- see
	// mikroview's own handleAuthChangePassword for the full reasoning.
	// An admin reset (POST /api/auth/users/{id}/reset-password, which
	// calls IssueResetCode) sets MustChangePassword, and so does a run of
	// failed second-factor steps (gauntlet.LoginLimiter.SecondFactorFailed,
	// #44). Skipping the check is safe for both: each ends every session
	// in the same write that sets the flag, so the caller got here
	// through a sign-in made since -- with the reset code, or with the
	// password and a second factor.
	if !user.MustChangePassword && !firstLocalPassword {
		// Throttled and re-checked by recheckPassword.
		if _, ok := g.recheckPassword(w, r, user, req.CurrentPassword, "current password is incorrect", now); !ok {
			return
		}

		if req.NewPassword == req.CurrentPassword {
			writeProblem(w, http.StatusBadRequest, classInvalidRequest, "the new password is the same as the current one", nil)
			return
		}
	} else if user.MustChangePassword && g.deps.Users.PasswordMatches(user.ID, req.NewPassword) {
		// No current password was asked for, so there is none to compare
		// with above; the stored hash answers instead. After a run of
		// failed second-factor steps, or a sign-in that found the
		// password in a breach, the password is presumed known to
		// someone else, and setting it again would lift the flag while
		// changing nothing. After an admin reset the stored hash is
		// unmatchable, and the reset code the caller signed in with is
		// what PasswordMatches refuses instead.
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "the new password is the same as the current one", nil)
		return
	}
	if g.refuseProductName(w, r, req.NewPassword) {
		return
	}
	if err := g.deps.Users.SetPassword(user.Username, req.NewPassword, now); err != nil {
		switch err {
		case gauntlet.ErrPasswordTooShort:
			writeProblem(w, http.StatusBadRequest, classInvalidRequest, err.Error(), nil)
			return
		case gauntlet.ErrPasswordBlocked, gauntlet.ErrPasswordContext:
			g.writeAuthError(w, r, err, http.StatusBadRequest, classInvalidRequest)
			return
		case gauntlet.ErrResetDuringChange:
			// An admin reset landed while this change was being
			// checked: the reset stands, this session is already
			// ended by it, and the owner signs in with its code.
			g.writeAuthError(w, r, err, http.StatusConflict, classConflict)
			return
		}
		// The 500 tells the caller nothing by design; the log is the
		// only place an operator can find out why.
		g.logError("changing the password for " + user.Username + ": " + err.Error())
		writeProblem(w, http.StatusInternalServerError, classServerError, "could not change the password", nil)
		return
	}

	// Every session issued before now is dead by SessionCutoff, but
	// that is only enforced on the next request each one makes -- dropped
	// here so they are gone immediately.
	method := g.sessionMethod(r, user.ID, now)
	g.deps.Sessions.RevokeAllForUser(user.ID)

	detail := "sessions ended: all"
	if user.MustChangePassword {
		detail += ", forced (an administrator's reset or repeated second-factor failures)"
	}
	g.audit(r, user.Username, "account.password_changed", user.Username, detail)

	g.issueSession(w, r, user.ID, method, now)
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
func (g *Gate) recheckPassword(w http.ResponseWriter, r *http.Request, user *gauntlet.User, password, wrongMsg string, now time.Time) (*gauntlet.User, bool) {
	if !g.deps.Limiter.ReserveRecheck(user.ID, now) {
		g.recheckRefused(r, user)
		writeProblem(w, http.StatusTooManyRequests, classRateLimited, "too many attempts, try again later", nil)
		return nil, false
	}
	current, err := g.deps.Users.Authenticate(user.Username, password, now)
	if err != nil {
		g.recheckFailed(r, user, gauntlet.SignInWrongPassword, gauntlet.SignInMethodPassword)
		writeUnauthorized(w, classInvalidCredentials, wrongMsg)
		return nil, false
	}
	g.deps.Limiter.ReleaseRecheck(user.ID, now)
	return current, true
}

// adminStepUpRequest is the body of an admin route that takes nothing
// but the caller's own password (#72, ASVS 7.5.3): reset-password,
// delete user, and clearing a user's authenticator app or passkeys.
type adminStepUpRequest struct {
	Password string `json:"password"`
}

// recheckAdminPassword is recheckPassword for the admin routes that
// take over, remove or hand out access to an account (#72): the
// caller's own password, entered again on the request itself, so a
// stolen session cookie alone cannot do any of them. A missing password
// is a wrong one -- 401 and counted on the same re-check budget -- not a
// separate 400, as on every other re-check route. A caller with no
// local password is 409 instead (refuseWithoutLocalPassword). Call it
// after the request has been checked for being well formed and before
// it reads or changes any account. Writes every refusal itself.
func (g *Gate) recheckAdminPassword(w http.ResponseWriter, r *http.Request, password string, now time.Time) bool {
	caller := UserFromContext(r)
	if caller == nil {
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return false
	}
	if refuseWithoutLocalPassword(w, caller) {
		return false
	}
	_, ok := g.recheckPassword(w, r, caller, password, "incorrect password", now)
	return ok
}

// refuseWithoutLocalPassword writes a 409, and reports true, when caller
// has no local password to re-check: an SSO-only account promoted to
// admin. Its password could never match, so a 401 would send it round
// a loop that only spends its re-check budget; the 409 says what to do
// instead -- set a local password first, as every admin must
// (ADR-0010). The budget is left untouched.
func refuseWithoutLocalPassword(w http.ResponseWriter, caller *gauntlet.User) bool {
	if caller.LocalPassword() {
		return false
	}
	writeProblem(w, http.StatusConflict, classConflict,
		"this account signs in through your identity provider and must set a local password first (POST /api/auth/password) before it can do this", nil)
	return true
}

// recheckSecondFactor is recheckPassword for a signed-in caller's
// second factor: code is a current TOTP code or one of the account's
// recovery codes, checked the way the login factor step checks them
// (handleLoginFactor) -- VerifyAndRecordTOTP first, so the code cannot
// be replayed, then BurnRecoveryCode, which spends a recovery code that
// matches. A passkey has no code to type, so an account holding only
// passkeys answers with a recovery code.
//
// Throttled on the same per-account re-check budget as recheckPassword,
// reserve-then-release: a wrong code keeps its reservation and counts
// as a failed re-check, a right one hands it back. A code that could not
// be recorded is the backend failing, not a wrong guess, and hands it
// back too, as the login factor step does. Call it only after
// recheckPassword has passed, so a recovery code is never spent on a
// request whose password was wrong.
//
// Writes the 429, 500 or the 401 carrying wrongMsg itself.
func (g *Gate) recheckSecondFactor(w http.ResponseWriter, r *http.Request, user *gauntlet.User, code, wrongMsg string, now time.Time) bool {
	if !g.deps.Limiter.ReserveRecheck(user.ID, now) {
		g.recheckRefused(r, user)
		writeProblem(w, http.StatusTooManyRequests, classRateLimited, "too many attempts, try again later", nil)
		return false
	}
	matched, err := g.deps.Users.VerifyAndRecordTOTP(user.ID, code, now)
	if err == nil && !matched {
		matched, err = g.deps.Users.BurnRecoveryCode(user.ID, code, now)
	}
	if err != nil {
		g.deps.Limiter.ReleaseRecheck(user.ID, now)
		g.logError("re-checking the second factor of " + user.Username + ": " + err.Error())
		writeProblem(w, http.StatusInternalServerError, classServerError, "unable to check the code", nil)
		return false
	}
	if !matched {
		g.recheckFailed(r, user, gauntlet.SignInFactorRefused, gauntlet.SignInMethodCode)
		writeUnauthorized(w, classInvalidCredentials, wrongMsg)
		return false
	}
	g.deps.Limiter.ReleaseRecheck(user.ID, now)
	return true
}

// recheckFailed records a wrong password or code at an in-session
// re-check (#45, ASVS 16.3.1): user.login_failed, as a failed sign-in
// is, marked step=recheck. Not a row of the sign-in history: the caller
// already holds a session, and the history is of sign-ins.
func (g *Gate) recheckFailed(r *http.Request, user *gauntlet.User, outcome gauntlet.SignInOutcome, method gauntlet.SignInMethod) {
	g.auditRecord(user.Username, "user.login_failed", user.Username,
		fmt.Sprintf("outcome=%s method=%s step=recheck from=%q", outcome, method, g.cfg.ClientIP(r)))
}

// recheckRefused is the rated Warn line for a re-check the limiter
// refused, as a refused sign-in leaves one.
func (g *Gate) recheckRefused(r *http.Request, user *gauntlet.User) {
	g.warnRefused(r, "recheck-refused", fmt.Sprintf("gate: re-check refused by the limiter: account=%q", user.Username))
}

// refuseProductName writes ErrPasswordContext's 400, and reports true,
// for a new password that is Config.ProductName or a simple derivative
// of it (gauntlet.PasswordMatchesContext, #43). The store checks the
// account's own username and gauntlet.Options.ProductName itself; an
// application that left that empty still has the name refused here. Every
// route that sets a password calls it before the store.
func (g *Gate) refuseProductName(w http.ResponseWriter, r *http.Request, password string) bool {
	if !gauntlet.PasswordMatchesContext(password, g.cfg.ProductName) {
		return false
	}
	g.writeAuthError(w, r, gauntlet.ErrPasswordContext, http.StatusBadRequest, classInvalidRequest)
	return true
}
