package gate

import (
	"errors"
	"net/http"

	"github.com/tomlawesome/gauntlet"
)

// -- Authenticator-app second factor (docs/design.md §1.6) -------------
//
// Four routes: enrol and confirm start and finish setting one up (an
// account's first second factor is then held until POST
// /api/auth/recovery-codes/confirm, recoverycodes_handler.go, #58), DELETE
// is the account owner turning it off with their password, and the
// admin route at the end is the Users-group path for a lost phone when
// the password still works. The fifth route this feature needs, POST
// /api/auth/login/factor, lives in login_handler.go since it is a
// login-flow endpoint first and a TOTP endpoint second.
//
// Every handler here re-reads the account from g.deps.Users rather than
// trusting UserFromContext's copy for anything beyond "who is calling"
// -- TOTPSecret, TOTPConfirmedAt and TOTPLastCounter are written by a
// *different* request than the one that reads them (enrol writes what
// confirm reads), so a copy resolved at the top of this request's
// session check is never new enough to check a code against.

type totpEnrolResponse struct {
	// URI is the otpauth:// URI the frontend renders as a QR code.
	URI string `json:"uri"`
	// Secret is the same value URI carries, base32, for typing in by
	// hand -- not every authenticator app's camera flow is reliable, so
	// the text secret is always shown beside the code.
	Secret string `json:"secret"`
}

// handleTOTPEnrol starts authenticator-app enrolment for the signed-in
// caller's own account: a fresh secret is generated and stored pending,
// not active until handleTOTPConfirm proves a code was produced from it
// (see gauntlet.Store.SetPendingTOTPSecretAt), within
// gauntlet.TOTPPendingLifetime of now (#58). Enrolling again before
// confirming simply replaces the pending secret -- that store method's
// own behaviour -- so this handler doesn't need to notice that case
// specially. Refused 409 while a first factor is on hold for its
// recovery codes to be confirmed (#58): one enrolment at a time.
func (g *Gate) handleTOTPEnrol(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
	}
	// SSO accounts are never offered a local factor: their identity
	// provider owns identity. Checked on LocalPassword(), not on whether
	// an SSO identity is linked -- the admin keeps its password even
	// once linked, and is still offered one; it's an account with *no*
	// local password (provisioned or converted to SSO-only) that has
	// nothing here to gate a factor behind.
	if !user.LocalPassword() {
		writeProblem(w, http.StatusConflict, classConflict, "this account signs in through your identity provider -- an authenticator app is not offered", nil)
		return
	}

	var req totpEnrolRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}

	// Password-gated (recheckPassword): planting a factor the account's
	// owner never sees locks them out at their next login.
	now := g.now()
	if _, ok := g.recheckPassword(w, r, user, req.Password, "incorrect password", now); !ok {
		return
	}

	secret, err := gauntlet.GenerateTOTPSecret()
	if err != nil {
		g.logError("generating TOTP secret for " + user.Username + ": " + err.Error())
		writeProblem(w, http.StatusInternalServerError, classServerError, "unable to start enrolment", nil)
		return
	}
	encoded := gauntlet.EncodeTOTPSecret(secret)
	if err := g.deps.Users.SetPendingTOTPSecretAt(user.ID, encoded, now); err != nil {
		status, class := http.StatusInternalServerError, classServerError
		if errors.Is(err, gauntlet.ErrTOTPAlreadyActive) || errors.Is(err, gauntlet.ErrEnrolmentHeld) {
			status, class = http.StatusConflict, classConflict
		}
		g.writeAuthError(w, r, err, status, class)
		return
	}

	writeJSON(w, http.StatusOK, totpEnrolResponse{
		URI:    gauntlet.TOTPEnrollmentURI(g.cfg.ProductName, user.Username, secret),
		Secret: encoded,
	})
}

type totpConfirmRequest struct {
	Code string `json:"code"`
}

type totpConfirmResponse struct {
	// Enabled is true when the app is live: confirmed on an account that
	// already had a second factor. False while PendingConfirmation is
	// true.
	Enabled bool `json:"enabled"`
	// RecoveryCodes is the only place the ten codes ever exist in clear
	// outside a person's own saved copy, sent when this app is the
	// account's first second factor. Nothing on this account can show
	// them again; losing this response before saving it means waiting
	// for the hold to expire and enrolling again.
	//
	// nil (JSON null) when AlreadyIssued is true: an account keeps one
	// set of recovery codes across all its factors.
	RecoveryCodes []string `json:"recoveryCodes"`
	// PendingConfirmation is true when the app and RecoveryCodes are on
	// hold (#58): neither is live until POST
	// /api/auth/recovery-codes/confirm, and both are deleted if that
	// does not come within gauntlet.HeldEnrolmentLifetime.
	PendingConfirmation bool `json:"pendingConfirmation,omitempty"`
	// AlreadyIssued is true when the app went live on an account that
	// already had a second factor, whose recovery codes stand.
	AlreadyIssued bool `json:"alreadyIssued,omitempty"`
}

// handleTOTPConfirm checks one code against the pending secret
// handleTOTPEnrol stored.
//
// On the account's first second factor (#58) the app and ten new
// recovery codes are saved together, in one write, on hold
// (gauntlet.Store.HoldFirstTOTP), and the codes are answered once:
// nothing goes live, no session is rotated and nothing is audited until
// the caller confirms the codes were saved (handleEnrolmentConfirm,
// which does all three).
//
// On an account that already has a second factor (a passkey) the app is
// confirmed live at once, with no codes, and confirming ends every other
// session on the account: turning on a second factor is exactly the
// moment a stale or forgotten session elsewhere should not get to ride
// along unchallenged without ever having to prove it. Same shape as
// handleChangePassword -- RevokeAllForUser, then reissue this browser
// its own fresh session -- since SessionStore.RevokeAllForUser has no
// notion of "except the caller".
//
// A pending secret set more than gauntlet.TOTPPendingLifetime ago is
// refused 401 step-expired: scan a new code.
func (g *Gate) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
	}

	var req totpConfirmRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}

	now := g.now()
	// Re-read rather than trust UserFromContext's copy -- see this
	// file's header comment. The pending secret being checked here only
	// exists because of a *previous* request (handleTOTPEnrol); this one
	// has to see that write.
	current, ok := g.deps.Users.Get(user.ID)
	if !ok {
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
	}

	// An app already held for its codes to be confirmed is not confirmed
	// again here, and neither is one beside a held passkey.
	if current.EnrolmentHeld(now) {
		g.writeAuthError(w, r, gauntlet.ErrEnrolmentHeld, http.StatusConflict, classConflict)
		return
	}
	// Same "nothing pending" test ConfirmTOTP makes, asked first: with no
	// secret to check against, VerifyTOTP would fail every code and the
	// caller would be told to check their clock instead of the 409.
	if current.TOTPSecret == "" || !current.TOTPConfirmedAt.IsZero() {
		g.writeAuthError(w, r, gauntlet.ErrNoPendingTOTP, http.StatusConflict, classConflict)
		return
	}
	if !current.TOTPPending(now) {
		writeUnauthorized(w, classStepExpired, "this authenticator app setup has expired -- start again and scan the new code")
		return
	}

	// Throttled on the per-account re-check bucket, reserve-then-release
	// as recheckPassword does: this route asks only for the session
	// cookie, so without it a stolen cookie could guess the six digits
	// without limit while the owner's enrolment is pending -- and a hit
	// plants a factor and hands over the recovery codes.
	if !g.deps.Limiter.ReserveRecheck(user.ID, now) {
		writeProblem(w, http.StatusTooManyRequests, classRateLimited, "too many attempts, try again later", nil)
		return
	}
	matched, ok := gauntlet.VerifyTOTP(current.TOTPSecret, req.Code, now, current.TOTPLastCounter)
	if !ok {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "that code didn't match -- check your authenticator app's clock and try again", nil)
		return
	}
	g.deps.Limiter.ReleaseRecheck(user.ID, now)

	if !current.HasSecondFactor() {
		// The first factor: held with its codes, in one write. The store
		// decides again under its lock; one that lost to a passkey going
		// live in between is confirmed live below instead.
		codes, err := g.deps.Users.HoldFirstTOTP(user.ID, current.TOTPSecret, matched, now)
		if err == nil {
			writeJSON(w, http.StatusOK, totpConfirmResponse{RecoveryCodes: codes, PendingConfirmation: true})
			return
		}
		if !errors.Is(err, gauntlet.ErrSecondFactorExists) {
			g.writeTOTPConfirmError(w, r, err)
			return
		}
	}

	if err := g.deps.Users.ConfirmTOTP(user.ID, now, matched); err != nil {
		g.writeTOTPConfirmError(w, r, err)
		return
	}

	// The factor is committed from here on, so every other session ends.
	g.deps.Sessions.RevokeAllForUser(user.ID)
	g.issueSession(w, r, user.ID, now)

	g.audit(r, user.Username, "account.totp_enabled", user.Username, "authenticator app confirmed; existing recovery codes unchanged")

	writeJSON(w, http.StatusOK, totpConfirmResponse{Enabled: true, RecoveryCodes: nil, AlreadyIssued: true})
	g.notify(r.Context(), &AccountNotice{
		Kind: NoticeSecondFactorAdded, UserID: user.ID, Username: user.Username, Role: user.Role, At: now,
		SecondFactor: &SecondFactorDetail{Method: "totp"},
	})
}

// writeTOTPConfirmError answers a refused confirmation: 409 when there
// is nothing pending any more or another enrolment is on hold, 500
// otherwise.
func (g *Gate) writeTOTPConfirmError(w http.ResponseWriter, r *http.Request, err error) {
	status, class := http.StatusInternalServerError, classServerError
	if errors.Is(err, gauntlet.ErrNoPendingTOTP) || errors.Is(err, gauntlet.ErrEnrolmentHeld) {
		status, class = http.StatusConflict, classConflict
	}
	g.writeAuthError(w, r, err, status, class)
}

type totpDeleteRequest struct {
	Password string `json:"password"`
}

type totpEnrolRequest struct {
	Password string `json:"password"`
}

// handleTOTPDelete turns off the signed-in caller's own authenticator-
// app factor, gated by their password -- the one self-service way to
// remove it; the admin route at the end of this file is the only other
// path, for when the password is what's lost instead.
func (g *Gate) handleTOTPDelete(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
	}

	var req totpDeleteRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}

	now := g.now()
	// Password-gated and throttled by recheckPassword.
	if _, ok := g.recheckPassword(w, r, user, req.Password, "incorrect password", now); !ok {
		return
	}

	if err := g.deps.Users.ClearTOTP(user.ID); err != nil {
		g.writeAuthError(w, r, err, http.StatusInternalServerError, classServerError)
		return
	}

	// An account may remove its only second factor. When doing so leaves
	// the account with none, every session on it -- this one included --
	// is revoked at once, so the very next request goes through
	// Protect's forced-enrolment door instead of riding an existing
	// cookie past a requirement the account no longer satisfies.
	// signedOut tells the caller that happened.
	signedOut := false
	if updated, ok := g.deps.Users.Get(user.ID); ok && !updated.HasSecondFactor() {
		g.deps.Sessions.RevokeAllForUser(user.ID)
		signedOut = true
	}

	g.audit(r, user.Username, "account.totp_disabled", user.Username, "removed by account owner")
	writeJSON(w, http.StatusOK, map[string]any{"disabled": true, "signedOut": signedOut})
	g.notify(r.Context(), &AccountNotice{
		Kind: NoticeSecondFactorRemoved, UserID: user.ID, Username: user.Username, Role: user.Role, At: now,
		SecondFactor: &SecondFactorDetail{Method: "totp"},
	})
}

// handleTOTPAdminClear lets an admin remove another user's authenticator-
// app factor from the Users group -- the path for a lost phone when the
// account owner still has their password.
//
// Never on the caller's own account: an admin locked out of their own
// factor has no console-based recovery tool in this module (docs/
// design.md §1.7 -- the recovery-key CLI stays mikroview's own), so
// self-clearing here would need its own separate justification this
// route was never meant to provide.
func (g *Gate) handleTOTPAdminClear(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "user id is required", nil)
		return
	}
	if caller := UserFromContext(r); caller != nil && caller.ID == id {
		writeProblem(w, http.StatusConflict, classConflict, "an administrator cannot clear their own authenticator app here", nil)
		return
	}

	target, ok := g.deps.Users.Get(id)
	if !ok {
		writeProblem(w, http.StatusNotFound, classNotFound, "no such user", nil)
		return
	}
	if err := g.deps.Users.ClearTOTP(id); err != nil {
		g.writeAuthError(w, r, err, http.StatusInternalServerError, classServerError)
		return
	}

	by := auditActor(r)
	g.audit(r, by, "user.totp_cleared", target.Username, "authenticator app removed by admin")
	writeJSON(w, http.StatusOK, map[string]any{"username": target.Username, "cleared": true})
	g.notify(r.Context(), &AccountNotice{
		Kind: NoticeSecondFactorRemoved, UserID: target.ID, Username: target.Username, Role: target.Role, At: g.now(), By: by,
		SecondFactor: &SecondFactorDetail{Method: "totp", All: true},
	})
}
