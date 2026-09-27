package gate

import (
	"net/http"

	"github.com/tomlawesome/gauntlet"
)

// -- Authenticator-app second factor (docs/design.md §1.6) -------------
//
// Four routes: enrol and confirm start and finish setting one up, DELETE
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
// (see gauntlet.Store.SetPendingTOTPSecret). Enrolling again before
// confirming simply replaces the pending secret -- that store method's
// own behaviour -- so this handler doesn't need to notice that case
// specially.
func (g *Gate) handleTOTPEnrol(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, "sign in first")
		return
	}
	// SSO accounts are never offered a local factor: their identity
	// provider owns identity. Checked on LocalPassword(), not on whether
	// an SSO identity is linked -- the admin keeps its password even
	// once linked, and is still offered one; it's an account with *no*
	// local password (provisioned or converted to SSO-only) that has
	// nothing here to gate a factor behind.
	if !user.LocalPassword() {
		http.Error(w, "this account signs in through your identity provider -- an authenticator app is not offered", http.StatusConflict)
		return
	}

	secret, err := gauntlet.GenerateTOTPSecret()
	if err != nil {
		g.logError("generating TOTP secret for " + user.Username + ": " + err.Error())
		http.Error(w, "unable to start enrolment", http.StatusInternalServerError)
		return
	}
	encoded := gauntlet.EncodeTOTPSecret(secret)
	if err := g.deps.Users.SetPendingTOTPSecret(user.ID, encoded); err != nil {
		status := http.StatusInternalServerError
		if err == gauntlet.ErrTOTPAlreadyActive {
			status = http.StatusConflict
		}
		g.writeAuthError(w, r, err, status)
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
	Enabled bool `json:"enabled"`
	// RecoveryCodes is the only place the ten codes ever exist in clear
	// outside a person's own saved copy -- see
	// gauntlet.Store.GenerateRecoveryCodes. Nothing on this account can
	// show them again; losing this response before saving it means
	// removing the factor and enrolling again.
	//
	// nil (JSON null) when AlreadyIssued is true: "mint if absent, never
	// re-mint" -- see GenerateRecoveryCodesIfAbsent's own doc comment.
	RecoveryCodes []string `json:"recoveryCodes"`
	// AlreadyIssued is true when this account already held recovery
	// codes before this confirm call.
	AlreadyIssued bool `json:"alreadyIssued,omitempty"`
}

// handleTOTPConfirm activates the pending secret handleTOTPEnrol stored,
// checking one code against it, and is the only place the ten recovery
// codes are minted and returned.
//
// Confirming ends every other session on this account: turning on a
// second factor is exactly the moment a stale or forgotten session
// elsewhere should not get to ride along unchallenged without ever
// having to prove it. Same shape as handleChangePassword --
// RevokeAllForUser, then reissue this browser its own fresh session --
// since SessionStore.RevokeAllForUser has no notion of "except the
// caller".
func (g *Gate) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, "sign in first")
		return
	}

	var req totpConfirmRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	now := g.now()
	// Re-read rather than trust UserFromContext's copy -- see this
	// file's header comment. The pending secret being checked here only
	// exists because of a *previous* request (handleTOTPEnrol); this one
	// has to see that write.
	current, ok := g.deps.Users.Get(user.ID)
	if !ok {
		writeUnauthorized(w, "sign in first")
		return
	}

	matched, ok := gauntlet.VerifyTOTP(current.TOTPSecret, req.Code, now, current.TOTPLastCounter)
	if !ok {
		http.Error(w, "that code didn't match -- check your authenticator app's clock and try again", http.StatusBadRequest)
		return
	}

	if err := g.deps.Users.ConfirmTOTP(user.ID, now, matched); err != nil {
		status := http.StatusInternalServerError
		if err == gauntlet.ErrNoPendingTOTP {
			status = http.StatusConflict
		}
		g.writeAuthError(w, r, err, status)
		return
	}

	// Mint-if-absent, atomically under the store's lock: a snapshot
	// taken before this call and a separate unconditional
	// GenerateRecoveryCodes would leave a window where two concurrent
	// first enrolments both saw no codes yet and both minted, the second
	// silently replacing what the first had already shown. See
	// GenerateRecoveryCodesIfAbsent's own doc comment.
	codes, alreadyIssued, err := g.deps.Users.GenerateRecoveryCodesIfAbsent(user.ID, now)
	if err != nil {
		// The factor is active at this point regardless -- ConfirmTOTP
		// already committed. Told to the caller plainly rather than
		// reported as a clean success: they are about to be shown
		// nothing to fall back on if the app is ever lost. Recovering
		// from here is DELETE /api/auth/totp followed by enrolling
		// again, same as any other abandoned enrolment.
		g.logError("generating recovery codes for " + user.Username + " after confirming TOTP: " + err.Error())
		http.Error(w, "the authenticator app is now active, but recovery codes could not be generated -- remove it and enrol again from account settings", http.StatusInternalServerError)
		return
	}
	detail := "authenticator app confirmed"
	if alreadyIssued {
		detail += "; existing recovery codes unchanged"
	} else {
		detail += "; recovery codes issued"
	}

	g.deps.Sessions.RevokeAllForUser(user.ID)
	sess := g.deps.Sessions.Create(user.ID, now)
	g.setSessionCookie(w, sess.ID)

	g.audit(user.Username, "account.totp_enabled", user.Username, detail)

	writeJSON(w, http.StatusOK, totpConfirmResponse{Enabled: true, RecoveryCodes: codes, AlreadyIssued: alreadyIssued})
}

type totpDeleteRequest struct {
	Password string `json:"password"`
}

// handleTOTPDelete turns off the signed-in caller's own authenticator-
// app factor, gated by their password -- the one self-service way to
// remove it; the admin route at the end of this file is the only other
// path, for when the password is what's lost instead.
func (g *Gate) handleTOTPDelete(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, "sign in first")
		return
	}

	var req totpDeleteRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	now := g.now()
	// Rate-limited on passwordRecheckLimiterKey, same bucket and
	// reasoning as handleChangePassword's current-password check: a
	// guess at a live credential, made by a caller who -- unlike an
	// ordinary login attempt -- already holds a session, which is
	// exactly the position a stolen-cookie attacker is in. Without this,
	// "turn off 2FA" would be an unthrottled password oracle sitting
	// behind nothing but a cookie.
	userKey := passwordRecheckLimiterKey(user.Username)
	if !g.deps.Limiter.Reserve(userKey, now) {
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
		return
	}
	if _, err := g.deps.Users.Authenticate(user.Username, req.Password, now); err != nil {
		writeUnauthorized(w, "incorrect password")
		return
	}
	g.deps.Limiter.Release(userKey, now)

	if err := g.deps.Users.ClearTOTP(user.ID); err != nil {
		g.writeAuthError(w, r, err, http.StatusInternalServerError)
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

	g.audit(user.Username, "account.totp_disabled", user.Username, "removed by account owner")
	writeJSON(w, http.StatusOK, map[string]any{"disabled": true, "signedOut": signedOut})
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
		http.Error(w, "user id is required", http.StatusBadRequest)
		return
	}
	if caller := UserFromContext(r); caller != nil && caller.ID == id {
		http.Error(w, "an administrator cannot clear their own authenticator app here", http.StatusConflict)
		return
	}

	target, ok := g.deps.Users.Get(id)
	if !ok {
		http.Error(w, "no such user", http.StatusNotFound)
		return
	}
	if err := g.deps.Users.ClearTOTP(id); err != nil {
		g.writeAuthError(w, r, err, http.StatusInternalServerError)
		return
	}

	g.audit(auditActor(r), "user.totp_cleared", target.Username, "authenticator app removed by admin")
	writeJSON(w, http.StatusOK, map[string]any{"username": target.Username, "cleared": true})
}
