package gate

import "net/http"

type recoveryCodesRegenerateRequest struct {
	Password string `json:"password"`
}

type recoveryCodesRegenerateResponse struct {
	// RecoveryCodes is the fresh ten, in clear, exactly once -- the same
	// one-shot contract totpConfirmResponse.RecoveryCodes documents.
	// Nothing on this account can show them again once this response is
	// gone.
	RecoveryCodes []string `json:"recoveryCodes"`
}

// handleRecoveryCodesRegenerate mints a fresh set of ten recovery codes
// for the signed-in caller's own account, replacing whichever set stood
// before. Password-gated exactly like handleTOTPDelete, and refused
// outright when the account has no second factor at all: recovery codes
// stand in for one, not for a password alone.
//
// Unlike ConfirmTOTP, this does not end other sessions: those end
// sessions because the set of factors protecting the account just
// changed and a session elsewhere might predate that change; regenerating
// codes changes nothing about which factors are active, so there is
// nothing for another session to have gotten away with. The codes are a
// spare key, not the lock.
func (g *Gate) handleRecoveryCodesRegenerate(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, "sign in first")
		return
	}

	var req recoveryCodesRegenerateRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	now := g.now()
	// Same passwordRecheckLimiterKey bucket and reasoning as
	// handleTOTPDelete: a caller who already holds a session is exactly
	// the position a stolen-cookie attacker is in, so this cannot be
	// left as an unthrottled password oracle behind a cookie.
	userKey := passwordRecheckLimiterKey(user.Username)
	if !g.deps.Limiter.Reserve(userKey, now) {
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
		return
	}
	current, err := g.deps.Users.Authenticate(user.Username, req.Password, now)
	if err != nil {
		writeUnauthorized(w, "incorrect password")
		return
	}
	g.deps.Limiter.Release(userKey, now)

	// Re-checked against the freshly authenticated copy, not the context
	// snapshot -- same reasoning handleTOTPConfirm's header comment gives
	// for re-reading rather than trusting UserFromContext.
	if !current.HasSecondFactor() {
		http.Error(w, "this account has no second factor yet -- recovery codes stand in for one, not for a password alone", http.StatusConflict)
		return
	}

	codes, err := g.deps.Users.GenerateRecoveryCodes(user.ID, now)
	if err != nil {
		// GenerateRecoveryCodes' own restore-on-failure contract already
		// left the old set intact and reported nothing as issued -- this
		// is a clean refusal, not a half-done one.
		g.writeAuthError(w, r, err, http.StatusInternalServerError)
		return
	}

	g.audit(user.Username, "account.recovery_codes_regenerated", user.Username, "")

	writeJSON(w, http.StatusOK, recoveryCodesRegenerateResponse{RecoveryCodes: codes})
}
