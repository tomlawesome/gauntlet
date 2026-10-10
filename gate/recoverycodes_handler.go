package gate

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/internal/plaintext"
)

type recoveryCodesRegenerateRequest struct {
	Password string `json:"password"`
}

type recoveryCodesRegenerateResponse struct {
	// RecoveryCodes is the fresh ten, in clear, exactly once -- the same
	// one-shot contract the first factor's codes have
	// (totpConfirmResponse.RecoveryCodes).
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
// The old set stops working at once, when RegenerateRecoveryCodes saves the
// new one, just before the reply is written (owner decision, 2026-10-08,
// #80 P1-S2: as GitHub, Google, Microsoft, 1Password and Dropbox do; NIST
// SP 800-63B-4 4.2.1.1 lets a replacement be requested at any time). The
// new codes are shown once, in that reply. Someone who missed them
// (dropped connection, closed page) regenerates again; there is no
// pending state and no way to show them twice. If the save fails the old
// set stays and no codes are issued. First issuance is different: it
// waits for handleEnrolmentConfirm, and this route refuses (409) while
// that first factor is still on hold.
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
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
	}

	if refuseWithoutLocalPassword(w, user) {
		return
	}
	var req recoveryCodesRegenerateRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}

	now := g.now()
	// Password-gated and throttled by recheckPassword.
	current, ok := g.recheckPassword(w, r, user, req.Password, "incorrect password", now)
	if !ok {
		return
	}

	// Re-checked against the freshly authenticated copy, not the context
	// snapshot -- same reasoning handleTOTPConfirm's header comment gives
	// for re-reading rather than trusting UserFromContext.
	if !current.HasSecondFactor() {
		writeProblem(w, http.StatusConflict, classConflict, noSecondFactorForCodesMessage, nil)
		return
	}

	// The store checks again under its lock: a last factor removed since
	// the check above is refused the same way, never given codes (#94).
	codes, err := g.deps.Users.RegenerateRecoveryCodes(user.ID)
	if errors.Is(err, gauntlet.ErrNoSecondFactors) {
		writeProblem(w, http.StatusConflict, classConflict, noSecondFactorForCodesMessage, nil)
		return
	}
	if errors.Is(err, gauntlet.ErrUserNotFound) { // deleted since recheckPassword read it (#95)
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
	}
	if err != nil {
		// RegenerateRecoveryCodes' own restore-on-failure contract already
		// left the old set intact and reported nothing as issued -- this
		// is a clean refusal, not a half-done one.
		g.writeAuthError(w, r, err, http.StatusInternalServerError, classServerError)
		return
	}

	g.audit(r, user.Username, "account.recovery_codes_regenerated", user.Username, "")

	writeJSON(w, http.StatusOK, recoveryCodesRegenerateResponse{RecoveryCodes: codes})
	g.notify(r.Context(), &AccountNotice{
		Kind: NoticeRecoveryCodesRegenerated, UserID: user.ID, Username: user.Username, Role: current.Role, At: now,
	})
}

// noSecondFactorForCodesMessage is the 409 for regenerating recovery
// codes on an account with no live second factor.
const noSecondFactorForCodesMessage = "this account has no second factor yet -- recovery codes stand in for one, not for a password alone"

// -- POST /api/auth/recovery-codes/confirm (#58) -------------------------

type enrolmentConfirmResponse struct {
	Confirmed bool `json:"confirmed"`
	// Factor is which kind of factor went live: "passkey" or "totp".
	Factor string `json:"factor"`
}

// handleEnrolmentConfirm is the signed-in caller saying "I've saved
// these": it takes the account's held first factor and its recovery
// codes off hold in one write (gauntlet.Store.ConfirmHeldEnrolment), and
// only then does what turning on a second factor does -- ends every
// other session on the account, renews this one (as handleTOTPConfirm
// does for a later app) and writes the audit line the factor's own
// route used to write: account.passkey_added or account.totp_enabled.
//
// No body and no password: the session that saw the codes is the one
// confirming them, and the factor and codes were already proved and
// password-gated by the routes that held them. Reachable at the
// must-enrol-factor door, since the account has no live factor until
// this answers. 409 conflict when nothing is held; 401 step-expired
// when the hold ran out (gauntlet.HeldEnrolmentLifetime) -- the held
// factor and codes are deleted by that same call, and the caller sets
// the factor up again.
func (g *Gate) handleEnrolmentConfirm(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r)
	if user == nil {
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
	}
	now := g.now()
	held, err := g.deps.Users.ConfirmHeldEnrolment(user.ID, now)
	switch {
	case errors.Is(err, gauntlet.ErrHeldEnrolmentExpired):
		writeUnauthorized(w, classStepExpired, gateErrorMessages[gauntlet.ErrHeldEnrolmentExpired])
		return
	case errors.Is(err, gauntlet.ErrNoHeldEnrolment), errors.Is(err, gauntlet.ErrPasskeyDuplicate), errors.Is(err, gauntlet.ErrPasskeyLimitReached):
		g.writeAuthError(w, r, err, http.StatusConflict, classConflict)
		return
	case err != nil:
		g.writeAuthError(w, r, err, http.StatusInternalServerError, classServerError)
		return
	}

	// The factor is live from here: no session from before it may ride
	// along unchallenged.
	method := g.sessionMethod(r, user.ID, now)
	g.deps.Sessions.RevokeAllForUser(user.ID)
	g.issueSession(w, r, user.ID, method, now)

	detail := &SecondFactorDetail{Method: "totp"}
	if held.Kind == gauntlet.HeldFactorPasskey && held.Passkey != nil {
		// Quoted in the audit entry, as in handlePasskeyRegisterFinish:
		// the name is the user's own text. Cleaned in the notice, for a
		// name held before names were checked (#89).
		g.audit(r, user.Username, "account.passkey_added", user.Username, fmt.Sprintf("name=%q", held.Passkey.Name))
		detail = &SecondFactorDetail{Method: "passkey", Name: plaintext.Clean(held.Passkey.Name)}
	} else {
		g.audit(r, user.Username, "account.totp_enabled", user.Username, "authenticator app confirmed; recovery codes issued")
	}
	writeJSON(w, http.StatusOK, enrolmentConfirmResponse{Confirmed: true, Factor: string(held.Kind)})
	g.notify(r.Context(), &AccountNotice{
		Kind: NoticeSecondFactorAdded, UserID: user.ID, Username: user.Username, Role: user.Role, At: now,
		SecondFactor: detail,
	})
}
