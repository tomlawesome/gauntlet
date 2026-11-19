package gate

import (
	"encoding/json"
	"net/http"
)

// StepUpProof is the step-up half of an application route's JSON body:
// the caller's own password and exactly one of a code (TOTP or recovery)
// or a passkey assertion from POST /api/auth/step-up/passkey/begin.
// Embed it in the route's request struct; the field names match
// gauntlet's own step-up routes.
type StepUpProof struct {
	Password  string          `json:"password"`
	Code      string          `json:"code,omitempty"`
	Assertion json.RawMessage `json:"assertion,omitempty"`
}

// stepUpMissing is the 400's detail when an application route's proof
// lacks the password, or carries neither or both of code and assertion.
const stepUpMissing = "this action needs your password and either a code from your authenticator app or a recovery code, or your passkey (password, code or assertion)"

// StepUp re-checks the signed-in caller's password and a current second
// factor on this request (ASVS 7.5.3), as granting admin does, before an
// application's own sensitive action (#133; ADR-0017). It writes every
// refusal itself and reports whether the handler may go ahead. Call it
// after the request has been validated and before anything is read or
// changed, so a recovery code is never spent on a request that is then
// refused for another reason.
//
// There is no stored proof and no freshness window: the proof is this
// request. Refusals use gauntlet's existing classes: 401
// sign-in-required with no session (a bearer-token or Exempt request),
// 409 conflict for an account with no local password, 400
// invalid-request for an incomplete proof (nothing checked), 401
// invalid-credentials for a wrong password, code or passkey, 401
// step-expired for a dead passkey ceremony, and 429 rate-limited once
// the account's re-check budget is spent.
func (g *Gate) StepUp(w http.ResponseWriter, r *http.Request, proof StepUpProof) bool {
	caller := UserFromContext(r)
	if caller == nil {
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return false
	}
	return g.recheckStepUp(w, r, caller, proof, g.now(), stepUpMissing)
}
