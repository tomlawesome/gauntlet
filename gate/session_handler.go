package gate

import (
	"net/http"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// sessionResponse is GET /api/auth/session's body -- mikroview's own
// shape (internal/api/auth.go). The booleans below are emitted even when false,
// as mikroview emits them: its frontend reads them as answers, not as
// keys that may be absent.
type sessionResponse struct {
	SetupRequired bool   `json:"setupRequired"`
	SSOAvailable  bool   `json:"ssoAvailable"`
	Authenticated bool   `json:"authenticated"`
	Username      string `json:"username,omitempty"`
	Role          string `json:"role,omitempty"`
	// HasLocalPassword mirrors gauntlet.User.LocalPassword: false only
	// for an SSO-provisioned account that has never set one.
	HasLocalPassword bool `json:"hasLocalPassword"`
	// SSOConnected reports whether this account is linked to an OIDC
	// identity, read directly off the user's OIDCSubject.
	SSOConnected bool `json:"ssoConnected"`
	// MustChangePassword mirrors the door Protect enforces in
	// protect.go.
	MustChangePassword bool `json:"mustChangePassword"`
	// MustEnrolSecondFactor is true only when this account has no
	// second factor yet -- it names the actual door Protect enforces
	// (always on since #49), not gauntlet.User.HasSecondFactor's raw
	// fact, so an SSO account with no local password, which the door
	// never applies to, does not get told to enrol something nothing
	// is checking for. It is also false while MustChangePassword holds,
	// since Protect's enrol routes answer 403 until the password is
	// changed (protect.go's !user.MustChangePassword guard).
	MustEnrolSecondFactor bool `json:"mustEnrolSecondFactor"`
	// HasTOTP reports gauntlet.User.HasActiveTOTP: a confirmed
	// authenticator-app factor, not a pending enrolment.
	HasTOTP bool `json:"hasTOTP"`
	// Passkeys reports the caller's own passkey count and whether this
	// deployment can offer passkeys, and why not -- a frontend explains
	// an unavailable state from it rather than hiding the feature.
	// Omitted while unauthenticated, and whenever the application has no
	// passkeys at all (Deps.Passkeys nil).
	Passkeys *sessionPasskeysInfo `json:"passkeys,omitempty"`
	// SignedInSince is the current session's IssuedAt, RFC3339 --
	// present only while Authenticated.
	SignedInSince string `json:"signedInSince,omitempty"`
}

// sessionPasskeysInfo is sessionResponse.Passkeys.
type sessionPasskeysInfo struct {
	// Count is read through Store.PasskeyCount.
	Count  int                    `json:"count"`
	Status gauntlet.PasskeyStatus `json:"status"`
	// Origin is set only when Status is ready.
	Origin string `json:"origin,omitempty"`
}

// handleSession always answers 200: it reports state, it does not gate
// access (exemptPaths exempts it for exactly this reason). A frontend
// calls this once on load to decide whether to render first-run
// registration, a login form, or the signed-in app.
func (g *Gate) handleSession(w http.ResponseWriter, r *http.Request) {
	now := g.now()
	resp := sessionResponse{
		SetupRequired: g.deps.Users.Count() == 0,
		SSOAvailable:  g.deps.OIDC != nil,
	}
	if user, ok := g.sessionUser(r, now); ok {
		resp.Authenticated = true
		resp.Username = user.Username
		resp.Role = string(user.Role)
		resp.HasLocalPassword = user.LocalPassword()
		resp.SSOConnected = user.OIDCSubject != ""
		resp.MustChangePassword = user.MustChangePassword
		resp.MustEnrolSecondFactor = !user.MustChangePassword && user.LocalPassword() && !user.HasSecondFactor()
		resp.HasTOTP = user.HasActiveTOTP()
		if g.deps.Passkeys != nil {
			resp.Passkeys = &sessionPasskeysInfo{
				Count:  g.deps.Users.PasskeyCount(user.ID),
				Status: g.deps.Passkeys.Status(),
				Origin: g.deps.Passkeys.Origin(),
			}
		}
		// sessionUser already validated the cookie once; re-reading it
		// here just for IssuedAt rather than widening sessionUser's own
		// signature for a field only this handler needs.
		if cookie, err := r.Cookie(g.sessionCookieName()); err == nil {
			if sess, ok := g.deps.Sessions.Validate(cookie.Value, now); ok {
				resp.SignedInSince = sess.IssuedAt.Format(time.RFC3339)
			}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
