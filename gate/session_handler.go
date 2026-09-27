package gate

import (
	"net/http"
	"time"
)

// sessionResponse is GET /api/auth/session's body -- mikroview's own
// shape (internal/api/auth.go), narrowed to what this stage's Store
// already supports: no SSO/passkey session fields, since neither OIDC
// nor the passkey ceremony are wired into gate yet.
type sessionResponse struct {
	SetupRequired bool   `json:"setupRequired"`
	SSOAvailable  bool   `json:"ssoAvailable"`
	Authenticated bool   `json:"authenticated"`
	Username      string `json:"username,omitempty"`
	Role          string `json:"role,omitempty"`
	// HasLocalPassword mirrors gauntlet.User.LocalPassword: false only
	// for an SSO-provisioned account that has never set one.
	HasLocalPassword bool `json:"hasLocalPassword,omitempty"`
	// SSOConnected reports whether this account is linked to an OIDC
	// identity -- read directly off the user's OIDCSubject rather than
	// through an OIDC-specific call, since gate has no OIDC handlers
	// yet to have established the link with.
	SSOConnected bool `json:"ssoConnected,omitempty"`
	// MustChangePassword mirrors the door Protect enforces in
	// protect.go.
	MustChangePassword bool `json:"mustChangePassword,omitempty"`
	// MustEnrolSecondFactor is true only when Config.RequireSecondFactor
	// is set and this account has none yet -- it names the actual door
	// Protect enforces, not gauntlet.User.HasSecondFactor's raw fact,
	// so a deployment that leaves RequireSecondFactor off never tells a
	// client to enrol something nothing is checking for.
	MustEnrolSecondFactor bool `json:"mustEnrolSecondFactor,omitempty"`
	// HasTOTP reports gauntlet.User.HasActiveTOTP -- data gate can read
	// today even though enrolling one is a stage-2 route (TOTP
	// confirmation only sets the fields this reads; it does not need
	// gate's own TOTP handlers to exist).
	HasTOTP bool `json:"hasTOTP,omitempty"`
	// SignedInSince is the current session's IssuedAt, RFC3339 --
	// present only while Authenticated.
	SignedInSince string `json:"signedInSince,omitempty"`
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
		resp.MustEnrolSecondFactor = g.cfg.RequireSecondFactor && user.LocalPassword() && !user.HasSecondFactor()
		resp.HasTOTP = user.HasActiveTOTP()
		// sessionUser already validated the cookie once; re-reading it
		// here just for IssuedAt rather than widening sessionUser's own
		// signature for a field only this handler needs.
		if cookie, err := r.Cookie(g.cfg.CookieName); err == nil {
			if sess, ok := g.deps.Sessions.Validate(cookie.Value, now); ok {
				resp.SignedInSince = sess.IssuedAt.Format(time.RFC3339)
			}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
