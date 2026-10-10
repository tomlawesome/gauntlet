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
	// protect.go -- including an admin with no local password while the
	// admin passkey rule is on (#82), whose HasLocalPassword is false.
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
	// MustEnrolPasskey is true exactly when Protect holds this account at
	// the admin passkey door (#82): the rule is on, the account is an
	// admin with a local password and no forced password change
	// pending, and it holds no passkey usable here. MustEnrolSecondFactor
	// keeps its meaning beside it; both may be true.
	MustEnrolPasskey bool `json:"mustEnrolPasskey"`
	// AdminPasskeyRequired says whether every admin must hold a passkey
	// on this deployment (Config.AdminPasskey), so a frontend can show
	// the requirement before the door ever holds. Present, true or
	// false, only while Authenticated.
	AdminPasskeyRequired *bool `json:"adminPasskeyRequired,omitempty"`
	// HasTOTP reports gauntlet.User.HasActiveTOTP: a confirmed
	// authenticator-app factor, not a pending enrolment.
	HasTOTP bool `json:"hasTOTP"`
	// Passkeys reports the caller's own passkey count and whether this
	// deployment can offer passkeys, and why not -- a frontend explains
	// an unavailable state from it rather than hiding the feature.
	// Omitted while unauthenticated, except when passkey-alone sign-in is
	// on and ready (#77): then it is there so a login page knows to show
	// "Sign in with a passkey", with Count 0, Status ready, Origin and
	// SignIn. Omitted whenever the application has no passkeys at all
	// (Deps.Passkeys nil).
	Passkeys *sessionPasskeysInfo `json:"passkeys,omitempty"`
	// SignedInSince is the current session's IssuedAt, RFC3339 --
	// present only while Authenticated.
	SignedInSince string `json:"signedInSince,omitempty"`
	// Resumable is true only while Authenticated is false and the
	// request's session cookie names a session that timed out through
	// inactivity inside its 24-hour ceiling and can be resumed with
	// the password alone (POST /api/auth/reauthenticate, #71). A
	// frontend then offers "enter your password to continue" instead
	// of the full sign-in form. Omitted otherwise.
	Resumable bool `json:"resumable,omitempty"`
}

// sessionPasskeysInfo is sessionResponse.Passkeys.
type sessionPasskeysInfo struct {
	// Count is read through Store.PasskeyCount.
	Count  int                    `json:"count"`
	Status gauntlet.PasskeyStatus `json:"status"`
	// Origin is set only when Status is ready.
	Origin string `json:"origin,omitempty"`
	// SignIn is true when signing in with a passkey alone is on and the
	// relying party is ready (Config.PasskeySignIn, #77): the routes
	// /api/auth/login/passkey/begin and /api/auth/login/passkey work.
	// Absent otherwise.
	SignIn bool `json:"signIn,omitempty"`
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
	if user, ok := g.sessionUser(r, now, true); ok {
		resp.Authenticated = true
		resp.Username = user.Username
		resp.Role = string(user.Role)
		resp.HasLocalPassword = user.LocalPassword()
		resp.SSOConnected = user.OIDCSubject != ""
		ruleOn := g.adminPasskeyRuleOn()
		resp.MustChangePassword = (user.MustChangePassword && user.LocalPassword()) ||
			(ruleOn && user.Role == gauntlet.RoleAdmin && !user.LocalPassword())
		resp.MustEnrolSecondFactor = !user.MustChangePassword && user.LocalPassword() && !user.HasSecondFactor()
		resp.MustEnrolPasskey = g.adminMustEnrolPasskey(user)
		resp.AdminPasskeyRequired = &ruleOn
		resp.HasTOTP = user.HasActiveTOTP()
		if g.deps.Passkeys != nil {
			resp.Passkeys = &sessionPasskeysInfo{
				Count:  g.deps.Users.PasskeyCount(user.ID),
				Status: g.deps.Passkeys.Status(),
				Origin: g.deps.Passkeys.Origin(),
				SignIn: g.passkeySignInOn(),
			}
		}
		// sessionUser already validated the cookie once; re-reading it
		// here just for IssuedAt rather than widening sessionUser's own
		// signature for a field only this handler needs. Peek, not
		// Validate: the read above has already slid the session once
		// (#104).
		if cookie, err := r.Cookie(g.sessionCookieName()); err == nil {
			if sess, ok := g.deps.Sessions.Peek(cookie.Value, now); ok {
				resp.SignedInSince = sess.IssuedAt.Format(time.RFC3339)
			}
		}
	}
	if !resp.Authenticated {
		_, _, resp.Resumable = g.resumableSession(r, now)
		if g.passkeySignInOn() {
			resp.Passkeys = &sessionPasskeysInfo{Status: g.deps.Passkeys.Status(), Origin: g.deps.Passkeys.Origin(), SignIn: true}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
