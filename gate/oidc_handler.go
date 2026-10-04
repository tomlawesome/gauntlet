package gate

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/oidc"
)

// oidcFlowCookieName carries the CSRF state, nonce and PKCE verifier a
// login or link flow started with, sealed via Deps.OIDCState, between
// the redirect to the provider and it coming back to the callback.
const oidcFlowCookieName = "gate_oidc_flow"

// oidcFlowCookiePath scopes the cookie to gate's own OIDC routes, per
// docs/design.md §1.5's fixed behaviour ("the OIDC flow cookie scoped to
// /api/auth/oidc"). oidcLoginPath and oidcCallbackPath (protect.go) stay
// plain string literals, because the contract tests read route patterns
// from the source; TestOIDCFlowCookiePathCoversItsRoutes keeps them under
// this prefix.
const oidcFlowCookiePath = oidcPathPrefix

// oidcFlowCookieMaxAge bounds both the cookie's own Max-Age and the
// tolerance passed to StateCodec.Decode -- kept as one constant so the
// two can never drift apart. Fixed at 5 minutes (docs/design.md §1.5),
// shorter than mikroview's own 10-minute constant for the same cookie:
// long enough for a real login (provider discovery page, maybe an MFA
// prompt) without leaving a usable flow lying around for long if
// abandoned.
const oidcFlowCookieMaxAge = 5 * time.Minute

func (g *Gate) setOIDCFlowCookie(w http.ResponseWriter, value string) {
	g.writeCookie(w, oidcFlowCookieName, value, oidcFlowCookiePath, int(oidcFlowCookieMaxAge.Seconds()))
}

func (g *Gate) clearOIDCFlowCookie(w http.ResponseWriter) {
	g.writeCookie(w, oidcFlowCookieName, "", oidcFlowCookiePath, -1)
}

// redirectWithSSOError sends the browser back to Config.LoginPath with
// ?ssoError=<opaque-code> -- never the provider's own error text, which
// has no business being echoed into the page (docs/design.md §1.5's
// fixed "?ssoError=" redirect target).
func (g *Gate) redirectWithSSOError(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, g.cfg.LoginPath+"?ssoError="+code, http.StatusFound)
}

// failSSO is redirectWithSSOError plus a Warn line, so an operator whose
// users keep landing back on the login page can see why. identity is
// the verified identity, or nil before one exists; its subject and
// issuer are quoted, as the provider chose them. Rated like the other
// refusals a stranger can send at will (warnRated): most of these need
// no more than a request to the callback URL.
func (g *Gate) failSSO(w http.ResponseWriter, r *http.Request, code string, identity *oidc.Identity) {
	address := g.cfg.ClientIP(r)
	msg := fmt.Sprintf("gate: SSO callback failed: ssoError=%s from=%q", code, address)
	if identity != nil {
		msg += fmt.Sprintf(" subject=%q issuer=%q", identity.Subject, identity.Issuer)
	}
	g.warnRated("sso "+code+" "+address, msg)
	g.redirectWithSSOError(w, r, code)
}

// handleOIDCLogin starts a login: generates fresh PKCE/state/nonce
// values (oidc.FlowState), seals them into a short-lived cookie, and
// redirects the browser to the provider. 404s if OIDC isn't configured
// -- see Deps.OIDC's doc comment.
func (g *Gate) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if g.deps.OIDC == nil {
		writeProblem(w, http.StatusNotFound, classNotFound, "", nil)
		return
	}

	fs, err := oidc.NewFlowState(g.now())
	if err != nil {
		g.logError("starting SSO login: " + err.Error())
		writeProblem(w, http.StatusInternalServerError, classServerError, "failed to start SSO login", nil)
		return
	}
	encoded, err := g.deps.OIDCState.Encode(fs)
	if err != nil {
		g.logError("starting SSO login: " + err.Error())
		writeProblem(w, http.StatusInternalServerError, classServerError, "failed to start SSO login", nil)
		return
	}
	g.setOIDCFlowCookie(w, encoded)

	http.Redirect(w, r, g.deps.OIDC.AuthCodeURL(fs.State, fs.Nonce, fs.CodeVerifier), http.StatusFound)
}

// handleOIDCLinkStart begins linking the signed-in account to an SSO
// identity. It returns the provider URL as JSON for the caller to
// navigate to, rather than issuing a redirect itself.
//
// POST, not GET, and that is the security-relevant part. Linking is
// destructive for every role but admin -- it removes the account's local
// password permanently (see gauntlet.Store.LinkOIDCIdentity) -- and even
// for the admin it attaches a permanent second way in. A GET that starts
// the flow could be triggered cross-site; POST puts it behind the CSRF
// header check, which a cross-site request cannot set.
//
// The target account is taken from the session and sealed into the flow
// state, never from the request body -- the caller does not get to say
// which account a link applies to.
func (g *Gate) handleOIDCLinkStart(w http.ResponseWriter, r *http.Request) {
	if g.deps.OIDC == nil {
		writeProblem(w, http.StatusNotFound, classNotFound, "", nil)
		return
	}
	caller := UserFromContext(r)
	if caller == nil {
		writeUnauthorized(w, classSignInRequired, "sign in first")
		return
	}
	// Already SSO-only: there is no local password left to convert.
	if !caller.LocalPassword() {
		writeProblem(w, http.StatusConflict, classConflict, "this account already signs in through your identity provider", nil)
		return
	}
	// Already connected -- keeping a password only if it is the admin.
	// Linking again could only mean pointing the account at a second
	// identity, which LinkOIDCIdentity refuses -- said here too so the
	// answer comes before the provider round trip.
	if caller.OIDCSubject != "" {
		writeProblem(w, http.StatusConflict, classConflict, "this account is already connected to your identity provider", nil)
		return
	}

	now := g.now()
	fs, err := oidc.NewFlowState(now)
	if err != nil {
		g.logError("starting SSO linking for account " + caller.ID + ": " + err.Error())
		writeProblem(w, http.StatusInternalServerError, classServerError, "failed to start SSO linking", nil)
		return
	}
	fs.LinkUserID = caller.ID

	encoded, err := g.deps.OIDCState.Encode(fs)
	if err != nil {
		g.logError("starting SSO linking for account " + caller.ID + ": " + err.Error())
		writeProblem(w, http.StatusInternalServerError, classServerError, "failed to start SSO linking", nil)
		return
	}
	g.setOIDCFlowCookie(w, encoded)
	writeJSON(w, http.StatusOK, map[string]string{
		"url": g.deps.OIDC.AuthCodeURL(fs.State, fs.Nonce, fs.CodeVerifier),
	})
}

// completeOIDCLink finishes a flow that handleOIDCLinkStart began.
//
// The session is re-checked against the account sealed into the flow,
// rather than trusted from either side alone: the sealed value can't be
// forged, but it also can't notice that the browser signed out and
// signed in as somebody else while the provider round trip was in
// flight -- without this check, that would attach the identity that just
// authenticated to whichever account started the flow.
func (g *Gate) completeOIDCLink(w http.ResponseWriter, r *http.Request, fs oidc.FlowState, identity *oidc.Identity, now time.Time) {
	caller, ok := g.sessionUser(r, now)
	if !ok || caller.ID != fs.LinkUserID {
		g.failSSO(w, r, "link_session_changed", identity)
		return
	}

	if err := g.deps.Users.LinkOIDCIdentity(caller.ID, identity.Issuer, identity.Subject, now); err != nil {
		if err == gauntlet.ErrOIDCIdentityTaken {
			g.failSSO(w, r, "link_identity_taken", identity)
			return
		}
		g.logWarn("linking SSO identity to account " + caller.ID + " failed: " + err.Error())
		g.redirectWithSSOError(w, r, "link_failed")
		return
	}
	// Recorded on the completed link rather than on the request that
	// started it: a link that never came back from the provider changed
	// nothing and should leave no trace. What it cost the account is
	// recorded too, since that differs by role -- the admin keeps its
	// password, everybody else loses it.
	detail := "issuer=" + identity.Issuer
	if caller.Role == gauntlet.RoleAdmin {
		detail += "; local password kept (admin)"
	} else {
		detail += "; local password removed"
	}
	g.audit(r, caller.Username, "account.link_sso", caller.Username, detail)

	// LinkOIDCIdentity sets SessionsEndedAt, which invalidates every
	// session issued before it -- including the one that just made this
	// request. The live ones are dropped here too, as the password,
	// reset and second-factor handlers drop theirs: the stored cutoff is
	// the only record of the link's, and an older build saving the
	// document while this one runs would drop it (#28). A fresh session
	// is issued so the person stays signed in on this browser.
	g.deps.Sessions.RevokeAllForUser(caller.ID)
	g.issueSession(w, r, caller.ID, now)
	http.Redirect(w, r, "/?ssoLinked=1", http.StatusFound)
}

// handleOIDCCallback completes a login: verifies the state/nonce/PKCE
// flow this browser started (see handleOIDCLogin), exchanges the
// authorization code, cryptographically verifies the resulting ID
// token, and either resolves or just-in-time provisions the local
// account for that (issuer, subject) identity (see
// gauntlet.Store.FindOrCreateOIDCUser) before creating a normal session
// -- from that point on this is indistinguishable from a local-password
// login to everything else in the application.
//
// Every failure path redirects to Config.LoginPath with
// "?ssoError=<opaque-code>" rather than rendering an error itself or
// reflecting any provider-supplied text. The flow cookie is cleared
// unconditionally, before any redirect, since it's single-use regardless
// of outcome.
func (g *Gate) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if g.deps.OIDC == nil {
		writeProblem(w, http.StatusNotFound, classNotFound, "", nil)
		return
	}

	cookie, cookieErr := r.Cookie(oidcFlowCookieName)
	// Cleared here, before any redirect below can call WriteHeader -- a
	// header added after that point would be silently dropped, and this
	// cookie must never survive past one use regardless of which path is
	// taken.
	g.clearOIDCFlowCookie(w)
	if cookieErr != nil {
		g.failSSO(w, r, "state_mismatch", nil)
		return
	}

	now := g.now()
	fs, err := g.deps.OIDCState.Decode(cookie.Value, oidcFlowCookieMaxAge, now)
	if err != nil {
		g.failSSO(w, r, "state_mismatch", nil)
		return
	}

	q := r.URL.Query()
	if q.Get("error") != "" {
		// The provider itself reported a failure (access_denied, etc) --
		// never surfaced verbatim, see this handler's doc comment.
		g.failSSO(w, r, "provider_error", nil)
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(fs.State)) != 1 {
		g.failSSO(w, r, "state_mismatch", nil)
		return
	}
	code := q.Get("code")
	if code == "" {
		g.failSSO(w, r, "provider_error", nil)
		return
	}

	tok, err := g.deps.OIDC.Exchange(r.Context(), code, fs.CodeVerifier)
	if err != nil {
		g.failSSO(w, r, "provider_error", nil)
		return
	}
	identity, err := g.deps.OIDC.VerifyIDToken(r.Context(), tok)
	if err != nil {
		g.failSSO(w, r, "verification_failed", nil)
		return
	}
	if !oidc.VerifyNonce(identity.Nonce, fs.Nonce) {
		g.failSSO(w, r, "state_mismatch", nil)
		return
	}

	// Authentic is not the same as authorised. This runs before
	// FindOrCreateOIDCUser on purpose: a refused identity must not be
	// provisioned an account as a side effect of being refused, and it
	// re-runs on every login, so revoking someone's group at the IdP
	// locks them out at their next sign-in rather than only whenever
	// their session happens to lapse.
	if err := g.deps.OIDCPolicy.Permit(identity); err != nil {
		// The specific unmet condition goes to the server log, not the
		// browser -- telling an outsider "not a member of any permitted
		// group" maps out the allowlist for them.
		//
		// Subject and issuer are quoted: both come from the provider's
		// token, and a newline or terminal escape in either would
		// otherwise forge a log line or run in the reader's terminal.
		g.logWarn(fmt.Sprintf("refused SSO login for subject %q at %q: %v", identity.Subject, identity.Issuer, err))
		g.recordSignIn(r, loginEvent(nil, ssoUsernameHint(identity), gauntlet.SignInSSORefused, gauntlet.SignInMethodSSO), loginReservation{}, now)
		g.redirectWithSSOError(w, r, "not_permitted")
		return
	}

	// Branch after the policy check above, deliberately: an identity
	// this deployment refuses must not be attachable to an existing
	// account either, and linking is the more dangerous of the two
	// outcomes -- it hands that identity a permanent way in.
	if fs.IsLink() {
		g.completeOIDCLink(w, r, fs, identity, now)
		return
	}

	user, _, err := g.deps.Users.FindOrCreateOIDCUser(identity.Issuer, identity.Subject, ssoUsernameHint(identity), now)
	if err != nil {
		g.failSSO(w, r, "login_failed", identity)
		return
	}

	// An SSO sign-in is a re-authentication like the password paths:
	// the session this browser held for the account ends, since the
	// cookie below replaces it (ASVS 7.2.4; see revokeReplacedSession).
	// The identity provider vouched for every credential: judge the
	// sign-in (#55) before any session exists. Never on the link branch
	// above, whose caller already holds a session.
	place := g.placeOf(r, "")
	verdict := g.judgeSignIn(r, user.ID, place, now)
	notice := g.completeSignIn(w, r, user, loginReservation{}, gauntlet.SignInMethodSSO, place, verdict, now)
	http.Redirect(w, r, "/", http.StatusFound)
	g.notifyUnusualSignIn(r.Context(), notice)
}

// ssoUsernameHint is the name an identity asks to be known by: its
// preferred_username, else its email.
func ssoUsernameHint(identity *oidc.Identity) string {
	if identity.PreferredUsername != "" {
		return identity.PreferredUsername
	}
	return identity.Email
}
