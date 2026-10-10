package gate

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/internal/groupname"
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
// issuer are quoted, as the provider chose them. cause, when not nil,
// is what went wrong behind the code (ssoCause), so a provider that is
// down, a wrong client secret and a failing disk do not read the same
// (#80). Rated like the other refusals a stranger can send at will
// (warnRated): most of these need no more than a request to the
// callback URL.
func (g *Gate) failSSO(w http.ResponseWriter, r *http.Request, code string, identity *oidc.Identity, cause error) {
	address := g.cfg.ClientIP(r)
	msg := fmt.Sprintf("gate: SSO callback failed: ssoError=%s from=%q", code, address)
	if identity != nil {
		msg += fmt.Sprintf(" subject=%q issuer=%q", identity.Subject, identity.Issuer)
	}
	if cause != nil {
		msg += fmt.Sprintf(" cause=%q", ssoCause(cause))
	}
	g.warnRated("sso "+code+" "+address, msg)
	g.redirectWithSSOError(w, r, code)
}

// maxSSOCause bounds the cause failSSO logs: much of it can be text a
// provider, or anyone calling the callback, chose.
const maxSSOCause = 300

// ssoCause is the text failSSO logs for err. A refusal from the token
// endpoint is its status, error code and description only, never the
// raw body oauth2 would print, which is the provider's own text and may
// echo what was sent to it. Nothing here carries a secret: the client
// secret and the PKCE verifier are sent, never part of an error, and the
// authorization code is not in the token endpoint's URL. Cut to
// maxSSOCause bytes on a character boundary; failSSO quotes it.
func ssoCause(err error) string {
	msg := err.Error()
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		msg = "the token endpoint refused the code exchange"
		if re.Response != nil {
			msg += ": " + re.Response.Status
		}
		if re.ErrorCode != "" {
			msg += ": " + re.ErrorCode
		}
		if re.ErrorDescription != "" {
			msg += " (" + re.ErrorDescription + ")"
		}
	}
	if len(msg) > maxSSOCause {
		msg = strings.ToValidUTF8(msg[:maxSSOCause], "") + "..."
	}
	return msg
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

// oidcLinkStartRequest is POST /api/auth/oidc/link's body: the caller's
// own password.
type oidcLinkStartRequest struct {
	Password string `json:"password"`
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
//
// Password-gated through recheckPassword, as TOTP enrolment and passkey
// registration are (ASVS 7.5.1): a link is permanent, and for anyone
// but an admin it removes the password and every local factor, so a
// stolen session cookie that could start one would become a way in that
// outlives the session. The password is the one thing a cookie does not
// carry. Checked here, before the provider round trip and before any
// flow state is sealed; the two 409s come first, since they check no
// credential and an account with no local password has none to give.
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
	var req oidcLinkStartRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}
	now := g.now()
	if _, ok := g.recheckPassword(w, r, caller, req.Password, "incorrect password", now); !ok {
		return
	}

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
		g.failSSO(w, r, "link_session_changed", identity, nil)
		return
	}

	if err := g.deps.Users.LinkOIDCIdentity(caller.ID, identity.Issuer, identity.Subject, now); err != nil {
		if err == gauntlet.ErrOIDCIdentityTaken {
			g.failSSO(w, r, "link_identity_taken", identity, nil)
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
	method := g.sessionMethod(r, caller.ID, now)
	g.deps.Sessions.RevokeAllForUser(caller.ID)
	g.issueSession(w, r, caller.ID, method, now)
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
		g.failSSO(w, r, "state_mismatch", nil, errors.New("no flow cookie: the sign-in was not started from this browser, or it took longer than the cookie lives"))
		return
	}

	now := g.now()
	fs, err := g.deps.OIDCState.Decode(cookie.Value, oidcFlowCookieMaxAge, now)
	if err != nil {
		g.failSSO(w, r, "state_mismatch", nil, err)
		return
	}

	q := r.URL.Query()
	if q.Get("error") != "" {
		// The provider itself reported a failure (access_denied, etc) --
		// never surfaced verbatim to the browser, see this handler's doc
		// comment; logged, quoted and cut short.
		cause := "the provider answered error=" + q.Get("error")
		if d := q.Get("error_description"); d != "" {
			cause += " (" + d + ")"
		}
		g.failSSO(w, r, "provider_error", nil, errors.New(cause))
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(fs.State)) != 1 {
		g.failSSO(w, r, "state_mismatch", nil, errors.New("the state parameter does not match this browser's sign-in"))
		return
	}
	code := q.Get("code")
	if code == "" {
		g.failSSO(w, r, "provider_error", nil, errors.New("the provider sent no code"))
		return
	}

	tok, err := g.deps.OIDC.Exchange(r.Context(), code, fs.CodeVerifier)
	if err != nil {
		g.failSSO(w, r, "provider_error", nil, err)
		return
	}
	identity, err := g.deps.OIDC.VerifyIDToken(r.Context(), tok)
	if err != nil {
		g.failSSO(w, r, "verification_failed", nil, err)
		return
	}
	if !oidc.VerifyNonce(identity.Nonce, fs.Nonce) {
		g.failSSO(w, r, "state_mismatch", nil, errors.New("the token's nonce does not match this browser's sign-in"))
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

	// The role the identity provider's groups give, if this deployment
	// maps groups to roles, goes into the same write that finds or
	// creates the account: no sign-in happens at a role the groups no
	// longer give.
	wantRole, _ := g.ssoRoleFor(identity)
	signIn, err := g.deps.Users.FindOrCreateOIDCUserWithRole(identity.Issuer, identity.Subject, ssoUsernameHint(identity), wantRole, now)
	if err != nil {
		g.failSSO(w, r, "login_failed", identity, err)
		return
	}
	user := signIn.User
	// An account this callback created is audited as an admin-created
	// one is (#78), so the trail says when and how it appeared.
	if signIn.Created {
		g.audit(r, ssoAuditActor, "user.create", user.Username,
			fmt.Sprintf("role=%s; first single sign-on at issuer %q", user.Role, identity.Issuer))
	}
	if signIn.RoleBefore != user.Role {
		g.recordSSORoleChange(r, signIn, identity.Issuer, now)
	}

	// An SSO sign-in is a re-authentication like the password paths:
	// the session this browser held for the account ends, since the
	// cookie below replaces it (ASVS 7.2.4; see revokeReplacedSession).
	// The identity provider vouched for every credential: judge the
	// sign-in (#55) before any session exists. Never on the link branch
	// above, whose caller already holds a session.
	place := g.placeOf(r, "")
	verdict := g.judgeSignIn(r, user, gauntlet.SignInMethodSSO, place, now)
	stop := func() {
		out, notice := g.stopSignIn(w, r, user, loginReservation{}, gauntlet.SignInMethodSSO, place, verdict, now)
		if out == stopHeld {
			// The frontend asks for the code and posts it to
			// login/confirm, which holds the ticket this set -- or,
			// held for a passkey, runs login/prove/begin and posts
			// the assertion to login/prove (#65).
			query := "?confirm=1"
			if verdict.action == UnusualSignInProve {
				query = "?prove=1"
			}
			http.Redirect(w, r, g.cfg.LoginPath+query, http.StatusFound)
			return
		}
		// Refused, or past the send limit (#84): the frontend's text is
		// generic either way, so both redirect refused; only a refusal
		// carries a notice.
		g.redirectWithSSOError(w, r, "refused")
		g.notify(r.Context(), notice)
	}
	if verdict.stopsSignIn() {
		stop()
		return
	}
	switch g.spendAllowance(w, r, user, place, &verdict, now) {
	case allowanceNotAllowed:
		// The allowance was already used: the policy's own answer, as
		// login's (#103) -- refused, or held for a code or a passkey.
		stop()
		return
	case allowanceFailed:
		// The allowance could not be saved as spent: no session, as
		// login's (#101). rememberAllowedSignIn has logged why.
		g.redirectWithSSOError(w, r, "login_failed")
		return
	}
	notice := g.completeSignIn(w, r, user, loginReservation{}, gauntlet.SignInMethodSSO, place, verdict, now)
	http.Redirect(w, r, "/", http.StatusFound)
	g.notify(r.Context(), notice)
}

// ssoRoleFor is the role Policy.RoleFromGroups gives identity: the
// highest role among the mapped groups it carries, else
// Policy.RoleWithoutGroup ("viewer" when unset). The second result is
// false when no map is configured, which leaves every role alone.
//
// Groups match like AllowedGroups -- trimmed, case-insensitive, by the
// same groupname.Match -- and the highest wins, so the result does not
// depend on the order the provider lists groups in. Only user and
// viewer are ever given: gate.New refuses any other value, and one that
// got past it here would fall to the lowest role rather than a higher
// one (ADR-0013).
func (g *Gate) ssoRoleFor(identity *oidc.Identity) (gauntlet.Role, bool) {
	p := g.deps.OIDCPolicy
	if len(p.RoleFromGroups) == 0 {
		return "", false
	}
	var best gauntlet.Role
	for _, group := range p.Groups(identity) {
		for name, value := range p.RoleFromGroups {
			if !groupname.Match(group, name) {
				continue
			}
			role := gauntlet.Role(value)
			if role != gauntlet.RoleUser && role != gauntlet.RoleViewer {
				continue
			}
			if best == "" || role.AtLeast(best) {
				best = role
			}
		}
	}
	if best != "" {
		return best, true
	}
	if gauntlet.Role(p.RoleWithoutGroup) == gauntlet.RoleUser {
		return gauntlet.RoleUser, true
	}
	return gauntlet.RoleViewer, true
}

// recordSSORoleChange does what handleSetRole does after a role change,
// for the change an SSO sign-in made: drop the in-memory sessions of a
// downgrade (the store already recorded SessionsEndedAt), write the
// audit line with actor "sso", and tell the application. The sign-in
// that follows issues its session at the new role.
func (g *Gate) recordSSORoleChange(r *http.Request, signIn gauntlet.OIDCSignIn, issuer string, now time.Time) {
	user := signIn.User
	if signIn.SessionsEnded {
		g.deps.Sessions.RevokeAllForUser(user.ID)
	}
	detail := fmt.Sprintf("from=%s to=%s; by group map at issuer %q", signIn.RoleBefore, user.Role, issuer)
	if signIn.SessionsEnded {
		detail += "; sessions ended: all"
	}
	g.audit(r, ssoAuditActor, "user.role_changed", user.Username, detail)
	g.notify(r.Context(), &AccountNotice{
		Kind: NoticeRoleChanged, UserID: user.ID, Username: user.Username, Role: user.Role, At: now,
		RoleChanged: &RoleChangeDetail{From: signIn.RoleBefore, To: user.Role, ViaSSO: true},
	})
}

// ssoAuditActor is the audit actor of a change the identity provider
// caused: no admin did it, and the account's own holder did not ask.
const ssoAuditActor = "sso"

// ssoUsernameHint is the name an identity asks to be known by: its
// preferred_username, else its email.
func ssoUsernameHint(identity *oidc.Identity) string {
	if identity.PreferredUsername != "" {
		return identity.PreferredUsername
	}
	return identity.Email
}
