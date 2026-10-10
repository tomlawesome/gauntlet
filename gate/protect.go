package gate

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// csrfHeaderName is fixed -- security behaviour, not application taste
// (docs/design.md §1.5). Its required value is Config.CSRFHeaderValue.
const csrfHeaderName = "X-Requested-With"

// changePasswordPath is the one route a session flagged
// MustChangePassword may still reach (mikroview's #1251) -- named once
// here rather than written as a literal in Protect, so the gate and the
// route table (routes.go) cannot drift apart silently.
const changePasswordPath = "/api/auth/password"

// The rest of the /api/auth/* paths the exempt lists and
// secondFactorEnrolPaths below name, held as constants for the same
// reason changePasswordPath is: routes.go registers each of them from
// these, so a route cannot move without its exemption moving with it.
const (
	sessionPath      = "/api/auth/session"
	registerPath     = "/api/auth/register"
	loginPath        = "/api/auth/login"
	loginFactorPath  = "/api/auth/login/factor"
	loginConfirmPath = "/api/auth/login/confirm"
	// loginProveBeginPath and loginProvePath finish a sign-in held for a
	// passkey (#65, ADR-0009; provelogin.go).
	loginProveBeginPath = "/api/auth/login/prove/begin"
	loginProvePath      = "/api/auth/login/prove"
	loginEscapePath     = "/api/auth/login/escape"
	logoutPath          = "/api/auth/logout"
	oidcPathPrefix      = "/api/auth/oidc"
	oidcLoginPath       = "/api/auth/oidc/login"
	oidcCallbackPath    = "/api/auth/oidc/callback"
	totpEnrolPath       = "/api/auth/totp/enrol"
	totpConfirmPath     = "/api/auth/totp/confirm"
	sessionsPath        = "/api/auth/sessions"
	unlockPath          = "/api/auth/unlock"

	// reauthenticatePath resumes a session that timed out with the
	// password alone (#71; reauthenticate_handler.go).
	reauthenticatePath = "/api/auth/reauthenticate"

	// enrolmentConfirmPath is where a held first factor and its
	// recovery codes are confirmed (#58; recoverycodes_handler.go).
	enrolmentConfirmPath = "/api/auth/recovery-codes/confirm"

	passkeysPath              = "/api/auth/passkeys"
	passkeyRegisterBeginPath  = "/api/auth/passkeys/register/begin"
	passkeyRegisterFinishPath = "/api/auth/passkeys/register/finish"
	loginFactorBeginPath      = "/api/auth/login/factor/begin"

	// loginPasskeyBeginPath and loginPasskeyPath are signing in with a
	// passkey alone (#77, ADR-0012; login_passkey_handler.go). Both
	// answer 404 unless Config.PasskeySignIn is set and the relying
	// party can do it.
	loginPasskeyBeginPath = "/api/auth/login/passkey/begin"
	loginPasskeyPath      = "/api/auth/login/passkey"

	// stepUpPasskeyBeginPath starts a passkey step-up for a signed-in
	// caller (#82; stepup_passkey_handler.go): the assertion it asks for
	// is the alternative to a code on every recheckStepUp route.
	stepUpPasskeyBeginPath = "/api/auth/step-up/passkey/begin"
)

// exemptPaths lists routes reachable without a session once an account
// exists -- either because they must work before one does (register,
// login) or because logout without a session is a harmless no-op, not
// worth a 401 for. Beyond the built-in set, an application adds its own
// with Exempt.
//
// POST /api/auth/login/factor is the second half of a login that stopped
// at handleLogin because the account holds an active second factor --
// reached with the short-lived pending-login cookie, never a session, so
// it has to work before one exists, same reasoning as /api/auth/login
// itself. POST /api/auth/login/factor/begin, which starts the passkey
// half of that step (G8), is reached the same way for the same reason.
// POST /api/auth/login/passkey/begin and /api/auth/login/passkey sign in
// with a passkey alone (#77): no session and no pending login, only the
// ceremony cookie the begin route set. POST /api/auth/login/prove/begin
// and /api/auth/login/prove finish a sign-in held for a passkey (#65):
// only the confirm ticket, as login/confirm has.
//
// GET /api/auth/oidc/login and /callback are a top-level
// browser redirect/navigation the provider issues, not a fetch() an
// application's frontend controls -- being listed here is what exempts
// them from requiring an existing session (state/nonce/PKCE, oidc.go, is
// the callback's real protection against a forged request, not the
// session check); isSafeMethod already exempts both from the CSRF-header
// check since they're GET.
//
// POST /api/auth/unlock is how the admin, disabled after a run of failed
// sign-ins with no other admin to unlock them, redeems the one-time code
// from the server's log (#44): by definition they cannot sign in to
// reach it. It only lifts the disable; it issues no session. Not in
// bootstrapExemptPaths: with no account there is nothing to unlock.
//
// POST /api/auth/reauthenticate resumes a session that has timed out
// (#71): by definition the caller has no live session to present, only
// the timed-out one's cookie, which the handler reads itself. It is
// session-exempt like login and still needs the CSRF header. Not in
// bootstrapExemptPaths: with no account there is no session to resume.
var exemptPaths = map[string]bool{
	"/api/healthz":        true,
	sessionPath:           true,
	registerPath:          true,
	loginPath:             true,
	logoutPath:            true,
	loginFactorPath:       true,
	loginFactorBeginPath:  true,
	loginPasskeyBeginPath: true,
	loginPasskeyPath:      true,
	loginConfirmPath:      true,
	loginProveBeginPath:   true,
	loginProvePath:        true,
	loginEscapePath:       true,
	oidcLoginPath:         true,
	oidcCallbackPath:      true,
	unlockPath:            true,
	reauthenticatePath:    true,
}

// bootstrapExemptPaths is the narrower set reachable while no account
// exists yet -- only what is needed to show and complete the one-time
// account-creation screen. Deliberately not extendable by Exempt: it is
// the highest-consequence window there is (the next request to
// /api/auth/register creates the permanent admin), so widening it is a
// decision for this package, not a per-application setting.
//
// The OIDC login/callback pair is not here: SSO never creates the first
// account (gauntlet.ErrSetupRequired, issue #37, ADR-0003). The first
// admin is a local account created with the setup code from the
// server's log, and links SSO afterwards. Before #37 the pair was
// exempt so the first-ever login could be through SSO; that made the
// first visitor at the IdP the admin.
var bootstrapExemptPaths = map[string]bool{
	"/api/healthz": true,
	sessionPath:    true,
	registerPath:   true,
}

// secondFactorEnrolPaths are the routes a session may still reach while
// stuck at the forced-enrolment door (always shut for a local-password
// account with no second factor, since #49) -- enrolling a TOTP factor
// or registering a passkey, and confirming the held first factor's
// recovery codes (#58: the factor is not live, so the door holds, until
// that confirmation), and nothing else, as mikroview's requireAuth has
// it. The admin passkey door (#82) admits the same routes. Named once here, the same reasoning
// changePasswordPath is, so Protect's gate and this list cannot drift
// apart silently. With Deps.Passkeys nil the passkey pair answers 404,
// so admitting it opens nothing.
//
// Deliberately excludes DELETE /api/auth/totp and the passkey list,
// rename and delete routes: there is nothing yet enrolled for them to
// act on while this gate holds, and admitting them would be surface this
// door has no reason to open.
var secondFactorEnrolPaths = map[string]bool{
	totpEnrolPath:             true,
	totpConfirmPath:           true,
	passkeyRegisterBeginPath:  true,
	passkeyRegisterFinishPath: true,
	enrolmentConfirmPath:      true,
}

func isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

// csrfOK requires the CSRF header on an unsafe method, writing the 403
// itself when it is missing -- the one check Protect makes in both its
// undecided and active states. A refusal leaves a rated Warn line
// (#45, ASVS 16.3.3).
func (g *Gate) csrfOK(w http.ResponseWriter, r *http.Request) bool {
	if !isSafeMethod(r.Method) && r.Header.Get(csrfHeaderName) != g.cfg.CSRFHeaderValue {
		g.warnRefused(r, "csrf", "gate: refused a request without the CSRF header")
		writeProblem(w, http.StatusForbidden, classCSRFRequired, "missing required header", nil)
		return false
	}
	return true
}

const bearerPrefix = "Bearer "

// bearerToken extracts the raw token value from an Authorization: Bearer
// <token> header, reporting false for a header that is missing or not
// in that form (Protect refuses the latter). The scheme name is matched case-insensitively --
// RFC 7235 §2.1 defines auth-scheme as a token compared case-
// insensitively, so "bearer x" and "BEARER x" are both bearer
// authentication, not "no token" falling through to the session-cookie
// path. Only the scheme name folds case; the token value after it is
// passed through exactly as sent.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < len(bearerPrefix) || !strings.EqualFold(h[:len(bearerPrefix)], bearerPrefix) {
		return "", false
	}
	return h[len(bearerPrefix):], true
}

// sessionUser resolves r's session cookie to a user, if any -- shared by
// Protect and handleSession so the invalidation rules (expiry, unknown
// user, and a session issued before the account's sessions were last
// ended -- a password change, a reset or an SSO link; see
// gauntlet.User.SessionCutoff) live in exactly one place. A session that
// fails that check is proactively revoked here rather than left to
// expire naturally, since it is already known to be invalid.
func (g *Gate) sessionUser(r *http.Request, now time.Time) (*gauntlet.User, bool) {
	cookie, err := r.Cookie(g.sessionCookieName())
	if err != nil {
		return nil, false
	}
	sess, ok := g.deps.Sessions.Validate(cookie.Value, now)
	if !ok {
		return nil, false
	}
	user, ok := g.deps.Users.Get(sess.UserID)
	if !ok {
		return nil, false
	}
	if sess.IssuedAt.Before(user.SessionCutoff()) {
		g.deps.Sessions.Revoke(sess.ID)
		return nil, false
	}
	return user, true
}

// Handle registers h as the handler bearer tokens of kind are dispatched
// to -- e.g. TokenKindAPI -> the application's read-only mux
// (docs/design.md §1.5). Bearer tokens are tried against every
// registered kind in the order Handle was called for it; a match is
// dispatched to that kind's handler and never to next. Calling Handle
// again for a kind already registered replaces its handler without
// changing its position in that order.
//
// Like Exempt, this is setup state a caller wires once before Protect
// ever serves a request -- not safe to call concurrently with a request
// in flight.
func (g *Gate) Handle(kind gauntlet.TokenKind, h http.Handler) {
	if _, exists := g.kindHandlers[kind]; !exists {
		g.kindOrder = append(g.kindOrder, kind)
	}
	g.kindHandlers[kind] = h
}

// Exempt adds paths reachable without a session, beyond the built-in
// /api/auth/* set (exemptPaths above). Like Handle, this is setup state
// wired once before Protect serves any request.
func (g *Gate) Exempt(paths ...string) {
	for _, p := range paths {
		g.exempt[p] = true
	}
}

func (g *Gate) isExempt(path string) bool {
	return exemptPaths[path] || g.exempt[path]
}

// writeUnauthorized answers a 401 with the WWW-Authenticate header RFC
// 9110 §15.5.2 requires on every 401 -- see rest.go's own doc comment on
// why this covers session-cookie paths too, not just bearer-token ones.
// class is explicit at every call site (invalid-credentials, sign-in-
// required or step-expired -- the three classes a 401 ever carries),
// never derived from msg.
func writeUnauthorized(w http.ResponseWriter, class problemClass, msg string) {
	writeUnauthorizedWith(w, class, msg, nil)
}

// writeUnauthorizedWith is writeUnauthorized with writeProblem's extra
// members: only a refused passkey's unknownCredential (#92) passes any.
func writeUnauthorizedWith(w http.ResponseWriter, class problemClass, msg string, extra map[string]any) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="gate"`)
	writeProblem(w, http.StatusUnauthorized, class, msg, extra)
}

// authGateHeader marks a 403 that means "sign-in worked, but this
// session is stuck at a door" (MustChangePassword or the missing-
// second-factor gate) rather than an ordinary refusal (wrong role,
// missing CSRF header). Ported from mikroview's own fix for exactly this
// (gitlab/dev 683704c4, forcedAuthGateHeader): its frontend had no way
// to tell these apart from any other 403 except by matching the 403's
// prose, so an existing session that a deploy turned into one of these
// would show it as a plain error instead of routing to the door that
// gets it out. Read by a frontend's shared fetch wrapper and matched on
// this header's value, never on the message text, which stays free to
// reword.
//
// Named generically here, unlike mikroview's own
// "X-Mikroview-Auth-Gate": this header is gate's, not any one
// application's, so its name is fixed security behaviour the same way
// csrfHeaderName's is, and does not belong on the "must not leak into
// birdcage" list docs/design.md §1.5 keeps for mikroview-branded
// strings.
const authGateHeader = "X-Auth-Gate"

const (
	authGateMustChangePassword = "must-change-password"
	authGateMustEnrolFactor    = "must-enrol-factor"
	// authGateMustEnrolPasskey is the admin passkey door (#82,
	// ADR-0015): an admin account with no passkey usable here, while
	// Config.AdminPasskey is AdminPasskeyRequired.
	authGateMustEnrolPasskey = "must-enrol-passkey"
)

// writeForcedAuthGate is writeUnauthorized's sibling for these three
// doors: sets the machine-readable header before the human-readable
// body, the same shape as that helper's WWW-Authenticate header.
// gateName is always one of authGateMustChangePassword,
// authGateMustEnrolFactor or authGateMustEnrolPasskey, which are also
// exactly the anchors of the three classes a forced gate ever answers
// with, so the class follows from gateName rather than being another,
// independently-written parameter the two could drift apart from.
func writeForcedAuthGate(w http.ResponseWriter, gateName, msg string) {
	w.Header().Set(authGateHeader, gateName)
	class := classMustChangePassword
	switch gateName {
	case authGateMustEnrolFactor:
		class = classMustEnrolFactor
	case authGateMustEnrolPasskey:
		class = classMustEnrolPasskey
	}
	writeProblem(w, http.StatusForbidden, class, msg, nil)
}

// Protect is mikroview's requireAuth, generalized over an application's
// own Config/Deps (docs/design.md §1.5). It has two states, checked in
// order, plus bearer-token dispatch nested inside the second -- the same
// shape mikroview's own doc comment on requireAuth describes:
//
//  1. Undecided (Users.Count()==0): only bootstrapExemptPaths stay
//     reachable, so live data behind next cannot be read by whoever
//     reaches the application before an account exists. A mutating
//     bootstrap-exempt request (only POST /api/auth/register is one)
//     still needs the CSRF header: there is no session yet to carry the
//     ordinary check, but register is the highest-consequence route
//     there is.
//  2. Active: a bearer token, if present, is tried against every kind
//     registered with Handle, in that order; a match dispatches to that
//     kind's handler and never to next, and an Authorization header that
//     matches no registered kind is rejected outright (never silently
//     treated as "no token" and passed on to the session-cookie check),
//     as is one that is not a well-formed Bearer credential at all.
//     Otherwise: the CSRF header on unsafe methods, exempt paths, the
//     session cookie, the MustChangePassword door (which also holds an
//     admin with no local password while the admin passkey rule is
//     on), the admin passkey door (#82), then the second-factor door
//     (always on, since #49), then next.
func (g *Gate) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := g.now()
		// The ESCAPED path, not the decoded one: http.ServeMux's own
		// pattern matching works on r.URL.EscapedPath() (a request for
		// "/api/auth%2Fsession" matches a registered "/api/{resource}"
		// pattern, never "/api/auth/session" -- %2F stays inside one
		// path segment rather than splitting it in two). Every
		// exempt/bootstrap/door comparison below has to use the same
		// path the mux will actually dispatch on, or a path that is
		// exempt only after decoding is treated as exempt here while
		// dispatching somewhere this check never intended to admit
		// (issue #13).
		path := r.URL.EscapedPath()

		if g.deps.Users.Count() == 0 {
			if !bootstrapExemptPaths[path] {
				writeProblem(w, http.StatusServiceUnavailable, classSetupRequired, "setup required", nil)
				return
			}
			if !g.csrfOK(w, r) {
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		if raw, ok := bearerToken(r); ok {
			for _, kind := range g.kindOrder {
				if tok, valid := g.deps.Tokens.Authenticate(raw, kind, now); valid {
					h := g.kindHandlers[kind]
					h.ServeHTTP(w, r.WithContext(withToken(r.Context(), tok)))
					return
				}
			}
			writeUnauthorized(w, classInvalidCredentials, "invalid or revoked token")
			return
		}
		// An Authorization header that is there but is not a
		// well-formed "Bearer <token>" -- another scheme, a bare
		// "Bearer", a tab for the space -- is refused the same way,
		// not skipped: skipping it let the request through on its
		// session cookie instead (#41). Only a request with no
		// Authorization header at all goes on to the cookie.
		if _, sent := r.Header["Authorization"]; sent {
			g.warnRefused(r, "authorization", "gate: refused a malformed Authorization header")
			writeUnauthorized(w, classInvalidCredentials, "invalid or revoked token")
			return
		}

		if !g.csrfOK(w, r) {
			return
		}
		if g.isExempt(path) {
			next.ServeHTTP(w, r)
			return
		}

		user, ok := g.sessionUser(r, now)
		if !ok {
			writeUnauthorized(w, classSignInRequired, "unauthorized")
			return
		}
		// docs/design.md §4's fail-closed list: "Unknown role → denied
		// everything." Checked here, before either door below, because
		// neither of them is what this is about -- a role no
		// CreateUser/Register call could ever produce only reaches a
		// live User via a document written outside this package (see
		// Role.rank's own doc comment), and the right response to that
		// is refusing the request outright, not routing it through
		// checks that assume a real tier. Without this, an ordinary
		// session-gated route with no RequireRole wrapper at all -- most
		// of an application's own routes -- let such an account straight
		// through; only a RequireRole-wrapped route ever consulted
		// Role.AtLeast (issue #14).
		if !isKnownRole(user.Role) {
			g.warnRefused(r, "role", fmt.Sprintf("gate: refused account %q: its role is not recognized", user.Username))
			writeProblem(w, http.StatusForbidden, classForbidden, "account role is not recognized", nil)
			return
		}
		// Two things set MustChangePassword: an administrator's reset,
		// and a run of failed second-factor steps that says someone else
		// knows the password (gauntlet.LoginLimiter.SecondFactorFailed,
		// #44). The account carries no record of which, so the message
		// names neither.
		//
		// Only for an account with a local password: one that signs in
		// through its identity provider has no password to change, and
		// the one route this door admits refuses it, so the door would
		// shut it out of everything. The store no longer sets the flag on
		// such an account, but a document written before that may carry
		// it.
		if user.MustChangePassword && user.LocalPassword() && path != changePasswordPath {
			g.warnRefused(r, "door", fmt.Sprintf("gate: refused account %q at the %s door", user.Username, authGateMustChangePassword))
			writeForcedAuthGate(w, authGateMustChangePassword, "this account's password must be changed -- set a new password before going any further")
			return
		}
		// An admin with no local password -- an SSO-only account promoted
		// to admin -- is held at the same door while the admin passkey
		// rule is on (#82 decision 5): registering a passkey needs a local
		// password (ADR-0004), so the chain is password, then passkey,
		// then admin. The one route admitted sets the first password from
		// a fresh SSO sign-in (handleChangePassword).
		if g.adminPasskeyRuleOn() && user.Role == gauntlet.RoleAdmin && !user.LocalPassword() && path != changePasswordPath {
			g.warnRefused(r, "door", fmt.Sprintf("gate: refused account %q at the %s door", user.Username, authGateMustChangePassword))
			writeForcedAuthGate(w, authGateMustChangePassword, "this admin account has no local password -- set one before going any further")
			return
		}
		// The admin passkey door (#82, ADR-0015): while the rule is on, an
		// admin account is held until it holds a passkey usable under the
		// relying party's current RP ID -- an authenticator app alone
		// never opens it. Checked before the any-factor door below, so an
		// admin with no factor at all is told the one thing that opens
		// this one; the same enrolment routes are admitted, and TOTP
		// enrolment still works there. The !MustChangePassword guard keeps
		// the no-deadlock property the door below documents.
		if g.adminMustEnrolPasskey(user) && !secondFactorEnrolPaths[path] {
			g.warnRefused(r, "door", fmt.Sprintf("gate: refused account %q at the %s door", user.Username, authGateMustEnrolPasskey))
			writeForcedAuthGate(w, authGateMustEnrolPasskey, "this admin account has no passkey -- register one before going any further")
			return
		}
		// The forced-enrolment door (mikroview's #1253), always shut for
		// every local-password account since #49 -- a second factor is
		// mandatory, not an application's choice, so this no longer reads
		// Config.RequireSecondFactor (deprecated; see that field's doc
		// comment).
		//
		// The !user.MustChangePassword guard is what stops this door and
		// the one above deadlocking each other: MustChangePassword's own
		// gate lets exactly one path through while it is set --
		// changePasswordPath -- and that path is not exempted from
		// this one below. Without the guard, a reset-code account with
		// no second factor would fall through to this gate on its one
		// admitted path and be refused that too: 403 on the only route
		// that could ever get it out of MustChangePassword, with no
		// request from that account able to escape (mikroview's own fix
		// for exactly this, gitlab/dev 683704c4).
		//
		// secondFactorEnrolPaths (TOTP enrol/confirm, passkey register
		// begin/finish, the held factor's confirmation) stays reachable
		// while this door holds -- without it, a newly created local
		// account with no factor yet would have no route left to enrol
		// one on.
		if !user.MustChangePassword && user.LocalPassword() && !user.HasSecondFactor() && !secondFactorEnrolPaths[path] {
			g.warnRefused(r, "door", fmt.Sprintf("gate: refused account %q at the %s door", user.Username, authGateMustEnrolFactor))
			writeForcedAuthGate(w, authGateMustEnrolFactor, "this account has no second factor -- enrol one before going any further")
			return
		}
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), user)))
	})
}

// adminPasskeyRuleOn reports whether every admin must hold a passkey
// here (Config.AdminPasskey, #82). New has already refused an unset
// value, and AdminPasskeyRequired without a ready relying party.
func (g *Gate) adminPasskeyRuleOn() bool {
	return g.cfg.AdminPasskey == AdminPasskeyRequired
}

// adminMustEnrolPasskey reports whether u is held at the admin passkey
// door, ignoring which route was asked for: the rule is on, u is an
// admin with a local password and no forced password change pending,
// and holds no passkey usable under the current RP ID. Protect and the
// session body (mustEnrolPasskey) both read it.
func (g *Gate) adminMustEnrolPasskey(u *gauntlet.User) bool {
	return g.adminPasskeyRuleOn() && u.Role == gauntlet.RoleAdmin &&
		!u.MustChangePassword && u.LocalPassword() && g.usablePasskeyCount(u) == 0
}

// isKnownRole reports whether r is one of the three roles this package
// actually assigns (docs/design.md §4's fail-closed list names the
// alternative: "Unknown role → denied everything"). gauntlet.Role.rank
// already ranks an unrecognized value at 0, below every named tier, but
// that alone only matters to a caller that compares ranks -- Protect's
// own check (above) and RequireRole's panic guard (below) are what
// actually act on it.
func isKnownRole(r gauntlet.Role) bool {
	switch r {
	case gauntlet.RoleAdmin, gauntlet.RoleUser, gauntlet.RoleViewer:
		return true
	default:
		return false
	}
}

// RequireRole wraps next so that a caller below min is refused with 403.
// It reads the caller from context (UserFromContext), so it belongs
// after Protect in a handler chain, never before: Protect is what puts
// the user there in the first place. A request with no user in context
// -- Count()==0's undecided state, an exempt path, or a bearer-token
// request, none of which ever populate it -- is refused the same way a
// real caller below min is, since gauntlet.Role's own AtLeast ranks a
// nil/unknown role below every named tier.
//
// Panics immediately -- at construction, not on the first request -- if
// min itself is not a recognized role: a caller passing anything else is
// a wiring mistake in this package's own route table, the same class of
// error a typo'd route pattern would be, and the way to catch it is
// failing loudly at startup rather than quietly admitting nothing to a
// route no request could ever satisfy (issue #14).
func RequireRole(min gauntlet.Role, next http.Handler) http.Handler {
	return requireRole(min, next, nil)
}

// requireRole is RequireRole, calling refused (when set) before it
// writes a 403.
func requireRole(min gauntlet.Role, next http.Handler, refused func(r *http.Request, min gauntlet.Role)) http.Handler {
	if !isKnownRole(min) {
		panic("gate: RequireRole given an unrecognized role: " + string(min))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r)
		if user == nil || !user.Role.AtLeast(min) {
			if refused != nil {
				refused(r, min)
			}
			writeProblem(w, http.StatusForbidden, classForbidden, "insufficient role", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// adminOnly is RequireRole(gauntlet.RoleAdmin, next) for Routes' own
// admin routes: a refusal also leaves a rated Warn line (#45, ASVS
// 16.3.2). An application's own RequireRole wrapping writes none -- it
// has no Gate to log through. A function rather than a Gate method so
// each route line names exactly one method of g, the handler (the
// contract test reads routes.go for it).
func adminOnly(g *Gate, next http.HandlerFunc) http.Handler {
	return requireRole(gauntlet.RoleAdmin, next, func(r *http.Request, min gauntlet.Role) {
		who := "a request with no signed-in account"
		if u := UserFromContext(r); u != nil {
			who = fmt.Sprintf("account %q", u.Username)
		}
		g.warnRefused(r, "role", fmt.Sprintf("gate: insufficient role: refused %s at a %s route", who, min))
	})
}

// warnRefused writes a rated Warn line (warnRated) for a refused
// request: kind names the refusal, and with the client address makes
// the key. msg gains the method, the path and the address, all quoted:
// each is the client's to choose.
func (g *Gate) warnRefused(r *http.Request, kind, msg string) {
	address := g.cfg.ClientIP(r)
	g.warnRated(kind+" "+address, fmt.Sprintf("%s: %q %q from=%q", msg, r.Method, r.URL.EscapedPath(), address))
}
