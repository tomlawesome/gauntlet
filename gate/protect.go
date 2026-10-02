package gate

import (
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
	logoutPath       = "/api/auth/logout"
	oidcLoginPath    = "/api/auth/oidc/login"
	oidcCallbackPath = "/api/auth/oidc/callback"
	totpEnrolPath    = "/api/auth/totp/enrol"
	totpConfirmPath  = "/api/auth/totp/confirm"

	passkeysPath              = "/api/auth/passkeys"
	passkeyRegisterBeginPath  = "/api/auth/passkeys/register/begin"
	passkeyRegisterFinishPath = "/api/auth/passkeys/register/finish"
	loginFactorBeginPath      = "/api/auth/login/factor/begin"
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
// half of that step (G8), is reached the same way for the same reason. GET /api/auth/oidc/login and /callback are a top-level
// browser redirect/navigation the provider issues, not a fetch() an
// application's frontend controls -- being listed here is what exempts
// them from requiring an existing session (state/nonce/PKCE, oidc.go, is
// the callback's real protection against a forged request, not the
// session check); isSafeMethod already exempts both from the CSRF-header
// check since they're GET.
var exemptPaths = map[string]bool{
	"/api/healthz":       true,
	sessionPath:          true,
	registerPath:         true,
	loginPath:            true,
	logoutPath:           true,
	loginFactorPath:      true,
	loginFactorBeginPath: true,
	oidcLoginPath:        true,
	oidcCallbackPath:     true,
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
// stuck at the forced-enrolment door (Config.RequireSecondFactor) --
// enrolling a TOTP factor or registering a passkey, and nothing else, as
// mikroview's requireAuth has it. Named once here, the same reasoning
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
}

func isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

// csrfOK requires the CSRF header on an unsafe method, writing the 403
// itself when it is missing -- the one check Protect makes in both its
// undecided and active states.
func (g *Gate) csrfOK(w http.ResponseWriter, r *http.Request) bool {
	if !isSafeMethod(r.Method) && r.Header.Get(csrfHeaderName) != g.cfg.CSRFHeaderValue {
		http.Error(w, "missing required header", http.StatusForbidden)
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
func writeUnauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="gate"`)
	http.Error(w, msg, http.StatusUnauthorized)
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
)

// writeForcedAuthGate is writeUnauthorized's sibling for this pair of
// doors: sets the machine-readable header before the human-readable
// body, the same shape as that helper's WWW-Authenticate header.
func writeForcedAuthGate(w http.ResponseWriter, gateName, msg string) {
	w.Header().Set(authGateHeader, gateName)
	http.Error(w, msg, http.StatusForbidden)
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
//     session cookie, the MustChangePassword door, then -- when
//     Config.RequireSecondFactor is set -- the second-factor door, then
//     next.
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
				http.Error(w, "setup required", http.StatusServiceUnavailable)
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
			writeUnauthorized(w, "invalid or revoked token")
			return
		}
		// An Authorization header that is there but is not a
		// well-formed "Bearer <token>" -- another scheme, a bare
		// "Bearer", a tab for the space -- is refused the same way,
		// not skipped: skipping it let the request through on its
		// session cookie instead (#41). Only a request with no
		// Authorization header at all goes on to the cookie.
		if _, sent := r.Header["Authorization"]; sent {
			writeUnauthorized(w, "invalid or revoked token")
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
			writeUnauthorized(w, "unauthorized")
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
			http.Error(w, "account role is not recognized", http.StatusForbidden)
			return
		}
		if user.MustChangePassword && path != changePasswordPath {
			writeForcedAuthGate(w, authGateMustChangePassword, "an administrator reset this account -- set a new password before going any further")
			return
		}
		// The forced-enrolment door (mikroview's #1253), gated by
		// Config.RequireSecondFactor rather than always on -- see that
		// field's doc comment.
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
		// begin/finish) stays reachable
		// while this door holds -- without it, an account with
		// RequireSecondFactor set and no factor yet would have no route
		// left to enrol one on.
		if !user.MustChangePassword && g.cfg.RequireSecondFactor && user.LocalPassword() && !user.HasSecondFactor() && !secondFactorEnrolPaths[path] {
			writeForcedAuthGate(w, authGateMustEnrolFactor, "this account has no second factor -- enrol one before going any further")
			return
		}
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), user)))
	})
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
	if !isKnownRole(min) {
		panic("gate: RequireRole given an unrecognized role: " + string(min))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r)
		if user == nil || !user.Role.AtLeast(min) {
			http.Error(w, "insufficient role", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
