package gate

import "net/http"

// Routes serves /api/auth/* and /api/tokens[/{id}] with mikroview's
// paths, request and response bodies (docs/design.md §1.5): session,
// register, login (single- and second-factor step), logout, logout-all,
// the caller's own session list and end-one-session route, password,
// the lone-admin unlock-code route (#44),
// users list/create/delete/reset-password/unlock/logout-all, the
// sign-in history (#53; 404 while Deps.SignIns is nil), TOTP enrol/confirm/delete
// plus the admin clear route, recovery-codes regenerate and the
// confirmation of a held first factor's codes (#58), the passkey
// list/register/rename/delete routes, the passkey login begin and the
// admin clear route (G8, ADR-0004; all 404 while Deps.Passkeys is nil),
// the OIDC login/callback/link trio, and tokens list/create/revoke.
//
// Mount the result under the same Protect that guards the rest of the
// application: Routes does not call Protect itself, and the admin-only
// handlers below rely on Protect having already put the caller in
// context for RequireRole to read.
func (g *Gate) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET "+sessionPath, g.handleSession)
	mux.HandleFunc("POST "+registerPath, g.handleRegister)
	mux.HandleFunc("POST "+loginPath, g.handleLogin)
	mux.HandleFunc("POST "+loginFactorPath, g.handleLoginFactor)
	mux.HandleFunc("POST "+logoutPath, g.handleLogout)
	mux.HandleFunc("POST /api/auth/logout-all", g.handleLogoutAll)
	mux.HandleFunc("POST "+changePasswordPath, g.handleChangePassword)
	mux.HandleFunc("GET "+sessionsPath, g.handleSessionsList)
	mux.HandleFunc("DELETE "+sessionsPath+"/{ref}", g.handleSessionEnd)
	mux.HandleFunc("POST "+unlockPath, g.handleUnlockCode)

	mux.HandleFunc("POST "+totpEnrolPath, g.handleTOTPEnrol)
	mux.HandleFunc("POST "+totpConfirmPath, g.handleTOTPConfirm)
	mux.HandleFunc("DELETE /api/auth/totp", g.handleTOTPDelete)
	mux.HandleFunc("POST /api/auth/recovery-codes", g.handleRecoveryCodesRegenerate)
	mux.HandleFunc("POST "+enrolmentConfirmPath, g.handleEnrolmentConfirm)

	mux.HandleFunc("GET "+passkeysPath, g.handlePasskeysList)
	mux.HandleFunc("POST "+passkeyRegisterBeginPath, g.handlePasskeyRegisterBegin)
	mux.HandleFunc("POST "+passkeyRegisterFinishPath, g.handlePasskeyRegisterFinish)
	mux.HandleFunc("PATCH "+passkeysPath+"/{id}", g.handlePasskeyRename)
	mux.HandleFunc("DELETE "+passkeysPath+"/{id}", g.handlePasskeyDelete)
	mux.HandleFunc("POST "+loginFactorBeginPath, g.handleLoginFactorBegin)

	mux.HandleFunc("GET "+oidcLoginPath, g.handleOIDCLogin)
	mux.HandleFunc("GET "+oidcCallbackPath, g.handleOIDCCallback)
	mux.HandleFunc("POST /api/auth/oidc/link", g.handleOIDCLinkStart)

	mux.Handle("GET /api/auth/users", adminOnly(g, g.handleListUsers))
	mux.Handle("POST /api/auth/users", adminOnly(g, g.handleCreateUser))
	mux.Handle("DELETE /api/auth/users/{id}", adminOnly(g, g.handleDeleteUser))
	mux.Handle("POST /api/auth/users/{id}/reset-password", adminOnly(g, g.handleResetPassword))
	mux.Handle("POST /api/auth/users/{id}/unlock", adminOnly(g, g.handleUnlockUser))
	mux.Handle("POST /api/auth/users/{id}/logout-all", adminOnly(g, g.handleAdminLogoutAll))
	mux.Handle("DELETE /api/auth/users/{id}/totp", adminOnly(g, g.handleTOTPAdminClear))
	mux.Handle("DELETE /api/auth/users/{id}/passkeys", adminOnly(g, g.handlePasskeysAdminClear))
	mux.Handle("GET /api/auth/sign-ins", adminOnly(g, g.handleSignInsList))

	mux.Handle("GET /api/tokens", adminOnly(g, g.handleTokensList))
	mux.Handle("POST /api/tokens", adminOnly(g, g.handleTokensCreate))
	mux.Handle("DELETE /api/tokens/{id}", adminOnly(g, g.handleTokensRevoke))

	return problemRouter{mux: mux}
}

// problemRouter wraps a ServeMux so a request matching no route, or
// matching one only under a different method, still answers
// application/problem+json (writeBlankProblem) instead of ServeMux's
// own text/plain body -- gauntlet #23's design decision for the two
// cases Routes itself never gets to choose a class for. The 405 case
// keeps the mux's own Allow header: see problemInterceptWriter.
type problemRouter struct {
	mux *http.ServeMux
}

// ServeHTTP asks the mux, read-only, whether r matches a route
// (Handler) before serving it for real: an empty pattern means it does
// not -- ServeMux's own "no route" and "wrong method" answer, which is
// safe to rewrite -- and a real pattern means a registered handler is
// about to run, whose own 404s and 409s (handleSessionEnd's "no such
// session", say) must reach the client exactly as it wrote them. Only
// the mux's own real ServeHTTP call, not Handler, fills in r.Pattern
// and the path wildcards a handler reads with r.PathValue -- Handler
// alone would leave every {id} and {ref} empty -- so it still runs
// exactly once per request either way, Handler being read-only ahead of
// it.
func (p problemRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, pattern := p.mux.Handler(r); pattern == "" {
		p.mux.ServeHTTP(&problemInterceptWriter{ResponseWriter: w}, r)
		return
	}
	p.mux.ServeHTTP(w, r)
}

// Mux returns the *http.ServeMux problemRouter wraps -- not for Routes'
// own callers, only for gate/contracttest's TestContractRoutesMatchDocument,
// which has to reach the live mux to confirm the route patterns it reads
// from this file's source are the ones actually served.
func (p problemRouter) Mux() *http.ServeMux { return p.mux }

// problemInterceptWriter rewrites the body net/http's own NotFound and
// MethodNotAllowed handling writes -- both go through http.Error,
// which sets its own Content-Type and X-Content-Type-Options before
// calling WriteHeader -- into writeBlankProblem's body instead, the
// moment either calls WriteHeader. The Allow header a 405 carries is
// set directly on the real ResponseWriter's header map before that,
// and is never touched here, so it survives unchanged.
type problemInterceptWriter struct {
	http.ResponseWriter
	rewriting bool
}

func (w *problemInterceptWriter) WriteHeader(status int) {
	if status == http.StatusNotFound || status == http.StatusMethodNotAllowed {
		w.rewriting = true
		writeBlankProblem(w.ResponseWriter, status)
		return
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *problemInterceptWriter) Write(b []byte) (int, error) {
	if w.rewriting {
		// Discard net/http's own text/plain body; writeBlankProblem
		// already wrote the real one from WriteHeader above.
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}
