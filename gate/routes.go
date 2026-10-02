package gate

import "net/http"

// Routes serves /api/auth/* and /api/tokens[/{id}] with mikroview's
// paths, request and response bodies (docs/design.md §1.5): session,
// register, login (single- and second-factor step), logout, logout-all,
// the caller's own session list and end-one-session route, password,
// the lone-admin unlock-code route (#44),
// users list/create/delete/reset-password/unlock, TOTP enrol/confirm/delete
// plus the admin clear route, recovery-codes regenerate, the passkey
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
	mux.Handle("DELETE /api/auth/users/{id}/totp", adminOnly(g, g.handleTOTPAdminClear))
	mux.Handle("DELETE /api/auth/users/{id}/passkeys", adminOnly(g, g.handlePasskeysAdminClear))

	mux.Handle("GET /api/tokens", adminOnly(g, g.handleTokensList))
	mux.Handle("POST /api/tokens", adminOnly(g, g.handleTokensCreate))
	mux.Handle("DELETE /api/tokens/{id}", adminOnly(g, g.handleTokensRevoke))

	return mux
}
