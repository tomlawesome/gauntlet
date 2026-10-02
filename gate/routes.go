package gate

import (
	"net/http"

	"github.com/tomlawesome/gauntlet"
)

// Routes serves /api/auth/* and /api/tokens[/{id}] with mikroview's
// paths, request and response bodies (docs/design.md §1.5): session,
// register, login (single- and second-factor step), logout, logout-all,
// password, users list/create/delete/reset-password, TOTP enrol/
// confirm/delete plus the admin clear route, recovery-codes regenerate,
// the passkey list/register/rename/delete routes, the passkey login
// begin and the admin clear route (G8, ADR-0004; all 404 while
// Deps.Passkeys is nil), the OIDC login/callback/link trio, and tokens
// list/create/revoke.
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

	mux.Handle("GET /api/auth/users", RequireRole(gauntlet.RoleAdmin, http.HandlerFunc(g.handleListUsers)))
	mux.Handle("POST /api/auth/users", RequireRole(gauntlet.RoleAdmin, http.HandlerFunc(g.handleCreateUser)))
	mux.Handle("DELETE /api/auth/users/{id}", RequireRole(gauntlet.RoleAdmin, http.HandlerFunc(g.handleDeleteUser)))
	mux.Handle("POST /api/auth/users/{id}/reset-password", RequireRole(gauntlet.RoleAdmin, http.HandlerFunc(g.handleResetPassword)))
	mux.Handle("DELETE /api/auth/users/{id}/totp", RequireRole(gauntlet.RoleAdmin, http.HandlerFunc(g.handleTOTPAdminClear)))
	mux.Handle("DELETE /api/auth/users/{id}/passkeys", RequireRole(gauntlet.RoleAdmin, http.HandlerFunc(g.handlePasskeysAdminClear)))

	mux.Handle("GET /api/tokens", RequireRole(gauntlet.RoleAdmin, http.HandlerFunc(g.handleTokensList)))
	mux.Handle("POST /api/tokens", RequireRole(gauntlet.RoleAdmin, http.HandlerFunc(g.handleTokensCreate)))
	mux.Handle("DELETE /api/tokens/{id}", RequireRole(gauntlet.RoleAdmin, http.HandlerFunc(g.handleTokensRevoke)))

	return mux
}
