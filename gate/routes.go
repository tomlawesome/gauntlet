package gate

import (
	"net/http"

	"github.com/tomlawesome/gauntlet"
)

// Routes serves /api/auth/* and /api/tokens[/{id}] with mikroview's
// paths, request and response bodies (docs/design.md §1.5) -- the stage
// 1 subset: session, register, login, logout, logout-all, password,
// users list/create/delete, tokens list/create/revoke. Second-factor
// login, TOTP, admin password reset and the OIDC pair are stage 2 (see
// the "G6 stage 2" TODOs elsewhere in this package) and are not
// registered here.
//
// Mount the result under the same Protect that guards the rest of the
// application: Routes does not call Protect itself, and the admin-only
// handlers below rely on Protect having already put the caller in
// context for RequireRole to read.
func (g *Gate) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/auth/session", g.handleSession)
	mux.HandleFunc("POST /api/auth/register", g.handleRegister)
	mux.HandleFunc("POST /api/auth/login", g.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", g.handleLogout)
	mux.HandleFunc("POST /api/auth/logout-all", g.handleLogoutAll)
	mux.HandleFunc("POST /api/auth/password", g.handleChangePassword)

	mux.Handle("GET /api/auth/users", RequireRole(gauntlet.RoleAdmin, http.HandlerFunc(g.handleListUsers)))
	mux.Handle("POST /api/auth/users", RequireRole(gauntlet.RoleAdmin, http.HandlerFunc(g.handleCreateUser)))
	mux.Handle("DELETE /api/auth/users/{id}", RequireRole(gauntlet.RoleAdmin, http.HandlerFunc(g.handleDeleteUser)))

	mux.Handle("GET /api/tokens", RequireRole(gauntlet.RoleAdmin, http.HandlerFunc(g.handleTokensList)))
	mux.Handle("POST /api/tokens", RequireRole(gauntlet.RoleAdmin, http.HandlerFunc(g.handleTokensCreate)))
	mux.Handle("DELETE /api/tokens/{id}", RequireRole(gauntlet.RoleAdmin, http.HandlerFunc(g.handleTokensRevoke)))

	return mux
}
