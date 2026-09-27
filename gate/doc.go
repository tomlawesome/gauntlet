// Package gate is mikroview's internal/api/{auth,tokens}.go turned into
// a reusable HTTP layer: the authentication middleware (Protect) and the
// account/token handlers (Routes) any application built on gauntlet
// wires in place of its own copy.
//
// This is stage 1 (G6, gauntlet issue #7): the middleware, the bootstrap
// and CSRF gates, bearer-token dispatch, and the account/session/token
// handlers. Second-factor login (POST /api/auth/login/factor), TOTP
// enrolment, admin password reset and the OIDC routes are stage 2 --
// see the "G6 stage 2" TODOs in login.go and protect.go for exactly
// where they attach.
//
// docs/design.md §1.5 is this package's specification; a divergence
// from it is called out where it happens, not left to be inferred from
// the code.
package gate
