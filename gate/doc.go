// Package gate is mikroview's internal/api/{auth,tokens}.go turned into
// a reusable HTTP layer: the authentication middleware (Protect) and the
// account/token handlers (Routes) any application built on gauntlet
// wires in place of its own copy.
//
// It carries the middleware, the bootstrap and CSRF gates, bearer-token
// dispatch, and the account, session, second-factor, admin-reset, OIDC
// and token handlers -- mikroview's whole route table except passkeys,
// which join when passkey/ lands (routes.go is the list).
//
// docs/design.md §1.5 is this package's specification; a divergence
// from it is called out where it happens, not left to be inferred from
// the code.
package gate
