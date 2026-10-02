// Package gate is mikroview's internal/api/{auth,tokens}.go turned into
// a reusable HTTP layer: the authentication middleware (Protect) and the
// account/token handlers (Routes) any application built on gauntlet
// wires in place of its own copy.
//
// It carries the middleware, the bootstrap and CSRF gates, bearer-token
// dispatch, and the account, session, second-factor (authenticator app
// and passkey), admin-reset, OIDC and token handlers -- mikroview's
// whole route table (routes.go is the list). The passkey routes drive
// the WebAuthn ceremony through Deps.Passkeys, a
// gauntlet.PasskeyCeremony; gate never imports gauntlet/passkey or the
// WebAuthn library, so an application without passkeys never links
// either (ADR-0004).
//
// docs/design.md §1.5 is this package's specification; a divergence
// from it is called out where it happens, not left to be inferred from
// the code.
package gate
