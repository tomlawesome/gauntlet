package gate

import (
	"context"
	"net/http"

	"github.com/tomlawesome/gauntlet"
)

// contextKey namespaces gate's own context values, mirroring mikroview's
// internal/api.contextKey -- an unexported type so nothing outside this
// package can collide with or forge one of these keys.
type contextKey int

const (
	userContextKey contextKey = iota
	tokenContextKey
)

// withUser attaches the authenticated user to ctx -- called once, by
// Protect, on the request it lets through the session-cookie path.
func withUser(ctx context.Context, u *gauntlet.User) context.Context {
	return context.WithValue(ctx, userContextKey, u)
}

// withToken attaches the authenticated bearer token to ctx -- called
// once, by Protect, on the request it dispatches to a Handle-registered
// kind's handler.
func withToken(ctx context.Context, t *gauntlet.Token) context.Context {
	return context.WithValue(ctx, tokenContextKey, t)
}

// UserFromContext returns the authenticated user for this request, or
// nil if the request reached here without one -- a bearer-token request
// (see TokenFromContext instead), or a route Exempt left reachable with
// no session.
func UserFromContext(r *http.Request) *gauntlet.User {
	u, _ := r.Context().Value(userContextKey).(*gauntlet.User)
	return u
}

// TokenFromContext returns the authenticated bearer token for this
// request, or nil if the request reached here through the session-cookie
// path instead (see UserFromContext).
func TokenFromContext(r *http.Request) *gauntlet.Token {
	t, _ := r.Context().Value(tokenContextKey).(*gauntlet.Token)
	return t
}
