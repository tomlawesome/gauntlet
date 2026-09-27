package gate

import (
	"net/http"
	"time"
)

// cookieMaxAge is how long the browser itself remembers the session
// cookie -- fixed here, not in Config, because it is security behaviour
// mikroview chose deliberately (docs/design.md §1.5), not an
// application preference: deliberately longer than the server-side idle
// timeout (SessionStore's ttl), which slides forward on use, so the
// cookie just needs to outlast any realistic idle gap.
const cookieMaxAge = 30 * 24 * time.Hour

// writeCookie is the only place a cookie is handed to the client, so the
// three fixed security attributes -- HttpOnly, SameSite=Lax, path -- are
// decided once. SameSite is Lax rather than Strict for the same reason
// mikroview's own writeCookie is: the OIDC flow cookie (oidc_handler.go)
// has to survive the provider's top-level cross-site redirect back to
// the callback route, and the session cookie is happy either way.
func (g *Gate) writeCookie(w http.ResponseWriter, name, value, path string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		HttpOnly: true,
		Secure:   g.cfg.SecureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

func (g *Gate) setSessionCookie(w http.ResponseWriter, sessionID string) {
	g.writeCookie(w, g.cfg.CookieName, sessionID, "/", int(cookieMaxAge.Seconds()))
}

func (g *Gate) clearSessionCookie(w http.ResponseWriter) {
	g.writeCookie(w, g.cfg.CookieName, "", "/", -1)
}
