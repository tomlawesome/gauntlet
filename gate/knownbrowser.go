package gate

import (
	"net/http"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// The known-browser cookie (#44): the token gauntlet.Store.RememberBrowser
// hands a browser that has completed a sign-in, which lets that browser
// keep a small allowance of its own while the account is locked out
// (gauntlet.LoginLimiter.ReserveKnownBrowser). See gauntlet's
// knownbrowser.go for the design; this file only carries the token to
// and from the browser.
const (
	// knownBrowserCookieName is generic ("gate_"), as
	// pendingLoginCookieName is. No __Host- prefix, unlike the session
	// cookie: that prefix requires Path=/, and this cookie is scoped
	// to the login routes. It names nothing -- the value is 32 random
	// bytes, and only its SHA-256 is on the account's record.
	knownBrowserCookieName = "gate_known_browser"

	// knownBrowserCookiePath is the prefix that covers login,
	// login/factor and login/factor/begin, the three routes the
	// allowance applies to, and no others: the browser sends the
	// cookie nowhere it is not read.
	knownBrowserCookiePath = loginPath
)

// knownBrowserToken returns the known-browser token r carries, or "".
// Only requests to the login routes carry it (knownBrowserCookiePath).
func knownBrowserToken(r *http.Request) string {
	cookie, err := r.Cookie(knownBrowserCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// isKnownBrowser reports whether r comes from a browser accountID
// remembers, still within gauntlet.KnownBrowserLifetime: the store
// checks the token's SHA-256 against the account's record and the
// entry's age, so a forged, expired or another account's token is
// false.
func (g *Gate) isKnownBrowser(r *http.Request, accountID string, now time.Time) bool {
	token := knownBrowserToken(r)
	return token != "" && g.deps.Users.KnowsBrowser(accountID, token, now)
}

// rememberBrowser records that this browser has just completed a sign-in
// on userID and hands it a fresh token, replacing the one it carried
// (gauntlet.Store.RememberBrowser): one write per issued session. The
// cookie's Max-Age is gauntlet.KnownBrowserLifetime, the same lifetime
// the store enforces from the entry's IssuedAt, so the browser forgets
// the token when the server would refuse it anyway.
//
// The old token reaches here only from a login route, the cookie's
// path; elsewhere -- a password change, an SSO callback -- the browser
// does not send it, its old entry stays on the record, unreachable, and
// ages out or is evicted as the oldest.
//
// A write that fails is logged and the sign-in goes on: the session is
// what the caller asked for, and the browser keeps whatever token it
// had. No cookie is set then, since its hash is on no record.
func (g *Gate) rememberBrowser(w http.ResponseWriter, r *http.Request, userID string, now time.Time) {
	token, err := g.deps.Users.RememberBrowser(userID, knownBrowserToken(r), now)
	if err != nil {
		g.logError("remembering the browser that signed in to account " + userID + ": " + err.Error())
		return
	}
	g.writeCookie(w, knownBrowserCookieName, token, knownBrowserCookiePath, int(gauntlet.KnownBrowserLifetime.Seconds()))
}
