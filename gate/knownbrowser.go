package gate

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/internal/browsertoken"
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
	// to gate's own routes. It names nothing -- the value is up to four
	// tokens of 32 random bytes each, no account IDs, and only each
	// token's SHA-256 is on its account's record.
	knownBrowserCookieName = "gate_known_browser"

	// knownBrowserCookiePath is the prefix of every route gate serves
	// that issues a session -- login and login/factor, register, the
	// password change, sign out everywhere, TOTP confirm, passkey
	// register/finish and the SSO callback -- as well as the three
	// login routes the allowance applies to. Every session issue must
	// see the browser's old token to replace it (rememberSignIn);
	// scoped to the login routes alone, an issue anywhere else added a
	// second entry for the same browser, and with only
	// gauntlet.MaxKnownBrowsers to an account, one browser could evict
	// the owner's others. Still not "/": the application's own routes
	// never receive it.
	knownBrowserCookiePath = "/api/auth"

	// maxKnownBrowserTokens is how many tokens the cookie carries: one
	// per account the browser has completed a sign-in on, most recent
	// first, so a browser shared by a few accounts is known to each of
	// them (#55 §4). The tokens are joined by "."; base64url never
	// contains one.
	maxKnownBrowserTokens = 4
)

// knownBrowserTokens returns the known-browser tokens r carries, most
// recent first, at most maxKnownBrowserTokens and each once. A part that
// is not a well-formed token is dropped, so neither a forged nor a
// truncated value costs a store lookup. Well-formed is
// internal/browsertoken's rule, the one the store applies to its own
// tokens before it hashes anything (#90), so the two cannot disagree.
// A cookie from before tokens were joined holds one token and reads as
// a list of one. Only requests under /api/auth carry it
// (knownBrowserCookiePath).
func knownBrowserTokens(r *http.Request) []string {
	cookie, err := r.Cookie(knownBrowserCookieName)
	if err != nil {
		return nil
	}
	var tokens []string
	for part := range strings.SplitSeq(cookie.Value, ".") {
		if !browsertoken.WellFormed(part) || slices.Contains(tokens, part) {
			continue
		}
		tokens = append(tokens, part)
		if len(tokens) == maxKnownBrowserTokens {
			break
		}
	}
	return tokens
}

// isKnownBrowser reports whether r comes from a browser accountID
// remembers, still within gauntlet.KnownBrowserLifetime: any token the
// cookie carries is live on the account. The store checks each token's
// SHA-256 against the account's record and the entry's age, so a
// forged, expired or another account's token is false. Every carried
// token is checked -- at most four constant-time checks -- rather than
// stopping at the first match.
func (g *Gate) isKnownBrowser(r *http.Request, accountID string, now time.Time) bool {
	known := false
	for _, token := range knownBrowserTokens(r) {
		if g.deps.Users.KnowsBrowser(accountID, token, now) {
			known = true
		}
	}
	return known
}

// rememberSignIn records that this browser has just completed a sign-in
// on userID and hands it a fresh token, replacing the one it carried for
// userID, and remembers the country and place the sign-in came from
// (gauntlet.Store.RememberSignIn, #55): one write per issued session.
// The token replaced is the first carried one userID knows; the new
// cookie is the fresh token first, then the other carried tokens --
// other accounts' -- cut to maxKnownBrowserTokens. A carried token for
// userID that has already expired is not matched: it stays in the
// cookie until the cap evicts it, and RememberBrowser's own liveness
// filter has already dropped it from the record. The
// cookie's Max-Age is gauntlet.KnownBrowserLifetime, the same lifetime
// the store enforces from the entry's IssuedAt, so the browser forgets
// the token when the server would refuse it anyway.
//
// Every route that issues a session is under the cookie's path, so the
// old token reaches here from each of them -- a password change or an
// SSO callback as much as a login -- and a browser keeps one entry
// however it came by its session. (The SSO callback is a cross-site
// top-level navigation, on which a SameSite=Lax cookie is sent.)
//
// A write that fails is logged and the sign-in goes on: the session is
// what the caller asked for, and the browser keeps whatever token it
// had. No cookie is set then, since its hash is on no record, and it
// reports false, so the sign-in is flagged as nothing (#55). A sign-in
// let through by an admin's allowance is the exception: it is
// remembered by rememberAllowedSignIn instead, and spendAllowance
// refuses it when that write fails (#101).
func (g *Gate) rememberSignIn(w http.ResponseWriter, r *http.Request, userID string, place signInPlace, now time.Time) bool {
	return g.rememberSignInWith(w, r, userID, place, now, g.deps.Users.RememberSignIn) == nil
}

// rememberAllowedSignIn is rememberSignIn for a sign-in let through by
// an admin's allowance (gauntlet.Store.RememberAllowedSignIn, #103):
// the same write and the same cookie, made only if the allowance is
// still live, and spending it. It returns the store's error: nil when
// remembered and spent, gauntlet.ErrSignInNotAllowed when the allowance
// had already been used or had expired -- nothing written, no cookie
// set, and not logged, since nothing failed -- and anything else when
// the write failed, which is logged.
func (g *Gate) rememberAllowedSignIn(w http.ResponseWriter, r *http.Request, userID string, place signInPlace, now time.Time) error {
	return g.rememberSignInWith(w, r, userID, place, now, g.deps.Users.RememberAllowedSignIn)
}

// rememberSignInWith is the body rememberSignIn and
// rememberAllowedSignIn share; remember is the store write.
func (g *Gate) rememberSignInWith(w http.ResponseWriter, r *http.Request, userID string, place signInPlace, now time.Time,
	remember func(accountID, replacing, country string, loc *gauntlet.Location, now time.Time) (string, error),
) error {
	carried := knownBrowserTokens(r)
	replacing := ""
	for _, t := range carried {
		if g.deps.Users.KnowsBrowser(userID, t, now) {
			replacing = t
			break
		}
	}
	token, err := remember(userID, replacing, place.client.Country, place.loc, now)
	if err != nil {
		if !errors.Is(err, gauntlet.ErrSignInNotAllowed) {
			g.logError("remembering the browser that signed in to account " + userID + ": " + err.Error())
		}
		return err
	}
	g.writeKnownBrowserCookie(w, token, carried, replacing)
	return nil
}

// writeKnownBrowserCookie sets the cookie to fresh followed by carried
// without replacing, at most maxKnownBrowserTokens.
func (g *Gate) writeKnownBrowserCookie(w http.ResponseWriter, fresh string, carried []string, replacing string) {
	tokens := []string{fresh}
	for _, t := range carried {
		if t != replacing && len(tokens) < maxKnownBrowserTokens {
			tokens = append(tokens, t)
		}
	}
	g.writeCookie(w, knownBrowserCookieName, strings.Join(tokens, "."), knownBrowserCookiePath, int(gauntlet.KnownBrowserLifetime.Seconds()))
}
