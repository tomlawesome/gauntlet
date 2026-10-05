package gate

import (
	"net/http"
	"strings"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// hostCookiePrefix is the name prefix that makes a browser refuse the
// session cookie unless it is Secure, carries no Domain and has Path=/
// -- all of which writeCookie already sets, so the prefix costs only
// the name and buys a guarantee the attributes alone cannot: no
// sibling host or plain-http origin can plant a cookie of that name
// (ASVS 3.3.3, SP 800-63B-4 §5.1.1). It is applied only while
// Config.SecureCookie is true, because a __Host- cookie without Secure
// is dropped by every browser, which under plain HTTP (development)
// would sign nobody in. gate.New refuses a CookieName that already
// carries this prefix or __Secure-; see New.
const hostCookiePrefix = "__Host-"

// sessionCookieName is the name the session cookie is written and read
// under: hostCookiePrefix plus Config.CookieName once the cookie is
// Secure, the bare name otherwise. Every reader goes through this so the
// name is decided in one place -- a reader using cfg.CookieName
// directly would accept, under TLS, a cookie that lacks the prefix's
// guarantees.
func (g *Gate) sessionCookieName() string {
	if g.cfg.SecureCookie {
		return hostCookiePrefix + g.cfg.CookieName
	}
	return g.cfg.CookieName
}

// hasReservedCookiePrefix reports whether name starts with a prefix the
// browser gives special meaning to (RFC 6265bis §4.1.3), which gate
// manages itself.
func hasReservedCookiePrefix(name string) bool {
	return strings.HasPrefix(name, hostCookiePrefix) || strings.HasPrefix(name, "__Secure-")
}

// sessionCookieMaxAge is how long the browser itself remembers the
// session cookie: the session store's lifetime ceiling, read from the
// store each time so it has one source of truth. The cookie thus
// expires exactly when the session can no longer be valid (SP
// 800-63B-4 §5.1.1: at or soon after the session). It is deliberately
// not the idle timeout: that slides forward on every use server-side,
// and tying the cookie to it would mean re-setting the cookie on every
// request to keep an active browser signed in. mikroview's 30-day
// constant, which this replaces, predated the ceiling. gate.New has
// already refused a store with no ceiling, so Limits never reports zero
// here.
func (g *Gate) sessionCookieMaxAge() time.Duration {
	_, ceiling := g.deps.Sessions.Limits()
	return ceiling
}

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
	g.writeCookie(w, g.sessionCookieName(), sessionID, "/", int(g.sessionCookieMaxAge().Seconds()))
}

// setResumedSessionCookie is setSessionCookie for a resumed session:
// the cookie lasts only until the session's original ceiling, not a
// fresh ceiling from now, so resuming never extends the 24 hours from
// the sign-in. At least one second, since a Max-Age of zero would mean
// no limit at all.
func (g *Gate) setResumedSessionCookie(w http.ResponseWriter, sess gauntlet.Session, now time.Time) {
	_, ceiling := g.deps.Sessions.Limits()
	left := int(sess.IssuedAt.Add(ceiling).Sub(now).Seconds())
	g.writeCookie(w, g.sessionCookieName(), sess.ID, "/", max(left, 1))
}

func (g *Gate) clearSessionCookie(w http.ResponseWriter) {
	g.writeCookie(w, g.sessionCookieName(), "", "/", -1)
}

// revokeReplacedSession ends the session r's cookie names when it is
// live and belongs to userID, the account a sign-in is about to issue a
// new session for. The new cookie overwrites the old one in the
// browser, so without this the old id would stay valid -- invisible to
// its owner, absent from any logout they do from this browser -- until
// it idled out (ASVS 7.2.4: the current token is terminated on
// re-authentication). Another account's session in the same browser is
// left alone: that person did not sign in, and this request proved
// nothing about them; a stray cookie is not authority to end a session
// it does not own.
//
// Called only through issueSession, so every path that issues a
// session runs it. Where the path has already ended every session of the
// account (password change, factor enrolment, SSO link, sign out
// everywhere) the cookie's session is gone and this finds nothing; at
// first-account registration no session can belong to the new account
// yet. Both are harmless, and one route through issueSession means a
// new sign-in path cannot forget it.
func (g *Gate) revokeReplacedSession(r *http.Request, userID string, now time.Time) {
	cookie, err := r.Cookie(g.sessionCookieName())
	if err != nil {
		return
	}
	sess, ok := g.deps.Sessions.Validate(cookie.Value, now)
	if !ok || sess.UserID != userID {
		return
	}
	g.deps.Sessions.Revoke(sess.ID)
}

// issueSession starts a session for userID and hands the browser its
// cookie -- the one way gate issues a session, so the four things every
// issue must do happen together at every one of them: end the session
// this browser already held for the account (revokeReplacedSession,
// #47), record the client so the account's owner can recognise the
// session in their own list (gauntlet.SessionStore.CreateFrom, #48),
// set the cookie under sessionCookieName with the ceiling's Max-Age
// (#47), and remember the browser, rotating its known-browser token
// (#44), with the country and place it came from (rememberSignIn, #55).
//
// The address is Config.ClientIP's, the same resolution the login
// limiter is keyed on, so the list shows what the application's own
// proxy policy believes; the agent is the request's User-Agent header;
// the country, if any, is Config.Country's for that address (#54) --
// signInClient builds all three, the same client a sign-in record for
// this request carries, so the session list and the history agree.
// Address and UserAgent are the client's word, cleaned and capped by
// CreateFrom.
func (g *Gate) issueSession(w http.ResponseWriter, r *http.Request, userID string, now time.Time) {
	g.issueSignInSession(w, r, userID, g.placeOf(r, ""), 0, now)
}

// issueSignInSession is issueSession for a sign-in already judged: place
// is where it came from, looked up once, and signals the unusual-sign-in
// signals the session carries (#55). The browser, country and place are
// remembered first (rememberSignIn); if that write fails, nothing is
// flagged and the session carries no signals. It returns the session
// and the signals it carries.
func (g *Gate) issueSignInSession(w http.ResponseWriter, r *http.Request, userID string, place signInPlace, signals gauntlet.SignInSignals, now time.Time) (gauntlet.Session, gauntlet.SignInSignals) {
	g.revokeReplacedSession(r, userID, now)
	if !g.rememberSignIn(w, r, userID, place, now) {
		signals = 0
	}
	client := place.client
	client.Unusual = signals
	sess := g.deps.Sessions.CreateFrom(userID, client, now)
	g.setSessionCookie(w, sess.ID)
	return sess, signals
}
