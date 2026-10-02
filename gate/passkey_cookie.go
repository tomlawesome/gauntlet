package gate

import (
	"net/http"
	"time"
)

// The two passkey ceremony cookies (G8, ADR-0004). Each carries the
// ceremony state gauntlet.PasskeyCeremony's Begin sealed -- gate never
// reads inside it -- from Begin to the matching Finish, written through
// writeCookie with its fixed attributes. Named generically ("gate_"),
// as pendingLoginCookieName is.
const (
	// passkeyRegisterCookieName/Path carry a registration from register/
	// begin to register/finish. The path is the whole /api/auth/passkeys
	// prefix rather than the two routes, for the same reason
	// pendingLoginCookiePath is a prefix: one Path value covers both
	// without widening to the whole API.
	passkeyRegisterCookieName = "gate_passkey_register"
	passkeyRegisterCookiePath = passkeysPath

	// passkeyAssertCookieName/Path carry a login ceremony from
	// login/factor/begin to login/factor's assertion branch.
	// "/api/auth/login" is the prefix pendingLoginCookiePath already
	// uses, and covers both routes.
	passkeyAssertCookieName = "gate_passkey_assert"
	passkeyAssertCookiePath = pendingLoginCookiePath

	// passkeyCeremonyCookieMaxAge is five minutes, matching the expiry
	// gauntlet/passkey seals into the ceremony state itself (its
	// ceremonyLifetime). Max-Age only tells the browser when to forget
	// the cookie; the sealed expiry is what the server enforces.
	passkeyCeremonyCookieMaxAge = 5 * time.Minute
)

func (g *Gate) setPasskeyRegisterCookie(w http.ResponseWriter, sealed string) {
	g.writeCookie(w, passkeyRegisterCookieName, sealed, passkeyRegisterCookiePath, int(passkeyCeremonyCookieMaxAge.Seconds()))
}

func (g *Gate) clearPasskeyRegisterCookie(w http.ResponseWriter) {
	g.writeCookie(w, passkeyRegisterCookieName, "", passkeyRegisterCookiePath, -1)
}

func (g *Gate) setPasskeyAssertCookie(w http.ResponseWriter, sealed string) {
	g.writeCookie(w, passkeyAssertCookieName, sealed, passkeyAssertCookiePath, int(passkeyCeremonyCookieMaxAge.Seconds()))
}

func (g *Gate) clearPasskeyAssertCookie(w http.ResponseWriter) {
	g.writeCookie(w, passkeyAssertCookieName, "", passkeyAssertCookiePath, -1)
}
