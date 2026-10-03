package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/tomlawesome/gauntlet/internal/spent"
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

// spentRegistrations holds every registration ceremony a finish has
// spent, keyed by registrationKey, so one password-proved begin stores
// at most one passkey (ruling S1 on #20). Claimed by
// handlePasskeyRegisterFinish once the library accepts the browser's
// response and before AddPasskey writes. The grace is one cookie
// lifetime, as internal/spent's contract asks of every caller. Shared by
// every Gate this process runs, like the ceremony cookies' sealing keys.
var spentRegistrations = spent.New(passkeyCeremonyCookieMaxAge)

// registrationKey is the hex SHA-256 of a sealed registration cookie --
// the one thing gate holds that is unique per begin (the seal carries a
// fresh random nonce), so the seam with gauntlet/passkey stays as it is
// rather than exporting a ceremony ID for this one caller.
func registrationKey(sealed string) string {
	sum := sha256.Sum256([]byte(sealed))
	return hex.EncodeToString(sum[:])
}
