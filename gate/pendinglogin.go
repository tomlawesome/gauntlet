package gate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tomlawesome/gauntlet/internal/expiry"
	"github.com/tomlawesome/gauntlet/internal/spent"
)

// pendingLoginCookieName carries a login that has proven the password but
// not yet the second factor (mikroview's #1249, docs/design.md §1.6) -- a
// "nearly in" ticket, not a session. The only thing it is worth to
// whoever holds it is one attempt per LoginLimiter window at the named
// account's code or a recovery code -- see handleLoginFactor.
//
// Named generically ("gate_", not an app-specific brand) the same way
// authGateHeader is: this cookie belongs to gate itself, not to any one
// application.
const pendingLoginCookieName = "gate_pending_login"

// pendingLoginCookiePath scopes the cookie to the two routes that ever
// need it: the login that sets it and the factor step that reads it.
// loginPath (protect.go) is a prefix of loginFactorPath too (RFC 6265's
// path-match rule), so one Path value covers both without widening it
// to the whole API the way the session cookie's "/" does.
const pendingLoginCookiePath = loginPath

// pendingLoginCookieMaxAge bounds both the cookie's own Max-Age and the
// tolerance pendingLoginStateCodec.decode checks IssuedAt against -- kept
// as one constant so the two can never drift apart. Five minutes,
// mikroview's #1249 number and this module's own docs/design.md §1.5:
// long enough to open an authenticator app and read off six digits,
// short enough that an abandoned login does not leave a live
// "one attempt away" ticket sitting in a browser.
const pendingLoginCookieMaxAge = 5 * time.Minute

// pendingLoginState is everything the pending cookie carries: which
// account proved its password, and when. Deliberately nothing else -- no
// role, no session ID, nothing a forged or replayed cookie could spend
// for more than "try one code against this one account's already-proven
// password".
type pendingLoginState struct {
	UserID   string
	IssuedAt time.Time
	// A cookie sealed before #86 may also carry "AfterReset", the reset
	// pass's flag (#32): decoding ignores it, so the code step reserves
	// on the address limit like any other.
	// ID makes the pending login one-shot (ruling R2 on #20): 16 random
	// bytes, hex, claimed in spentPendingLogins by the sign-in that
	// completes it, so one correct password yields one session. A cookie
	// without one -- sealed before this field existed -- is refused.
	ID string
}

// errPendingLoginInvalid covers every way a pending-login cookie can
// fail to decode: tampered, corrupt, or expired -- one error rather than
// several, the same stance oidc.ErrFlowStateInvalid takes and for the
// same reason: which specific failure occurred isn't something a caller
// (or an attacker probing the endpoint) needs to be able to tell apart.
var errPendingLoginInvalid = errors.New("gate: pending login expired or was tampered with")

// sealCodec seals and opens a small JSON value for a cookie the same
// way oidc.StateCodec seals an oidc.FlowState: AES-256-GCM, stdlib only,
// so a tampered cookie fails the auth-tag check rather than decoding
// into a different account, with a key generated once via crypto/rand
// and held only in memory. The pending-login ticket and the
// confirm-login ticket (#55) each have their own, with their own key.
//
// A second implementation rather than reusing oidc.StateCodec directly.
// That type is hard-coded to oidc.FlowState's fields, and gate has no
// other reason to depend on the oidc package's cookie-sealing internals
// -- widening a codec that belongs to one login flow to also carry a
// second, unrelated flow's payload would leave neither flow's cookie
// shape visible from its own file.
type sealCodec struct {
	aead cipher.AEAD
}

// mustNewSealCodec builds a codec with a fresh key. what names it in a
// panic.
func mustNewSealCodec(what string) *sealCodec {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// Same stance gauntlet's own newID takes (id.go): a CSPRNG that
		// cannot produce bytes is not a condition to degrade from
		// gracefully here -- every login on an account with a second
		// factor depends on this codec existing.
		panic("gate: crypto/rand unavailable: " + err.Error())
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("gate: constructing " + what + " cipher: " + err.Error())
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic("gate: constructing " + what + " AEAD: " + err.Error())
	}
	return &sealCodec{aead: aead}
}

// seal encodes v as JSON and seals it, base64url without padding.
func (c *sealCodec) seal(v any) (string, error) {
	plaintext, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("gate: encoding sealed state: %w", err)
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("gate: generating seal nonce: %w", err)
	}
	sealed := c.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// open reverses seal into v, reporting whether value opened. Strict:
// only the spelling seal wrote opens, so a sealed value has one cookie
// string, as passkey's seal does (#20).
func (c *sealCodec) open(value string, v any) bool {
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return false
	}
	ns := c.aead.NonceSize()
	if len(sealed) < ns {
		return false
	}
	nonce, ciphertext := sealed[:ns], sealed[ns:]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return false
	}
	return json.Unmarshal(plaintext, v) == nil
}

// pendingLoginStateCodec seals/opens a pendingLoginState (sealCodec).
type pendingLoginStateCodec struct {
	*sealCodec
}

// pendingLoginCodec is built once, at package load, and shared by every
// Gate this process runs -- the same "generated once, held only in
// memory, lost on restart" lifetime gauntlet.SessionStore and
// oidc.StateCodec already have. A restart simply fails any login stuck
// mid-second-step cleanly (the browser gets a cookie the new process
// can't open, and tries the password step again), an entirely acceptable
// cost for state that was never meant to outlive five minutes anyway.
var pendingLoginCodec = mustNewPendingLoginCodec()

func mustNewPendingLoginCodec() *pendingLoginStateCodec {
	return &pendingLoginStateCodec{mustNewSealCodec("pending-login")}
}

func (c *pendingLoginStateCodec) encode(st pendingLoginState) (string, error) {
	return c.seal(st)
}

// decode reverses encode, refusing (errPendingLoginInvalid) anything
// malformed, tampered, or pendingLoginCookieMaxAge old or older as
// measured from the sealed IssuedAt against now (internal/expiry: refused
// from the instant it expires).
func (c *pendingLoginStateCodec) decode(cookieValue string, now time.Time) (pendingLoginState, error) {
	var st pendingLoginState
	if !c.open(cookieValue, &st) {
		return pendingLoginState{}, errPendingLoginInvalid
	}
	if expiry.Expired(st.IssuedAt, pendingLoginCookieMaxAge, now) {
		return pendingLoginState{}, errPendingLoginInvalid
	}
	if st.ID == "" {
		return pendingLoginState{}, errPendingLoginInvalid
	}
	return st, nil
}

// spentPendingLogins holds the ID of every pending login a sign-in has
// completed, until one lifetime after the cookie carrying it would be
// refused anyway: the forget time is the sealed IssuedAt plus
// pendingLoginCookieMaxAge, the same expiry decode checks, compared on
// the same wall clock, and the grace of one more pendingLoginCookieMaxAge
// means a request that read the clock before that expiry cannot find the
// ID already forgotten by one that read it after (ruling S2 on #20,
// internal/spent). Shared by every Gate this process runs, like
// pendingLoginCodec, whose cookies it guards.
var spentPendingLogins = spent.New(pendingLoginCookieMaxAge)

// pendingLogin reads, opens and checks the pending-login cookie for
// login/factor and login/factor/begin. A cookie that is missing, does
// not open, has expired, or whose pending login a sign-in has already
// completed is refused with 401 "sign in again" and cleared.
func (g *Gate) pendingLogin(w http.ResponseWriter, r *http.Request, now time.Time) (pendingLoginState, bool) {
	refuse := func() (pendingLoginState, bool) {
		g.clearPendingLoginCookie(w)
		writeUnauthorized(w, classStepExpired, "sign in again")
		return pendingLoginState{}, false
	}
	cookie, err := r.Cookie(pendingLoginCookieName)
	if err != nil {
		return refuse()
	}
	st, err := pendingLoginCodec.decode(cookie.Value, now)
	if err != nil || spentPendingLogins.Spent(st.ID, now) {
		return refuse()
	}
	return st, true
}

// setPendingLoginCookie seals a fresh pendingLoginState for userID and
// writes it -- called from handleLogin the moment a password checks out
// against an account holding an active second factor, in place of
// creating a session.
func (g *Gate) setPendingLoginCookie(w http.ResponseWriter, userID string, now time.Time) error {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return fmt.Errorf("gate: generating pending login id: %w", err)
	}
	encoded, err := pendingLoginCodec.encode(pendingLoginState{UserID: userID, IssuedAt: now, ID: hex.EncodeToString(id)})
	if err != nil {
		return err
	}
	g.writeCookie(w, pendingLoginCookieName, encoded, pendingLoginCookiePath, int(pendingLoginCookieMaxAge.Seconds()))
	return nil
}

func (g *Gate) clearPendingLoginCookie(w http.ResponseWriter) {
	g.writeCookie(w, pendingLoginCookieName, "", pendingLoginCookiePath, -1)
}
