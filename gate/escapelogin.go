package gate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/internal/spent"
)

// The escape code (#66, ADR-0011): when the unusual-sign-in policy
// refuses (block) a lone admin -- the only admin able to act -- from a
// browser the account has never used, nobody can reset them and the
// application's own remedy (Decide) may be out of reach. gate then
// writes a one-time code to the server's own log, as the setup and
// unlock codes are, and holds a sealed ticket in the refused browser.
// Typing the code into that browser -- POST /api/auth/login/escape --
// lets that one sign-in through. It is the confirm step (confirmlogin.go)
// with the code delivered to the log instead of Config.DeliverConfirmCode.

// escapeLoginCookieName carries a refused lone admin's sign-in, which
// has proven every credential and owes the escape code. Generic
// ("gate_"), as confirmLoginCookieName is.
const escapeLoginCookieName = "gate_escape_login"

// escapeLoginCookiePath is loginPath, a prefix of loginEscapePath, so the
// cookie reaches the escape route and nothing outside the login routes.
const escapeLoginCookiePath = loginPath

// EscapeCodeLifetime is how long an escape code, and the ticket carrying
// its hash, lives: the confirm code's 15 minutes, since whoever reads the
// log is the person at the keyboard.
const EscapeCodeLifetime = ConfirmCodeLifetime

// EscapeCodeHandler receives the escape code a refused lone admin may
// type into the browser that was refused (#66) -- Config.OnEscapeCode.
// An interface rather than a bare func so that Config stays comparable
// in spirit with Options.OnSetupCode and OnUnlockCode (ADR-0002);
// EscapeCodeFunc adapts a plain function.
type EscapeCodeHandler interface {
	// EscapeCode is called, before the refusal is answered, with the
	// admin's username, the address the refused attempt came from and
	// the code in its display form, xxxx-xxxx-xxxx-xxxx. It runs under
	// DecideTimeout (a panic or overrun issues no code). The code is a
	// secret for whoever may read the server's log: announce it nowhere
	// else.
	EscapeCode(username, address, code string)
}

// EscapeCodeFunc adapts a function to EscapeCodeHandler.
type EscapeCodeFunc func(username, address, code string)

// EscapeCode calls f(username, address, code).
func (f EscapeCodeFunc) EscapeCode(username, address, code string) { f(username, address, code) }

// escapeCodeLogLine is what Config.Log carries when Config.OnEscapeCode
// is not set: one line, at Warn, like the setup and unlock codes'. Until
// it is used or expires, anyone who reads it and holds the refused
// browser's cookie can sign in -- but only with the password and second
// factor that browser already proved.
func escapeCodeLogLine(username, address, code string) string {
	return fmt.Sprintf("sign-in for the admin account %q from %s was refused by the unusual-sign-in policy, and no other admin can act -- "+
		"let that attempt through with escape code %s (valid %d minutes, in the browser that was refused; "+
		"it then signs in with the password and second factor it already proved)",
		username, address, code, int(EscapeCodeLifetime/time.Minute))
}

// escapeLoginState is what the escape ticket carries. The code itself
// never: only its SHA-256.
type escapeLoginState struct {
	UserID   string
	IssuedAt time.Time
	// ID makes the ticket one-shot: 16 random bytes, hex, claimed in
	// spentEscapeLogins by the sign-in that completes it.
	ID string
	// CodeHash is the hex SHA-256 of the code's canonical form
	// (gauntlet.NewOneTimeCode), no dashes, upper case.
	CodeHash string
	Signals  gauntlet.SignInSignals
	// Method is how the credentials were presented.
	Method gauntlet.SignInMethod
}

// escapeLoginCodec seals the ticket with its own per-process key, so a
// restart kills every outstanding escape code, as it does the setup and
// unlock codes.
var escapeLoginCodec = mustNewSealCodec("escape-login")

// spentEscapeLogins holds the ID of every ticket a sign-in has
// completed, for as long as the ticket could still open.
var spentEscapeLogins = spent.New(EscapeCodeLifetime)

// decodeEscapeLogin opens a ticket, refusing anything malformed,
// tampered, without an ID, or EscapeCodeLifetime old or older.
func decodeEscapeLogin(value string, now time.Time) (escapeLoginState, bool) {
	var st escapeLoginState
	if !escapeLoginCodec.open(value, &st) || st.ID == "" || st.UserID == "" || st.CodeHash == "" {
		return escapeLoginState{}, false
	}
	if !now.Before(st.IssuedAt.Add(EscapeCodeLifetime)) {
		return escapeLoginState{}, false
	}
	return st, true
}

// escapeCodeHash is the form a code is kept and compared in: the hex
// SHA-256 of its canonical form.
func escapeCodeHash(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// escapeCodeMatches reports whether typed is the code hashed as want:
// with or without dashes, in either case, compared in constant time.
func escapeCodeMatches(typed, want string) bool {
	got := escapeCodeHash(gauntlet.NormaliseResetCode(typed))
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// escapeOffered reports whether a refusal of user's sign-in may carry an
// escape code: an admin, on the local password or factor path (never the
// SSO callback, ADR-0010), with something that can announce the code and
// no other admin able to act (Store.OtherAdminCanAct).
func (g *Gate) escapeOffered(user *gauntlet.User, method gauntlet.SignInMethod, now time.Time) bool {
	if user.Role != gauntlet.RoleAdmin || method == gauntlet.SignInMethodSSO {
		return false
	}
	if g.cfg.OnEscapeCode == nil && g.cfg.Log == nil {
		return false // nothing can announce it: fail closed
	}
	return !g.deps.Users.OtherAdminCanAct(user.ID, now)
}

// startEscape mints an escape code and its ticket for user's refused
// sign-in when escapeOffered, announces the code (Config.OnEscapeCode,
// else one Warn line on Config.Log), and only then sets the ticket cookie
// and records escape_issued with the signals. Nothing is written to the
// account. It reports whether a code was issued; when not, no ticket or
// cookie exists and the refusal is as it always was.
func (g *Gate) startEscape(w http.ResponseWriter, r *http.Request, user *gauntlet.User, res loginReservation, method gauntlet.SignInMethod, place signInPlace, signals gauntlet.SignInSignals, now time.Time) bool {
	if !g.escapeOffered(user, method, now) {
		return false
	}
	display, canonical := gauntlet.NewOneTimeCode()
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		g.logError("gate: generating an escape ticket id: " + err.Error())
		return false
	}
	ticket, err := escapeLoginCodec.seal(escapeLoginState{
		UserID: user.ID, IssuedAt: now, ID: hex.EncodeToString(id),
		CodeHash: escapeCodeHash(canonical), Signals: signals, Method: method,
	})
	if err != nil {
		g.logError(err.Error())
		return false
	}
	address := place.client.Address
	if h := g.cfg.OnEscapeCode; h != nil {
		err := g.callBounded(r.Context(), func(context.Context) error {
			h.EscapeCode(user.Username, address, display)
			return nil
		})
		if err != nil {
			g.logError(fmt.Sprintf("gate: Config.OnEscapeCode could not take the escape code for account %q: %q", user.Username, err.Error()))
			return false
		}
	} else {
		g.logWarn(escapeCodeLogLine(user.Username, address, display))
	}
	g.writeCookie(w, escapeLoginCookieName, ticket, escapeLoginCookiePath, int(EscapeCodeLifetime.Seconds()))
	ev := loginEvent(user, "", gauntlet.SignInEscapeIssued, method)
	ev.Client.Unusual = signals
	g.recordSignIn(r, ev, res, now)
	return true
}

func (g *Gate) clearEscapeLoginCookie(w http.ResponseWriter) {
	g.writeCookie(w, escapeLoginCookieName, "", escapeLoginCookiePath, -1)
}

// loginEscapeRequest is POST /api/auth/login/escape's body.
type loginEscapeRequest struct {
	Code string `json:"code"`
}

// handleLoginEscape completes a refused lone admin's sign-in with the
// escape code from the server's log (#66). It is handleLoginConfirm with
// the escape cookie, codec and spent set, and the reset-code form of the
// code. Session-exempt, like login; the CSRF header is required as on
// every POST. A missing, invalid, expired or spent ticket, or one whose
// account is gone, is 401 step-expired and the cookie is cleared. The
// attempt is reserved on the account and address as any login step (429
// past the limit, so an address ban or a lockout refuses it too). A wrong
// code keeps the reservation, which counts the failure, and counts toward
// the run of second-factor failures that forces a new password; the
// answer is 401 invalid-credentials whatever is wrong with it. The right
// code completes the sign-in: the session carries the ticket's signals,
// the history row is a success marked confirmed, and the browser, country
// and place are remembered.
func (g *Gate) handleLoginEscape(w http.ResponseWriter, r *http.Request) {
	var req loginEscapeRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}
	now := g.now()
	expired := func() {
		g.clearEscapeLoginCookie(w)
		writeUnauthorized(w, classStepExpired, "sign in again")
	}
	cookie, err := r.Cookie(escapeLoginCookieName)
	if err != nil {
		expired()
		return
	}
	st, ok := decodeEscapeLogin(cookie.Value, now)
	if !ok || spentEscapeLogins.Spent(st.ID, now) {
		expired()
		return
	}
	user, ok := g.deps.Users.Get(st.UserID)
	if !ok {
		expired()
		return
	}
	res, ok := g.reserveLogin(w, r, user.ID, user.Username, gauntlet.SignInMethodCode, false, now)
	if !ok {
		return
	}
	defer g.releaseAfterReset(res)

	if !escapeCodeMatches(req.Code, st.CodeHash) {
		g.endAfterReset(res)
		g.secondFactorFailed(user, now)
		g.recordSignIn(r, loginEvent(user, "", gauntlet.SignInEscapeRefused, gauntlet.SignInMethodCode), res, now)
		writeUnauthorized(w, classInvalidCredentials, "invalid escape code")
		return
	}
	// One-shot: of two completions racing on one ticket, the loser is a
	// replay and is told to sign in again, as confirm's is.
	if !spentEscapeLogins.Claim(st.ID, st.IssuedAt.Add(EscapeCodeLifetime), now) {
		g.endAfterReset(res)
		expired()
		return
	}
	g.completeLogin(res, now)
	g.endAfterReset(res)
	g.clearEscapeLoginCookie(w)
	place := g.placeOf(r, res.address)
	notice := g.completeSignIn(w, r, user, res, st.Method, place,
		unusualVerdict{action: UnusualSignInBlock, signals: st.Signals, reason: "escape", escape: true}, now)
	writeJSON(w, http.StatusOK, map[string]any{"username": user.Username, "role": user.Role})
	g.notify(r.Context(), notice)
}
