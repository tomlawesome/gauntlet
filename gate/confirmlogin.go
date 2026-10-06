package gate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/internal/spent"
)

// The confirm step (#55): under the confirm action an unusual sign-in is
// not finished. A code goes to the person through the application
// (Config.NotifyUnusualSignIn), and typing it into the page they are on
// -- POST /api/auth/login/confirm -- completes the same sign-in. Until
// then the browser holds a sealed ticket, never a session.

// confirmLoginCookieName carries a sign-in that has proven every
// credential and owes a confirmation code. Generic ("gate_"), as
// pendingLoginCookieName is.
const confirmLoginCookieName = "gate_confirm_login"

// confirmLoginCookiePath is loginPath, a prefix of loginConfirmPath, so
// the cookie reaches the confirm route and nothing outside the login
// routes. The SSO callback can still set it: a response sets a cookie
// for any path.
const confirmLoginCookiePath = loginPath

// ConfirmCodeLifetime is how long a confirmation code, and the ticket
// carrying its hash, lives: 15 minutes, since a mail takes a minute to
// arrive and a person a few to find it.
const ConfirmCodeLifetime = 15 * time.Minute

// confirmLoginState is what the confirm ticket carries. The code itself
// never: only its SHA-256.
type confirmLoginState struct {
	UserID   string
	IssuedAt time.Time
	// ID makes the ticket one-shot: 16 random bytes, hex, claimed in
	// spentConfirmLogins by the sign-in that completes it.
	ID string
	// CodeHash is the hex SHA-256 of the code's eight digits, no dash.
	// Empty on a prove ticket.
	CodeHash string
	Signals  gauntlet.SignInSignals
	// Method is how the credentials were presented.
	Method gauntlet.SignInMethod
	// Prove marks a ticket that is held for a passkey assertion for the
	// account (#65, login/prove) rather than a code: it carries no
	// CodeHash, and login/confirm refuses it as login/prove refuses one
	// that does not.
	Prove bool
}

// confirmLoginCodec seals the ticket with its own per-process key, so a
// restart fails a waiting confirmation cleanly and the person signs in
// again.
var confirmLoginCodec = mustNewSealCodec("confirm-login")

// spentConfirmLogins holds the ID of every ticket a sign-in has
// completed, for as long as the ticket could still open.
var spentConfirmLogins = spent.New(ConfirmCodeLifetime)

// decodeConfirmLogin opens a ticket, refusing anything malformed,
// tampered, without an ID, with a code hash when it is a prove ticket
// or none when it is not, or ConfirmCodeLifetime old or older.
func decodeConfirmLogin(value string, now time.Time) (confirmLoginState, bool) {
	var st confirmLoginState
	if !confirmLoginCodec.open(value, &st) || st.ID == "" || st.UserID == "" || (st.CodeHash == "") != st.Prove {
		return confirmLoginState{}, false
	}
	if !now.Before(st.IssuedAt.Add(ConfirmCodeLifetime)) {
		return confirmLoginState{}, false
	}
	return st, true
}

// newConfirmCode returns eight decimal digits from crypto/rand, as shown
// ("1234-5678") and as hashed ("12345678").
func newConfirmCode() (shown, digits string, err error) {
	n, err := rand.Int(rand.Reader, big.NewInt(100_000_000))
	if err != nil {
		return "", "", fmt.Errorf("gate: generating a confirmation code: %w", err)
	}
	digits = fmt.Sprintf("%08d", n.Int64())
	return digits[:4] + "-" + digits[4:], digits, nil
}

// confirmCodeHash is the form a code is kept and compared in.
func confirmCodeHash(digits string) string {
	sum := sha256.Sum256([]byte(digits))
	return hex.EncodeToString(sum[:])
}

// confirmCodeMatches reports whether typed is the code hashed as want:
// surrounding whitespace trimmed, with or without the dash, compared in
// constant time.
func confirmCodeMatches(typed, want string) bool {
	typed = strings.TrimSpace(typed)
	if len(typed) == 9 && typed[4] == '-' {
		typed = typed[:4] + typed[5:]
	}
	if len(typed) != 8 {
		return false
	}
	for i := range len(typed) {
		if typed[i] < '0' || typed[i] > '9' {
			return false
		}
	}
	return subtle.ConstantTimeCompare([]byte(confirmCodeHash(typed)), []byte(want)) == 1
}

// ConfirmCode is what Config.DeliverConfirmCode is handed: an unusual
// sign-in's confirmation code, shown to the application exactly once --
// a secret for one person -- and the case it belongs to, minus anything
// a function handed it could complete the sign-in with itself (no
// request, header, password or session).
type ConfirmCode struct {
	UserID, Username string
	Role             gauntlet.Role
	// Code is the eight digits, shown ("1234-5678"). ExpiresAt is when
	// they die.
	Code      string
	ExpiresAt time.Time
	Signals   gauntlet.SignInSignals
	Method    gauntlet.SignInMethod
	// Client is the address, agent (text, never markup) and country the
	// sign-in came from.
	Client gauntlet.SessionClient
	At     time.Time
}

// startConfirm mints a code and its ticket for user's sign-in, asks the
// application to deliver it -- synchronously, before the response, under
// decideTimeout (callBounded) -- and only then sets the ticket cookie
// and records confirm_sent with the signals (no audit record, as
// password_ok writes none). Nothing is written to the account. It
// reports whether the code went out; when it did not
// (Config.DeliverConfirmCode failed, panicked or outlasted the
// deadline), no ticket or cookie exists and the caller refuses the
// attempt (notify-failed).
func (g *Gate) startConfirm(w http.ResponseWriter, r *http.Request, user *gauntlet.User, res loginReservation, method gauntlet.SignInMethod, place signInPlace, signals gauntlet.SignInSignals, now time.Time) bool {
	deliver := g.cfg.DeliverConfirmCode
	if deliver == nil {
		return false
	}
	shown, digits, err := newConfirmCode()
	if err != nil {
		g.logError(err.Error())
		return false
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		g.logError("gate: generating a confirm ticket id: " + err.Error())
		return false
	}
	ticket, err := confirmLoginCodec.seal(confirmLoginState{
		UserID: user.ID, IssuedAt: now, ID: hex.EncodeToString(id),
		CodeHash: confirmCodeHash(digits), Signals: signals, Method: method,
	})
	if err != nil {
		g.logError(err.Error())
		return false
	}
	client := place.client
	client.Unusual = signals
	c := ConfirmCode{
		UserID: user.ID, Username: user.Username, Role: user.Role,
		Code: shown, ExpiresAt: now.Add(ConfirmCodeLifetime),
		Signals: signals, Method: method, Client: client, At: now,
	}
	if err := g.callBounded(r.Context(), func(ctx context.Context) error { return deliver(ctx, c) }); err != nil {
		g.logError(fmt.Sprintf("gate: Config.DeliverConfirmCode could not take the confirmation code for account %q: %q", user.Username, err.Error()))
		return false
	}
	g.writeCookie(w, confirmLoginCookieName, ticket, confirmLoginCookiePath, int(ConfirmCodeLifetime.Seconds()))
	ev := loginEvent(user, "", gauntlet.SignInConfirmSent, method)
	ev.Client.Unusual = signals
	g.recordSignIn(r, ev, res, now)
	return true
}

func (g *Gate) clearConfirmLoginCookie(w http.ResponseWriter) {
	g.writeCookie(w, confirmLoginCookieName, "", confirmLoginCookiePath, -1)
}

// loginConfirmRequest is POST /api/auth/login/confirm's body.
type loginConfirmRequest struct {
	Code string `json:"code"`
}

// handleLoginConfirm completes a sign-in held for a confirmation code
// (#55). Session-exempt, like login; the CSRF header is required as on
// every POST. A missing, invalid, expired or spent ticket, or one whose
// account is gone, is 401 step-expired and the cookie is cleared. The
// attempt is reserved on the account and address as any login step
// (429 past the limit). A wrong code keeps the reservation, which counts
// the failure, and counts toward the run of second-factor failures
// that forces a new password: whoever is guessing holds the password
// and the second factor. The right code completes the sign-in: the
// session carries the ticket's signals, the history row is a success
// marked confirmed, and the browser, country and place are remembered.
func (g *Gate) handleLoginConfirm(w http.ResponseWriter, r *http.Request) {
	var req loginConfirmRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}
	now := g.now()
	expired := func() {
		g.clearConfirmLoginCookie(w)
		writeUnauthorized(w, classStepExpired, "sign in again")
	}
	cookie, err := r.Cookie(confirmLoginCookieName)
	if err != nil {
		expired()
		return
	}
	st, ok := decodeConfirmLogin(cookie.Value, now)
	if !ok || st.Prove || spentConfirmLogins.Spent(st.ID, now) {
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

	if !confirmCodeMatches(req.Code, st.CodeHash) {
		g.endAfterReset(res)
		g.secondFactorFailed(user, now)
		g.recordSignIn(r, loginEvent(user, "", gauntlet.SignInConfirmRefused, gauntlet.SignInMethodCode), res, now)
		writeUnauthorized(w, classInvalidCredentials, "invalid confirmation code")
		return
	}
	// One-shot: of two completions racing on one ticket, the loser is a
	// replay and is told to sign in again, as completeLoginFactor's is.
	if !spentConfirmLogins.Claim(st.ID, st.IssuedAt.Add(ConfirmCodeLifetime), now) {
		g.endAfterReset(res)
		expired()
		return
	}
	g.completeHeldSignIn(w, r, user, res, st, UnusualSignInConfirm, now)
}

// completeHeldSignIn issues the session a held sign-in's ticket has
// earned, once its code (confirm) or passkey (prove) has checked out and
// the ticket is claimed: the limiter's reservation is completed, the
// ticket cookie dropped, the session carries the ticket's signals, the
// history row is a success marked confirmed and the browser, country and
// place are remembered. It answers 200 with the account.
func (g *Gate) completeHeldSignIn(w http.ResponseWriter, r *http.Request, user *gauntlet.User, res loginReservation, st confirmLoginState, action UnusualSignInAction, now time.Time) {
	g.completeLogin(res, now)
	g.endAfterReset(res)
	g.clearConfirmLoginCookie(w)
	place := g.placeOf(r, res.address)
	_, signals := g.issueSignInSession(w, r, user.ID, place, st.Signals, st.Method, now)
	ev := loginEvent(user, "", gauntlet.SignInSuccess, st.Method)
	ev.Client.Unusual, ev.Confirmed = signals, true
	// The note names what was judged -- the ticket's signals -- and how
	// the hold was answered, whatever remembering the browser did to the
	// session's signals: the audit says how this sign-in was completed
	// (recordSignInNote reads the action), and a failed remember write
	// must not lose that.
	note := fmt.Sprintf("unusual=%s; action=%s; ", st.Signals, action)
	g.recordSignInNote(r, ev, res, note, now)
	writeJSON(w, http.StatusOK, map[string]any{"username": user.Username, "role": user.Role})
}
