package gate

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// loginReservation is what one login attempt holds against the
// LoginLimiter: the client address, and the account being tried -- by
// its ID when the name matches an account, so its counter and its
// persisted lockout are the account's own (#19), or by the typed name
// when it matches none. Either a single source hammering many usernames
// or many sources hammering one account is bounded, as in mikroview's
// handleAuthLogin.
type loginReservation struct {
	ipKey     string
	accountID string // set when the name matched an account
	nameKey   string // set when it did not
	// afterReset is set when the address was at its limit and the
	// attempt went ahead on the account's pass after a password reset
	// (gauntlet.LoginLimiter.AllowAfterReset, #32): nothing is
	// reserved on ipKey, so nothing is released from it either.
	afterReset bool
	// pendingAfterReset is set for a code step whose password step spent
	// the pass (pendingLoginState.AfterReset): ipKey is skipped, and there
	// is no pass left to hand back or use up.
	pendingAfterReset bool
}

// reserveLogin reserves one attempt on both buckets, or neither, and
// writes the 429 itself when it is neither. accountID is "" for a name
// that matches no account.
//
// An account reset out of a lockout after its address reached the limit
// gets past the address bucket, one attempt at a time, until its
// sign-in finishes or a guess fails (AllowAfterReset, #32); its own
// bucket still applies.
func (g *Gate) reserveLogin(w http.ResponseWriter, r *http.Request, accountID, username string, pendingAfterReset bool, now time.Time) (loginReservation, bool) {
	res := loginReservation{ipKey: "ip:" + g.cfg.ClientIP(r), accountID: accountID, pendingAfterReset: pendingAfterReset}
	if accountID == "" {
		res.nameKey = "user:" + strings.ToLower(username)
	}
	ok := pendingAfterReset || g.deps.Limiter.Reserve(res.ipKey, now)
	if !ok && accountID != "" && g.deps.Limiter.AllowAfterReset(res.ipKey, g.deps.Users, accountID, now) {
		ok, res.afterReset = true, true
	}
	if ok {
		if accountID != "" {
			ok = g.deps.Limiter.ReserveAccount(g.deps.Users, accountID, now)
		} else {
			ok = g.deps.Limiter.Reserve(res.nameKey, now)
		}
		if !ok && !res.afterReset && !pendingAfterReset {
			g.deps.Limiter.Release(res.ipKey, now)
		}
		if !ok && res.afterReset {
			g.deps.Limiter.ReleaseAfterReset(res.ipKey, accountID)
		}
	}
	if !ok {
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
	}
	return res, ok
}

// releaseLogin returns both reservations after a successful attempt.
func (g *Gate) releaseLogin(res loginReservation, now time.Time) {
	if !res.afterReset && !res.pendingAfterReset {
		g.deps.Limiter.Release(res.ipKey, now)
	}
	if res.accountID != "" {
		g.deps.Limiter.ReleaseAccount(g.deps.Users, res.accountID, now)
	} else {
		g.deps.Limiter.Release(res.nameKey, now)
	}
}

// endAfterReset uses up the account's pass past the address limit, if
// this attempt used one: called when a session is issued, when the
// password step hands over to the code step (the pending login carries
// it from there), and on a wrong password.
func (g *Gate) endAfterReset(res loginReservation) {
	if res.afterReset {
		g.deps.Limiter.EndAfterReset(res.ipKey, res.accountID)
	}
}

// releaseAfterReset hands the pass back when the attempt holding it
// returns, whichever way: deferred straight after reserveLogin, so a
// concurrent attempt is refused only while this one runs. After
// endAfterReset it changes nothing.
func (g *Gate) releaseAfterReset(res loginReservation) {
	if res.afterReset {
		g.deps.Limiter.ReleaseAfterReset(res.ipKey, res.accountID)
	}
}

// handleLogin is rate-limited independently by account and by source
// IP (gauntlet.LoginLimiter) -- see reserveLogin.
func (g *Gate) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req credentialsRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	now := g.now()
	var accountID string
	if u, ok := g.deps.Users.ByUsername(req.Username); ok {
		accountID = u.ID
	}
	// Reserve, not a read-then-record: the attempt is claimed *before*
	// the ~100ms Argon2id verification, exactly as mikroview's own
	// handleAuthLogin explains -- otherwise a simultaneous burst all
	// pass a plain check before any of them finishes verifying, and a
	// threshold of N admits as many concurrent attempts as an attacker
	// cares to send.
	res, ok := g.reserveLogin(w, r, accountID, req.Username, false, now)
	if !ok {
		return
	}
	defer g.releaseAfterReset(res)

	user, err := g.deps.Users.Authenticate(req.Username, req.Password, now)
	if err != nil && !errors.Is(err, gauntlet.ErrInvalidCredentials) {
		// Authenticate's only other error is a reset code's spend that
		// could not be saved. Refused either way, but that is the
		// backend failing, not a wrong credential: no 401, and no count
		// toward a lockout that outlasts the outage.
		g.releaseLogin(res, now)
		g.logError("recording login for " + req.Username + ": " + err.Error())
		http.Error(w, "unable to complete sign-in", http.StatusInternalServerError)
		return
	}
	if err != nil {
		// Reservations stay claimed -- that is what counts the failure.
		// Deliberately the same body and status for an unknown username,
		// a wrong password and a revoked/expired reset code alike (see
		// gauntlet.Store.Authenticate's own doc comment): none of that
		// distinction is safe to hand back to whoever is asking.
		g.endAfterReset(res)
		writeUnauthorized(w, "invalid username or password")
		return
	}
	// Only a success releases, so ordinary repeated logins never
	// accumulate toward the threshold.
	g.releaseLogin(res, now)

	// A correct password on an account holding an active second factor
	// must NOT create a session -- see docs/design.md §1.6 and the
	// SECURITY note gauntlet #7's brief called out explicitly. What it
	// gets instead is a short-lived pending-login cookie naming the
	// account, and the caller is told which factor to ask for next. The
	// real login only happens in handleLoginFactor below, once that
	// code (or a recovery code) checks out too.
	//
	// HasSecondFactor, not HasActiveTOTP: User carries a Passkeys field
	// (round-tripped from mikroview's documents, docs/design.md
	// Summary) even though the passkey ceremony itself is deferred to
	// G8. An account whose only factor is a passkey still gets the
	// pending cookie -- so a recovery code can still complete the login
	// below -- but an empty factors list, since gate has no passkey
	// verification to offer yet.
	if user.HasSecondFactor() {
		factors := []string{}
		if user.HasActiveTOTP() {
			factors = append(factors, "totp")
		}
		// A pass is spent here, not held across the code step: the
		// pending login carries the owner past the address limit
		// instead, so a guess sent in between cannot take it.
		g.endAfterReset(res)
		if err := g.setPendingLoginCookie(w, user.ID, res.afterReset, now); err != nil {
			g.logError("sealing pending-login cookie for " + user.Username + ": " + err.Error())
			http.Error(w, "unable to complete sign-in", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"secondFactor": factors})
		return
	}

	// A leftover pending-login cookie from an earlier, abandoned attempt
	// (this account or another one on the same browser) has no bearing
	// on a login that just completed through the ordinary one-step path.
	g.clearPendingLoginCookie(w)
	g.endAfterReset(res)
	sess := g.deps.Sessions.Create(user.ID, now)
	g.setSessionCookie(w, sess.ID)
	g.audit(user.Username, "user.login", user.Username, "")
	writeJSON(w, http.StatusOK, map[string]any{"username": user.Username, "role": user.Role})
}

type loginFactorRequest struct {
	Code string `json:"code"`
}

// handleLoginFactor completes a login that handleLogin stopped short of a
// session for: the pending-login cookie names the account whose password
// already checked out, and this checks one more credential against it --
// a live TOTP code, or, since that can be lost too, one of the account's
// ten recovery codes, burned the moment it works.
//
// Rate-limited on the exact same LoginLimiter buckets handleLogin itself
// reserves against (the address and the account) -- a wrong code
// here is exactly as good a brute-force move as a wrong password there,
// so both share one budget rather than each getting their own.
func (g *Gate) handleLoginFactor(w http.ResponseWriter, r *http.Request) {
	var req loginFactorRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie(pendingLoginCookieName)
	if err != nil {
		writeUnauthorized(w, "sign in again")
		return
	}
	now := g.now()
	st, err := pendingLoginCodec.decode(cookie.Value, now)
	if err != nil {
		g.clearPendingLoginCookie(w)
		writeUnauthorized(w, "sign in again")
		return
	}

	// The account was deleted, or every second factor it held was
	// cleared -- by an admin, or the account owner themselves -- in the
	// window between the password step and this one. Either way there
	// is nothing left this cookie can complete.
	user, ok := g.deps.Users.Get(st.UserID)
	if !ok || !user.HasSecondFactor() {
		g.clearPendingLoginCookie(w)
		writeUnauthorized(w, "sign in again")
		return
	}

	res, ok := g.reserveLogin(w, r, user.ID, user.Username, st.AfterReset, now)
	if !ok {
		return
	}
	defer g.releaseAfterReset(res)

	// Verified and recorded in one call, under the store's lock, so two
	// concurrent submissions of the same code can't both check against
	// the same not-yet-advanced counter -- see VerifyAndRecordTOTP's own
	// doc comment.
	matched, err := g.deps.Users.VerifyAndRecordTOTP(user.ID, req.Code, now)
	if err != nil {
		// A code whose counter could not be saved is refused (ok is
		// false), but that is the backend failing, not a wrong guess: it
		// must not try the recovery codes, answer 401, or count toward
		// a lockout that outlasts the outage.
		g.releaseLogin(res, now)
		g.logError("recording TOTP replay counter for " + user.Username + ": " + err.Error())
		http.Error(w, "unable to complete sign-in", http.StatusInternalServerError)
		return
	}
	if matched {
		g.completeLoginFactor(w, user, res, now)
		return
	}

	if burned, err := g.deps.Users.BurnRecoveryCode(user.ID, req.Code, now); err != nil {
		// A wrong or used code is (false, nil); an error is a spend that
		// could not be saved. Refused either way, but as the backend's
		// failure, like the TOTP case above: no 401, no lockout count.
		g.releaseLogin(res, now)
		g.logError("recording spent recovery code for " + user.Username + ": " + err.Error())
		http.Error(w, "unable to complete sign-in", http.StatusInternalServerError)
		return
	} else if burned {
		g.completeLoginFactor(w, user, res, now)
		return
	}

	// Reservations stay claimed -- that is what counts the failure, same
	// as handleLogin's own wrong-password path. Deliberately one message
	// regardless of whether the code looked like a TOTP guess or a
	// recovery-code guess: which kind was tried is not information a
	// caller needs back.
	g.endAfterReset(res)
	writeUnauthorized(w, "invalid code")
}

// completeLoginFactor is handleLoginFactor's success path: release the
// reservations a wrong guess would have kept, drop the now-spent pending
// cookie, and issue the real session handleLogin withheld.
func (g *Gate) completeLoginFactor(w http.ResponseWriter, user *gauntlet.User, res loginReservation, now time.Time) {
	g.releaseLogin(res, now)
	g.endAfterReset(res)
	g.clearPendingLoginCookie(w)
	sess := g.deps.Sessions.Create(user.ID, now)
	g.setSessionCookie(w, sess.ID)
	g.audit(user.Username, "user.login", user.Username, "via second factor")
	writeJSON(w, http.StatusOK, map[string]any{"username": user.Username, "role": user.Role})
}
