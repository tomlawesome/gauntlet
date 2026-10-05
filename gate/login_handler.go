package gate

import (
	"encoding/json"
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
	// knownBrowser is set when the ordinary path refused the attempt and
	// it went ahead on the known browser's own allowance
	// (gauntlet.LoginLimiter.ReserveKnownBrowser, #44): that is the one
	// reservation it holds -- nothing on ipKey or the account's login
	// budget -- so it is the one released.
	knownBrowser bool

	// address is the client address ipKey was built from, so the
	// attempt's record names the address the limiter counted
	// (recordSignIn).
	address string
	// refusal is why reserveLogin refused the attempt: locked, disabled
	// or rate_limited. Empty for an admitted one.
	refusal gauntlet.SignInOutcome
	// lockoutStarted, disabledNow and lockouts are the account's
	// decision for this attempt (gauntlet.AccountDecision): set when the
	// attempt filled the window and started a lockout ending at
	// lockedUntil, or disabled sign-in. They are recorded only if the
	// attempt then fails; one that succeeds hands both back. lockedUntil
	// is also the end of the lockout that refused an attempt.
	lockoutStarted bool
	disabledNow    bool
	lockouts       int
	lockedUntil    time.Time
}

// reserveLogin reserves one attempt on both buckets, or neither, and
// writes the 429 itself when it is neither. accountID is "" for a name
// that matches no account.
//
// An account reset out of a lockout after its address reached the limit
// gets past the address bucket, one attempt at a time, until its
// sign-in finishes or a guess fails (AllowAfterReset, #32); its own
// bucket still applies.
//
// When that path refuses an attempt on a real account -- the account
// locked out, or the address at its limit -- a browser the account
// remembers gets one more chance, on its own allowance
// (ReserveKnownBrowser, #44): a stranger who locked the owner out has
// no such browser. The cookie is checked only then, so an ordinary
// attempt costs no extra read, and the allowance's bucket exists only
// for a token that matched. It is refused while the account is
// disabled, and every failure through it still counts toward the
// disable.
//
// username is the account's own username when accountID is set, else
// the name as typed; method is what the attempt presents. A refusal is
// recorded (recordSignIn) as locked, disabled or rate_limited.
//
// An address that has been banned (AddressBanned) is refused first with
// the same 429 and rate_limited as the address limit, unless the browser
// is a known one for the account (see below). Failed attempts are
// counted toward the ban in recordSignIn, not here.
func (g *Gate) reserveLogin(w http.ResponseWriter, r *http.Request, accountID, username string, method gauntlet.SignInMethod, pendingAfterReset bool, now time.Time) (loginReservation, bool) {
	address := g.cfg.ClientIP(r)
	res := loginReservation{ipKey: "ip:" + address, address: address, accountID: accountID, pendingAfterReset: pendingAfterReset}
	if accountID == "" {
		res.nameKey = "user:" + strings.ToLower(username)
	}
	// A banned address (gauntlet.LoginLimiter.AddressBanned, #70) is
	// refused before anything is reserved, as the address limit refuses
	// it, unless the browser is one the account remembers: behind a
	// reverse proxy that hands gauntlet its own address, one attacker's
	// ban would otherwise be everyone's, the owner's included. Such a
	// browser goes on to the ordinary path, which may still refuse it
	// and give it its own allowance below.
	_, banned := g.deps.Limiter.AddressBanned(address, now)
	if banned && accountID != "" && g.isKnownBrowser(r, accountID, now) {
		banned = false
	}
	ok := !banned && (pendingAfterReset || g.deps.Limiter.Reserve(res.ipKey, now))
	if !ok && !banned && accountID != "" && g.deps.Limiter.AllowAfterReset(res.ipKey, g.deps.Users, accountID, now) {
		ok, res.afterReset = true, true
	}
	if ok {
		if accountID != "" {
			d := g.deps.Limiter.ReserveAccountDecision(g.deps.Users, accountID, now)
			ok = d.Allowed
			res.lockoutStarted, res.disabledNow, res.lockouts, res.lockedUntil = d.LockoutStarted, d.DisabledNow, d.Lockouts, d.LockedUntil
			switch {
			case d.Disabled:
				res.refusal = gauntlet.SignInDisabled
			case d.Locked:
				res.refusal = gauntlet.SignInLocked
			}
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
	if !ok && !banned && accountID != "" && g.isKnownBrowser(r, accountID, now) {
		if d := g.deps.Limiter.ReserveKnownBrowserDecision(g.deps.Users, accountID, now); d.Allowed {
			// Whatever the ordinary path reserved has been handed back
			// above, a reset pass included, so this is the only
			// reservation the attempt holds. A failure through it that
			// disables sign-in is recorded as one on the ordinary path
			// is (#45); filling the allowance is no lockout.
			ok, res.afterReset, res.knownBrowser, res.refusal = true, false, true, ""
			res.lockoutStarted, res.lockedUntil = false, time.Time{}
			res.disabledNow, res.lockouts = d.DisabledNow, d.Lockouts
		}
	}
	if !ok {
		if res.refusal == "" {
			res.refusal = gauntlet.SignInRateLimited
		}
		ev := gauntlet.SignInEvent{UserID: accountID, Username: username, Outcome: res.refusal, Method: method}
		if accountID == "" {
			ev.Username = gauntlet.MaskUnknownUsername(username)
		}
		g.recordSignIn(r, ev, res, now)
		writeProblem(w, http.StatusTooManyRequests, classRateLimited, "too many attempts, try again later", nil)
	}
	return res, ok
}

// releaseLogin returns both reservations after a successful attempt,
// or the known browser's one (ReleaseKnownBrowser).
func (g *Gate) releaseLogin(res loginReservation, now time.Time) {
	if res.knownBrowser {
		g.deps.Limiter.ReleaseKnownBrowser(g.deps.Users, res.accountID, now)
		return
	}
	if !res.afterReset && !res.pendingAfterReset {
		g.deps.Limiter.Release(res.ipKey, now)
	}
	if res.accountID != "" {
		g.deps.Limiter.ReleaseAccount(g.deps.Users, res.accountID, now)
	} else {
		g.deps.Limiter.Release(res.nameKey, now)
	}
}

// completeLogin is releaseLogin for an attempt that completed a sign-in
// -- a session is about to be issued -- rather than only passing the
// password step: it returns the address reservation, and resets the
// account's whole count (gauntlet.LoginLimiter.SignedIn, #44): its
// lockouts, the attempts in its window and its run of second-factor
// failures. A correct password on an account that still owes a second
// factor is releaseLogin, which resets none of that.
func (g *Gate) completeLogin(res loginReservation, now time.Time) {
	if res.accountID == "" {
		// The name matched no account when the attempt was reserved --
		// one created since -- so there is no account count to reset.
		g.releaseLogin(res, now)
		return
	}
	if !res.afterReset && !res.pendingAfterReset && !res.knownBrowser {
		g.deps.Limiter.Release(res.ipKey, now)
	}
	// SignedIn drops the known browser's allowance too.
	g.deps.Limiter.SignedIn(g.deps.Users, res.accountID, now)
}

// secondFactorFailed counts a refused second-factor step toward the
// account's run of them (gauntlet.LoginLimiter.SecondFactorFailed, #44),
// on top of the reservation the attempt keeps. Only the pending login's
// owner reaches that step, and only with the right password, so enough
// of them in a row require a new password at the next sign-in.
func (g *Gate) secondFactorFailed(user *gauntlet.User, now time.Time) {
	g.deps.Limiter.SecondFactorFailed(g.deps.Users, user.ID, now)
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
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}

	now := g.now()
	var matched *gauntlet.User
	accountID, name := "", req.Username
	if u, ok := g.deps.Users.ByUsername(req.Username); ok {
		matched, accountID, name = u, u.ID, u.Username
	}
	// Reserve, not a read-then-record: the attempt is claimed *before*
	// the ~100ms Argon2id verification, exactly as mikroview's own
	// handleAuthLogin explains -- otherwise a simultaneous burst all
	// pass a plain check before any of them finishes verifying, and a
	// threshold of N admits as many concurrent attempts as an attacker
	// cares to send.
	res, ok := g.reserveLogin(w, r, accountID, name, gauntlet.SignInMethodPassword, false, now)
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
		writeProblem(w, http.StatusInternalServerError, classServerError, "unable to complete sign-in", nil)
		return
	}
	if err != nil {
		// Reservations stay claimed -- that is what counts the failure.
		// Deliberately the same body and status for an unknown username,
		// a wrong password and a revoked/expired reset code alike (see
		// gauntlet.Store.Authenticate's own doc comment): none of that
		// distinction is safe to hand back to whoever is asking.
		g.endAfterReset(res)
		outcome := gauntlet.SignInWrongPassword
		if matched == nil {
			outcome = gauntlet.SignInNoSuchUser
		}
		g.recordSignIn(r, loginEvent(matched, req.Username, outcome, gauntlet.SignInMethodPassword), res, now)
		writeUnauthorized(w, classInvalidCredentials, "invalid username or password")
		return
	}
	// Only a success releases, so ordinary repeated logins never
	// accumulate toward the threshold: releaseLogin for a password that
	// still owes a second factor, completeLogin for a sign-in it
	// completes.

	// A correct password on an account holding an active second factor
	// must NOT create a session -- see docs/design.md §1.6 and the
	// SECURITY note gauntlet #7's brief called out explicitly. What it
	// gets instead is a short-lived pending-login cookie naming the
	// account, and the caller is told which factor to ask for next. The
	// real login only happens in handleLoginFactor below, once that
	// code (or a recovery code) checks out too.
	//
	// HasSecondFactor, not HasActiveTOTP: an account may hold a passkey
	// instead of, or alongside, an authenticator app. The factor list
	// names only what is usable now, passkey first (mikroview's order):
	// "passkey" when the relying party is ready and the account holds at
	// least one passkey under its current RP ID, with passkeyOrigin
	// beside it; "totp" when that is active. An account whose only
	// passkeys are stale, or whose application has no passkeys
	// (Deps.Passkeys nil), still gets the pending cookie -- so a
	// recovery code can complete the login below -- but may get an
	// empty list.
	if user.HasSecondFactor() {
		g.releaseLogin(res, now)
		factors := []string{}
		passkeyOrigin := ""
		if g.usablePasskeyCount(user) > 0 {
			factors = append(factors, "passkey")
			passkeyOrigin = g.deps.Passkeys.Origin()
		}
		if user.HasActiveTOTP() {
			factors = append(factors, "totp")
		}
		// A pass is spent here, not held across the code step: the
		// pending login carries the owner past the address limit
		// instead, so a guess sent in between cannot take it.
		g.endAfterReset(res)
		if err := g.setPendingLoginCookie(w, user.ID, res.afterReset, now); err != nil {
			g.logError("sealing pending-login cookie for " + user.Username + ": " + err.Error())
			writeProblem(w, http.StatusInternalServerError, classServerError, "unable to complete sign-in", nil)
			return
		}
		g.recordSignIn(r, loginEvent(user, "", gauntlet.SignInPasswordOK, gauntlet.SignInMethodPassword), res, now)
		resp := map[string]any{"secondFactor": factors}
		if passkeyOrigin != "" {
			resp["passkeyOrigin"] = passkeyOrigin
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// Every credential has passed: judge the sign-in (#55) before any
	// session exists.
	place := g.placeOf(r, res.address)
	verdict := g.judgeSignIn(r, user, gauntlet.SignInMethodPassword, place, now)
	if verdict.stopsSignIn() {
		// Confirm or block: the credential was right, so the attempt is
		// handed back rather than completed; nothing completed, so the
		// account's count is not reset.
		g.releaseLogin(res, now)
		g.endAfterReset(res)
		g.clearPendingLoginCookie(w)
		sent, notice := g.stopSignIn(w, r, user, res, gauntlet.SignInMethodPassword, place, verdict, now)
		if sent {
			writeJSON(w, http.StatusOK, g.heldChallenge(verdict))
			return
		}
		writeSignInRefused(w)
		g.notify(r.Context(), notice)
		return
	}

	// A leftover pending-login cookie from an earlier, abandoned attempt
	// (this account or another one on the same browser) has no bearing
	// on a login that just completed through the ordinary one-step path.
	g.completeLogin(res, now)
	g.clearPendingLoginCookie(w)
	g.endAfterReset(res)
	// The session this browser already held for the account ends here:
	// the cookie below replaces it, and nothing else would (ASVS 7.2.4;
	// see revokeReplacedSession).
	notice := g.completeSignIn(w, r, user, res, gauntlet.SignInMethodPassword, place, verdict, now)
	writeJSON(w, http.StatusOK, map[string]any{"username": user.Username, "role": user.Role})
	g.notify(r.Context(), notice)
}

type loginFactorRequest struct {
	Code string `json:"code"`
	// Assertion is the passkey branch (G8): the browser's
	// PublicKeyCredential JSON from navigator.credentials.get(), for the
	// ceremony login/factor/begin started. A frontend sends this or
	// Code, and the branch follows whichever is present.
	Assertion json.RawMessage `json:"assertion,omitempty"`
}

// handleLoginFactor completes a login that handleLogin stopped short of a
// session for: the pending-login cookie names the account whose password
// already checked out, and this checks one more credential against it --
// a live TOTP code, a passkey assertion (verifyPasskeyAssertion), or,
// since either can be lost too, one of the account's ten recovery codes,
// burned the moment it works.
//
// Rate-limited on the exact same LoginLimiter buckets handleLogin itself
// reserves against (the address and the account) -- a wrong code or a
// refused assertion here is exactly as good a brute-force move as a
// wrong password there, so all of them share one budget rather than each
// getting their own.
func (g *Gate) handleLoginFactor(w http.ResponseWriter, r *http.Request) {
	var req loginFactorRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}
	// An assertion where the application has no passkeys is a request
	// for a route that does not exist here, as every passkey route is.
	if len(req.Assertion) > 0 && g.passkeysOff(w, r) {
		return
	}

	now := g.now()
	st, ok := g.pendingLogin(w, r, now)
	if !ok {
		return
	}

	// The account was deleted, or every second factor it held was
	// cleared -- by an admin, or the account owner themselves -- in the
	// window between the password step and this one. Either way there
	// is nothing left this cookie can complete.
	user, ok := g.deps.Users.Get(st.UserID)
	if !ok || !user.HasSecondFactor() {
		g.clearPendingLoginCookie(w)
		writeUnauthorized(w, classStepExpired, "sign in again")
		return
	}

	method := gauntlet.SignInMethodCode
	if len(req.Assertion) > 0 {
		method = gauntlet.SignInMethodPasskey
	}
	res, ok := g.reserveLogin(w, r, user.ID, user.Username, method, st.AfterReset, now)
	if !ok {
		return
	}
	defer g.releaseAfterReset(res)

	if len(req.Assertion) > 0 {
		if g.verifyPasskeyAssertion(w, r, user, req.Assertion, res, now) {
			// login/factor/begin reserved one attempt on each key for
			// the challenge this assertion answered; a completed sign-in
			// hands that back too, so a passkey sign-in costs none of
			// the budget a wrong guess is limited by. completeLoginFactor
			// releases this request's own; begin's goes back only once
			// the sign-in has actually completed, so a replay refused
			// there keeps both.
			if g.completeLoginFactor(w, r, user, res, st, method, now) {
				g.releaseLogin(res, now)
			}
		}
		return
	}

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
		writeProblem(w, http.StatusInternalServerError, classServerError, "unable to complete sign-in", nil)
		return
	}
	if matched {
		g.completeLoginFactor(w, r, user, res, st, method, now)
		return
	}

	if burned, err := g.deps.Users.BurnRecoveryCode(user.ID, req.Code, now); err != nil {
		// A wrong or used code is (false, nil); an error is a spend that
		// could not be saved. Refused either way, but as the backend's
		// failure, like the TOTP case above: no 401, no lockout count.
		g.releaseLogin(res, now)
		g.logError("recording spent recovery code for " + user.Username + ": " + err.Error())
		writeProblem(w, http.StatusInternalServerError, classServerError, "unable to complete sign-in", nil)
		return
	} else if burned {
		g.completeLoginFactor(w, r, user, res, st, method, now)
		return
	}

	// Reservations stay claimed -- that is what counts the failure, same
	// as handleLogin's own wrong-password path. Deliberately one message
	// regardless of whether the code looked like a TOTP guess or a
	// recovery-code guess: which kind was tried is not information a
	// caller needs back.
	g.endAfterReset(res)
	g.secondFactorFailed(user, now)
	g.recordSignIn(r, loginEvent(user, "", gauntlet.SignInFactorRefused, gauntlet.SignInMethodCode), res, now)
	writeUnauthorized(w, classInvalidCredentials, "invalid code")
}

// completeLoginFactor is handleLoginFactor's success path: spend the
// pending login, release the reservations a wrong guess would have kept
// and reset the account's count (completeLogin), drop the pending
// cookie, and issue the real session handleLogin withheld. It reports
// whether every credential was accepted. method is how the second
// factor was presented.
//
// The pending login is claimed first, under spentPendingLogins' lock, so
// of two completions racing on one cookie exactly one wins (ruling R2 on
// #20). The loser is a replay, not a success: it keeps its reservations
// and is told to sign in again. The forget time is IssuedAt plus
// pendingLoginCookieMaxAge -- the same expiry pendingLoginCodec.decode
// refuses the cookie at, so the claim and the decode share one expiry by
// construction, on the same wall clock.
//
// It also reports true when the unusual-sign-in policy refused the
// sign-in or held it for a confirmation code (#55): every credential
// was right, so the passkey begin step's reservation is handed back as
// for a success.
func (g *Gate) completeLoginFactor(w http.ResponseWriter, r *http.Request, user *gauntlet.User, res loginReservation, st pendingLoginState, method gauntlet.SignInMethod, now time.Time) bool {
	if !spentPendingLogins.Claim(st.ID, st.IssuedAt.Add(pendingLoginCookieMaxAge), now) {
		g.endAfterReset(res)
		g.clearPendingLoginCookie(w)
		writeUnauthorized(w, classStepExpired, "sign in again")
		return false
	}
	// Every credential has passed: judge the sign-in (#55) before any
	// session exists.
	place := g.placeOf(r, res.address)
	verdict := g.judgeSignIn(r, user, method, place, now)
	if verdict.stopsSignIn() {
		// The pending login is already spent above, so one correct code
		// yields one refusal or one confirmation code, never that and
		// then a session.
		g.releaseLogin(res, now)
		g.endAfterReset(res)
		g.clearPendingLoginCookie(w)
		sent, notice := g.stopSignIn(w, r, user, res, method, place, verdict, now)
		if sent {
			writeJSON(w, http.StatusOK, g.heldChallenge(verdict))
			return true
		}
		writeSignInRefused(w)
		g.notify(r.Context(), notice)
		return true
	}
	g.completeLogin(res, now)
	g.endAfterReset(res)
	g.clearPendingLoginCookie(w)
	// As in handleLogin: the session this browser held for the account
	// is replaced by the cookie below, so it ends here (ASVS 7.2.4). Only
	// here, not at the password step, which issues no session.
	notice := g.completeSignIn(w, r, user, res, method, place, verdict, now)
	writeJSON(w, http.StatusOK, map[string]any{"username": user.Username, "role": user.Role})
	g.notify(r.Context(), notice)
	return true
}
