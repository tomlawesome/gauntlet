package gate

import (
	"net/http"
	"strings"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// loginLimiterKeys returns the two LoginLimiter buckets a login attempt
// is reserved against -- client IP and username, mirroring mikroview's
// handleAuthLogin -- so that either a single source hammering many
// usernames or many sources hammering one username is bounded.
func (g *Gate) loginLimiterKeys(r *http.Request, username string) (ipKey, userKey string) {
	return "ip:" + g.cfg.ClientIP(r), "user:" + strings.ToLower(username)
}

// handleLogin is rate-limited independently by username and by source
// IP (gauntlet.LoginLimiter) -- see loginLimiterKeys.
func (g *Gate) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req credentialsRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	now := g.now()
	ipKey, userKey := g.loginLimiterKeys(r, req.Username)
	// Reserve, not a read-then-record: the attempt is claimed *before*
	// the ~100ms Argon2id verification, exactly as mikroview's own
	// handleAuthLogin explains -- otherwise a simultaneous burst all
	// pass a plain check before any of them finishes verifying, and a
	// threshold of N admits as many concurrent attempts as an attacker
	// cares to send.
	if !g.deps.Limiter.Reserve(ipKey, now) {
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
		return
	}
	if !g.deps.Limiter.Reserve(userKey, now) {
		g.deps.Limiter.Release(ipKey, now)
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
		return
	}

	user, err := g.deps.Users.Authenticate(req.Username, req.Password, now)
	if err != nil {
		// Reservations stay claimed -- that is what counts the failure.
		// Deliberately the same body and status for an unknown username,
		// a wrong password and a revoked/expired reset code alike (see
		// gauntlet.Store.Authenticate's own doc comment): none of that
		// distinction is safe to hand back to whoever is asking.
		writeUnauthorized(w, "invalid username or password")
		return
	}
	// Only a success releases, so ordinary repeated logins never
	// accumulate toward the threshold.
	g.deps.Limiter.Release(ipKey, now)
	g.deps.Limiter.Release(userKey, now)

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
		if err := g.setPendingLoginCookie(w, user.ID, now); err != nil {
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
// reserves against (ip: and user:, keyed the same way) -- a wrong code
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

	ipKey, userKey := g.loginLimiterKeys(r, user.Username)
	if !g.deps.Limiter.Reserve(ipKey, now) {
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
		return
	}
	if !g.deps.Limiter.Reserve(userKey, now) {
		g.deps.Limiter.Release(ipKey, now)
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
		return
	}

	// Verified and recorded in one call, under the store's lock, so two
	// concurrent submissions of the same code can't both check against
	// the same not-yet-advanced counter -- see VerifyAndRecordTOTP's own
	// doc comment.
	if matched, err := g.deps.Users.VerifyAndRecordTOTP(user.ID, req.Code, now); matched {
		if err != nil {
			// The replay guard failing to advance doesn't undo the fact
			// that a correct, unreplayed code was just presented -- see
			// VerifyAndRecordTOTP's own doc comment.
			g.logWarn("advancing TOTP replay counter for " + user.Username + ": " + err.Error())
		}
		g.completeLoginFactor(w, user, ipKey, userKey, now)
		return
	}

	if burned, err := g.deps.Users.BurnRecoveryCode(user.ID, req.Code, now); err != nil {
		g.logError("recording spent recovery code for " + user.Username + ": " + err.Error())
	} else if burned {
		g.completeLoginFactor(w, user, ipKey, userKey, now)
		return
	}

	// Reservations stay claimed -- that is what counts the failure, same
	// as handleLogin's own wrong-password path. Deliberately one message
	// regardless of whether the code looked like a TOTP guess or a
	// recovery-code guess: which kind was tried is not information a
	// caller needs back.
	writeUnauthorized(w, "invalid code")
}

// completeLoginFactor is handleLoginFactor's success path: release the
// reservations a wrong guess would have kept, drop the now-spent pending
// cookie, and issue the real session handleLogin withheld.
func (g *Gate) completeLoginFactor(w http.ResponseWriter, user *gauntlet.User, ipKey, userKey string, now time.Time) {
	g.deps.Limiter.Release(ipKey, now)
	g.deps.Limiter.Release(userKey, now)
	g.clearPendingLoginCookie(w)
	sess := g.deps.Sessions.Create(user.ID, now)
	g.setSessionCookie(w, sess.ID)
	g.audit(user.Username, "user.login", user.Username, "via second factor")
	writeJSON(w, http.StatusOK, map[string]any{"username": user.Username, "role": user.Role})
}
