package gate

import (
	"net/http"
	"strings"
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

	// TODO(G6 stage 2): mikroview's handleAuthLogin stops here for an
	// account holding an active second factor -- it seals a short-lived
	// pending-login cookie naming the account and answers with the
	// factor(s) available, and only POST /api/auth/login/factor (not in
	// this stage) actually creates a session. This is that branch
	// point: a correct password on such an account must not fall
	// through to session creation below once the second-factor login
	// step exists. Until then, a HasSecondFactor account still
	// completes login through this one-step path -- there is no
	// pending-cookie/verification code in gate yet to hand off to -- so
	// RequireSecondFactor deployments should not treat login itself as
	// enforcing the factor; only Protect's own door (protect.go) does.
	if user.HasSecondFactor() {
		g.logWarn("login for " + user.Username + ": account holds a second factor, but gate stage 1 has no login/factor step -- completing as a single-step login (see the G6 stage 2 TODO in login_handler.go)")
	}

	sess := g.deps.Sessions.Create(user.ID, now)
	g.setSessionCookie(w, sess.ID)
	g.audit(user.Username, "user.login", user.Username, "")
	writeJSON(w, http.StatusOK, map[string]any{"username": user.Username, "role": user.Role})
}
