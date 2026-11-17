package gate

import (
	"net/http"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// login/factor/begin and the login buckets (#85): begin counts on a
// budget of the account's own, never handed back, so every release in
// the factor step returns a reservation that same request took.

// Prompts the owner abandons cost no sign-in attempts: as many begins as
// the threshold, none finished, and the password step still answers
// 200 from the same address with no lockout on the record.
func TestPasskeyAbandonedFactorBeginsStartNoLockout(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	registerPasskey(t, bilbo, ts, g, "YubiKey")
	const threshold = 3
	g.deps.Limiter = mustNewLoginLimiter(t, threshold, time.Minute)

	pending := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	for range threshold {
		passkeyLoginFactorBegin(t, pending, ts)
	}
	for i := range threshold {
		if r := tryLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword); r.status != http.StatusOK {
			t.Fatalf("password step %d after %d abandoned begins = %d %s, want 200", i+1, threshold, r.status, r.body)
		}
	}
	if until := g.deps.Users.LoginLockedUntil(passkeyBilboID(t, g)); !until.IsZero() {
		t.Errorf("abandoned begins locked the account until %v", until)
	}
}

// The factor step hands back only what it reserved itself. A begin
// whose window has passed, then three wrong passwords from the same
// address: completing the passkey step -- signed in, or refused by the
// unusual-sign-in policy -- leaves those three counted.
func TestPasskeyFactorStepHandsBackOnlyItsOwnAttempt(t *testing.T) {
	for name, tc := range map[string]struct {
		policy UnusualSignInPolicy
		status int
	}{
		"signed in":             {UnusualSignInPolicy{Action: UnusualSignInOff}, http.StatusOK},
		"refused by the policy": {UnusualSignInPolicy{Action: UnusualSignInBlock}, http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			g, ts, _ := passkeyFixture(t)
			clock := &escalationClock{t: time.Now()}
			g.cfg.Now = clock.now
			bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
			fake, _ := registerPasskey(t, bilbo, ts, g, "YubiKey")
			g.cfg.UnusualSignIns = tc.policy
			const threshold = 5
			g.deps.Limiter = mustNewLoginLimiter(t, threshold, time.Minute)

			pending := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
			options := passkeyLoginFactorBegin(t, pending, ts)
			clock.set(clock.now().Add(time.Minute + time.Second)) // begin's window has passed
			for range 3 {
				if r := tryLogin(t, ts, "nobody-at-all", "wrong-password-placeholder"); r.status != http.StatusUnauthorized {
					t.Fatalf("a wrong password = %d, want 401", r.status)
				}
			}
			if status, body := readAll(t, submitPasskeyAssertion(t, pending, ts, fake, options)); status != tc.status {
				t.Fatalf("the passkey step = %d %s, want %d", status, body, tc.status)
			}
			room := 0
			for g.deps.Limiter.Reserve("ip:198.51.100.1", clock.now()) {
				room++
			}
			if room != threshold-3 {
				t.Errorf("the address has %d attempts left, want %d: the factor step handed back a wrong guess", room, threshold-3)
			}
		})
	}
}

// A passkey-only account still passes the second step when the login
// page's passkey sign-in has spent the address's challenge budget: the
// two budgets are apart.
func TestPasskeyFactorBeginIsNotTheLoginPageChallengeBudget(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	fake, _ := registerPasskey(t, bilbo, ts, g, "YubiKey")
	if u, _ := g.deps.Users.Get(passkeyBilboID(t, g)); u.TOTPSecret != "" {
		t.Fatal("test setup: bilbo has a TOTP factor")
	}
	now := time.Now()
	for g.deps.Limiter.Reserve(passkeyBeginKey("198.51.100.1"), now) { // as login/passkey/begin spends it
	}
	pending := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	if status, body := readAll(t, submitPasskeyAssertion(t, pending, ts, fake, passkeyLoginFactorBegin(t, pending, ts))); status != http.StatusOK {
		t.Fatalf("the second step after the login page's challenges = %d %s, want 200", status, body)
	}
}

// A stranger holding the password, from as many addresses as they like,
// begins at most the threshold; the owner's own browser still begins,
// on its own budget, and signs in.
func TestPasskeyFactorBeginKnownBrowserPastAFullBudget(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	known := newBrowserJar(t)
	e.mustSignIn(t, known)

	stranger := startPasskeyLogin(t, e.ts, passkeyBilboUsername, passkeyBilboPassword)
	for range 5 { // newTestGate's limiter threshold
		passkeyLoginFactorBegin(t, stranger, e.ts)
	}
	if status, body := readAll(t, postJSON(t, stranger, e.ts.URL+"/api/auth/login/factor/begin", struct{}{})); status != http.StatusTooManyRequests {
		t.Fatalf("the stranger's sixth begin = %d %s, want 429", status, body)
	}
	if ev := lastEvent(t, e); ev.Outcome != gauntlet.SignInRateLimited || ev.Method != gauntlet.SignInMethodPasskey {
		t.Errorf("event = %+v, want rate_limited/passkey", ev)
	}

	if status := signInFrom(t, known, e.ts, passkeyBilboUsername, passkeyBilboPassword); status != http.StatusOK {
		t.Fatalf("the owner's password step = %d", status)
	}
	if status, body := readAll(t, submitPasskeyAssertion(t, known, e.ts, e.fake, passkeyLoginFactorBegin(t, known, e.ts))); status != http.StatusOK {
		t.Fatalf("the owner's known browser past the stranger's begins = %d %s, want 200", status, body)
	}
}

// A sign-in from a known browser during a lockout behaves as before: the
// password step, begin and the assertion all pass on its allowance.
func TestPasskeyFactorStepKnownBrowserThroughALockout(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	known := newBrowserJar(t)
	e.mustSignIn(t, known)

	failLoginWindow(t, e.g, e.ts, e.clock, passkeyBilboUsername)
	if r := tryLogin(t, e.ts, passkeyBilboUsername, passkeyBilboPassword); r.status != http.StatusTooManyRequests {
		t.Fatalf("the right password from another browser during the lockout = %d, want 429", r.status)
	}
	if status := signInFrom(t, known, e.ts, passkeyBilboUsername, passkeyBilboPassword); status != http.StatusOK {
		t.Fatalf("the known browser's password step during the lockout = %d, want 200", status)
	}
	if status, body := readAll(t, submitPasskeyAssertion(t, known, e.ts, e.fake, passkeyLoginFactorBegin(t, known, e.ts))); status != http.StatusOK {
		t.Fatalf("the known browser's passkey step during the lockout = %d %s, want 200", status, body)
	}
	if u, _ := e.g.deps.Users.Get(e.id); u.LoginLockoutCount != 0 || !u.LoginLockedUntil.IsZero() {
		t.Errorf("after the sign-in the record holds count %d until %v, want both cleared", u.LoginLockoutCount, u.LoginLockedUntil)
	}
}

// A banned address is refused at begin as at every login step, unless
// the browser is one the account remembers.
func TestPasskeyFactorBeginAtABannedAddress(t *testing.T) {
	e := newAloneEnv(t)
	known := newBrowserJar(t)
	e.mustSignIn(t, known)
	stranger := startPasskeyLogin(t, e.ts, passkeyBilboUsername, passkeyBilboPassword)
	if status := signInFrom(t, known, e.ts, passkeyBilboUsername, passkeyBilboPassword); status != http.StatusOK {
		t.Fatalf("the owner's password step = %d", status)
	}

	for range gauntlet.AddressBanFailures {
		e.g.deps.Limiter.RecordAddressFailure("198.51.100.1", e.clock.now())
	}
	if status, body := readAll(t, postJSON(t, stranger, e.ts.URL+"/api/auth/login/factor/begin", struct{}{})); status != http.StatusTooManyRequests {
		t.Errorf("begin from the banned address = %d %s, want 429", status, body)
	}
	passkeyLoginFactorBegin(t, known, e.ts)
}

// An unknown browser holding a pending login made before a lockout is
// refused at begin, with no challenge to touch its passkey for: begin
// reads the lockout without reserving anything, and login/factor still
// decides.
func TestPasskeyFactorBeginRefusesALockedAccountEarly(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	stranger := startPasskeyLogin(t, e.ts, passkeyBilboUsername, passkeyBilboPassword)
	failLoginWindow(t, e.g, e.ts, e.clock, passkeyBilboUsername)

	resp := postJSON(t, stranger, e.ts.URL+"/api/auth/login/factor/begin", struct{}{})
	status, body := readAll(t, resp)
	if status != http.StatusTooManyRequests {
		t.Fatalf("begin during the lockout = %d %s, want 429", status, body)
	}
	for _, c := range resp.Cookies() {
		if c.Name == passkeyAssertCookieName && c.MaxAge >= 0 {
			t.Error("begin during the lockout set a ceremony cookie")
		}
	}
	if ev := lastEvent(t, e); ev.Outcome != gauntlet.SignInLocked || ev.LockedUntil.IsZero() || ev.Method != gauntlet.SignInMethodPasskey {
		t.Errorf("event = %+v, want locked/passkey with its end", ev)
	}
}
