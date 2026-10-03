package gate

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// The escalating lockout and the disable (#44) through the login
// handlers: what a disabled account is told, which sign-ins reset the
// count, and the run of second-factor failures that forces a new
// password.

// escalationClock is a gate clock a test moves by hand, past lockouts
// hours or days long.
type escalationClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *escalationClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *escalationClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// escalationFixture is totpFixture (an admin and bob, password only so
// far) on a hand-moved clock, with every request from a fresh address,
// so only the account's own limit ever refuses one.
func escalationFixture(t *testing.T) (*Gate, *httptest.Server, *escalationClock) {
	t.Helper()
	g, ts, _ := totpFixture(t)
	clock := &escalationClock{t: time.Now()}
	g.cfg.Now = clock.now
	var n atomic.Int64
	g.cfg.ClientIP = func(*http.Request) string { return fmt.Sprintf("192.0.2.%d", n.Add(1)) }
	return g, ts, clock
}

// loginResult is everything a caller of the password step sees.
type loginResult struct {
	status      int
	body        string
	contentType string
}

func tryLogin(t *testing.T, ts *httptest.Server, username, password string) loginResult {
	t.Helper()
	resp := postJSON(t, &http.Client{Jar: mustCookieJar(t)}, ts.URL+"/api/auth/login",
		credentialsRequest{Username: username, Password: password})
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return loginResult{status: resp.StatusCode, body: string(body), contentType: resp.Header.Get("Content-Type")}
}

// failLoginWindow sends the five wrong passwords that start a lockout,
// waiting out any lockout in force first, and returns how long the one
// they start lasts.
func failLoginWindow(t *testing.T, g *Gate, ts *httptest.Server, clock *escalationClock, username string) time.Duration {
	t.Helper()
	u, ok := g.deps.Users.ByUsername(username)
	if !ok {
		t.Fatalf("no account %s", username)
	}
	if until := g.deps.Users.LoginLockedUntil(u.ID); until.After(clock.now()) {
		clock.set(until.Add(time.Second))
	}
	start := clock.now()
	for i := range 5 {
		if r := tryLogin(t, ts, username, "wrong-password-placeholder"); r.status != http.StatusUnauthorized {
			t.Fatalf("wrong password %d of the window: status %d, want 401", i+1, r.status)
		}
	}
	return g.deps.Users.LoginLockedUntil(u.ID).Sub(start)
}

// wrongTOTPCode is a code that none of the steps the verifier accepts
// around now would produce for secret.
func wrongTOTPCode(secret []byte, now time.Time) string {
	c := totpCounterNow(now)
	valid := map[string]bool{}
	for _, step := range []uint64{c - 1, c, c + 1} {
		valid[gauntlet.GenerateTOTPCode(secret, step)] = true
	}
	for _, code := range []string{"000000", "111111", "222222", "333333"} {
		if !valid[code] {
			return code
		}
	}
	panic("unreachable: four distinct codes, at most three valid")
}

// After fifty failures in a row the right password is refused, a year
// later, with exactly what a locked account is told: the caller learns
// nothing new from a disabled account.
func TestADisabledAccountIsRefusedExactlyLikeALockedOne(t *testing.T) {
	g, ts, clock := escalationFixture(t)

	failLoginWindow(t, g, ts, clock, totpBobUsername)
	locked := tryLogin(t, ts, totpBobUsername, totpBobPassword)
	if locked.status != http.StatusTooManyRequests {
		t.Fatalf("the right password during a lockout: status %d, want 429", locked.status)
	}

	for failed := 5; failed < gauntlet.MaxConsecutiveLoginFailures; failed += 5 {
		failLoginWindow(t, g, ts, clock, totpBobUsername)
	}
	clock.set(clock.now().Add(365 * 24 * time.Hour))
	if disabled := tryLogin(t, ts, totpBobUsername, totpBobPassword); disabled != locked {
		t.Errorf("the right password a year after 50 failures got %+v, want exactly the locked response %+v", disabled, locked)
	}
}

// Only a completed sign-in resets the count. The right password on an
// account that still owes a second factor does not: the next lockout is
// the third. Completing the sign-in, through either path, does: the
// next is a first one again.
func TestOnlyACompletedSignInResetsTheLockoutCount(t *testing.T) {
	g, ts, clock := escalationFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	secret, _, _ := totpEnrolAndConfirm(t, bob, ts)

	failLoginWindow(t, g, ts, clock, totpBobUsername)
	failLoginWindow(t, g, ts, clock, totpBobUsername)
	id := totpBobID(t, g)
	clock.set(g.deps.Users.LoginLockedUntil(id).Add(time.Second))
	startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	if got := failLoginWindow(t, g, ts, clock, totpBobUsername); got != 45*time.Minute {
		t.Errorf("after the right password alone the next lockout lasts %v, want the third's 45m", got)
	}

	clock.set(g.deps.Users.LoginLockedUntil(id).Add(time.Second))
	owner := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	resp := submitLoginFactor(t, owner, ts, gauntlet.GenerateTOTPCode(secret, totpCounterNow(clock.now())))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the owner's second factor got %d, want 200", resp.StatusCode)
	}
	if got := failLoginWindow(t, g, ts, clock, totpBobUsername); got != 5*time.Minute {
		t.Errorf("after a sign-in completed with a second factor the next lockout lasts %v, want a first one's 5m", got)
	}

	// The one-step path: an account with no second factor, whose
	// password alone issues a session (held at the enrolment door, #49).
	// The fixture's admin enrols one, so clear it here.
	admin, _ := g.deps.Users.ByUsername("admin")
	if err := g.deps.Users.ClearTOTP(admin.ID); err != nil {
		t.Fatal(err)
	}
	failLoginWindow(t, g, ts, clock, "admin")
	failLoginWindow(t, g, ts, clock, "admin")
	clock.set(g.deps.Users.LoginLockedUntil(admin.ID).Add(time.Second))
	if r := tryLogin(t, ts, "admin", "password-placeholder-1"); r.status != http.StatusOK {
		t.Fatalf("the admin's sign-in got %d, want 200", r.status)
	}
	if got := failLoginWindow(t, g, ts, clock, "admin"); got != 5*time.Minute {
		t.Errorf("after a one-step sign-in the next lockout lasts %v, want a first one's 5m", got)
	}
}

// Five failed second-factor steps in a row say someone else has the
// password: the account must change it. The owner, signing in once the
// lockout those failures started has ended, gets a session held at the
// change-password door.
func TestFiveSecondFactorFailuresMakeTheOwnerChangeThePassword(t *testing.T) {
	g, ts, clock := escalationFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	secret, _, _ := totpEnrolAndConfirm(t, bob, ts)
	id := totpBobID(t, g)

	guesser := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	for i := 1; i <= 5; i++ {
		resp := submitLoginFactor(t, guesser, ts, wrongTOTPCode(secret, clock.now()))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong code %d: status %d, want 401", i, resp.StatusCode)
		}
		u, _ := g.deps.Users.Get(id)
		if u.MustChangePassword != (i == 5) {
			t.Fatalf("after %d second-factor failures MustChangePassword = %v", i, u.MustChangePassword)
		}
	}

	clock.set(g.deps.Users.LoginLockedUntil(id).Add(time.Minute))
	owner := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	resp := submitLoginFactor(t, owner, ts, gauntlet.GenerateTOTPCode(secret, totpCounterNow(clock.now())))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the owner's sign-in got %d, want 200", resp.StatusCode)
	}
	sessResp, err := owner.Get(ts.URL + "/api/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sessResp.Body.Close() }()
	var sess sessionResponse
	if err := json.NewDecoder(sessResp.Body).Decode(&sess); err != nil {
		t.Fatal(err)
	}
	if !sess.Authenticated || !sess.MustChangePassword {
		t.Errorf("the owner's session after five second-factor failures: %+v, want signed in and made to change the password", sess)
	}
}

// Four failures, a completed sign-in, then four more are two runs, not
// one: no password change is required.
func TestASignInEndsTheRunOfSecondFactorFailures(t *testing.T) {
	g, ts, clock := escalationFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	secret, _, _ := totpEnrolAndConfirm(t, bob, ts)
	id := totpBobID(t, g)

	fail4 := func() {
		pending := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
		for range 4 {
			_ = submitLoginFactor(t, pending, ts, wrongTOTPCode(secret, clock.now())).Body.Close()
		}
	}
	fail4()
	clock.set(clock.now().Add(time.Minute)) // a fresh TOTP step, past the one confirmed
	owner := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	resp := submitLoginFactor(t, owner, ts, gauntlet.GenerateTOTPCode(secret, totpCounterNow(clock.now())))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the owner's sign-in got %d, want 200", resp.StatusCode)
	}
	fail4()
	if u, _ := g.deps.Users.Get(id); u.MustChangePassword {
		t.Error("failures either side of a completed sign-in were counted as one run")
	}
}

// A refused passkey assertion is a failed second-factor step like a
// wrong code: five in a row make the owner change the password.
func TestFiveRefusedPasskeyAssertionsMakeTheOwnerChangeThePassword(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	registerPasskey(t, bilbo, ts, g, "key")

	pending := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	for i := 1; i <= 5; i++ {
		resp, body := postWithCookie(t, pending, ts.URL+"/api/auth/login/factor",
			loginFactorRequest{Assertion: json.RawMessage(`{"id":"x"}`)},
			&http.Cookie{Name: passkeyAssertCookieName, Value: "garbage"})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("refused assertion %d: status %d %q, want 401", i, resp.StatusCode, body)
		}
		u, _ := g.deps.Users.ByUsername(passkeyBilboUsername)
		if u.MustChangePassword != (i == 5) {
			t.Fatalf("after %d refused assertions MustChangePassword = %v", i, u.MustChangePassword)
		}
	}
}
