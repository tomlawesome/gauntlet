package gate

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// lockOutFromFixtureAddress spends the fixture's whole per-address
// budget (5 per window, newTestGate's one client address) on wrong
// passwords for username, which locks that account out too.
func lockOutFromFixtureAddress(t *testing.T, base, username string) {
	t.Helper()
	for i := range 5 {
		resp := postJSON(t, &http.Client{}, base+"/api/auth/login",
			credentialsRequest{Username: username, Password: "wrong-password-placeholder"})
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong password %d for %q got %d, want 401", i+1, username, resp.StatusCode)
		}
	}
	resp := postJSON(t, &http.Client{}, base+"/api/auth/login",
		credentialsRequest{Username: username, Password: "wrong-password-placeholder"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("sixth attempt for %q got %d, want 429", username, resp.StatusCode)
	}
}

func loginStatus(t *testing.T, base, username, password string) int {
	t.Helper()
	resp := postJSON(t, &http.Client{}, base+"/api/auth/login", credentialsRequest{Username: username, Password: password})
	_ = resp.Body.Close()
	return resp.StatusCode
}

// #32: a locked-out account rescued by a password reset signs in from
// the address its lockout came from at once, rather than being refused
// by the per-address counter for the rest of the window.
func TestResetLetsAccountPastAddressLimit(t *testing.T) {
	t.Run("CLI SetPassword", func(t *testing.T) {
		g, ts, _ := totpFixture(t)
		lockOutFromFixtureAddress(t, ts.URL, totpBobUsername)

		const newPW = "reset-by-cli-placeholder"
		if err := g.deps.Users.SetPassword(totpBobUsername, newPW, time.Now()); err != nil {
			t.Fatal(err)
		}
		if got := loginStatus(t, ts.URL, totpBobUsername, newPW); got != http.StatusOK {
			t.Errorf("the new password after a CLI reset got %d, want 200", got)
		}
	})

	t.Run("reset code", func(t *testing.T) {
		g, ts, _ := totpFixture(t)
		lockOutFromFixtureAddress(t, ts.URL, totpBobUsername)

		_, code, err := g.deps.Users.IssueResetCode(totpBobID(t, g), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if got := loginStatus(t, ts.URL, totpBobUsername, code); got != http.StatusOK {
			t.Errorf("the reset code got %d, want 200", got)
		}
	})
}

// The pass is the reset account's alone: every other name tried from
// the full address -- another real account, or one that matches none --
// is still refused, and the reset account's pass is used up by its
// first sign-in, so a second one from that address is refused too.
func TestResetPassLeavesOtherAccountsLimited(t *testing.T) {
	g, ts, _ := totpFixture(t)
	lockOutFromFixtureAddress(t, ts.URL, totpBobUsername)

	const newPW = "reset-by-cli-placeholder"
	if err := g.deps.Users.SetPassword(totpBobUsername, newPW, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := loginStatus(t, ts.URL, "admin", "password123"); got != http.StatusTooManyRequests {
		t.Errorf("another account's correct password from the full address got %d, want 429", got)
	}
	if got := loginStatus(t, ts.URL, "nobody", "password123"); got != http.StatusTooManyRequests {
		t.Errorf("an unknown name from the full address got %d, want 429", got)
	}
	if got := loginStatus(t, ts.URL, totpBobUsername, newPW); got != http.StatusOK {
		t.Fatalf("the reset account's new password got %d, want 200", got)
	}
	if got := loginStatus(t, ts.URL, "admin", "password123"); got != http.StatusTooManyRequests {
		t.Errorf("another account after the reset account signed in got %d, want 429: the pass freed an address slot", got)
	}
	if got := loginStatus(t, ts.URL, totpBobUsername, newPW); got != http.StatusTooManyRequests {
		t.Errorf("a second sign-in on the same pass got %d, want 429", got)
	}
}

// A wrong guess under the pass uses it up: whoever is at the address
// gets one try at the new password, not one per window.
func TestResetPassEndsOnAWrongGuess(t *testing.T) {
	g, ts, _ := totpFixture(t)
	lockOutFromFixtureAddress(t, ts.URL, totpBobUsername)

	const newPW = "reset-by-cli-placeholder"
	if err := g.deps.Users.SetPassword(totpBobUsername, newPW, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := loginStatus(t, ts.URL, totpBobUsername, "wrong-password-placeholder"); got != http.StatusUnauthorized {
		t.Fatalf("a wrong password under the pass got %d, want 401", got)
	}
	if got := loginStatus(t, ts.URL, totpBobUsername, newPW); got != http.StatusTooManyRequests {
		t.Errorf("the new password after the pass was used up got %d, want 429", got)
	}
}

// An account with a second factor needs two requests to sign in; the
// pass covers both, and is used up once the session is issued.
func TestResetPassCoversTheSecondFactorStep(t *testing.T) {
	g, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	secret, _, counter := totpEnrolAndConfirm(t, bob, ts)
	lockOutFromFixtureAddress(t, ts.URL, totpBobUsername)

	const newPW = "reset-by-cli-placeholder"
	if err := g.deps.Users.SetPassword(totpBobUsername, newPW, time.Now()); err != nil {
		t.Fatal(err)
	}
	client := startTOTPLogin(t, ts, totpBobUsername, newPW)
	resp := submitLoginFactor(t, client, ts, gauntlet.GenerateTOTPCode(secret, counter+1))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the code step after a reset got %d, want 200", resp.StatusCode)
	}
	if !sessionAuthenticated(t, client, ts) {
		t.Error("the code step after a reset issued no session")
	}
	if got := loginStatus(t, ts.URL, totpBobUsername, newPW); got != http.StatusTooManyRequests {
		t.Errorf("a second sign-in after the pass's session got %d, want 429", got)
	}
}

// A wrong guess at the account from the same address, sent while the
// owner is reading their code, cannot take the pass away: the password
// step spends it, and the pending login it issues carries the owner
// through the code step.
func TestResetPassCannotBeTakenBetweenLoginSteps(t *testing.T) {
	g, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	secret, _, counter := totpEnrolAndConfirm(t, bob, ts)
	lockOutFromFixtureAddress(t, ts.URL, totpBobUsername)

	const newPW = "reset-by-cli-placeholder"
	if err := g.deps.Users.SetPassword(totpBobUsername, newPW, time.Now()); err != nil {
		t.Fatal(err)
	}
	client := startTOTPLogin(t, ts, totpBobUsername, newPW)
	if got := loginStatus(t, ts.URL, totpBobUsername, "wrong-password-placeholder"); got != http.StatusTooManyRequests {
		t.Errorf("a guess between the owner's two steps got %d, want 429", got)
	}
	resp := submitLoginFactor(t, client, ts, gauntlet.GenerateTOTPCode(secret, counter+1))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the owner's code step after an interleaved guess got %d, want 200", resp.StatusCode)
	}
}

// Only a reset that ends the account's own lockout earns the pass. An
// account that was never locked out, changing its own password while
// guesses at other names fill the shared address, stays behind the
// address limit like everyone else there.
func TestOwnPasswordChangeGetsNoAddressPass(t *testing.T) {
	_, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	// A voluntary password change is not an enrolment route, so an
	// account stuck at the forced-enrolment door cannot reach it either
	// (#49, docs/design.md §1.6) -- bob needs a factor first to stand in
	// for an ordinary, already-enrolled account here.
	totpEnrolAndConfirm(t, bob, ts)
	lockOutFromFixtureAddress(t, ts.URL, "nobody-placeholder")

	const newPW = "changed-by-bob-placeholder"
	resp := postJSON(t, bob, ts.URL+"/api/auth/password",
		changePasswordRequest{CurrentPassword: totpBobPassword, NewPassword: newPW})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("changing bob's own password got %d, want 200", resp.StatusCode)
	}
	if got := loginStatus(t, ts.URL, totpBobUsername, newPW); got != http.StatusTooManyRequests {
		t.Errorf("bob's login after changing his own password at a full address got %d, want 429", got)
	}
}

// TestLoginRefusedByTheAccountLimitHandsBackTheAddressReservation: an
// attempt the account's own limit refuses has already reserved one
// attempt on its address, and must hand it back -- otherwise anyone
// retrying a locked-out account fills their own address's budget and is
// then refused for every other account as well. Here one address makes
// twice the threshold's worth of refused attempts at the locked-out
// admin, then signs bob in.
func TestLoginRefusedByTheAccountLimitHandsBackTheAddressReservation(t *testing.T) {
	g := newTestGate(t)
	const threshold = 5
	g.deps.Limiter = mustNewLoginLimiter(t, threshold, time.Minute)
	g.cfg.ClientIP = func(r *http.Request) string { return r.Header.Get("X-Test-IP") }
	ts := newTestServer(t, g)
	registerAdmin(t, ts, "admin", "password123")
	if _, err := g.deps.Users.CreateUser("bob", "password456", gauntlet.RoleUser, time.Now()); err != nil {
		t.Fatal(err)
	}

	loginAttempt := func(ip, username, password string) int {
		t.Helper()
		body := `{"username":"` + username + `","password":"` + password + `"}`
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/login", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(csrfHeaderName, testCSRFValue)
		req.Header.Set("X-Test-IP", ip)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	// Lock the admin out from addresses that are then done with.
	for i := range threshold {
		loginAttempt("198.51.100."+strconv.Itoa(i+1), "admin", "wrong")
	}
	const ip = "198.51.100.99"
	for range 2 * threshold {
		if got := loginAttempt(ip, "admin", "password123"); got != http.StatusTooManyRequests {
			t.Fatalf("an attempt at the locked-out admin got %d, want 429", got)
		}
	}
	if got := loginAttempt(ip, "bob", "password456"); got != http.StatusOK {
		t.Errorf("bob's sign-in from an address whose only attempts the admin's limit refused got %d, want 200", got)
	}
}
