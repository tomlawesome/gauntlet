package gate

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// A password reset clears the account's own count and lockout (#24) and
// nothing on its address's limit: #32's pass past a full address is
// retired (#86). A browser the account remembers still gets past that
// limit on its own allowance (#44).

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

// An account reset out of a lockout, signing in from the address the
// lockout's guesses filled on a browser it does not remember, is
// refused like anyone else there until the address's window has passed,
// then gets in.
func TestAResetAccountWaitsOutAFullAddress(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reset func(t *testing.T, g *Gate, now time.Time) string
	}{
		{"CLI SetPassword", func(t *testing.T, g *Gate, now time.Time) string {
			const newPW = "reset-by-cli-placeholder"
			if err := g.deps.Users.SetPassword(totpBobUsername, newPW, now); err != nil {
				t.Fatal(err)
			}
			return newPW
		}},
		{"reset code", func(t *testing.T, g *Gate, now time.Time) string {
			_, code, err := g.deps.Users.IssueResetCode(totpBobID(t, g), now)
			if err != nil {
				t.Fatal(err)
			}
			return code
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, ts, _ := totpFixture(t)
			start := time.Now()
			clock := &escalationClock{t: start}
			g.cfg.Now = clock.now
			lockOutFromFixtureAddress(t, ts.URL, totpBobUsername)

			clock.set(start.Add(time.Second))
			password := tc.reset(t, g, clock.now())
			if got := loginStatus(t, ts.URL, totpBobUsername, password); got != http.StatusTooManyRequests {
				t.Errorf("the reset account at the full address got %d, want 429", got)
			}
			clock.set(start.Add(5*time.Minute + time.Second))
			if got := loginStatus(t, ts.URL, totpBobUsername, password); got != http.StatusOK {
				t.Errorf("the reset account once the address's window had passed got %d, want 200", got)
			}
		})
	}
}

// A CLI reset keeps the browsers the account remembers, so the owner's
// own browser signs in at the full address at once, while the same new
// password from any other browser is refused.
func TestAResetAccountsKnownBrowserPassesAFullAddress(t *testing.T) {
	g, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	lockOutFromFixtureAddress(t, ts.URL, totpBobUsername)

	const newPW = "reset-by-cli-placeholder"
	if err := g.deps.Users.SetPassword(totpBobUsername, newPW, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := loginStatus(t, ts.URL, totpBobUsername, newPW); got != http.StatusTooManyRequests {
		t.Errorf("the new password from an unknown browser at the full address got %d, want 429", got)
	}
	if got := signInFrom(t, bob, ts, totpBobUsername, newPW); got != http.StatusOK {
		t.Errorf("bob's known browser at the full address after the reset got %d, want 200", got)
	}
}

// A pending-login cookie sealed before #86 may carry the pass's
// "AfterReset" flag. It still opens, and the flag is ignored: the code
// step is refused at a full address like any other.
func TestAnOldPendingCookieAfterResetFlagIsIgnored(t *testing.T) {
	g, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	secret, _, counter := totpEnrolAndConfirm(t, bob, ts)

	now := time.Now()
	old, err := pendingLoginCodec.seal(struct {
		UserID     string
		IssuedAt   time.Time
		AfterReset bool
		ID         string
	}{totpBobID(t, g), now, true, newTestPendingID(t)})
	if err != nil {
		t.Fatal(err)
	}
	if st, err := pendingLoginCodec.decode(old, now); err != nil || st.UserID != totpBobID(t, g) {
		t.Fatalf("a cookie carrying the old flag decoded to %+v, %v; want bob's pending login", st, err)
	}

	// Guesses at a name that is no account fill the address without
	// locking bob out.
	lockOutFromFixtureAddress(t, ts.URL, "nobody-placeholder")
	resp, body := postRaw(t, ts.URL+"/api/auth/login/factor",
		loginFactorRequest{Code: gauntlet.GenerateTOTPCode(secret, counter+1)},
		&http.Cookie{Name: pendingLoginCookieName, Value: old})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("the code step on an old cookie carrying the flag at a full address got %d (%s), want 429", resp.StatusCode, body)
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
	registerAdmin(t, ts, "admin", "password-placeholder-1")
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
		if got := loginAttempt(ip, "admin", "password-placeholder-1"); got != http.StatusTooManyRequests {
			t.Fatalf("an attempt at the locked-out admin got %d, want 429", got)
		}
	}
	if got := loginAttempt(ip, "bob", "password456"); got != http.StatusOK {
		t.Errorf("bob's sign-in from an address whose only attempts the admin's limit refused got %d, want 200", got)
	}
}
