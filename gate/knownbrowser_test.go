package gate

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// The known-browser allowance (#44) through the routes: the cookie each
// session issue sets and rotates, the allowance it gives past a lockout
// or an address limit, and what forgets it.

// knownCookieFrom is the known-browser cookie resp sets, or nil.
func knownCookieFrom(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == knownBrowserCookieName {
			return c
		}
	}
	return nil
}

// knownToken is the newest known-browser token client's jar would send
// to the login routes -- the first of the cookie's tokens -- or "".
func knownToken(t *testing.T, client *http.Client, ts *httptest.Server) string {
	t.Helper()
	u, err := url.Parse(ts.URL + loginPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == knownBrowserCookieName {
			first, _, _ := strings.Cut(c.Value, ".")
			return first
		}
	}
	return ""
}

// signInFrom sends username's password from client, the browser it
// already is, and returns the status.
func signInFrom(t *testing.T, client *http.Client, ts *httptest.Server, username, password string) int {
	t.Helper()
	status, _ := readAll(t, postJSON(t, client, ts.URL+"/api/auth/login", credentialsRequest{Username: username, Password: password}))
	return status
}

// A sign-in sets the cookie with the attributes the design names, its
// value is known to that account only, and the browser's next sign-in
// replaces it: the old value stops working and the account still
// remembers one browser.
func TestSignInSetsAndRotatesTheKnownBrowserCookie(t *testing.T) {
	g, ts, _ := totpFixture(t)
	id := totpBobID(t, g)
	bob := &http.Client{Jar: mustCookieJar(t)}

	resp := postJSON(t, bob, ts.URL+"/api/auth/login", credentialsRequest{Username: totpBobUsername, Password: totpBobPassword})
	_ = resp.Body.Close()
	c := knownCookieFrom(resp)
	if c == nil {
		t.Fatal("a sign-in set no known-browser cookie")
	}
	if c.Path != "/api/auth" || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode ||
		c.MaxAge != int((45*24*time.Hour).Seconds()) || c.Secure {
		t.Errorf("cookie = %+v, want path /api/auth, HttpOnly, SameSite=Lax, Max-Age 45 days, not Secure in a plain-HTTP fixture", c)
	}
	if raw, err := base64.RawURLEncoding.DecodeString(c.Value); err != nil || len(raw) != 32 {
		t.Errorf("value %q is not 32 bytes of base64url", c.Value)
	}
	now := g.now()
	if !g.deps.Users.KnowsBrowser(id, c.Value, now) {
		t.Fatal("bob's account does not know the browser that just signed in")
	}
	admin, _ := g.deps.Users.ByUsername("admin")
	if g.deps.Users.KnowsBrowser(admin.ID, c.Value, now) {
		t.Error("another account knows bob's browser")
	}

	if status := signInFrom(t, bob, ts, totpBobUsername, totpBobPassword); status != http.StatusOK {
		t.Fatalf("bob's second sign-in = %d", status)
	}
	next := knownToken(t, bob, ts)
	if next == "" || next == c.Value {
		t.Fatalf("the second sign-in left the token %q, want a new one", next)
	}
	now = g.now()
	if g.deps.Users.KnowsBrowser(id, c.Value, now) || !g.deps.Users.KnowsBrowser(id, next, now) {
		t.Error("rotation did not replace the old token with the new")
	}
	if u, _ := g.deps.Users.Get(id); len(u.KnownBrowsers) != 1 {
		t.Errorf("the account remembers %d browsers after two sign-ins from one, want 1", len(u.KnownBrowsers))
	}
}

// Every path that issues a session issues the cookie too, through
// issueSession: the second-factor step, a password change and sign out
// everywhere, as well as the one-step sign-in above.
func TestEverySessionIssueSetsTheKnownBrowserCookie(t *testing.T) {
	g, ts, _ := totpFixture(t)
	id := totpBobID(t, g)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	secret, _, counter := totpEnrolAndConfirm(t, bob, ts)

	check := func(name string, resp *http.Response) {
		t.Helper()
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s = %d", name, resp.StatusCode)
		}
		c := knownCookieFrom(resp)
		if c == nil || !g.deps.Users.KnowsBrowser(id, strings.Split(c.Value, ".")[0], g.now()) {
			t.Errorf("%s set no known-browser cookie the account knows", name)
		}
	}

	resp := postJSON(t, bob, ts.URL+"/api/auth/login", credentialsRequest{Username: totpBobUsername, Password: totpBobPassword})
	_ = resp.Body.Close()
	if knownCookieFrom(resp) != nil {
		t.Error("the password step alone, owing a second factor, set the cookie")
	}
	check("the second-factor step", submitLoginFactor(t, bob, ts, gauntlet.GenerateTOTPCode(secret, counter+1)))
	check("a password change", postJSON(t, bob, ts.URL+"/api/auth/password",
		changePasswordRequest{CurrentPassword: totpBobPassword, NewPassword: totpBobPassword + "-2"}))
	check("sign out everywhere", postJSON(t, bob, ts.URL+"/api/auth/logout-all", nil))
}

// A stranger locks bob out; bob's own browser signs in all the same, on
// its allowance, while the right password from any other browser is
// refused. The completed sign-in resets the account's count.
func TestAKnownBrowserSignsInThroughALockout(t *testing.T) {
	g, ts, clock := escalationFixture(t)
	id := totpBobID(t, g)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)

	failLoginWindow(t, g, ts, clock, totpBobUsername)
	if r := tryLogin(t, ts, totpBobUsername, totpBobPassword); r.status != http.StatusTooManyRequests {
		t.Fatalf("the right password from another browser during the lockout = %d, want 429", r.status)
	}
	if status := signInFrom(t, bob, ts, totpBobUsername, totpBobPassword); status != http.StatusOK {
		t.Fatalf("bob's known browser during the lockout = %d, want 200", status)
	}
	if u, _ := g.deps.Users.Get(id); u.LoginLockoutCount != 0 || !u.LoginLockedUntil.IsZero() {
		t.Errorf("after bob's sign-in the record holds count %d, until %v; want both cleared", u.LoginLockoutCount, u.LoginLockedUntil)
	}
}

// The allowance covers a client address at its limit too: guesses at
// other names from bob's address do not keep bob out.
func TestAKnownBrowserPassesTheAddressLimit(t *testing.T) {
	g, ts, _ := totpFixture(t)
	g.cfg.ClientIP = func(*http.Request) string { return "192.0.2.10" }
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	for range 5 {
		_ = tryLogin(t, ts, "nobody-here", "wrong-password-placeholder")
	}
	if r := tryLogin(t, ts, totpBobUsername, totpBobPassword); r.status != http.StatusTooManyRequests {
		t.Fatalf("precondition: the address at its limit, got %d", r.status)
	}
	if status := signInFrom(t, bob, ts, totpBobUsername, totpBobPassword); status != http.StatusOK {
		t.Errorf("bob's known browser at a full address = %d, want 200", status)
	}
}

// The allowance is no way round the disable: refused once the account
// is disabled, and failures through it bring the disable on.
func TestAKnownBrowserCannotPassOrOutlastTheDisable(t *testing.T) {
	g, ts, clock := escalationFixture(t)
	id := totpBobID(t, g)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)

	for range 9 {
		failLoginWindow(t, g, ts, clock, totpBobUsername)
	}
	for i := range 5 {
		if status := signInFrom(t, bob, ts, totpBobUsername, "wrong-password-placeholder"); status != http.StatusUnauthorized {
			t.Fatalf("known-browser guess %d during the lockout = %d, want 401", i+1, status)
		}
	}
	if u, _ := g.deps.Users.Get(id); u.LoginDisabledAt.IsZero() {
		t.Fatal("the fiftieth failure, from the known browser, did not disable the account")
	}
	clock.set(clock.now().Add(2 * time.Hour)) // past the last lockout, inside the 24-hour disable
	if status := signInFrom(t, bob, ts, totpBobUsername, totpBobPassword); status != http.StatusTooManyRequests {
		t.Errorf("the known browser's right password on a disabled account = %d, want 429", status)
	}
}

// Sign out everywhere forgets every other browser and remembers the
// one it was called from; a reset code forgets them all.
func TestSignOutEverywhereAndAResetCodeForgetKnownBrowsers(t *testing.T) {
	g, ts, admin := totpFixture(t)
	id := totpBobID(t, g)
	browserA := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	secret, _, counter := totpEnrolAndConfirm(t, browserA, ts) // past the enrolment door
	browserB := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	if status, body := readAll(t, submitLoginFactor(t, browserB, ts, gauntlet.GenerateTOTPCode(secret, counter+1))); status != http.StatusOK {
		t.Fatalf("browser B's sign-in = %d %s", status, body)
	}
	tokenB := knownToken(t, browserB, ts)
	if !g.deps.Users.KnowsBrowser(id, tokenB, g.now()) {
		t.Fatal("precondition: browser B is not known")
	}

	if status, body := readAll(t, postJSON(t, browserA, ts.URL+"/api/auth/logout-all", nil)); status != http.StatusOK {
		t.Fatalf("sign out everywhere = %d %s", status, body)
	}
	now := g.now()
	if g.deps.Users.KnowsBrowser(id, tokenB, now) {
		t.Error("sign out everywhere left the other browser known")
	}
	tokenA := knownToken(t, browserA, ts)
	if !g.deps.Users.KnowsBrowser(id, tokenA, now) {
		t.Error("sign out everywhere did not remember the browser it was called from")
	}
	if u, _ := g.deps.Users.Get(id); len(u.KnownBrowsers) != 1 {
		t.Errorf("after sign out everywhere the account remembers %d, want 1", len(u.KnownBrowsers))
	}

	resp := postJSON(t, admin, ts.URL+"/api/auth/users/"+id+"/reset-password", adminStepUpRequest{Password: testAdminPassword})
	if status, body := readAll(t, resp); status != http.StatusOK {
		t.Fatalf("reset = %d %s", status, body)
	}
	if g.deps.Users.KnowsBrowser(id, tokenA, g.now()) {
		t.Error("a reset code left a browser known")
	}
}

// The forced password change after a run of second-factor failures
// ends bob's sessions but not his browser's allowance: that is when the
// owner needs it most.
func TestTheForcedChangeKeepsTheKnownBrowser(t *testing.T) {
	g, ts, clock := escalationFixture(t)
	id := totpBobID(t, g)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	secret, _, _ := totpEnrolAndConfirm(t, bob, ts)
	clock.set(clock.now().Add(time.Minute))

	guesser := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	for range 5 {
		_ = submitLoginFactor(t, guesser, ts, wrongTOTPCode(secret, clock.now())).Body.Close()
	}
	u, _ := g.deps.Users.Get(id)
	if !u.MustChangePassword || !clock.now().Before(u.LoginLockedUntil) {
		t.Fatalf("precondition: a forced change and a lockout, got must-change %v, locked until %v", u.MustChangePassword, u.LoginLockedUntil)
	}
	if !g.deps.Users.KnowsBrowser(id, knownToken(t, bob, ts), clock.now()) {
		t.Fatal("the forced change forgot bob's browser")
	}
	if status := signInFrom(t, bob, ts, totpBobUsername, totpBobPassword); status != http.StatusOK {
		t.Fatalf("bob's password step from his browser during the lockout = %d, want 200", status)
	}
	resp := submitLoginFactor(t, bob, ts, gauntlet.GenerateTOTPCode(secret, totpCounterNow(clock.now())+1))
	if status, body := readAll(t, resp); status != http.StatusOK {
		t.Errorf("bob's second factor from his browser during the lockout = %d %s, want 200", status, body)
	}
}

// A forged value, or one another account remembers, gets nothing.
func TestAForgedOrForeignKnownBrowserCookieGetsNothing(t *testing.T) {
	g, ts, clock := escalationFixture(t)
	failLoginWindow(t, g, ts, clock, totpBobUsername)

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	admin, _ := g.deps.Users.ByUsername("admin")
	adminToken, err := g.deps.Users.RememberBrowser(admin.ID, "", clock.now())
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"a forged value":           base64.RawURLEncoding.EncodeToString(raw),
		"the admin's own browser":  adminToken,
		"a value that is not ours": "not-a-token",
	} {
		if value == "" {
			t.Fatalf("%s: no token", name)
		}
		client := &http.Client{Jar: mustCookieJar(t)}
		u, _ := url.Parse(ts.URL + loginPath)
		client.Jar.SetCookies(u, []*http.Cookie{{Name: knownBrowserCookieName, Value: value, Path: loginPath}})
		if status := signInFrom(t, client, ts, totpBobUsername, totpBobPassword); status != http.StatusTooManyRequests {
			t.Errorf("%s during bob's lockout = %d, want 429", name, status)
		}
	}
}

// A session issued outside the login routes -- here a password change
// -- replaces the browser's token rather than adding one, because the
// cookie's path covers every /api/auth route that issues a session: so
// one browser cannot eat the account's cap of three and evict the
// owner's others. B signs in first, then A again, then C; A's password
// change must leave B remembered, and three entries in all.
func TestASessionIssuedOutsideLoginRotatesTheKnownBrowser(t *testing.T) {
	g, ts, _ := totpFixture(t)
	id := totpBobID(t, g)
	browserA := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	_, recovery, _ := totpEnrolAndConfirm(t, browserA, ts)

	signInWithRecovery := func(client *http.Client, code string) {
		t.Helper()
		if status := signInFrom(t, client, ts, totpBobUsername, totpBobPassword); status != http.StatusOK {
			t.Fatalf("password step = %d", status)
		}
		if status, body := readAll(t, submitLoginFactor(t, client, ts, code)); status != http.StatusOK {
			t.Fatalf("recovery-code step = %d %s", status, body)
		}
	}
	browserB := &http.Client{Jar: mustCookieJar(t)}
	signInWithRecovery(browserB, recovery[0])
	signInWithRecovery(browserA, recovery[1])
	browserC := &http.Client{Jar: mustCookieJar(t)}
	signInWithRecovery(browserC, recovery[2])
	tokenA := knownToken(t, browserA, ts)

	resp := postJSON(t, browserA, ts.URL+"/api/auth/password",
		changePasswordRequest{CurrentPassword: totpBobPassword, NewPassword: totpBobPassword + "-2"})
	if status, body := readAll(t, resp); status != http.StatusOK {
		t.Fatalf("password change = %d %s", status, body)
	}
	now := g.now()
	if !g.deps.Users.KnowsBrowser(id, knownToken(t, browserB, ts), now) {
		t.Error("browser A's password change evicted browser B")
	}
	if g.deps.Users.KnowsBrowser(id, tokenA, now) || !g.deps.Users.KnowsBrowser(id, knownToken(t, browserA, ts), now) {
		t.Error("the password change did not replace browser A's token")
	}
	if u, _ := g.deps.Users.Get(id); len(u.KnownBrowsers) != 3 {
		t.Errorf("the account remembers %d browsers for three, want 3", len(u.KnownBrowsers))
	}
}
