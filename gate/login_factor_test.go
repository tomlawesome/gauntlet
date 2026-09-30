// Ported from mikroview's internal/api/totp_test.go: the login/factor
// cases (docs/design.md §1.5, §1.6) -- the pending-login cookie, the
// second-factor login step itself, and the security property the G6
// stage 2 brief called its own single most important test.
package gate

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// startTOTPLogin posts the password step for an account that holds an
// active factor and asserts the shape this requires -- no session,
// {"secondFactor":["totp"]} -- returning the client for the caller to
// carry on with against /api/auth/login/factor.
func startTOTPLogin(t *testing.T, ts *httptest.Server, username, password string) *http.Client {
	t.Helper()
	client := &http.Client{Jar: mustCookieJar(t)}
	resp := postJSON(t, client, ts.URL+"/api/auth/login", credentialsRequest{Username: username, Password: password})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("password step returned %d: %s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	factors, _ := out["secondFactor"].([]any)
	if len(factors) != 1 || factors[0] != "totp" {
		t.Fatalf(`password step response = %v, want exactly {"secondFactor":["totp"]}`, out)
	}
	return client
}

func submitLoginFactor(t *testing.T, client *http.Client, ts *httptest.Server, code string) *http.Response {
	t.Helper()
	return postJSON(t, client, ts.URL+"/api/auth/login/factor", loginFactorRequest{Code: code})
}

func sessionAuthenticated(t *testing.T, client *http.Client, ts *httptest.Server) bool {
	t.Helper()
	resp, err := client.Get(ts.URL + "/api/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body sessionResponse
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return body.Authenticated
}

// TestPasswordOnlyLoginOnFactorAccountNeverCreatesSession is the G6
// stage 2 brief's own "single most important test": a correct password
// on an account holding an active factor must not, under any
// circumstances, establish a session.
func TestPasswordOnlyLoginOnFactorAccountNeverCreatesSession(t *testing.T) {
	_, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	totpEnrolAndConfirm(t, bob, ts)

	client := &http.Client{Jar: mustCookieJar(t)}
	resp := postJSON(t, client, ts.URL+"/api/auth/login",
		credentialsRequest{Username: totpBobUsername, Password: totpBobPassword})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("the password step itself returned %d, want 200: %s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if _, hasUsername := out["username"]; hasUsername {
		t.Errorf("the password step's response carried a username -- that shape means a session was created: %v", out)
	}

	if sessionAuthenticated(t, client, ts) {
		t.Fatal("a correct password on an account with an active factor established a session -- see this test's own name")
	}

	protected, err := client.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = protected.Body.Close() }()
	if protected.StatusCode != http.StatusUnauthorized {
		t.Errorf("got %d from a protected route after a password-only login on a factor account, want 401", protected.StatusCode)
	}
}

func TestTOTPReplayOfSameCodeRefused(t *testing.T) {
	_, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	secret, _, confirmCounter := totpEnrolAndConfirm(t, bob, ts)

	code := gauntlet.GenerateTOTPCode(secret, confirmCounter+1)

	first := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	resp := submitLoginFactor(t, first, ts, code)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the first use of the code returned %d, want 200", resp.StatusCode)
	}

	second := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	replay := submitLoginFactor(t, second, ts, code)
	defer func() { _ = replay.Body.Close() }()
	if replay.StatusCode != http.StatusUnauthorized {
		t.Errorf("replaying the same code returned %d, want 401", replay.StatusCode)
	}
	if sessionAuthenticated(t, second, ts) {
		t.Error("a replayed code must not establish a session")
	}
}

func TestTOTPRecoveryCodeSingleUse(t *testing.T) {
	_, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	_, codes, _ := totpEnrolAndConfirm(t, bob, ts)
	code := codes[0]

	first := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	resp := submitLoginFactor(t, first, ts, code)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the first use of the recovery code returned %d, want 200", resp.StatusCode)
	}

	second := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	reuse := submitLoginFactor(t, second, ts, code)
	defer func() { _ = reuse.Body.Close() }()
	if reuse.StatusCode != http.StatusUnauthorized {
		t.Errorf("reusing a spent recovery code returned %d, want 401", reuse.StatusCode)
	}
	if sessionAuthenticated(t, second, ts) {
		t.Error("a spent recovery code must not establish a session")
	}
}

// TestLoginFactorWrongCodeRefused covers an ordinary wrong guess -- not a
// replay, not a burned recovery code, just wrong -- still refused with
// 401 and the reservations left claimed.
func TestLoginFactorWrongCodeRefused(t *testing.T) {
	_, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	totpEnrolAndConfirm(t, bob, ts)

	pending := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	resp := submitLoginFactor(t, pending, ts, "000000")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a wrong code got %d, want 401", resp.StatusCode)
	}
}

// TestLoginFactorWithoutPendingCookie covers hitting the second step
// cold, with no cookie at all.
func TestLoginFactorWithoutPendingCookie(t *testing.T) {
	_, ts, _ := totpFixture(t)
	client := &http.Client{Jar: mustCookieJar(t)}
	resp := postJSON(t, client, ts.URL+"/api/auth/login/factor", loginFactorRequest{Code: "000000"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no pending cookie at all got %d, want 401", resp.StatusCode)
	}
}

// TestPendingLoginCookieExpiry proves the 5-minute bound is enforced by
// the route, not just documented -- a cookie forged with an IssuedAt
// outside the window is refused even with an otherwise-untouched, live
// factor behind it; a cookie forged with a fresh IssuedAt and the right
// code still works, proving the first refusal is really about age and
// not a broken codec.
func TestPendingLoginCookieExpiry(t *testing.T) {
	g, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	secret, _, confirmCounter := totpEnrolAndConfirm(t, bob, ts)
	id := totpBobID(t, g)

	// The stale request carries a genuinely correct code -- generated at
	// confirmCounter+1, same as the fresh check below, just never spent
	// -- so a 401 here can only be about the cookie's age.
	staleCode := gauntlet.GenerateTOTPCode(secret, confirmCounter+1)
	stale, err := pendingLoginCodec.encode(pendingLoginState{UserID: id, IssuedAt: time.Now().Add(-6 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	staleReq, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/login/factor",
		strings.NewReader(`{"code":"`+staleCode+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	staleReq.Header.Set("Content-Type", "application/json")
	staleReq.Header.Set(csrfHeaderName, testCSRFValue)
	staleReq.AddCookie(&http.Cookie{Name: pendingLoginCookieName, Value: stale})
	staleResp, err := (&http.Client{}).Do(staleReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = staleResp.Body.Close() }()
	if staleResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a 6-minute-old pending-login cookie carrying a correct code got %d, want 401", staleResp.StatusCode)
	}

	// Same counter (+1) as staleCode above: with the expiry guard
	// working, the stale request never actually consumed it, so this one
	// is still good.
	fresh, err := pendingLoginCodec.encode(pendingLoginState{UserID: id, IssuedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	code := gauntlet.GenerateTOTPCode(secret, confirmCounter+1)
	freshReq, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/login/factor",
		strings.NewReader(`{"code":"`+code+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	freshReq.Header.Set("Content-Type", "application/json")
	freshReq.Header.Set(csrfHeaderName, testCSRFValue)
	freshReq.AddCookie(&http.Cookie{Name: pendingLoginCookieName, Value: fresh})
	freshResp, err := (&http.Client{}).Do(freshReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = freshResp.Body.Close() }()
	if freshResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(freshResp.Body)
		t.Errorf("a fresh pending-login cookie with the right code got %d, want 200: %s", freshResp.StatusCode, body)
	}
}

// TestLoginFactorAccountLostFactorMidFlow covers the window between the
// password step and the factor step where every second factor on the
// account is cleared (an admin's TOTP clear, or the owner's own delete)
// -- the pending cookie still exists, but there is nothing left it can
// complete.
func TestLoginFactorAccountLostFactorMidFlow(t *testing.T) {
	g, ts, admin := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	totpEnrolAndConfirm(t, bob, ts)
	id := totpBobID(t, g)

	pending := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)

	clearResp := deleteJSON(t, admin, ts.URL+"/api/auth/users/"+id+"/totp", nil)
	_ = clearResp.Body.Close()
	if clearResp.StatusCode != http.StatusOK {
		t.Fatalf("admin clear returned %d", clearResp.StatusCode)
	}

	resp := submitLoginFactor(t, pending, ts, "000000")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("completing a pending login after the factor was cleared got %d, want 401", resp.StatusCode)
	}
}

// TestLoginUserKeyRateLimitExhaustsIndependentlyOfIP covers handleLogin's
// second Reserve call: the IP bucket has room, but the *username*
// bucket -- exhausted by failed attempts arriving from several other
// source addresses -- does not, and that alone is enough to refuse the
// request (and release the IP reservation this attempt claimed).
func TestLoginUserKeyRateLimitExhaustsIndependentlyOfIP(t *testing.T) {
	g := newTestGate(t)
	g.deps.Limiter = mustNewLoginLimiter(t, 5, time.Minute)
	g.cfg.ClientIP = func(r *http.Request) string { return r.Header.Get("X-Test-IP") }
	ts := newTestServer(t, g)
	registerAdmin(t, ts, "admin", "password123")

	loginAttempt := func(ip, password string) *http.Response {
		body := `{"username":"admin","password":"` + password + `"}`
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
		return resp
	}

	// Five failures against "admin", each from its own distinct source
	// IP -- the username bucket reaches its threshold while no single IP
	// bucket ever holds more than one failure.
	for i := 0; i < 5; i++ {
		resp := loginAttempt("198.51.100."+string(rune('1'+i)), "wrong")
		_ = resp.Body.Close()
	}

	// A sixth attempt, from yet another fresh IP, with the *correct*
	// password: the IP bucket has room, but the username bucket is
	// already at the limit.
	resp := loginAttempt("198.51.100.99", "password123")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("a correct password against an exhausted username bucket got %d, want 429", resp.StatusCode)
	}
}

// TestLoginFactorUserKeyRateLimitExhaustsIndependentlyOfIP is
// TestLoginUserKeyRateLimitExhaustsIndependentlyOfIP's twin for
// handleLoginFactor's own Reserve pair. A pending cookie obtained while
// the username bucket had room stays valid for its own five minutes,
// so the bucket can still fill up afterward (wrong-password attempts
// against the same username, from several other source addresses)
// before the factor step is ever submitted -- and that alone refuses
// it, even from a source address that has never made a single request.
func TestLoginFactorUserKeyRateLimitExhaustsIndependentlyOfIP(t *testing.T) {
	g, ts, admin := totpFixture(t)
	g.deps.Limiter = mustNewLoginLimiter(t, 5, time.Minute)
	var testIP string
	g.cfg.ClientIP = func(r *http.Request) string { return testIP }
	_ = admin

	testIP = "203.0.113.1"
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	totpEnrolAndConfirm(t, bob, ts)

	testIP = "203.0.113.2"
	pending := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)

	for i := 0; i < 5; i++ {
		testIP = "203.0.113." + string(rune('3'+i))
		resp := postJSON(t, &http.Client{}, ts.URL+"/api/auth/login", credentialsRequest{Username: totpBobUsername, Password: "wrong"})
		_ = resp.Body.Close()
	}

	testIP = "203.0.113.250" // never seen before in this test
	resp := submitLoginFactor(t, pending, ts, "000000")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("login/factor after exhausting the username bucket from other IPs got %d, want 429", resp.StatusCode)
	}
}

// TestConcurrentTOTPLoginFactorSubmissionsOnlyOneWins reproduces the race
// checking a TOTP code and recording its counter as two separate calls
// would leave open: two concurrent submissions of the same code both
// verifying against the same not-yet-advanced counter and both winning a
// session. gauntlet.Store.VerifyAndRecordTOTP does both under one lock
// acquisition, which is what this asserts: exactly one of the concurrent
// submissions succeeds. Run with -race to be meaningful.
func TestConcurrentTOTPLoginFactorSubmissionsOnlyOneWins(t *testing.T) {
	_, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	secret, _, counter := totpEnrolAndConfirm(t, bob, ts)

	pending := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	code := gauntlet.GenerateTOTPCode(secret, counter+1)
	body, err := json.Marshal(loginFactorRequest{Code: code})
	if err != nil {
		t.Fatal(err)
	}

	const attempts = 20
	var wg sync.WaitGroup
	var successes int32
	errs := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/login/factor", bytes.NewReader(body))
			if err != nil {
				errs <- err
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(csrfHeaderName, testCSRFValue)
			resp, err := pending.Do(req)
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode == http.StatusOK {
				atomic.AddInt32(&successes, 1)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	if successes != 1 {
		t.Errorf("%d of %d concurrent submissions of the same code succeeded, want exactly 1", successes, attempts)
	}
}
