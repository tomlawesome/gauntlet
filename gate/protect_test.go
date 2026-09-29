// Ported from mikroview's internal/api/auth_test.go: the requireAuth
// cases that fall inside G6 stage 1 (docs/design.md §1.5) -- bootstrap
// gating, CSRF, session gating and the PasswordChangedAt revoke check.
// Second-factor login, TOTP and OIDC cases are stage 2 and are not
// ported here.
package gate

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// TestUndecidedStateRestrictsToBootstrapPaths covers the gap a
// blanket-open zero-account state would leave: before an account has
// been created, an ordinary protected route must not be reachable by
// whoever gets there first.
func TestUndecidedStateRestrictsToBootstrapPaths(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)

	resp, err := http.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected /api/protected to be blocked while undecided, got %d", resp.StatusCode)
	}
}

func TestUndecidedStateAllowsBootstrapPaths(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)

	for _, path := range []string{"/api/healthz", "/api/auth/session"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected %s to stay reachable while undecided, got %d", path, resp.StatusCode)
		}
	}
}

// TestBootstrapRegisterRequiresCSRFHeader: a bare cross-site <form
// method=POST> can't set a custom header, so a request missing it
// during the undecided window must be rejected for the endpoint that
// makes an irreversible, deployment-wide choice.
func TestBootstrapRegisterRequiresCSRFHeader(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)

	b, _ := json.Marshal(credentialsRequest{Username: "admin", Password: "password123"})
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/register", strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Deliberately no csrfHeaderName.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for register without the CSRF header during bootstrap, got %d", resp.StatusCode)
	}
	if g.deps.Users.Count() != 0 {
		t.Error("the forged request must not have taken effect")
	}
}

func TestAuthSessionReportsSetupRequired(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)

	resp, err := http.Get(ts.URL + "/api/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	var body sessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !body.SetupRequired || body.Authenticated {
		t.Errorf("expected setupRequired=true, authenticated=false, got %+v", body)
	}
}

func TestAuthSessionReportsSignedInSince(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)

	client := registerAdmin(t, ts, "admin", "password123")

	resp, err := client.Get(ts.URL + "/api/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	var body sessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !body.Authenticated {
		t.Fatalf("expected an authenticated session, got %+v", body)
	}
	since, err := time.Parse(time.RFC3339, body.SignedInSince)
	if err != nil {
		t.Fatalf("signedInSince %q did not parse as RFC3339: %v", body.SignedInSince, err)
	}
	if time.Since(since) > time.Minute {
		t.Errorf("expected signedInSince to be about now, got %v", since)
	}
}

func TestRegisterCreatesAdminAndStartsASession(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)

	client := registerAdmin(t, ts, "admin", "password123")

	sessResp, err := client.Get(ts.URL + "/api/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sessResp.Body.Close() }()
	var body sessionResponse
	_ = json.NewDecoder(sessResp.Body).Decode(&body)
	if !body.Authenticated || body.Role != "admin" {
		t.Errorf("expected an authenticated admin session after registering, got %+v", body)
	}
}

func TestRegisterRefusesAnEmailShapedUsername(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)

	client := &http.Client{}
	resp := postJSON(t, client, ts.URL+"/api/auth/register", credentialsRequest{Username: "tom@example.com", Password: "password123"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "email address") {
		t.Errorf("refusal = %q, want it to name the rule", strings.TrimSpace(string(body)))
	}
	if g.deps.Users.Count() != 0 {
		t.Error("the refused registration created an account anyway")
	}
}

func TestRegisterClosesAfterFirstUser(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)

	registerAdmin(t, ts, "admin", "password123")

	resp := postJSON(t, &http.Client{}, ts.URL+"/api/auth/register", credentialsRequest{Username: "second", Password: "password456"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("expected 409 for a second registration attempt, got %d", resp.StatusCode)
	}
}

func TestAPIGatedOnceAUserExists(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)

	registerAdmin(t, ts, "admin", "password123")

	resp, err := http.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for an unauthenticated request once a user exists, got %d", resp.StatusCode)
	}

	hz, err := http.Get(ts.URL + "/api/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hz.Body.Close() }()
	if hz.StatusCode != http.StatusOK {
		t.Errorf("expected /api/healthz to stay open, got %d", hz.StatusCode)
	}
}

func TestLoginThenAccessProtectedRoute(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)

	registerAdmin(t, ts, "admin", "password123").Jar = nil // registration's own session is not what this test checks

	client := &http.Client{Jar: mustCookieJar(t)}
	loginResp := postJSON(t, client, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "password123"})
	_ = loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected login to succeed, got %d", loginResp.StatusCode)
	}

	resp, err := client.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected the session cookie to grant access, got %d", resp.StatusCode)
	}
	_ = g
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)

	registerAdmin(t, ts, "admin", "password123")

	resp := postJSON(t, &http.Client{}, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "wrong"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for a wrong password, got %d", resp.StatusCode)
	}
}

func TestLoginRejectsUnknownUsernameWithIdenticalBody(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	registerAdmin(t, ts, "admin", "password123")

	wrongPW := postJSON(t, &http.Client{}, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "wrong"})
	defer func() { _ = wrongPW.Body.Close() }()
	unknown := postJSON(t, &http.Client{}, ts.URL+"/api/auth/login", credentialsRequest{Username: "nobody", Password: "wrong"})
	defer func() { _ = unknown.Body.Close() }()

	if wrongPW.StatusCode != unknown.StatusCode {
		t.Fatalf("status differs: wrong password %d, unknown user %d", wrongPW.StatusCode, unknown.StatusCode)
	}
	b1, _ := io.ReadAll(wrongPW.Body)
	b2, _ := io.ReadAll(unknown.Body)
	if string(b1) != string(b2) {
		t.Errorf("bodies differ: %q vs %q -- a caller could tell a username exists", b1, b2)
	}
}

func TestLoginRateLimited(t *testing.T) {
	g := newTestGate(t)
	g.deps.Limiter = mustNewLoginLimiter(t, 2, time.Minute)
	ts := newTestServer(t, g)

	registerAdmin(t, ts, "admin", "password123")

	for i := 0; i < 2; i++ {
		_ = postJSON(t, &http.Client{}, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "wrong"}).Body.Close()
	}
	resp := postJSON(t, &http.Client{}, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "password123"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429 after exceeding the rate limit, got %d (even with the correct password)", resp.StatusCode)
	}
}

// TestLoginLockoutSurvivesALimiterRestart: the lockout is written to the
// account (#19), so a fresh limiter -- what a restarted process has --
// still refuses the account, even with the right password.
func TestLoginLockoutSurvivesALimiterRestart(t *testing.T) {
	g := newTestGate(t)
	g.deps.Limiter = mustNewLoginLimiter(t, 2, time.Minute)
	ts := newTestServer(t, g)

	registerAdmin(t, ts, "admin", "password123")
	for i := 0; i < 2; i++ {
		_ = postJSON(t, &http.Client{}, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "wrong"}).Body.Close()
	}

	g.deps.Limiter = mustNewLoginLimiter(t, 2, time.Minute)
	resp := postJSON(t, &http.Client{}, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "password123"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected the persisted lockout to refuse the account after a restart, got %d", resp.StatusCode)
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)

	client := registerAdmin(t, ts, "admin", "password123")
	_ = postJSON(t, client, ts.URL+"/api/auth/logout", map[string]any{}).Body.Close()

	resp, err := client.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected the session to no longer work after logout, got %d", resp.StatusCode)
	}
}

func TestLogoutAllRejectsAnonymousCaller(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	registerAdmin(t, ts, "admin", "password123")

	resp := postJSON(t, &http.Client{}, ts.URL+"/api/auth/logout-all", map[string]any{})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected an anonymous caller to be refused, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got == "" {
		t.Error("expected a WWW-Authenticate header on the 401 (RFC 9110 §15.5.2)")
	}
}

func TestLogoutAllEndsEverySessionButTheCallers(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	registerAdmin(t, ts, "admin", "password123")

	deviceA := &http.Client{Jar: mustCookieJar(t)}
	_ = postJSON(t, deviceA, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "password123"}).Body.Close()

	deviceB := &http.Client{Jar: mustCookieJar(t)}
	_ = postJSON(t, deviceB, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "password123"}).Body.Close()

	callResp := postJSON(t, deviceA, ts.URL+"/api/auth/logout-all", map[string]any{})
	_ = callResp.Body.Close()
	if callResp.StatusCode != http.StatusOK {
		t.Fatalf("expected sign-out-everywhere to succeed, got %d", callResp.StatusCode)
	}

	aResp, err := deviceA.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = aResp.Body.Close() }()
	if aResp.StatusCode != http.StatusOK {
		t.Errorf("expected the calling device's session to keep working, got %d", aResp.StatusCode)
	}

	bResp, err := deviceB.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bResp.Body.Close() }()
	if bResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected the other device's session to be revoked, got %d", bResp.StatusCode)
	}
}

// TestPasswordResetInvalidatesExistingSessions simulates a password
// reset from a separate process (a CLI recovery tool in the real
// application) -- it has no handle on the running server's
// SessionStore, so this has to work purely off the persisted
// User.PasswordChangedAt field (see Gate.sessionUser).
func TestPasswordResetInvalidatesExistingSessions(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password123")

	pre, err := client.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	_ = pre.Body.Close()
	if pre.StatusCode != http.StatusOK {
		t.Fatalf("expected the session to work before the reset, got %d", pre.StatusCode)
	}

	if err := g.deps.Users.SetPassword("admin", "new-password", time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	post, err := client.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = post.Body.Close() }()
	if post.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected the pre-reset session to be invalidated, got %d", post.StatusCode)
	}
}

func TestMutatingRequestWithoutCSRFHeaderIsRejectedOnceAuthActive(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	registerAdmin(t, ts, "admin", "password123")

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for a mutating request missing the CSRF header, got %d", resp.StatusCode)
	}
}

// TestExpiredSessionIsRefused pins the sliding-expiry ceiling: a session
// whose ttl has elapsed must be refused, not silently renewed.
func TestExpiredSessionIsRefused(t *testing.T) {
	g := newTestGate(t)
	g.deps.Sessions = gauntlet.NewSessionStore(time.Millisecond, 0)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password123")

	time.Sleep(5 * time.Millisecond)

	resp, err := client.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected an expired session to be refused, got %d", resp.StatusCode)
	}
}

// TestRequireSecondFactorBlocksAccountWithNone pins Protect's own door,
// gated by Config.RequireSecondFactor -- docs/design.md §1.5.
func TestRequireSecondFactorBlocksAccountWithNone(t *testing.T) {
	g := newTestGate(t)
	g.cfg.RequireSecondFactor = true
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password123")

	resp, err := client.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for a local account with no second factor once RequireSecondFactor is set, got %d", resp.StatusCode)
	}
}

// TestRequireSecondFactorOffAllowsAccountWithNone is the control for the
// test above: with the door off (the default), the same account is let
// through.
func TestRequireSecondFactorOffAllowsAccountWithNone(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password123")

	resp, err := client.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected RequireSecondFactor=false to let the account through, got %d", resp.StatusCode)
	}
}

// TestAuthSessionEmitsFalseBooleans: mikroview's frontend reads
// hasLocalPassword and its siblings as answers, so a false one has to
// be on the wire as false, not left out.
func TestAuthSessionEmitsFalseBooleans(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password123")

	resp, err := client.Get(ts.URL + "/api/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"hasLocalPassword", "ssoConnected", "mustChangePassword", "mustEnrolSecondFactor", "hasTOTP"} {
		if _, ok := body[key]; !ok {
			t.Errorf("session response is missing %q; a false value must still be emitted", key)
		}
	}
}
