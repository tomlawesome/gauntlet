// Ported from mikroview's internal/api/auth_test.go: the requireAuth
// cases that fall inside G6 stage 1 (docs/design.md §1.5) -- bootstrap
// gating, CSRF, session gating and the session-cutoff revoke check.
// Second-factor login, TOTP and OIDC cases are stage 2 and are not
// ported here.
package gate

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
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

	b, _ := json.Marshal(credentialsRequest{Username: "admin", Password: "password-placeholder-1"})
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

	client := registerAdmin(t, ts, "admin", "password-placeholder-1")

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

	client := registerAdmin(t, ts, "admin", "password-placeholder-1")

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
	resp := postJSON(t, client, ts.URL+"/api/auth/register", registerRequest{Username: "tom@example.com", Password: "password-placeholder-1", SetupCode: setupCodeFor(t, g)})
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

	registerAdmin(t, ts, "admin", "password-placeholder-1")

	resp := postJSON(t, &http.Client{}, ts.URL+"/api/auth/register", credentialsRequest{Username: "second", Password: "password456"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("expected 409 for a second registration attempt, got %d", resp.StatusCode)
	}
}

func TestAPIGatedOnceAUserExists(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)

	registerAdmin(t, ts, "admin", "password-placeholder-1")

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

	// registerAdminNoFactor: a confirmed factor would turn the
	// password-only login below into a pending login, not the full
	// session this test is about.
	registerAdminNoFactor(t, ts, "admin", "password-placeholder-1").Jar = nil // registration's own session is not what this test checks

	client := &http.Client{Jar: mustCookieJar(t)}
	loginResp := postJSON(t, client, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "password-placeholder-1"})
	_ = loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected login to succeed, got %d", loginResp.StatusCode)
	}
	enrolTOTPFactor(t, client, ts, "password-placeholder-1") // /api/protected is not an enrolment route

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

	registerAdmin(t, ts, "admin", "password-placeholder-1")

	resp := postJSON(t, &http.Client{}, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "wrong"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for a wrong password, got %d", resp.StatusCode)
	}
}

func TestLoginRejectsUnknownUsernameWithIdenticalBody(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	registerAdmin(t, ts, "admin", "password-placeholder-1")

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

	registerAdmin(t, ts, "admin", "password-placeholder-1")

	for i := 0; i < 2; i++ {
		_ = postJSON(t, &http.Client{}, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "wrong"}).Body.Close()
	}
	resp := postJSON(t, &http.Client{}, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "password-placeholder-1"})
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

	registerAdmin(t, ts, "admin", "password-placeholder-1")
	for i := 0; i < 2; i++ {
		_ = postJSON(t, &http.Client{}, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "wrong"}).Body.Close()
	}

	g.deps.Limiter = mustNewLoginLimiter(t, 2, time.Minute)
	resp := postJSON(t, &http.Client{}, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "password-placeholder-1"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected the persisted lockout to refuse the account after a restart, got %d", resp.StatusCode)
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)

	client := registerAdmin(t, ts, "admin", "password-placeholder-1")
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
	registerAdmin(t, ts, "admin", "password-placeholder-1")

	resp := postJSON(t, &http.Client{}, ts.URL+"/api/auth/logout-all", map[string]any{})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected an anonymous caller to be refused, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got == "" {
		t.Error("expected a WWW-Authenticate header on the 401 (RFC 9110 §15.5.2)")
	}
}

// sessionClient is an http.Client whose jar carries a session cookie for
// an already-issued session -- for standing up a second "device" whose
// session was never actually logged in through the login flow (that
// flow would need to clear the forced-enrolment door itself, or -- past
// it -- would be ended by enrolling a factor on a sibling session, see
// TestTOTPConfirmSignsOutOtherSessionsEvenWhenRecoveryCodesFail).
func sessionClient(t *testing.T, ts string, sessionID string) *http.Client {
	t.Helper()
	jar := mustCookieJar(t)
	u, err := url.Parse(ts)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(u, []*http.Cookie{{Name: testCookieName, Value: sessionID, Path: "/"}})
	return &http.Client{Jar: jar}
}

func TestLogoutAllEndsEverySessionButTheCallers(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	// registerAdminNoFactor, then enrol a factor on that same session:
	// doing it through a real login for "deviceA"/"deviceB" below would
	// either leave them at a pending login (once admin already holds a
	// factor) or, enrolled afterward on one of them, end the other's
	// session as a side effect (TOTP confirm's own revoke-other-sessions
	// rule) -- neither is what this test, about logout-all itself, is
	// about, so both device sessions are created directly instead.
	setup := registerAdminNoFactor(t, ts, "admin", "password-placeholder-1")
	enrolTOTPFactor(t, setup, ts, "password-placeholder-1") // logout-all and /api/protected are not enrolment routes

	admin, ok := g.deps.Users.ByUsername("admin")
	if !ok {
		t.Fatal("admin account missing")
	}
	now := time.Now()
	deviceA := sessionClient(t, ts.URL, g.deps.Sessions.Create(admin.ID, now).ID)
	deviceB := sessionClient(t, ts.URL, g.deps.Sessions.Create(admin.ID, now).ID)

	callResp := postJSON(t, deviceA, ts.URL+"/api/auth/logout-all", logoutAllRequest{Password: testAdminPassword})
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
// User.SessionCutoff (see Gate.sessionUser).
func TestPasswordResetInvalidatesExistingSessions(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password-placeholder-1")

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

// TestLinkingSSOInvalidatesExistingSessions: linking an account to SSO
// ends its earlier sessions through SessionsEndedAt, not
// PasswordChangedAt (#28), so the gate's check has to read both.
func TestLinkingSSOInvalidatesExistingSessions(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password-placeholder-1")
	if got := protectedStatusWithCookie(t, client, ts.URL, nil); got != http.StatusOK {
		t.Fatalf("expected the session to work before the link, got %d", got)
	}
	admin, _ := g.deps.Users.ByUsername("admin")
	if err := g.deps.Users.LinkOIDCIdentity(admin.ID, "https://idp.example", "subject-1", time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := protectedStatusWithCookie(t, client, ts.URL, nil); got != http.StatusUnauthorized {
		t.Errorf("expected the pre-link session to be invalidated, got %d", got)
	}
}

// TestAnOlderDocumentsLinkStillEndsEarlierSessions: an accounts
// document written before SessionsEndedAt existed (gauntlet v0.2.0,
// mikroview) records an SSO link in passwordChangedAt alone. A session
// issued before that time stays dead; one issued after it works.
func TestAnOlderDocumentsLinkStillEndsEarlierSessions(t *testing.T) {
	linkedAt := time.Now().Add(-time.Minute)
	hash, err := gauntlet.HashPassword("password-placeholder-1")
	if err != nil {
		t.Fatal(err)
	}
	users := openStoreWithUsers(t, gauntlet.User{
		ID:                "linked-admin",
		Username:          "admin",
		PasswordHash:      hash,
		Role:              gauntlet.RoleAdmin,
		CreatedAt:         linkedAt.Add(-time.Hour),
		PasswordChangedAt: linkedAt,
		OIDCIssuer:        "https://idp.example",
		OIDCSubject:       "subject-1",
		HasLocalPassword:  true,
		// This account still carries a local password (see the field's
		// doc comment), so it needs an active second factor to clear the
		// forced-enrolment door -- not what this test is about, hence a
		// secret no code is ever verified against.
		TOTPSecret:      "placeholder-secret",
		TOTPConfirmedAt: linkedAt.Add(-time.Hour),
	})
	if u, _ := users.Get("linked-admin"); !u.SessionsEndedAt.IsZero() {
		t.Fatalf("test setup: the older document should carry no sessionsEndedAt, got %v", u.SessionsEndedAt)
	}
	g := newTestGate(t)
	g.deps.Users = users
	ts := newTestServer(t, g)

	before := g.deps.Sessions.Create("linked-admin", linkedAt.Add(-time.Second))
	if got := protectedStatusWithCookie(t, http.DefaultClient, ts.URL, &http.Cookie{Name: testCookieName, Value: before.ID}); got != http.StatusUnauthorized {
		t.Errorf("a session issued before the older document's link got %d, want 401", got)
	}
	after := g.deps.Sessions.Create("linked-admin", linkedAt.Add(time.Second))
	if got := protectedStatusWithCookie(t, http.DefaultClient, ts.URL, &http.Cookie{Name: testCookieName, Value: after.ID}); got != http.StatusOK {
		t.Errorf("a session issued after the older document's link got %d, want 200", got)
	}
}

// protectedStatusWithCookie is the status GET /api/protected answers
// client with, sending cookie too when it is not nil.
func protectedStatusWithCookie(t *testing.T, client *http.Client, base string, cookie *http.Cookie) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+"/api/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestMutatingRequestWithoutCSRFHeaderIsRejectedOnceAuthActive(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	registerAdmin(t, ts, "admin", "password-placeholder-1")

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
	// registerAdminNoFactor: session expiry is caught in Protect before
	// the second-factor door is ever reached, so this account does not
	// need one -- and registerAdmin's extra enrol/confirm round trips
	// would risk outliving the 1ms session this test needs to survive
	// registration itself.
	client := registerAdminNoFactor(t, ts, "admin", "password-placeholder-1")

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

// TestRequireSecondFactorBlocksAccountWithNone pins Protect's own door:
// a local-password account with no confirmed second factor can reach
// nothing but the enrolment routes (#49) -- docs/design.md §1.5.
func TestRequireSecondFactorBlocksAccountWithNone(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdminNoFactor(t, ts, "admin", "password-placeholder-1")

	resp, err := client.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for a local account with no second factor, got %d", resp.StatusCode)
	}
}

// TestRequireSecondFactorFalseStillBlocksAccountWithNone pins #49: the
// deprecated Config.RequireSecondFactor field no longer has an "off"
// state that lets an unenrolled local-password account through. Before
// #49 this was the control test for the one above, proving the door
// opened when the field was left false (its zero value); now the field
// is ignored and the door holds regardless, so the account can still
// reach only the enrolment routes.
func TestRequireSecondFactorFalseStillBlocksAccountWithNone(t *testing.T) {
	g := newTestGate(t)
	g.cfg.RequireSecondFactor = false //nolint:staticcheck // pinning that the deprecated field is ignored
	ts := newTestServer(t, g)
	client := registerAdminNoFactor(t, ts, "admin", "password-placeholder-1")

	resp, err := client.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected RequireSecondFactor=false to still block an unenrolled local account, got %d", resp.StatusCode)
	}

	enrol := postJSON(t, client, ts.URL+"/api/auth/totp/enrol", totpEnrolRequest{Password: "password-placeholder-1"})
	defer func() { _ = enrol.Body.Close() }()
	if enrol.StatusCode != http.StatusOK {
		t.Errorf("expected the TOTP enrolment route to stay reachable while stuck at the door, got %d", enrol.StatusCode)
	}
}

// TestAuthSessionEmitsFalseBooleans: mikroview's frontend reads
// hasLocalPassword and its siblings as answers, so a false one has to
// be on the wire as false, not left out.
func TestAuthSessionEmitsFalseBooleans(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password-placeholder-1")

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

// An SSO-only account has no password to change, and the one route the
// must-change door admits refuses it, so the door would shut it out of
// everything. The store no longer sets the flag on such an account, but
// a document written before that may carry it: the door lets it by.
func TestMustChangePasswordDoorSkipsAnSSOOnlyAccount(t *testing.T) {
	hash, err := gauntlet.HashPassword("password-placeholder-1")
	if err != nil {
		t.Fatal(err)
	}
	g := newTestGate(t)
	g.deps.Users = openStoreWithUsers(t,
		gauntlet.User{
			ID: "admin-1", Username: "admin", PasswordHash: hash, Role: gauntlet.RoleAdmin,
			CreatedAt: time.Now(), HasLocalPassword: true,
		},
		gauntlet.User{
			ID: "frodo-1", Username: "frodo", PasswordHash: hash, Role: gauntlet.RoleUser,
			CreatedAt: time.Now(), OIDCIssuer: "https://idp.example", OIDCSubject: "subject-frodo",
			HasLocalPassword: false, MustChangePassword: true,
		})
	ts := newTestServer(t, g)
	sess := g.deps.Sessions.Create("frodo-1", time.Now())
	if got := protectedStatusWithCookie(t, sessionClient(t, ts.URL, sess.ID), ts.URL, nil); got != http.StatusOK {
		t.Errorf("an SSO-only account carrying MustChangePassword got %d, want 200", got)
	}
}
