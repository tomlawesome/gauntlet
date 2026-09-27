// Ported from mikroview's internal/api/totp_test.go: the TOTP enrol/
// confirm/delete and admin-clear cases that fall inside G6 stage 2
// (docs/design.md §1.5, §1.6). The concurrent-submission race test lives
// in login_factor_test.go alongside the rest of the login/factor cases.
package gate

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
)

const totpBobPassword = "totp-bob-password-placeholder"
const totpBobUsername = "bob"

// totpCounterNow mirrors totp.go's own unexported totpStep (30 seconds)
// without reaching into gauntlet for it -- this file only ever needs the
// counter to hand to gauntlet.GenerateTOTPCode/gauntlet.VerifyTOTP, both
// already exported for exactly this.
func totpCounterNow(now time.Time) uint64 {
	return uint64(now.Unix()) / 30
}

// totpFixture stands up a Gate/server holding an admin and one ordinary
// account ("bob", user role, no factor yet).
func totpFixture(t *testing.T) (*Gate, *httptest.Server, *http.Client) {
	t.Helper()
	g := newTestGate(t)
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password123")
	_ = postJSON(t, admin, ts.URL+"/api/auth/users",
		createUserRequest{Username: totpBobUsername, Password: totpBobPassword, Role: "user"}).Body.Close()
	return g, ts, admin
}

func totpBobID(t *testing.T, g *Gate) string {
	t.Helper()
	u, ok := g.deps.Users.ByUsername(totpBobUsername)
	if !ok {
		t.Fatal("the bob account the TOTP tests act on was not created")
	}
	return u.ID
}

func totpEnrol(t *testing.T, client *http.Client, ts *httptest.Server) totpEnrolResponse {
	t.Helper()
	resp := postJSON(t, client, ts.URL+"/api/auth/totp/enrol", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("enrol returned %d: %s", resp.StatusCode, body)
	}
	var out totpEnrolResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// totpEnrolAndConfirm drives enrol+confirm end to end for client (already
// signed in, holding no active factor yet). Returns the decoded secret,
// the ten recovery codes confirm hands back, and the counter the
// confirming code was generated at -- a further code has to be generated
// at counter+1 or later, never by reading the wall clock a second time.
func totpEnrolAndConfirm(t *testing.T, client *http.Client, ts *httptest.Server) ([]byte, []string, uint64) {
	t.Helper()
	enrolled := totpEnrol(t, client, ts)
	secret, err := gauntlet.DecodeTOTPSecret(enrolled.Secret)
	if err != nil {
		t.Fatalf("decoding the enrolled secret: %v", err)
	}
	counter := totpCounterNow(time.Now())
	code := gauntlet.GenerateTOTPCode(secret, counter)

	resp := postJSON(t, client, ts.URL+"/api/auth/totp/confirm", totpConfirmRequest{Code: code})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("confirm returned %d: %s", resp.StatusCode, body)
	}
	var out totpConfirmResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.Enabled || len(out.RecoveryCodes) != 10 {
		t.Fatalf("confirm response = %+v, want enabled with 10 recovery codes", out)
	}
	return secret, out.RecoveryCodes, counter
}

func loggedInClient(t *testing.T, ts *httptest.Server, username, password string) *http.Client {
	t.Helper()
	client := &http.Client{Jar: mustCookieJar(t)}
	resp := postJSON(t, client, ts.URL+"/api/auth/login", credentialsRequest{Username: username, Password: password})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("signing %s in returned %d: %s", username, resp.StatusCode, body)
	}
	return client
}

func TestTOTPEnrolConfirmLoginFactorAndDelete(t *testing.T) {
	g, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)

	secret, _, confirmCounter := totpEnrolAndConfirm(t, bob, ts)

	// Confirming must not sign this browser out.
	sessResp, err := bob.Get(ts.URL + "/api/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sessResp.Body.Close() }()
	var sess sessionResponse
	_ = json.NewDecoder(sessResp.Body).Decode(&sess)
	if !sess.Authenticated {
		t.Fatal("confirming TOTP should not have signed this browser out")
	}

	// A fresh browser presenting only the password stops short of a
	// session.
	pending := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	protected, err := pending.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	_ = protected.Body.Close()
	if protected.StatusCode != http.StatusUnauthorized {
		t.Errorf("the password-only step reached a protected route with %d, want 401", protected.StatusCode)
	}

	code := gauntlet.GenerateTOTPCode(secret, confirmCounter+1)
	resp := submitLoginFactor(t, pending, ts, code)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login/factor returned %d, want 200", resp.StatusCode)
	}

	del := deleteJSON(t, bob, ts.URL+"/api/auth/totp", totpDeleteRequest{Password: totpBobPassword})
	defer func() { _ = del.Body.Close() }()
	if del.StatusCode != http.StatusOK {
		t.Fatalf("delete returned %d", del.StatusCode)
	}
	if u, ok := g.deps.Users.Get(totpBobID(t, g)); !ok || u.HasActiveTOTP() {
		t.Error("expected the factor to be gone after DELETE /api/auth/totp")
	}

	// An ordinary password login works again, one step, no factor
	// requested.
	plain := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	plainSess, err := plain.Get(ts.URL + "/api/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plainSess.Body.Close() }()
	var out sessionResponse
	_ = json.NewDecoder(plainSess.Body).Decode(&out)
	if !out.Authenticated {
		t.Error("expected a plain password login to work once the factor was removed")
	}
}

func TestTOTPDeleteLeavingNoFactorSignsOutEverySession(t *testing.T) {
	g, ts, _ := totpFixture(t)
	deviceA := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	totpEnrolAndConfirm(t, deviceA, ts)
	deviceB := loggedInClient(t, ts, totpBobUsername, totpBobPassword)

	resp := deleteJSON(t, deviceA, ts.URL+"/api/auth/totp", totpDeleteRequest{Password: totpBobPassword})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("delete returned %d: %s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["disabled"] != true || out["signedOut"] != true {
		t.Errorf("delete response = %v, want disabled=true signedOut=true", out)
	}
	_ = g

	for name, client := range map[string]*http.Client{"deviceA (the caller)": deviceA, "deviceB": deviceB} {
		r, err := client.Get(ts.URL + "/api/protected")
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s's session got %d once the account lost its only factor, want 401", name, r.StatusCode)
		}
	}
}

// TestConcurrentTOTPLoginFactorSubmissionsOnlyOneWins lives here, next to
// the fixtures it needs, even though it exercises handleLoginFactor --
// see login_factor_test.go for the rest of that handler's cases.

func TestTOTPEnrolRefusedForSSOAccount(t *testing.T) {
	g, ts, _ := totpFixture(t)
	// A second (issuer, subject) so this doesn't become the first
	// account and get RoleAdmin -- totpFixture already registered admin.
	u, _, err := g.deps.Users.FindOrCreateOIDCUser("https://idp.example", "subject-placeholder", "frodo", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sess := g.deps.Sessions.Create(u.ID, time.Now())

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/totp/enrol", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(csrfHeaderName, testCSRFValue)
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: sess.ID})
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("enrol for an SSO-only account got %d, want 409", resp.StatusCode)
	}
}

func TestTOTPEnrolConflictWhenAlreadyActive(t *testing.T) {
	_, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	totpEnrolAndConfirm(t, bob, ts)

	resp := postJSON(t, bob, ts.URL+"/api/auth/totp/enrol", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("enrolling again while active got %d, want 409", resp.StatusCode)
	}
}

func TestTOTPConfirmRejectsBadCode(t *testing.T) {
	_, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	totpEnrol(t, bob, ts)

	resp := postJSON(t, bob, ts.URL+"/api/auth/totp/confirm", totpConfirmRequest{Code: "000000"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a wrong code got %d, want 400", resp.StatusCode)
	}
}

// TestTOTPConfirmAgainAfterAlreadyConfirmedRefused covers ConfirmTOTP's
// ErrNoPendingTOTP path from the route: a second, otherwise-valid code
// submitted after the factor is already active finds no pending
// secret left to confirm.
func TestTOTPConfirmAgainAfterAlreadyConfirmedRefused(t *testing.T) {
	_, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	secret, _, confirmCounter := totpEnrolAndConfirm(t, bob, ts)

	code := gauntlet.GenerateTOTPCode(secret, confirmCounter+1)
	resp := postJSON(t, bob, ts.URL+"/api/auth/totp/confirm", totpConfirmRequest{Code: code})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("confirming again once already active got %d, want 409", resp.StatusCode)
	}
}

// TestTOTPDeleteRateLimited proves DELETE /api/auth/totp's password
// re-check is throttled on passwordRecheckLimiterKey, not an unbounded
// oracle behind a stolen session cookie.
func TestTOTPDeleteRateLimited(t *testing.T) {
	g, ts, _ := totpFixture(t)
	g.deps.Limiter = gauntlet.NewLoginLimiter(2, time.Minute)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	totpEnrolAndConfirm(t, bob, ts)

	for i := 0; i < 2; i++ {
		_ = deleteJSON(t, bob, ts.URL+"/api/auth/totp", totpDeleteRequest{Password: "wrong"}).Body.Close()
	}
	resp := deleteJSON(t, bob, ts.URL+"/api/auth/totp", totpDeleteRequest{Password: totpBobPassword})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429 after exceeding the rate limit, got %d (even with the correct password)", resp.StatusCode)
	}
}

func TestTOTPDeleteWrongPassword(t *testing.T) {
	g, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	totpEnrolAndConfirm(t, bob, ts)
	id := totpBobID(t, g)

	resp := deleteJSON(t, bob, ts.URL+"/api/auth/totp", totpDeleteRequest{Password: "not-the-password"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a wrong password got %d, want 401", resp.StatusCode)
	}
	u, ok := g.deps.Users.Get(id)
	if !ok || !u.HasActiveTOTP() {
		t.Error("the factor must survive a wrong-password attempt to remove it")
	}
}

func TestAdminCannotClearOwnTOTP(t *testing.T) {
	g, ts, admin := totpFixture(t)
	adminUser, ok := g.deps.Users.ByUsername("admin")
	if !ok {
		t.Fatal("no admin account")
	}

	resp := deleteJSON(t, admin, ts.URL+"/api/auth/users/"+adminUser.ID+"/totp", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("an admin clearing their own factor got %d, want 409", resp.StatusCode)
	}
}

func TestTOTPAdminClearHappyPath(t *testing.T) {
	g, ts, admin := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	totpEnrolAndConfirm(t, bob, ts)
	id := totpBobID(t, g)

	resp := deleteJSON(t, admin, ts.URL+"/api/auth/users/"+id+"/totp", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("admin clear returned %d: %s", resp.StatusCode, body)
	}
	u, ok := g.deps.Users.Get(id)
	if !ok || u.HasActiveTOTP() {
		t.Error("expected the factor to be cleared")
	}

	plain := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	plainSess, err := plain.Get(ts.URL + "/api/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plainSess.Body.Close() }()
	var out sessionResponse
	_ = json.NewDecoder(plainSess.Body).Decode(&out)
	if !out.Authenticated {
		t.Error("expected a plain password login to work once the admin cleared the factor")
	}
}

func TestTOTPAdminClearRefusals(t *testing.T) {
	t.Run("a user-tier caller may not clear someone else's factor", func(t *testing.T) {
		g, ts, adminClient := totpFixture(t)
		bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
		totpEnrolAndConfirm(t, bob, ts)
		id := totpBobID(t, g)

		_ = postJSON(t, adminClient, ts.URL+"/api/auth/users",
			createUserRequest{Username: "operator", Password: "operator-password-placeholder", Role: "user"}).Body.Close()
		operator := loggedInClient(t, ts, "operator", "operator-password-placeholder")

		resp := deleteJSON(t, operator, ts.URL+"/api/auth/users/"+id+"/totp", nil)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("a user-tier caller got %d, want 403", resp.StatusCode)
		}
	})

	t.Run("no such account", func(t *testing.T) {
		_, ts, admin := totpFixture(t)
		resp := deleteJSON(t, admin, ts.URL+"/api/auth/users/not-a-real-user-id/totp", nil)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("a nonexistent target got %d, want 404", resp.StatusCode)
		}
	})
}

func TestTheFactorIsVisibleToTheFrontend(t *testing.T) {
	g, ts, admin := totpFixture(t)
	_ = postJSON(t, admin, ts.URL+"/api/auth/users",
		createUserRequest{Username: "carol", Password: totpBobPassword, Role: "user"}).Body.Close()

	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	if got := totpSessionHasTOTP(t, bob, ts); got {
		t.Error("the session reports a factor before one was enrolled")
	}
	if got := totpListedHasTOTP(t, admin, ts, totpBobUsername); got {
		t.Error("the user list reports a factor for bob before one was enrolled")
	}

	totpEnrolAndConfirm(t, bob, ts)

	if got := totpSessionHasTOTP(t, bob, ts); !got {
		t.Error("bob's own session does not report the factor they just enrolled")
	}
	if got := totpListedHasTOTP(t, admin, ts, totpBobUsername); !got {
		t.Error("the admin user list does not report bob's factor")
	}
	if got := totpListedHasTOTP(t, admin, ts, "carol"); got {
		t.Error("the user list reports a factor for carol, who never enrolled one")
	}

	if err := g.deps.Users.ClearTOTP(totpBobID(t, g)); err != nil {
		t.Fatal(err)
	}
	if got := totpListedHasTOTP(t, admin, ts, totpBobUsername); got {
		t.Error("the user list still reports a factor after it was cleared")
	}
}

func totpSessionHasTOTP(t *testing.T, client *http.Client, ts *httptest.Server) bool {
	t.Helper()
	resp, err := client.Get(ts.URL + "/api/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body sessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body.HasTOTP
}

func totpListedHasTOTP(t *testing.T, admin *http.Client, ts *httptest.Server, username string) bool {
	t.Helper()
	resp, err := admin.Get(ts.URL + "/api/auth/users")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out []userSummary
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	for _, u := range out {
		if u.Username == username {
			return u.HasTOTP
		}
	}
	t.Fatalf("no row for %q in the user list", username)
	return false
}
