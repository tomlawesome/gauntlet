// Ported from mikroview's internal/api/totp_test.go: the TOTP enrol/
// confirm/delete and admin-clear cases that fall inside G6 stage 2
// (docs/design.md §1.5, §1.6). The concurrent-submission race test lives
// in login_factor_test.go alongside the rest of the login/factor cases.
package gate

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/tomlawesome/gauntlet/persist"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")
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
	resp := postJSON(t, client, ts.URL+"/api/auth/totp/enrol", totpEnrolRequest{Password: totpBobPassword})
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
// signed in, holding no active factor yet), then confirms the held app
// and its codes (#58), so the app is live. Returns the decoded secret,
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
	if out.Enabled || !out.PendingConfirmation || len(out.RecoveryCodes) != 10 {
		t.Fatalf("confirm response = %+v, want held with 10 recovery codes", out)
	}
	confirmEnrolmentOK(t, client, ts)
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
	// Both devices must hold a live session when the factor goes. Enrolling
	// ends bob's other sessions, so deviceB signs in after it, through the
	// second-factor step: signing in with the password alone would stop
	// short of a session and leave nothing for the delete to revoke.
	deviceA := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	secret, _, counter := totpEnrolAndConfirm(t, deviceA, ts)
	deviceB := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	factorResp := submitLoginFactor(t, deviceB, ts, gauntlet.GenerateTOTPCode(secret, counter+1))
	_ = factorResp.Body.Close()
	if factorResp.StatusCode != http.StatusOK {
		t.Fatalf("deviceB's second-factor sign-in returned %d, want 200", factorResp.StatusCode)
	}
	for name, client := range map[string]*http.Client{"deviceA (the caller)": deviceA, "deviceB": deviceB} {
		r, err := client.Get(ts.URL + "/api/protected")
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("%s's session got %d before the factor was removed, want 200: it must be live for the sign-out to mean anything", name, r.StatusCode)
		}
	}

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

	resp := postJSON(t, bob, ts.URL+"/api/auth/totp/enrol", totpEnrolRequest{Password: totpBobPassword})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("enrolling again while active got %d, want 409", resp.StatusCode)
	}
}

// A session alone must not be enough to start enrolment: that is the
// position a stolen cookie puts an attacker in, and a factor planted from
// it locks the real owner out at their next login. The password is the
// one thing the cookie does not carry.
func TestTOTPEnrolRequiresPassword(t *testing.T) {
	g, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)

	for name, body := range map[string]any{
		"wrong password": totpEnrolRequest{Password: "not-bobs-password"},
		"no password":    totpEnrolRequest{},
	} {
		resp := postJSON(t, bob, ts.URL+"/api/auth/totp/enrol", body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: enrol got %d, want 401", name, resp.StatusCode)
		}
	}
	if u, ok := g.deps.Users.Get(totpBobID(t, g)); !ok || u.TOTPSecret != "" {
		t.Fatal("a refused enrolment left a pending secret on the account")
	}
	// The right password still works, so the check is a check and not a
	// broken route.
	totpEnrol(t, bob, ts)
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

// TestTOTPConfirmWrongCodeAndRefusalAreRecorded: a wrong code at
// confirm is a user.login_failed record marked as a re-check, and a
// confirm the limiter refuses is the rated Warn line, as at every other
// in-session re-check.
func TestTOTPConfirmWrongCodeAndRefusalAreRecorded(t *testing.T) {
	g, ts, _ := totpFixture(t)
	g.deps.Limiter = mustNewLoginLimiter(t, 1, time.Minute)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	totpEnrol(t, bob, ts)
	audit, logs, _ := recordSignIns(g)

	status, _ := readAll(t, postJSON(t, bob, ts.URL+"/api/auth/totp/confirm", totpConfirmRequest{Code: "000000"}))
	if status != http.StatusBadRequest {
		t.Fatalf("a wrong code got %d, want 400", status)
	}
	want := auditEntry{totpBobUsername, "user.login_failed", totpBobUsername, "outcome=factor_refused method=code step=recheck " + fixtureFrom}
	if failed := auditEntries(audit, "user.login_failed"); len(failed) != 1 || failed[0] != want {
		t.Errorf("records = %+v, want %+v", failed, want)
	}

	status, _ = readAll(t, postJSON(t, bob, ts.URL+"/api/auth/totp/confirm", totpConfirmRequest{Code: "000000"}))
	if status != http.StatusTooManyRequests {
		t.Fatalf("a confirm over the limit got %d, want 429", status)
	}
	if lines := logLines(logs, "re-check refused"); len(lines) != 1 || !strings.Contains(lines[0], `account="bob"`) {
		t.Errorf("refused re-check lines = %q, want one naming the account", lines)
	}
}

// TestTOTPConfirmWithNothingPendingIsAConflict: a confirm with no
// enrolment started is the documented 409, not a 400 telling the person
// to check their phone's clock.
func TestTOTPConfirmWithNothingPendingIsAConflict(t *testing.T) {
	_, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)

	resp := postJSON(t, bob, ts.URL+"/api/auth/totp/confirm", totpConfirmRequest{Code: "123456"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("confirm with no enrolment pending got %d, want 409", resp.StatusCode)
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

// TestTOTPConfirmRateLimited proves POST /api/auth/totp/confirm counts
// wrong codes on the per-account re-check bucket: a session cookie
// alone must not buy unlimited guesses at a pending enrolment's code.
func TestTOTPConfirmRateLimited(t *testing.T) {
	g, ts, _ := totpFixture(t)
	g.deps.Limiter = mustNewLoginLimiter(t, 2, time.Minute)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	enrolled := totpEnrol(t, bob, ts)
	secret, err := gauntlet.DecodeTOTPSecret(enrolled.Secret)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ {
		_ = postJSON(t, bob, ts.URL+"/api/auth/totp/confirm", totpConfirmRequest{Code: "000000x"}).Body.Close()
	}
	code := gauntlet.GenerateTOTPCode(secret, totpCounterNow(time.Now()))
	resp := postJSON(t, bob, ts.URL+"/api/auth/totp/confirm", totpConfirmRequest{Code: code})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429 after exceeding the rate limit, got %d (even with the correct code)", resp.StatusCode)
	}
	if u, ok := g.deps.Users.Get(totpBobID(t, g)); !ok || u.HasActiveTOTP() {
		t.Error("a refused confirm must leave the factor pending, not active")
	}
}

// TestTOTPDeleteRateLimited proves DELETE /api/auth/totp's password
// re-check is throttled on the per-account re-check bucket, not an unbounded
// oracle behind a stolen session cookie.
func TestTOTPDeleteRateLimited(t *testing.T) {
	g, ts, _ := totpFixture(t)
	g.deps.Limiter = mustNewLoginLimiter(t, 2, time.Minute)
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

	resp := deleteJSON(t, admin, ts.URL+"/api/auth/users/"+adminUser.ID+"/totp", adminStepUpRequest{Password: testAdminPassword})
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

	resp := deleteJSON(t, admin, ts.URL+"/api/auth/users/"+id+"/totp", adminStepUpRequest{Password: testAdminPassword})
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

		// Past the second-factor door, so it is the role check that answers.
		operator := userClientPastTheDoor(t, ts, adminClient, "operator", "operator-password-placeholder")

		wantProblem(t, deleteJSON(t, operator, ts.URL+"/api/auth/users/"+id+"/totp", adminStepUpRequest{Password: testAdminPassword}),
			http.StatusForbidden, classForbidden)
		if u, ok := g.deps.Users.Get(id); !ok || !u.HasActiveTOTP() {
			t.Error("a refused request cleared the factor anyway")
		}
	})

	t.Run("no such account", func(t *testing.T) {
		_, ts, admin := totpFixture(t)
		resp := deleteJSON(t, admin, ts.URL+"/api/auth/users/not-a-real-user-id/totp", adminStepUpRequest{Password: testAdminPassword})
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

// budgetBackend saves normally until armed, then fails every save. It
// lets a test make the second of two saves in one request fail.
type budgetBackend struct {
	inner persist.Backend
	left  int // saves allowed once armed; -1 = unarmed
}

func (b *budgetBackend) Load(ctx context.Context) (persist.Snapshot, error) {
	return b.inner.Load(ctx)
}

func (b *budgetBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	if b.left >= 0 {
		if b.left == 0 {
			return 0, errors.New("budget backend: save refused")
		}
		b.left--
	}
	return b.inner.Save(ctx, payload, expect)
}

func (b *budgetBackend) Close() error     { return b.inner.Close() }
func (b *budgetBackend) Describe() string { return "budget test backend" }

// ProtectedAtRest: a test backend over persist.Memory has no storage
// to copy (persist.AtRest), so OpenStore accepts it as it does Memory.
func (b *budgetBackend) ProtectedAtRest() bool { return true }

// budgetTOTPFixture is a gate over a store whose saves can be made to
// fail, with "bob" signed in on two devices and an authenticator app
// enrolled (scanned, not confirmed) on the first, and the code that
// confirms it.
func budgetTOTPFixture(t *testing.T) (g *Gate, ts *httptest.Server, backend *budgetBackend, deviceA, deviceB *http.Client, code string) {
	t.Helper()
	g = newTestGate(t)
	backend = &budgetBackend{inner: persist.NewMemory(), left: -1}
	g.deps.Users = openTrackedStore(t, backend)
	ts = newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")
	_ = postJSON(t, admin, ts.URL+"/api/auth/users",
		createUserRequest{Username: totpBobUsername, Password: totpBobPassword, Role: "user"}).Body.Close()

	deviceA = loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	deviceB = loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	enrolled := totpEnrol(t, deviceA, ts)
	secret, err := gauntlet.DecodeTOTPSecret(enrolled.Secret)
	if err != nil {
		t.Fatal(err)
	}
	return g, ts, backend, deviceA, deviceB, gauntlet.GenerateTOTPCode(secret, totpCounterNow(time.Now()))
}

// TestTheFirstAppWhoseHoldCannotBeSavedHoldsNothing: the first app and
// its recovery codes are one write (#58), so a failed save leaves
// neither live nor held, ends no session, and the same code can simply
// be sent again -- where the old two-write order left an active app
// with no codes behind it (the partially-completed answer this
// replaces).
func TestTheFirstAppWhoseHoldCannotBeSavedHoldsNothing(t *testing.T) {
	g, ts, backend, deviceA, deviceB, code := budgetTOTPFixture(t)

	backend.left = 0
	resp := postJSON(t, deviceA, ts.URL+"/api/auth/totp/confirm", totpConfirmRequest{Code: code})
	backend.left = -1
	wantProblem(t, resp, http.StatusInternalServerError, classServerError)

	u, _ := g.deps.Users.Get(totpBobID(t, g))
	if u.HasActiveTOTP() || u.HeldEnrolment != nil || len(u.RecoveryCodes) != 0 {
		t.Fatalf("after a failed hold: active=%v held=%+v codes=%d, want nothing", u.HasActiveTOTP(), u.HeldEnrolment, len(u.RecoveryCodes))
	}
	if !sessionAuthenticated(t, deviceB, ts) || !sessionAuthenticated(t, deviceA, ts) {
		t.Error("a failed hold ended a session")
	}

	retry := postJSON(t, deviceA, ts.URL+"/api/auth/totp/confirm", totpConfirmRequest{Code: code})
	defer func() { _ = retry.Body.Close() }()
	var out totpConfirmResponse
	if err := json.NewDecoder(retry.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if retry.StatusCode != http.StatusOK || !out.PendingConfirmation || len(out.RecoveryCodes) != 10 {
		t.Errorf("sending the code again = %d %+v, want the app held with ten codes", retry.StatusCode, out)
	}
}

// TestAConfirmationThatCannotBeSavedChangesNothing: taking the held app
// off hold is one write, and the other sessions end only once it is
// saved, so a failed save is a plain 500 with the app still held,
// nothing ended, and a retry that works.
func TestAConfirmationThatCannotBeSavedChangesNothing(t *testing.T) {
	g, ts, backend, deviceA, deviceB, code := budgetTOTPFixture(t)
	resp := postJSON(t, deviceA, ts.URL+"/api/auth/totp/confirm", totpConfirmRequest{Code: code})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("holding the app returned %d", resp.StatusCode)
	}

	backend.left = 0
	failed := confirmEnrolment(t, deviceA, ts)
	backend.left = -1
	wantProblem(t, failed, http.StatusInternalServerError, classServerError)
	u, _ := g.deps.Users.Get(totpBobID(t, g))
	if u.HasActiveTOTP() || u.HeldEnrolment == nil {
		t.Fatalf("after a failed confirmation: active=%v held=%+v, want still held", u.HasActiveTOTP(), u.HeldEnrolment)
	}
	if !sessionAuthenticated(t, deviceB, ts) {
		t.Error("a failed confirmation ended another session")
	}

	confirmEnrolmentOK(t, deviceA, ts)
	if sessionAuthenticated(t, deviceB, ts) {
		t.Error("the confirmation that worked did not end the other session")
	}
	if u, _ := g.deps.Users.Get(totpBobID(t, g)); !u.HasActiveTOTP() || len(u.RecoveryCodes) != 10 {
		t.Error("the app and its codes are not live after the confirmation")
	}
}

// wantNothingRecordedOrSent fails t if audit holds any record or rec any
// notice: what a request that changed nothing must leave behind.
func wantNothingRecordedOrSent(t *testing.T, g *Gate, audit *auditRecorder, rec *noticeRecorder) {
	t.Helper()
	g.notifying.Wait()
	audit.mu.Lock()
	entries := append([]auditEntry(nil), audit.entries...)
	audit.mu.Unlock()
	if len(entries) != 0 {
		t.Errorf("audit records = %+v, want none", entries)
	}
	if notices := rec.all(); len(notices) != 0 {
		t.Errorf("notices = %+v, want none", notices)
	}
}

// Removing an authenticator app the account does not have changes
// nothing: the owner's own delete is a 404 that signs no one out, and
// neither route writes a record or sends a notice. A second click on
// "Disable" used to end every session on the account and announce a
// removal that did not happen.
func TestTOTPRemovalWithNothingToRemoveChangesNothing(t *testing.T) {
	t.Run("owner", func(t *testing.T) {
		// The account needs some factor to be past the must-enrol door:
		// a passkey, the case a stale "Disable" button leaves.
		g, ts, _ := passkeyFixture(t)
		bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
		registerPasskey(t, bilbo, ts, g, "YubiKey")
		audit, rec := &auditRecorder{}, &noticeRecorder{}
		g.cfg.Audit, g.cfg.Notices = audit, rec

		status, body := readAll(t, deleteJSON(t, bilbo, ts.URL+"/api/auth/totp", totpDeleteRequest{Password: passkeyBilboPassword}))
		if status != http.StatusNotFound || !strings.Contains(body, "not-found") {
			t.Errorf("delete with no app = %d %s, want 404 not-found", status, body)
		}
		wantNothingRecordedOrSent(t, g, audit, rec)
		if !sessionOf(t, bilbo, ts).Authenticated {
			t.Error("the caller was signed out by a delete that removed nothing")
		}
	})
	t.Run("admin", func(t *testing.T) {
		g, ts, admin := totpFixture(t)
		bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
		audit, rec := &auditRecorder{}, &noticeRecorder{}
		g.cfg.Audit, g.cfg.Notices = audit, rec

		status, body := readAll(t, deleteJSON(t, admin, ts.URL+"/api/auth/users/"+totpBobID(t, g)+"/totp", adminStepUpRequest{Password: testAdminPassword}))
		var out map[string]any
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatalf("admin clear = %d %s: %v", status, body, err)
		}
		if status != http.StatusOK || out["username"] != totpBobUsername || out["cleared"] != false {
			t.Errorf("admin clear with no app = %d %v, want 200 cleared=false", status, out)
		}
		wantNothingRecordedOrSent(t, g, audit, rec)
		if !sessionOf(t, bob, ts).Authenticated {
			t.Error("bob was signed out by a clear that removed nothing")
		}
	})
}
