package gate

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tomlawesome/gauntlet"
)

// #45's remaining records: the client address in every audit record a
// request writes, failed in-session re-checks, oversize bodies, and the
// disable a known browser's allowance brings on.

// Every audit record a request writes carries the address it came from,
// across the account, token, factor and session routes.
func TestEveryAuditRecordCarriesTheAddress(t *testing.T) {
	g := newTestGate(t)
	audit := &auditRecorder{}
	g.cfg.Audit = audit
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")
	_ = postJSON(t, admin, ts.URL+"/api/auth/users", createUserRequest{Username: totpBobUsername, Password: totpBobPassword, Role: "user"}).Body.Close()
	_ = postJSON(t, admin, ts.URL+"/api/auth/users", createUserRequest{Username: "carol", Password: totpBobPassword, Role: "user"}).Body.Close()
	bobID := totpBobID(t, g)
	carol, _ := g.deps.Users.ByUsername("carol")

	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	_, _, _ = totpEnrolAndConfirm(t, bob, ts)
	_ = postJSON(t, bob, ts.URL+"/api/auth/recovery-codes", recoveryCodesRegenerateRequest{Password: totpBobPassword}).Body.Close()
	_ = postJSON(t, bob, ts.URL+"/api/auth/logout-all", logoutAllRequest{Password: totpBobPassword}).Body.Close()
	_ = postJSON(t, bob, ts.URL+changePasswordPath, changePasswordRequest{CurrentPassword: totpBobPassword, NewPassword: "a-new-bob-password-9"}).Body.Close()
	_ = deleteJSON(t, bob, ts.URL+"/api/auth/totp", totpDeleteRequest{Password: "a-new-bob-password-9"}).Body.Close()

	resp := postJSON(t, admin, ts.URL+"/api/tokens", createTokenRequest{Name: "ci", Password: testAdminPassword})
	var tok struct {
		ID string `json:"id"`
	}
	status, body := readAll(t, resp)
	if status != http.StatusCreated {
		t.Fatalf("token create: %d %s", status, body)
	}
	if err := json.Unmarshal([]byte(body), &tok); err != nil {
		t.Fatal(err)
	}
	_ = deleteJSON(t, admin, ts.URL+"/api/tokens/"+tok.ID, nil).Body.Close()
	_ = postJSON(t, admin, ts.URL+"/api/auth/users/"+bobID+"/reset-password", adminStepUpRequest{Password: testAdminPassword}).Body.Close()
	_ = postJSON(t, admin, ts.URL+"/api/auth/users/"+bobID+"/unlock", nil).Body.Close()
	_ = postJSON(t, admin, ts.URL+"/api/auth/users/"+carol.ID+"/logout-all", nil).Body.Close()
	_ = deleteJSON(t, admin, ts.URL+"/api/auth/users/"+carol.ID, adminStepUpRequest{Password: testAdminPassword}).Body.Close()
	_ = postJSON(t, admin, ts.URL+"/api/auth/logout", nil).Body.Close()

	audit.mu.Lock()
	defer audit.mu.Unlock()
	seen := map[string]bool{}
	for _, e := range audit.entries {
		seen[e.Action] = true
		if !strings.Contains(e.Detail, fixtureFrom) {
			t.Errorf("%s has no address: %q", e.Action, e.Detail)
		}
	}
	for _, want := range []string{
		"user.register", "user.create", "account.totp_enabled", "account.recovery_codes_regenerated",
		"account.password_changed", "account.totp_disabled", "account.sessions_ended", "token.create",
		"token.revoke", "user.password_reset", "user.unlock", "user.sessions_ended", "user.delete",
	} {
		if !seen[want] {
			t.Errorf("the scenario wrote no %s record, so its address went unchecked", want)
		}
	}
}

// A wrong password at an in-session re-check is a user.login_failed
// record marked as a re-check, with the address; the right one writes
// nothing.
func TestRecheckWrongPasswordIsRecorded(t *testing.T) {
	g, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	audit, _, events := recordSignIns(g)

	status, _ := readAll(t, postJSON(t, bob, ts.URL+"/api/auth/totp/enrol", totpEnrolRequest{Password: "wrong-password-placeholder"}))
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong re-check password: %d", status)
	}
	failed := auditEntries(audit, "user.login_failed")
	want := auditEntry{totpBobUsername, "user.login_failed", totpBobUsername, "outcome=wrong_password method=password step=recheck " + fixtureFrom}
	if len(failed) != 1 || failed[0] != want {
		t.Errorf("records = %+v, want %+v", failed, want)
	}
	if n := len(events.all()); n != 0 {
		t.Errorf("a re-check reached the sign-in history (%d events): it is not a sign-in", n)
	}

	status, _ = readAll(t, postJSON(t, bob, ts.URL+"/api/auth/totp/enrol", totpEnrolRequest{Password: totpBobPassword}))
	if status != http.StatusOK {
		t.Fatalf("right re-check password: %d", status)
	}
	if n := len(auditEntries(audit, "user.login_failed")); n != 1 {
		t.Errorf("a right re-check password wrote a failure (%d records)", n)
	}
}

// A wrong code at the second-factor re-check is recorded the same way,
// and a re-check the limiter refuses is a rated Warn line.
func TestRecheckWrongCodeAndRefusalAreRecorded(t *testing.T) {
	g, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	_, _, _ = totpEnrolAndConfirm(t, bob, ts)
	audit, logs, _ := recordSignIns(g)
	user, _ := g.deps.Users.ByUsername(totpBobUsername)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/users/x/unlock", nil)
	if g.recheckSecondFactor(httptest.NewRecorder(), req, user, "not-a-code", "wrong", g.now()) {
		t.Fatal("a wrong code passed the re-check")
	}
	want := auditEntry{totpBobUsername, "user.login_failed", totpBobUsername, "outcome=factor_refused method=code step=recheck " + fixtureFrom}
	if failed := auditEntries(audit, "user.login_failed"); len(failed) != 1 || failed[0] != want {
		t.Errorf("records = %+v, want %+v", failed, want)
	}

	for range 10 {
		g.recheckPassword(httptest.NewRecorder(), req, user, "wrong-password-placeholder", "wrong", g.now())
	}
	lines := logLines(logs, "re-check refused")
	if len(lines) != 1 || !strings.Contains(lines[0], fixtureFrom) || !strings.Contains(lines[0], `account="bob"`) {
		t.Errorf("refused re-check lines = %q, want one naming the account and address", lines)
	}
}

// A request body over the limit leaves one rated Warn line with the
// address, however many are sent.
func TestOversizeBodyLeavesARatedWarnLine(t *testing.T) {
	g, ts, _ := totpFixture(t)
	logs := &messageRecorder{}
	g.cfg.Log = slog.New(logs)
	big := `{"username":"` + strings.Repeat("a", maxJSONBodyBytes+1) + `","password":"x"}`
	for range 3 {
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/login", strings.NewReader(big))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(csrfHeaderName, testCSRFValue)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("oversize body: %d", resp.StatusCode)
		}
	}
	lines := logLines(logs, "request body over")
	if len(lines) != 1 || !strings.Contains(lines[0], fixtureFrom) || !strings.Contains(lines[0], `"/api/auth/login"`) {
		t.Errorf("oversize lines = %q, want one with the path and address", lines)
	}
}

// The failure through a known browser's allowance that disables the
// account's sign-in writes account.disabled, as one on the ordinary
// path does.
func TestKnownBrowserDisableIsAudited(t *testing.T) {
	g, ts, clock := escalationFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	for range 9 {
		failLoginWindow(t, g, ts, clock, totpBobUsername)
	}
	audit, _, events := recordSignIns(g)
	for range 5 {
		signInFrom(t, bob, ts, totpBobUsername, "wrong-password-placeholder")
	}
	if u, _ := g.deps.Users.ByUsername(totpBobUsername); u.LoginDisabledAt.IsZero() {
		t.Fatal("precondition: the known browser's fifth failure should disable sign-in")
	}
	disabled := auditEntries(audit, "account.disabled")
	if len(disabled) != 1 || !strings.Contains(disabled[0].Detail, "from=") {
		t.Errorf("account.disabled records = %+v, want one", disabled)
	}
	got := events.all()
	if last := got[len(got)-1]; !last.Disabled || last.Outcome != gauntlet.SignInWrongPassword {
		t.Errorf("the disabling attempt's event = %+v, want Disabled", last)
	}
}
