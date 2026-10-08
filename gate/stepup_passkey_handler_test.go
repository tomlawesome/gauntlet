// Step-up with a passkey (#82 decision 6): every route that asks for the
// caller's password and a current second factor (recheckStepUp) takes
// password + assertion as an alternative to password + code, through
// POST /api/auth/step-up/passkey/begin and its own ceremony cookie, on
// the account's re-check budget.
//
// This file may import the WebAuthn library's protocol package: only
// gate's non-test code must not.
package gate

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/internal/passkeytest"
)

// passkeyStepUpFixture is a gate with the admin passkey rule on, whose
// "admin" holds a passkey and nothing else (its fake is returned), and
// "bilbo", an ordinary user, to grant admin to.
func passkeyStepUpFixture(t *testing.T) (g *Gate, ts *httptest.Server, admin *http.Client, fake *passkeytest.FakeAuthenticator, adminID, bilboID string) {
	t.Helper()
	g = adminPasskeyGate(t)
	ts = newTestServer(t, g)
	admin = registerAdminNoFactor(t, ts, "admin", doorTestPassword)
	fake = registerPasskeyWith(t, admin, ts, g, doorTestPassword)
	resp := postJSON(t, admin, ts.URL+"/api/auth/users", createUserRequest{Username: passkeyBilboUsername, Password: passkeyBilboPassword})
	if status, body := readAll(t, resp); status != http.StatusCreated {
		t.Fatalf("creating bilbo = %d %s", status, body)
	}
	u, _ := g.deps.Users.ByUsername("admin")
	return g, ts, admin, fake, u.ID, passkeyBilboID(t, g)
}

// stepUpBegin posts the step-up begin route as client.
func stepUpBegin(t *testing.T, client *http.Client, ts *httptest.Server) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+stepUpPasskeyBeginPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(csrfHeaderName, testCSRFValue)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// stepUpOptions begins a passkey step-up as client and returns the
// request options it answered.
func stepUpOptions(t *testing.T, client *http.Client, ts *httptest.Server) *protocol.CredentialAssertion {
	t.Helper()
	resp := stepUpBegin(t, client, ts)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("step-up begin = %d %s, want 200", resp.StatusCode, body)
	}
	var options protocol.CredentialAssertion
	if err := json.NewDecoder(resp.Body).Decode(&options); err != nil {
		t.Fatal(err)
	}
	return &options
}

// signStepUp signs options with fake.
func signStepUp(t *testing.T, fake *passkeytest.FakeAuthenticator, options *protocol.CredentialAssertion) json.RawMessage {
	t.Helper()
	body, err := fake.AssertionResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// grantAdmin sends the role route's grant with body.
func grantAdmin(t *testing.T, client *http.Client, ts *httptest.Server, id string, body setRoleRequest) (int, string) {
	t.Helper()
	body.Role = "admin"
	return readAll(t, doJSON(t, client, http.MethodPut, ts.URL+"/api/auth/users/"+id+"/role", body))
}

// recheckRoom is how many re-checks id's budget has left, measured by
// reserving until refused and handing every one back.
func recheckRoom(g *Gate, id string) int {
	n := 0
	for g.deps.Limiter.ReserveRecheck(id, time.Now()) {
		n++
	}
	for range n {
		g.deps.Limiter.ReleaseRecheck(id, time.Now())
	}
	return n
}

func isAdmin(g *Gate, id string) bool {
	u, ok := g.deps.Users.Get(id)
	return ok && u.Role == gauntlet.RoleAdmin
}

// A passkey-only admin grants admin with the password and a passkey,
// spending no recovery code. The begin takes nothing from the re-check
// budget; the finish reserves and hands back, as a code would; the audit
// says a passkey was used.
func TestStepUpWithAPasskeyGrantsAdmin(t *testing.T) {
	g, ts, admin, fake, adminID, bilboID := passkeyStepUpFixture(t)
	full := recheckRoom(g, adminID)

	options := stepUpOptions(t, admin, ts)
	if got := recheckRoom(g, adminID); got != full {
		t.Errorf("after begin the re-check budget has %d left, want all %d: a begin is not a re-check", got, full)
	}
	status, body := grantAdmin(t, admin, ts, bilboID, setRoleRequest{Password: doorTestPassword, Assertion: signStepUp(t, fake, options)})
	if status != http.StatusOK {
		t.Fatalf("granting admin with password and passkey = %d %s, want 200", status, body)
	}
	if !isAdmin(g, bilboID) {
		t.Error("bilbo is not an admin after a good step-up")
	}
	if got := recheckRoom(g, adminID); got != full {
		t.Errorf("after the finish the re-check budget has %d left, want all %d back", got, full)
	}
	if e := findAuditEntry(t, g, "user.role_changed"); !strings.Contains(e.Detail, "granting admin's password and passkey re-entered") {
		t.Errorf("audit detail = %q, want it to say the passkey was used", e.Detail)
	}
}

// Creating an admin and the admin's own unlock take the passkey too.
func TestStepUpWithAPasskeyCreatesAnAdminAndUnlocksTheCaller(t *testing.T) {
	g, ts, admin, fake, adminID, _ := passkeyStepUpFixture(t)

	resp := postJSON(t, admin, ts.URL+"/api/auth/users", createUserRequest{
		Username: "second", Password: "password-placeholder-6", Role: "admin",
		AdminPassword: doorTestPassword, AdminAssertion: signStepUp(t, fake, stepUpOptions(t, admin, ts)),
	})
	if status, body := readAll(t, resp); status != http.StatusCreated {
		t.Fatalf("creating an admin with password and passkey = %d %s, want 201", status, body)
	}
	if e := findAuditEntry(t, g, "user.create"); !strings.Contains(e.Detail, "password and passkey re-entered") {
		t.Errorf("audit detail = %q, want it to say the passkey was used", e.Detail)
	}

	disableAccount(t, g.deps.Users, adminID)
	status, out := unlockSelf(t, admin, ts, adminID, unlockSelfRequest{Password: doorTestPassword, Assertion: signStepUp(t, fake, stepUpOptions(t, admin, ts))})
	if status != http.StatusOK || !out.WasDisabled {
		t.Fatalf("own unlock with password and passkey = %d %+v, want 200 lifting the disable", status, out)
	}
	if u, _ := g.deps.Users.Get(adminID); !u.LoginDisabledAt.IsZero() {
		t.Error("the disable is still in force")
	}
	if e := findAuditEntry(t, g, "user.unlock"); !strings.Contains(e.Detail, "password and passkey re-entered") {
		t.Errorf("audit detail = %q, want it to say the passkey was used", e.Detail)
	}
}

// Begin refuses what cannot work: no session (401), passkeys off (404),
// a relying party that is not ready (409), a caller with no passkey
// usable here (409), and a caller with no local password (409).
func TestStepUpPasskeyBeginRefusals(t *testing.T) {
	t.Run("no session", func(t *testing.T) {
		_, ts, _, _, _, _ := passkeyStepUpFixture(t)
		wantProblem(t, stepUpBegin(t, &http.Client{}, ts), http.StatusUnauthorized, classSignInRequired)
	})
	t.Run("passkeys off", func(t *testing.T) {
		g := newTestGate(t)
		ts := newTestServer(t, g)
		admin := registerAdmin(t, ts, "admin", doorTestPassword)
		wantProblem(t, stepUpBegin(t, admin, ts), http.StatusNotFound, classNotFound)
	})
	t.Run("not ready", func(t *testing.T) {
		g, ts, admin, _, _, _ := passkeyStepUpFixture(t)
		g.cfg.AdminPasskey = AdminPasskeyOptional // the door would hold the admin otherwise
		g.deps.Passkeys = mustRelyingParty(t, "https://192.0.2.10")
		wantProblem(t, stepUpBegin(t, admin, ts), http.StatusConflict, classConflict)
	})
	t.Run("no usable passkey", func(t *testing.T) {
		g := passkeyGate(t)
		ts := newTestServer(t, g)
		admin := registerAdmin(t, ts, "admin", doorTestPassword)
		wantProblem(t, stepUpBegin(t, admin, ts), http.StatusConflict, classConflict)
	})
	t.Run("no local password", func(t *testing.T) {
		g := passkeyGate(t)
		ts := newTestServer(t, g)
		registerAdmin(t, ts, "admin", doorTestPassword)
		id, ann := ssoOnlyAdmin(t, g, ts, "subject-ann")
		resp := stepUpBegin(t, ann, ts)
		if status, body := readAll(t, resp); status != http.StatusConflict || !strings.Contains(body, "local password") {
			t.Errorf("begin by an SSO-only admin = %d %s, want 409 naming the local password", status, body)
		}
		if got := recheckRoom(g, id); got != 5 {
			t.Errorf("the 409 left %d re-checks, want all 5", got)
		}
	})
}

// A refused finish grants nothing. A wrong assertion is 401
// invalid-credentials with the route's one message and counts as a
// failed re-check (the begin's reservation is kept); a dead or missing
// ceremony is 401 step-expired and clears the cookie; code and assertion
// together are 400.
func TestStepUpPasskeyFinishRefusals(t *testing.T) {
	t.Run("both code and assertion", func(t *testing.T) {
		g, ts, admin, fake, _, bilboID := passkeyStepUpFixture(t)
		status, body := grantAdmin(t, admin, ts, bilboID, setRoleRequest{Password: doorTestPassword, Code: "123456", Assertion: signStepUp(t, fake, stepUpOptions(t, admin, ts))})
		if status != http.StatusBadRequest || !strings.Contains(body, "password, code or assertion") {
			t.Errorf("code and assertion together = %d %s, want 400 naming the fields", status, body)
		}
		if isAdmin(g, bilboID) {
			t.Error("bilbo was granted admin")
		}
	})
	t.Run("neither", func(t *testing.T) {
		_, ts, admin, _, _, bilboID := passkeyStepUpFixture(t)
		if status, body := grantAdmin(t, admin, ts, bilboID, setRoleRequest{Password: doorTestPassword}); status != http.StatusBadRequest || !strings.Contains(body, "password, code or assertion") {
			t.Errorf("no code or assertion = %d %s, want 400 naming the fields", status, body)
		}
	})
	t.Run("another account's passkey", func(t *testing.T) {
		g, ts, admin, _, adminID, bilboID := passkeyStepUpFixture(t)
		bilbo := loggedInPasskeyClient(t, ts, g)
		bilboKey := registerPasskeyWith(t, bilbo, ts, g, passkeyBilboPassword)
		full := recheckRoom(g, adminID)
		status, body := grantAdmin(t, admin, ts, bilboID, setRoleRequest{Password: doorTestPassword, Assertion: signStepUp(t, bilboKey, stepUpOptions(t, admin, ts))})
		if status != http.StatusUnauthorized || decodeProblem(t, []byte(body)).Type != problemTypeBase+classInvalidCredentials.anchor || !strings.Contains(body, "incorrect password or code") {
			t.Errorf("another account's passkey = %d %s, want 401 invalid-credentials", status, body)
		}
		if isAdmin(g, bilboID) {
			t.Error("bilbo was granted admin")
		}
		if got := recheckRoom(g, adminID); got != full-1 {
			t.Errorf("after a refused assertion the budget has %d left, want %d: it counts as a failed re-check", got, full-1)
		}
		if e := findAuditEntry(t, g, "user.login_failed"); !strings.Contains(e.Detail, "method=passkey") || !strings.Contains(e.Detail, "step=recheck") {
			t.Errorf("audit detail = %q, want a passkey re-check failure", e.Detail)
		}
	})
	t.Run("an unknown key", func(t *testing.T) {
		g, ts, admin, _, _, bilboID := passkeyStepUpFixture(t)
		stranger := newFake(g)
		if status, body := grantAdmin(t, admin, ts, bilboID, setRoleRequest{Password: doorTestPassword, Assertion: signStepUp(t, stranger, stepUpOptions(t, admin, ts))}); status != http.StatusUnauthorized {
			t.Errorf("an unregistered key = %d %s, want 401", status, body)
		}
	})
	t.Run("no ceremony", func(t *testing.T) {
		g, ts, admin, fake, _, bilboID := passkeyStepUpFixture(t)
		// Options from a begin on another client: this one carries no
		// step-up cookie.
		other := sessionClient(t, ts.URL, g.deps.Sessions.Create(passkeyAdminID(t, g), time.Now()).ID)
		assertion := signStepUp(t, fake, stepUpOptions(t, other, ts))
		status, body := grantAdmin(t, admin, ts, bilboID, setRoleRequest{Password: doorTestPassword, Assertion: assertion})
		if status != http.StatusUnauthorized || decodeProblem(t, []byte(body)).Type != problemTypeBase+classStepExpired.anchor {
			t.Errorf("no step-up cookie = %d %s, want 401 step-expired", status, body)
		}
	})
	t.Run("a dead ceremony", func(t *testing.T) {
		g, ts, admin, fake, _, bilboID := passkeyStepUpFixture(t)
		options := stepUpOptions(t, admin, ts)
		admin.Jar.SetCookies(mustParseURL(t, ts.URL+"/api/auth"), []*http.Cookie{{Name: passkeyStepUpCookieName, Value: "tampered", Path: passkeyStepUpCookiePath}})
		resp := doJSON(t, admin, http.MethodPut, ts.URL+"/api/auth/users/"+bilboID+"/role", setRoleRequest{Role: "admin", Password: doorTestPassword, Assertion: signStepUp(t, fake, options)})
		cleared := cookieCleared(resp, passkeyStepUpCookieName)
		if status, body := readAll(t, resp); status != http.StatusUnauthorized || decodeProblem(t, []byte(body)).Type != problemTypeBase+classStepExpired.anchor {
			t.Errorf("a tampered step-up cookie = %d %s, want 401 step-expired", status, body)
		}
		if !cleared {
			t.Error("the dead step-up cookie was not cleared")
		}
		if isAdmin(g, bilboID) {
			t.Error("bilbo was granted admin")
		}
	})
	t.Run("a login-step cookie", func(t *testing.T) {
		g, ts, admin, fake, _, bilboID := passkeyStepUpFixture(t)
		// A real second-step login ceremony for the same account, its
		// cookie presented to the step-up finish under its own name.
		login := startPasskeyLoginAs(t, ts, "admin", doorTestPassword)
		options := passkeyLoginFactorBegin(t, login, ts)
		sealed := ""
		for _, c := range login.Jar.Cookies(mustParseURL(t, ts.URL+passkeyAssertCookiePath)) {
			if c.Name == passkeyAssertCookieName {
				sealed = c.Value
			}
		}
		if sealed == "" {
			t.Fatal("the login step set no passkey ceremony cookie")
		}
		admin.Jar.SetCookies(mustParseURL(t, ts.URL+"/api/auth"), []*http.Cookie{{Name: passkeyAssertCookieName, Value: sealed, Path: "/api/auth"}})
		status, body := grantAdmin(t, admin, ts, bilboID, setRoleRequest{Password: doorTestPassword, Assertion: signStepUp(t, fake, options)})
		if status != http.StatusUnauthorized || decodeProblem(t, []byte(body)).Type != problemTypeBase+classStepExpired.anchor {
			t.Errorf("a login-step cookie at the step-up = %d %s, want 401 step-expired", status, body)
		}
		if isAdmin(g, bilboID) {
			t.Error("bilbo was granted admin")
		}
	})
	t.Run("clone warning", func(t *testing.T) {
		g, ts, admin, fake, _, bilboID := passkeyStepUpFixture(t)
		fake.SignCount = 5
		if status, body := grantAdmin(t, admin, ts, bilboID, setRoleRequest{Password: doorTestPassword, Assertion: signStepUp(t, fake, stepUpOptions(t, admin, ts))}); status != http.StatusOK {
			t.Fatalf("first grant = %d %s, want 200", status, body)
		}
		if status, body := readAll(t, doJSON(t, admin, http.MethodPut, ts.URL+"/api/auth/users/"+bilboID+"/role", setRoleRequest{Role: "user"})); status != http.StatusOK {
			t.Fatalf("demoting bilbo = %d %s", status, body)
		}
		fake.SignCount = 3
		status, body := grantAdmin(t, admin, ts, bilboID, setRoleRequest{Password: doorTestPassword, Assertion: signStepUp(t, fake, stepUpOptions(t, admin, ts))})
		if status != http.StatusUnauthorized || decodeProblem(t, []byte(body)).Type != problemTypeBase+classInvalidCredentials.anchor {
			t.Errorf("a regressed counter = %d %s, want 401 invalid-credentials", status, body)
		}
		if isAdmin(g, bilboID) {
			t.Error("bilbo was granted admin on a clone-suspected passkey")
		}
		findAuditEntry(t, g, "account.passkey_clone_suspected")
	})
}

// passkeyAdminID is the fixture admin's account ID.
func passkeyAdminID(t *testing.T, g *Gate) string {
	t.Helper()
	u, ok := g.deps.Users.ByUsername("admin")
	if !ok {
		t.Fatal("no admin account")
	}
	return u.ID
}

// startPasskeyLoginAs does the password step for username, whose factor
// is a passkey, and returns the client holding the pending login.
func startPasskeyLoginAs(t *testing.T, ts *httptest.Server, username, password string) *http.Client {
	t.Helper()
	client := &http.Client{Jar: mustCookieJar(t)}
	resp := postJSON(t, client, ts.URL+"/api/auth/login", credentialsRequest{Username: username, Password: password})
	if status, body := readAll(t, resp); status != http.StatusOK {
		t.Fatalf("password step = %d %s", status, body)
	}
	return client
}

// stepUpBeginRoom is how many step-up begins id's own counted bucket
// has left, measured as recheckRoom measures.
func stepUpBeginRoom(g *Gate, id string) int {
	n := 0
	for g.deps.Limiter.Reserve("passkey-stepup-begin:"+id, time.Now()) {
		n++
	}
	for range n {
		g.deps.Limiter.Release("passkey-stepup-begin:"+id, time.Now())
	}
	return n
}

// A passkey prompt that is cancelled, expires or is replaced costs no
// re-check: begins that never finish leave the budget whole, so the
// password re-check still works after as many of them as the budget
// holds (docs/design.md, "One rule for every budget").
func TestStepUpPasskeyBeginsDoNotSpendTheRecheckBudget(t *testing.T) {
	g, ts, admin, _, adminID, _ := passkeyStepUpFixture(t)
	full := recheckRoom(g, adminID)
	for range full {
		stepUpOptions(t, admin, ts)
	}
	if got := recheckRoom(g, adminID); got != full {
		t.Fatalf("after %d unfinished begins the re-check budget has %d left, want all %d", full, got, full)
	}
	resp := postJSON(t, admin, ts.URL+passkeyRegisterBeginPath, passkeyRegisterBeginRequest{Password: doorTestPassword})
	if status, body := readAll(t, resp); status != http.StatusOK {
		t.Errorf("a password re-check after the begins = %d %s, want 200", status, body)
	}
}

// Begins are bounded on a counted bucket of their own: past the limit
// they are 429, and a successful step-up does not refund them.
func TestStepUpPasskeyBeginsAreBoundedAndNeverRefunded(t *testing.T) {
	g, ts, admin, fake, adminID, bilboID := passkeyStepUpFixture(t)
	limit := stepUpBeginRoom(g, adminID)
	var options *protocol.CredentialAssertion
	for range limit {
		options = stepUpOptions(t, admin, ts)
	}
	wantProblem(t, stepUpBegin(t, admin, ts), http.StatusTooManyRequests, classRateLimited)

	if status, body := grantAdmin(t, admin, ts, bilboID, setRoleRequest{Password: doorTestPassword, Assertion: signStepUp(t, fake, options)}); status != http.StatusOK {
		t.Fatalf("granting admin with the last begin's passkey = %d %s, want 200", status, body)
	}
	wantProblem(t, stepUpBegin(t, admin, ts), http.StatusTooManyRequests, classRateLimited)
}

// A dead or missing ceremony checks nothing, so it is not a failed
// guess: the re-check budget is left whole.
func TestStepUpPasskeyStepExpiredDoesNotCount(t *testing.T) {
	g, ts, admin, fake, adminID, bilboID := passkeyStepUpFixture(t)
	full := recheckRoom(g, adminID)
	options := stepUpOptions(t, admin, ts)
	admin.Jar.SetCookies(mustParseURL(t, ts.URL+"/api/auth"), []*http.Cookie{{Name: passkeyStepUpCookieName, Value: "tampered", Path: passkeyStepUpCookiePath}})
	if status, body := grantAdmin(t, admin, ts, bilboID, setRoleRequest{Password: doorTestPassword, Assertion: signStepUp(t, fake, options)}); status != http.StatusUnauthorized {
		t.Fatalf("a dead ceremony = %d %s, want 401", status, body)
	}
	if got := recheckRoom(g, adminID); got != full {
		t.Errorf("after a dead ceremony the re-check budget has %d left, want all %d", got, full)
	}
}
