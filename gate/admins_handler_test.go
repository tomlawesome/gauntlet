package gate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/tomlawesome/gauntlet"
)

// Several admins (#67, ADR-0010) and the role route (#75): granting
// admin needs the granting admin's password and a current second factor
// on the same request; the last admin cannot be demoted or deleted; a
// downgrade ends the account's sessions; each change is audited and
// noticed.

// adminsFixture is a gate whose admin "admin" holds an authenticator app
// and recovery codes -- spent one a step-up, so each request carries a
// fresh code -- and an ordinary user "bob" with a live, factor-holding
// session.
type adminsFixture struct {
	g        *Gate
	ts       *httptest.Server
	admin    *http.Client
	adminID  string
	bobID    string
	bob      *http.Client
	notices  *noticeRecorder
	recovery []string
	secret   []byte
	counter  uint64
	// bobSecret and bobCounter are bob's own authenticator app, for a
	// test that signs him in again after his sessions were ended: a
	// further code is generated at bobCounter+1.
	bobSecret  []byte
	bobCounter uint64
}

func newAdminsFixture(t *testing.T) *adminsFixture {
	t.Helper()
	g := newTestGate(t)
	g.cfg.Audit = &auditRecorder{}
	rec := &noticeRecorder{}
	g.cfg.Notices = rec
	ts := newTestServer(t, g)
	f := &adminsFixture{g: g, ts: ts, notices: rec}
	f.admin = registerAdminNoFactor(t, ts, "admin", selfUnlockAdminPassword)
	f.secret, f.recovery, f.counter = enrolAdminTOTP(t, f.admin, ts)
	u, _ := g.deps.Users.ByUsername("admin")
	f.adminID = u.ID
	_ = postJSON(t, f.admin, ts.URL+"/api/auth/users",
		createUserRequest{Username: totpBobUsername, Password: totpBobPassword, Role: "user"}).Body.Close()
	f.bobID = totpBobID(t, g)
	f.bob = loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	f.bobSecret, _, f.bobCounter = totpEnrolAndConfirm(t, f.bob, ts)
	return f
}

// code is the next unused recovery code.
func (f *adminsFixture) code() string {
	c := f.recovery[0]
	f.recovery = f.recovery[1:]
	return c
}

func (f *adminsFixture) setRole(t *testing.T, client *http.Client, id string, body any) (int, string) {
	t.Helper()
	return readAll(t, doJSON(t, client, http.MethodPut, f.ts.URL+"/api/auth/users/"+id+"/role", body))
}

// grantBob makes bob an admin with a valid step-up.
func (f *adminsFixture) grantBob(t *testing.T) {
	t.Helper()
	status, body := f.setRole(t, f.admin, f.bobID, setRoleRequest{Role: "admin", Password: selfUnlockAdminPassword, Code: f.code()})
	if status != http.StatusOK {
		t.Fatalf("granting bob admin = %d %s", status, body)
	}
}

func roleOf(t *testing.T, g *Gate, id string) gauntlet.Role {
	t.Helper()
	u, ok := g.deps.Users.Get(id)
	if !ok {
		t.Fatalf("no account %s", id)
	}
	return u.Role
}

func adminProblemType(t *testing.T, body string) string {
	t.Helper()
	return decodeProblem(t, []byte(body)).Type
}

func TestCreateAdminNeedsTheCallersPasswordAndASecondFactor(t *testing.T) {
	f := newAdminsFixture(t)
	create := func(body createUserRequest) (int, string) {
		t.Helper()
		return readAll(t, postJSON(t, f.admin, f.ts.URL+"/api/auth/users", body))
	}
	base := createUserRequest{Username: "second", Password: "password456", Role: "admin"}

	missing := base // the session alone
	if status, _ := create(missing); status != http.StatusBadRequest {
		t.Errorf("no step-up = %d, want 400", status)
	}
	noCode := base
	noCode.AdminPassword = selfUnlockAdminPassword
	if status, _ := create(noCode); status != http.StatusBadRequest {
		t.Errorf("no code = %d, want 400", status)
	}
	wrongPassword := base
	wrongPassword.AdminPassword, wrongPassword.AdminCode = "wrong-password-placeholder", f.code()
	if status, body := create(wrongPassword); status != http.StatusUnauthorized || adminProblemType(t, body) != problemTypeBase+"invalid-credentials" {
		t.Errorf("wrong password = %d %s, want 401 invalid-credentials", status, body)
	}
	wrongCode := base
	wrongCode.AdminPassword, wrongCode.AdminCode = selfUnlockAdminPassword, wrongTOTPCode(f.secret, f.g.now())
	if status, _ := create(wrongCode); status != http.StatusUnauthorized {
		t.Errorf("wrong code = %d, want 401", status)
	}
	if _, ok := f.g.deps.Users.ByUsername("second"); ok {
		t.Fatal("a refused step-up created the account anyway")
	}

	// A TOTP code works as well as a recovery code.
	good := base
	good.AdminPassword, good.AdminCode = selfUnlockAdminPassword, gauntlet.GenerateTOTPCode(f.secret, f.counter+1)
	if status, body := create(good); status != http.StatusCreated {
		t.Fatalf("create admin with step-up = %d %s, want 201", status, body)
	}
	if u, _ := f.g.deps.Users.ByUsername("second"); u == nil || u.Role != gauntlet.RoleAdmin {
		t.Fatalf("second = %+v, want an admin", u)
	}
	if n := len(f.g.deps.Users.Admins()); n != 2 {
		t.Errorf("%d admins, want 2", n)
	}

	e := findAuditEntry(t, f.g, "user.create")
	if e.Actor != "admin" || e.Target != "second" || !strings.Contains(e.Detail, "role=admin") {
		t.Errorf("audit = %+v", e)
	}
	n := lastNotice(t, f.g, f.notices, NoticeRoleChanged)
	if n.Username != "second" || n.Role != gauntlet.RoleAdmin || n.By != "admin" ||
		n.RoleChanged == nil || n.RoleChanged.From != "" || n.RoleChanged.To != gauntlet.RoleAdmin {
		t.Errorf("notice = %+v", n)
	}
}

// The new account's username and password are checked before the
// step-up, so a typo in either does not spend the recovery code that
// came with it: the same code still creates the admin afterwards.
func TestCreateAdminRefusesABadAccountBeforeSpendingACode(t *testing.T) {
	f := newAdminsFixture(t)
	code := f.code()
	create := func(username, password string) (int, string) {
		t.Helper()
		return readAll(t, postJSON(t, f.admin, f.ts.URL+"/api/auth/users", createUserRequest{
			Username: username, Password: password, Role: "admin",
			AdminPassword: selfUnlockAdminPassword, AdminCode: code,
		}))
	}

	if status, body := create(totpBobUsername, "short"); status != http.StatusBadRequest {
		t.Errorf("a taken username with a too-short password = %d %s, want 400", status, body)
	}
	if status, body := create(totpBobUsername, "password456"); status != http.StatusConflict {
		t.Errorf("a taken username = %d %s, want 409", status, body)
	}
	if status, body := create("second", "password456"); status != http.StatusCreated {
		t.Errorf("creating the admin with the same recovery code = %d %s, want 201 -- the refusals spent it", status, body)
	}
}

// A user or viewer needs no step-up, and the extra fields are not
// read for them.
func TestCreateNonAdminNeedsNoStepUp(t *testing.T) {
	f := newAdminsFixture(t)
	for _, role := range []string{"user", "viewer"} {
		status, body := readAll(t, postJSON(t, f.admin, f.ts.URL+"/api/auth/users",
			createUserRequest{Username: "new-" + role, Password: "password456", Role: role}))
		if status != http.StatusCreated {
			t.Errorf("create %s = %d %s, want 201", role, status, body)
		}
	}
}

func TestSetRoleGrantNeedsStepUp(t *testing.T) {
	f := newAdminsFixture(t)
	cases := []struct {
		name string
		body setRoleRequest
		want int
	}{
		{"the session alone", setRoleRequest{Role: "admin"}, http.StatusBadRequest},
		{"no code", setRoleRequest{Role: "admin", Password: selfUnlockAdminPassword}, http.StatusBadRequest},
		{"no password", setRoleRequest{Role: "admin", Code: f.recovery[1]}, http.StatusBadRequest},
		{"wrong password", setRoleRequest{Role: "admin", Password: "wrong-password-placeholder", Code: f.recovery[1]}, http.StatusUnauthorized},
		{"wrong code", setRoleRequest{Role: "admin", Password: selfUnlockAdminPassword, Code: wrongTOTPCode(f.secret, f.g.now())}, http.StatusUnauthorized},
	}
	for _, c := range cases {
		if status, body := f.setRole(t, f.admin, f.bobID, c.body); status != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, status, body, c.want)
		}
		if r := roleOf(t, f.g, f.bobID); r != gauntlet.RoleUser {
			t.Fatalf("%s: bob's role is %q, want user still", c.name, r)
		}
	}
	// The recovery code in the refused requests above was never spent
	// (the password was checked first or the request was incomplete).
	status, body := f.setRole(t, f.admin, f.bobID, setRoleRequest{Role: "admin", Password: selfUnlockAdminPassword, Code: f.recovery[1]})
	if status != http.StatusOK {
		t.Fatalf("grant with password and code = %d %s, want 200", status, body)
	}
	var out setRoleResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out != (setRoleResponse{Username: totpBobUsername, From: "user", To: "admin"}) {
		t.Errorf("response = %+v", out)
	}
	if r := roleOf(t, f.g, f.bobID); r != gauntlet.RoleAdmin {
		t.Errorf("bob's role = %q, want admin", r)
	}
	u, _ := f.g.deps.Users.Get(f.bobID)
	if u.RoleChangedAt.IsZero() {
		t.Error("RoleChangedAt was not written")
	}

	e := findAuditEntry(t, f.g, "user.role_changed")
	if e.Actor != "admin" || e.Target != totpBobUsername || !strings.Contains(e.Detail, "from=user to=admin") {
		t.Errorf("audit = %+v", e)
	}
	n := lastNotice(t, f.g, f.notices, NoticeRoleChanged)
	if n.UserID != f.bobID || n.By != "admin" || n.RoleChanged == nil ||
		n.RoleChanged.From != gauntlet.RoleUser || n.RoleChanged.To != gauntlet.RoleAdmin {
		t.Errorf("notice = %+v", n)
	}
}

// A grant ends nothing: bob's session carries on, now as an admin.
func TestSetRoleGrantKeepsTheAccountsSessions(t *testing.T) {
	f := newAdminsFixture(t)
	f.grantBob(t)
	if status, _ := listSessions(t, f.bob, f.ts); status != http.StatusOK {
		t.Errorf("bob's session after a grant: %d, want 200", status)
	}
}

func TestSetRoleDowngradeEndsTheAccountsSessions(t *testing.T) {
	for _, c := range []struct {
		name     string
		from, to string
	}{
		{"admin to user", "admin", "user"},
		{"admin to viewer", "admin", "viewer"},
		{"user to viewer", "user", "viewer"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newAdminsFixture(t)
			if c.from == "admin" {
				f.grantBob(t)
			}
			status, body := f.setRole(t, f.admin, f.bobID, setRoleRequest{Role: c.to})
			if status != http.StatusOK {
				t.Fatalf("%s = %d %s, want 200 with no step-up", c.name, status, body)
			}
			var out setRoleResponse
			_ = json.Unmarshal([]byte(body), &out)
			if !out.SessionsEnded || out.From != c.from || out.To != c.to {
				t.Errorf("response = %+v", out)
			}
			requireSignedIn(t, f.ts, []*http.Client{f.bob}, false)
			// The account's record carries the cutoff too, so the end
			// holds in another process.
			if u, _ := f.g.deps.Users.Get(f.bobID); u.SessionsEndedAt.IsZero() {
				t.Error("SessionsEndedAt was not recorded")
			}
			if status, _ := listSessions(t, f.admin, f.ts); status != http.StatusOK {
				t.Error("the acting admin's own session ended")
			}
			e := findAuditEntry(t, f.g, "user.role_changed")
			if e.Actor != "admin" || !strings.Contains(e.Detail, "from="+c.from+" to="+c.to) {
				t.Errorf("audit = %+v", e)
			}
			n := lastNotice(t, f.g, f.notices, NoticeRoleChanged)
			if n.RoleChanged == nil || string(n.RoleChanged.From) != c.from || string(n.RoleChanged.To) != c.to {
				t.Errorf("notice = %+v", n)
			}
		})
	}
}

// user -> viewer -> user, no step-up for either; an upgrade to user does
// not end sessions.
func TestSetRoleUserViewerNeedsNoStepUp(t *testing.T) {
	f := newAdminsFixture(t)
	if status, body := f.setRole(t, f.admin, f.bobID, setRoleRequest{Role: "viewer"}); status != http.StatusOK {
		t.Fatalf("user to viewer = %d %s", status, body)
	}
	// The demotion ended bob's sessions. Sign him in again, through his
	// authenticator app: this is the live session the promotion must leave
	// alone. (A password-only sign-in would stop at the second-factor step
	// and hold no session at all.)
	bob := startTOTPLogin(t, f.ts, totpBobUsername, totpBobPassword)
	resp := submitLoginFactor(t, bob, f.ts, gauntlet.GenerateTOTPCode(f.bobSecret, f.bobCounter+1))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bob's second-factor sign-in as a viewer = %d", resp.StatusCode)
	}
	requireSignedIn(t, f.ts, []*http.Client{bob}, true)
	endedBefore, _ := f.g.deps.Users.Get(f.bobID)

	status, body := f.setRole(t, f.admin, f.bobID, setRoleRequest{Role: "user"})
	if status != http.StatusOK {
		t.Fatalf("viewer to user = %d %s", status, body)
	}
	var promoted setRoleResponse
	_ = json.Unmarshal([]byte(body), &promoted)
	if promoted.SessionsEnded || promoted.From != "viewer" || promoted.To != "user" {
		t.Errorf("response = %+v, want an upgrade that ends nothing", promoted)
	}
	requireSignedIn(t, f.ts, []*http.Client{bob}, true)
	if u, _ := f.g.deps.Users.Get(f.bobID); !u.SessionsEndedAt.Equal(endedBefore.SessionsEndedAt) {
		t.Errorf("SessionsEndedAt moved from %v to %v on an upgrade", endedBefore.SessionsEndedAt, u.SessionsEndedAt)
	}

	var out setRoleResponse
	_, body = f.setRole(t, f.admin, f.bobID, setRoleRequest{Role: "viewer"})
	_ = json.Unmarshal([]byte(body), &out)
	if out.From != "user" {
		t.Errorf("from = %q, want user", out.From)
	}
}

func TestSetRoleRefusals(t *testing.T) {
	f := newAdminsFixture(t)

	if status, body := f.setRole(t, f.admin, f.bobID, setRoleRequest{Role: "owner"}); status != http.StatusBadRequest {
		t.Errorf("unknown role = %d %s, want 400", status, body)
	}
	if status, body := f.setRole(t, f.admin, f.bobID, setRoleRequest{}); status != http.StatusBadRequest {
		t.Errorf("empty role = %d %s, want 400", status, body)
	}
	if status, body := f.setRole(t, f.admin, "no-such-id", setRoleRequest{Role: "user"}); status != http.StatusNotFound {
		t.Errorf("unknown account = %d %s, want 404", status, body)
	}
	// Already that role: 409 before any step-up is asked for.
	status, body := f.setRole(t, f.admin, f.bobID, setRoleRequest{Role: "user"})
	if status != http.StatusConflict || adminProblemType(t, body) != problemTypeBase+"conflict" {
		t.Errorf("same role = %d %s, want 409 conflict", status, body)
	}
	status, body = f.setRole(t, f.admin, f.adminID, setRoleRequest{Role: "admin"})
	if status != http.StatusConflict {
		t.Errorf("admin to admin without step-up = %d %s, want 409", status, body)
	}
	if status, _ := readAll(t, doJSON(t, f.admin, http.MethodPut, f.ts.URL+"/api/auth/users/"+f.bobID+"/role", "{")); status != http.StatusBadRequest {
		t.Errorf("a bad body = %d, want 400", status)
	}
	// An unknown field is refused, not ignored.
	if status, _ := readAll(t, doJSON(t, f.admin, http.MethodPut, f.ts.URL+"/api/auth/users/"+f.bobID+"/role",
		map[string]any{"role": "viewer", "extra": 1})); status != http.StatusBadRequest {
		t.Errorf("an unknown field = %d, want 400", status)
	}
	if r := roleOf(t, f.g, f.bobID); r != gauntlet.RoleUser {
		t.Errorf("bob's role = %q after refusals, want user", r)
	}
}

func TestSetRoleIsAdminOnly(t *testing.T) {
	f := newAdminsFixture(t)
	// bob is a user: refused whatever he asks for, himself included.
	status, body := f.setRole(t, f.bob, f.bobID, setRoleRequest{Role: "admin", Password: totpBobPassword, Code: "000000"})
	if status != http.StatusForbidden {
		t.Errorf("a user asking for admin = %d %s, want 403", status, body)
	}
	if r := roleOf(t, f.g, f.bobID); r != gauntlet.RoleUser {
		t.Errorf("bob's role = %q", r)
	}
}

func TestLastAdminCannotBeDemotedOrDeleted(t *testing.T) {
	f := newAdminsFixture(t)

	status, body := f.setRole(t, f.admin, f.adminID, setRoleRequest{Role: "user"})
	if status != http.StatusConflict || adminProblemType(t, body) != problemTypeBase+"last-admin" {
		t.Errorf("demoting the last admin = %d %s, want 409 last-admin", status, body)
	}
	status, body = f.setRole(t, f.admin, f.adminID, setRoleRequest{Role: "viewer"})
	if status != http.StatusConflict || adminProblemType(t, body) != problemTypeBase+"last-admin" {
		t.Errorf("demoting the last admin to viewer = %d %s, want 409 last-admin", status, body)
	}
	req, _ := http.NewRequest(http.MethodDelete, f.ts.URL+"/api/auth/users/"+f.adminID, strings.NewReader(`{"password":"`+testAdminPassword+`"}`))
	req.Header.Set(csrfHeaderName, testCSRFValue)
	resp, err := f.admin.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	status, body = readAll(t, resp)
	if status != http.StatusConflict || adminProblemType(t, body) != problemTypeBase+"last-admin" {
		t.Errorf("deleting the last admin = %d %s, want 409 last-admin", status, body)
	}
	if !strings.Contains(body, "last admin account cannot be deleted") {
		t.Errorf("message = %s", body)
	}
	if r := roleOf(t, f.g, f.adminID); r != gauntlet.RoleAdmin {
		t.Errorf("the last admin's role = %q", r)
	}
	if status, _ := listSessions(t, f.admin, f.ts); status != http.StatusOK {
		t.Error("the refused change ended the last admin's session")
	}
}

// The last admin with a local password cannot be demoted while the
// other admins sign in only through SSO (#79): 409 last-admin, with a
// message saying what to do instead -- whether it demotes itself or an
// SSO-only admin, who needs no step-up to demote, tries. (Deleting it
// over HTTP cannot get that far: the only admin able to pass the
// delete's step-up is itself, and nobody deletes their own account.
// The store's own test covers the delete.)
func TestLastLocalAdminCannotBeDemoted(t *testing.T) {
	f := newAdminsFixture(t)
	_, ann := ssoOnlyAdmin(t, f.g, f.ts, "subject-ann")

	for name, client := range map[string]*http.Client{"itself": f.admin, "an SSO-only admin": ann} {
		status, body := f.setRole(t, client, f.adminID, setRoleRequest{Role: "user"})
		if status != http.StatusConflict || adminProblemType(t, body) != problemTypeBase+"last-admin" {
			t.Errorf("%s demoting the last admin with a password = %d %s, want 409 last-admin", name, status, body)
		}
		if !strings.Contains(body, "local password") {
			t.Errorf("message = %s", body)
		}
	}
	if r := roleOf(t, f.g, f.adminID); r != gauntlet.RoleAdmin {
		t.Errorf("admin's role = %q, want admin", r)
	}
}

func TestAdminMayDemoteThemselvesWhenAnotherAdminExists(t *testing.T) {
	f := newAdminsFixture(t)
	f.grantBob(t)

	status, body := f.setRole(t, f.admin, f.adminID, setRoleRequest{Role: "user"})
	if status != http.StatusOK {
		t.Fatalf("self-demote with another admin = %d %s, want 200", status, body)
	}
	if r := roleOf(t, f.g, f.adminID); r != gauntlet.RoleUser {
		t.Errorf("admin's role = %q, want user", r)
	}
	// Their own sessions end like anyone's downgrade.
	if status, _ := listSessions(t, f.admin, f.ts); status != http.StatusUnauthorized {
		t.Errorf("the demoted admin's session = %d, want 401", status)
	}
	// And now bob is the last admin.
	status, body = f.setRole(t, f.bob, f.bobID, setRoleRequest{Role: "user"})
	if status != http.StatusConflict || adminProblemType(t, body) != problemTypeBase+"last-admin" {
		t.Errorf("bob demoting himself as the last admin = %d %s, want 409 last-admin", status, body)
	}
}

func TestAdminMayDeleteAnotherAdminButNotThemselves(t *testing.T) {
	f := newAdminsFixture(t)
	f.grantBob(t)
	del := func(id string) (int, string) {
		req, _ := http.NewRequest(http.MethodDelete, f.ts.URL+"/api/auth/users/"+id, strings.NewReader(`{"password":"`+testAdminPassword+`"}`))
		req.Header.Set(csrfHeaderName, testCSRFValue)
		resp, err := f.admin.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return readAll(t, resp)
	}
	status, body := del(f.adminID)
	if status != http.StatusConflict || adminProblemType(t, body) != problemTypeBase+"conflict" {
		t.Errorf("deleting your own account = %d %s, want 409 conflict", status, body)
	}
	if status, body := del(f.bobID); status != http.StatusOK {
		t.Errorf("deleting another admin = %d %s, want 200", status, body)
	}
	if _, ok := f.g.deps.Users.Get(f.bobID); ok {
		t.Error("bob is still there")
	}
}

// Step-up guesses count on the account's re-check budget, as every other
// re-check does.
func TestSetRoleStepUpGuessesCountOnTheRecheckBudget(t *testing.T) {
	f := newAdminsFixture(t)
	wrong := wrongTOTPCode(f.secret, f.g.now())
	for i := range 5 {
		status, _ := f.setRole(t, f.admin, f.bobID, setRoleRequest{Role: "admin", Password: selfUnlockAdminPassword, Code: wrong})
		if status != http.StatusUnauthorized {
			t.Fatalf("guess %d = %d, want 401", i+1, status)
		}
	}
	status, _ := f.setRole(t, f.admin, f.bobID, setRoleRequest{Role: "admin", Password: selfUnlockAdminPassword, Code: f.code()})
	if status != http.StatusTooManyRequests {
		t.Errorf("the right pair after five wrong guesses = %d, want 429", status)
	}
	if r := roleOf(t, f.g, f.bobID); r != gauntlet.RoleUser {
		t.Errorf("bob's role = %q, want user", r)
	}
}

// Two admins demoting each other at once, over HTTP, end with exactly
// one admin.
func TestConcurrentDemotesOverHTTPLeaveOneAdmin(t *testing.T) {
	f := newAdminsFixture(t)
	f.grantBob(t)

	var wg sync.WaitGroup
	start := make(chan struct{})
	statuses := make([]int, 2)
	for i, c := range []struct {
		client *http.Client
		target string
	}{{f.admin, f.bobID}, {f.bob, f.adminID}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			statuses[i], _ = f.setRole(t, c.client, c.target, setRoleRequest{Role: "user"})
		}()
	}
	close(start)
	wg.Wait()

	if n := len(f.g.deps.Users.Admins()); n != 1 {
		t.Fatalf("%d admins after two admins demoted each other at once (statuses %v), want 1", n, statuses)
	}
}

// The role route and an admin created over HTTP reach a second admin who
// can do admin things: list accounts.
func TestSecondAdminReachesAdminRoutes(t *testing.T) {
	f := newAdminsFixture(t)
	f.grantBob(t)
	resp, err := f.bob.Get(f.ts.URL + "/api/auth/users")
	if err != nil {
		t.Fatal(err)
	}
	if status, body := readAll(t, resp); status != http.StatusOK {
		t.Errorf("a granted admin listing accounts = %d %s, want 200", status, body)
	}
}

// -- Promotion under the admin passkey rule (#82) -----------------------

// newAdminPasskeyFixture is newAdminsFixture on a gate with a ready
// relying party, where "admin" also holds a passkey, and then the admin
// passkey rule turned on -- so admin is past the door and bob, a user
// with only an authenticator app, is not an admin yet.
func newAdminPasskeyFixture(t *testing.T) *adminsFixture {
	t.Helper()
	f := newAdminsFixture(t)
	f.g.deps.Passkeys = mustRelyingParty(t, passkeyTestPublicURL)
	registerPasskeyWith(t, f.admin, f.ts, f.g, selfUnlockAdminPassword)
	f.g.cfg.AdminPasskey = AdminPasskeyRequired
	return f
}

// heldInList is the users list's heldForPasskey for each username, as
// the admin reads it; absent means the member was missing.
func (f *adminsFixture) heldInList(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	resp, err := f.admin.Get(f.ts.URL + "/api/auth/users")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var rows []map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	out := map[string]json.RawMessage{}
	for _, row := range rows {
		var name string
		_ = json.Unmarshal(row["username"], &name)
		out[name] = row["heldForPasskey"]
	}
	return out
}

func heldField(t *testing.T, body string) string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("decoding %s: %v", body, err)
	}
	return string(m["heldForPasskey"])
}

// Granting admin to an account with no passkey grants it, says so
// (heldForPasskey, the audit detail, the users list), and holds the
// account at the passkey door from its next request. Demoting it
// releases it.
func TestGrantingAdminHoldsTheAccountForAPasskey(t *testing.T) {
	f := newAdminPasskeyFixture(t)
	status, body := f.setRole(t, f.admin, f.bobID, setRoleRequest{Role: "admin", Password: selfUnlockAdminPassword, Code: f.code()})
	if status != http.StatusOK || heldField(t, body) != "true" {
		t.Fatalf("granting bob admin = %d %s, want 200 with heldForPasskey true", status, body)
	}
	if e := findAuditEntry(t, f.g, "user.role_changed"); !strings.Contains(e.Detail, "; held for a passkey") {
		t.Errorf("audit detail = %q, want it to say the account is held for a passkey", e.Detail)
	}
	wantDoor(t, f.bob, f.ts, "/api/protected", authGateMustEnrolPasskey, "no passkey")
	if held := f.heldInList(t); string(held[totpBobUsername]) != "true" || string(held["admin"]) != "false" {
		t.Errorf("users list heldForPasskey = %s, want bob true and admin false", held)
	}

	status, body = f.setRole(t, f.admin, f.bobID, setRoleRequest{Role: "user"})
	if status != http.StatusOK || heldField(t, body) != "false" {
		t.Fatalf("demoting bob = %d %s, want 200 with heldForPasskey false", status, body)
	}
	if e := findAuditEntry(t, f.g, "user.role_changed"); strings.Contains(e.Detail, "held for a passkey") {
		t.Errorf("demotion audit detail = %q, want no hold", e.Detail)
	}
	bob := sessionClient(t, f.ts.URL, f.g.deps.Sessions.Create(f.bobID, f.g.now()).ID) // the demotion ended bob's sessions
	wantThrough(t, bob, f.ts, "/api/protected")
	if held := f.heldInList(t); string(held[totpBobUsername]) != "false" {
		t.Errorf("users list heldForPasskey for a demoted bob = %s, want false", held[totpBobUsername])
	}
}

// An account that already holds a usable passkey is granted admin and
// not held.
func TestGrantingAdminToAnAccountWithAPasskeyHoldsNothing(t *testing.T) {
	f := newAdminPasskeyFixture(t)
	registerPasskeyWith(t, f.bob, f.ts, f.g, totpBobPassword)
	status, body := f.setRole(t, f.admin, f.bobID, setRoleRequest{Role: "admin", Password: selfUnlockAdminPassword, Code: f.code()})
	if status != http.StatusOK || heldField(t, body) != "false" {
		t.Fatalf("granting bob admin = %d %s, want 200 with heldForPasskey false", status, body)
	}
	if e := findAuditEntry(t, f.g, "user.role_changed"); strings.Contains(e.Detail, "held for a passkey") {
		t.Errorf("audit detail = %q, want no hold", e.Detail)
	}
	wantThrough(t, f.bob, f.ts, "/api/protected")
}

// Creating an admin creates it held: a new account holds no passkey.
// A user created beside it is not held, and with the rule optional
// nothing is.
func TestCreatingAnAdminHoldsItForAPasskey(t *testing.T) {
	f := newAdminPasskeyFixture(t)
	create := func(body createUserRequest) (int, string) {
		t.Helper()
		return readAll(t, postJSON(t, f.admin, f.ts.URL+"/api/auth/users", body))
	}
	status, body := create(createUserRequest{Username: "second", Password: "password456", Role: "admin", AdminPassword: selfUnlockAdminPassword, AdminCode: f.code()})
	if status != http.StatusCreated || heldField(t, body) != "true" {
		t.Fatalf("creating an admin = %d %s, want 201 with heldForPasskey true", status, body)
	}
	if e := findAuditEntry(t, f.g, "user.create"); !strings.Contains(e.Detail, "; held for a passkey") {
		t.Errorf("audit detail = %q, want it to say the account is held for a passkey", e.Detail)
	}
	if held := f.heldInList(t); string(held["second"]) != "true" {
		t.Errorf("users list heldForPasskey for second = %s, want true", held["second"])
	}
	status, body = create(createUserRequest{Username: "third", Password: "password789"})
	if status != http.StatusCreated || heldField(t, body) != "false" {
		t.Errorf("creating a user = %d %s, want 201 with heldForPasskey false", status, body)
	}

	f.g.cfg.AdminPasskey = AdminPasskeyOptional
	status, body = create(createUserRequest{Username: "fourth", Password: "password-placeholder-4", Role: "admin", AdminPassword: selfUnlockAdminPassword, AdminCode: f.code()})
	if status != http.StatusCreated || heldField(t, body) != "false" {
		t.Errorf("creating an admin with the rule optional = %d %s, want 201 with heldForPasskey false", status, body)
	}
	if e := findAuditEntry(t, f.g, "user.create"); strings.Contains(e.Detail, "held for a passkey") {
		t.Errorf("audit detail with the rule optional = %q, want no hold", e.Detail)
	}
	if held := f.heldInList(t); string(held["second"]) != "false" {
		t.Errorf("users list heldForPasskey with the rule optional = %s, want false", held["second"])
	}
}
