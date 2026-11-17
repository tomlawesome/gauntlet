// Ported from mikroview's internal/api/auth_test.go: the account-admin
// cases that fall inside G6 stage 1.
package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/persist"
)

func TestAdminCanCreateAdditionalUsers(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password-placeholder-1")

	resp := postJSON(t, client, ts.URL+"/api/auth/users", createUserRequest{Username: "operator", Password: "password456", Role: "user"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected an admin to be able to create an additional user, got %d", resp.StatusCode)
	}
}

func TestAdminCanCreateViewerAndSessionReportsIt(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	adminClient := registerAdmin(t, ts, "admin", "password-placeholder-1")

	resp := postJSON(t, adminClient, ts.URL+"/api/auth/users", createUserRequest{Username: "watcher", Password: "password456", Role: "viewer"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected an admin to be able to create a viewer, got %d", resp.StatusCode)
	}

	viewerClient := &http.Client{Jar: mustCookieJar(t)}
	_ = postJSON(t, viewerClient, ts.URL+"/api/auth/login", credentialsRequest{Username: "watcher", Password: "password456"}).Body.Close()

	sessResp, err := viewerClient.Get(ts.URL + "/api/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sessResp.Body.Close() }()
	var body sessionResponse
	_ = json.NewDecoder(sessResp.Body).Decode(&body)
	if !body.Authenticated || body.Role != string(gauntlet.RoleViewer) {
		t.Errorf("expected an authenticated viewer session reporting role %q, got %+v", gauntlet.RoleViewer, body)
	}
}

func TestCreateUserDefaultsToUserRole(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	adminClient := registerAdmin(t, ts, "admin", "password-placeholder-1")

	resp := postJSON(t, adminClient, ts.URL+"/api/auth/users", createUserRequest{Username: "operator", Password: "password456"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected creation with no role field to succeed, got %d", resp.StatusCode)
	}

	u, ok := g.deps.Users.ByUsername("operator")
	if !ok {
		t.Fatal("expected the account to exist")
	}
	if u.Role != gauntlet.RoleUser {
		t.Errorf("expected an empty role field to default to RoleUser, got %v", u.Role)
	}
}

func TestCreateUserRejectsUnrecognizedRole(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	adminClient := registerAdmin(t, ts, "admin", "password-placeholder-1")

	resp := postJSON(t, adminClient, ts.URL+"/api/auth/users", createUserRequest{Username: "someone", Password: "password456", Role: "owner"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for an unrecognized role, got %d", resp.StatusCode)
	}
	if _, ok := g.deps.Users.ByUsername("someone"); ok {
		t.Error("expected the account to not have been created")
	}
}

func TestAdminCreateUserRejectsDuplicateUsername(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password-placeholder-1")
	_ = postJSON(t, client, ts.URL+"/api/auth/users", createUserRequest{Username: "operator", Password: "password456", Role: "user"}).Body.Close()

	resp := postJSON(t, client, ts.URL+"/api/auth/users", createUserRequest{Username: "operator", Password: "password789", Role: "user"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("expected 409 for a duplicate username, got %d", resp.StatusCode)
	}
}

func TestAdminCreatingAnAdminWithoutStepUpIsRefused(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password-placeholder-1")

	resp := postJSON(t, client, ts.URL+"/api/auth/users", createUserRequest{Username: "second", Password: "password456", Role: "admin"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for an admin-role request with no step-up, got %d", resp.StatusCode)
	}
	if _, ok := g.deps.Users.ByUsername("second"); ok {
		t.Error("a refused admin-role request created the account anyway")
	}
}

// TestNonAdminCannotCreateUsers is this stage's below-role 403 case.
func TestNonAdminCannotCreateUsers(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	adminClient := registerAdmin(t, ts, "admin", "password-placeholder-1")
	// Past the second-factor door, so it is the role check that answers.
	userClient := userClientPastTheDoor(t, ts, adminClient, "operator", "password456")

	wantProblem(t, postJSON(t, userClient, ts.URL+"/api/auth/users", createUserRequest{Username: "another", Password: "password789", Role: "user"}),
		http.StatusForbidden, classForbidden)
	if _, ok := g.deps.Users.ByUsername("another"); ok {
		t.Error("a refused request created the account anyway")
	}
}

func TestUserListIsAdminOnly(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	adminClient := registerAdmin(t, ts, "admin", "password-placeholder-1")
	// Past the second-factor door, so it is the role check that answers.
	userClient := userClientPastTheDoor(t, ts, adminClient, "operator", "password456")

	resp, err := userClient.Get(ts.URL + "/api/auth/users")
	if err != nil {
		t.Fatal(err)
	}
	wantProblem(t, resp, http.StatusForbidden, classForbidden)

	adminResp, err := adminClient.Get(ts.URL + "/api/auth/users")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = adminResp.Body.Close() }()
	var users []userSummary
	if err := json.NewDecoder(adminResp.Body).Decode(&users); err != nil {
		t.Fatalf("decoding the user list: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(users))
	}
	for _, u := range users {
		if u.ID == "" || u.Username == "" {
			t.Errorf("incomplete user summary: %+v", u)
		}
	}
}

func TestDeletingAUserRevokesTheirSessionAndTokens(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	adminClient := registerAdmin(t, ts, "admin", "password-placeholder-1")
	_ = postJSON(t, adminClient, ts.URL+"/api/auth/users", createUserRequest{Username: "operator", Password: "password456", Role: "user"}).Body.Close()

	operator, ok := g.deps.Users.ByUsername("operator")
	if !ok {
		t.Fatal("the account under test was not created")
	}

	// A token attributed to the account being deleted, created directly
	// through the store -- only an admin may mint one through the API,
	// and this stands in for a token issued while that account still
	// held admin, before a transfer.
	_, _, err := g.deps.Tokens.Create("operators-token", gauntlet.TokenKindAPI, "", operator, time.Now())
	if err != nil {
		t.Fatalf("Tokens.Create: %v", err)
	}

	operatorClient := &http.Client{Jar: mustCookieJar(t)}
	_ = postJSON(t, operatorClient, ts.URL+"/api/auth/login", credentialsRequest{Username: "operator", Password: "password456"}).Body.Close()
	enrolTOTPFactor(t, operatorClient, ts, "password456") // /api/protected is not an enrolment route, so the "live before the delete" baseline below needs a factor first
	live, err := operatorClient.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	_ = live.Body.Close()
	if live.StatusCode != http.StatusOK {
		t.Fatalf("the session under test does not work before the delete: %d", live.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/auth/users/"+operator.ID, strings.NewReader(`{"password":"`+testAdminPassword+`"}`))
	req.Header.Set(csrfHeaderName, testCSRFValue)
	resp, err := adminClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected the delete to succeed, got %d", resp.StatusCode)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if got, _ := body["tokensRevoked"].(float64); got != 1 {
		t.Errorf("expected tokensRevoked=1, got %v", body["tokensRevoked"])
	}

	after, err := operatorClient.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = after.Body.Close() }()
	if after.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected the deleted user's session to be revoked, got %d", after.StatusCode)
	}
	if len(g.deps.Tokens.List()) != 0 {
		t.Error("expected the deleted user's tokens to be revoked")
	}
}

func TestDeletingTheAdminIsRefused(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password-placeholder-1")

	admin, ok := g.deps.Users.ByUsername("admin")
	if !ok {
		t.Fatal("the admin account was not created")
	}

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/auth/users/"+admin.ID, strings.NewReader(`{"password":"`+testAdminPassword+`"}`))
	req.Header.Set(csrfHeaderName, testCSRFValue)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("expected 409 for deleting the admin, got %d", resp.StatusCode)
	}
	// gauntlet #15: ErrCannotDeleteAdmin gets its own message now,
	// instead of falling through to the generic "unable to complete the
	// request" -- see gateErrorMessages (httpjson.go).
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "admin account cannot be deleted") {
		t.Errorf("expected a specific admin-cannot-be-deleted message, got %q", body)
	}
	if _, ok := g.deps.Users.Get(admin.ID); !ok {
		t.Error("the admin account must still exist")
	}
}

func TestDeleteUserNotFound(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password-placeholder-1")

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/auth/users/does-not-exist", strings.NewReader(`{"password":"`+testAdminPassword+`"}`))
	req.Header.Set(csrfHeaderName, testCSRFValue)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for an unknown user id, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "no such user") {
		t.Errorf("expected the not-found message, got %q", body)
	}
}

// TestCreateAdminRoleRequestGetsSpecificMessage: a create-user request
// asking for role "admin" without the step-up fields says what it needs.
func TestCreateAdminRoleRequestGetsSpecificMessage(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password-placeholder-1")

	resp := postJSON(t, client, ts.URL+"/api/auth/users", createUserRequest{Username: "second", Password: "password456", Role: "admin"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for an admin-role request, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "your own password") {
		t.Errorf("expected a message naming the step-up, got %q", body)
	}
	if _, ok := g.deps.Users.ByUsername("second"); ok {
		t.Error("a refused admin-role request created the account anyway")
	}
}

// TestCreateUserWithoutStorageSaysWhatToDo: with no persistent storage
// the admin create-account route answers 503 with the same message
// register gives, not a 500 (#25). The handler is called directly: a
// store with no backend can never hold the admin account Protect and
// RequireRole would need to let the request through.
func TestCreateUserWithoutStorageSaysWhatToDo(t *testing.T) {
	g := newTestGate(t)
	users, err := gauntlet.OpenStore(nil, gauntlet.Options{})
	if err != nil {
		t.Fatalf("OpenStore(nil): %v", err)
	}
	g.deps.Users = users

	b, err := json.Marshal(createUserRequest{Username: "operator", Password: "password456"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/auth/users", bytes.NewReader(b))
	req = req.WithContext(withUser(req.Context(), &gauntlet.User{ID: "admin-id", Username: "admin", Role: gauntlet.RoleAdmin}))
	rec := httptest.NewRecorder()
	g.handleCreateUser(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 with no account storage, got %d", rec.Code)
	}
	if got, want := decodeProblem(t, rec.Body.Bytes()).Detail, gateErrorMessages[gauntlet.ErrNotPersisted]; got != want {
		t.Errorf("detail = %q, want %q", got, want)
	}
}

// versionCountingBackend counts calls to Version, the cheap staleness
// check every gauntlet.Store method makes against its backend
// (reloadIfStale) before doing anything else. gauntlet #42's regression
// guard reads this count rather than len(someCounter): on a real
// backend each Version round trip can itself stall for seconds, so what
// matters is that handleListUsers makes one of these per *request*
// (List's own check), not one per *account* on top of it.
type versionCountingBackend struct {
	*persist.Memory
	versionCalls atomic.Int64
}

func (b *versionCountingBackend) Version(ctx context.Context) (int64, bool, error) {
	b.versionCalls.Add(1)
	return b.Memory.Version(ctx)
}

// TestListUsersDoesNotCheckPasskeysPerAccount is gauntlet #42: before
// the fix, handleListUsers called Store.PasskeyCount once per account
// after List(), and each of those calls paid its own staleness check
// against the backend on top of List()'s own -- on a stalled backend,
// an N-account list could cost N times reloadTimeout. The fix reads
// gauntlet.User.PasskeyCount off each List() entry instead, so the
// backend cost of GET /api/auth/users must stay flat as accounts (and
// their passkeys) are added, not grow with them.
//
// The request's own fixed cost (Protect's session lookup plus List's
// own staleness check) is measured first, with a single account, then
// used as the expectation for a second request made after more
// accounts and passkeys exist -- rather than asserting a specific call
// count, which would be pinning an implementation detail of Protect
// this test has no business caring about.
func TestListUsersDoesNotCheckPasskeysPerAccount(t *testing.T) {
	backend := &versionCountingBackend{Memory: persist.NewMemory()}
	users := openTrackedStore(t, backend)
	g := newTestGateWithUsers(t, users)
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")

	getUsers := func() []userSummary {
		t.Helper()
		resp, err := admin.Get(ts.URL + "/api/auth/users")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /api/auth/users: status = %d, want 200", resp.StatusCode)
		}
		var out []userSummary
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	before := backend.versionCalls.Load()
	getUsers()
	baseline := backend.versionCalls.Load() - before

	if _, err := users.CreateUser("one", "password456", gauntlet.RoleUser, time.Now()); err != nil {
		t.Fatal(err)
	}
	two, err := users.CreateUser("two", "password789", gauntlet.RoleUser, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.AddPasskey(two.ID, gauntlet.Passkey{ID: []byte("pk-1"), RPID: "passkeys.example.org", Name: "key one"}); err != nil {
		t.Fatal(err)
	}
	if _, err := users.AddPasskey(two.ID, gauntlet.Passkey{ID: []byte("pk-2"), RPID: "passkeys.example.org", Name: "key two"}); err != nil {
		t.Fatal(err)
	}

	before = backend.versionCalls.Load()
	out := getUsers()
	withThreeAccounts := backend.versionCalls.Load() - before

	if withThreeAccounts != baseline {
		t.Errorf("GET /api/auth/users made %d Version calls against the backend with 3 accounts, want %d (the single-account baseline, unchanged) -- PasskeyCount must not be read per account", withThreeAccounts, baseline)
	}

	byUsername := make(map[string]userSummary, len(out))
	for _, u := range out {
		byUsername[u.Username] = u
	}
	if got := byUsername["admin"].PasskeyCount; got != 0 {
		t.Errorf("admin PasskeyCount = %d, want 0", got)
	}
	if got := byUsername["one"].PasskeyCount; got != 0 {
		t.Errorf("one PasskeyCount = %d, want 0", got)
	}
	if got := byUsername["two"].PasskeyCount; got != 2 {
		t.Errorf("two PasskeyCount = %d, want 2", got)
	}
}

// ssoAccount provisions an SSO account at role the way a sign-in would,
// without a provider: the role route reads only the store and the policy.
func ssoAccount(t *testing.T, f *adminsFixture, subject string, role gauntlet.Role) string {
	t.Helper()
	in, err := f.g.deps.Users.FindOrCreateOIDCUserWithRole("https://idp.example", subject, subject, role, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return in.User.ID
}

func TestSetRoleRefusesUserViewerChangesOnAnSSOManagedAccount(t *testing.T) {
	f := newAdminsFixture(t)
	f.g.deps.OIDCPolicy.RoleFromGroups = map[string]string{"staff": "user", "guests": "viewer"}
	id := ssoAccount(t, f, "sso-pat", gauntlet.RoleViewer)

	for _, role := range []string{"user", "viewer"} {
		status, body := f.setRole(t, f.admin, id, setRoleRequest{Role: role})
		want := http.StatusConflict
		if role == "viewer" {
			// Already that role: the plain conflict says so first.
			if status != want || adminProblemType(t, body) != problemTypeBase+"conflict" {
				t.Errorf("same role = %d %s, want 409 conflict", status, body)
			}
			continue
		}
		if status != want || adminProblemType(t, body) != problemTypeBase+"role-managed-by-sso" {
			t.Errorf("viewer -> %s = %d %s, want 409 role-managed-by-sso", role, status, body)
		}
		if !strings.Contains(body, "identity provider") {
			t.Errorf("body %s does not point at the identity provider", body)
		}
	}
	if r := roleOf(t, f.g, id); r != gauntlet.RoleViewer {
		t.Errorf("role = %q after refusals, want viewer", r)
	}
	// user -> viewer is refused too.
	userID := ssoAccount(t, f, "sso-sam", gauntlet.RoleUser)
	if status, body := f.setRole(t, f.admin, userID, setRoleRequest{Role: "viewer"}); status != http.StatusConflict ||
		adminProblemType(t, body) != problemTypeBase+"role-managed-by-sso" {
		t.Errorf("user -> viewer = %d %s, want 409 role-managed-by-sso", status, body)
	}
}

func TestSetRoleOnAnSSOAccountStillGrantsAndDemotesAdmin(t *testing.T) {
	f := newAdminsFixture(t)
	f.g.deps.OIDCPolicy.RoleFromGroups = map[string]string{"staff": "user"}
	id := ssoAccount(t, f, "sso-pat", gauntlet.RoleUser)

	status, body := f.setRole(t, f.admin, id, setRoleRequest{Role: "admin", Password: selfUnlockAdminPassword, Code: f.code()})
	if status != http.StatusOK {
		t.Fatalf("granting admin to a managed account = %d %s, want 200", status, body)
	}
	// An admin is not managed: demoting works, and the map takes over at
	// the account's next SSO sign-in.
	if status, body := f.setRole(t, f.admin, id, setRoleRequest{Role: "user"}); status != http.StatusOK {
		t.Errorf("demoting an SSO admin = %d %s, want 200", status, body)
	}
	if r := roleOf(t, f.g, id); r != gauntlet.RoleUser {
		t.Errorf("role = %q, want user", r)
	}
}

func TestSetRoleSSOManagementNeedsALinkAndAMap(t *testing.T) {
	f := newAdminsFixture(t)
	sso := ssoAccount(t, f, "sso-pat", gauntlet.RoleUser)

	// No map configured: an SSO account's role is an admin's to set.
	if status, body := f.setRole(t, f.admin, sso, setRoleRequest{Role: "viewer"}); status != http.StatusOK {
		t.Errorf("SSO account with no map = %d %s, want 200", status, body)
	}
	// A map configured: a local account is unaffected.
	f.g.deps.OIDCPolicy.RoleFromGroups = map[string]string{"staff": "user"}
	if status, body := f.setRole(t, f.admin, f.bobID, setRoleRequest{Role: "viewer"}); status != http.StatusOK {
		t.Errorf("local account with a map = %d %s, want 200", status, body)
	}
}
