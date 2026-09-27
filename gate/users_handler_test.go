// Ported from mikroview's internal/api/auth_test.go: the account-admin
// cases that fall inside G6 stage 1.
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

func TestAdminCanCreateAdditionalUsers(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password123")

	resp := postJSON(t, client, ts.URL+"/api/auth/users", createUserRequest{Username: "operator", Password: "password456", Role: "user"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected an admin to be able to create an additional user, got %d", resp.StatusCode)
	}
}

func TestAdminCanCreateViewerAndSessionReportsIt(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	adminClient := registerAdmin(t, ts, "admin", "password123")

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
	adminClient := registerAdmin(t, ts, "admin", "password123")

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
	adminClient := registerAdmin(t, ts, "admin", "password123")

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
	client := registerAdmin(t, ts, "admin", "password123")
	_ = postJSON(t, client, ts.URL+"/api/auth/users", createUserRequest{Username: "operator", Password: "password456", Role: "user"}).Body.Close()

	resp := postJSON(t, client, ts.URL+"/api/auth/users", createUserRequest{Username: "operator", Password: "password789", Role: "user"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("expected 409 for a duplicate username, got %d", resp.StatusCode)
	}
}

func TestAdminCannotCreateASecondAdmin(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password123")

	resp := postJSON(t, client, ts.URL+"/api/auth/users", createUserRequest{Username: "second", Password: "password456", Role: "admin"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for an admin-role request, got %d", resp.StatusCode)
	}
	if _, ok := g.deps.Users.ByUsername("second"); ok {
		t.Error("a refused admin-role request created the account anyway")
	}
}

// TestNonAdminCannotCreateUsers is this stage's below-role 403 case.
func TestNonAdminCannotCreateUsers(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	adminClient := registerAdmin(t, ts, "admin", "password123")
	_ = postJSON(t, adminClient, ts.URL+"/api/auth/users", createUserRequest{Username: "operator", Password: "password456", Role: "user"}).Body.Close()

	userClient := &http.Client{Jar: mustCookieJar(t)}
	_ = postJSON(t, userClient, ts.URL+"/api/auth/login", credentialsRequest{Username: "operator", Password: "password456"}).Body.Close()

	resp := postJSON(t, userClient, ts.URL+"/api/auth/users", createUserRequest{Username: "another", Password: "password789", Role: "user"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected a non-admin to be forbidden from creating users, got %d", resp.StatusCode)
	}
}

func TestUserListIsAdminOnly(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	adminClient := registerAdmin(t, ts, "admin", "password123")
	_ = postJSON(t, adminClient, ts.URL+"/api/auth/users", createUserRequest{Username: "operator", Password: "password456", Role: "user"}).Body.Close()

	userClient := &http.Client{Jar: mustCookieJar(t)}
	_ = postJSON(t, userClient, ts.URL+"/api/auth/login", credentialsRequest{Username: "operator", Password: "password456"}).Body.Close()

	resp, err := userClient.Get(ts.URL + "/api/auth/users")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for a non-admin, got %d", resp.StatusCode)
	}

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
	adminClient := registerAdmin(t, ts, "admin", "password123")
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
	live, err := operatorClient.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	_ = live.Body.Close()
	if live.StatusCode != http.StatusOK {
		t.Fatalf("the session under test does not work before the delete: %d", live.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/auth/users/"+operator.ID, nil)
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
	client := registerAdmin(t, ts, "admin", "password123")

	admin, ok := g.deps.Users.ByUsername("admin")
	if !ok {
		t.Fatal("the admin account was not created")
	}

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/auth/users/"+admin.ID, nil)
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
	client := registerAdmin(t, ts, "admin", "password123")

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/auth/users/does-not-exist", nil)
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

// TestCreateAdminRoleRequestGetsSpecificMessage covers the other half of
// gauntlet #15's error-message work: ErrSingleAdmin, from a create-user
// request asking for role "admin".
func TestCreateAdminRoleRequestGetsSpecificMessage(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password123")

	resp := postJSON(t, client, ts.URL+"/api/auth/users", createUserRequest{Username: "second", Password: "password456", Role: "admin"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for an admin-role request, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "only one admin account") {
		t.Errorf("expected a specific single-admin message, got %q", body)
	}
	if _, ok := g.deps.Users.ByUsername("second"); ok {
		t.Error("a refused admin-role request created the account anyway")
	}
}
