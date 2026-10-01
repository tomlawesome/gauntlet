// Ported from mikroview's internal/api/tokens_test.go: the admin-gated
// token-management cases that fall inside G6 stage 1.
package gate

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/persist"
)

func TestTokensCreateRequiresAdmin(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	adminClient := registerAdmin(t, ts, "admin", "password123")
	_ = postJSON(t, adminClient, ts.URL+"/api/auth/users", createUserRequest{Username: "operator", Password: "password456", Role: "user"}).Body.Close()

	userClient := &http.Client{Jar: mustCookieJar(t)}
	_ = postJSON(t, userClient, ts.URL+"/api/auth/login", credentialsRequest{Username: "operator", Password: "password456"}).Body.Close()

	resp := postJSON(t, userClient, ts.URL+"/api/tokens", createTokenRequest{Name: "mine"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected a non-admin to be forbidden from creating a token, got %d", resp.StatusCode)
	}
}

func TestCreateTokenRejectsEmptyName(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password123")

	resp := postJSON(t, admin, ts.URL+"/api/tokens", createTokenRequest{Name: ""})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for an empty name, got %d", resp.StatusCode)
	}
}

func TestCreateTokenRejectsInvalidKind(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password123")

	resp := postJSON(t, admin, ts.URL+"/api/tokens", createTokenRequest{Name: "mine", Kind: "not-a-real-kind"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for an unregistered kind, got %d", resp.StatusCode)
	}
}

func TestTokensListAdminOnly(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	adminClient := registerAdmin(t, ts, "admin", "password123")
	_ = postJSON(t, adminClient, ts.URL+"/api/auth/users", createUserRequest{Username: "operator", Password: "password456", Role: "user"}).Body.Close()

	userClient := &http.Client{Jar: mustCookieJar(t)}
	_ = postJSON(t, userClient, ts.URL+"/api/auth/login", credentialsRequest{Username: "operator", Password: "password456"}).Body.Close()

	resp, err := userClient.Get(ts.URL + "/api/tokens")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for a non-admin, got %d", resp.StatusCode)
	}
}

func TestAdminCanCreateListAndRevokeTokens(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	adminClient := registerAdmin(t, ts, "admin", "password123")

	createResp := postJSON(t, adminClient, ts.URL+"/api/tokens", createTokenRequest{Name: "integration"})
	defer func() { _ = createResp.Body.Close() }()
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", createResp.StatusCode)
	}
	var created tokenResponse
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.Value == "" {
		t.Fatal("expected the raw token value in the create response")
	}
	if created.Kind != gauntlet.TokenKindAPI {
		t.Errorf("expected the default kind to be api, got %q", created.Kind)
	}

	listResp, err := adminClient.Get(ts.URL + "/api/tokens")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listResp.Body.Close() }()
	var listBody struct {
		Tokens []tokenResponse `json:"tokens"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listBody); err != nil {
		t.Fatal(err)
	}
	if len(listBody.Tokens) != 1 {
		t.Fatalf("expected 1 token listed, got %d", len(listBody.Tokens))
	}
	if listBody.Tokens[0].Value != "" {
		t.Error("expected the list response to never carry the raw value")
	}

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/tokens/"+created.ID, nil)
	req.Header.Set(csrfHeaderName, testCSRFValue)
	revokeResp, err := adminClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = revokeResp.Body.Close() }()
	if revokeResp.StatusCode != http.StatusOK {
		t.Errorf("expected the revoke to succeed, got %d", revokeResp.StatusCode)
	}
	if len(g.deps.Tokens.List()) != 0 {
		t.Error("expected the token to be gone after revoke")
	}
}

func TestCreateTokenRejectsAnUnscopedIngestToken(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	adminClient := registerAdmin(t, ts, "admin", "password123")

	resp := postJSON(t, adminClient, ts.URL+"/api/tokens", createTokenRequest{Name: "router", Kind: string(gauntlet.TokenKindIngest)})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for an ingest token with no device, got %d", resp.StatusCode)
	}
}

// TestCreateTokenRejectsATooLongName: a name over MaxTokenNameLen is the
// caller's mistake, so it is a 400 naming the limit, not a 500 (#25).
func TestCreateTokenRejectsATooLongName(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	adminClient := registerAdmin(t, ts, "admin", "password123")

	name := strings.Repeat("n", gauntlet.MaxTokenNameLen+1)
	resp := postJSON(t, adminClient, ts.URL+"/api/tokens", createTokenRequest{Name: name})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for a %d-character token name, got %d", len(name), resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(body)), gauntlet.ErrTokenNameInvalid.Error(); got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if len(g.deps.Tokens.List()) != 0 {
		t.Error("a refused token was created anyway")
	}
}

// TestCreateTokenWithoutStorageSaysWhatToDo: the 503 for a token store
// with no backend carries gateErrorMessages' entry for it, which names
// the fix, not the generic text every other unmapped error gets.
func TestCreateTokenWithoutStorageSaysWhatToDo(t *testing.T) {
	g := newTestGate(t)
	tokens, err := gauntlet.OpenTokenStore(nil, gauntlet.TokenOptions{})
	if err != nil {
		t.Fatalf("OpenTokenStore(nil): %v", err)
	}
	g.deps.Tokens = tokens
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password123")

	resp := postJSON(t, admin, ts.URL+"/api/tokens", createTokenRequest{Name: "mine"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 with no token storage, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(body)), gateErrorMessages[gauntlet.ErrTokenNotPersisted]; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

// TestRevokeTokenStorageFailureIsNotReportedAsGone: a revoke whose save
// fails leaves the token working, so answering 404 ("already revoked")
// would tell an admin revoking a leaked token that it is dead when it
// is not. The refusal must be a 5xx the document describes.
func TestRevokeTokenStorageFailureIsNotReportedAsGone(t *testing.T) {
	c := newContractChecker(t)
	g := newTestGate(t)
	backend := &budgetBackend{inner: persist.NewMemory(), left: -1}
	tokens, err := gauntlet.OpenTokenStore(backend, gauntlet.TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	g.deps.Tokens = tokens
	registerUserDirect(t, g, "admin", "password123")
	raw, tok, err := tokens.Create("leaked", gauntlet.TokenKindAPI, "", nil, nowUTC())
	if err != nil {
		t.Fatal(err)
	}
	g.Handle(gauntlet.TokenKindAPI, kindEchoHandler("/api/readonly"))
	ts := newTestServer(t, g)
	admin := c.client()
	c.do(admin, ts.URL, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{Username: "admin", Password: "password123"}}, 200, nil)

	backend.left = 0
	c.do(admin, ts.URL, call{method: "DELETE", path: "/api/tokens/" + tok.ID}, http.StatusInternalServerError, nil)

	resp := bearerRequest(t, ts.URL, "/api/readonly", raw)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the token stopped working although its revoke was refused: got %d, want 200", resp.StatusCode)
	}
}
