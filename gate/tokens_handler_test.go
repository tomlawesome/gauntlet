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
	adminClient := registerAdmin(t, ts, "admin", "password-placeholder-1")
	_ = postJSON(t, adminClient, ts.URL+"/api/auth/users", createUserRequest{Username: "operator", Password: "password456", Role: "user"}).Body.Close()

	userClient := &http.Client{Jar: mustCookieJar(t)}
	_ = postJSON(t, userClient, ts.URL+"/api/auth/login", credentialsRequest{Username: "operator", Password: "password456"}).Body.Close()

	resp := postJSON(t, userClient, ts.URL+"/api/tokens", createTokenRequest{Name: "mine", Password: testAdminPassword})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected a non-admin to be forbidden from creating a token, got %d", resp.StatusCode)
	}
}

func TestCreateTokenRejectsEmptyName(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")

	resp := postJSON(t, admin, ts.URL+"/api/tokens", createTokenRequest{Name: "", Password: testAdminPassword})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for an empty name, got %d", resp.StatusCode)
	}
}

// TestCreateTokenRejectsABlankName: the store trims the name, so one of
// only spaces would otherwise be issued with no name at all.
func TestCreateTokenRejectsABlankName(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")

	resp := postJSON(t, admin, ts.URL+"/api/tokens", createTokenRequest{Name: "   ", Password: testAdminPassword})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for a name of only spaces, got %d", resp.StatusCode)
	}
	if len(g.deps.Tokens.List()) != 0 {
		t.Error("a refused token was created anyway")
	}
}

func TestCreateTokenRejectsInvalidKind(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")

	resp := postJSON(t, admin, ts.URL+"/api/tokens", createTokenRequest{Name: "mine", Kind: "not-a-real-kind", Password: testAdminPassword})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for an unregistered kind, got %d", resp.StatusCode)
	}
}

func TestTokensListAdminOnly(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	adminClient := registerAdmin(t, ts, "admin", "password-placeholder-1")
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
	adminClient := registerAdmin(t, ts, "admin", "password-placeholder-1")

	createResp := postJSON(t, adminClient, ts.URL+"/api/tokens", createTokenRequest{Name: "integration", Password: testAdminPassword})
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
	adminClient := registerAdmin(t, ts, "admin", "password-placeholder-1")

	resp := postJSON(t, adminClient, ts.URL+"/api/tokens", createTokenRequest{Name: "router", Kind: string(gauntlet.TokenKindIngest), Password: testAdminPassword})
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
	adminClient := registerAdmin(t, ts, "admin", "password-placeholder-1")

	name := strings.Repeat("n", gauntlet.MaxTokenNameLen+1)
	resp := postJSON(t, adminClient, ts.URL+"/api/tokens", createTokenRequest{Name: name, Password: testAdminPassword})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for a %d-character token name, got %d", len(name), resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := decodeProblem(t, body).Detail, gauntlet.ErrTokenNameInvalid.Error(); got != want {
		t.Errorf("detail = %q, want %q", got, want)
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
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")

	resp := postJSON(t, admin, ts.URL+"/api/tokens", createTokenRequest{Name: "mine", Password: testAdminPassword})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 with no token storage, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := decodeProblem(t, body).Detail, gateErrorMessages[gauntlet.ErrTokenNotPersisted]; got != want {
		t.Errorf("detail = %q, want %q", got, want)
	}
}

// TestRevokeTokenStorageFailureIsNotReportedAsGone: a revoke whose save
// fails leaves the token working, so answering 404 ("already revoked")
// would tell an admin revoking a leaked token that it is dead when it
// is not. The refusal must be a 5xx; gate/contracttest's copy of this
// test checks the document describes it.
func TestRevokeTokenStorageFailureIsNotReportedAsGone(t *testing.T) {
	g := newTestGate(t)
	backend := &budgetBackend{inner: persist.NewMemory(), left: -1}
	tokens, err := gauntlet.OpenTokenStore(backend, gauntlet.TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	g.deps.Tokens = tokens
	registerUserDirect(t, g, "admin", "password-placeholder-1")
	raw, tok, err := tokens.Create("leaked", gauntlet.TokenKindAPI, "", nil, nowUTC())
	if err != nil {
		t.Fatal(err)
	}
	g.Handle(gauntlet.TokenKindAPI, kindEchoHandler("/api/readonly"))
	ts := newTestServer(t, g)
	admin := loggedInClient(t, ts, "admin", "password-placeholder-1")
	enrolTOTPFactor(t, admin, ts, "password-placeholder-1") // DELETE /api/tokens/{id} is not an enrolment route

	backend.left = 0
	req, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/tokens/"+tok.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(csrfHeaderName, testCSRFValue)
	revoke, err := admin.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = revoke.Body.Close()
	if revoke.StatusCode != http.StatusInternalServerError {
		t.Fatalf("a revoke whose save failed answered %d, want 500", revoke.StatusCode)
	}

	resp := bearerRequest(t, ts.URL, "/api/readonly", raw)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the token stopped working although its revoke was refused: got %d, want 200", resp.StatusCode)
	}
}

// TestTokenRegisteredKinds: an application may register its own token
// kinds (TokenOptions.Kinds), and gate serves any of them, not only api
// and ingest. Leaving kind out still means api, which is refused when
// the application did not register api. gate/contracttest's
// TestContractTokenRegisteredKinds checks the document accepts them.
func TestTokenRegisteredKinds(t *testing.T) {
	g := newTestGate(t)
	const custom gauntlet.TokenKind = "droplist-pull"
	tokens, err := gauntlet.OpenTokenStore(persist.NewMemory(), gauntlet.TokenOptions{Kinds: []gauntlet.TokenKind{custom}})
	if err != nil {
		t.Fatal(err)
	}
	g.deps.Tokens = tokens
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")
	expect := func(resp *http.Response, want int, out any) {
		t.Helper()
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != want {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("status %d, want %d: %s", resp.StatusCode, want, body)
		}
		if out != nil {
			if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
				t.Fatal(err)
			}
		}
	}

	var created tokenResponse
	expect(postJSON(t, admin, ts.URL+"/api/tokens", createTokenRequest{Name: "pull", Kind: string(custom), Password: testAdminPassword}), http.StatusCreated, &created)
	if created.Kind != custom {
		t.Errorf("created kind = %q, want %q", created.Kind, custom)
	}
	expect(postJSON(t, admin, ts.URL+"/api/tokens", createTokenRequest{Name: "default", Password: testAdminPassword}), http.StatusBadRequest, nil)
	var list struct {
		Tokens []tokenResponse `json:"tokens"`
	}
	listed, err := admin.Get(ts.URL + "/api/tokens")
	if err != nil {
		t.Fatal(err)
	}
	expect(listed, http.StatusOK, &list)
	if len(list.Tokens) != 1 || list.Tokens[0].Kind != custom {
		t.Errorf("listed tokens = %+v, want one of kind %q", list.Tokens, custom)
	}
}
