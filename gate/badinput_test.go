// Malformed-request-body cases for every handler that decodes JSON --
// docs/testing.md: "a refusal is behaviour", so these are their own
// tests rather than left implicit in the happy-path ones.
package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/persist"
)

func postRawBody(t *testing.T, client *http.Client, url, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrfHeaderName, testCSRFValue)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestRegisterRejectsInvalidJSON(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	resp := postRawBody(t, &http.Client{}, ts.URL+"/api/auth/register", "not json")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestLoginRejectsInvalidJSON(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	registerAdmin(t, ts, "admin", "password-placeholder-1")
	resp := postRawBody(t, &http.Client{}, ts.URL+"/api/auth/login", "not json")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestCreateUserRejectsInvalidJSON(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password-placeholder-1")
	resp := postRawBody(t, client, ts.URL+"/api/auth/users", "not json")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestCreateTokenRejectsInvalidJSON(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password-placeholder-1")
	resp := postRawBody(t, client, ts.URL+"/api/tokens", "not json")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestChangePasswordRejectsInvalidJSON(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password-placeholder-1")
	resp := postRawBody(t, client, ts.URL+"/api/auth/password", "not json")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestLoginFactorRejectsInvalidJSON(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	registerAdmin(t, ts, "admin", "password-placeholder-1")
	resp := postRawBody(t, &http.Client{}, ts.URL+"/api/auth/login/factor", "not json")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestTOTPConfirmRejectsInvalidJSON(t *testing.T) {
	_, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	resp := postRawBody(t, bob, ts.URL+"/api/auth/totp/confirm", "not json")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestTOTPDeleteRejectsInvalidJSON(t *testing.T) {
	_, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	totpEnrolAndConfirm(t, bob, ts) // DELETE /api/auth/totp is not an enrolment route, so bob needs a factor to reach the handler at all
	req, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/auth/totp", strings.NewReader("not json"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrfHeaderName, testCSRFValue)
	resp, err := bob.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestRecoveryCodesRegenerateRejectsInvalidJSON(t *testing.T) {
	_, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	totpEnrolAndConfirm(t, bob, ts) // not an enrolment route, so bob needs a factor to reach the handler at all
	resp := postRawBody(t, bob, ts.URL+"/api/auth/recovery-codes", "not json")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestTokensRevokeUnknownIDNotFound(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password-placeholder-1")

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/tokens/does-not-exist", nil)
	req.Header.Set(csrfHeaderName, testCSRFValue)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// failAfterNSaves is a persist.Backend that succeeds its first n Saves
// and fails every one after -- for exercising a handler's own
// already-committed-but-this-part-failed logging path (handleDeleteUser
// revoking tokens), the same shape gauntlet's own saveBudgetBackend
// (testhelpers_test.go) gives Store's rollback tests.
type failAfterNSaves struct {
	inner persist.Backend
	left  int
}

func (b *failAfterNSaves) Load(ctx context.Context) (persist.Snapshot, error) {
	return b.inner.Load(ctx)
}
func (b *failAfterNSaves) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	if b.left <= 0 {
		return 0, errBoom
	}
	b.left--
	return b.inner.Save(ctx, payload, expect)
}
func (b *failAfterNSaves) Close() error     { return b.inner.Close() }
func (b *failAfterNSaves) Describe() string { return "fail-after-n-saves test backend" }

var errBoom = errBoomType{}

type errBoomType struct{}

func (errBoomType) Error() string { return "boom: backend unavailable" }

// TestDeleteUserReportsWhenTokenRevocationFails covers handleDeleteUser's
// fail-closed path (gauntlet #15): the account deletion has already
// committed by the time the token revocation is attempted, and there is
// no undoing that to retry, but a failure revoking this user's tokens
// must not be answered as a plain success either -- the deleted user's
// tokens are still live, and a 200 with tokensRevoked=0 would read
// exactly like "this user held none". It is said out loud server-side
// (Gate.logError), recorded in the audit detail, and reported to the
// caller as a 500 with a JSON body naming the account and what still
// needs doing by hand.
func TestDeleteUserReportsWhenTokenRevocationFails(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password-placeholder-1")
	_ = postJSON(t, client, ts.URL+"/api/auth/users", createUserRequest{Username: "operator", Password: "password456", Role: "user"}).Body.Close()

	operator, ok := g.deps.Users.ByUsername("operator")
	if !ok {
		t.Fatal("operator account missing")
	}

	// A token store backed by a backend that allows exactly one more
	// save (the token's own creation below) and then refuses every
	// save after -- so RevokeAllCreatedBy, called by handleDeleteUser
	// once the account deletion has already committed, fails.
	failing := &failAfterNSaves{inner: persist.NewMemory(), left: 1}
	tokens, err := gauntlet.OpenTokenStore(failing, gauntlet.TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := tokens.Create("operators-token", gauntlet.TokenKindAPI, "", operator, nowUTC()); err != nil {
		t.Fatal(err)
	}
	failing.left = 0
	g.deps.Tokens = tokens

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/auth/users/"+operator.ID, strings.NewReader(`{"password":"`+testAdminPassword+`"}`))
	req.Header.Set(csrfHeaderName, testCSRFValue)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected a failed token revocation to answer 500, got %d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding the error body: %v", err)
	}
	if body["detail"] == nil || body["detail"] == "" {
		t.Errorf("expected a non-empty detail field, got %+v", body)
	}
	if body["username"] != "operator" {
		t.Errorf("expected the response to still name the deleted account, got %+v", body)
	}
	// The account deletion itself is not undone by the token-revoke
	// failure -- it already committed before RevokeAllCreatedBy was
	// even called.
	if _, ok := g.deps.Users.Get(operator.ID); ok {
		t.Error("expected the account to still be deleted despite the 500")
	}
}

// TestJSONBodyRejectsUnknownField covers every handler's request struct
// against a body carrying one extra field alongside its real ones --
// gauntlet #15's DisallowUnknownFields divergence from mikroview (this
// file's own header comment).
func TestJSONBodyRejectsUnknownField(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password-placeholder-1")

	resp := postRawBody(t, client, ts.URL+"/api/auth/users",
		`{"username":"operator","password":"password456","role":"user","admin":true}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an unrecognized field", resp.StatusCode)
	}
	if _, ok := g.deps.Users.ByUsername("operator"); ok {
		t.Error("expected the account to not have been created")
	}
}

// TestJSONBodyRejectsTrailingData covers the other half of the same
// divergence: a body that decodes cleanly but then has more after it.
func TestJSONBodyRejectsTrailingData(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	registerAdmin(t, ts, "admin", "password-placeholder-1")

	resp := postRawBody(t, &http.Client{}, ts.URL+"/api/auth/login",
		`{"username":"admin","password":"password-placeholder-1"}{"trailing":true}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for trailing data after the JSON value", resp.StatusCode)
	}
}
