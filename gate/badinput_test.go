// Malformed-request-body cases for every handler that decodes JSON --
// docs/testing.md: "a refusal is behaviour", so these are their own
// tests rather than left implicit in the happy-path ones.
package gate

import (
	"bytes"
	"context"
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
	registerAdmin(t, ts, "admin", "password123")
	resp := postRawBody(t, &http.Client{}, ts.URL+"/api/auth/login", "not json")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestCreateUserRejectsInvalidJSON(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password123")
	resp := postRawBody(t, client, ts.URL+"/api/auth/users", "not json")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestCreateTokenRejectsInvalidJSON(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password123")
	resp := postRawBody(t, client, ts.URL+"/api/tokens", "not json")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestChangePasswordRejectsInvalidJSON(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password123")
	resp := postRawBody(t, client, ts.URL+"/api/auth/password", "not json")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestLoginFactorRejectsInvalidJSON(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	registerAdmin(t, ts, "admin", "password123")
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
	resp := postRawBody(t, bob, ts.URL+"/api/auth/recovery-codes", "not json")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestTokensRevokeUnknownIDNotFound(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password123")

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

// TestDeleteUserLogsWhenTokenRevocationFails covers handleDeleteUser's
// R6 path: the account deletion has already committed by the time the
// token revocation is attempted, so a failure there must not turn a
// successful delete into an error response -- it is said out loud
// server-side (Gate.logError) and the response reports zero tokens
// revoked, not what was attempted.
func TestDeleteUserLogsWhenTokenRevocationFails(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password123")
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

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/auth/users/"+operator.ID, nil)
	req.Header.Set(csrfHeaderName, testCSRFValue)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected the delete itself to still succeed, got %d", resp.StatusCode)
	}
}
