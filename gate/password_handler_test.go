// Ported from mikroview's internal/api/auth_test.go: the
// handleAuthChangePassword cases.
package gate

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/persist"
)

func TestChangePasswordRotatesTheSessionAndEndsOthers(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password-placeholder-1")

	other := &http.Client{Jar: mustCookieJar(t)}
	_ = postJSON(t, other, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "password-placeholder-1"}).Body.Close()

	resp := postJSON(t, client, ts.URL+"/api/auth/password", changePasswordRequest{CurrentPassword: "password-placeholder-1", NewPassword: "new-password-1"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected the change to succeed, got %d", resp.StatusCode)
	}

	// The calling client's session was rotated, so it should still work.
	live, err := client.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = live.Body.Close() }()
	if live.StatusCode != http.StatusOK {
		t.Errorf("expected the caller's own (rotated) session to keep working, got %d", live.StatusCode)
	}

	// The other client's session must be dead.
	dead, err := other.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dead.Body.Close() }()
	if dead.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected the other session to be revoked, got %d", dead.StatusCode)
	}
}

func TestChangePasswordRefusesAWrongCurrentPassword(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password-placeholder-1")

	resp := postJSON(t, client, ts.URL+"/api/auth/password", changePasswordRequest{CurrentPassword: "wrong", NewPassword: "new-password-1"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for a wrong current password, got %d", resp.StatusCode)
	}
}

func TestChangePasswordRefusesAShortOrUnchangedPassword(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password-placeholder-1")

	short := postJSON(t, client, ts.URL+"/api/auth/password", changePasswordRequest{CurrentPassword: "password-placeholder-1", NewPassword: "short"})
	defer func() { _ = short.Body.Close() }()
	if short.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for a too-short new password, got %d", short.StatusCode)
	}

	unchanged := postJSON(t, client, ts.URL+"/api/auth/password", changePasswordRequest{CurrentPassword: "password-placeholder-1", NewPassword: "password-placeholder-1"})
	defer func() { _ = unchanged.Body.Close() }()
	if unchanged.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for an unchanged password, got %d", unchanged.StatusCode)
	}
}

func TestChangePasswordRequiresASession(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	registerAdmin(t, ts, "admin", "password-placeholder-1")

	resp := postJSON(t, &http.Client{}, ts.URL+"/api/auth/password", changePasswordRequest{CurrentPassword: "password-placeholder-1", NewPassword: "new-password-1"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 with no session, got %d", resp.StatusCode)
	}
}

// lockedBuffer is a log sink the server's handler goroutine writes while
// the test goroutine reads.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestChangePasswordStoreFailureIsLogged: the 500's documented promise
// is that the details are in the server log, so the store's error has to
// actually reach it.
func TestChangePasswordStoreFailureIsLogged(t *testing.T) {
	g := newTestGate(t)
	backend := &budgetBackend{inner: persist.NewMemory(), left: -1}
	users := openTrackedStore(t, backend)
	g.deps.Users = users
	logs := &lockedBuffer{}
	g.cfg.Log = slog.New(slog.NewTextHandler(logs, nil))
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password-placeholder-1")

	backend.left = 0
	resp := postJSON(t, client, ts.URL+"/api/auth/password", changePasswordRequest{CurrentPassword: "password-placeholder-1", NewPassword: "new-password-1"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("a failing store got %d, want 500", resp.StatusCode)
	}
	if !strings.Contains(logs.String(), "save refused") {
		t.Errorf("the store's error is not in the server log; log = %q", logs.String())
	}
}

// ssoOnlyAdmin provisions an account through SSO, as a sign-in would,
// promotes it to admin, and returns its ID and a client holding a
// session for it. The account has no local password.
func ssoOnlyAdmin(t *testing.T, g *Gate, ts *httptest.Server, subject string) (string, *http.Client) {
	t.Helper()
	u, _, err := g.deps.Users.FindOrCreateOIDCUser("https://idp.example", subject, subject, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.deps.Users.SetRole(u.ID, gauntlet.RoleAdmin, time.Now()); err != nil {
		t.Fatal(err)
	}
	sess := g.deps.Sessions.Create(u.ID, time.Now())
	return u.ID, sessionClient(t, ts.URL, sess.ID)
}

// Every admin keeps a local password (ADR-0010), so an SSO-only admin
// may set one with nothing but the new password; an SSO-only user still
// may not. Once it has one, the forced second-factor enrolment door
// holds it like any other local account.
func TestSSOOnlyAdminSetsAFirstLocalPassword(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	registerAdmin(t, ts, "admin", "password-placeholder-1")

	frodo, _, err := g.deps.Users.FindOrCreateOIDCUser("https://idp.example", "subject-frodo", "frodo", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	user := sessionClient(t, ts.URL, g.deps.Sessions.Create(frodo.ID, time.Now()).ID)
	refused := postJSON(t, user, ts.URL+"/api/auth/password", changePasswordRequest{NewPassword: "new-password-1"})
	_ = refused.Body.Close()
	if refused.StatusCode != http.StatusConflict {
		t.Errorf("an SSO-only user setting a password got %d, want 409", refused.StatusCode)
	}

	id, admin := ssoOnlyAdmin(t, g, ts, "subject-ann")
	if got := protectedStatusWithCookie(t, admin, ts.URL, nil); got != http.StatusOK {
		t.Fatalf("the SSO-only admin's session got %d before setting a password, want 200", got)
	}
	resp := postJSON(t, admin, ts.URL+"/api/auth/password", changePasswordRequest{NewPassword: "new-password-1"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("an SSO-only admin setting a first password got %d, want 200", resp.StatusCode)
	}
	u, _ := g.deps.Users.Get(id)
	if !u.LocalPassword() {
		t.Error("the admin still has no local password")
	}
	if _, err := g.deps.Users.Authenticate(u.Username, "new-password-1", time.Now()); err != nil {
		t.Errorf("the new password does not sign in: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	door, err := admin.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = door.Body.Close()
	if door.StatusCode != http.StatusForbidden || door.Header.Get(authGateHeader) != authGateMustEnrolFactor {
		t.Errorf("after setting a password: %d %s=%q, want 403 at the %s door",
			door.StatusCode, authGateHeader, door.Header.Get(authGateHeader), authGateMustEnrolFactor)
	}
}
