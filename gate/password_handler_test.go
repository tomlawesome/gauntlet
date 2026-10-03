// Ported from mikroview's internal/api/auth_test.go: the
// handleAuthChangePassword cases.
package gate

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

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
