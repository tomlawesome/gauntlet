// Ported from mikroview's internal/api/auth_test.go: the
// handleAuthChangePassword cases.
package gate

import (
	"net/http"
	"testing"
)

func TestChangePasswordRotatesTheSessionAndEndsOthers(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password123")

	other := &http.Client{Jar: mustCookieJar(t)}
	_ = postJSON(t, other, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "password123"}).Body.Close()

	resp := postJSON(t, client, ts.URL+"/api/auth/password", changePasswordRequest{CurrentPassword: "password123", NewPassword: "new-password-1"})
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
	client := registerAdmin(t, ts, "admin", "password123")

	resp := postJSON(t, client, ts.URL+"/api/auth/password", changePasswordRequest{CurrentPassword: "wrong", NewPassword: "new-password-1"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for a wrong current password, got %d", resp.StatusCode)
	}
}

func TestChangePasswordRefusesAShortOrUnchangedPassword(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password123")

	short := postJSON(t, client, ts.URL+"/api/auth/password", changePasswordRequest{CurrentPassword: "password123", NewPassword: "short"})
	defer func() { _ = short.Body.Close() }()
	if short.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for a too-short new password, got %d", short.StatusCode)
	}

	unchanged := postJSON(t, client, ts.URL+"/api/auth/password", changePasswordRequest{CurrentPassword: "password123", NewPassword: "password123"})
	defer func() { _ = unchanged.Body.Close() }()
	if unchanged.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for an unchanged password, got %d", unchanged.StatusCode)
	}
}

func TestChangePasswordRequiresASession(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	registerAdmin(t, ts, "admin", "password123")

	resp := postJSON(t, &http.Client{}, ts.URL+"/api/auth/password", changePasswordRequest{CurrentPassword: "password123", NewPassword: "new-password-1"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 with no session, got %d", resp.StatusCode)
	}
}
