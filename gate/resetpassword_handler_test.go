// Ported from mikroview's internal/api/auth_test.go/resetpassword_test.go
// equivalents for the admin password-reset route (docs/design.md §1.5).
package gate

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestAdminResetPasswordHappyPath(t *testing.T) {
	g, ts, admin := totpFixture(t)
	id := totpBobID(t, g)

	resp := postJSON(t, admin, ts.URL+"/api/auth/users/"+id+"/reset-password", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset-password returned %d", resp.StatusCode)
	}
	var out resetPasswordResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Username != totpBobUsername || out.Code == "" {
		t.Errorf("reset-password response = %+v, want username %q and a non-empty code", out, totpBobUsername)
	}

	// The old password no longer works; the code does, as the current
	// password (this stage carries no dedicated redeem-and-set-password
	// route yet -- Store.Authenticate itself accepts a live reset code
	// in place of the password, per its own doc comment).
	oldPW := postJSON(t, &http.Client{}, ts.URL+"/api/auth/login", credentialsRequest{Username: totpBobUsername, Password: totpBobPassword})
	defer func() { _ = oldPW.Body.Close() }()
	if oldPW.StatusCode != http.StatusUnauthorized {
		t.Errorf("the old password after a reset got %d, want 401", oldPW.StatusCode)
	}

	viaCode := postJSON(t, &http.Client{}, ts.URL+"/api/auth/login", credentialsRequest{Username: totpBobUsername, Password: out.Code})
	defer func() { _ = viaCode.Body.Close() }()
	if viaCode.StatusCode != http.StatusOK {
		t.Errorf("logging in with the reset code got %d, want 200", viaCode.StatusCode)
	}
}

func TestAdminCannotResetOwnPassword(t *testing.T) {
	g, ts, admin := totpFixture(t)
	adminUser, ok := g.deps.Users.ByUsername("admin")
	if !ok {
		t.Fatal("no admin account")
	}

	resp := postJSON(t, admin, ts.URL+"/api/auth/users/"+adminUser.ID+"/reset-password", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("an admin resetting their own password got %d, want 409", resp.StatusCode)
	}
}

func TestResetPasswordRefusedForSSOOnlyAccount(t *testing.T) {
	g, ts, admin := totpFixture(t)
	u, _, err := g.deps.Users.FindOrCreateOIDCUser("https://idp.example", "subject-placeholder", "frodo", nowUTC())
	if err != nil {
		t.Fatal(err)
	}

	resp := postJSON(t, admin, ts.URL+"/api/auth/users/"+u.ID+"/reset-password", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("resetting an SSO-only account got %d, want 409", resp.StatusCode)
	}
}

func TestResetPasswordNotFound(t *testing.T) {
	_, ts, admin := totpFixture(t)
	resp := postJSON(t, admin, ts.URL+"/api/auth/users/not-a-real-user-id/reset-password", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("resetting an unknown user got %d, want 404", resp.StatusCode)
	}
}

func TestResetPasswordRequiresAdmin(t *testing.T) {
	g, ts, _ := totpFixture(t)
	id := totpBobID(t, g)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)

	resp := postJSON(t, bob, ts.URL+"/api/auth/users/"+id+"/reset-password", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("a non-admin resetting a password got %d, want 403", resp.StatusCode)
	}
}
