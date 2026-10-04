package gate

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// TestRequireRoleBelowMinIsRefused is a direct unit test for the
// below-role 403 case, independent of any HTTP routing.
func TestRequireRoleBelowMinIsRefused(t *testing.T) {
	ok := false
	h := RequireRole(gauntlet.RoleAdmin, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok = true
		w.WriteHeader(http.StatusOK)
	}))

	for _, tc := range []struct {
		name string
		user *gauntlet.User
		want int
	}{
		{"no user in context", nil, http.StatusForbidden},
		{"viewer below admin", &gauntlet.User{Role: gauntlet.RoleViewer}, http.StatusForbidden},
		{"user below admin", &gauntlet.User{Role: gauntlet.RoleUser}, http.StatusForbidden},
		{"admin at min", &gauntlet.User{Role: gauntlet.RoleAdmin}, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok = false
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			if tc.user != nil {
				req = req.WithContext(withUser(req.Context(), tc.user))
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
			if tc.want == http.StatusOK && !ok {
				t.Error("expected next to have run")
			}
			if tc.want != http.StatusOK && ok {
				t.Error("expected next NOT to have run")
			}
		})
	}
}

func TestUserAndTokenFromContextDefaultNil(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if u := UserFromContext(req); u != nil {
		t.Errorf("expected nil user on a bare request, got %+v", u)
	}
	if tok := TokenFromContext(req); tok != nil {
		t.Errorf("expected nil token on a bare request, got %+v", tok)
	}
}

// TestExemptAddsBeyondBuiltInSet pins Gate.Exempt: a path added through
// it becomes reachable without a session, alongside the built-in
// /api/auth/* set, without needing a code change to exemptPaths itself.
func TestExemptAddsBeyondBuiltInSet(t *testing.T) {
	g := newTestGate(t)
	g.Exempt("/api/public-thing")
	appMux := http.NewServeMux()
	appMux.HandleFunc("GET /api/public-thing", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	appMux.Handle("/", g.Routes())
	ts := httptest.NewServer(g.Protect(appMux))
	defer ts.Close()
	testServerGates.Store(ts, g)

	registerAdmin(t, ts, "admin", "password-placeholder-1")

	resp, err := http.Get(ts.URL + "/api/public-thing")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected the Exempt-added path to be reachable with no session, got %d", resp.StatusCode)
	}
}

// primeMustChangePasswordAdmin returns a Store whose one account --
// "admin", password "password-placeholder-1" -- already carries
// MustChangePassword=true. No method in this stage's Store sets that
// field (SetPassword is the only public write path, and it clears the
// flag as part of what it does), so the fixture primes a persist.Memory
// document directly (openStoreWithUsers), the same way a hand-built
// accounts file would.
func primeMustChangePasswordAdmin(t *testing.T) *gauntlet.Store {
	t.Helper()
	hash, err := gauntlet.HashPassword("password-placeholder-1")
	if err != nil {
		t.Fatal(err)
	}
	return openStoreWithUsers(t, gauntlet.User{
		ID:                 "admin-1",
		Username:           "admin",
		PasswordHash:       hash,
		Role:               gauntlet.RoleAdmin,
		CreatedAt:          time.Now(),
		HasLocalPassword:   true,
		MustChangePassword: true,
	})
}

// TestMustChangePasswordDoesNotDeadlockWithSecondFactorDoor pins the fix
// ported from mikroview's own gitlab/dev 683704c4: a session stuck at
// MustChangePassword must still be able to reach changePasswordPath even
// though the second-factor door is shut and the account has no factor
// yet -- without the !user.MustChangePassword guard in Protect, that
// request would be refused by the second-factor door too, with no path
// left to escape it.
func TestMustChangePasswordDoesNotDeadlockWithSecondFactorDoor(t *testing.T) {
	g := newTestGate(t)
	g.deps.Users = primeMustChangePasswordAdmin(t)
	ts := newTestServer(t, g)

	client := &http.Client{Jar: mustCookieJar(t)}
	loginResp := postJSON(t, client, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "password-placeholder-1"})
	_ = loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected login to succeed, got %d", loginResp.StatusCode)
	}

	resp := postJSON(t, client, ts.URL+"/api/auth/password", changePasswordRequest{NewPassword: "a-new-password"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected the change-password route to stay reachable for a MustChangePassword session even with the second-factor door shut, got %d", resp.StatusCode)
	}
}

// TestSessionMustEnrolSecondFactorFollowsMustChangePasswordDoor pins
// gauntlet#58 F2: while MustChangePassword holds, Protect refuses the
// enrol routes with 403 (the guard above), so GET /api/auth/session
// must report mustEnrolSecondFactor as false too -- it names the door
// Protect enforces, not the raw HasSecondFactor fact, and that door is
// shut here.
func TestSessionMustEnrolSecondFactorFollowsMustChangePasswordDoor(t *testing.T) {
	g := newTestGate(t)
	g.deps.Users = primeMustChangePasswordAdmin(t)
	ts := newTestServer(t, g)

	client := &http.Client{Jar: mustCookieJar(t)}
	loginResp := postJSON(t, client, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "password-placeholder-1"})
	_ = loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("expected login to succeed, got %d", loginResp.StatusCode)
	}

	enrol := postJSON(t, client, ts.URL+"/api/auth/totp/enrol", totpEnrolRequest{Password: "password-placeholder-1"})
	_ = enrol.Body.Close()
	if enrol.StatusCode != http.StatusForbidden {
		t.Fatalf("precondition: expected the enrol route to be refused while MustChangePassword holds, got %d", enrol.StatusCode)
	}

	sess := sessionOf(t, client, ts)
	if sess.MustEnrolSecondFactor {
		t.Errorf("mustEnrolSecondFactor = true while the enrol routes answer 403 must-change-password; the flag should follow the routes")
	}
}

// TestForcedAuthGateHeaderNamesTheDoor pins the machine-readable header
// (protect.go's authGateHeader) that lets a frontend tell a forced-door
// 403 apart from an ordinary refusal.
func TestForcedAuthGateHeaderNamesTheDoor(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := registerAdminNoFactor(t, ts, "admin", "password-placeholder-1")

	resp, err := client.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get(authGateHeader); got != authGateMustEnrolFactor {
		t.Errorf("expected %s: %s, got %q", authGateHeader, authGateMustEnrolFactor, got)
	}
}
