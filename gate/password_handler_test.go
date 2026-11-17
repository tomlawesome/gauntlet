// Ported from mikroview's internal/api/auth_test.go: the
// handleAuthChangePassword cases.
package gate

import (
	"bytes"
	"context"
	"io"
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
	// A fresh SSO sign-in, as the callback leaves it.
	sess := g.deps.Sessions.CreateFrom(u.ID, gauntlet.SessionClient{Method: gauntlet.SignInMethodSSO}, time.Now())
	return u.ID, sessionClient(t, ts.URL, sess.ID)
}

// The cookie alone is what a thief holds, so an SSO-only admin sets its
// first password only from a session its identity provider issued in
// the last ten minutes: an older one, or one made any other way, is
// 409 and sets nothing.
func TestSSOOnlyAdminFirstPasswordNeedsAFreshSSOSignIn(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	registerAdmin(t, ts, "admin", "password-placeholder-1")
	id, _ := ssoOnlyAdmin(t, g, ts, "subject-ann")

	for name, sess := range map[string]gauntlet.Session{
		"an SSO session eleven minutes old": g.deps.Sessions.CreateFrom(id, gauntlet.SessionClient{Method: gauntlet.SignInMethodSSO}, time.Now().Add(-11*time.Minute)),
		"a fresh session not made by SSO":   g.deps.Sessions.CreateFrom(id, gauntlet.SessionClient{Method: gauntlet.SignInMethodPassword}, time.Now()),
		"a fresh session with no method":    g.deps.Sessions.Create(id, time.Now()),
	} {
		resp := postJSON(t, sessionClient(t, ts.URL, sess.ID), ts.URL+"/api/auth/password", changePasswordRequest{NewPassword: "new-password-1"})
		status, body := readAll(t, resp)
		if status != http.StatusConflict || !strings.Contains(body, "sign in again through your identity provider") {
			t.Errorf("%s = %d %s, want 409 asking for a fresh SSO sign-in", name, status, body)
		}
	}
	if u, _ := g.deps.Users.Get(id); u.LocalPassword() {
		t.Error("a refused request set a local password")
	}
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

// A forced change asks for no current password, so the handler has none
// to compare the new one with: the stored hash answers instead. Setting
// the same password again is refused; a different one is accepted and
// lifts the flag.
func TestForcedPasswordChangeRefusesTheSamePassword(t *testing.T) {
	g := newTestGate(t)
	g.deps.Users = primeMustChangePasswordAdmin(t)
	ts := newTestServer(t, g)

	client := &http.Client{Jar: mustCookieJar(t)}
	login := postJSON(t, client, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "password-placeholder-1"})
	_ = login.Body.Close()
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login got %d, want 200", login.StatusCode)
	}

	same := postJSON(t, client, ts.URL+"/api/auth/password", changePasswordRequest{NewPassword: "password-placeholder-1"})
	status, body := readAll(t, same)
	if status != http.StatusBadRequest || !strings.Contains(body, "same as the current one") {
		t.Errorf("resubmitting the current password under a forced change = %d %s, want 400 naming it", status, body)
	}
	if u, _ := g.deps.Users.Get("admin-1"); !u.MustChangePassword {
		t.Fatal("the refused change lifted MustChangePassword")
	}

	changed := postJSON(t, client, ts.URL+"/api/auth/password", changePasswordRequest{NewPassword: "a-new-password"})
	_ = changed.Body.Close()
	if changed.StatusCode != http.StatusOK {
		t.Fatalf("a different password under a forced change got %d, want 200", changed.StatusCode)
	}
	if u, _ := g.deps.Users.Get("admin-1"); u.MustChangePassword {
		t.Error("MustChangePassword is still set after a new password")
	}
}

// Signing in with a reset code spends it, but the code was seen by the
// admin who issued it, and the forced change exists to retire it: set
// as the new password it is refused like the current one. A different
// password is accepted, and nothing of the code is kept after that.
func TestForcedPasswordChangeRefusesTheSpentResetCode(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	registerAdminNoFactor(t, ts, "admin", "password-placeholder-1")
	u, _ := g.deps.Users.ByUsername("admin")
	_, code, err := g.deps.Users.IssueResetCode(u.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: mustCookieJar(t)}
	login := postJSON(t, client, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: code})
	_ = login.Body.Close()
	if login.StatusCode != http.StatusOK {
		t.Fatalf("signing in with the reset code got %d, want 200", login.StatusCode)
	}

	for _, typed := range []string{code, gauntlet.FormatResetCode(code)} {
		status, body := readAll(t, postJSON(t, client, ts.URL+"/api/auth/password", changePasswordRequest{NewPassword: typed}))
		if status != http.StatusBadRequest || !strings.Contains(body, "same as the current one") {
			t.Errorf("setting the spent reset code %q as the password = %d %s, want 400", typed, status, body)
		}
	}

	changed := postJSON(t, client, ts.URL+"/api/auth/password", changePasswordRequest{NewPassword: "a-new-password"})
	_ = changed.Body.Close()
	if changed.StatusCode != http.StatusOK {
		t.Fatalf("a different password got %d, want 200", changed.StatusCode)
	}
	after, _ := g.deps.Users.Get(u.ID)
	if after.MustChangePassword || after.ResetCodeSpentHash != "" {
		t.Errorf("after the change: MustChangePassword %v, ResetCodeSpentHash %q; want false, empty", after.MustChangePassword, after.ResetCodeSpentHash)
	}
}

// resetDuringCheck is a gauntlet.BreachChecker that issues an admin
// reset for the account it is pointed at on its first call: the window
// a password change leaves between reading the account and saving.
type resetDuringCheck struct {
	once  sync.Once
	users *gauntlet.Store
	id    string
}

func (c *resetDuringCheck) Breached(context.Context, string) (bool, error) {
	if c.users != nil {
		c.once.Do(func() { _, _, _ = c.users.IssueResetCode(c.id, time.Now()) })
	}
	return false, nil
}

// An admin reset that lands while the owner's own password change is
// being checked wins (#80): the change answers 409 and saves nothing,
// so the code the admin read out still works.
func TestChangePasswordRacingAnAdminResetIs409(t *testing.T) {
	checker := &resetDuringCheck{}
	var code string
	users, err := gauntlet.OpenStore(persist.NewMemory(), gauntlet.Options{
		OnSetupCode: gauntlet.SetupCodeFunc(func(c string) { code = c }),
		BreachCheck: checker,
	})
	if err != nil {
		t.Fatal(err)
	}
	testSetupCodes.Store(users, code)
	t.Cleanup(func() { testSetupCodes.Delete(users) })
	g := newTestGateWithUsers(t, users)
	ts := newTestServer(t, g)
	client := registerAdmin(t, ts, "admin", "password-placeholder-1")
	admin, _ := users.ByUsername("admin")
	checker.id, checker.users = admin.ID, users

	resp := postJSON(t, client, ts.URL+"/api/auth/password", changePasswordRequest{CurrentPassword: "password-placeholder-1", NewPassword: "new-password-1"})
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	body := decodeProblem(t, raw)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body.Detail, "reset") {
		t.Fatalf("a change racing a reset got %d %q, want 409 naming the reset", resp.StatusCode, body.Detail)
	}
	if u, _ := users.Get(admin.ID); !u.MustChangePassword {
		t.Error("the reset did not stand")
	}
}
