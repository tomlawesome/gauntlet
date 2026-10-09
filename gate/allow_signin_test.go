package gate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/oidc"
	"github.com/tomlawesome/gauntlet/persist"
)

// An administrator's allowance of an account's next sign-in (#81,
// ADR-0009 decision 11): what judging does with it, and the route that
// sets it.

// allow records the allowance for id at the fixture's clock, as the
// route would.
func (e *unusualEnv) allow(t *testing.T, id string) {
	t.Helper()
	if _, err := e.g.deps.Users.AllowNextSignIn(id, e.clock.now()); err != nil {
		t.Fatalf("AllowNextSignIn: %v", err)
	}
}

// signInResponse sends bob's password from b at address and returns the
// response, its status and its body.
func (e *unusualEnv) signInResponse(t *testing.T, b *browser, address string) (*http.Response, int, string) {
	t.Helper()
	resp := postJSON(t, b.at(address), e.ts.URL+"/api/auth/login",
		credentialsRequest{Username: totpBobUsername, Password: totpBobPassword})
	status, body := readAll(t, resp)
	return resp, status, body
}

func TestAllowedSignInCompletesUnderBlock(t *testing.T) {
	e, _ := newNotifiedEnv(t, UnusualSignInPolicy{NewBrowser: UnusualSignInBlock})
	e.mustSignIn(t, newTestBrowser(t), addrLondon)
	e.advance(time.Hour)

	b := newTestBrowser(t)
	if status, body := e.signIn(t, b, addrLondon); status != http.StatusForbidden {
		t.Fatalf("a new browser under block = %d %s, want 403", status, body)
	}

	e.allow(t, e.bobID)
	resp, status, body := e.signInResponse(t, b, addrLondon)
	if status != http.StatusOK || !strings.Contains(body, `"username"`) {
		t.Fatalf("the allowed sign-in = %d %s, want 200 with the account", status, body)
	}
	if c := cookieNamed(resp, e.g.sessionCookieName()); c == nil || c.MaxAge < 0 {
		t.Errorf("no session cookie on the allowed sign-in: %+v", c)
	}
	if c := cookieNamed(resp, knownBrowserCookieName); c == nil || c.Value == "" {
		t.Errorf("the allowed browser was not remembered: %+v", c)
	}
	if got := e.newestSession(t).Client.Unusual; got != gauntlet.SignalNewBrowser {
		t.Errorf("session signals = %q, want new-browser", got)
	}
	row := e.newestRow(t)
	if row.Outcome != gauntlet.SignInSuccess || row.Client.Unusual != gauntlet.SignalNewBrowser || !row.Confirmed {
		t.Errorf("history row = %+v, want a confirmed success with new-browser", row)
	}
	entry, ok := e.lastAudit("user.login")
	if want := `unusual=new-browser; action=block; allowed=used; notify=quiet; via admin allowance; from="` + addrLondon + `"`; !ok || entry.Detail != want {
		t.Errorf("user.login detail = %q, want %q", entry.Detail, want)
	}
	if u, _ := e.g.deps.Users.Get(e.bobID); !u.SignInAllowedUntil.IsZero() {
		t.Errorf("the allowance is still set after the sign-in it was for: %v", u.SignInAllowedUntil)
	}

	// Single use, and the browser it let in is now one the account
	// knows: the next sign-in from it raises nothing.
	e.mustSignIn(t, b, addrLondon)
	e.expectSignals(t, 0)
	if status, body := e.signIn(t, newTestBrowser(t), addrLondon); status != http.StatusForbidden {
		t.Errorf("another new browser after the allowance was spent = %d %s, want 403", status, body)
	}
}

func TestAllowanceExpires(t *testing.T) {
	e, _ := newNotifiedEnv(t, UnusualSignInPolicy{NewBrowser: UnusualSignInBlock})
	e.mustSignIn(t, newTestBrowser(t), addrLondon)
	e.advance(time.Hour)
	e.allow(t, e.bobID)
	e.advance(gauntlet.SignInAllowanceLifetime)
	resp := postJSON(t, newTestBrowser(t).at(addrLondon), e.ts.URL+"/api/auth/login",
		credentialsRequest{Username: totpBobUsername, Password: totpBobPassword})
	checkRefused(t, e.g, resp)
}

func TestAllowedSignInNeedsNoCodeOrPasskey(t *testing.T) {
	t.Run("confirm", func(t *testing.T) {
		e := newUnusualEnvWith(t, persist.NewMemory(), func(c *Config) {
			c.UnusualSignIns = UnusualSignInPolicy{NewBrowser: UnusualSignInConfirm}
			c.DeliverConfirmCode = func(context.Context, ConfirmCode) error {
				t.Error("a confirmation code was sent for an allowed sign-in")
				return nil
			}
		})
		e.mustSignIn(t, newTestBrowser(t), addrLondon)
		e.advance(time.Hour)
		e.allow(t, e.bobID)
		status, body := e.signIn(t, newTestBrowser(t), addrLondon)
		if status != http.StatusOK || !strings.Contains(body, `"username"`) {
			t.Fatalf("the allowed sign-in under confirm = %d %s, want 200 with the account", status, body)
		}
		entry, _ := e.lastAudit("user.login")
		if want := `unusual=new-browser; action=confirm; allowed=used; via admin allowance; from="` + addrLondon + `"`; entry.Detail != want {
			t.Errorf("user.login detail = %q, want %q", entry.Detail, want)
		}
	})
	t.Run("prove", func(t *testing.T) {
		e := newProveEnv(t)
		e.g.cfg.ClientIP = func(*http.Request) string { return addrLondon }
		if _, err := e.g.deps.Users.AllowNextSignIn(e.id, e.clock.now()); err != nil {
			t.Fatal(err)
		}
		resp, body := e.codeSignIn(t, newBrowserJar(t))
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"username"`) || strings.Contains(body, "prove") {
			t.Fatalf("the allowed sign-in under prove = %d %s, want 200 with the account", resp.StatusCode, body)
		}
		if codes := e.notices.allCodes(); len(codes) != 0 {
			t.Errorf("codes sent for an allowed sign-in: %+v", codes)
		}
		entry := findAuditEntry(t, e.g, "user.login")
		if want := `unusual=new-browser; action=prove; allowed=used; notify=asked; via admin allowance; from="` + addrLondon + `"`; entry.Detail != want {
			t.Errorf("user.login detail = %q, want %q", entry.Detail, want)
		}
	})
}

func TestAllowanceLetsAnSSOOnlyAccountIn(t *testing.T) {
	g, ts, fp := newOIDCTestGate(t, oidc.Policy{})
	g.cfg.Audit = &auditRecorder{}
	g.cfg.ClientIP = func(*http.Request) string { return addrLondon }
	g.cfg.UnusualSignIns = UnusualSignInPolicy{NewBrowser: UnusualSignInBlock}
	callback := func() *http.Response {
		t.Helper()
		fs, err := oidc.NewFlowState(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))
		client := noRedirectClient()
		client.Jar = mustCookieJar(t)
		resp, err := client.Do(oidcCallbackRequest(t, g, ts, fs, "state="+fs.State+"&code=test-code"))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}
	if resp := callback(); resp.Header.Get("Location") != "/" {
		t.Fatalf("the first SSO sign-in went to %q", resp.Header.Get("Location"))
	}
	if resp := callback(); resp.Header.Get("Location") != testLoginPath+"?ssoError=refused" {
		t.Fatalf("a new browser's SSO sign-in went to %q, want refused", resp.Header.Get("Location"))
	}

	var sso *gauntlet.User
	for _, u := range g.deps.Users.List() {
		if u.OIDCSubject != "" {
			sso = &u
		}
	}
	if sso == nil || sso.HasLocalPassword {
		t.Fatalf("no SSO-only account: %+v", sso)
	}
	if _, err := g.deps.Users.AllowNextSignIn(sso.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	resp := callback()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Errorf("the allowed SSO sign-in = %d to %q, want /", resp.StatusCode, resp.Header.Get("Location"))
	}
	if c := cookieNamed(resp, testCookieName); c == nil || c.MaxAge < 0 {
		t.Error("the allowed SSO sign-in set no session cookie")
	}
	entry := findAuditEntry(t, g, "user.login")
	if want := `unusual=new-browser; action=block; allowed=used; via admin allowance; from="` + addrLondon + `"`; entry.Detail != want {
		t.Errorf("user.login detail = %q, want %q", entry.Detail, want)
	}
}

func TestAllowedSignInNoticeSaysAllowed(t *testing.T) {
	e, rec := newNotifiedEnv(t, UnusualSignInPolicy{NewBrowser: UnusualSignInBlock})
	e.mustSignIn(t, newTestBrowser(t), addrLondon)
	e.advance(time.Hour)
	e.allow(t, e.bobID)
	e.mustSignIn(t, newTestBrowser(t), addrLondon)

	got := e.notices(rec)
	if len(got) != 1 || got[0].UnusualSignIn == nil {
		t.Fatalf("notices = %+v, want one unusual-sign-in notice", got)
	}
	u := got[0].UnusualSignIn
	sess := e.newestSession(t)
	if u.Reason != "allowed" || u.SessionRef == "" || u.SessionRef != sess.Ref() || u.Action != UnusualSignInBlock || u.Signals != gauntlet.SignalNewBrowser {
		t.Errorf("notice detail = %+v (session ref %s)", u, sess.Ref())
	}
}

// allowSignIn posts body to the allow-sign-in route for id as client.
func allowSignIn(t *testing.T, client *http.Client, ts *httptest.Server, id string, body any) *http.Response {
	t.Helper()
	return postJSON(t, client, ts.URL+"/api/auth/users/"+id+"/allow-sign-in", body)
}

func TestAdminAllowsAnotherAccountsNextSignIn(t *testing.T) {
	e, rec := newNotifiedEnv(t, UnusualSignInPolicy{NewBrowser: UnusualSignInBlock})
	admin := e.adminNow(t)
	now := e.clock.now()
	resp := allowSignIn(t, admin, e.ts, e.bobID, adminStepUpRequest{Password: testAdminPassword})
	status, body := readAll(t, resp)
	if status != http.StatusOK {
		t.Fatalf("allow-sign-in = %d %s", status, body)
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(body), &fields); err != nil || len(fields) != 2 {
		t.Errorf("body = %s, want exactly username and allowedUntil", body)
	}
	var out struct {
		Username     string    `json:"username"`
		AllowedUntil time.Time `json:"allowedUntil"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	until := now.Add(gauntlet.SignInAllowanceLifetime)
	if out.Username != totpBobUsername || !out.AllowedUntil.Equal(until) {
		t.Errorf("answer = %+v, want bob until %v", out, until)
	}
	if u, _ := e.g.deps.Users.Get(e.bobID); !u.SignInAllowed(now) || !u.SignInAllowedUntil.Equal(until) {
		t.Errorf("stored allowance ends %v, want %v", u.SignInAllowedUntil, until)
	}

	entry, ok := e.lastAudit("user.sign_in_allowed")
	if !ok || entry.Actor != "admin" || entry.Target != totpBobUsername ||
		!strings.Contains(entry.Detail, "next sign-in allowed until "+until.Format(time.RFC3339)+" ") ||
		strings.Contains(entry.Detail, "own account") {
		t.Errorf("user.sign_in_allowed = %+v", entry)
	}

	e.g.notifying.Wait()
	var notice *AccountNotice
	for _, n := range rec.all() {
		if n.Kind == NoticeSignInAllowed {
			notice = &n
		}
	}
	if notice == nil || notice.UserID != e.bobID || notice.Username != totpBobUsername || notice.Role != gauntlet.RoleUser ||
		notice.By != "admin" || !notice.At.Equal(now) || notice.SignInAllowed == nil || !notice.SignInAllowed.Until.Equal(until) {
		t.Errorf("notice = %+v", notice)
	}

	// A second call inside the window starts a fresh ten minutes.
	e.advance(3 * time.Minute)
	if status, body := readAll(t, allowSignIn(t, e.adminNow(t), e.ts, e.bobID, adminStepUpRequest{Password: testAdminPassword})); status != http.StatusOK {
		t.Fatalf("a second allow-sign-in = %d %s", status, body)
	}
	if u, _ := e.g.deps.Users.Get(e.bobID); !u.SignInAllowedUntil.Equal(e.clock.now().Add(gauntlet.SignInAllowanceLifetime)) {
		t.Errorf("after a second call the allowance ends %v", u.SignInAllowedUntil)
	}
}

func TestAdminAllowsTheirOwnNextSignIn(t *testing.T) {
	t.Run("code", func(t *testing.T) {
		g := newTestGate(t)
		g.cfg.Audit = &auditRecorder{}
		ts := newTestServer(t, g)
		admin := registerAdminNoFactor(t, ts, "admin", selfUnlockAdminPassword)
		secret, _, counter := enrolAdminTOTP(t, admin, ts)
		u, _ := g.deps.Users.ByUsername("admin")
		resp := allowSignIn(t, admin, ts, u.ID, unlockSelfRequest{Password: selfUnlockAdminPassword, Code: gauntlet.GenerateTOTPCode(secret, counter+1)})
		if status, body := readAll(t, resp); status != http.StatusOK {
			t.Fatalf("own allow-sign-in with password and code = %d %s", status, body)
		}
		if got, _ := g.deps.Users.Get(u.ID); got.SignInAllowedUntil.IsZero() {
			t.Error("no allowance recorded")
		}
		if e := findAuditEntry(t, g, "user.sign_in_allowed"); !strings.Contains(e.Detail, "; own account, password and second factor re-entered") {
			t.Errorf("audit detail = %q", e.Detail)
		}
	})
	t.Run("passkey", func(t *testing.T) {
		g, ts, admin, fake, adminID, _ := passkeyStepUpFixture(t)
		resp := allowSignIn(t, admin, ts, adminID, unlockSelfRequest{Password: doorTestPassword, Assertion: signStepUp(t, fake, stepUpOptions(t, admin, ts))})
		if status, body := readAll(t, resp); status != http.StatusOK {
			t.Fatalf("own allow-sign-in with password and passkey = %d %s", status, body)
		}
		if e := findAuditEntry(t, g, "user.sign_in_allowed"); !strings.Contains(e.Detail, "; own account, password and passkey re-entered") {
			t.Errorf("audit detail = %q", e.Detail)
		}
	})
}

func TestAllowSignInRefusals(t *testing.T) {
	allowed := func(g *Gate, id string) bool {
		u, ok := g.deps.Users.Get(id)
		return ok && !u.SignInAllowedUntil.IsZero()
	}
	t.Run("another account, no or wrong password", func(t *testing.T) {
		g, ts, admin, id := stepUpFixture(t)
		g.deps.Limiter = mustNewLoginLimiter(t, 2, time.Minute)
		wantProblem(t, allowSignIn(t, admin, ts, id, adminStepUpRequest{}), http.StatusUnauthorized, classInvalidCredentials)
		wantProblem(t, allowSignIn(t, admin, ts, id, adminStepUpRequest{Password: "not-the-password"}), http.StatusUnauthorized, classInvalidCredentials)
		// Both counted on the re-check budget: the right one is now 429.
		wantProblem(t, allowSignIn(t, admin, ts, id, adminStepUpRequest{Password: testAdminPassword}), http.StatusTooManyRequests, classRateLimited)
		if allowed(g, id) {
			t.Error("a refused request recorded an allowance")
		}
	})
	t.Run("own account, no code", func(t *testing.T) {
		g, ts, admin, _ := stepUpFixture(t)
		u, _ := g.deps.Users.ByUsername("admin")
		wantProblem(t, allowSignIn(t, admin, ts, u.ID, unlockSelfRequest{Password: testAdminPassword}), http.StatusBadRequest, classInvalidRequest)
		if allowed(g, u.ID) {
			t.Error("a refused request recorded an allowance")
		}
	})
	t.Run("not an admin", func(t *testing.T) {
		g, ts, _ := totpFixture(t)
		bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
		totpEnrolAndConfirm(t, bob, ts) // past the enrolment door, so the role is what refuses
		admin, _ := g.deps.Users.ByUsername("admin")
		bobID := totpBobID(t, g)
		wantProblem(t, allowSignIn(t, bob, ts, admin.ID, adminStepUpRequest{Password: totpBobPassword}), http.StatusForbidden, classForbidden)
		wantProblem(t, allowSignIn(t, bob, ts, bobID, unlockSelfRequest{Password: totpBobPassword, Code: "123456"}), http.StatusForbidden, classForbidden)
		if allowed(g, admin.ID) || allowed(g, bobID) {
			t.Error("a non-admin recorded an allowance")
		}
	})
	t.Run("another account, a second factor in the body", func(t *testing.T) {
		g, ts, admin, id := stepUpFixture(t)
		g.deps.Limiter = mustNewLoginLimiter(t, 1, time.Minute)
		for _, body := range []any{
			unlockSelfRequest{Password: testAdminPassword, Code: "123456"},
			map[string]any{"password": testAdminPassword, "assertion": map[string]any{"id": "x"}},
		} {
			wantProblem(t, allowSignIn(t, admin, ts, id, body), http.StatusBadRequest, classInvalidRequest)
		}
		if allowed(g, id) {
			t.Error("a refused request recorded an allowance")
		}
		// Refused before the password is checked: nothing counted.
		if status, body := readAll(t, allowSignIn(t, admin, ts, id, adminStepUpRequest{Password: testAdminPassword})); status != http.StatusOK {
			t.Errorf("then the password alone = %d %s, want 200", status, body)
		}
	})
	t.Run("unknown account", func(t *testing.T) {
		_, ts, admin, _ := stepUpFixture(t)
		wantProblem(t, allowSignIn(t, admin, ts, "no-such-id", adminStepUpRequest{Password: testAdminPassword}), http.StatusNotFound, classNotFound)
	})
	t.Run("SSO-only caller", func(t *testing.T) {
		g, ts, _, id := stepUpFixture(t)
		_, ann := ssoOnlyAdmin(t, g, ts, "subject-ann")
		resp := allowSignIn(t, ann, ts, id, adminStepUpRequest{Password: "anything-at-all"})
		if status, body := readAll(t, resp); status != http.StatusConflict || !strings.Contains(body, "local password") {
			t.Errorf("allow-sign-in by an SSO-only admin = %d %s, want 409 naming the local password", status, body)
		}
		if allowed(g, id) {
			t.Error("an SSO-only admin recorded an allowance")
		}
	})
	t.Run("unreadable body", func(t *testing.T) {
		g, ts, admin, id := stepUpFixture(t)
		wantProblem(t, allowSignIn(t, admin, ts, id, "not an object"), http.StatusBadRequest, classInvalidRequest)
		if allowed(g, id) {
			t.Error("a bad body recorded an allowance")
		}
	})
	t.Run("no CSRF header", func(t *testing.T) {
		g, ts, admin, id := stepUpFixture(t)
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/users/"+id+"/allow-sign-in",
			strings.NewReader(`{"password":"`+testAdminPassword+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := admin.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if status, body := readAll(t, resp); status != http.StatusForbidden {
			t.Errorf("without the CSRF header = %d %s, want 403", status, body)
		}
		if allowed(g, id) {
			t.Error("a request without the CSRF header recorded an allowance")
		}
	})
}
