package gate

import (
	"context"
	"net/http"
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
	if !ok || !strings.HasPrefix(entry.Detail, "unusual=new-browser; action=block; allowed=used; ") {
		t.Errorf("user.login detail = %q", entry.Detail)
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
		if entry, _ := e.lastAudit("user.login"); !strings.HasPrefix(entry.Detail, "unusual=new-browser; action=confirm; allowed=used; ") {
			t.Errorf("user.login detail = %q", entry.Detail)
		}
	})
	t.Run("prove", func(t *testing.T) {
		e := newProveEnv(t)
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
		if entry := findAuditEntry(t, e.g, "user.login"); !strings.HasPrefix(entry.Detail, "unusual=new-browser; action=prove; allowed=used; ") {
			t.Errorf("user.login detail = %q", entry.Detail)
		}
	})
}

func TestAllowanceLetsAnSSOOnlyAccountIn(t *testing.T) {
	g, ts, fp := newOIDCTestGate(t, oidc.Policy{})
	g.cfg.Audit = &auditRecorder{}
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
	if entry := findAuditEntry(t, g, "user.login"); !strings.HasPrefix(entry.Detail, "unusual=new-browser; action=block; allowed=used; ") {
		t.Errorf("user.login detail = %q", entry.Detail)
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
