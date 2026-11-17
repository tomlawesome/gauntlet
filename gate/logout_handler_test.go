package gate

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/oidc"
)

// Sign out everywhere asks for no credential, so the session it issues
// continues the caller's and keeps that sign-in's 24-hour ceiling.
// Issued as a fresh sign-in, a cookie used on this route once an hour
// would never expire.
func TestLogoutAllKeepsTheOriginalCeiling(t *testing.T) {
	f := newResumeFixture(t)
	before, ok := f.g.deps.Sessions.Validate(f.cookie, f.clock.now())
	if !ok {
		t.Fatal("bob's session is not live")
	}

	f.keepAlive(t, 23*time.Hour, f.bob)
	resp := postJSON(t, f.bob, f.ts.URL+"/api/auth/logout-all", logoutAllRequest{Password: totpBobPassword})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout-all at +23h returned %d", resp.StatusCode)
	}
	maxAge := 0
	for _, c := range resp.Cookies() {
		if c.Name == testCookieName {
			maxAge = c.MaxAge
		}
	}
	if maxAge <= 0 || maxAge > 60*60 {
		t.Errorf("cookie Max-Age = %d, want at most the hour left to the ceiling", maxAge)
	}

	after := sessionCookie(t, f.bob, f.ts)
	if after == f.cookie {
		t.Fatal("logout-all kept the old session ID")
	}
	sess, ok := f.g.deps.Sessions.Validate(after, f.clock.now())
	if !ok {
		t.Fatal("the session logout-all issued is not live")
	}
	if !sess.IssuedAt.Equal(before.IssuedAt) {
		t.Errorf("IssuedAt = %v, want the original sign-in's %v", sess.IssuedAt, before.IssuedAt)
	}

	f.at(23*time.Hour + 30*time.Minute)
	if got := protectedStatus(t, f.bob, f.ts); got != http.StatusOK {
		t.Fatalf("the new session was refused inside the ceiling: %d", got)
	}
	f.at(24*time.Hour + time.Second)
	if got := protectedStatus(t, f.bob, f.ts); got != http.StatusUnauthorized {
		t.Errorf("the session from logout-all outlived the original ceiling: %d", got)
	}
}

// Sign out everywhere forgets every browser the account remembers, so a
// stolen cookie alone must not reach it: an account with a local
// password gives it again. No password, or a wrong one, is 401 and
// leaves every session and every remembered browser as it was.
func TestLogoutAllAsksForThePassword(t *testing.T) {
	g, ts, _ := totpFixture(t)
	id := totpBobID(t, g)
	browserA := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	secret, _, counter := totpEnrolAndConfirm(t, browserA, ts) // past the enrolment door
	browserB := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	if status, body := readAll(t, submitLoginFactor(t, browserB, ts, gauntlet.GenerateTOTPCode(secret, counter+1))); status != http.StatusOK {
		t.Fatalf("browser B's sign-in = %d %s", status, body)
	}
	tokenB := knownToken(t, browserB, ts)

	for name, body := range map[string]any{
		"no body":        nil,
		"no password":    map[string]any{},
		"wrong password": logoutAllRequest{Password: "not-bobs-password"},
	} {
		if status, raw := readAll(t, postJSON(t, browserA, ts.URL+"/api/auth/logout-all", body)); status != http.StatusUnauthorized {
			t.Errorf("%s: sign out everywhere = %d %s, want 401", name, status, raw)
		}
		if got := protectedStatus(t, browserB, ts); got != http.StatusOK {
			t.Errorf("%s: browser B's session was ended (%d)", name, got)
		}
		if !g.deps.Users.KnowsBrowser(id, tokenB, g.now()) {
			t.Errorf("%s: browser B was forgotten", name)
		}
	}

	if status, raw := readAll(t, postJSON(t, browserA, ts.URL+"/api/auth/logout-all", logoutAllRequest{Password: totpBobPassword})); status != http.StatusOK {
		t.Fatalf("sign out everywhere with the password = %d %s", status, raw)
	}
	if got := protectedStatus(t, browserB, ts); got != http.StatusUnauthorized {
		t.Errorf("browser B's session outlived sign out everywhere (%d)", got)
	}
	if g.deps.Users.KnowsBrowser(id, tokenB, g.now()) {
		t.Error("sign out everywhere with the password left browser B known")
	}
}

// An SSO-only account has no password to give, so its sign out
// everywhere ends every session but keeps what the account trusts: a
// cookie alone must not wipe the unusual-sign-in baseline. The calling
// browser stays remembered, the other one too, and the audit says the
// browsers were kept.
func TestLogoutAllWithoutAPasswordKeepsTheBaseline(t *testing.T) {
	g, ts, fp := newOIDCTestGate(t, oidc.Policy{})
	g.cfg.Audit = &auditRecorder{}
	signIn := func() *http.Client {
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
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
			t.Fatalf("callback = %d to %q", resp.StatusCode, resp.Header.Get("Location"))
		}
		return client
	}
	browserA, browserB := signIn(), signIn()
	tokenB := knownToken(t, browserB, ts)
	u, ok := g.deps.Users.ByOIDCIdentity(fp.Issuer(), "test-subject-123")
	if !ok || u.LocalPassword() {
		t.Fatalf("precondition: an SSO-only account, got %+v", u)
	}

	if status, raw := readAll(t, postJSON(t, browserA, ts.URL+"/api/auth/logout-all", nil)); status != http.StatusOK {
		t.Fatalf("sign out everywhere = %d %s", status, raw)
	}
	if got := protectedStatus(t, browserB, ts); got != http.StatusUnauthorized {
		t.Errorf("browser B's session outlived sign out everywhere (%d)", got)
	}
	now := g.now()
	if !g.deps.Users.KnowsBrowser(u.ID, tokenB, now) {
		t.Error("an SSO-only sign out everywhere forgot the other remembered browser")
	}
	if !g.deps.Users.KnowsBrowser(u.ID, knownToken(t, browserA, ts), now) {
		t.Error("an SSO-only sign out everywhere did not remember the calling browser")
	}
	if entry := findAuditEntry(t, g, "account.sessions_ended"); !strings.Contains(entry.Detail, "remembered browsers kept") {
		t.Errorf("audit detail = %q, want it to say the browsers were kept", entry.Detail)
	}
}
