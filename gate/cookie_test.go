// The session cookie's hardening (#47): the __Host- prefix once the
// cookie is Secure, a browser lifetime tied to the session store's
// ceiling, a startup warning when SecureCookie is off, and the session
// a login replaces being ended rather than left to idle out.
package gate

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/oidc"
)

// sessionCookieFrom returns the session cookie resp set under name, or
// nil when it set none.
func sessionCookieFrom(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// jarSessionID is the session id client would send to ts's root, under
// name -- the cookie jar's copy of what the last sign-in issued.
func jarSessionID(t *testing.T, client *http.Client, ts *httptest.Server, name string) string {
	t.Helper()
	u, err := url.Parse(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	t.Fatalf("client holds no %s cookie", name)
	return ""
}

// TestSessionCookieHostPrefixWhenSecure: with SecureCookie on, the
// cookie is written and read as __Host- + CookieName (ASVS 3.3.3, SP
// 800-63B-4 §5.1.1), and the bare name is not a session any more.
func TestSessionCookieHostPrefixWhenSecure(t *testing.T) {
	g := newTestGate(t)
	g.cfg.SecureCookie = true
	ts := newTestServer(t, g)

	client := &http.Client{Jar: mustCookieJar(t)}
	resp := postJSON(t, client, ts.URL+"/api/auth/register", registerRequest{Username: "admin", Password: "password-placeholder-345", SetupCode: setupCodeFor(t, g)})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: status %d, want 201", resp.StatusCode)
	}
	want := "__Host-" + testCookieName
	c := sessionCookieFrom(resp, want)
	if c == nil {
		t.Fatalf("register set cookies %v, want one named %s", resp.Cookies(), want)
	}
	if !c.Secure || c.Path != "/" || c.Domain != "" || !c.HttpOnly {
		t.Errorf("%s = %+v, want Secure, Path=/, no Domain, HttpOnly -- the attributes __Host- requires", want, c)
	}
	if sessionCookieFrom(resp, testCookieName) != nil {
		t.Errorf("register also set the bare %s cookie; the prefixed name is the only session cookie", testCookieName)
	}

	// Read under the prefixed name only: a cookie under the bare name,
	// which a browser would accept without any of __Host-'s guarantees,
	// is not consulted. The new account holds no second factor yet, so
	// a recognised session is stopped at the enrolment door (403, #49);
	// an unrecognised cookie is no session at all (401).
	if got := protectedStatusWithCookie(t, http.DefaultClient, ts.URL, &http.Cookie{Name: want, Value: c.Value}); got != http.StatusForbidden {
		t.Errorf("protected route with the %s cookie: %d, want 403 (a session, parked at the second-factor door)", want, got)
	}
	if got := protectedStatusWithCookie(t, http.DefaultClient, ts.URL, &http.Cookie{Name: testCookieName, Value: c.Value}); got != http.StatusUnauthorized {
		t.Errorf("protected route with the bare %s cookie: %d, want 401", testCookieName, got)
	}

	// Logout clears the same name it set.
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/logout", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrfHeaderName, testCSRFValue)
	req.AddCookie(&http.Cookie{Name: want, Value: c.Value})
	out, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = out.Body.Close()
	if !cookieCleared(out, want) {
		t.Errorf("logout did not clear %s: %v", want, out.Cookies())
	}
}

// TestSessionCookieBareNameWhenInsecure: with SecureCookie off (plain
// HTTP, development) the cookie keeps the configured name -- a browser
// refuses a __Host- cookie that is not Secure, so prefixing it there
// would sign nobody in.
func TestSessionCookieBareNameWhenInsecure(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := &http.Client{Jar: mustCookieJar(t)}
	resp := postJSON(t, client, ts.URL+"/api/auth/register", registerRequest{Username: "admin", Password: "password-placeholder-345", SetupCode: setupCodeFor(t, g)})
	_ = resp.Body.Close()
	if sessionCookieFrom(resp, testCookieName) == nil {
		t.Errorf("register set cookies %v, want the bare %s", resp.Cookies(), testCookieName)
	}
	if sessionCookieFrom(resp, "__Host-"+testCookieName) != nil {
		t.Error("register set a __Host- cookie without Secure; a browser would drop it")
	}
}

// TestNewRefusesPrefixedCookieName: gate adds the prefix itself, so a
// CookieName that already carries one would be doubled under TLS and,
// under plain HTTP, silently dropped by every browser.
func TestNewRefusesPrefixedCookieName(t *testing.T) {
	deps := validDeps(t)
	for _, name := range []string{"__Host-session", "__Secure-session"} {
		cfg := validConfig()
		cfg.CookieName = name
		_, err := New(cfg, deps)
		if err == nil || !strings.Contains(err.Error(), "Config.CookieName") {
			t.Errorf("New with CookieName %q: err = %v, want a refusal naming Config.CookieName", name, err)
		}
	}
}

// TestSessionCookieMaxAgeIsSessionCeiling: the browser forgets the
// cookie when the session can no longer be valid -- Max-Age equals the
// store's lifetime ceiling, not a fixed 30 days (SP 800-63B-4 §5.1.1:
// expire at or soon after the session).
func TestSessionCookieMaxAgeIsSessionCeiling(t *testing.T) {
	g := newTestGate(t)
	ceiling := 6 * time.Hour
	g.deps.Sessions = gauntlet.NewSessionStore(time.Hour, ceiling)
	ts := newTestServer(t, g)
	client := &http.Client{Jar: mustCookieJar(t)}
	resp := postJSON(t, client, ts.URL+"/api/auth/register", registerRequest{Username: "admin", Password: "password-placeholder-345", SetupCode: setupCodeFor(t, g)})
	_ = resp.Body.Close()
	c := sessionCookieFrom(resp, testCookieName)
	if c == nil {
		t.Fatalf("register set no %s cookie", testCookieName)
	}
	if c.MaxAge != int(ceiling.Seconds()) {
		t.Errorf("session cookie Max-Age = %d, want the store's ceiling %d", c.MaxAge, int(ceiling.Seconds()))
	}
}

// TestNewWarnsWhenSecureCookieOff: a deployment that leaves
// SecureCookie false gets exactly one startup warning naming the
// setting (ASVS 3.3.1, SP 800-63B-4 §5.1.1 Secure SHALL), and none
// when it is on -- birdcage's startup is designed to show it.
func TestNewWarnsWhenSecureCookieOff(t *testing.T) {
	for _, secure := range []bool{false, true} {
		rec := &messageRecorder{}
		cfg := validConfig()
		cfg.Log = slog.New(rec)
		cfg.SecureCookie = secure
		if _, err := New(cfg, validDeps(t)); err != nil {
			t.Fatal(err)
		}
		var warned []string
		for _, m := range rec.msgs {
			if strings.Contains(m, "SecureCookie") {
				warned = append(warned, m)
			}
		}
		if secure && len(warned) != 0 {
			t.Errorf("SecureCookie=true: New logged %q, want no warning", warned)
		}
		if !secure && len(warned) != 1 {
			t.Errorf("SecureCookie=false: New logged %q, want exactly one warning naming SecureCookie", rec.msgs)
		}
	}
}

// TestLoginRevokesSessionItReplaces: a login from a browser that still
// holds a live session for the same account ends that session (ASVS
// 7.2.4): the new cookie replaces the old one, so the old id would
// otherwise stay valid, invisible to its owner, until it idled out.
// Another account's session in the same browser is left alone -- that
// person did not sign in, and the request proved nothing about it.
func TestLoginRevokesSessionItReplaces(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	// No second factor, so the password alone issues the replacing
	// session (parked at the enrolment door, which does not matter here).
	admin := registerAdminNoFactor(t, ts, "admin", "password-placeholder-345")
	first := jarSessionID(t, admin, ts, testCookieName)
	now := g.now()
	if _, ok := g.deps.Sessions.Validate(first, now); !ok {
		t.Fatal("the registration session should be live before the second login")
	}

	resp := postJSON(t, admin, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "password-placeholder-345"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second login: status %d, want 200", resp.StatusCode)
	}
	second := jarSessionID(t, admin, ts, testCookieName)
	if second == first {
		t.Fatal("the second login reused the first session id")
	}
	if _, ok := g.deps.Sessions.Validate(first, now); ok {
		t.Error("the session the login replaced is still valid; it must be revoked")
	}
	if _, ok := g.deps.Sessions.Validate(second, now); !ok {
		t.Error("the new session is not valid")
	}

	// Someone else's session in this browser: not this account's to end.
	other := g.deps.Sessions.Create("someone-else", now)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/login", strings.NewReader(`{"username":"admin","password":"password-placeholder-345"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrfHeaderName, testCSRFValue)
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: other.ID})
	out, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = out.Body.Close()
	if out.StatusCode != http.StatusOK {
		t.Fatalf("login over another account's cookie: status %d, want 200", out.StatusCode)
	}
	if _, ok := g.deps.Sessions.Validate(other.ID, now); !ok {
		t.Error("a login as admin revoked another account's session; only the same account's is ended")
	}
}

// TestLoginFactorRevokesSessionItReplaces is the two-step path's copy of
// TestLoginRevokesSessionItReplaces: the session the code step issues
// replaces the one the browser held, so that one ends.
func TestLoginFactorRevokesSessionItReplaces(t *testing.T) {
	g, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	secret, _, confirmCounter := totpEnrolAndConfirm(t, bob, ts)
	first := jarSessionID(t, bob, ts, testCookieName)
	now := g.now()

	resp := postJSON(t, bob, ts.URL+"/api/auth/login", credentialsRequest{Username: totpBobUsername, Password: totpBobPassword})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("password step: status %d, want 200", resp.StatusCode)
	}
	if _, ok := g.deps.Sessions.Validate(first, now); !ok {
		t.Fatal("the password step alone must not end the held session; nothing has replaced it yet")
	}
	resp = submitLoginFactor(t, bob, ts, gauntlet.GenerateTOTPCode(secret, confirmCounter+1))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("code step: status %d, want 200", resp.StatusCode)
	}
	second := jarSessionID(t, bob, ts, testCookieName)
	if second == first {
		t.Fatal("the code step reused the held session id")
	}
	if _, ok := g.deps.Sessions.Validate(first, now); ok {
		t.Error("the session the code step replaced is still valid; it must be revoked")
	}
	if !sessionAuthenticated(t, bob, ts) {
		t.Error("the new session does not authenticate")
	}
}

// TestOIDCCallbackRevokesSessionItReplaces: an SSO sign-in is a
// re-authentication too, so the callback ends the same account's held
// session as the password paths do.
func TestOIDCCallbackRevokesSessionItReplaces(t *testing.T) {
	g, ts, fp := newOIDCTestGate(t, oidc.Policy{})
	now := g.now()

	// First SSO login provisions the account and issues a session.
	fs, err := oidc.NewFlowState(now)
	if err != nil {
		t.Fatal(err)
	}
	fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))
	resp, err := noRedirectClient().Do(oidcCallbackRequest(t, g, ts, fs, "state="+fs.State+"&code=test-code"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	first := sessionCookieFrom(resp, testCookieName)
	if first == nil {
		t.Fatalf("first SSO login set no session cookie (status %d, location %q)", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Second SSO login from the browser still holding that session.
	fs2, err := oidc.NewFlowState(now)
	if err != nil {
		t.Fatal(err)
	}
	fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs2.Nonce))
	req := oidcCallbackRequest(t, g, ts, fs2, "state="+fs2.State+"&code=test-code")
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: first.Value})
	resp2, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	second := sessionCookieFrom(resp2, testCookieName)
	if second == nil || second.Value == first.Value {
		t.Fatalf("second SSO login set %+v, want a fresh session cookie", second)
	}
	if _, ok := g.deps.Sessions.Validate(first.Value, now); ok {
		t.Error("the session the SSO login replaced is still valid; it must be revoked")
	}
	if _, ok := g.deps.Sessions.Validate(second.Value, now); !ok {
		t.Error("the new SSO session is not valid")
	}
}
