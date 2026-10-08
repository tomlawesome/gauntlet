package gate

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// POST /api/auth/reauthenticate (#71): a session that timed out through
// inactivity inside its 24-hour ceiling resumes with the password alone.

// resumeFixture is bob, signed in with a confirmed authenticator app on
// a hand-moved clock, every request from a fresh address so only the
// account's own limit ever refuses one. bob is the browser holding the
// session issued at t0.
type resumeFixture struct {
	g      *Gate
	ts     *httptest.Server
	clock  *escalationClock
	bob    *http.Client
	cookie string // bob's session as first issued, still held by the browser
	codes  []string
	t0     time.Time
	audit  *auditRecorder
	events *signInEvents
}

func newResumeFixture(t *testing.T) *resumeFixture {
	t.Helper()
	g, ts, clock := escalationFixture(t)
	bob := newBrowser(t, "Firefox/131.0 (laptop)", "203.0.113.10")
	resp := postJSON(t, bob, ts.URL+"/api/auth/login", credentialsRequest{Username: totpBobUsername, Password: totpBobPassword})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bob's sign-in returned %d", resp.StatusCode)
	}
	_, codes, _ := totpEnrolAndConfirm(t, bob, ts)
	audit, _, events := recordSignIns(g)
	return &resumeFixture{g: g, ts: ts, clock: clock, bob: bob, cookie: sessionCookie(t, bob, ts), codes: codes, t0: clock.now(), audit: audit, events: events}
}

// at moves the clock to t0 plus d.
func (f *resumeFixture) at(d time.Duration) { f.clock.set(f.t0.Add(d)) }

// keepAlive moves the clock to t0 plus d in half-hour steps, using each
// of live at every step so they never idle out on the way.
func (f *resumeFixture) keepAlive(t *testing.T, d time.Duration, live ...*http.Client) {
	t.Helper()
	for step := 30 * time.Minute; ; step += 30 * time.Minute {
		if step > d {
			step = d
		}
		f.at(step)
		for _, c := range live {
			if got := protectedStatus(t, c, f.ts); got != http.StatusOK {
				t.Fatalf("a client kept alive was refused at +%v: %d", step, got)
			}
		}
		if step == d {
			return
		}
	}
}

func reauth(t *testing.T, c *http.Client, ts *httptest.Server, password string) (*http.Response, []byte) {
	t.Helper()
	resp := postJSON(t, c, ts.URL+reauthenticatePath, reauthenticateRequest{Password: password})
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

// wantProblem fails unless resp is the status and class given.
func wantResumeProblem(t *testing.T, resp *http.Response, body []byte, status int, class problemClass) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("status = %d, want %d: %s", resp.StatusCode, status, body)
	}
	if got := decodeProblem(t, body).Type; got != problemTypeBase+class.anchor {
		t.Fatalf("problem type = %q, want the %s class: %s", got, class.anchor, body)
	}
}

// sessionCookie is the session cookie c holds for ts.
func sessionCookie(t *testing.T, c *http.Client, ts *httptest.Server) string {
	t.Helper()
	u, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
	for _, ck := range c.Jar.Cookies(u.URL) {
		if ck.Name == testCookieName {
			return ck.Value
		}
	}
	t.Fatal("the client holds no session cookie")
	return ""
}

// withCookie sends method path with only the given session cookie value
// and the CSRF header, as a browser that still holds that cookie would.
func withCookie(t *testing.T, ts *httptest.Server, method, path, cookie string, body any) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, ts.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrfHeaderName, testCSRFValue)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: testCookieName, Value: cookie})
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

// sessionState is GET /api/auth/session as c sees it.
func sessionState(t *testing.T, c *http.Client, ts *httptest.Server) map[string]any {
	t.Helper()
	resp, err := c.Get(ts.URL + "/api/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestReauthenticateResumesATimedOutSessionWithTheNewIDOnly(t *testing.T) {
	f := newResumeFixture(t)
	old := sessionCookie(t, f.bob, f.ts)

	f.at(2 * time.Hour)
	if got := protectedStatus(t, f.bob, f.ts); got != http.StatusUnauthorized {
		t.Fatalf("a timed-out session reached a protected route: %d", got)
	}
	st := sessionState(t, f.bob, f.ts)
	if st["authenticated"] != false || st["resumable"] != true {
		t.Fatalf("session state = %v, want unauthenticated and resumable", st)
	}

	resp, body := reauth(t, f.bob, f.ts, totpBobPassword)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resume: status %d: %s", resp.StatusCode, body)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil || got["username"] != totpBobUsername || got["role"] != "user" || len(got) != 2 {
		t.Errorf("body = %s, want login's success body", body)
	}
	fresh := sessionCookie(t, f.bob, f.ts)
	if fresh == old {
		t.Error("the session ID did not change")
	}
	if got := protectedStatus(t, f.bob, f.ts); got != http.StatusOK {
		t.Errorf("the resumed session was refused: %d", got)
	}
	st = sessionState(t, f.bob, f.ts)
	if st["authenticated"] != true || st["resumable"] != nil {
		t.Errorf("session state after resume = %v, want authenticated and not resumable", st)
	}
	if want := f.t0.Format(time.RFC3339); st["signedInSince"] != want {
		t.Errorf("signedInSince = %v, want the original sign-in %s", st["signedInSince"], want)
	}

	// The old ID is dead: no request, and no second resume.
	if r, _ := withCookie(t, f.ts, http.MethodGet, "/api/protected", old, nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("the old ID reached a protected route: %d", r.StatusCode)
	}
	r, b := withCookie(t, f.ts, http.MethodPost, reauthenticatePath, old, reauthenticateRequest{Password: totpBobPassword})
	wantResumeProblem(t, r, b, http.StatusUnauthorized, classSignInRequired)
	if r.Header.Get("WWW-Authenticate") == "" {
		t.Error("the 401 carries no WWW-Authenticate header")
	}

	// A resume is an audited sign-in, not a user.login, and a history row.
	rec := auditEntries(f.audit, "user.reauthenticated")
	if len(rec) != 1 || rec[0].Actor != totpBobUsername || rec[0].Target != totpBobUsername ||
		!strings.HasPrefix(rec[0].Detail, "session resumed with password; from=") {
		t.Errorf("user.reauthenticated records = %+v, want one for bob", rec)
	}
	if n := len(auditEntries(f.audit, "user.login")); n != 0 {
		t.Errorf("a resume wrote %d user.login records", n)
	}
	wantEvents(t, f.events.all(), "success/resume")
}

// The cookie, like the session, ends at the original ceiling, and a
// resume never moves it.
func TestReauthenticateKeepsTheOriginalCeiling(t *testing.T) {
	f := newResumeFixture(t)

	f.at(23*time.Hour + 30*time.Minute)
	resp, body := reauth(t, f.bob, f.ts, totpBobPassword)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resume at +23h30m: status %d: %s", resp.StatusCode, body)
	}
	var maxAge int
	for _, c := range resp.Cookies() {
		if c.Name == testCookieName {
			maxAge = c.MaxAge
		}
	}
	if maxAge != 30*60 {
		t.Errorf("cookie Max-Age = %d, want the 1800 seconds left to the ceiling", maxAge)
	}
	if got := protectedStatus(t, f.bob, f.ts); got != http.StatusOK {
		t.Fatalf("the resumed session was refused: %d", got)
	}

	f.at(24*time.Hour + time.Second)
	if got := protectedStatus(t, f.bob, f.ts); got != http.StatusUnauthorized {
		t.Errorf("a resumed session outlived the original ceiling: %d", got)
	}
	resp, body = reauth(t, f.bob, f.ts, totpBobPassword)
	wantResumeProblem(t, resp, body, http.StatusUnauthorized, classSignInRequired)
}

// A resumed session can time out and be resumed again, under the same
// ceiling.
func TestReauthenticateTwice(t *testing.T) {
	f := newResumeFixture(t)
	for _, d := range []time.Duration{2 * time.Hour, 5 * time.Hour} {
		f.at(d)
		if resp, body := reauth(t, f.bob, f.ts, totpBobPassword); resp.StatusCode != http.StatusOK {
			t.Fatalf("resume at +%v: status %d: %s", d, resp.StatusCode, body)
		}
	}
	f.at(25 * time.Hour)
	if got := protectedStatus(t, f.bob, f.ts); got != http.StatusUnauthorized {
		t.Errorf("past the ceiling: %d", got)
	}
}

func TestReauthenticatePastTheCeilingIsRefused(t *testing.T) {
	f := newResumeFixture(t)
	f.at(24*time.Hour + time.Second)

	if st := sessionState(t, f.bob, f.ts); st["resumable"] != nil {
		t.Errorf("session state past the ceiling = %v, want not resumable", st)
	}
	resp, body := reauth(t, f.bob, f.ts, totpBobPassword)
	wantResumeProblem(t, resp, body, http.StatusUnauthorized, classSignInRequired)
}

func TestReauthenticateWithNoResumableSessionIsRefusedAlike(t *testing.T) {
	f := newResumeFixture(t)

	// No cookie at all.
	resp, body := reauth(t, &http.Client{Jar: mustCookieJar(t)}, f.ts, totpBobPassword)
	wantResumeProblem(t, resp, body, http.StatusUnauthorized, classSignInRequired)
	// An unknown cookie.
	r, b := withCookie(t, f.ts, http.MethodPost, reauthenticatePath, "no-such-session", reauthenticateRequest{Password: totpBobPassword})
	wantResumeProblem(t, r, b, http.StatusUnauthorized, classSignInRequired)
	// A live session has nothing to resume.
	resp, body = reauth(t, f.bob, f.ts, totpBobPassword)
	wantResumeProblem(t, resp, body, http.StatusUnauthorized, classSignInRequired)
	// None of those touched the limiter or the history.
	wantEvents(t, f.events.all())
}

func TestReauthenticateNeedsTheCSRFHeaderAndAWellFormedBody(t *testing.T) {
	f := newResumeFixture(t)
	f.at(2 * time.Hour)
	cookie := sessionCookie(t, f.bob, f.ts)

	req, _ := http.NewRequest(http.MethodPost, f.ts.URL+reauthenticatePath, strings.NewReader(`{"password":"x"}`))
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: cookie})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	wantResumeProblem(t, resp, b, http.StatusForbidden, classCSRFRequired)

	r, b := withCookie(t, f.ts, http.MethodPost, reauthenticatePath, cookie, map[string]any{"password": "x", "username": "admin"})
	wantResumeProblem(t, r, b, http.StatusBadRequest, classInvalidRequest)
}

// A wrong password is a failed sign-in: refused, recorded and counted,
// and the session stays resumable for the right one.
func TestReauthenticateWrongPasswordIsRefusedAndCounted(t *testing.T) {
	f := newResumeFixture(t)
	f.at(2 * time.Hour)

	resp, body := reauth(t, f.bob, f.ts, "wrong-password-placeholder")
	wantResumeProblem(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
	wantEvents(t, f.events.all(), "wrong_password/resume")
	failed := auditEntries(f.audit, "user.login_failed")
	if len(failed) != 1 || !strings.Contains(failed[0].Detail, "outcome=wrong_password method=resume") {
		t.Errorf("user.login_failed records = %+v, want one for a wrong password at resume", failed)
	}
	if n := len(auditEntries(f.audit, "user.reauthenticated")); n != 0 {
		t.Errorf("a wrong password wrote %d user.reauthenticated records", n)
	}
	if got := protectedStatus(t, f.bob, f.ts); got != http.StatusUnauthorized {
		t.Errorf("a wrong password resumed the session: %d", got)
	}
	if resp, body := reauth(t, f.bob, f.ts, totpBobPassword); resp.StatusCode != http.StatusOK {
		t.Fatalf("the right password after a wrong one: status %d: %s", resp.StatusCode, body)
	}
}

// Five wrong passwords lock the account out as five at login do, and
// then even the right password is a 429 until the lockout ends.
func TestReauthenticateLockedOutAccountIsRefusedWith429(t *testing.T) {
	f := newResumeFixture(t)
	f.at(2 * time.Hour)
	// From a browser the account does not remember: only the session
	// cookie, none of the known-browser ones f.bob would also send.
	resume := func(password string) (*http.Response, []byte) {
		return withCookie(t, f.ts, http.MethodPost, reauthenticatePath, f.cookie, reauthenticateRequest{Password: password})
	}
	for i := range 5 {
		resp, body := resume("wrong-password-placeholder")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong password %d: status %d: %s", i+1, resp.StatusCode, body)
		}
	}
	until := f.g.deps.Users.LoginLockedUntil(totpBobID(t, f.g))
	if !until.After(f.clock.now()) {
		t.Fatal("five wrong passwords at resume started no lockout")
	}
	resp, body := resume(totpBobPassword)
	wantResumeProblem(t, resp, body, http.StatusTooManyRequests, classRateLimited)
	if ev := f.events.all(); len(ev) != 6 || ev[5].Outcome != gauntlet.SignInLocked || ev[5].Method != gauntlet.SignInMethodResume {
		t.Errorf("sign-in events = %+v, want the sixth a locked resume", ev)
	}
	// Signing in the ordinary way is refused too: one count for both.
	if r := tryLogin(t, f.ts, totpBobUsername, totpBobPassword); r.status != http.StatusTooManyRequests {
		t.Errorf("a password sign-in during the lockout: status %d, want 429", r.status)
	}

	// The browser the account remembers still gets its own allowance
	// during the lockout, as at login (#44).
	if resp, body := reauth(t, f.bob, f.ts, totpBobPassword); resp.StatusCode != http.StatusOK {
		t.Fatalf("resume from a remembered browser during the lockout: status %d: %s", resp.StatusCode, body)
	}
}

func TestReauthenticateAfterALockoutEnds(t *testing.T) {
	f := newResumeFixture(t)
	f.at(2 * time.Hour)
	for range 5 {
		_, _ = withCookie(t, f.ts, http.MethodPost, reauthenticatePath, f.cookie, reauthenticateRequest{Password: "wrong-password-placeholder"})
	}
	f.clock.set(f.g.deps.Users.LoginLockedUntil(totpBobID(t, f.g)).Add(time.Second))
	if resp, body := reauth(t, f.bob, f.ts, totpBobPassword); resp.StatusCode != http.StatusOK {
		t.Fatalf("resume after the lockout: status %d: %s", resp.StatusCode, body)
	}
}

// A banned address is refused as at login, 429, before the password is
// looked at.
func TestReauthenticateFromABannedAddressIsRefused(t *testing.T) {
	f := newResumeFixture(t)
	f.at(2 * time.Hour)
	f.g.cfg.ClientIP = func(*http.Request) string { return "192.0.2.200" }
	for range gauntlet.AddressBanFailures {
		f.g.deps.Limiter.RecordAddressFailure("192.0.2.200", f.clock.now())
	}
	resp, body := withCookie(t, f.ts, http.MethodPost, reauthenticatePath, f.cookie, reauthenticateRequest{Password: totpBobPassword})
	wantResumeProblem(t, resp, body, http.StatusTooManyRequests, classRateLimited)
}

func TestReauthenticateRefusedAfterLogout(t *testing.T) {
	f := newResumeFixture(t)
	f.at(2 * time.Hour)

	resp := postJSON(t, f.bob, f.ts.URL+"/api/auth/logout", struct{}{})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	// The cookie is cleared with the logout, so use the old value.
	r, b := withCookie(t, f.ts, http.MethodPost, reauthenticatePath, f.cookie, reauthenticateRequest{Password: totpBobPassword})
	wantResumeProblem(t, r, b, http.StatusUnauthorized, classSignInRequired)
}

// bob's first browser times out while his second stays in use; the
// second then ends every session, or changes the password.
func TestReauthenticateRefusedAfterTheAccountsSessionsEnd(t *testing.T) {
	cases := []struct {
		name string
		end  func(t *testing.T, f *resumeFixture, second *http.Client)
	}{
		{"logout-all", func(t *testing.T, f *resumeFixture, second *http.Client) {
			resp := postJSON(t, second, f.ts.URL+"/api/auth/logout-all", logoutAllRequest{Password: totpBobPassword})
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("logout-all: %d", resp.StatusCode)
			}
		}},
		{"password change", func(t *testing.T, f *resumeFixture, second *http.Client) {
			resp := postJSON(t, second, f.ts.URL+"/api/auth/password",
				changePasswordRequest{CurrentPassword: totpBobPassword, NewPassword: "a-brand-new-password-placeholder"})
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("password change: %d", resp.StatusCode)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newResumeFixture(t)
			first := sessionCookie(t, f.bob, f.ts)
			second := signInBob(t, f.ts, "Chrome/130 (phone)", "203.0.113.20", f.codes[0])
			f.keepAlive(t, 2*time.Hour, second)
			if _, ok := f.g.deps.Sessions.Resumable(first, f.clock.now()); !ok {
				t.Fatal("test setup: the first browser's session should be timed out and resumable")
			}

			tc.end(t, f, second)
			r, b := withCookie(t, f.ts, http.MethodPost, reauthenticatePath, first, reauthenticateRequest{Password: totpBobPassword})
			wantResumeProblem(t, r, b, http.StatusUnauthorized, classSignInRequired)
			if _, ok := f.g.deps.Sessions.Resumable(first, f.clock.now()); ok {
				t.Error("the ended session is still resumable in the store")
			}
		})
	}
}

// A password set behind the session's back (the store, say, or another
// process) ends it by SessionCutoff even though nothing revoked it.
func TestReauthenticateRefusedWhenThePasswordChangedSinceSignIn(t *testing.T) {
	f := newResumeFixture(t)
	f.at(2 * time.Hour)
	if err := f.g.deps.Users.SetPassword(totpBobUsername, "a-brand-new-password-placeholder", f.clock.now()); err != nil {
		t.Fatal(err)
	}
	cookie := f.cookie
	if st := sessionState(t, f.bob, f.ts); st["resumable"] != nil {
		t.Errorf("session state after a password change = %v, want not resumable", st)
	}
	for _, pw := range []string{totpBobPassword, "a-brand-new-password-placeholder"} {
		r, b := withCookie(t, f.ts, http.MethodPost, reauthenticatePath, cookie, reauthenticateRequest{Password: pw})
		wantResumeProblem(t, r, b, http.StatusUnauthorized, classSignInRequired)
	}
}

// The account is gone: nothing to resume.
func TestReauthenticateRefusedForADeletedAccount(t *testing.T) {
	f := newResumeFixture(t)
	f.at(2 * time.Hour)
	if _, err := f.g.deps.Users.DeleteUser(totpBobID(t, f.g)); err != nil {
		t.Fatal(err)
	}
	r, b := withCookie(t, f.ts, http.MethodPost, reauthenticatePath, f.cookie, reauthenticateRequest{Password: totpBobPassword})
	wantResumeProblem(t, r, b, http.StatusUnauthorized, classSignInRequired)
}

// resumeStoreFixture is a gate over the given hand-written accounts,
// with a session for each already timed out.
func resumeStoreFixture(t *testing.T, users ...gauntlet.User) (*Gate, *httptest.Server, time.Time) {
	t.Helper()
	hash, err := gauntlet.HashPassword("password-placeholder-1")
	if err != nil {
		t.Fatal(err)
	}
	admin := gauntlet.User{ID: "admin-1", Username: "admin", PasswordHash: hash, Role: gauntlet.RoleAdmin,
		CreatedAt: time.Now(), HasLocalPassword: true}
	g := newTestGate(t)
	g.deps.Users = openStoreWithUsers(t, append([]gauntlet.User{admin}, users...)...)
	ts := newTestServer(t, g)
	t0 := time.Now()
	g.cfg.Now = func() time.Time { return t0.Add(2 * time.Hour) }
	return g, ts, t0
}

// An SSO-only account has no password to resume with: the answer is the
// one for no resumable session, and the session is not offered for it.
func TestReauthenticateRefusedForAnSSOOnlyAccount(t *testing.T) {
	sso := gauntlet.User{ID: "sso-1", Username: "sso-user", Role: gauntlet.RoleUser, CreatedAt: time.Now(),
		OIDCIssuer: "https://idp.example", OIDCSubject: "subject-1"}
	g, ts, t0 := resumeStoreFixture(t, sso)
	sess := g.deps.Sessions.Create(sso.ID, t0)

	r, b := withCookie(t, ts, http.MethodPost, reauthenticatePath, sess.ID, reauthenticateRequest{Password: testAdminPassword})
	wantResumeProblem(t, r, b, http.StatusUnauthorized, classSignInRequired)
	r, b = withCookie(t, ts, http.MethodGet, "/api/auth/session", sess.ID, nil)
	if r.StatusCode != http.StatusOK || strings.Contains(string(b), "resumable") {
		t.Errorf("session state for an SSO-only account = %s, want no resumable field", b)
	}
}

// An account that owes a password change signs in the full way, which
// takes it to the door.
func TestReauthenticateRefusedWhileAPasswordChangeIsOwed(t *testing.T) {
	hash, err := gauntlet.HashPassword("password-placeholder-1")
	if err != nil {
		t.Fatal(err)
	}
	u := gauntlet.User{ID: "owes-1", Username: "owes", PasswordHash: hash, Role: gauntlet.RoleUser, CreatedAt: time.Now(),
		HasLocalPassword: true, MustChangePassword: true}
	g, ts, t0 := resumeStoreFixture(t, u)
	sess := g.deps.Sessions.Create(u.ID, t0)

	r, b := withCookie(t, ts, http.MethodPost, reauthenticatePath, sess.ID, reauthenticateRequest{Password: "password-placeholder-1"})
	wantResumeProblem(t, r, b, http.StatusUnauthorized, classSignInRequired)
}

// The route needs an account to exist, and is session-exempt and
// CSRF-checked like login.
func TestReauthenticatePathIsSessionExemptButNotBootstrapExempt(t *testing.T) {
	if !exemptPaths[reauthenticatePath] {
		t.Error("the reauthenticate path is not session-exempt")
	}
	if bootstrapExemptPaths[reauthenticatePath] {
		t.Error("the reauthenticate path is reachable before any account exists")
	}
}
