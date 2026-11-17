package gate

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// A person's own session list (gauntlet#48): GET /api/auth/sessions and
// DELETE /api/auth/sessions/{ref}.

// sessionsTestIPHeader carries the address each test browser claims, so
// the fixture's Config.ClientIP can be seen to be the source of a row's
// address.
const sessionsTestIPHeader = "X-Test-IP"

// browserTransport stamps every request with one browser's agent and
// address, as a real browser sends the same User-Agent on every request.
type browserTransport struct {
	agent, address string
}

func (b browserTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", b.agent)
	req.Header.Set(sessionsTestIPHeader, b.address)
	return http.DefaultTransport.RoundTrip(req)
}

func newBrowser(t *testing.T, agent, address string) *http.Client {
	t.Helper()
	return &http.Client{Jar: mustCookieJar(t), Transport: browserTransport{agent: agent, address: address}}
}

// sessionsFixture stands up a gate whose ClientIP reads
// sessionsTestIPHeader and whose audit is recorded, with an admin and
// "bob" (user role) signed in from his first browser and holding a
// confirmed TOTP factor -- confirming it ended every other session, so
// that browser holds bob's only one. It returns bob's recovery codes,
// each good for one further sign-in from another browser.
func sessionsFixture(t *testing.T) (*Gate, *httptest.Server, *http.Client, []string) {
	t.Helper()
	g := newTestGate(t)
	g.cfg.ClientIP = func(r *http.Request) string {
		if ip := r.Header.Get(sessionsTestIPHeader); ip != "" {
			return ip
		}
		return "198.51.100.1"
	}
	g.cfg.Audit = &auditRecorder{}
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")
	_ = postJSON(t, admin, ts.URL+"/api/auth/users",
		createUserRequest{Username: totpBobUsername, Password: totpBobPassword, Role: "user"}).Body.Close()

	bob := newBrowser(t, "Firefox/131.0 (laptop)", "203.0.113.10")
	resp := postJSON(t, bob, ts.URL+"/api/auth/login", credentialsRequest{Username: totpBobUsername, Password: totpBobPassword})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bob's first sign-in returned %d", resp.StatusCode)
	}
	_, codes, _ := totpEnrolAndConfirm(t, bob, ts)
	return g, ts, bob, codes
}

// signInBob signs bob in from a new browser with a recovery code as
// the second factor, so each call is one more session on his account.
func signInBob(t *testing.T, ts *httptest.Server, agent, address, code string) *http.Client {
	t.Helper()
	client := newBrowser(t, agent, address)
	resp := postJSON(t, client, ts.URL+"/api/auth/login", credentialsRequest{Username: totpBobUsername, Password: totpBobPassword})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bob's password step returned %d", resp.StatusCode)
	}
	resp = submitLoginFactor(t, client, ts, code)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bob's second-factor step returned %d", resp.StatusCode)
	}
	return client
}

func listSessions(t *testing.T, client *http.Client, ts *httptest.Server) (int, sessionListResponse) {
	t.Helper()
	resp, err := client.Get(ts.URL + "/api/auth/sessions")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out sessionListResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode, out
}

func mustListSessions(t *testing.T, client *http.Client, ts *httptest.Server) sessionListResponse {
	t.Helper()
	status, out := listSessions(t, client, ts)
	if status != http.StatusOK {
		t.Fatalf("GET /api/auth/sessions returned %d, want 200", status)
	}
	return out
}

// endSession sends DELETE /api/auth/sessions/{ref} with no body, with
// the CSRF header unless csrf is false, and returns the response with
// its body read.
func endSession(t *testing.T, client *http.Client, ts *httptest.Server, ref string, csrf bool) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/auth/sessions/"+ref, nil)
	if err != nil {
		t.Fatal(err)
	}
	if csrf {
		req.Header.Set(csrfHeaderName, testCSRFValue)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func currentRow(t *testing.T, list sessionListResponse) sessionRow {
	t.Helper()
	var found []sessionRow
	for _, row := range list.Sessions {
		if row.Current {
			found = append(found, row)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d rows marked current, want exactly 1: %+v", len(found), list.Sessions)
	}
	return found[0]
}

func sessionListAuditCount(g *Gate) int {
	rec := g.cfg.Audit.(*auditRecorder)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	n := 0
	for _, e := range rec.entries {
		if e.Action == "account.sessions_ended" && strings.Contains(e.Detail, "via session list") {
			n++
		}
	}
	return n
}

// With no session, both routes answer 401: /api/auth/sessions is not
// the exempt /api/auth/session.
func TestSessionsAnonymousIsUnauthorized(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	_ = registerAdmin(t, ts, "admin", "password-placeholder-1")
	anon := &http.Client{Jar: mustCookieJar(t)}

	if status, _ := listSessions(t, anon, ts); status != http.StatusUnauthorized {
		t.Errorf("anonymous GET /api/auth/sessions = %d, want 401", status)
	}
	if resp, _ := endSession(t, anon, ts, strings.Repeat("0", 32), true); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous DELETE /api/auth/sessions/{ref} = %d, want 401", resp.StatusCode)
	}
}

// Two sign-ins give two rows, newest first, each listing the address
// Config.ClientIP resolved and the browser's User-Agent; only the
// session the request was made with is current. No row carries the
// session ID (the cookie) anywhere.
func TestSessionsListShowsEachSignIn(t *testing.T) {
	g, ts, laptop, codes := sessionsFixture(t)
	phone := signInBob(t, ts, "Safari/18.0 (phone)", "192.0.2.44", codes[0])

	list := mustListSessions(t, phone, ts)
	if list.Total != 2 || len(list.Sessions) != 2 {
		t.Fatalf("list = %+v, want 2 rows and total 2", list)
	}
	cur := currentRow(t, list)
	if cur.UserAgent != "Safari/18.0 (phone)" || cur.Address != "192.0.2.44" {
		t.Errorf("current row = %+v, want the phone's agent and address", cur)
	}
	if list.Sessions[0] != cur {
		t.Errorf("first row = %+v, want the newest sign-in (the phone's)", list.Sessions[0])
	}
	other := list.Sessions[1]
	if other.UserAgent != "Firefox/131.0 (laptop)" || other.Address != "203.0.113.10" {
		t.Errorf("other row = %+v, want the laptop's agent and address", other)
	}
	if other.SignedInAt.After(cur.SignedInAt) || cur.LastUsedAt.Before(cur.SignedInAt) {
		t.Errorf("times out of order: current %+v, other %+v", cur, other)
	}
	if !sessionRefPattern(cur.Ref) || !sessionRefPattern(other.Ref) || cur.Ref == other.Ref {
		t.Errorf("refs %q and %q, want two distinct 32-hex refs", cur.Ref, other.Ref)
	}

	// From the laptop, the laptop's row is the current one.
	if got := currentRow(t, mustListSessions(t, laptop, ts)); got.Ref != other.Ref {
		t.Errorf("laptop's current row = %+v, want %s", got, other.Ref)
	}

	bob, _ := g.deps.Users.ByUsername(totpBobUsername)
	for _, sess := range g.deps.Sessions.ListForUser(bob.ID, time.Now()) {
		resp, err := phone.Get(ts.URL + "/api/auth/sessions")
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if strings.Contains(string(raw), sess.ID) {
			t.Fatalf("the list body carries a session ID: %s", raw)
		}
	}
}

func sessionRefPattern(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

// A session issued before the account's SessionCutoff -- one another
// process (the CLI reset tool) left behind, or one older than a
// password change -- is neither listed nor counted, and is revoked, as
// sessionUser would revoke it on its next request.
func TestSessionsListSkipsPreCutoffSession(t *testing.T) {
	g, ts, bob, _ := sessionsFixture(t)
	// A password change records the cutoff and reissues this browser's
	// session after it.
	resp := postJSON(t, bob, ts.URL+"/api/auth/password", changePasswordRequest{CurrentPassword: totpBobPassword, NewPassword: totpBobPassword + "-2"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("changing bob's password returned %d", resp.StatusCode)
	}
	user, _ := g.deps.Users.ByUsername(totpBobUsername)
	cutoff := user.SessionCutoff()
	if cutoff.IsZero() || time.Since(cutoff) > time.Minute {
		t.Fatalf("bob's SessionCutoff = %v, want a moment ago", cutoff)
	}
	stale := g.deps.Sessions.CreateFrom(user.ID, gauntlet.SessionClient{UserAgent: "stale"}, cutoff.Add(-time.Second))

	list := mustListSessions(t, bob, ts)
	if list.Total != 1 || len(list.Sessions) != 1 || list.Sessions[0].UserAgent == "stale" {
		t.Fatalf("list = %+v, want only the live session", list)
	}
	if _, ok := g.deps.Sessions.Validate(stale.ID, time.Now()); ok {
		t.Error("the pre-cutoff session was skipped but not revoked")
	}
}

// Ending another of one's own sessions: that session's cookie stops
// working, this one does not, the cookie is left alone, and one audit
// line records it by ref, never by agent or address.
func TestSessionsEndAnotherSession(t *testing.T) {
	g, ts, laptop, codes := sessionsFixture(t)
	phone := signInBob(t, ts, "Safari/18.0 (phone)", "192.0.2.44", codes[0])
	laptopRef := currentRow(t, mustListSessions(t, laptop, ts)).Ref

	resp, body := endSession(t, phone, ts, laptopRef, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ending the laptop's session returned %d: %s", resp.StatusCode, body)
	}
	var out sessionEndedResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Ended || out.SignedOut {
		t.Errorf("response = %+v, want ended and not signed out", out)
	}
	for _, c := range resp.Cookies() {
		if c.Name == g.sessionCookieName() {
			t.Errorf("ending another session touched this browser's cookie: %+v", c)
		}
	}

	if status, _ := listSessions(t, laptop, ts); status != http.StatusUnauthorized {
		t.Errorf("the ended session's cookie still answers %d, want 401", status)
	}
	list := mustListSessions(t, phone, ts)
	if list.Total != 1 || !list.Sessions[0].Current {
		t.Errorf("after ending the laptop's session, list = %+v, want only the phone's", list)
	}

	if n := sessionListAuditCount(g); n != 1 {
		t.Fatalf("%d session-list audit lines, want 1", n)
	}
	entry := findAuditEntry(t, g, "account.sessions_ended")
	if entry.Detail != "sessions ended: one, ref="+laptopRef+`, via session list; from="192.0.2.44"` || entry.Actor != totpBobUsername || entry.Target != totpBobUsername {
		t.Errorf("audit entry = %+v", entry)
	}
	if strings.Contains(entry.Detail, "Firefox") || strings.Contains(entry.Detail, "203.0.113.10") {
		t.Errorf("audit entry carries the agent or address: %+v", entry)
	}
}

// Ending the session the request was made with signs this browser out:
// the cookie is cleared and the response says so.
func TestSessionsEndCurrentSessionClearsCookie(t *testing.T) {
	g, ts, bob, _ := sessionsFixture(t)
	ref := currentRow(t, mustListSessions(t, bob, ts)).Ref

	resp, body := endSession(t, bob, ts, ref, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ending the current session returned %d: %s", resp.StatusCode, body)
	}
	var out sessionEndedResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Ended || !out.SignedOut {
		t.Errorf("response = %+v, want ended and signed out", out)
	}
	cleared := false
	for _, c := range resp.Cookies() {
		if c.Name == g.sessionCookieName() && c.Value == "" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Errorf("session cookie not cleared: %v", resp.Header.Values("Set-Cookie"))
	}
	if status, _ := listSessions(t, bob, ts); status != http.StatusUnauthorized {
		t.Errorf("after ending its own session the browser gets %d, want 401", status)
	}
}

// Any ref that is not one of the caller's own live sessions is 404, and
// ends nothing: another account's ref, an unknown one, a malformed one,
// and the raw session ID alike. Never 403, which would confirm another
// account's session exists.
func TestSessionsEndRefusesRefsNotTheCallers(t *testing.T) {
	g, ts, bob, _ := sessionsFixture(t)
	// The admin needs a ref of its own to aim at: a session made in the
	// store and handed to a browser, the same as a sign-in would.
	adminUser, _ := g.deps.Users.ByUsername("admin")
	adminSess := g.deps.Sessions.Create(adminUser.ID, time.Now())
	admin := &http.Client{Jar: mustCookieJar(t)}
	tsURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	admin.Jar.SetCookies(tsURL, []*http.Cookie{{Name: g.sessionCookieName(), Value: adminSess.ID, Path: "/"}})
	adminSessions := len(g.deps.Sessions.ListForUser(adminUser.ID, time.Now()))
	adminRef := currentRow(t, mustListSessions(t, admin, ts)).Ref
	bobUser, _ := g.deps.Users.ByUsername(totpBobUsername)
	bobSession := g.deps.Sessions.ListForUser(bobUser.ID, time.Now())[0]

	for name, ref := range map[string]string{
		"another account's ref": adminRef,
		"unknown ref":           strings.Repeat("0", 32),
		"malformed ref":         "not-a-ref",
		"the session ID itself": bobSession.ID,
	} {
		resp, body := endSession(t, bob, ts, ref, true)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404: %s", name, resp.StatusCode, body)
		}
	}

	if got := len(g.deps.Sessions.ListForUser(adminUser.ID, time.Now())); got != adminSessions {
		t.Errorf("admin holds %d sessions, want %d: a refused ref ended one", got, adminSessions)
	}
	if list := mustListSessions(t, bob, ts); list.Total != 1 {
		t.Errorf("bob holds %d sessions, want 1: a refused ref ended one", list.Total)
	}
	if n := sessionListAuditCount(g); n != 0 {
		t.Errorf("%d session-list audit lines for refused refs, want 0", n)
	}
}

// Without the CSRF header the request is refused before it reaches the
// handler, and nothing ends.
func TestSessionsEndRequiresCSRFHeader(t *testing.T) {
	_, ts, bob, _ := sessionsFixture(t)
	ref := currentRow(t, mustListSessions(t, bob, ts)).Ref

	if resp, _ := endSession(t, bob, ts, ref, false); resp.StatusCode != http.StatusForbidden {
		t.Errorf("DELETE without the CSRF header = %d, want 403", resp.StatusCode)
	}
	if list := mustListSessions(t, bob, ts); list.Total != 1 {
		t.Errorf("after a refused DELETE, list = %+v, want the session still there", list)
	}
}

// Sign out everywhere is unchanged, and afterwards the list holds the
// one fresh session it issued, recorded with this browser's details.
func TestSessionsLogoutAllLeavesOneRow(t *testing.T) {
	_, ts, laptop, codes := sessionsFixture(t)
	_ = signInBob(t, ts, "Safari/18.0 (phone)", "192.0.2.44", codes[0])
	_ = signInBob(t, ts, "Chrome/130.0 (desktop)", "192.0.2.45", codes[1])
	if list := mustListSessions(t, laptop, ts); list.Total != 3 {
		t.Fatalf("before sign out everywhere, total = %d, want 3", list.Total)
	}

	resp := postJSON(t, laptop, ts.URL+"/api/auth/logout-all", logoutAllRequest{Password: totpBobPassword})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout-all returned %d", resp.StatusCode)
	}
	list := mustListSessions(t, laptop, ts)
	if list.Total != 1 || len(list.Sessions) != 1 || !list.Sessions[0].Current {
		t.Fatalf("after sign out everywhere, list = %+v, want one current row", list)
	}
	if row := list.Sessions[0]; row.UserAgent != "Firefox/131.0 (laptop)" || row.Address != "203.0.113.10" {
		t.Errorf("the fresh session = %+v, want this browser's agent and address", row)
	}
}

// The list stops at maxSessionRows, and total says how many there are.
// The extra sessions are made in the store directly rather than by 100
// more HTTP sign-ins: each would hash a password, and the cap does not
// care how a session was made.
func TestSessionsListIsCappedWithTotal(t *testing.T) {
	g, ts, bob, _ := sessionsFixture(t)
	user, _ := g.deps.Users.ByUsername(totpBobUsername)
	now := time.Now()
	for i := range maxSessionRows {
		g.deps.Sessions.CreateFrom(user.ID, gauntlet.SessionClient{UserAgent: "script"}, now.Add(time.Duration(i)*time.Millisecond))
	}

	list := mustListSessions(t, bob, ts)
	if len(list.Sessions) != maxSessionRows || list.Total != maxSessionRows+1 {
		t.Fatalf("listed %d rows, total %d; want %d rows, total %d", len(list.Sessions), list.Total, maxSessionRows, maxSessionRows+1)
	}
	// Newest first: the browser's own (oldest) session is the one cut.
	for i := 1; i < len(list.Sessions); i++ {
		if list.Sessions[i].SignedInAt.After(list.Sessions[i-1].SignedInAt) {
			t.Fatalf("row %d signed in after row %d: not newest first", i, i-1)
		}
	}
}

// The list says how each session's sign-in was made (#77): the password
// then a code, here, for the phone; and the laptop's password sign-in,
// whose session the TOTP confirmation rotated, keeps its method.
func TestSessionsListShowsHowEachWasSignedIn(t *testing.T) {
	_, ts, _, codes := sessionsFixture(t)
	phone := signInBob(t, ts, "Safari/18.0 (phone)", "192.0.2.44", codes[0])

	list := mustListSessions(t, phone, ts)
	if got := currentRow(t, list).Method; got != gauntlet.SignInMethodCode {
		t.Errorf("phone row method = %q, want code", got)
	}
	for _, row := range list.Sessions {
		if !row.Current && row.Method != gauntlet.SignInMethodPassword {
			t.Errorf("laptop row method = %q, want password (kept across the factor confirmation)", row.Method)
		}
	}
}
