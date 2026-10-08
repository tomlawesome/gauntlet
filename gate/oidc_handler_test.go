// Ported from mikroview's internal/api/oidc_test.go, driven against the
// fake in-process provider gauntlet/internal/testutil ships for exactly
// this (docs/design.md's G6 done-when: "OIDC callback (fake provider)").
package gate

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/internal/testutil"
	"github.com/tomlawesome/gauntlet/oidc"
	"github.com/tomlawesome/gauntlet/persist"
)

const oidcTestClientID = "test-client"

// newOIDCTestGate builds a Gate wired to a fresh fake provider -- policy
// is passed straight through as Deps.OIDCPolicy so each test can control
// what gets permitted.
// newOIDCTestGate is newEmptyOIDCTestGate plus the first admin,
// "setup-admin", registered with the setup code: SSO never creates the
// first account (issue #37), so every SSO test starts after it.
func newOIDCTestGate(t *testing.T, policy oidc.Policy) (*Gate, *httptest.Server, *testutil.FakeProvider) {
	t.Helper()
	g, ts, fp := newEmptyOIDCTestGate(t, policy)
	registerAdmin(t, ts, "setup-admin", "setup-admin-password")
	return g, ts, fp
}

func newEmptyOIDCTestGate(t *testing.T, policy oidc.Policy) (*Gate, *httptest.Server, *testutil.FakeProvider) {
	t.Helper()
	fp := testutil.NewFakeProvider(t)
	client, err := oidc.New(context.Background(), oidc.Config{
		IssuerURL:   fp.Issuer(),
		ClientID:    oidcTestClientID,
		RedirectURL: "http://app.example/api/auth/oidc/callback",
	})
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}
	codec, err := oidc.NewStateCodec()
	if err != nil {
		t.Fatalf("oidc.NewStateCodec: %v", err)
	}

	g := newTestGate(t)
	g.deps.OIDC = client
	g.deps.OIDCState = codec
	g.deps.OIDCPolicy = policy
	return g, newTestServer(t, g), fp
}

func oidcCallbackRequest(t *testing.T, g *Gate, ts *httptest.Server, fs oidc.FlowState, query string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/auth/oidc/callback?"+query, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := g.deps.OIDCState.Encode(fs)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: oidcFlowCookieName, Value: encoded})
	return req
}

func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestOIDCCallbackFakeProviderHappyPath(t *testing.T) {
	g, ts, fp := newOIDCTestGate(t, oidc.Policy{})
	fs, err := oidc.NewFlowState(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))

	req := oidcCallbackRequest(t, g, ts, fs, "state="+fs.State+"&code=test-code")
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback returned %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Errorf("redirect location = %q, want %q", loc, "/")
	}
	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == testCookieName {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected a session cookie to be set on a successful callback")
	}
	if g.deps.Users.Count() != 2 {
		t.Fatalf("expected the admin plus exactly one just-in-time provisioned account, got %d", g.deps.Users.Count())
	}
	u, ok := g.deps.Users.ByOIDCIdentity(fp.Issuer(), fp.DefaultClaims(oidcTestClientID, fs.Nonce).Subject)
	if !ok || u.Role != "user" {
		t.Errorf("expected an SSO-provisioned account to be an ordinary user (the admin is local, #37), got %v %v", u, ok)
	}
}

func TestOIDCCallbackStateMismatchRefused(t *testing.T) {
	g, ts, fp := newOIDCTestGate(t, oidc.Policy{})
	fs, err := oidc.NewFlowState(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))

	req := oidcCallbackRequest(t, g, ts, fs, "state=not-the-right-state&code=test-code")
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback returned %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != testLoginPath+"?ssoError=state_mismatch" {
		t.Errorf("redirect location = %q, want the state_mismatch ssoError", loc)
	}
	if g.deps.Users.Count() != 1 {
		t.Error("a state-mismatched callback must not provision an account")
	}
}

func TestOIDCCallbackNonceMismatchRefused(t *testing.T) {
	g, ts, fp := newOIDCTestGate(t, oidc.Policy{})
	fs, err := oidc.NewFlowState(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	claims := fp.DefaultClaims(oidcTestClientID, "a-different-nonce-entirely")
	fp.NextIDToken = fp.SignRS256(t, claims)

	req := oidcCallbackRequest(t, g, ts, fs, "state="+fs.State+"&code=test-code")
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if loc := resp.Header.Get("Location"); loc != testLoginPath+"?ssoError=state_mismatch" {
		t.Errorf("redirect location = %q, want the state_mismatch ssoError (nonce reuses that code)", loc)
	}
	if g.deps.Users.Count() != 1 {
		t.Error("a nonce-mismatched callback must not provision an account")
	}
}

func TestOIDCCallbackPolicyRefusal(t *testing.T) {
	g, ts, fp := newOIDCTestGate(t, oidc.Policy{AllowedEmails: []string{"someone-else@example.com"}})
	fs, err := oidc.NewFlowState(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// DefaultClaims' email (person@example.com) is not on the allowlist.
	fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))

	req := oidcCallbackRequest(t, g, ts, fs, "state="+fs.State+"&code=test-code")
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if loc := resp.Header.Get("Location"); loc != testLoginPath+"?ssoError=not_permitted" {
		t.Errorf("redirect location = %q, want the not_permitted ssoError", loc)
	}
	if g.deps.Users.Count() != 1 {
		t.Error("an identity the policy refuses must not be provisioned an account")
	}
}

// messageRecorder is a slog.Handler keeping each record's message as
// gate wrote it. slog's own text and JSON handlers escape a message
// themselves, so they cannot show whether gate did; a handler that
// prints the message as-is (slog's default one, or an app's own) can.
type messageRecorder struct {
	mu   sync.Mutex
	msgs []string
}

func (m *messageRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (m *messageRecorder) Handle(_ context.Context, r slog.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.msgs = append(m.msgs, r.Message)
	return nil
}
func (m *messageRecorder) WithAttrs([]slog.Attr) slog.Handler { return m }
func (m *messageRecorder) WithGroup(string) slog.Handler      { return m }

// TestOIDCCallbackPolicyRefusalLogEscapesSubject: the subject comes from
// the identity provider, so a newline or terminal escape in it must
// reach the log escaped -- otherwise it forges a second log line, or
// runs escape codes in the terminal of whoever reads the log.
func TestOIDCCallbackPolicyRefusalLogEscapesSubject(t *testing.T) {
	g, ts, fp := newOIDCTestGate(t, oidc.Policy{AllowedEmails: []string{"someone-else@example.com"}})
	logs := &messageRecorder{}
	g.cfg.Log = slog.New(logs)
	fs, err := oidc.NewFlowState(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	claims := fp.DefaultClaims(oidcTestClientID, fs.Nonce)
	claims.Subject = "x\nFORGED"
	fp.NextIDToken = fp.SignRS256(t, claims)

	req := oidcCallbackRequest(t, g, ts, fs, "state="+fs.State+"&code=test-code")
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	logs.mu.Lock()
	defer logs.mu.Unlock()
	found := false
	for _, msg := range logs.msgs {
		if !strings.Contains(msg, "refused SSO login") {
			continue
		}
		found = true
		if strings.Contains(msg, "\n") || !strings.Contains(msg, `x\nFORGED`) {
			t.Errorf("the subject reached the log unescaped: %q", msg)
		}
	}
	if !found {
		t.Fatalf("no refused-login line was logged; got %q", logs.msgs)
	}
}

// TestOIDCCallbackPolicyRefusalOnReturningUser covers the other half of
// docs/design.md's "re-checked on every login": TestOIDCCallbackPolicyRefusal
// above only exercises a refusal on first provisioning. Here the same
// identity signs in successfully once, then has its access revoked at
// the IdP (modelled by tightening the policy in place), and must be
// refused on its very next sign-in -- not grandfathered in because an
// account already exists for it.
func TestOIDCCallbackPolicyRefusalOnReturningUser(t *testing.T) {
	g, ts, fp := newOIDCTestGate(t, oidc.Policy{})

	fs1, err := oidc.NewFlowState(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs1.Nonce))
	req1 := oidcCallbackRequest(t, g, ts, fs1, "state="+fs1.State+"&code=test-code")
	resp1, err := noRedirectClient().Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp1.Body.Close() }()
	if resp1.StatusCode != http.StatusFound || resp1.Header.Get("Location") != "/" {
		t.Fatalf("first login: status=%d location=%q, want 302 to /", resp1.StatusCode, resp1.Header.Get("Location"))
	}
	if g.deps.Users.Count() != 2 {
		t.Fatalf("expected the admin plus one provisioned account after the first login, got %d", g.deps.Users.Count())
	}

	// The policy tightens after that first, successful login -- standing
	// in for the person's access being revoked at the IdP. DefaultClaims'
	// email (person@example.com) is not on this allowlist.
	g.deps.OIDCPolicy = oidc.Policy{AllowedEmails: []string{"someone-else@example.com"}}

	fs2, err := oidc.NewFlowState(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs2.Nonce))
	req2 := oidcCallbackRequest(t, g, ts, fs2, "state="+fs2.State+"&code=test-code")
	resp2, err := noRedirectClient().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if loc := resp2.Header.Get("Location"); loc != testLoginPath+"?ssoError=not_permitted" {
		t.Errorf("returning user's second login: redirect location = %q, want the not_permitted ssoError", loc)
	}
	for _, c := range resp2.Cookies() {
		if c.Name == testCookieName {
			t.Error("a policy-refused login for a returning user must not set a session cookie")
		}
	}
	if g.deps.Users.Count() != 2 {
		t.Error("a policy refusal on a returning user must not provision another account")
	}
}

func TestOIDCCallbackProviderErrorRefused(t *testing.T) {
	g, ts, _ := newOIDCTestGate(t, oidc.Policy{})
	fs, err := oidc.NewFlowState(time.Now())
	if err != nil {
		t.Fatal(err)
	}

	req := oidcCallbackRequest(t, g, ts, fs, "state="+fs.State+"&error=access_denied")
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if loc := resp.Header.Get("Location"); loc != testLoginPath+"?ssoError=provider_error" {
		t.Errorf("redirect location = %q, want the provider_error ssoError", loc)
	}
}

func TestOIDCLoginRedirectsToProviderAndSetsFlowCookie(t *testing.T) {
	g, ts, fp := newOIDCTestGate(t, oidc.Policy{})
	resp, err := noRedirectClient().Get(ts.URL + "/api/auth/oidc/login")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login returned %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("expected a redirect Location")
	}
	if !strings.HasPrefix(loc, fp.Issuer()+"/authorize") {
		t.Errorf("redirect Location = %q, want the provider's authorization endpoint %s/authorize", loc, fp.Issuer())
	}
	var flowCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == oidcFlowCookieName {
			flowCookie = c
		}
	}
	if flowCookie == nil {
		t.Fatal("expected the OIDC flow cookie to be set")
	}
	_ = g
}

// TestOIDCRoutesAreNotFoundWithoutOIDC pins "Deps.OIDC nil => those
// answer 404" (docs/design.md §1.5) for all three routes.
func TestOIDCRoutesAreNotFoundWithoutOIDC(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	// registerAdminNoFactor: the test signs in again below with only a
	// password, which needs a full session, not the pending login a
	// confirmed factor would leave it with -- not what this test is about.
	registerAdminNoFactor(t, ts, "admin", "password-placeholder-1")

	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodGet, "/api/auth/oidc/login"},
		{http.MethodGet, "/api/auth/oidc/callback"},
	} {
		req, err := http.NewRequest(tc.method, ts.URL+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s got %d with SSO off, want 404", tc.method, tc.path, resp.StatusCode)
		}
	}

	admin := &http.Client{Jar: mustCookieJar(t)}
	_ = postJSON(t, admin, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "password-placeholder-1"}).Body.Close()
	enrolTOTPFactor(t, admin, ts, "password-placeholder-1") // POST /api/auth/oidc/link is not an enrolment route
	linkResp := postJSON(t, admin, ts.URL+"/api/auth/oidc/link", map[string]any{})
	defer func() { _ = linkResp.Body.Close() }()
	if linkResp.StatusCode != http.StatusNotFound {
		t.Errorf("POST /api/auth/oidc/link got %d with SSO off, want 404", linkResp.StatusCode)
	}
}

func TestOIDCLinkStartRefusesAlreadySSOOnlyAccount(t *testing.T) {
	g, ts, _ := newEmptyOIDCTestGate(t, oidc.Policy{})
	registerAdmin(t, ts, "admin", "password-placeholder-1")
	// A second account, SSO-provisioned from the start.
	u, _, err := g.deps.Users.FindOrCreateOIDCUser("https://idp.example", "subject-1", "frodo", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sess := g.deps.Sessions.Create(u.ID, time.Now())
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/oidc/link", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(csrfHeaderName, testCSRFValue)
	req.AddCookie(&http.Cookie{Name: testCookieName, Value: sess.ID})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("starting a link for an SSO-only account got %d, want 409", resp.StatusCode)
	}
}

func TestOIDCLinkStartRefusesAlreadyConnectedAccount(t *testing.T) {
	g, ts, fp := newEmptyOIDCTestGate(t, oidc.Policy{})
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")

	// Link once, successfully.
	fs := oidcCompleteLinkFlow(t, g, ts, admin, testAdminPassword, fp)
	_ = fs

	// A second attempt is refused before any provider round trip.
	resp := postJSON(t, admin, ts.URL+"/api/auth/oidc/link", map[string]any{})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("starting a second link got %d, want 409", resp.StatusCode)
	}
}

// TestOIDCLinkStartAsksForThePassword: a link is permanent and strips a
// non-admin of its password and factors, so the session cookie alone
// must not start one. No password, or a wrong one, is 401 and seals no
// flow state; the right one goes on to the provider.
func TestOIDCLinkStartAsksForThePassword(t *testing.T) {
	_, ts, _ := newEmptyOIDCTestGate(t, oidc.Policy{})
	admin := registerAdmin(t, ts, "admin", testAdminPassword)

	for name, body := range map[string]any{
		"no body field":  map[string]any{},
		"wrong password": oidcLinkStartRequest{Password: "not-the-password"},
	} {
		resp := postJSON(t, admin, ts.URL+"/api/auth/oidc/link", body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: link start got %d, want 401", name, resp.StatusCode)
		}
		if cookieNamed(resp, oidcFlowCookieName) != nil {
			t.Errorf("%s: link start sealed a flow cookie", name)
		}
	}

	resp := postJSON(t, admin, ts.URL+"/api/auth/oidc/link", oidcLinkStartRequest{Password: testAdminPassword})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("link start with the right password got %d, want 200", resp.StatusCode)
	}
	if cookieNamed(resp, oidcFlowCookieName) == nil {
		t.Error("link start with the right password sealed no flow cookie")
	}
}

// TestOIDCLinkRevokesEarlierSessionsInMemory: completing a link drops
// the account's live sessions on the spot, as a password change does,
// rather than leaving them to the stored cutoff alone. The link records
// itself only in SessionsEndedAt, and an older build saving the
// document while this one runs drops that field (#28). Here the field
// is stripped from the stored account after the link and the store
// reloaded from that document: a session from before the link -- the
// linking browser's old one, and another device's -- must still be
// refused.
func TestOIDCLinkRevokesEarlierSessionsInMemory(t *testing.T) {
	g, ts, fp := newEmptyOIDCTestGate(t, oidc.Policy{})
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")
	adminUser, ok := g.deps.Users.ByUsername("admin")
	if !ok {
		t.Fatal("no admin account")
	}
	u, _ := url.Parse(ts.URL)
	var linkingCookie *http.Cookie
	for _, c := range admin.Jar.Cookies(u) {
		if c.Name == testCookieName {
			linkingCookie = &http.Cookie{Name: c.Name, Value: c.Value}
		}
	}
	if linkingCookie == nil {
		t.Fatal("the admin client holds no session cookie")
	}
	other := g.deps.Sessions.Create(adminUser.ID, time.Now().Add(-time.Minute))
	otherCookie := &http.Cookie{Name: testCookieName, Value: other.ID}

	oidcCompleteLinkFlow(t, g, ts, admin, testAdminPassword, fp)

	linked, ok := g.deps.Users.Get(adminUser.ID)
	if !ok || linked.SessionsEndedAt.IsZero() {
		t.Fatalf("test setup: the link recorded no SessionsEndedAt (%+v)", linked)
	}
	stripped := *linked
	stripped.SessionsEndedAt = time.Time{}
	g.deps.Users = openStoreWithUsers(t, stripped)

	for name, c := range map[string]*http.Cookie{"the linking browser's old session": linkingCookie, "another device's session": otherCookie} {
		if got := protectedStatusWithCookie(t, http.DefaultClient, ts.URL, c); got != http.StatusUnauthorized {
			t.Errorf("%s, issued before the link, got %d once the stored cutoff was lost; want 401", name, got)
		}
	}
	if got := protectedStatusWithCookie(t, admin, ts.URL, nil); got != http.StatusOK {
		t.Errorf("the session the link issued got %d, want 200", got)
	}
}

// oidcCompleteLinkFlow drives handleOIDCLinkStart + the callback for
// client (already signed in, with password) end to end, returning the
// FlowState used.
func oidcCompleteLinkFlow(t *testing.T, g *Gate, ts *httptest.Server, client *http.Client, password string, fp *testutil.FakeProvider) oidc.FlowState {
	t.Helper()
	startResp := postJSON(t, client, ts.URL+"/api/auth/oidc/link", oidcLinkStartRequest{Password: password})
	defer func() { _ = startResp.Body.Close() }()
	if startResp.StatusCode != http.StatusOK {
		t.Fatalf("link start returned %d", startResp.StatusCode)
	}
	var flowCookie *http.Cookie
	for _, c := range startResp.Cookies() {
		if c.Name == oidcFlowCookieName {
			flowCookie = c
		}
	}
	if flowCookie == nil {
		t.Fatal("expected the OIDC flow cookie to be set by link start")
	}
	fs, err := g.deps.OIDCState.Decode(flowCookie.Value, oidcFlowCookieMaxAge, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/auth/oidc/callback?state="+fs.State+"&code=test-code", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(flowCookie)
	for _, c := range client.Jar.Cookies(req.URL) {
		req.AddCookie(c)
	}
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/?ssoLinked=1" {
		t.Fatalf("link callback returned %d %q, want 302 to /?ssoLinked=1", resp.StatusCode, resp.Header.Get("Location"))
	}
	// LinkOIDCIdentity bumps SessionsEndedAt, which invalidates the
	// session client was signed in with -- the callback issues a fresh
	// one instead, but this response went through noRedirectClient
	// (never client itself), so client's own jar has to be told about it
	// by hand, or every call after this one would find client signed
	// out.
	client.Jar.SetCookies(req.URL, resp.Cookies())
	return fs
}

// TestOIDCLinkCallbackRefusesIdentityAlreadyLinkedElsewhere covers
// completeOIDCLink's ErrOIDCIdentityTaken branch: the identity that
// comes back is already linked to a *different* account.
func TestOIDCLinkCallbackRefusesIdentityAlreadyLinkedElsewhere(t *testing.T) {
	g, ts, fp := newEmptyOIDCTestGate(t, oidc.Policy{})
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")

	// A different account already holds this (issuer, subject).
	if _, _, err := g.deps.Users.FindOrCreateOIDCUser(fp.Issuer(), "test-subject-123", "someoneelse", time.Now()); err != nil {
		t.Fatal(err)
	}

	startResp := postJSON(t, admin, ts.URL+"/api/auth/oidc/link", oidcLinkStartRequest{Password: testAdminPassword})
	defer func() { _ = startResp.Body.Close() }()
	var flowCookie *http.Cookie
	for _, c := range startResp.Cookies() {
		if c.Name == oidcFlowCookieName {
			flowCookie = c
		}
	}
	if flowCookie == nil {
		t.Fatal("expected the OIDC flow cookie to be set by link start")
	}
	fs, err := g.deps.OIDCState.Decode(flowCookie.Value, oidcFlowCookieMaxAge, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// DefaultClaims' Subject is "test-subject-123", matching the account
	// created above.
	fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/auth/oidc/callback?state="+fs.State+"&code=test-code", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(flowCookie)
	for _, c := range admin.Jar.Cookies(req.URL) {
		req.AddCookie(c)
	}
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if loc := resp.Header.Get("Location"); loc != testLoginPath+"?ssoError=link_identity_taken" {
		t.Errorf("redirect location = %q, want the link_identity_taken ssoError", loc)
	}
}

// TestOIDCLinkCallbackSessionChangedRefused covers completeOIDCLink's
// "the browser is signed in as someone else by the time the provider
// comes back" branch.
func TestOIDCLinkCallbackSessionChangedRefused(t *testing.T) {
	g, ts, fp := newEmptyOIDCTestGate(t, oidc.Policy{})
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")

	startResp := postJSON(t, admin, ts.URL+"/api/auth/oidc/link", oidcLinkStartRequest{Password: testAdminPassword})
	defer func() { _ = startResp.Body.Close() }()
	var flowCookie *http.Cookie
	for _, c := range startResp.Cookies() {
		if c.Name == oidcFlowCookieName {
			flowCookie = c
		}
	}
	if flowCookie == nil {
		t.Fatal("expected the OIDC flow cookie to be set by link start")
	}
	fs, err := g.deps.OIDCState.Decode(flowCookie.Value, oidcFlowCookieMaxAge, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))

	// No session cookie at all on the callback request -- as if the
	// browser had signed out (or a different browser altogether)
	// between starting the link and the provider redirect back.
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/auth/oidc/callback?state="+fs.State+"&code=test-code", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(flowCookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if loc := resp.Header.Get("Location"); loc != testLoginPath+"?ssoError=link_session_changed" {
		t.Errorf("redirect location = %q, want the link_session_changed ssoError", loc)
	}

	g.deps.Users.List() // silence unused warnings if any
}

// TestOIDCLinkNonAdminLosesLocalPassword covers completeOIDCLink's
// non-admin audit-detail branch: a plain user loses its local password
// on linking, unlike the admin.
func TestOIDCLinkNonAdminLosesLocalPassword(t *testing.T) {
	g, ts, fp := newEmptyOIDCTestGate(t, oidc.Policy{})
	adminClient := registerAdmin(t, ts, "admin", "password-placeholder-1")
	_ = postJSON(t, adminClient, ts.URL+"/api/auth/users",
		createUserRequest{Username: "operator", Password: "operator-password-placeholder", Role: "user"}).Body.Close()
	operator := loggedInClient(t, ts, "operator", "operator-password-placeholder")
	enrolTOTPFactor(t, operator, ts, "operator-password-placeholder") // POST /api/auth/oidc/link is not an enrolment route

	oidcCompleteLinkFlow(t, g, ts, operator, "operator-password-placeholder", fp)

	u, ok := g.deps.Users.ByUsername("operator")
	if !ok || u.LocalPassword() {
		t.Error("expected the non-admin account to lose its local password on linking")
	}
}

// TestOIDCCallbackMissingFlowCookieRefused and its siblings cover
// handleOIDCCallback's earlier refusal branches, none of which need a
// real flow cookie at all.
func TestOIDCCallbackMissingFlowCookieRefused(t *testing.T) {
	_, ts, _ := newOIDCTestGate(t, oidc.Policy{})
	resp, err := noRedirectClient().Get(ts.URL + "/api/auth/oidc/callback?state=x&code=y")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if loc := resp.Header.Get("Location"); loc != testLoginPath+"?ssoError=state_mismatch" {
		t.Errorf("redirect location = %q, want the state_mismatch ssoError", loc)
	}
}

func TestOIDCCallbackGarbledFlowCookieRefused(t *testing.T) {
	_, ts, _ := newOIDCTestGate(t, oidc.Policy{})
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/auth/oidc/callback?state=x&code=y", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: oidcFlowCookieName, Value: "not-a-real-sealed-value"})
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if loc := resp.Header.Get("Location"); loc != testLoginPath+"?ssoError=state_mismatch" {
		t.Errorf("redirect location = %q, want the state_mismatch ssoError", loc)
	}
}

func TestOIDCCallbackMissingCodeParamRefused(t *testing.T) {
	g, ts, fp := newOIDCTestGate(t, oidc.Policy{})
	fs, err := oidc.NewFlowState(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_ = fp
	req := oidcCallbackRequest(t, g, ts, fs, "state="+fs.State)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if loc := resp.Header.Get("Location"); loc != testLoginPath+"?ssoError=provider_error" {
		t.Errorf("redirect location = %q, want the provider_error ssoError", loc)
	}
}

// TestOIDCCallbackBadSignatureRefused covers VerifyIDToken's failure
// path from the route: an alg=none token is authentic-looking but
// carries no valid signature the verifier's allowlisted algorithms
// (RS256/ES256/PS256) will ever accept.
func TestOIDCCallbackBadSignatureRefused(t *testing.T) {
	g, ts, fp := newOIDCTestGate(t, oidc.Policy{})
	fs, err := oidc.NewFlowState(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fp.NextIDToken = fp.SignNoneAlgorithm(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))

	req := oidcCallbackRequest(t, g, ts, fs, "state="+fs.State+"&code=test-code")
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if loc := resp.Header.Get("Location"); loc != testLoginPath+"?ssoError=verification_failed" {
		t.Errorf("redirect location = %q, want the verification_failed ssoError", loc)
	}
}

// TestOIDCLinkHappyPath drives the link-start + callback pair end to
// end: an admin (which keeps its password on a link) starts a link,
// completes it against the fake provider, and ends up with both
// credentials working.
func TestOIDCLinkHappyPath(t *testing.T) {
	g, ts, fp := newEmptyOIDCTestGate(t, oidc.Policy{})
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")

	startResp := postJSON(t, admin, ts.URL+"/api/auth/oidc/link", oidcLinkStartRequest{Password: testAdminPassword})
	defer func() { _ = startResp.Body.Close() }()
	if startResp.StatusCode != http.StatusOK {
		t.Fatalf("link start returned %d", startResp.StatusCode)
	}
	var flowCookie *http.Cookie
	for _, c := range startResp.Cookies() {
		if c.Name == oidcFlowCookieName {
			flowCookie = c
		}
	}
	if flowCookie == nil {
		t.Fatal("expected the OIDC flow cookie to be set by link start")
	}

	adminUser, ok := g.deps.Users.ByUsername("admin")
	if !ok {
		t.Fatal("no admin account")
	}
	// Decode the sealed flow to recover State/Nonce for the callback --
	// the test drives the callback directly rather than an actual
	// browser round trip through the fake provider's /authorize (which
	// deliberately 501s, per FakeProvider's own doc comment).
	fs, err := g.deps.OIDCState.Decode(flowCookie.Value, oidcFlowCookieMaxAge, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if fs.LinkUserID != adminUser.ID {
		t.Fatalf("flow LinkUserID = %q, want %q", fs.LinkUserID, adminUser.ID)
	}
	fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/auth/oidc/callback?state="+fs.State+"&code=test-code", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(flowCookie)
	for _, c := range admin.Jar.Cookies(req.URL) {
		req.AddCookie(c)
	}
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("link callback returned %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/?ssoLinked=1" {
		t.Errorf("redirect location = %q, want %q", loc, "/?ssoLinked=1")
	}

	linked, ok := g.deps.Users.Get(adminUser.ID)
	if !ok || linked.OIDCSubject == "" {
		t.Error("expected the admin account to carry the linked SSO identity")
	}
	if !linked.LocalPassword() {
		t.Error("expected the admin to keep its local password after linking")
	}
}

// TestOIDCLinkStartRefusesAnonymousCaller covers handleOIDCLinkStart's
// own "sign in first" check with OIDC actually configured (distinct
// from the SSO-off 404 case) -- called directly rather than through
// Protect, since Protect's own session check already refuses any
// request that would otherwise reach this handler with no caller in
// context, the same "defensive, not reachable via the real route table"
// case as the other handlers' equivalent checks.
func TestOIDCLinkStartRefusesAnonymousCaller(t *testing.T) {
	g, _, _ := newOIDCTestGate(t, oidc.Policy{})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/oidc/link", nil)
	rec := httptest.NewRecorder()
	g.handleOIDCLinkStart(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("starting a link with no caller in context got %d, want 401", rec.Code)
	}
}

// TestOIDCCallbackUsesEmailWhenPreferredUsernameEmpty covers the
// username-hint fallback: a provider that releases no preferred_username
// claim still gets a usable hint from email.
func TestOIDCCallbackUsesEmailWhenPreferredUsernameEmpty(t *testing.T) {
	g, ts, fp := newOIDCTestGate(t, oidc.Policy{})
	fs, err := oidc.NewFlowState(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	claims := fp.DefaultClaims(oidcTestClientID, fs.Nonce)
	claims.PreferredUsername = ""
	claims.Email = "no-preferred-username@example.com"
	fp.NextIDToken = fp.SignRS256(t, claims)

	req := oidcCallbackRequest(t, g, ts, fs, "state="+fs.State+"&code=test-code")
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("callback returned %d %q, want 302 to /", resp.StatusCode, resp.Header.Get("Location"))
	}
	u, ok := g.deps.Users.ByUsername("no-preferred-username@example.com")
	if !ok {
		// FindOrCreateOIDCUser sanitises an email-shaped hint into a
		// synthetic username -- assert on the identity instead of the
		// exact name it landed on.
		users := g.deps.Users.List()
		if len(users) != 1 {
			t.Fatalf("expected exactly one provisioned account, got %d", len(users))
		}
		u = &users[0]
	}
	if u.OIDCSubject == "" {
		t.Error("expected the provisioned account to carry the OIDC identity")
	}
}

// TestAllowIssuerRefusesKnownMultiTenantProviders is a sanity check on
// the fail-closed startup call an application wiring Deps.OIDC is
// expected to make (oidc.AllowIssuerWithPolicy, ADR-0014) --
// belt-and-braces over oidc.New's and gate.New's own enforcement of the
// same rule. The enforcement itself lives in the oidc package's own,
// more exhaustive tests; this pins that gate's own docs are backed by a
// real assertion: a shared issuer with no tenant pinned is refused.
func TestAllowIssuerRefusesKnownMultiTenantProviders(t *testing.T) {
	if err := oidc.AllowIssuerWithPolicy("https://accounts.google.com", oidc.Policy{}); err == nil {
		t.Error("expected a shared issuer with no tenant claim pinned to be refused")
	}
}

// warnRecorder keeps the message of each Warn record and nothing else.
type warnRecorder struct {
	mu   sync.Mutex
	msgs []string
}

func (w *warnRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (w *warnRecorder) Handle(_ context.Context, r slog.Record) error {
	if r.Level == slog.LevelWarn {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.msgs = append(w.msgs, r.Message)
	}
	return nil
}
func (w *warnRecorder) WithAttrs([]slog.Attr) slog.Handler { return w }
func (w *warnRecorder) WithGroup(string) slog.Handler      { return w }

// TestOIDCCallbackFailuresAreLogged: the changelog promises a failed SSO
// login or link is logged. Every failed callback writes exactly one Warn
// line naming the ssoError it sent and where the request came from; a
// successful login or link writes none.
func TestOIDCCallbackFailuresAreLogged(t *testing.T) {
	// linkCallback starts a link as admin and returns the callback
	// request carrying the flow cookie, with admin's session cookie only
	// when withSession is set.
	linkCallback := func(t *testing.T, g *Gate, ts *httptest.Server, fp *testutil.FakeProvider, admin *http.Client, withSession bool) *http.Request {
		t.Helper()
		startResp := postJSON(t, admin, ts.URL+"/api/auth/oidc/link", oidcLinkStartRequest{Password: testAdminPassword})
		_ = startResp.Body.Close()
		var flowCookie *http.Cookie
		for _, c := range startResp.Cookies() {
			if c.Name == oidcFlowCookieName {
				flowCookie = c
			}
		}
		if flowCookie == nil {
			t.Fatal("expected the OIDC flow cookie to be set by link start")
		}
		fs, err := g.deps.OIDCState.Decode(flowCookie.Value, oidcFlowCookieMaxAge, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/auth/oidc/callback?state="+fs.State+"&code=test-code", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(flowCookie)
		if withSession {
			for _, c := range admin.Jar.Cookies(req.URL) {
				req.AddCookie(c)
			}
		}
		return req
	}
	newFlow := func(t *testing.T) oidc.FlowState {
		t.Helper()
		fs, err := oidc.NewFlowState(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return fs
	}

	cases := []struct {
		name string
		// code is the ssoError the callback must send; "" for success.
		code string
		// request sets the scene and returns the callback request; it
		// runs after the first admin is registered (SSO never creates
		// the first account) and before the log is captured.
		request func(t *testing.T, g *Gate, ts *httptest.Server, fp *testutil.FakeProvider, admin *http.Client) *http.Request
	}{
		{"missing flow cookie", "state_mismatch", func(t *testing.T, g *Gate, ts *httptest.Server, fp *testutil.FakeProvider, admin *http.Client) *http.Request {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/auth/oidc/callback?state=x&code=y", nil)
			if err != nil {
				t.Fatal(err)
			}
			return req
		}},
		{"state mismatch", "state_mismatch", func(t *testing.T, g *Gate, ts *httptest.Server, fp *testutil.FakeProvider, admin *http.Client) *http.Request {
			return oidcCallbackRequest(t, g, ts, newFlow(t), "state=not-the-right-state&code=test-code")
		}},
		{"provider error", "provider_error", func(t *testing.T, g *Gate, ts *httptest.Server, fp *testutil.FakeProvider, admin *http.Client) *http.Request {
			fs := newFlow(t)
			return oidcCallbackRequest(t, g, ts, fs, "state="+fs.State+"&error=access_denied")
		}},
		{"verification failed", "verification_failed", func(t *testing.T, g *Gate, ts *httptest.Server, fp *testutil.FakeProvider, admin *http.Client) *http.Request {
			fs := newFlow(t)
			fp.NextIDToken = fp.SignNoneAlgorithm(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))
			return oidcCallbackRequest(t, g, ts, fs, "state="+fs.State+"&code=test-code")
		}},
		{"nonce mismatch", "state_mismatch", func(t *testing.T, g *Gate, ts *httptest.Server, fp *testutil.FakeProvider, admin *http.Client) *http.Request {
			fs := newFlow(t)
			fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, "a-different-nonce-entirely"))
			return oidcCallbackRequest(t, g, ts, fs, "state="+fs.State+"&code=test-code")
		}},
		{"link session changed", "link_session_changed", func(t *testing.T, g *Gate, ts *httptest.Server, fp *testutil.FakeProvider, admin *http.Client) *http.Request {
			return linkCallback(t, g, ts, fp, admin, false)
		}},
		{"link identity taken", "link_identity_taken", func(t *testing.T, g *Gate, ts *httptest.Server, fp *testutil.FakeProvider, admin *http.Client) *http.Request {
			if _, _, err := g.deps.Users.FindOrCreateOIDCUser(fp.Issuer(), "test-subject-123", "someoneelse", time.Now()); err != nil {
				t.Fatal(err)
			}
			return linkCallback(t, g, ts, fp, admin, true)
		}},
		{"login succeeds", "", func(t *testing.T, g *Gate, ts *httptest.Server, fp *testutil.FakeProvider, admin *http.Client) *http.Request {
			fs := newFlow(t)
			fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))
			return oidcCallbackRequest(t, g, ts, fs, "state="+fs.State+"&code=test-code")
		}},
		{"link succeeds", "", func(t *testing.T, g *Gate, ts *httptest.Server, fp *testutil.FakeProvider, admin *http.Client) *http.Request {
			return linkCallback(t, g, ts, fp, admin, true)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, ts, fp := newEmptyOIDCTestGate(t, oidc.Policy{})
			admin := registerAdmin(t, ts, "admin", "password-placeholder-1")
			req := tc.request(t, g, ts, fp, admin)
			logs := &warnRecorder{}
			g.cfg.Log = slog.New(logs)

			resp, err := noRedirectClient().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			loc := resp.Header.Get("Location")

			logs.mu.Lock()
			defer logs.mu.Unlock()
			if tc.code == "" {
				if strings.Contains(loc, "ssoError") {
					t.Fatalf("callback redirected to %q, want success", loc)
				}
				if len(logs.msgs) != 0 {
					t.Errorf("a successful callback logged warnings: %q", logs.msgs)
				}
				return
			}
			if want := testLoginPath + "?ssoError=" + tc.code; loc != want {
				t.Fatalf("redirect location = %q, want %q", loc, want)
			}
			if len(logs.msgs) != 1 {
				t.Fatalf("got %d warnings, want exactly one: %q", len(logs.msgs), logs.msgs)
			}
			if !strings.Contains(logs.msgs[0], "ssoError="+tc.code) || !strings.Contains(logs.msgs[0], "from=") {
				t.Errorf("warning %q does not name ssoError=%s and the client address", logs.msgs[0], tc.code)
			}
		})
	}
}

// TestOIDCCallbackFailureLogIsRated: a stranger can hit the callback as
// fast as they like, so repeats of one failure from one address share a
// line, like the other refusals (warnRated).
func TestOIDCCallbackFailureLogIsRated(t *testing.T) {
	g, ts, _ := newOIDCTestGate(t, oidc.Policy{})
	logs := &warnRecorder{}
	g.cfg.Log = slog.New(logs)
	for range 3 {
		resp, err := noRedirectClient().Get(ts.URL + "/api/auth/oidc/callback?state=x&code=y")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	logs.mu.Lock()
	defer logs.mu.Unlock()
	if len(logs.msgs) != 1 {
		t.Errorf("got %d warnings for three identical failures, want one: %q", len(logs.msgs), logs.msgs)
	}
}

// The OIDC flow cookie must reach both OIDC routes; the routes stay
// string literals for the contract tests, so this keeps them from
// drifting out from under the cookie's Path (#58).
func TestOIDCFlowCookiePathCoversItsRoutes(t *testing.T) {
	for _, route := range []string{oidcLoginPath, oidcCallbackPath} {
		if !strings.HasPrefix(route, oidcFlowCookiePath+"/") {
			t.Errorf("route %q is not under the OIDC flow cookie's Path %q", route, oidcFlowCookiePath)
		}
	}
}

// ssoRolesGate is an SSO gate whose policy maps groups to roles, with an
// audit recorder and a notice recorder attached (#76, ADR-0013).
type ssoRolesGate struct {
	g     *Gate
	ts    *httptest.Server
	fp    *testutil.FakeProvider
	audit *auditRecorder
	notes *noticeRecorder
}

func newSSORolesGate(t *testing.T, policy oidc.Policy) *ssoRolesGate {
	t.Helper()
	g, ts, fp := newOIDCTestGate(t, policy)
	f := &ssoRolesGate{g: g, ts: ts, fp: fp, audit: &auditRecorder{}, notes: &noticeRecorder{}}
	g.cfg.Audit = f.audit
	g.cfg.Notices = f.notes
	return f
}

// signIn runs the SSO callback for subject with groups in the token and
// returns the session cookie it set, nil if none.
func (f *ssoRolesGate) signIn(t *testing.T, subject string, groups []string) *http.Cookie {
	t.Helper()
	fs, err := oidc.NewFlowState(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	claims := f.fp.DefaultClaims(oidcTestClientID, fs.Nonce)
	claims.Subject, claims.PreferredUsername, claims.Email, claims.Groups = subject, subject, subject+"@example.com", groups
	f.fp.NextIDToken = f.fp.SignRS256(t, claims)

	resp, err := noRedirectClient().Do(oidcCallbackRequest(t, f.g, f.ts, fs, "state="+fs.State+"&code=test-code"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Fatalf("sign-in of %q redirected to %q, want /", subject, loc)
	}
	for _, c := range resp.Cookies() {
		if c.Name == testCookieName {
			return c
		}
	}
	return nil
}

func (f *ssoRolesGate) role(t *testing.T, subject string) gauntlet.Role {
	t.Helper()
	u, ok := f.g.deps.Users.ByOIDCIdentity(f.fp.Issuer(), subject)
	if !ok {
		t.Fatalf("no account for %q", subject)
	}
	return u.Role
}

func (f *ssoRolesGate) roleNotices() []AccountNotice {
	f.g.notifying.Wait() // notices are sent in the background
	f.notes.mu.Lock()
	defer f.notes.mu.Unlock()
	var out []AccountNotice
	for _, n := range f.notes.notices {
		if n.Kind == NoticeRoleChanged {
			out = append(out, n)
		}
	}
	return out
}

func TestSSORolesHighestOfSeveralGroupsWins(t *testing.T) {
	f := newSSORolesGate(t, oidc.Policy{RoleFromGroups: map[string]string{"staff": "user", "guests": "viewer"}})

	// Both orders, and the group names matched like AllowedGroups.
	f.signIn(t, "both-a", []string{"guests", "staff"})
	f.signIn(t, "both-b", []string{" STAFF ", "guests"})
	f.signIn(t, "guest", []string{"guests", "unmapped"})
	for subject, want := range map[string]gauntlet.Role{"both-a": gauntlet.RoleUser, "both-b": gauntlet.RoleUser, "guest": gauntlet.RoleViewer} {
		if got := f.role(t, subject); got != want {
			t.Errorf("%s: role = %q, want %q", subject, got, want)
		}
	}
}

func TestSSORolesFallbackIsViewerByDefaultAndUserWhenAsked(t *testing.T) {
	f := newSSORolesGate(t, oidc.Policy{RoleFromGroups: map[string]string{"staff": "user"}})
	f.signIn(t, "stranger", []string{"other"})
	f.signIn(t, "no-claim", nil) // an absent groups claim is "no group", not a refusal
	for _, subject := range []string{"stranger", "no-claim"} {
		if got := f.role(t, subject); got != gauntlet.RoleViewer {
			t.Errorf("%s: role = %q, want viewer (the default for no mapped group)", subject, got)
		}
	}

	f.g.deps.OIDCPolicy.RoleWithoutGroup = "user"
	f.signIn(t, "stranger-2", []string{"other"})
	f.signIn(t, "no-claim-2", nil)
	for _, subject := range []string{"stranger-2", "no-claim-2"} {
		if got := f.role(t, subject); got != gauntlet.RoleUser {
			t.Errorf("%s: role = %q, want user with RoleWithoutGroup set", subject, got)
		}
	}
}

func TestSSORolesNoMapLeavesRolesAlone(t *testing.T) {
	f := newSSORolesGate(t, oidc.Policy{})
	f.signIn(t, "plain", []string{"guests"})
	if got := f.role(t, "plain"); got != gauntlet.RoleUser {
		t.Errorf("role = %q, want user: no map, no change", got)
	}
	u, _ := f.g.deps.Users.ByOIDCIdentity(f.fp.Issuer(), "plain")
	if _, _, err := f.g.deps.Users.SetRole(u.ID, gauntlet.RoleViewer, time.Now()); err != nil {
		t.Fatal(err)
	}
	f.signIn(t, "plain", []string{"staff"})
	if got := f.role(t, "plain"); got != gauntlet.RoleViewer {
		t.Errorf("role = %q, want viewer kept: with no map an admin's choice stands", got)
	}
	if n := len(f.roleNotices()); n != 0 {
		t.Errorf("%d role notices, want 0", n)
	}
}

func TestSSORolesDowngradeAuditsNotifiesAndEndsOtherSessions(t *testing.T) {
	f := newSSORolesGate(t, oidc.Policy{RoleFromGroups: map[string]string{"staff": "user", "guests": "viewer"}})
	f.signIn(t, "pat", []string{"staff"})
	u, _ := f.g.deps.Users.ByOIDCIdentity(f.fp.Issuer(), "pat")
	other := f.g.deps.Sessions.Create(u.ID, time.Now().Add(-time.Minute))
	otherCookie := &http.Cookie{Name: testCookieName, Value: other.ID}
	if got := protectedStatusWithCookie(t, http.DefaultClient, f.ts.URL, otherCookie); got != http.StatusOK {
		t.Fatalf("test setup: the other session got %d, want 200", got)
	}
	if n := len(f.roleNotices()); n != 0 {
		t.Fatalf("test setup: %d role notices before any change", n)
	}

	// The group changes at the provider: pat moves from staff to guests.
	fresh := f.signIn(t, "pat", []string{"guests"})

	if got := f.role(t, "pat"); got != gauntlet.RoleViewer {
		t.Fatalf("role = %q, want viewer", got)
	}
	if got := protectedStatusWithCookie(t, http.DefaultClient, f.ts.URL, otherCookie); got != http.StatusUnauthorized {
		t.Errorf("the other session got %d after the downgrade, want 401", got)
	}
	if fresh == nil {
		t.Fatal("the downgrading sign-in issued no session")
	}
	if got := protectedStatusWithCookie(t, http.DefaultClient, f.ts.URL, fresh); got != http.StatusOK {
		t.Errorf("the new session got %d, want 200", got)
	}

	e := findAuditEntry(t, f.g, "user.role_changed")
	wantDetail := `from=user to=viewer; by group map at issuer "` + f.fp.Issuer() + `"; sessions ended: all; from=`
	if e.Actor != "sso" || e.Target != "pat" || !strings.HasPrefix(e.Detail, wantDetail) {
		t.Errorf("audit entry = %+v, want actor sso on pat with detail starting %q", e, wantDetail)
	}
	notices := f.roleNotices()
	if len(notices) != 1 {
		t.Fatalf("%d role notices, want 1", len(notices))
	}
	n := notices[0]
	if n.By != "" || n.Username != "pat" || n.Role != gauntlet.RoleViewer || n.RoleChanged == nil ||
		n.RoleChanged.From != gauntlet.RoleUser || n.RoleChanged.To != gauntlet.RoleViewer || !n.RoleChanged.ViaSSO {
		t.Errorf("notice = %+v (%+v), want a viewer change by nobody, ViaSSO", n, n.RoleChanged)
	}
}

func TestSSORolesUpgradeKeepsSessionsAndSaysSo(t *testing.T) {
	f := newSSORolesGate(t, oidc.Policy{RoleFromGroups: map[string]string{"staff": "user", "guests": "viewer"}})
	f.signIn(t, "sam", []string{"guests"})
	u, _ := f.g.deps.Users.ByOIDCIdentity(f.fp.Issuer(), "sam")
	other := f.g.deps.Sessions.Create(u.ID, time.Now().Add(-time.Minute))

	f.signIn(t, "sam", []string{"staff"})

	if got := f.role(t, "sam"); got != gauntlet.RoleUser {
		t.Fatalf("role = %q, want user", got)
	}
	if got := protectedStatusWithCookie(t, http.DefaultClient, f.ts.URL, &http.Cookie{Name: testCookieName, Value: other.ID}); got != http.StatusOK {
		t.Errorf("the other session got %d after an upgrade, want 200", got)
	}
	e := findAuditEntry(t, f.g, "user.role_changed")
	if strings.Contains(e.Detail, "sessions ended") || !strings.HasPrefix(e.Detail, "from=viewer to=user; ") {
		t.Errorf("audit detail = %q, want an upgrade with no sessions ended", e.Detail)
	}
}

func TestSSORolesCreationAtTheMappedRoleIsNotAChange(t *testing.T) {
	f := newSSORolesGate(t, oidc.Policy{RoleFromGroups: map[string]string{"guests": "viewer"}})
	f.signIn(t, "new", []string{"guests"})
	if got := f.role(t, "new"); got != gauntlet.RoleViewer {
		t.Fatalf("role = %q, want viewer from creation", got)
	}
	if n := len(f.roleNotices()); n != 0 {
		t.Errorf("%d role notices for a creation, want 0", n)
	}
}

func TestSSORolesNeverTouchAnAdmin(t *testing.T) {
	f := newSSORolesGate(t, oidc.Policy{RoleFromGroups: map[string]string{"guests": "viewer"}})
	f.signIn(t, "boss", []string{"guests"})
	u, _ := f.g.deps.Users.ByOIDCIdentity(f.fp.Issuer(), "boss")
	if _, _, err := f.g.deps.Users.SetRole(u.ID, gauntlet.RoleAdmin, time.Now()); err != nil {
		t.Fatal(err)
	}
	before := len(f.roleNotices())

	f.signIn(t, "boss", []string{"guests"})
	f.signIn(t, "boss", nil)

	if got := f.role(t, "boss"); got != gauntlet.RoleAdmin {
		t.Errorf("role = %q, want admin untouched by the map", got)
	}
	if n := len(f.roleNotices()) - before; n != 0 {
		t.Errorf("%d role notices for an admin's sign-ins, want 0", n)
	}
}

// TestSSOFirstSignInAuditsTheCreation (#78): an account the SSO callback
// creates is audited as user.create, as an admin-created one is, naming
// the issuer and the role it was given; a later sign-in creates nothing.
func TestSSOFirstSignInAuditsTheCreation(t *testing.T) {
	f := newSSORolesGate(t, oidc.Policy{RoleFromGroups: map[string]string{"staff": "user"}})
	creates := func() []auditEntry {
		rec := f.g.cfg.Audit.(*auditRecorder)
		rec.mu.Lock()
		defer rec.mu.Unlock()
		var out []auditEntry
		for _, e := range rec.entries {
			if e.Action == "user.create" {
				out = append(out, e)
			}
		}
		return out
	}

	f.signIn(t, "newcomer", []string{"other"})
	got := creates()
	if len(got) != 1 {
		t.Fatalf("%d user.create records after an SSO first sign-in, want 1", len(got))
	}
	e := got[0]
	if e.Actor != "sso" || e.Target != "newcomer" ||
		!strings.Contains(e.Detail, "role=viewer") || !strings.Contains(e.Detail, f.fp.Issuer()) {
		t.Errorf("user.create = %+v, want actor sso on newcomer naming role=viewer and the issuer", e)
	}

	f.signIn(t, "newcomer", []string{"other"})
	if n := len(creates()); n != 1 {
		t.Errorf("%d user.create records after a second sign-in, want still 1", n)
	}
}

// A failed callback's warning says why (#80): a provider that refused
// the code exchange, a token that did not verify and an account store
// that could not save all read differently, where each used to be a
// bare ssoError code. The token endpoint's raw body is not logged --
// only its status, error code and description -- since it is the
// provider's text and may echo what was sent to it.
func TestOIDCCallbackFailureLogNamesTheCause(t *testing.T) {
	cases := []struct {
		name, code string
		want       []string
		setup      func(t *testing.T, g *Gate, fp *testutil.FakeProvider, fs oidc.FlowState)
	}{
		{"exchange refused", "provider_error", []string{"401", "invalid_client", "client authentication failed"}, func(t *testing.T, g *Gate, fp *testutil.FakeProvider, fs oidc.FlowState) {
			fp.TokenErrorStatus = http.StatusUnauthorized
			fp.TokenErrorBody = `{"error":"invalid_client","error_description":"client authentication failed","echo":"raw-body-marker"}`
		}},
		{"provider unreachable", "provider_error", []string{"exchanging authorization code"}, func(t *testing.T, g *Gate, fp *testutil.FakeProvider, fs oidc.FlowState) {
			fp.Server.Close()
		}},
		{"token does not verify", "verification_failed", []string{"verifying id_token"}, func(t *testing.T, g *Gate, fp *testutil.FakeProvider, fs oidc.FlowState) {
			fp.NextIDToken = fp.SignNoneAlgorithm(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))
		}},
		{"account store fails", "login_failed", []string{"save refused"}, func(t *testing.T, g *Gate, fp *testutil.FakeProvider, fs oidc.FlowState) {
			fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))
			backend := &budgetBackend{inner: persist.NewMemory(), left: -1}
			users := openTrackedStore(t, backend)
			if _, err := users.Register("setup-admin", "setup-admin-password", time.Now()); err != nil {
				t.Fatal(err)
			}
			backend.left = 0
			g.deps.Users = users
		}},
		{"provider reported an error", "provider_error", []string{"access_denied"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, ts, fp := newOIDCTestGate(t, oidc.Policy{})
			fs, err := oidc.NewFlowState(time.Now())
			if err != nil {
				t.Fatal(err)
			}
			query := "state=" + fs.State + "&code=test-code"
			if tc.setup == nil {
				query = "state=" + fs.State + "&error=access_denied"
			} else {
				tc.setup(t, g, fp, fs)
			}
			logs := &warnRecorder{}
			g.cfg.Log = slog.New(logs)

			resp, err := noRedirectClient().Do(oidcCallbackRequest(t, g, ts, fs, query))
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if want := testLoginPath + "?ssoError=" + tc.code; resp.Header.Get("Location") != want {
				t.Fatalf("redirect location = %q, want %q", resp.Header.Get("Location"), want)
			}
			logs.mu.Lock()
			defer logs.mu.Unlock()
			if len(logs.msgs) != 1 {
				t.Fatalf("got %d warnings, want one: %q", len(logs.msgs), logs.msgs)
			}
			line := logs.msgs[0]
			for _, w := range tc.want {
				if !strings.Contains(line, "cause=") || !strings.Contains(line, w) {
					t.Errorf("warning %q does not give the cause (want %q)", line, w)
				}
			}
			if strings.Contains(line, "raw-body-marker") {
				t.Errorf("warning %q carries the token endpoint's raw body", line)
			}
		})
	}
}
