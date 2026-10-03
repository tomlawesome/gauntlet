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

	"github.com/tomlawesome/gauntlet/internal/testutil"
	"github.com/tomlawesome/gauntlet/oidc"
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
	var flowCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == oidcFlowCookieName {
			flowCookie = c
		}
	}
	if flowCookie == nil {
		t.Fatal("expected the OIDC flow cookie to be set")
	}
	_ = fp
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
	registerAdminNoFactor(t, ts, "admin", "password123")

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
	_ = postJSON(t, admin, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: "password123"}).Body.Close()
	enrolTOTPFactor(t, admin, ts, "password123") // POST /api/auth/oidc/link is not an enrolment route
	linkResp := postJSON(t, admin, ts.URL+"/api/auth/oidc/link", map[string]any{})
	defer func() { _ = linkResp.Body.Close() }()
	if linkResp.StatusCode != http.StatusNotFound {
		t.Errorf("POST /api/auth/oidc/link got %d with SSO off, want 404", linkResp.StatusCode)
	}
}

func TestOIDCLinkStartRefusesAlreadySSOOnlyAccount(t *testing.T) {
	g, ts, _ := newEmptyOIDCTestGate(t, oidc.Policy{})
	registerAdmin(t, ts, "admin", "password123")
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
	admin := registerAdmin(t, ts, "admin", "password123")

	// Link once, successfully.
	fs := oidcCompleteLinkFlow(t, g, ts, admin, fp)
	_ = fs

	// A second attempt is refused before any provider round trip.
	resp := postJSON(t, admin, ts.URL+"/api/auth/oidc/link", map[string]any{})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("starting a second link got %d, want 409", resp.StatusCode)
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
	admin := registerAdmin(t, ts, "admin", "password123")
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

	oidcCompleteLinkFlow(t, g, ts, admin, fp)

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
// client (already signed in) end to end, returning the FlowState used.
func oidcCompleteLinkFlow(t *testing.T, g *Gate, ts *httptest.Server, client *http.Client, fp *testutil.FakeProvider) oidc.FlowState {
	t.Helper()
	startResp := postJSON(t, client, ts.URL+"/api/auth/oidc/link", map[string]any{})
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
	admin := registerAdmin(t, ts, "admin", "password123")

	// A different account already holds this (issuer, subject).
	if _, _, err := g.deps.Users.FindOrCreateOIDCUser(fp.Issuer(), "test-subject-123", "someoneelse", time.Now()); err != nil {
		t.Fatal(err)
	}

	startResp := postJSON(t, admin, ts.URL+"/api/auth/oidc/link", map[string]any{})
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
	admin := registerAdmin(t, ts, "admin", "password123")

	startResp := postJSON(t, admin, ts.URL+"/api/auth/oidc/link", map[string]any{})
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
	adminClient := registerAdmin(t, ts, "admin", "password123")
	_ = postJSON(t, adminClient, ts.URL+"/api/auth/users",
		createUserRequest{Username: "operator", Password: "operator-password-placeholder", Role: "user"}).Body.Close()
	operator := loggedInClient(t, ts, "operator", "operator-password-placeholder")
	enrolTOTPFactor(t, operator, ts, "operator-password-placeholder") // POST /api/auth/oidc/link is not an enrolment route

	oidcCompleteLinkFlow(t, g, ts, operator, fp)

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
	admin := registerAdmin(t, ts, "admin", "password123")

	startResp := postJSON(t, admin, ts.URL+"/api/auth/oidc/link", map[string]any{})
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
// expected to make (oidc.AllowIssuer, docs/design.md §1.4/§4) --
// belt-and-braces over oidc.New's own enforcement of the same policy.
// The enforcement itself lives in the oidc package's own, more
// exhaustive tests; this pins that gate's own docs are backed by a real
// assertion.
func TestAllowIssuerRefusesKnownMultiTenantProviders(t *testing.T) {
	if err := oidc.AllowIssuer("https://accounts.google.com"); err == nil {
		t.Error("expected a known multi-tenant issuer to be refused")
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
		startResp := postJSON(t, admin, ts.URL+"/api/auth/oidc/link", map[string]any{})
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
			admin := registerAdmin(t, ts, "admin", "password123")
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
