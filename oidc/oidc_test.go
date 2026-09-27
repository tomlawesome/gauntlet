package oidc

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/internal/testutil"
)

func testClient(t *testing.T, fp *testutil.FakeProvider) *Client {
	t.Helper()
	c, err := New(context.Background(), Config{
		IssuerURL:    fp.Issuer(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "https://gauntlet.example/api/auth/oidc/callback",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNewDiscoversProviderAndBuildsAuthCodeURL(t *testing.T) {
	fp := testutil.NewFakeProvider(t)
	c := testClient(t, fp)

	raw := c.AuthCodeURL("state-123", "nonce-456", "verifier-789")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("AuthCodeURL produced an unparseable URL: %v", err)
	}
	q := u.Query()

	if got := q.Get("client_id"); got != "test-client" {
		t.Errorf("client_id = %q, want test-client", got)
	}
	if got := q.Get("state"); got != "state-123" {
		t.Errorf("state = %q, want state-123", got)
	}
	if got := q.Get("nonce"); got != "nonce-456" {
		t.Errorf("nonce = %q, want nonce-456", got)
	}
	if got := q.Get("response_type"); got != "code" {
		t.Errorf("response_type = %q, want code", got)
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256 -- PKCE must be present", got)
	}
	if q.Get("code_challenge") == "" {
		t.Error("code_challenge is empty -- PKCE challenge missing from the auth URL")
	}
	if !strings.Contains(raw, fp.Issuer()) {
		t.Errorf("AuthCodeURL %q doesn't point at the discovered provider %q", raw, fp.Issuer())
	}
}

// TestAuthCodeURLRedirectURIComesOnlyFromConfig pins the property
// SECURITY.md and Config.RedirectURL's doc comment both promise:
// redirect_uri is always exactly what New was configured with, never
// anything AuthCodeURL's own parameters (or, transitively, a caller's
// request Host header) could influence -- AuthCodeURL takes no such
// parameter at all, so this also documents that there is nothing for a
// future change to wire up by accident.
func TestAuthCodeURLRedirectURIComesOnlyFromConfig(t *testing.T) {
	fp := testutil.NewFakeProvider(t)
	c, err := New(context.Background(), Config{
		IssuerURL:    fp.Issuer(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "https://app.example/callback",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	raw := c.AuthCodeURL("state", "nonce", "verifier")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("AuthCodeURL produced an unparseable URL: %v", err)
	}
	if got := u.Query().Get("redirect_uri"); got != "https://app.example/callback" {
		t.Errorf("redirect_uri = %q, want the exact configured RedirectURL", got)
	}
}

// TestNewFailsClosedOnUnreachableProvider proves the fail-closed contract
// New's doc comment promises: a provider that can't be discovered yields
// an error, not a Client that silently skips verification or panics
// later. Callers (gate) are expected to treat this the same as any other
// "leave SSO off" startup condition.
func TestNewFailsClosedOnUnreachableProvider(t *testing.T) {
	// A server that answers 404 for discovery, standing in for a
	// misconfigured issuer URL or an IdP that is simply down.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	if _, err := New(context.Background(), Config{
		IssuerURL:    srv.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "https://app.example/callback",
		HTTPTimeout:  time.Second,
	}); err == nil {
		t.Fatal("New succeeded against a provider with no discovery document")
	}
}

func TestExchangeAndVerifyIDTokenRoundTrip(t *testing.T) {
	fp := testutil.NewFakeProvider(t)
	c := testClient(t, fp)

	nonce := "nonce-abc"
	claims := fp.DefaultClaims("test-client", nonce)
	fp.NextIDToken = fp.SignRS256(t, claims)

	tok, err := c.Exchange(context.Background(), "any-code", "any-verifier")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	id, err := c.VerifyIDToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}

	if id.Issuer != fp.Issuer() {
		t.Errorf("Issuer = %q, want %q", id.Issuer, fp.Issuer())
	}
	if id.Subject != "test-subject-123" {
		t.Errorf("Subject = %q, want test-subject-123", id.Subject)
	}
	if id.Nonce != nonce {
		t.Errorf("Nonce = %q, want %q", id.Nonce, nonce)
	}
	if id.Email != "person@example.com" || !id.EmailVerified {
		t.Errorf("Email/EmailVerified = %q/%v, want person@example.com/true", id.Email, id.EmailVerified)
	}
	if id.PreferredUsername != "person" {
		t.Errorf("PreferredUsername = %q, want person", id.PreferredUsername)
	}
	if !VerifyNonce(id.Nonce, nonce) {
		t.Error("VerifyNonce rejected a matching nonce")
	}
}

func TestVerifyNonceMismatchDetected(t *testing.T) {
	fp := testutil.NewFakeProvider(t)
	c := testClient(t, fp)

	claims := fp.DefaultClaims("test-client", "nonce-the-provider-actually-returned")
	fp.NextIDToken = fp.SignRS256(t, claims)

	tok, err := c.Exchange(context.Background(), "any-code", "any-verifier")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	id, err := c.VerifyIDToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}

	// A caller comparing against a *different* nonce (e.g. the one from a
	// stale or attacker-supplied flow state) must be told it doesn't
	// match -- VerifyIDToken succeeding on its own is not enough proof of
	// a legitimate, non-replayed login.
	if VerifyNonce(id.Nonce, "nonce-the-flow-state-actually-expected") {
		t.Fatal("VerifyNonce accepted a mismatched nonce")
	}
}

func TestVerifyIDTokenRejectsHS256AlgorithmConfusion(t *testing.T) {
	fp := testutil.NewFakeProvider(t)
	c := testClient(t, fp)

	claims := fp.DefaultClaims("test-client", "nonce-1")
	fp.NextIDToken = fp.SignHS256WithPublicKeyBytes(t, claims)

	tok, err := c.Exchange(context.Background(), "any-code", "any-verifier")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if _, err := c.VerifyIDToken(context.Background(), tok); err == nil {
		t.Fatal("VerifyIDToken accepted an HS256-signed token (algorithm-confusion attack using the provider's public key as an HMAC secret) -- SupportedSigningAlgs is not being enforced")
	}
}

func TestVerifyIDTokenRejectsNoneAlgorithm(t *testing.T) {
	fp := testutil.NewFakeProvider(t)
	c := testClient(t, fp)

	claims := fp.DefaultClaims("test-client", "nonce-1")
	fp.NextIDToken = fp.SignNoneAlgorithm(t, claims)

	tok, err := c.Exchange(context.Background(), "any-code", "any-verifier")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if _, err := c.VerifyIDToken(context.Background(), tok); err == nil {
		t.Fatal("VerifyIDToken accepted an alg=none, unsigned token")
	}
}

func TestVerifyIDTokenRejectsWrongAudience(t *testing.T) {
	fp := testutil.NewFakeProvider(t)
	c := testClient(t, fp)

	claims := fp.DefaultClaims("some-other-client", "nonce-1")
	fp.NextIDToken = fp.SignRS256(t, claims)

	tok, err := c.Exchange(context.Background(), "any-code", "any-verifier")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if _, err := c.VerifyIDToken(context.Background(), tok); err == nil {
		t.Fatal("VerifyIDToken accepted a token issued for a different client_id (aud mismatch)")
	}
}

func TestVerifyIDTokenRejectsExpiredToken(t *testing.T) {
	fp := testutil.NewFakeProvider(t)
	c := testClient(t, fp)

	claims := fp.DefaultClaims("test-client", "nonce-1")
	claims.Expiry = time.Now().Add(-time.Hour).Unix()
	claims.IssuedAt = time.Now().Add(-2 * time.Hour).Unix()
	fp.NextIDToken = fp.SignRS256(t, claims)

	tok, err := c.Exchange(context.Background(), "any-code", "any-verifier")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if _, err := c.VerifyIDToken(context.Background(), tok); err == nil {
		t.Fatal("VerifyIDToken accepted an expired token")
	}
}

func TestVerifyIDTokenRejectsWrongIssuer(t *testing.T) {
	fp := testutil.NewFakeProvider(t)
	c := testClient(t, fp)

	claims := fp.DefaultClaims("test-client", "nonce-1")
	claims.Issuer = "https://not-the-real-provider.example"
	fp.NextIDToken = fp.SignRS256(t, claims)

	tok, err := c.Exchange(context.Background(), "any-code", "any-verifier")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if _, err := c.VerifyIDToken(context.Background(), tok); err == nil {
		t.Fatal("VerifyIDToken accepted a token with a mismatched issuer claim")
	}
}

// TestHTTPTimeoutBoundsAHungProvider proves the timeout wiring (New's
// defaultHTTPTimeout, reapplied in Exchange/VerifyIDToken via
// oidc.ClientContext) actually takes effect end to end, not just that the
// client field gets set -- a provider that never responds to the token
// request must fail within the configured timeout, not hang the caller
// indefinitely.
func TestHTTPTimeoutBoundsAHungProvider(t *testing.T) {
	fp := testutil.NewFakeProvider(t)
	fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims("test-client", "nonce-1")) // never actually reached; just avoids an unrelated t.Fatal-from-goroutine if the hang doesn't block as expected
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	fp.Server.Config.Handler = wrapHang(fp.Server.Config.Handler, hang)

	c, err := New(context.Background(), Config{
		IssuerURL:    fp.Issuer(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "https://gauntlet.example/api/auth/oidc/callback",
		HTTPTimeout:  100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := c.Exchange(context.Background(), "any-code", "any-verifier")
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Exchange against a hung /token endpoint returned no error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Exchange did not respect HTTPTimeout -- still blocked well past it")
	}
}

// TestHTTPTimeoutBoundsAHungDiscoveryRequest is TestHTTPTimeoutBoundsAHungProvider's
// sibling for New's own discovery fetch (the .well-known document), the
// first of the three call sites defaultHTTPTimeout's doc comment names.
// A provider that accepts the connection but never answers discovery
// must fail New within the configured timeout, not hang whatever called
// New (an application's own startup) indefinitely.
func TestHTTPTimeoutBoundsAHungDiscoveryRequest(t *testing.T) {
	fp := testutil.NewFakeProvider(t)
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	fp.Server.Config.Handler = wrapHangPath(fp.Server.Config.Handler, hang, "/.well-known/openid-configuration")

	done := make(chan error, 1)
	go func() {
		_, err := New(context.Background(), Config{
			IssuerURL:    fp.Issuer(),
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "https://gauntlet.example/api/auth/oidc/callback",
			HTTPTimeout:  100 * time.Millisecond,
		})
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("New against a hung discovery endpoint returned no error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("New did not respect HTTPTimeout -- still blocked well past it")
	}
}

// TestHTTPTimeoutBoundsAHungJWKSFetch is the third call site: go-oidc
// fetches the provider's JWKS lazily, on first Verify, rather than
// during discovery (VerifyIDToken's own doc comment) -- so this hangs
// /jwks specifically, only once a token is ready to verify, and checks
// VerifyIDToken itself respects the timeout rather than New having
// already forced a fetch.
func TestHTTPTimeoutBoundsAHungJWKSFetch(t *testing.T) {
	fp := testutil.NewFakeProvider(t)
	c, err := New(context.Background(), Config{
		IssuerURL:    fp.Issuer(),
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "https://gauntlet.example/api/auth/oidc/callback",
		HTTPTimeout:  100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	claims := fp.DefaultClaims("test-client", "nonce-1")
	fp.NextIDToken = fp.SignRS256(t, claims)
	tok, err := c.Exchange(context.Background(), "any-code", "any-verifier")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	fp.Server.Config.Handler = wrapHangPath(fp.Server.Config.Handler, hang, "/jwks")

	done := make(chan error, 1)
	go func() {
		_, err := c.VerifyIDToken(context.Background(), tok)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("VerifyIDToken against a hung /jwks endpoint returned no error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("VerifyIDToken did not respect HTTPTimeout -- still blocked well past it")
	}
}

// wrapHang makes every /token request block until hang is closed,
// simulating a provider that's up (accepts the connection) but never
// responds -- the scenario an HTTP client Timeout guards against, as
// opposed to a connection-refused/DNS failure that fails fast on its own
// regardless of any timeout setting.
func wrapHang(next http.Handler, hang chan struct{}) http.Handler {
	return wrapHangPath(next, hang, "/token")
}

// wrapHangPath generalizes wrapHang to an arbitrary path, so the
// discovery- and JWKS-timeout tests above can hang their own endpoint
// instead of /token.
func wrapHangPath(next http.Handler, hang chan struct{}, path string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path {
			<-hang
		}
		next.ServeHTTP(w, r)
	})
}

func TestExchangeSendsCodeVerifier(t *testing.T) {
	fp := testutil.NewFakeProvider(t)
	c := testClient(t, fp)
	claims := fp.DefaultClaims("test-client", "nonce-1")
	fp.NextIDToken = fp.SignRS256(t, claims)

	// oauth2.VerifierOption's actual wire behavior is x/oauth2's own
	// well-tested responsibility -- this just confirms Exchange is wired
	// to actually pass the verifier through at all, since a no-op here
	// would silently defeat PKCE while every other test still passed.
	inner := fp.Server.Config.Handler
	var capturedBody string
	fp.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			b, _ := io.ReadAll(r.Body)
			_ = r.Body.Close()
			capturedBody = string(b)
			r.Body = io.NopCloser(bytes.NewReader(b))
		}
		inner.ServeHTTP(w, r)
	})

	if _, err := c.Exchange(context.Background(), "any-code", "the-real-verifier"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !strings.Contains(capturedBody, "code_verifier=the-real-verifier") {
		t.Errorf("token request body %q did not include the PKCE code_verifier", capturedBody)
	}
}
