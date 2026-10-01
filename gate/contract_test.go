// Contract tests: every route Routes serves, driven through
// docs/api/auth.yaml (ADR-0002, #22). A request or response that the
// document does not describe fails here, and so does a route that exists
// on one side only -- so a handler that drifts from the document fails
// CI instead of a frontend.
package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	legacyrouter "github.com/getkin/kin-openapi/routers/legacy"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/internal/testutil"
	"github.com/tomlawesome/gauntlet/oidc"
)

// contractDocPath is the OpenAPI document, relative to this package.
const contractDocPath = "../docs/api/auth.yaml"

// loadContractDoc loads and validates the document itself before any
// request is checked against it.
func loadContractDoc(t *testing.T) *openapi3.T {
	t.Helper()
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(contractDocPath)
	if err != nil {
		t.Fatalf("loading %s: %v", contractDocPath, err)
	}
	if err := doc.Validate(loader.Context); err != nil {
		t.Fatalf("%s is not a valid OpenAPI document: %v", contractDocPath, err)
	}
	if !doc.IsOpenAPI31OrLater() {
		t.Fatalf("%s declares openapi %q, want 3.1", contractDocPath, doc.OpenAPI)
	}
	return doc
}

// documentedOperations lists every "METHOD /path" the document holds.
func documentedOperations(doc *openapi3.T) []string {
	var ops []string
	for path, item := range doc.Paths.Map() {
		for method := range item.Operations() {
			ops = append(ops, method+" "+path)
		}
	}
	slices.Sort(ops)
	return ops
}

// contractChecker validates traffic against the document and records
// which operation answered with which status, so the test can prove
// every route was driven.
type contractChecker struct {
	t      *testing.T
	doc    *openapi3.T
	router routers.Router

	mu   sync.Mutex
	seen map[string]map[int]bool // "METHOD /path/{param}" -> statuses
}

func newContractChecker(t *testing.T) *contractChecker {
	t.Helper()
	doc := loadContractDoc(t)
	router, err := legacyrouter.NewRouter(doc)
	if err != nil {
		t.Fatalf("building a router over %s: %v", contractDocPath, err)
	}
	return &contractChecker{t: t, doc: doc, router: router, seen: map[string]map[int]bool{}}
}

// skipRequestCheck marks a request the test sends malformed on purpose
// (bad JSON, a missing CSRF header): the request is not what the
// document allows, but the response to it still has to be.
type skipRequestCheck struct{}

func malformed(ctx context.Context) context.Context {
	return context.WithValue(ctx, skipRequestCheck{}, true)
}

// client returns a cookie-carrying client whose every request and
// response under /api/auth and /api/tokens is checked against the
// document. It never follows redirects: every redirect these routes
// issue leaves the API.
func (c *contractChecker) client() *http.Client {
	return &http.Client{
		Jar:           mustCookieJar(c.t),
		Transport:     contractTransport{c: c, base: http.DefaultTransport},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type contractTransport struct {
	c    *contractChecker
	base http.RoundTripper
}

var contractOptions = &openapi3filter.Options{
	AuthenticationFunc:    openapi3filter.NoopAuthenticationFunc,
	IncludeResponseStatus: true, // an undocumented status is a failure
	MultiError:            true,
}

func (tr contractTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(req.URL.Path, "/api/auth/") && !strings.HasPrefix(req.URL.Path, "/api/tokens") {
		return tr.base.RoundTrip(req)
	}
	t := tr.c.t
	what := req.Method + " " + req.URL.Path

	var reqBody []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		reqBody = b
	}
	withBody := func() *http.Request {
		r := req.Clone(req.Context())
		r.Body = io.NopCloser(bytes.NewReader(reqBody))
		r.ContentLength = int64(len(reqBody))
		return r
	}

	route, params, err := tr.c.router.FindRoute(withBody())
	if err != nil {
		t.Errorf("%s: no such operation in %s: %v", what, contractDocPath, err)
		return tr.base.RoundTrip(withBody())
	}
	in := &openapi3filter.RequestValidationInput{Request: withBody(), PathParams: params, Route: route, Options: contractOptions}
	if req.Context().Value(skipRequestCheck{}) == nil {
		if err := openapi3filter.ValidateRequest(req.Context(), in); err != nil {
			t.Errorf("%s: request does not match %s: %v", what, contractDocPath, err)
		}
	}

	resp, err := tr.base.RoundTrip(withBody())
	if err != nil {
		return nil, err
	}
	respBody, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(respBody))

	out := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: in,
		Status:                 resp.StatusCode,
		Header:                 resp.Header,
		Options:                contractOptions,
	}
	out.SetBodyBytes(respBody)
	if err := openapi3filter.ValidateResponse(req.Context(), out); err != nil {
		t.Errorf("%s -> %d %q: response does not match %s: %v", what, resp.StatusCode, respBody, contractDocPath, err)
	}

	op := route.Method + " " + route.Path
	tr.c.mu.Lock()
	if tr.c.seen[op] == nil {
		tr.c.seen[op] = map[int]bool{}
	}
	tr.c.seen[op][resp.StatusCode] = true
	tr.c.mu.Unlock()
	return resp, nil
}

// requireEveryOperationDriven fails for any documented operation the
// test never reached, and for any documented success or redirect status
// it never saw. Error statuses are checked whenever they occur; not
// every one is reachable from a test (a failing random source, say).
func (c *contractChecker) requireEveryOperationDriven() {
	c.t.Helper()
	for path, item := range c.doc.Paths.Map() {
		for method, op := range item.Operations() {
			key := method + " " + path
			seen := c.seen[key]
			if len(seen) == 0 {
				c.t.Errorf("%s: documented but never driven by the contract test", key)
				continue
			}
			for code := range op.Responses.Map() {
				status, err := strconv.Atoi(code)
				if err != nil {
					c.t.Errorf("%s: response key %q is not a status code", key, code)
					continue
				}
				if status < 400 && !seen[status] {
					c.t.Errorf("%s: documented %d never seen", key, status)
				}
			}
		}
	}
}

// call is one request for contractChecker.send: body is sent as-is when
// it is a string (for deliberately malformed JSON), JSON-encoded
// otherwise, and not at all when nil. Every POST and DELETE carries the
// CSRF header unless noCSRF is set.
type call struct {
	method, path string
	body         any
	noCSRF       bool
	bad          bool // the request is deliberately not what the document allows
}

// do is send, requiring status want and decoding the body into out when
// out is non-nil.
func (c *contractChecker) do(client *http.Client, base string, in call, want int, out any) *http.Response {
	c.t.Helper()
	resp, raw := c.send(client, base, in)
	if resp.StatusCode != want {
		c.t.Fatalf("%s %s: status %d, want %d: %s", in.method, in.path, resp.StatusCode, want, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			c.t.Fatalf("%s %s: decoding %s: %v", in.method, in.path, raw, err)
		}
	}
	return resp
}

// send makes one request through client and returns the response with
// its body already read.
func (c *contractChecker) send(client *http.Client, base string, in call) (*http.Response, []byte) {
	c.t.Helper()
	var body io.Reader
	switch b := in.body.(type) {
	case nil:
	case string:
		body = strings.NewReader(b)
	default:
		enc, err := json.Marshal(b)
		if err != nil {
			c.t.Fatal(err)
		}
		body = bytes.NewReader(enc)
	}
	ctx := context.Background()
	if in.bad || in.noCSRF {
		ctx = malformed(ctx)
	}
	req, err := http.NewRequestWithContext(ctx, in.method, base+in.path, body)
	if err != nil {
		c.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if !in.noCSRF && in.method != http.MethodGet {
		req.Header.Set(csrfHeaderName, testCSRFValue)
	}
	resp, err := client.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatal(err)
	}
	return resp, raw
}

// TestContractEveryRoute drives every route in docs/api/auth.yaml --
// success paths and the refusals a test can reach -- and checks each
// request and response against the document.
func TestContractEveryRoute(t *testing.T) {
	c := newContractChecker(t)
	contractLocalAccounts(t, c)
	contractSSO(t, c)
	contractNoStorage(t, c)
	c.requireEveryOperationDriven()
}

// contractNoStorage covers the 503 an admin gets creating an account
// when the store has no persistent storage. A store with no backend can
// never hold the admin account Protect and RequireRole need, so the
// handler is mounted on its own with the admin already in the request's
// context; the traffic is still checked against the document.
func contractNoStorage(t *testing.T, c *contractChecker) {
	g := newTestGate(t)
	users, err := gauntlet.OpenStore(nil, gauntlet.Options{})
	if err != nil {
		t.Fatalf("OpenStore(nil): %v", err)
	}
	g.deps.Users = users
	admin := &gauntlet.User{ID: "admin-id", Username: "admin", Role: gauntlet.RoleAdmin}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.handleCreateUser(w, r.WithContext(withUser(r.Context(), admin)))
	}))
	t.Cleanup(ts.Close)

	c.do(c.client(), ts.URL, call{method: "POST", path: "/api/auth/users", body: createUserRequest{Username: "operator", Password: "contract-operator-password"}}, 503, nil)
}

func contractLocalAccounts(t *testing.T, c *contractChecker) {
	g := newTestGate(t)
	g.Handle(gauntlet.TokenKindAPI, testProtectedHandler())
	ts := newTestServer(t, g)
	u := ts.URL
	const adminPass = "contract-admin-password"
	const bobPass = "contract-bob-password"

	anon := c.client()
	var state sessionResponse
	c.do(anon, u, call{method: "GET", path: "/api/auth/session"}, 200, &state)
	if !state.SetupRequired {
		t.Fatal("a fresh store should report setupRequired")
	}
	c.do(anon, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"nobody", "x"}}, 503, nil)
	c.do(anon, u, call{method: "GET", path: "/api/auth/users"}, 503, nil)
	c.do(anon, u, call{method: "POST", path: "/api/auth/register", body: registerRequest{"admin", adminPass, ""}, noCSRF: true}, 403, nil)
	c.do(anon, u, call{method: "POST", path: "/api/auth/register", body: "not json", bad: true}, 400, nil)
	c.do(anon, u, call{method: "POST", path: "/api/auth/register", body: registerRequest{"admin", adminPass, "AAAA-AAAA-AAAA-AAAA"}}, 401, nil)

	admin := c.client()
	c.do(admin, u, call{method: "POST", path: "/api/auth/register", body: registerRequest{"admin", adminPass, setupCodeFor(t, g)}}, 201, nil)
	c.do(anon, u, call{method: "POST", path: "/api/auth/register", body: registerRequest{"second", adminPass, ""}}, 409, nil)
	c.do(admin, u, call{method: "GET", path: "/api/auth/session"}, 200, &state)
	if !state.Authenticated || state.Role != "admin" || state.SignedInSince == "" {
		t.Fatalf("admin session state = %+v", state)
	}

	c.do(anon, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"admin", "wrong-password"}}, 401, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"admin", adminPass}}, 200, nil)

	// Accounts.
	c.do(admin, u, call{method: "POST", path: "/api/auth/users", body: createUserRequest{Username: "bob", Password: bobPass}}, 201, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users", body: createUserRequest{Username: "bob", Password: bobPass}}, 409, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users", body: createUserRequest{Username: "eve", Password: bobPass, Role: "admin"}}, 400, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users", body: createUserRequest{Username: "vic", Password: bobPass, Role: "viewer"}}, 201, nil)
	var users []userSummary
	c.do(admin, u, call{method: "GET", path: "/api/auth/users"}, 200, &users)
	if len(users) != 3 {
		t.Fatalf("listed %d users, want 3", len(users))
	}
	c.do(anon, u, call{method: "GET", path: "/api/auth/users"}, 401, nil)
	bob := c.client()
	c.do(bob, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"bob", bobPass}}, 200, nil)
	c.do(bob, u, call{method: "GET", path: "/api/auth/users"}, 403, nil)
	c.do(bob, u, call{method: "POST", path: "/api/auth/logout-all", noCSRF: true}, 403, nil)
	bobID, adminID, vicID := "", "", ""
	for _, s := range users {
		switch s.Username {
		case "bob":
			bobID = s.ID
		case "admin":
			adminID = s.ID
		case "vic":
			vicID = s.ID
		}
	}

	// Authenticator app, recovery codes and the second-factor login.
	c.do(bob, u, call{method: "POST", path: "/api/auth/totp/enrol", body: totpEnrolRequest{Password: "wrong"}}, 401, nil)
	var enrolled totpEnrolResponse
	c.do(bob, u, call{method: "POST", path: "/api/auth/totp/enrol", body: totpEnrolRequest{Password: bobPass}}, 200, &enrolled)
	secret, err := gauntlet.DecodeTOTPSecret(enrolled.Secret)
	if err != nil {
		t.Fatal(err)
	}
	counter := totpCounterNow(time.Now())
	c.do(bob, u, call{method: "POST", path: "/api/auth/totp/confirm", body: totpConfirmRequest{Code: "000000x"}}, 400, nil)
	var confirmed totpConfirmResponse
	c.do(bob, u, call{method: "POST", path: "/api/auth/totp/confirm", body: totpConfirmRequest{Code: gauntlet.GenerateTOTPCode(secret, counter)}}, 200, &confirmed)
	c.do(bob, u, call{method: "POST", path: "/api/auth/totp/enrol", body: totpEnrolRequest{Password: bobPass}}, 409, nil)

	// Confirming on an account that already holds recovery codes (as one
	// with a passkey does) is the only answer carrying alreadyIssued. The
	// document's closed bodies only catch a renamed optional field when
	// the test makes the handler send it.
	if _, err := g.deps.Users.GenerateRecoveryCodes(vicID, time.Now()); err != nil {
		t.Fatal(err)
	}
	vic := c.client()
	c.do(vic, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"vic", bobPass}}, 200, nil)
	c.do(vic, u, call{method: "POST", path: "/api/auth/totp/enrol", body: totpEnrolRequest{Password: bobPass}}, 200, &enrolled)
	if secret, err = gauntlet.DecodeTOTPSecret(enrolled.Secret); err != nil {
		t.Fatal(err)
	}
	confirmed = totpConfirmResponse{}
	c.do(vic, u, call{method: "POST", path: "/api/auth/totp/confirm", body: totpConfirmRequest{Code: gauntlet.GenerateTOTPCode(secret, counter)}}, 200, &confirmed)
	if !confirmed.AlreadyIssued {
		t.Fatalf("confirming with recovery codes already held = %+v, want alreadyIssued", confirmed)
	}

	var codes recoveryCodesRegenerateResponse
	c.do(bob, u, call{method: "POST", path: "/api/auth/recovery-codes", body: recoveryCodesRegenerateRequest{Password: bobPass}}, 200, &codes)

	bob2 := c.client()
	var challenge struct {
		SecondFactor []string `json:"secondFactor"`
	}
	c.do(bob2, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"bob", bobPass}}, 200, &challenge)
	if !slices.Equal(challenge.SecondFactor, []string{"totp"}) {
		t.Fatalf("second-factor challenge = %+v", challenge)
	}
	c.do(anon, u, call{method: "POST", path: "/api/auth/login/factor", body: loginFactorRequest{Code: codes.RecoveryCodes[0]}}, 401, nil)
	c.do(bob2, u, call{method: "POST", path: "/api/auth/login/factor", body: "{", bad: true}, 400, nil)
	c.do(bob2, u, call{method: "POST", path: "/api/auth/login/factor", body: loginFactorRequest{Code: codes.RecoveryCodes[0]}}, 200, nil)

	var removed map[string]any
	c.do(bob2, u, call{method: "DELETE", path: "/api/auth/totp", body: totpDeleteRequest{Password: bobPass}}, 200, &removed)
	if removed["signedOut"] != true {
		t.Fatalf("removing the only factor should sign out: %v", removed)
	}
	c.do(bob, u, call{method: "POST", path: "/api/auth/recovery-codes", body: recoveryCodesRegenerateRequest{Password: bobPass}}, 401, nil)
	bob = c.client()
	c.do(bob, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"bob", bobPass}}, 200, nil)
	c.do(bob, u, call{method: "POST", path: "/api/auth/recovery-codes", body: recoveryCodesRegenerateRequest{Password: bobPass}}, 409, nil)

	c.do(admin, u, call{method: "DELETE", path: "/api/auth/users/" + bobID + "/totp"}, 200, nil)
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/users/" + adminID + "/totp"}, 409, nil)
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/users/no-such-id/totp"}, 404, nil)

	// Admin reset, the must-change-password door, and changing a password.
	var reset resetPasswordResponse
	c.do(admin, u, call{method: "POST", path: "/api/auth/users/" + bobID + "/reset-password"}, 200, &reset)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users/" + adminID + "/reset-password"}, 409, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users/no-such-id/reset-password"}, 404, nil)
	bob = c.client()
	c.do(bob, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"bob", reset.Code}}, 200, nil)
	resp := c.do(bob, u, call{method: "POST", path: "/api/auth/logout-all"}, 403, nil)
	if resp.Header.Get(authGateHeader) != authGateMustChangePassword {
		t.Fatalf("%s = %q, want %q", authGateHeader, resp.Header.Get(authGateHeader), authGateMustChangePassword)
	}
	c.do(bob, u, call{method: "POST", path: "/api/auth/password", body: changePasswordRequest{NewPassword: "short"}}, 400, nil)
	c.do(bob, u, call{method: "POST", path: "/api/auth/password", body: changePasswordRequest{NewPassword: bobPass + "-2"}}, 200, nil)
	c.do(bob, u, call{method: "POST", path: "/api/auth/password", body: changePasswordRequest{CurrentPassword: "wrong", NewPassword: bobPass}}, 401, nil)
	c.do(bob, u, call{method: "POST", path: "/api/auth/logout-all"}, 200, nil)
	c.do(bob, u, call{method: "POST", path: "/api/auth/logout"}, 200, nil)
	c.do(bob, u, call{method: "POST", path: "/api/auth/logout", noCSRF: true}, 403, nil)
	c.do(anon, u, call{method: "POST", path: "/api/auth/logout-all"}, 401, nil)

	// API tokens.
	var created tokenResponse
	c.do(admin, u, call{method: "POST", path: "/api/tokens", body: createTokenRequest{Name: "grafana"}}, 201, &created)
	c.do(admin, u, call{method: "POST", path: "/api/tokens", body: createTokenRequest{Name: ""}}, 400, nil)
	c.do(admin, u, call{method: "POST", path: "/api/tokens", body: createTokenRequest{Name: strings.Repeat("n", gauntlet.MaxTokenNameLen+1)}}, 400, nil)
	c.do(admin, u, call{method: "POST", path: "/api/tokens", body: createTokenRequest{Name: "sensor", Kind: "ingest", Device: "sensor-1"}}, 201, nil)
	// Used once, so the list carries lastUsedAt (see alreadyIssued above).
	used := bearerRequest(t, u, "/api/protected", created.Value)
	_ = used.Body.Close()
	if used.StatusCode != http.StatusOK {
		t.Fatalf("using the new token: status %d", used.StatusCode)
	}
	var listed struct {
		Tokens []tokenResponse `json:"tokens"`
	}
	c.do(admin, u, call{method: "GET", path: "/api/tokens"}, 200, &listed)
	if i := slices.IndexFunc(listed.Tokens, func(tok tokenResponse) bool { return tok.ID == created.ID }); i < 0 || listed.Tokens[i].LastUsedAt.IsZero() {
		t.Fatalf("listed tokens = %+v, want %s with lastUsedAt", listed.Tokens, created.ID)
	}
	c.do(bob, u, call{method: "GET", path: "/api/tokens"}, 401, nil)
	c.do(admin, u, call{method: "DELETE", path: "/api/tokens/" + created.ID}, 200, nil)
	c.do(admin, u, call{method: "DELETE", path: "/api/tokens/" + created.ID}, 404, nil)

	// Deleting accounts.
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/users/" + adminID}, 409, nil)
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/users/no-such-id"}, 404, nil)
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/users/" + bobID}, 200, nil)

	// SSO is off on this gate.
	c.do(anon, u, call{method: "GET", path: "/api/auth/oidc/login"}, 404, nil)
	c.do(anon, u, call{method: "GET", path: "/api/auth/oidc/callback?state=x&code=y"}, 404, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/oidc/link"}, 404, nil)

	// Last, because it exhausts this client address's login budget.
	limited := false
	for range 10 {
		resp, _ := c.send(anon, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"vic", "wrong"}})
		if resp.StatusCode == http.StatusTooManyRequests {
			limited = true
			break
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("a wrong password answered %d, want 401 until the limit", resp.StatusCode)
		}
	}
	if !limited {
		t.Fatal("ten wrong passwords never reached the login limit")
	}
}

func contractSSO(t *testing.T, c *contractChecker) {
	g, ts, fp := newOIDCTestGate(t, oidc.Policy{})
	u := ts.URL

	// The first admin is local (newOIDCTestGate registered "setup-admin"
	// with the setup code); the first SSO sign-in is an ordinary user.
	first := c.client()
	contractSSOSignIn(t, c, g, fp, first, u, "/api/auth/oidc/login", "/")
	admin := c.client()
	c.do(admin, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"setup-admin", "setup-admin-password"}}, 200, nil)

	c.do(c.client(), u, call{method: "POST", path: "/api/auth/users", body: createUserRequest{Username: "carol", Password: "contract-carol-password"}}, 401, nil)
	c.do(first, u, call{method: "POST", path: "/api/auth/users", body: createUserRequest{Username: "carol", Password: "contract-carol-password"}}, 403, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users", body: createUserRequest{Username: "carol", Password: "contract-carol-password"}}, 201, nil)

	// carol links her local account to a second identity.
	carol := c.client()
	c.do(carol, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"carol", "contract-carol-password"}}, 200, nil)
	contractSSOSignIn(t, c, g, fp, carol, u, "/api/auth/oidc/link", "/?ssoLinked=1")
	c.do(carol, u, call{method: "POST", path: "/api/auth/oidc/link"}, 409, nil)

	// A callback with no flow cookie goes back to the login page.
	resp := c.do(c.client(), u, call{method: "GET", path: "/api/auth/oidc/callback?state=x&code=y"}, 302, nil)
	if loc := resp.Header.Get("Location"); loc != testLoginPath+"?ssoError=state_mismatch" {
		t.Fatalf("callback without a flow cookie redirected to %q", loc)
	}
}

// contractSSOSignIn starts a flow at start (the SSO login or link route),
// has the fake provider answer for the next subject, and finishes it at
// the callback, which must redirect to wantLocation.
func contractSSOSignIn(t *testing.T, c *contractChecker, g *Gate, fp *testutil.FakeProvider, client *http.Client, base, start, wantLocation string) {
	t.Helper()
	if start == "/api/auth/oidc/login" {
		c.do(client, base, call{method: "GET", path: start}, 302, nil)
	} else {
		c.do(client, base, call{method: "POST", path: start}, 200, nil)
	}
	target, err := http.NewRequest(http.MethodGet, base+"/api/auth/oidc/callback", nil)
	if err != nil {
		t.Fatal(err)
	}
	var flow string
	for _, ck := range client.Jar.Cookies(target.URL) {
		if ck.Name == oidcFlowCookieName {
			flow = ck.Value
		}
	}
	fs, err := g.deps.OIDCState.Decode(flow, oidcFlowCookieMaxAge, time.Now())
	if err != nil {
		t.Fatalf("decoding the flow cookie: %v", err)
	}
	claims := fp.DefaultClaims(oidcTestClientID, fs.Nonce)
	claims.Subject = fmt.Sprintf("contract-subject-%d", time.Now().UnixNano())
	fp.NextIDToken = fp.SignRS256(t, claims)
	resp := c.do(client, base, call{method: "GET", path: "/api/auth/oidc/callback?state=" + fs.State + "&code=test-code"}, 302, nil)
	if loc := resp.Header.Get("Location"); loc != wantLocation {
		t.Fatalf("callback redirected to %q, want %q", loc, wantLocation)
	}
}

// TestContractRoutesMatchDocument checks the route table itself: every
// pattern Routes registers is an operation in the document, and every
// operation in the document is a pattern Routes registers. The patterns
// are read from routes.go's source (a ServeMux cannot list what it
// holds), then each is confirmed against the live mux, so the source
// reading cannot drift from what is actually served.
func TestContractRoutesMatchDocument(t *testing.T) {
	doc := loadContractDoc(t)
	registered := registeredRoutePatterns(t)

	mux, ok := newTestGate(t).Routes().(*http.ServeMux)
	if !ok {
		t.Fatal("Routes no longer returns an *http.ServeMux; update this test's live check")
	}
	for _, pattern := range registered {
		method, path, _ := strings.Cut(pattern, " ")
		req := httptest.NewRequest(method, strings.NewReplacer("{id}", "some-id").Replace(path), nil)
		if _, got := mux.Handler(req); got != pattern {
			t.Errorf("routes.go registers %q but the live mux serves %s %s as %q", pattern, method, req.URL.Path, got)
		}
	}

	documented := documentedOperations(doc)
	for _, op := range registered {
		if !slices.Contains(documented, op) {
			t.Errorf("Routes serves %s, which %s does not describe", op, contractDocPath)
		}
	}
	for _, op := range documented {
		if !slices.Contains(registered, op) {
			t.Errorf("%s describes %s, which Routes does not serve", contractDocPath, op)
		}
	}
	if len(registered) == 0 {
		t.Fatal("read no route patterns from routes.go")
	}
}

// registeredRoutePatterns reads the first argument of every
// mux.Handle/mux.HandleFunc call in Routes, resolving the package's
// string constants (sessionPath and the rest), and returns them sorted.
func registeredRoutePatterns(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	consts := map[string]string{}
	var routes *ast.FuncDecl
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				if d.Tok != token.CONST {
					continue
				}
				for _, spec := range d.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, id := range vs.Names {
						if i >= len(vs.Values) {
							continue
						}
						if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							v, err := strconv.Unquote(lit.Value)
							if err != nil {
								t.Fatal(err)
							}
							consts[id.Name] = v
						}
					}
				}
			case *ast.FuncDecl:
				if d.Name.Name == "Routes" && d.Recv != nil {
					routes = d
				}
			}
		}
	}
	if routes == nil {
		t.Fatal("no Routes method found in package gate")
	}

	var eval func(ast.Expr) string
	eval = func(e ast.Expr) string {
		switch e := e.(type) {
		case *ast.BasicLit:
			v, err := strconv.Unquote(e.Value)
			if err != nil {
				t.Fatal(err)
			}
			return v
		case *ast.Ident:
			v, ok := consts[e.Name]
			if !ok {
				t.Fatalf("route pattern uses %s, which is not a string constant in package gate", e.Name)
			}
			return v
		case *ast.BinaryExpr:
			if e.Op == token.ADD {
				return eval(e.X) + eval(e.Y)
			}
		}
		t.Fatalf("cannot read route pattern at %s", fset.Position(e.Pos()))
		return ""
	}

	var patterns []string
	ast.Inspect(routes.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") || len(call.Args) != 2 {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "mux" {
			return true
		}
		patterns = append(patterns, eval(call.Args[0]))
		return true
	})
	slices.Sort(patterns)
	return patterns
}
