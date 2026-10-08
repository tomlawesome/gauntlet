// Contract tests: every route Routes serves, driven through
// docs/api/auth.yaml (ADR-0002, #22). A request or response that the
// document does not describe fails here, and so does a route that exists
// on one side only -- so a handler that drifts from the document fails
// CI instead of a frontend.
//
// This is its own Go module (#30) so the validator, kin-openapi, stays
// out of the library's go.mod and so out of every app that imports
// gauntlet. Being outside package gate, it reaches the gate only through
// its exported API, exactly as an application does.
package contracttest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	"github.com/go-webauthn/webauthn/protocol"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/gate"
	"github.com/tomlawesome/gauntlet/internal/passkeytest"
	"github.com/tomlawesome/gauntlet/internal/testutil"
	"github.com/tomlawesome/gauntlet/oidc"
	"github.com/tomlawesome/gauntlet/passkey"
	"github.com/tomlawesome/gauntlet/persist"
)

// contractDocPath is the OpenAPI document, relative to this package.
const contractDocPath = "../../docs/api/auth.yaml"

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
	checkJSONResponseHeaders(t, what, resp)

	op := route.Method + " " + route.Path
	tr.c.mu.Lock()
	if tr.c.seen[op] == nil {
		tr.c.seen[op] = map[int]bool{}
	}
	tr.c.seen[op][resp.StatusCode] = true
	tr.c.mu.Unlock()
	return resp, nil
}

// checkJSONResponseHeaders is gauntlet #46's guard, widened for #23:
// every JSON response gate writes -- a success body (Content-Type:
// application/json; charset=utf-8, gate/httpjson.go's writeJSON) or an
// RFC 9457 problem body (application/problem+json, no charset,
// writeProblem) -- must carry Cache-Control: no-store and
// X-Content-Type-Options: nosniff. A response of neither Content-Type
// is not this issue's concern.
func checkJSONResponseHeaders(t *testing.T, what string, resp *http.Response) {
	t.Helper()
	ct := resp.Header.Get("Content-Type")
	switch ct {
	case "application/json; charset=utf-8", "application/problem+json":
	default:
		return
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("%s -> %d: Cache-Control = %q, want \"no-store\"", what, resp.StatusCode, got)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("%s -> %d: X-Content-Type-Options = %q, want \"nosniff\"", what, resp.StatusCode, got)
	}
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
	contractPasskeys(t, c)
	contractPasskeySignIn(t, c)
	contractProve(t, c)
	contractUnlockCode(t, c)
	contractUnusualSignIns(t, c)
	contractEscapeCode(t, c)
	contractResume(t, c)
	c.requireEveryOperationDriven()
}

// contractUnusualSignIns covers the unusual-sign-in answers (#55) on a
// gate whose policy blocks a new browser: the password step and the
// second-factor step each answer 403 sign-in-refused, with no
// X-Auth-Gate header.
func contractUnusualSignIns(t *testing.T, c *contractChecker) {
	users, code := openStore(t, persist.NewMemory())
	g := newGateWith(t, gate.Deps{Users: users}, func(cfg *gate.Config) {
		cfg.UnusualSignIns = gate.UnusualSignInPolicy{NewBrowser: gate.UnusualSignInBlock}
	})
	ts := newTestServer(t, g)
	u := ts.URL
	const adminPass = "contract-admin-password"
	admin := c.client()
	c.do(admin, u, call{method: "POST", path: "/api/auth/register", body: registerRequest{"admin", adminPass, code}}, 201, nil)

	refused := func(resp *http.Response) {
		t.Helper()
		if resp.Header.Get("X-Auth-Gate") != "" {
			t.Errorf("a refused sign-in carries X-Auth-Gate %q", resp.Header.Get("X-Auth-Gate"))
		}
	}
	stranger := c.client()
	refused(c.do(stranger, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"admin", adminPass}}, 403, nil))

	recovery := enrolTOTPFactor(t, c, u, admin, adminPass)
	stranger = c.client()
	c.do(stranger, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"admin", adminPass}}, 200, nil)
	refused(c.do(stranger, u, call{method: "POST", path: "/api/auth/login/factor", body: loginFactorRequest{Code: recovery[0]}}, 403, nil))

	// The same under confirm: a new browser is sent a code, through the
	// application, and finishes with POST /api/auth/login/confirm.
	users, code = openStore(t, persist.NewMemory())
	codes := &codeCatcher{}
	g = newGateWith(t, gate.Deps{Users: users}, func(cfg *gate.Config) {
		cfg.UnusualSignIns = gate.UnusualSignInPolicy{NewBrowser: gate.UnusualSignInConfirm}
		cfg.DeliverConfirmCode = codes.deliver
	})
	ts = newTestServer(t, g)
	u = ts.URL
	admin = c.client()
	c.do(admin, u, call{method: "POST", path: "/api/auth/register", body: registerRequest{"admin", adminPass, code}}, 201, nil)
	var challenge map[string]any
	newcomer := c.client()
	c.do(newcomer, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"admin", adminPass}}, 200, &challenge)
	if challenge["confirm"] != true {
		t.Fatalf("login under confirm = %v", challenge)
	}
	c.do(newcomer, u, call{method: "POST", path: "/api/auth/login/confirm", body: "not json", bad: true}, 400, nil)
	c.do(newcomer, u, call{method: "POST", path: "/api/auth/login/confirm", body: confirmCodeRequest{Code: "0000-000x"}}, 401, nil)
	c.do(newcomer, u, call{method: "POST", path: "/api/auth/login/confirm", body: confirmCodeRequest{Code: codes.last()}, noCSRF: true}, 403, nil)
	c.do(newcomer, u, call{method: "POST", path: "/api/auth/login/confirm", body: confirmCodeRequest{Code: codes.last()}}, 200, nil)
	c.do(newcomer, u, call{method: "POST", path: "/api/auth/login/confirm", body: confirmCodeRequest{Code: codes.last()}}, 401, nil)

	recovery = enrolTOTPFactor(t, c, u, admin, adminPass)
	newcomer = c.client()
	c.do(newcomer, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"admin", adminPass}}, 200, nil)
	c.do(newcomer, u, call{method: "POST", path: "/api/auth/login/factor", body: loginFactorRequest{Code: recovery[0]}}, 200, &challenge)
	if challenge["confirm"] != true {
		t.Fatalf("login/factor under confirm = %v", challenge)
	}
	c.do(newcomer, u, call{method: "POST", path: "/api/auth/login/confirm", body: confirmCodeRequest{Code: codes.last()}}, 200, nil)
}

// contractResume covers POST /api/auth/reauthenticate (#71): a session
// that timed out through inactivity inside its ceiling reports itself
// resumable and resumes with the password alone, on a gate whose clock
// the test moves.
func contractResume(t *testing.T, c *contractChecker) {
	users, code := openStore(t, persist.NewMemory())
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); defer mu.Unlock(); now = now.Add(d) }
	g := newGateWith(t, gate.Deps{Users: users}, func(cfg *gate.Config) { cfg.Now = clock })
	ts := newTestServer(t, g)
	u := ts.URL
	const adminPass = "contract-admin-password"
	admin := c.client()
	c.do(admin, u, call{method: "POST", path: "/api/auth/register", body: registerRequest{"admin", adminPass, code}}, 201, nil)

	// Live: nothing to resume.
	session := func(client *http.Client) map[string]any {
		var state map[string]any
		c.do(client, u, call{method: "GET", path: "/api/auth/session"}, 200, &state)
		return state
	}
	if state := session(admin); state["resumable"] != nil {
		t.Errorf("a live session reports resumable: %v", state)
	}
	c.do(admin, u, call{method: "POST", path: "/api/auth/reauthenticate", body: reauthenticateRequest{Password: adminPass}}, 401, nil)

	advance(2 * time.Hour)
	if state := session(admin); state["authenticated"] != false || state["resumable"] != true {
		t.Errorf("a timed-out session reports %v, want unauthenticated and resumable", state)
	}
	c.do(admin, u, call{method: "POST", path: "/api/auth/reauthenticate", body: "not json", bad: true}, 400, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/reauthenticate", body: reauthenticateRequest{Password: adminPass}, noCSRF: true}, 403, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/reauthenticate", body: reauthenticateRequest{Password: "wrong-password-placeholder"}}, 401, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/reauthenticate", body: reauthenticateRequest{Password: adminPass}}, 200, nil)
	if state := session(admin); state["authenticated"] != true || state["resumable"] != nil {
		t.Errorf("a resumed session reports %v, want authenticated and not resumable", state)
	}

	// Timed out again: wrong passwords count, and past the original
	// ceiling nothing resumes it.
	advance(2 * time.Hour)
	if state := session(admin); state["resumable"] != true {
		t.Fatalf("a second timeout reports %v, want resumable", state)
	}
	// From a browser the account does not remember (only the session
	// cookie), five wrong passwords lock the account out.
	stranger := c.client()
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	for _, ck := range admin.Jar.Cookies(parsed) {
		if ck.Name == testCookieName {
			stranger.Jar.SetCookies(parsed, []*http.Cookie{ck})
		}
	}
	for range 5 {
		c.do(stranger, u, call{method: "POST", path: "/api/auth/reauthenticate", body: reauthenticateRequest{Password: "wrong-password-placeholder"}}, 401, nil)
	}
	c.do(stranger, u, call{method: "POST", path: "/api/auth/reauthenticate", body: reauthenticateRequest{Password: adminPass}}, 429, nil)
	advance(25 * time.Hour)
	c.do(stranger, u, call{method: "POST", path: "/api/auth/reauthenticate", body: reauthenticateRequest{Password: adminPass}}, 401, nil)
}

// reauthenticateRequest is POST /api/auth/reauthenticate's body.
type reauthenticateRequest struct {
	Password  string          `json:"password,omitempty"`
	Assertion json.RawMessage `json:"assertion,omitempty"`
}

// loginPasskeyRequest is POST /api/auth/login/passkey's body.
type loginPasskeyRequest struct {
	Assertion json.RawMessage `json:"assertion"`
}

// loginProveRequest is POST /api/auth/login/prove's body.
type loginProveRequest struct {
	Assertion json.RawMessage `json:"assertion"`
}

// contractEscapeCode covers the lone admin's escape (#66): blocked from a
// new browser, the admin gets the escape cookie and the application the
// code (Config.OnEscapeCode), and POST /api/auth/login/escape lets that
// attempt through.
func contractEscapeCode(t *testing.T, c *contractChecker) {
	users, code := openStore(t, persist.NewMemory())
	escapes := &escapeCatcher{}
	g := newGateWith(t, gate.Deps{Users: users}, func(cfg *gate.Config) {
		cfg.UnusualSignIns = gate.UnusualSignInPolicy{NewBrowser: gate.UnusualSignInBlock}
		cfg.OnEscapeCode = escapes
	})
	ts := newTestServer(t, g)
	u := ts.URL
	const adminPass = "contract-admin-password"
	c.do(c.client(), u, call{method: "POST", path: "/api/auth/register", body: registerRequest{"admin", adminPass, code}}, 201, nil)

	stranger := c.client()
	resp := c.do(stranger, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"admin", adminPass}}, 403, nil)
	if resp.Header.Get("X-Auth-Gate") != "" {
		t.Errorf("a refused sign-in carries X-Auth-Gate %q", resp.Header.Get("X-Auth-Gate"))
	}
	if escapes.last() == "" {
		t.Fatal("the lone admin's refusal gave the application no escape code")
	}
	c.do(stranger, u, call{method: "POST", path: "/api/auth/login/escape", body: "not json", bad: true}, 400, nil)
	c.do(stranger, u, call{method: "POST", path: "/api/auth/login/escape", body: escapeCodeRequest{Code: "AAAA-AAAA-AAAA-AAAA"}}, 401, nil)
	c.do(stranger, u, call{method: "POST", path: "/api/auth/login/escape", body: escapeCodeRequest{Code: escapes.last()}, noCSRF: true}, 403, nil)
	c.do(stranger, u, call{method: "POST", path: "/api/auth/login/escape", body: escapeCodeRequest{Code: escapes.last()}}, 200, nil)
	c.do(stranger, u, call{method: "POST", path: "/api/auth/login/escape", body: escapeCodeRequest{Code: escapes.last()}}, 401, nil)
}

// escapeCodeRequest is POST /api/auth/login/escape's body.
type escapeCodeRequest struct {
	Code string `json:"code"`
}

// escapeCatcher is a gate.Config.OnEscapeCode keeping the last escape
// code it was given.
type escapeCatcher struct {
	mu   sync.Mutex
	code string
}

func (e *escapeCatcher) EscapeCode(_, _, code string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.code = code
}

func (e *escapeCatcher) last() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.code
}

// confirmCodeRequest is POST /api/auth/login/confirm's body.
type confirmCodeRequest struct {
	Code string `json:"code"`
}

// codeCatcher is a gate.Config.DeliverConfirmCode keeping the last
// confirmation code it was given.
type codeCatcher struct {
	mu   sync.Mutex
	code string
}

func (c *codeCatcher) deliver(_ context.Context, n gate.ConfirmCode) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n.Code != "" {
		c.code = n.Code
	}
	return nil
}

func (c *codeCatcher) last() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.code
}

// contractNoStorage covers the 503 an admin gets creating an account
// when the store has no persistent storage. A store with no backend can
// never hold the admin account Protect and RequireRole need, so two
// gates share one server: one with storage signs the admin in (its
// Protect puts the admin in the request's context, which any gate's
// RequireRole reads), and one over a store with no backend answers the
// account creation. The traffic is still checked against the document.
func contractNoStorage(t *testing.T, c *contractChecker) {
	stored := newTestGate(t)
	noBackend, err := gauntlet.OpenStore(nil, gauntlet.Options{})
	if err != nil {
		t.Fatalf("OpenStore(nil): %v", err)
	}
	unstored := newGate(t, gate.Deps{Users: noBackend})

	mux := http.NewServeMux()
	mux.Handle("POST /api/auth/users", unstored.Routes())
	mux.Handle("/", stored.g.Routes())
	ts := httptest.NewServer(stored.g.Protect(mux))
	t.Cleanup(ts.Close)

	admin := c.client()
	c.do(admin, ts.URL, call{method: "POST", path: "/api/auth/register", body: registerRequest{"admin", "contract-admin-password", stored.setupCode}}, 201, nil)
	enrolTOTPFactor(t, c, ts.URL, admin, "contract-admin-password") // POST /api/auth/users is not an enrolment route
	c.do(admin, ts.URL, call{method: "POST", path: "/api/auth/users", body: createUserRequest{Username: "operator", Password: "contract-operator-password"}}, 503, nil)
	// This gate keeps no sign-in history.
	c.do(admin, ts.URL, call{method: "GET", path: "/api/auth/sign-ins"}, 404, nil)
}

// contractUnlockCode covers POST /api/auth/unlock, the lone-admin unlock
// code (#44): a store that opens with its admin's sign-in disabled
// announces one, and the route takes it. The admin is registered through
// the checked server, disabled by fifty failures made straight on the
// limiter (the exported API, on a clock long past), and the store opened
// again over the same backend, as a restart would.
func contractUnlockCode(t *testing.T, c *contractChecker) {
	backend := persist.NewMemory()
	first := newTestGateWith(t, backend, nil)
	firstTS := newTestServer(t, first.g)
	c.do(c.client(), firstTS.URL, call{method: "POST", path: "/api/auth/register", body: registerRequest{"admin", "contract-admin-password", first.setupCode}}, 201, nil)
	admin, ok := first.users.ByUsername("admin")
	if !ok {
		t.Fatal("no admin after registering")
	}
	limiter, err := gauntlet.NewLoginLimiter(5, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Recent enough that the disable has not lifted itself
	// (LoginDisableDuration, 24 hours): the lockouts on the way to it
	// add up to about eight hours.
	at := time.Now().Add(-12 * time.Hour)
	for range gauntlet.MaxConsecutiveLoginFailures {
		limiter.ReserveAccount(first.users, admin.ID, at)
		if until := first.users.LoginLockedUntil(admin.ID); until.After(at) {
			at = until
		}
		at = at.Add(time.Second)
	}

	var code string
	users, err := gauntlet.OpenStore(backend, gauntlet.Options{
		OnUnlockCode: gauntlet.UnlockCodeFunc(func(_, c string) { code = c }),
	})
	if err != nil {
		t.Fatal(err)
	}
	if code == "" {
		t.Fatal("a store opening with its admin disabled announced no unlock code")
	}
	ts := newTestServer(t, newGate(t, gate.Deps{Users: users}))
	u := ts.URL
	anon := c.client()
	c.do(anon, u, call{method: "POST", path: "/api/auth/unlock", body: unlockCodeRequest{"admin", code}, noCSRF: true}, 403, nil)
	c.do(anon, u, call{method: "POST", path: "/api/auth/unlock", body: "{", bad: true}, 400, nil)
	c.do(anon, u, call{method: "POST", path: "/api/auth/unlock", body: unlockCodeRequest{"admin", "AAAA-AAAA-AAAA-AAAA"}}, 401, nil)
	c.do(anon, u, call{method: "POST", path: "/api/auth/unlock", body: unlockCodeRequest{"admin", code}}, 200, nil)
	c.do(anon, u, call{method: "POST", path: "/api/auth/unlock", body: unlockCodeRequest{"admin", code}}, 401, nil)
	c.do(anon, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"admin", "contract-admin-password"}}, 200, nil)
}

func contractLocalAccounts(t *testing.T, c *contractChecker) {
	f := newSignInsGate(t)
	g := f.g
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
	c.do(anon, u, call{method: "POST", path: "/api/auth/unlock", body: unlockCodeRequest{"admin", "AAAA-AAAA-AAAA-AAAA"}}, 503, nil)
	c.do(anon, u, call{method: "POST", path: "/api/auth/users/no-such-id/logout-all"}, 503, nil)
	c.do(anon, u, call{method: "GET", path: "/api/auth/sign-ins"}, 503, nil)
	c.do(anon, u, call{method: "POST", path: "/api/auth/register", body: registerRequest{"admin", adminPass, ""}, noCSRF: true}, 403, nil)
	c.do(anon, u, call{method: "POST", path: "/api/auth/register", body: "not json", bad: true}, 400, nil)
	c.do(anon, u, call{method: "POST", path: "/api/auth/register", body: registerRequest{"admin", adminPass, "AAAA-AAAA-AAAA-AAAA"}}, 401, nil)

	admin := c.client()
	c.do(admin, u, call{method: "POST", path: "/api/auth/register", body: registerRequest{"admin", adminPass, f.setupCode}}, 201, nil)
	c.do(anon, u, call{method: "POST", path: "/api/auth/register", body: registerRequest{"second", adminPass, ""}}, 409, nil)
	c.do(admin, u, call{method: "GET", path: "/api/auth/session"}, 200, &state)
	if !state.Authenticated || state.Role != "admin" || state.SignedInSince == "" {
		t.Fatalf("admin session state = %+v", state)
	}

	c.do(anon, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"admin", "wrong-password"}}, 401, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"admin", adminPass}}, 200, nil)
	// Every route from here on is not an enrolment route, so admin needs
	// a second factor to clear the forced-enrolment door (#49) before it
	// can reach any of them -- done now, not before the re-login above,
	// which needs a full session rather than the pending login a
	// confirmed factor would leave it with.
	adminRecovery := enrolTOTPFactor(t, c, u, admin, adminPass)

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

	// The sign-in history (#53): the wrong password and the sign-ins
	// above are rows.
	var history struct {
		SignIns []struct {
			Outcome string `json:"outcome"`
		} `json:"signIns"`
		More  bool `json:"more"`
		Total int  `json:"total"`
	}
	c.do(admin, u, call{method: "GET", path: "/api/auth/sign-ins"}, 200, &history)
	if history.Total < 3 || len(history.SignIns) != history.Total {
		t.Fatalf("sign-in history = %+v, want the attempts made so far", history)
	}
	c.do(admin, u, call{method: "GET", path: "/api/auth/sign-ins?outcome=wrong_password&limit=1&before=1000&address=198.51.100.1"}, 200, &history)
	if len(history.SignIns) != 1 || history.SignIns[0].Outcome != "wrong_password" {
		t.Fatalf("filtered sign-in history = %+v", history)
	}
	c.do(admin, u, call{method: "GET", path: "/api/auth/sign-ins?limit=0", bad: true}, 400, nil)
	c.do(admin, u, call{method: "GET", path: "/api/auth/sign-ins?outcome=bogus", bad: true}, 400, nil)
	c.do(bob, u, call{method: "GET", path: "/api/auth/sign-ins"}, 403, nil)
	c.do(anon, u, call{method: "GET", path: "/api/auth/sign-ins"}, 401, nil)

	// Unusual sign-ins (#55): the admin signing in from a second browser
	// is flagged (new-browser, the default policy), on that session's row
	// and on the history's; ?unusual=true lists only such rows.
	admin2 := c.client()
	c.do(admin2, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"admin", adminPass}}, 200, nil)
	c.do(admin2, u, call{method: "POST", path: "/api/auth/login/factor", body: loginFactorRequest{Code: adminRecovery[len(adminRecovery)-1]}}, 200, nil)
	var adminSessions struct {
		Sessions []struct {
			Current bool     `json:"current"`
			Unusual []string `json:"unusual"`
		} `json:"sessions"`
	}
	c.do(admin2, u, call{method: "GET", path: "/api/auth/sessions"}, 200, &adminSessions)
	flagged := 0
	for _, s := range adminSessions.Sessions {
		if len(s.Unusual) > 0 {
			flagged++
			if !s.Current || s.Unusual[0] != "new-browser" {
				t.Fatalf("admin's sessions = %+v, want only the second browser's flagged new-browser", adminSessions)
			}
		}
	}
	if flagged != 1 {
		t.Fatalf("admin's sessions = %+v, want one flagged", adminSessions)
	}
	var unusualHistory struct {
		SignIns []struct {
			Unusual []string `json:"unusual"`
		} `json:"signIns"`
	}
	c.do(admin2, u, call{method: "GET", path: "/api/auth/sign-ins?unusual=true"}, 200, &unusualHistory)
	if len(unusualHistory.SignIns) != 1 || len(unusualHistory.SignIns[0].Unusual) != 1 {
		t.Fatalf("unusual sign-ins = %+v, want the second browser's", unusualHistory)
	}
	c.do(admin2, u, call{method: "GET", path: "/api/auth/sign-ins?unusual=maybe", bad: true}, 400, nil)
	c.do(admin2, u, call{method: "POST", path: "/api/auth/logout"}, 200, nil)
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
	c.do(bob, u, call{method: "POST", path: enrolmentConfirmPath}, 409, nil) // nothing held yet
	c.do(anon, u, call{method: "POST", path: enrolmentConfirmPath}, 401, nil)
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
	if !confirmed.PendingConfirmation || confirmed.Enabled || len(confirmed.RecoveryCodes) != 10 {
		t.Fatalf("the first app = %+v, want ten codes held for confirmation", confirmed)
	}
	// One enrolment at a time while the app is held (#58).
	c.do(bob, u, call{method: "POST", path: "/api/auth/totp/enrol", body: totpEnrolRequest{Password: bobPass}}, 409, nil)
	var done enrolmentConfirmResponse
	c.do(bob, u, call{method: "POST", path: enrolmentConfirmPath}, 200, &done)
	if !done.Confirmed || done.Factor != "totp" {
		t.Fatalf("confirming the held app = %+v", done)
	}
	c.do(bob, u, call{method: "POST", path: "/api/auth/totp/enrol", body: totpEnrolRequest{Password: bobPass}}, 409, nil)

	// Confirming on an account that already has a second factor (a
	// passkey, written to the store directly: this gate has no relying
	// party) is the only answer carrying alreadyIssued. The document's
	// closed bodies only catch a renamed optional field when the test
	// makes the handler send it.
	vic := c.client()
	c.do(vic, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"vic", bobPass}}, 200, nil)
	if _, err := f.users.AddPasskey(vicID, gauntlet.Passkey{ID: []byte("vic-credential"), RPID: "vic.example.org"}); err != nil {
		t.Fatal(err)
	}
	c.do(vic, u, call{method: "POST", path: "/api/auth/totp/enrol", body: totpEnrolRequest{Password: bobPass}}, 200, &enrolled)
	if secret, err = gauntlet.DecodeTOTPSecret(enrolled.Secret); err != nil {
		t.Fatal(err)
	}
	confirmed = totpConfirmResponse{}
	c.do(vic, u, call{method: "POST", path: "/api/auth/totp/confirm", body: totpConfirmRequest{Code: gauntlet.GenerateTOTPCode(secret, counter)}}, 200, &confirmed)
	if !confirmed.AlreadyIssued || !confirmed.Enabled || confirmed.RecoveryCodes != nil {
		t.Fatalf("confirming beside a live passkey = %+v, want enabled, alreadyIssued, no codes", confirmed)
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
	// bob now holds no second factor at all. regenerateRecoveryCodes's
	// own refusal for that (409, still documented above) is unreachable
	// through the ordinary session-cookie path since #49: the
	// forced-enrolment door in Protect already refuses every
	// non-enrolment route to such an account before the handler runs.
	c.do(bob, u, call{method: "POST", path: "/api/auth/recovery-codes", body: recoveryCodesRegenerateRequest{Password: bobPass}}, 403, nil)

	// The admin routes that take over or strip an account ask for the
	// calling admin's own password again (#72): a wrong one is a 401.
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/users/" + bobID + "/totp", body: passwordRequest{"wrong"}}, 401, nil)
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/users/" + bobID + "/totp", body: passwordRequest{adminPass}}, 200, nil)
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/users/" + adminID + "/totp", body: passwordRequest{adminPass}}, 409, nil)
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/users/no-such-id/totp", body: passwordRequest{adminPass}}, 404, nil)

	// Admin reset, the must-change-password door, and changing a password.
	var reset resetPasswordResponse
	c.do(admin, u, call{method: "POST", path: "/api/auth/users/" + bobID + "/reset-password", body: passwordRequest{adminPass}}, 200, &reset)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users/" + adminID + "/reset-password", body: passwordRequest{adminPass}}, 409, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users/no-such-id/reset-password", body: passwordRequest{adminPass}}, 404, nil)

	// The admin unlock route (#44): 200 whether or not anything was
	// locked, 404 for no account. The caller's own takes the password
	// and a current second factor again: 400 without them, 401 with a
	// wrong one, 200 with both right (adminRecovery: the admin's own
	// recovery codes, from their enrolment above).
	var unlocked unlockUserResponse
	c.do(admin, u, call{method: "POST", path: "/api/auth/users/" + bobID + "/unlock"}, 200, &unlocked)
	if unlocked.WasDisabled || unlocked.WasLockedOut {
		t.Fatalf("unlocking an account with nothing to lift = %+v", unlocked)
	}
	c.do(admin, u, call{method: "POST", path: "/api/auth/users/" + adminID + "/unlock"}, 400, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users/" + adminID + "/unlock", body: unlockSelfRequest{Password: adminPass}}, 400, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users/" + adminID + "/unlock", body: unlockSelfRequest{Password: "wrong-password", Code: adminRecovery[0]}}, 401, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users/" + adminID + "/unlock", body: unlockSelfRequest{Password: adminPass, Code: adminRecovery[0]}}, 200, &unlocked)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users/no-such-id/unlock"}, 404, nil)
	c.do(anon, u, call{method: "POST", path: "/api/auth/users/" + bobID + "/unlock"}, 401, nil)

	// The admin's sign-out of another account (#53): every status but
	// 503, which the setup section above drives.
	var loggedOut adminLogoutAllResponse
	c.do(admin, u, call{method: "POST", path: "/api/auth/users/" + bobID + "/logout-all", body: adminLogoutAllRequest{Reason: "contract test"}}, 200, &loggedOut)
	if loggedOut.Username != "bob" || loggedOut.Notified {
		t.Fatalf("admin logout-all = %+v, want bob's, not notified", loggedOut)
	}
	c.do(admin, u, call{method: "POST", path: "/api/auth/users/" + bobID + "/logout-all"}, 200, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users/" + bobID + "/logout-all", body: adminLogoutAllRequest{Reason: "line\nbreak"}}, 400, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users/" + bobID + "/logout-all", body: "{", bad: true}, 400, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users/" + adminID + "/logout-all"}, 409, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users/no-such-id/logout-all"}, 404, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users/" + bobID + "/logout-all", noCSRF: true}, 403, nil)
	c.do(vic, u, call{method: "POST", path: "/api/auth/users/" + bobID + "/logout-all"}, 403, nil)
	c.do(anon, u, call{method: "POST", path: "/api/auth/users/" + bobID + "/logout-all"}, 401, nil)
	bob = c.client()
	c.do(bob, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"bob", reset.Code}}, 200, nil)
	resp := c.do(bob, u, call{method: "POST", path: "/api/auth/logout-all"}, 403, nil)
	if resp.Header.Get(authGateHeader) != authGateMustChangePassword {
		t.Fatalf("%s = %q, want %q", authGateHeader, resp.Header.Get(authGateHeader), authGateMustChangePassword)
	}
	c.do(bob, u, call{method: "POST", path: "/api/auth/password", body: changePasswordRequest{NewPassword: "short"}}, 400, nil)
	c.do(bob, u, call{method: "POST", path: "/api/auth/password", body: changePasswordRequest{NewPassword: bobPass + "-2"}}, 200, nil)
	// Admin cleared bob's factor above (line 487) and this SetPassword
	// just cleared MustChangePassword, so bob is otherwise back at the
	// forced-enrolment door -- a voluntary change is not an enrolment
	// route either, so bob needs a factor again before the wrong-
	// current-password check below can reach the handler at all.
	enrolTOTPFactor(t, c, u, bob, bobPass+"-2")
	c.do(bob, u, call{method: "POST", path: "/api/auth/password", body: changePasswordRequest{CurrentPassword: "wrong", NewPassword: bobPass}}, 401, nil)
	c.do(bob, u, call{method: "POST", path: "/api/auth/logout-all", body: passwordRequest{"wrong"}}, 401, nil)
	c.do(bob, u, call{method: "POST", path: "/api/auth/logout-all", body: passwordRequest{bobPass + "-2"}}, 200, nil)

	// The caller's own sessions (#48). Sign out everywhere left bob one
	// session, listed with the address and agent the closed row schema
	// allows; ending it signs this client out, which the logout below
	// then finds already done.
	var sessions struct {
		Sessions []struct {
			Ref       string `json:"ref"`
			Current   bool   `json:"current"`
			UserAgent string `json:"userAgent"`
			Address   string `json:"address"`
		} `json:"sessions"`
		Total int `json:"total"`
	}
	c.do(bob, u, call{method: "GET", path: "/api/auth/sessions"}, 200, &sessions)
	if sessions.Total != 1 || len(sessions.Sessions) != 1 || !sessions.Sessions[0].Current || sessions.Sessions[0].UserAgent == "" || sessions.Sessions[0].Address == "" {
		t.Fatalf("bob's sessions after sign out everywhere = %+v", sessions)
	}
	c.do(anon, u, call{method: "GET", path: "/api/auth/sessions"}, 401, nil)
	c.do(bob, u, call{method: "DELETE", path: "/api/auth/sessions/" + strings.Repeat("0", 32)}, 404, nil)
	c.do(bob, u, call{method: "DELETE", path: "/api/auth/sessions/" + sessions.Sessions[0].Ref, noCSRF: true}, 403, nil)
	var ended struct {
		Ended     bool `json:"ended"`
		SignedOut bool `json:"signedOut"`
	}
	c.do(bob, u, call{method: "DELETE", path: "/api/auth/sessions/" + sessions.Sessions[0].Ref}, 200, &ended)
	if !ended.Ended || !ended.SignedOut {
		t.Fatalf("ending bob's only session = %+v, want ended and signed out", ended)
	}
	c.do(bob, u, call{method: "GET", path: "/api/auth/sessions"}, 401, nil)

	c.do(bob, u, call{method: "POST", path: "/api/auth/logout"}, 200, nil)
	c.do(bob, u, call{method: "POST", path: "/api/auth/logout", noCSRF: true}, 403, nil)
	c.do(anon, u, call{method: "POST", path: "/api/auth/logout-all"}, 401, nil)

	// API tokens.
	var created tokenResponse
	c.do(admin, u, call{method: "POST", path: "/api/tokens", body: createTokenRequest{Name: "grafana", Password: adminPass}}, 201, &created)
	c.do(admin, u, call{method: "POST", path: "/api/tokens", body: createTokenRequest{Name: "", Password: adminPass}}, 400, nil)
	c.do(admin, u, call{method: "POST", path: "/api/tokens", body: createTokenRequest{Name: strings.Repeat("n", gauntlet.MaxTokenNameLen+1), Password: adminPass}}, 400, nil)
	c.do(admin, u, call{method: "POST", path: "/api/tokens", body: createTokenRequest{Name: "sensor", Kind: "ingest", Device: "sensor-1", Password: adminPass}}, 201, nil)
	// expiresAt (#74): a year by default, chosen, or "never" (the key is
	// then absent from the response, which the document allows).
	if created.ExpiresAt.IsZero() || !strings.HasPrefix(created.Value, "gnt_") {
		t.Fatalf("created token = %+v, want a year-out expiresAt and a gnt_ value", created)
	}
	empty, never, soon, past := "", "never", time.Now().Add(48*time.Hour).UTC().Format(time.RFC3339), time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	var neverTok, soonTok tokenResponse
	c.do(admin, u, call{method: "POST", path: "/api/tokens", body: createTokenRequest{Name: "forever", ExpiresAt: &never, Password: adminPass}}, 201, &neverTok)
	c.do(admin, u, call{method: "POST", path: "/api/tokens", body: createTokenRequest{Name: "soon", ExpiresAt: &soon, Password: adminPass}}, 201, &soonTok)
	c.do(admin, u, call{method: "POST", path: "/api/tokens", body: createTokenRequest{Name: "late", ExpiresAt: &past, Password: adminPass}}, 400, nil)
	c.do(admin, u, call{method: "POST", path: "/api/tokens", body: createTokenRequest{Name: "odd", ExpiresAt: &empty, Password: adminPass}}, 400, nil)
	if !neverTok.ExpiresAt.IsZero() || soonTok.ExpiresAt.IsZero() {
		t.Fatalf("never = %+v, soon = %+v", neverTok, soonTok)
	}
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
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/users/" + adminID, body: passwordRequest{adminPass}}, 409, nil)
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/users/no-such-id", body: passwordRequest{adminPass}}, 404, nil)
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/users/" + bobID, body: passwordRequest{adminPass}}, 200, nil)

	// Several admins (#67) and role changes (#75). The step-up is the
	// caller's password and a current second factor (an unspent recovery
	// code here) on the same request.
	c.do(admin, u, call{method: "POST", path: "/api/auth/users", body: createUserRequest{Username: "eve", Password: bobPass, Role: "admin"}}, 400, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users", body: createUserRequest{Username: "eve", Password: bobPass, Role: "admin", AdminPassword: adminPass}}, 400, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users", body: createUserRequest{Username: "eve", Password: bobPass, Role: "admin", AdminPassword: "wrong-password", AdminCode: adminRecovery[1]}}, 401, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users", body: createUserRequest{Username: "eve", Password: bobPass, Role: "admin", AdminPassword: adminPass, AdminCode: adminRecovery[1]}}, 201, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users", body: createUserRequest{Username: "dan", Password: bobPass, Role: "user"}}, 201, nil)
	var several []userSummary
	c.do(admin, u, call{method: "GET", path: "/api/auth/users"}, 200, &several)
	eveID, danID := "", ""
	for _, s := range several {
		switch s.Username {
		case "eve":
			eveID = s.ID
		case "dan":
			danID = s.ID
		}
	}
	role := func(id string) string { return "/api/auth/users/" + id + "/role" }
	dan := c.client()
	c.do(dan, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"dan", bobPass}}, 200, nil)
	var changed setRoleResponse
	c.do(admin, u, call{method: "PUT", path: role(danID), body: setRoleRequest{Role: "user"}}, 409, nil) // already a user
	c.do(admin, u, call{method: "PUT", path: role(danID), body: setRoleRequest{Role: "owner"}}, 400, nil)
	c.do(admin, u, call{method: "PUT", path: role(danID), body: "{", bad: true}, 400, nil)
	c.do(admin, u, call{method: "PUT", path: role(danID), body: setRoleRequest{Role: "admin"}}, 400, nil) // no step-up
	c.do(admin, u, call{method: "PUT", path: role(danID), body: setRoleRequest{Role: "admin", Password: adminPass}}, 400, nil)
	c.do(admin, u, call{method: "PUT", path: role(danID), body: setRoleRequest{Role: "admin", Password: "wrong-password", Code: adminRecovery[2]}}, 401, nil)
	c.do(admin, u, call{method: "PUT", path: role(danID), body: setRoleRequest{Role: "admin", Password: adminPass, Code: adminRecovery[2]}}, 200, &changed)
	if changed != (setRoleResponse{Username: "dan", From: "user", To: "admin"}) {
		t.Fatalf("granting admin = %+v", changed)
	}
	c.do(admin, u, call{method: "PUT", path: role(danID), body: setRoleRequest{Role: "viewer"}}, 200, &changed) // a downgrade needs no step-up
	if changed != (setRoleResponse{Username: "dan", From: "admin", To: "viewer", SessionsEnded: true}) {
		t.Fatalf("demoting an admin = %+v", changed)
	}
	c.do(dan, u, call{method: "GET", path: "/api/auth/users"}, 401, nil) // dan's session ended with the downgrade
	c.do(admin, u, call{method: "PUT", path: role("no-such-id"), body: setRoleRequest{Role: "user"}}, 404, nil)
	c.do(admin, u, call{method: "PUT", path: role(danID), body: setRoleRequest{Role: "user"}, noCSRF: true}, 403, nil)
	c.do(anon, u, call{method: "PUT", path: role(danID), body: setRoleRequest{Role: "user"}}, 401, nil)
	c.do(vic, u, call{method: "PUT", path: role(danID), body: setRoleRequest{Role: "user"}}, 403, nil)
	// Another admin may be deleted; the last one may be neither deleted
	// nor demoted, and says so with its own class.
	lastAdmin := func(p *struct {
		Type string `json:"type"`
	}) {
		t.Helper()
		if want := "https://github.com/tomlawesome/gauntlet/blob/main/docs/api/errors.md#last-admin"; p.Type != want {
			t.Errorf("the last admin's refusal has type %q, want %q", p.Type, want)
		}
	}
	var refusal struct {
		Type string `json:"type"`
	}
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/users/" + adminID, body: passwordRequest{adminPass}}, 409, nil) // eve exists: not your own account
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/users/" + eveID, body: passwordRequest{adminPass}}, 200, nil)
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/users/" + adminID, body: passwordRequest{adminPass}}, 409, &refusal)
	lastAdmin(&refusal)
	c.do(admin, u, call{method: "PUT", path: role(adminID), body: setRoleRequest{Role: "user"}}, 409, &refusal)
	lastAdmin(&refusal)

	// SSO is off on this gate.
	c.do(anon, u, call{method: "GET", path: "/api/auth/oidc/login"}, 404, nil)
	c.do(anon, u, call{method: "GET", path: "/api/auth/oidc/callback?state=x&code=y"}, 404, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/oidc/link", body: passwordRequest{adminPass}}, 404, nil)

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
	codec, ts, fp := newOIDCTestServer(t)
	u := ts.URL

	// The first admin is local (newOIDCTestServer registered "setup-admin"
	// with the setup code); the first SSO sign-in is an ordinary user.
	first := c.client()
	contractSSOSignIn(t, c, codec, fp, first, u, "/api/auth/oidc/login", nil, "/")
	// An SSO-provisioned account has no local password: no passkey.
	c.do(first, u, call{method: "POST", path: "/api/auth/passkeys/register/begin", body: passwordRequest{"anything"}}, 409, nil)
	admin := c.client()
	c.do(admin, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"setup-admin", "setup-admin-password"}}, 200, nil)
	enrolTOTPFactor(t, c, u, admin, "setup-admin-password") // POST /api/auth/users is not an enrolment route

	c.do(c.client(), u, call{method: "POST", path: "/api/auth/users", body: createUserRequest{Username: "carol", Password: "contract-carol-password"}}, 401, nil)
	c.do(first, u, call{method: "POST", path: "/api/auth/users", body: createUserRequest{Username: "carol", Password: "contract-carol-password"}}, 403, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users", body: createUserRequest{Username: "carol", Password: "contract-carol-password"}}, 201, nil)

	// The first SSO account's role comes from its groups (#76): it has
	// none, so it is a viewer, and the role route will not move it.
	var accounts []userSummary
	c.do(admin, u, call{method: "GET", path: "/api/auth/users"}, 200, &accounts)
	firstID := ""
	for _, a := range accounts {
		if a.Username == "person" {
			firstID = a.ID
		}
	}
	if firstID == "" {
		t.Fatal("the first SSO account is not in the user list")
	}
	var managed struct {
		Type string `json:"type"`
	}
	c.do(admin, u, call{method: "PUT", path: "/api/auth/users/" + firstID + "/role", body: setRoleRequest{Role: "user"}}, 409, &managed)
	if want := "https://github.com/tomlawesome/gauntlet/blob/main/docs/api/errors.md#role-managed-by-sso"; managed.Type != want {
		t.Errorf("the managed account's refusal has type %q, want %q", managed.Type, want)
	}

	// carol links her local account to a second identity.
	carol := c.client()
	c.do(carol, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"carol", "contract-carol-password"}}, 200, nil)
	enrolTOTPFactor(t, c, u, carol, "contract-carol-password") // POST /api/auth/oidc/link is not an enrolment route
	c.do(carol, u, call{method: "POST", path: "/api/auth/oidc/link", body: passwordRequest{"wrong"}}, 401, nil)
	contractSSOSignIn(t, c, codec, fp, carol, u, "/api/auth/oidc/link", passwordRequest{"contract-carol-password"}, "/?ssoLinked=1")
	c.do(carol, u, call{method: "POST", path: "/api/auth/oidc/link", body: passwordRequest{"contract-carol-password"}}, 409, nil)

	// A callback with no flow cookie goes back to the login page.
	resp := c.do(c.client(), u, call{method: "GET", path: "/api/auth/oidc/callback?state=x&code=y"}, 302, nil)
	if loc := resp.Header.Get("Location"); loc != testLoginPath+"?ssoError=state_mismatch" {
		t.Fatalf("callback without a flow cookie redirected to %q", loc)
	}
}

// contractSSOSignIn starts a flow at start (the SSO login or link route,
// the link sent body), has the fake provider answer for the next
// subject, and finishes it at the callback, which must redirect to
// wantLocation.
func contractSSOSignIn(t *testing.T, c *contractChecker, codec *oidc.StateCodec, fp *testutil.FakeProvider, client *http.Client, base, start string, body any, wantLocation string) {
	t.Helper()
	if start == "/api/auth/oidc/login" {
		c.do(client, base, call{method: "GET", path: start}, 302, nil)
	} else {
		c.do(client, base, call{method: "POST", path: start, body: body}, 200, nil)
	}
	target, err := http.NewRequest(http.MethodGet, base+"/api/auth/oidc/callback", nil)
	if err != nil {
		t.Fatal(err)
	}
	// The flow cookie is the one this gate's codec can open; it is
	// seconds old, so a minute's allowance is plenty.
	var fs oidc.FlowState
	found := false
	for _, ck := range client.Jar.Cookies(target.URL) {
		if got, err := codec.Decode(ck.Value, time.Minute, time.Now()); err == nil {
			fs, found = got, true
		}
	}
	if !found {
		t.Fatalf("%s set no flow cookie this gate's codec can open", start)
	}
	claims := fp.DefaultClaims(oidcTestClientID, fs.Nonce)
	claims.Subject = fmt.Sprintf("contract-subject-%d", time.Now().UnixNano())
	fp.NextIDToken = fp.SignRS256(t, claims)
	resp := c.do(client, base, call{method: "GET", path: "/api/auth/oidc/callback?state=" + fs.State + "&code=test-code"}, 302, nil)
	if loc := resp.Header.Get("Location"); loc != wantLocation {
		t.Fatalf("callback redirected to %q, want %q", loc, wantLocation)
	}
}

// TestRevokeTokenStorageFailureIsNotReportedAsGone: a revoke whose save
// fails leaves the token working, so answering 404 ("already revoked")
// would tell an admin revoking a leaked token that it is dead when it
// is not. The refusal must be a 5xx the document describes. Package
// gate's test of the same name checks the behaviour without the
// document.
func TestRevokeTokenStorageFailureIsNotReportedAsGone(t *testing.T) {
	c := newContractChecker(t)
	backend := &budgetBackend{inner: persist.NewMemory(), left: -1}
	tokens, err := gauntlet.OpenTokenStore(backend, gauntlet.TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	f := newTestGateWith(t, persist.NewMemory(), tokens)
	if _, err := f.users.Register("admin", "password-placeholder-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	raw, tok, err := tokens.Create("leaked", gauntlet.TokenKindAPI, "", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.g.Handle(gauntlet.TokenKindAPI, testProtectedHandler())
	ts := newTestServer(t, f.g)
	admin := c.client()
	c.do(admin, ts.URL, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{Username: "admin", Password: "password-placeholder-1"}}, 200, nil)
	enrolTOTPFactor(t, c, ts.URL, admin, "password-placeholder-1") // DELETE /api/tokens/{id} is not an enrolment route

	backend.left = 0
	c.do(admin, ts.URL, call{method: "DELETE", path: "/api/tokens/" + tok.ID}, http.StatusInternalServerError, nil)

	resp := bearerRequest(t, ts.URL, "/api/protected", raw)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the token stopped working although its revoke was refused: got %d, want 200", resp.StatusCode)
	}
}

// TestContractTokenRegisteredKinds: an application may register its own
// token kinds (TokenOptions.Kinds), so the document must accept any of
// them, not only api and ingest. Leaving kind out still means api, which
// is refused when the application did not register api.
func TestContractTokenRegisteredKinds(t *testing.T) {
	c := newContractChecker(t)
	const custom gauntlet.TokenKind = "droplist-pull"
	tokens, err := gauntlet.OpenTokenStore(persist.NewMemory(), gauntlet.TokenOptions{Kinds: []gauntlet.TokenKind{custom}})
	if err != nil {
		t.Fatal(err)
	}
	f := newTestGateWith(t, persist.NewMemory(), tokens)
	ts := newTestServer(t, f.g)
	u := ts.URL
	admin := c.client()
	c.do(admin, u, call{method: "POST", path: "/api/auth/register", body: registerRequest{Username: "admin", Password: "contract-admin-password", SetupCode: f.setupCode}}, 201, nil)
	enrolTOTPFactor(t, c, u, admin, "contract-admin-password") // POST /api/tokens is not an enrolment route

	var created tokenResponse
	// The calling admin's own password is asked for again (#72).
	c.do(admin, u, call{method: "POST", path: "/api/tokens", body: createTokenRequest{Name: "pull", Kind: string(custom), Password: "wrong"}}, 401, nil)
	c.do(admin, u, call{method: "POST", path: "/api/tokens", body: createTokenRequest{Name: "pull", Kind: string(custom), Password: "contract-admin-password"}}, 201, &created)
	if created.Kind != custom {
		t.Errorf("created kind = %q, want %q", created.Kind, custom)
	}
	c.do(admin, u, call{method: "POST", path: "/api/tokens", body: createTokenRequest{Name: "default", Password: "contract-admin-password"}}, 400, nil)
	var list struct {
		Tokens []tokenResponse `json:"tokens"`
	}
	c.do(admin, u, call{method: "GET", path: "/api/tokens"}, 200, &list)
	if len(list.Tokens) != 1 || list.Tokens[0].Kind != custom {
		t.Errorf("listed tokens = %+v, want one of kind %q", list.Tokens, custom)
	}
}

// TestTOTPConfirmWhoseHoldCannotBeSavedIsAPlainServerError: the first
// app and its recovery codes are one write (#58), so a failed save is a
// plain server-error with nothing done -- the body the document's
// InternalError describes, not 0.2.0's partially-completed one.
func TestTOTPConfirmWhoseHoldCannotBeSavedIsAPlainServerError(t *testing.T) {
	const bobName, bobPass = "bob", "bob-password-123"
	c := newContractChecker(t)
	backend := &budgetBackend{inner: persist.NewMemory(), left: -1}
	f := newTestGateWith(t, backend, nil)
	ts := newTestServer(t, f.g)
	admin := c.client()
	c.do(admin, ts.URL, call{method: "POST", path: "/api/auth/register", body: registerRequest{"admin", "password-placeholder-1", f.setupCode}}, 201, nil)
	enrolTOTPFactor(t, c, ts.URL, admin, "password-placeholder-1") // POST /api/auth/users is not an enrolment route
	c.do(admin, ts.URL, call{method: "POST", path: "/api/auth/users", body: createUserRequest{Username: bobName, Password: bobPass, Role: "user"}}, 201, nil)

	bob := c.client()
	c.do(bob, ts.URL, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{bobName, bobPass}}, 200, nil)
	var enrolled totpEnrolResponse
	c.do(bob, ts.URL, call{method: "POST", path: "/api/auth/totp/enrol", body: totpEnrolRequest{Password: bobPass}}, 200, &enrolled)
	secret, err := gauntlet.DecodeTOTPSecret(enrolled.Secret)
	if err != nil {
		t.Fatal(err)
	}
	code := gauntlet.GenerateTOTPCode(secret, totpCounterNow(time.Now()))

	backend.left = 0 // the hold's one save fails
	resp, raw := c.send(bob, ts.URL, call{method: "POST", path: "/api/auth/totp/confirm", body: totpConfirmRequest{Code: code}})
	backend.left = -1
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("confirm with the hold's save failing returned %d, want 500: %s", resp.StatusCode, raw)
	}
	var body struct {
		Type       string `json:"type"`
		TOTPActive *bool  `json:"totpActive"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("the 500 body is not JSON: %v: %s", err, raw)
	}
	if !strings.HasSuffix(body.Type, "#server-error") || body.TOTPActive != nil {
		t.Errorf("the 500 body = %s, want a plain server-error", raw)
	}
}

// passkeyGateServer serves a gate whose Deps.Passkeys is a relying party
// for publicURL ("" for one that is not ready), with "admin" registered
// and signed in on the returned client and "bob" created.
func passkeyGateServer(t *testing.T, c *contractChecker, publicURL string, wired bool) (*fixture, *httptest.Server, *http.Client) {
	t.Helper()
	users, code := openStore(t, persist.NewMemory())
	deps := gate.Deps{Users: users}
	if wired {
		rp, err := passkey.New(passkey.Config{PublicURL: publicURL, DisplayName: testProductName})
		if err != nil {
			t.Fatal(err)
		}
		deps.Passkeys = rp
	}
	f := &fixture{g: newGate(t, deps), users: users, setupCode: code}
	ts := newTestServer(t, f.g)
	admin := c.client()
	c.do(admin, ts.URL, call{method: "POST", path: "/api/auth/register", body: registerRequest{"admin", "contract-admin-password", code}}, 201, nil)
	enrolTOTPFactor(t, c, ts.URL, admin, "contract-admin-password") // POST /api/auth/users is not an enrolment route
	c.do(admin, ts.URL, call{method: "POST", path: "/api/auth/users", body: createUserRequest{Username: "bob", Password: "contract-bob-password"}}, 201, nil)
	return f, ts, admin
}

// contractPasskeys drives the passkey routes (G8, ADR-0004) with the
// shared fake authenticator: every documented success and the refusals
// a test can reach, on a wired gate, one whose relying party is not
// ready, and one with no passkeys at all.
func contractPasskeys(t *testing.T, c *contractChecker) {
	const bobPass = "contract-bob-password"
	const publicURL = "https://passkeys.example.org"
	f, ts, admin := passkeyGateServer(t, c, publicURL, true)
	u := ts.URL
	anon := c.client()
	bob := c.client()
	c.do(bob, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"bob", bobPass}}, 200, nil)

	var rows []passkeyRow
	// GET /api/auth/passkeys is deliberately not one of the
	// forced-enrolment door's exempt routes (secondFactorEnrolPaths'
	// own doc comment in gate/protect.go: "there is nothing yet
	// enrolled for them to act on while this gate holds") -- bob holds
	// no second factor yet, so this is the door, not an empty list. The
	// populated list is checked with bob2 further down, once bob has
	// registered his first passkey.
	c.do(bob, u, call{method: "GET", path: "/api/auth/passkeys"}, 403, nil)
	c.do(anon, u, call{method: "GET", path: "/api/auth/passkeys"}, 401, nil)
	var state sessionResponse
	c.do(bob, u, call{method: "GET", path: "/api/auth/session"}, 200, &state)
	if state.Passkeys == nil || state.Passkeys.Status != "ready" || state.Passkeys.Origin != publicURL {
		t.Fatalf("session passkeys = %+v, want ready at %s", state.Passkeys, publicURL)
	}

	register := func(client *http.Client, fake *passkeytest.FakeAuthenticator, name string, want int, out any) {
		t.Helper()
		var creation protocol.CredentialCreation
		c.do(client, u, call{method: "POST", path: "/api/auth/passkeys/register/begin", body: passwordRequest{bobPass}}, 200, &creation)
		body, err := fake.RegisterResponse(&creation)
		if err != nil {
			t.Fatal(err)
		}
		c.do(client, u, call{method: "POST", path: "/api/auth/passkeys/register/finish", body: passkeyRegisterFinishRequest{json.RawMessage(body), name}}, want, out)
	}

	// Registration is password-gated at begin.
	c.do(bob, u, call{method: "POST", path: "/api/auth/passkeys/register/begin", body: passwordRequest{"wrong"}}, 401, nil)

	// Refused registrations, then the first factor (held with ten codes
	// until confirmed, #58), a second (live, alreadyIssued) and a
	// duplicate.
	wrongOrigin := passkeytest.New("passkeys.example.org", "https://not-the-relying-party.example")
	register(bob, wrongOrigin, "wrong origin", 400, nil)
	c.do(bob, u, call{method: "POST", path: "/api/auth/passkeys/register/finish", body: "{", bad: true}, 400, nil)
	c.do(admin, u, call{method: "POST", path: "/api/auth/passkeys/register/finish", body: passkeyRegisterFinishRequest{json.RawMessage(`{}`), "no begin"}}, 401, nil)
	// A dead ceremony (a garbage cookie) is 401 and clears the cookie; the
	// wrong-origin finish above was 400, the refused-credential meaning.
	deadURL, err := url.Parse(u + "/api/auth/passkeys")
	if err != nil {
		t.Fatal(err)
	}
	bob.Jar.SetCookies(deadURL, []*http.Cookie{{Name: "gate_passkey_register", Value: "garbage", Path: "/api/auth/passkeys"}})
	dead := c.do(bob, u, call{method: "POST", path: "/api/auth/passkeys/register/finish", body: passkeyRegisterFinishRequest{json.RawMessage(`{}`), "dead"}}, 401, nil)
	if i := slices.IndexFunc(dead.Cookies(), func(ck *http.Cookie) bool { return ck.Name == "gate_passkey_register" && ck.MaxAge < 0 }); i < 0 {
		t.Fatal("a dead registration ceremony did not clear its cookie")
	}
	key := passkeytest.New("passkeys.example.org", publicURL)
	var first passkeyRegisterFinishResponse
	register(bob, key, "first", 200, &first)
	if len(first.RecoveryCodes) != 10 || !first.PendingConfirmation {
		t.Fatalf("first passkey = %+v, want ten recovery codes held for confirmation", first)
	}
	// One enrolment at a time while it is held.
	c.do(bob, u, call{method: "POST", path: "/api/auth/passkeys/register/begin", body: passwordRequest{bobPass}}, 409, nil)
	var done enrolmentConfirmResponse
	c.do(bob, u, call{method: "POST", path: enrolmentConfirmPath}, 200, &done)
	if done.Factor != "passkey" {
		t.Fatalf("confirming the held passkey = %+v", done)
	}
	spare := passkeytest.New("passkeys.example.org", publicURL)
	var second passkeyRegisterFinishResponse
	register(bob, spare, "spare", 200, &second)
	// A copy of that ceremony's cookie, kept and sent again after the
	// finish stored its passkey, is refused (one begin, one passkey).
	var again protocol.CredentialCreation
	c.do(bob, u, call{method: "POST", path: "/api/auth/passkeys/register/begin", body: passwordRequest{bobPass}}, 200, &again)
	regURL, err := url.Parse(u + "/api/auth/passkeys/register/finish")
	if err != nil {
		t.Fatal(err)
	}
	var keptRegister *http.Cookie
	for _, ck := range bob.Jar.Cookies(regURL) {
		if ck.Name == "gate_passkey_register" {
			keptRegister = &http.Cookie{Name: ck.Name, Value: ck.Value, Path: "/api/auth/passkeys"}
		}
	}
	if keptRegister == nil {
		t.Fatal("register/begin set no ceremony cookie")
	}
	third := passkeytest.New("passkeys.example.org", publicURL)
	thirdBody, err := third.RegisterResponse(&again)
	if err != nil {
		t.Fatal(err)
	}
	c.do(bob, u, call{method: "POST", path: "/api/auth/passkeys/register/finish", body: passkeyRegisterFinishRequest{json.RawMessage(thirdBody), "third"}}, 200, nil)
	bob.Jar.SetCookies(regURL, []*http.Cookie{keptRegister})
	fourthBody, err := passkeytest.New("passkeys.example.org", publicURL).RegisterResponse(&again)
	if err != nil {
		t.Fatal(err)
	}
	c.do(bob, u, call{method: "POST", path: "/api/auth/passkeys/register/finish", body: passkeyRegisterFinishRequest{json.RawMessage(fourthBody), "fourth"}}, 401, nil)
	if !second.AlreadyIssued || second.RecoveryCodes != nil {
		t.Fatalf("second passkey = %+v, want alreadyIssued and no codes", second)
	}
	register(bob, key, "again", 409, nil)

	// Rename.
	var renamed passkeyRow
	c.do(bob, u, call{method: "PATCH", path: "/api/auth/passkeys/" + first.Passkey.ID, body: passkeyRenameRequest{"YubiKey"}}, 200, &renamed)
	c.do(bob, u, call{method: "PATCH", path: "/api/auth/passkeys/bm8tc3VjaC1rZXk", body: passkeyRenameRequest{"x"}}, 404, nil)
	c.do(bob, u, call{method: "PATCH", path: "/api/auth/passkeys/not!base64", body: passkeyRenameRequest{"x"}}, 400, nil)
	c.do(bob, u, call{method: "PATCH", path: "/api/auth/passkeys/" + first.Passkey.ID, body: passkeyRenameRequest{"x"}, noCSRF: true}, 403, nil)

	// Sign in with a passkey.
	bob2 := c.client()
	var challenge struct {
		SecondFactor  []string `json:"secondFactor"`
		PasskeyOrigin string   `json:"passkeyOrigin"`
	}
	c.do(bob2, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"bob", bobPass}}, 200, &challenge)
	if !slices.Equal(challenge.SecondFactor, []string{"passkey"}) || challenge.PasskeyOrigin != publicURL {
		t.Fatalf("second-factor challenge = %+v", challenge)
	}
	c.do(anon, u, call{method: "POST", path: "/api/auth/login/factor/begin"}, 401, nil)
	assert := func(client *http.Client, fake *passkeytest.FakeAuthenticator, want int) {
		t.Helper()
		var options protocol.CredentialAssertion
		c.do(client, u, call{method: "POST", path: "/api/auth/login/factor/begin"}, 200, &options)
		body, err := fake.AssertionResponse(&options)
		if err != nil {
			t.Fatal(err)
		}
		c.do(client, u, call{method: "POST", path: "/api/auth/login/factor", body: loginFactorRequest{Assertion: json.RawMessage(body)}}, want, nil)
	}
	wrongRPID := *key
	wrongRPID.RPID = "not-the-relying-party.example"
	assert(bob2, &wrongRPID, 401)
	assert(bob2, key, 200)
	c.do(bob2, u, call{method: "GET", path: "/api/auth/passkeys"}, 200, &rows)
	if i := slices.IndexFunc(rows, func(r passkeyRow) bool { return r.ID == first.Passkey.ID }); i < 0 || rows[i].Name != "YubiKey" || rows[i].LastUsedAt.IsZero() {
		t.Fatalf("listed passkeys = %+v, want %s renamed and with lastUsedAt", rows, first.Passkey.ID)
	}

	// An account whose only passkey is stale: no passkey offered, and
	// begin refuses.
	var users []userSummary
	c.do(admin, u, call{method: "GET", path: "/api/auth/users"}, 200, &users)
	c.do(admin, u, call{method: "POST", path: "/api/auth/users", body: createUserRequest{Username: "carol", Password: bobPass}}, 201, nil)
	carol, ok := f.users.ByUsername("carol")
	if !ok {
		t.Fatal("carol was not created")
	}
	if _, err := f.users.AddPasskey(carol.ID, gauntlet.Passkey{ID: []byte("old-credential"), RPID: "old.example.org"}); err != nil {
		t.Fatal(err)
	}
	carolClient := c.client()
	c.do(carolClient, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"carol", bobPass}}, 200, &challenge)
	if len(challenge.SecondFactor) != 0 {
		t.Fatalf("a stale-only account was offered %v", challenge.SecondFactor)
	}
	c.do(carolClient, u, call{method: "POST", path: "/api/auth/login/factor/begin"}, 409, nil)

	// Removing passkeys: the owner's own, then an admin's clear.
	var removed map[string]any
	c.do(bob2, u, call{method: "DELETE", path: "/api/auth/passkeys/" + second.Passkey.ID, body: passwordRequest{"wrong"}}, 401, nil)
	c.do(bob2, u, call{method: "DELETE", path: "/api/auth/passkeys/" + second.Passkey.ID, body: passwordRequest{bobPass}}, 200, &removed)
	if removed["signedOut"] != false {
		t.Fatalf("removing one of three passkeys = %v, want signedOut false", removed)
	}
	c.do(bob2, u, call{method: "DELETE", path: "/api/auth/passkeys/" + second.Passkey.ID, body: passwordRequest{bobPass}}, 404, nil)
	adminRow := slices.IndexFunc(users, func(s userSummary) bool { return s.Username == "admin" })
	bobRow := slices.IndexFunc(users, func(s userSummary) bool { return s.Username == "bob" })
	if adminRow < 0 || bobRow < 0 || users[bobRow].PasskeyCount != 3 {
		t.Fatalf("users list = %+v, want bob with passkeyCount 3", users)
	}
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/users/" + users[adminRow].ID + "/passkeys", body: passwordRequest{"contract-admin-password"}}, 409, nil)
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/users/no-such-id/passkeys", body: passwordRequest{"contract-admin-password"}}, 404, nil)
	c.do(bob2, u, call{method: "DELETE", path: "/api/auth/users/" + users[bobRow].ID + "/passkeys", body: passwordRequest{bobPass}}, 403, nil)
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/users/" + users[bobRow].ID + "/passkeys", body: passwordRequest{"wrong"}}, 401, nil)
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/users/" + users[bobRow].ID + "/passkeys", body: passwordRequest{"contract-admin-password"}}, 200, nil)

	// A relying party that is not ready.
	_, unready, unreadyAdmin := passkeyGateServer(t, c, "", true)
	state = sessionResponse{}
	c.do(unreadyAdmin, unready.URL, call{method: "GET", path: "/api/auth/session"}, 200, &state)
	if state.Passkeys == nil || state.Passkeys.Status != "unset" || state.Passkeys.Origin != "" {
		t.Fatalf("session passkeys with no public URL = %+v, want unset", state.Passkeys)
	}
	c.do(unreadyAdmin, unready.URL, call{method: "GET", path: "/api/auth/passkeys"}, 200, &rows)
	c.do(unreadyAdmin, unready.URL, call{method: "POST", path: "/api/auth/passkeys/register/begin", body: passwordRequest{"contract-admin-password"}}, 409, nil)
	c.do(unreadyAdmin, unready.URL, call{method: "POST", path: "/api/auth/passkeys/register/finish", body: passkeyRegisterFinishRequest{json.RawMessage(`{}`), ""}}, 409, nil)

	// No passkeys at all.
	off, offTS, offAdmin := passkeyGateServer(t, c, "", false)
	o := offTS.URL
	bobOff, ok := off.users.ByUsername("bob")
	if !ok {
		t.Fatal("bob was not created")
	}
	state = sessionResponse{}
	c.do(offAdmin, o, call{method: "GET", path: "/api/auth/session"}, 200, &state)
	if state.Passkeys != nil {
		t.Fatalf("session with passkeys off carries %+v", state.Passkeys)
	}
	c.do(offAdmin, o, call{method: "GET", path: "/api/auth/passkeys"}, 404, nil)
	c.do(offAdmin, o, call{method: "POST", path: "/api/auth/passkeys/register/begin", body: passwordRequest{"contract-admin-password"}}, 404, nil)
	c.do(offAdmin, o, call{method: "POST", path: "/api/auth/passkeys/register/finish", body: passkeyRegisterFinishRequest{json.RawMessage(`{}`), ""}}, 404, nil)
	c.do(offAdmin, o, call{method: "PATCH", path: "/api/auth/passkeys/eA", body: passkeyRenameRequest{"x"}}, 404, nil)
	c.do(offAdmin, o, call{method: "DELETE", path: "/api/auth/passkeys/eA", body: passwordRequest{"contract-admin-password"}}, 404, nil)
	c.do(offAdmin, o, call{method: "DELETE", path: "/api/auth/users/" + bobOff.ID + "/passkeys", body: passwordRequest{"contract-admin-password"}}, 404, nil)
	c.do(anon, o, call{method: "POST", path: "/api/auth/login/factor/begin"}, 404, nil)
	c.do(anon, o, call{method: "POST", path: "/api/auth/login/factor", body: loginFactorRequest{Assertion: json.RawMessage(`{"id":"eA"}`)}}, 404, nil)
}

// passkeySignInGate serves a gate whose relying party is for publicURL
// ("" for one that is not ready) with Config.PasskeySignIn as given and
// the clock if one is, and "admin" registered and signed in on the
// returned client.
func passkeySignInGate(t *testing.T, c *contractChecker, publicURL string, on bool, clock func() time.Time) (*fixture, *httptest.Server, *http.Client) {
	t.Helper()
	users, code := openStore(t, persist.NewMemory())
	rp, err := passkey.New(passkey.Config{PublicURL: publicURL, DisplayName: testProductName})
	if err != nil {
		t.Fatal(err)
	}
	g := newGateWith(t, gate.Deps{Users: users, Passkeys: rp}, func(cfg *gate.Config) {
		cfg.PasskeySignIn = on
		if clock != nil {
			cfg.Now = clock
		}
	})
	f := &fixture{g: g, users: users, setupCode: code}
	ts := newTestServer(t, g)
	admin := c.client()
	c.do(admin, ts.URL, call{method: "POST", path: "/api/auth/register", body: registerRequest{"admin", "contract-admin-password", code}}, 201, nil)
	return f, ts, admin
}

// contractProve drives a sign-in held for a passkey (#65): a gate whose
// policy proves a new browser, an admin holding a passkey and recovery
// codes, the code step answering {"prove": "passkey"}, and the two prove
// routes -- refusals, the replay and the success -- plus both routes on a
// gate with no passkeys.
func contractProve(t *testing.T, c *contractChecker) {
	const adminPass = "contract-admin-password"
	const publicURL = "https://passkeys.example.org"
	users, code := openStore(t, persist.NewMemory())
	rp, err := passkey.New(passkey.Config{PublicURL: publicURL, DisplayName: testProductName})
	if err != nil {
		t.Fatal(err)
	}
	g := newGateWith(t, gate.Deps{Users: users, Passkeys: rp}, func(cfg *gate.Config) {
		cfg.UnusualSignIns = gate.UnusualSignInPolicy{NewBrowser: gate.UnusualSignInProve}
	})
	ts := newTestServer(t, g)
	u := ts.URL
	admin := c.client()
	c.do(admin, u, call{method: "POST", path: "/api/auth/register", body: registerRequest{"admin", adminPass, code}}, 201, nil)

	fake := passkeytest.New("passkeys.example.org", publicURL)
	var creation protocol.CredentialCreation
	c.do(admin, u, call{method: "POST", path: "/api/auth/passkeys/register/begin", body: passwordRequest{adminPass}}, 200, &creation)
	regBody, err := fake.RegisterResponse(&creation)
	if err != nil {
		t.Fatal(err)
	}
	var registered passkeyRegisterFinishResponse
	c.do(admin, u, call{method: "POST", path: "/api/auth/passkeys/register/finish", body: passkeyRegisterFinishRequest{json.RawMessage(regBody), "key"}}, 200, &registered)
	c.do(admin, u, call{method: "POST", path: enrolmentConfirmPath}, 200, nil)
	if len(registered.RecoveryCodes) == 0 {
		t.Fatal("the admin's first passkey issued no recovery codes")
	}
	adminUser, ok := users.ByUsername("admin")
	if !ok {
		t.Fatal("admin was not created")
	}
	fake.UserHandle = []byte(adminUser.ID)

	// A new browser: the password, then a recovery code, and the answer
	// is the passkey owed.
	held := func(recovery string) *http.Client {
		t.Helper()
		client := c.client()
		c.do(client, u, call{method: "POST", path: "/api/auth/login", body: credentialsRequest{"admin", adminPass}}, 200, nil)
		var challenge map[string]any
		c.do(client, u, call{method: "POST", path: "/api/auth/login/factor", body: loginFactorRequest{Code: recovery}}, 200, &challenge)
		if challenge["prove"] != "passkey" || challenge["passkeyOrigin"] != publicURL || len(challenge) != 2 {
			t.Fatalf("login/factor under prove = %v", challenge)
		}
		return client
	}
	begin := func(client *http.Client, who *passkeytest.FakeAuthenticator) json.RawMessage {
		t.Helper()
		var options protocol.CredentialAssertion
		c.do(client, u, call{method: "POST", path: "/api/auth/login/prove/begin"}, 200, &options)
		body, err := who.AssertionResponse(&options)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	newcomer := held(registered.RecoveryCodes[0])
	c.do(newcomer, u, call{method: "POST", path: "/api/auth/login/prove/begin", noCSRF: true}, 403, nil)
	stranger := *fake
	stranger.RPID = "not-the-relying-party.example"
	c.do(newcomer, u, call{method: "POST", path: "/api/auth/login/prove", body: loginProveRequest{begin(newcomer, &stranger)}}, 401, nil)
	c.do(newcomer, u, call{method: "POST", path: "/api/auth/login/prove", body: "{", bad: true}, 400, nil)
	right := begin(newcomer, fake)
	c.do(newcomer, u, call{method: "POST", path: "/api/auth/login/prove", body: loginProveRequest{right}, noCSRF: true}, 403, nil)
	c.do(newcomer, u, call{method: "POST", path: "/api/auth/login/prove", body: loginProveRequest{right}}, 200, nil)
	var state sessionResponse
	c.do(newcomer, u, call{method: "GET", path: "/api/auth/session"}, 200, &state)
	if !state.Authenticated || state.Role != "admin" {
		t.Fatalf("session after the proof = %+v, want the admin signed in", state)
	}
	// The ticket is spent.
	c.do(newcomer, u, call{method: "POST", path: "/api/auth/login/prove", body: loginProveRequest{right}}, 401, nil)
	c.do(newcomer, u, call{method: "POST", path: "/api/auth/login/prove/begin"}, 401, nil)
	// A browser holding no ticket, and a code ticket at the prove routes.
	c.do(c.client(), u, call{method: "POST", path: "/api/auth/login/prove/begin"}, 401, nil)
	c.do(c.client(), u, call{method: "POST", path: "/api/auth/login/prove", body: loginProveRequest{right}}, 401, nil)

	// No passkeys here: neither route exists.
	none, noneCode := openStore(t, persist.NewMemory())
	bare := newTestServer(t, newGateWith(t, gate.Deps{Users: none}, nil))
	c.do(c.client(), bare.URL, call{method: "POST", path: "/api/auth/register", body: registerRequest{"admin", adminPass, noneCode}}, 201, nil)
	c.do(c.client(), bare.URL, call{method: "POST", path: "/api/auth/login/prove/begin"}, 404, nil)
	c.do(c.client(), bare.URL, call{method: "POST", path: "/api/auth/login/prove", body: loginProveRequest{json.RawMessage(`{}`)}}, 404, nil)
}

// contractPasskeySignIn drives signing in with a passkey alone and a
// passkey resuming a timed-out session (#77): the two routes, the
// reauthenticate route's assertion body, the session body's signIn, and
// the refusals a test can reach, on a gate with it on, one with it off
// and one whose relying party is not ready.
func contractPasskeySignIn(t *testing.T, c *contractChecker) {
	const adminPass = "contract-admin-password"
	const publicURL = "https://passkeys.example.org"
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); defer mu.Unlock(); now = now.Add(d) }
	f, ts, admin := passkeySignInGate(t, c, publicURL, true, clock)
	u := ts.URL

	// The admin's first passkey: held with its codes, then confirmed.
	fake := passkeytest.New("passkeys.example.org", publicURL)
	var creation protocol.CredentialCreation
	c.do(admin, u, call{method: "POST", path: "/api/auth/passkeys/register/begin", body: passwordRequest{adminPass}}, 200, &creation)
	regBody, err := fake.RegisterResponse(&creation)
	if err != nil {
		t.Fatal(err)
	}
	c.do(admin, u, call{method: "POST", path: "/api/auth/passkeys/register/finish", body: passkeyRegisterFinishRequest{json.RawMessage(regBody), "key"}}, 200, nil)
	c.do(admin, u, call{method: "POST", path: enrolmentConfirmPath}, 200, nil)
	adminUser, ok := f.users.ByUsername("admin")
	if !ok {
		t.Fatal("admin was not created")
	}
	fake.UserHandle = []byte(adminUser.ID)

	// A signed-out page learns that it may offer the passkey.
	anon := c.client()
	var state sessionResponse
	c.do(anon, u, call{method: "GET", path: "/api/auth/session"}, 200, &state)
	if state.Passkeys == nil || !state.Passkeys.SignIn || state.Passkeys.Status != "ready" || state.Passkeys.Origin != publicURL || state.Passkeys.Count != 0 {
		t.Fatalf("signed-out session passkeys = %+v, want signIn, ready at %s, count 0", state.Passkeys, publicURL)
	}

	begin := func(client *http.Client, who *passkeytest.FakeAuthenticator) json.RawMessage {
		t.Helper()
		var options protocol.CredentialAssertion
		c.do(client, u, call{method: "POST", path: "/api/auth/login/passkey/begin"}, 200, &options)
		body, err := who.AssertionResponse(&options)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	finish := func(client *http.Client, assertion json.RawMessage, want int) {
		t.Helper()
		c.do(client, u, call{method: "POST", path: "/api/auth/login/passkey", body: loginPasskeyRequest{assertion}}, want, nil)
	}

	// Refusals.
	c.do(anon, u, call{method: "POST", path: "/api/auth/login/passkey/begin", noCSRF: true}, 403, nil)
	c.do(c.client(), u, call{method: "POST", path: "/api/auth/login/passkey", body: loginPasskeyRequest{json.RawMessage(`{}`)}}, 401, nil) // no ceremony
	stranger := c.client()
	body := begin(stranger, fake)
	c.do(stranger, u, call{method: "POST", path: "/api/auth/login/passkey", body: "{", bad: true}, 400, nil)
	c.do(stranger, u, call{method: "POST", path: "/api/auth/login/passkey", body: loginPasskeyRequest{body}, noCSRF: true}, 403, nil)
	noUV := *fake
	noUV.NoUserVerification = true
	finish(stranger, begin(stranger, &noUV), 401)
	// Each refusal keeps its attempts against the address's limit of five
	// in five minutes; the clock moves on between them.
	advance(6 * time.Minute)
	unknown := *fake
	unknown.UserHandle = []byte("no-such-account")
	finish(stranger, begin(stranger, &unknown), 401)
	wrongRPID := *fake
	wrongRPID.RPID = "not-the-relying-party.example"
	finish(stranger, begin(stranger, &wrongRPID), 401)

	// Signing in, and the session says how.
	advance(6 * time.Minute)
	finish(anon, begin(anon, fake), 200)
	state = sessionResponse{}
	c.do(anon, u, call{method: "GET", path: "/api/auth/session"}, 200, &state)
	if !state.Authenticated || state.Role != "admin" {
		t.Fatalf("session after a passkey sign-in = %+v, want the admin signed in", state)
	}
	var sessions struct {
		Sessions []struct {
			Current bool   `json:"current"`
			Method  string `json:"method"`
		} `json:"sessions"`
	}
	c.do(anon, u, call{method: "GET", path: "/api/auth/sessions"}, 200, &sessions)
	if len(sessions.Sessions) == 0 || !sessions.Sessions[0].Current || sessions.Sessions[0].Method != "passkey_alone" {
		t.Fatalf("session list = %+v, want the current session's method passkey_alone", sessions)
	}

	// The same passkey resumes the timed-out session; another's does not.
	advance(2 * time.Hour)
	c.do(anon, u, call{method: "GET", path: "/api/auth/session"}, 200, &state)
	if state.Authenticated {
		t.Fatalf("a timed-out session is still authenticated: %+v", state)
	}
	reauth := func(client *http.Client, req reauthenticateRequest, want int, bad bool) {
		t.Helper()
		c.do(client, u, call{method: "POST", path: "/api/auth/reauthenticate", body: req, bad: bad}, want, nil)
	}
	reauth(anon, reauthenticateRequest{Assertion: begin(anon, &unknown)}, 401, false)
	reauth(anon, reauthenticateRequest{Password: adminPass, Assertion: json.RawMessage(`{}`)}, 400, true)
	reauth(anon, reauthenticateRequest{Assertion: begin(anon, fake)}, 200, false)
	c.do(anon, u, call{method: "GET", path: "/api/auth/session"}, 200, &state)
	if !state.Authenticated {
		t.Fatalf("session after a passkey resume = %+v, want authenticated", state)
	}

	// One address cannot mint challenges without limit.
	advance(6 * time.Minute)
	limited := false
	for range 10 {
		resp, _ := c.send(c.client(), u, call{method: "POST", path: "/api/auth/login/passkey/begin"})
		if resp.StatusCode == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("ten begins from one address never reached the limit")
	}

	// Off: both routes, and an assertion at reauthenticate, are not there.
	_, offTS, offAdmin := passkeySignInGate(t, c, publicURL, false, nil)
	off := offTS.URL
	state = sessionResponse{}
	c.do(c.client(), off, call{method: "GET", path: "/api/auth/session"}, 200, &state)
	if state.Passkeys != nil {
		t.Fatalf("signed-out session with sign-in off carries %+v", state.Passkeys)
	}
	c.do(c.client(), off, call{method: "POST", path: "/api/auth/login/passkey/begin"}, 404, nil)
	c.do(c.client(), off, call{method: "POST", path: "/api/auth/login/passkey", body: loginPasskeyRequest{json.RawMessage(`{}`)}}, 404, nil)
	c.do(offAdmin, off, call{method: "POST", path: "/api/auth/reauthenticate", body: reauthenticateRequest{Assertion: json.RawMessage(`{}`)}}, 404, nil)

	// A relying party that is not ready.
	_, unreadyTS, _ := passkeySignInGate(t, c, "", true, nil)
	unready := unreadyTS.URL
	c.do(c.client(), unready, call{method: "POST", path: "/api/auth/login/passkey/begin"}, 409, nil)
	c.do(c.client(), unready, call{method: "POST", path: "/api/auth/login/passkey", body: loginPasskeyRequest{json.RawMessage(`{}`)}}, 409, nil)
}
