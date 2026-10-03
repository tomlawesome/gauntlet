package gate

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/persist"
)

// testCSRFValue is the X-Requested-With value every fixture's Gate is
// configured with -- postJSON/putJSON below send it, the same way a
// real frontend always does.
const testCSRFValue = "test-frontend"

// testCookieName is the fixture's session cookie name.
const testCookieName = "gate_test_session"

// testProductName is the fixture's Config.ProductName -- required since
// New fails closed on an empty one (Routes always serves the TOTP
// enrolment routes, which read it).
const testProductName = "Gate Test Suite"

// testLoginPath is the fixture's Config.LoginPath, the frontend route a
// failed OIDC callback redirects to with ?ssoError=.
const testLoginPath = "/login"

// mustNewLoginLimiter is every fixture's way to build a limiter: the
// thresholds and windows below are all fixed, known-good literals, so a
// config error here would be a mistake in the test itself, not something
// worth a table of its own the way NewLoginLimiter's own refusal is
// tested in the root package.
func mustNewLoginLimiter(t *testing.T, threshold int, window time.Duration) *gauntlet.LoginLimiter {
	t.Helper()
	l, err := gauntlet.NewLoginLimiter(threshold, window)
	if err != nil {
		t.Fatalf("NewLoginLimiter: %v", err)
	}
	return l
}

// newTestGate builds a Gate over fresh, empty, in-memory stores --
// gauntlet ships no file backend for tests to open against (persist.
// Memory is the one persist.Backend this module carries; see
// persist/memory.go), so every fixture starts from persist.NewMemory()
// rather than mikroview's own auth.Open(tempFile) pattern.
// testSetupCodes keeps the setup code each test store announced at
// open (gauntlet.Options.OnSetupCode), by store, so registerAdmin and
// setupCodeFor can present it the way an operator reading the log
// would. testServerGates maps a test server back to its gate for
// registerAdmin, which is handed only the server.
var (
	testSetupCodes  sync.Map // *gauntlet.Store -> string
	testServerGates sync.Map // *httptest.Server -> *Gate
)

// setupCodeFor is the code g's store announced when it opened.
func setupCodeFor(t *testing.T, g *Gate) string {
	t.Helper()
	code, ok := testSetupCodes.Load(g.deps.Users)
	if !ok {
		t.Fatal("this gate's store announced no setup code -- open it through newTestGate")
	}
	return code.(string)
}

// openTrackedStore opens a store over backend and records the setup
// code it announces, so a gate given this store can still be set up
// through registerAdmin.
func openTrackedStore(t *testing.T, backend persist.Backend) *gauntlet.Store {
	t.Helper()
	var code string
	users, err := gauntlet.OpenStore(backend, gauntlet.Options{
		OnSetupCode: gauntlet.SetupCodeFunc(func(c string) { code = c }),
	})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	testSetupCodes.Store(users, code)
	t.Cleanup(func() { testSetupCodes.Delete(users) })
	return users
}

func newTestGate(t *testing.T) *Gate {
	t.Helper()
	return newTestGateWithUsers(t, openTrackedStore(t, persist.NewMemory()))
}

// newTestGateWithUsers is newTestGate, but over an already-opened
// (and already openTrackedStore-tracked, for registerAdmin) accounts
// store -- for a fixture that needs to control the store's backend,
// such as one counting the calls a handler makes against it.
func newTestGateWithUsers(t *testing.T, users *gauntlet.Store) *Gate {
	t.Helper()
	tokens, err := gauntlet.OpenTokenStore(persist.NewMemory(), gauntlet.TokenOptions{})
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}
	sessions := gauntlet.NewSessionStore(gauntlet.MaxSessionIdle, gauntlet.MaxSessionLifetime)
	limiter := mustNewLoginLimiter(t, 5, 5*time.Minute)

	g, err := New(Config{
		CookieName:      testCookieName,
		CSRFHeaderValue: testCSRFValue,
		ClientIP:        func(r *http.Request) string { return "198.51.100.1" },
		ProductName:     testProductName,
		LoginPath:       testLoginPath,
	}, Deps{Users: users, Sessions: sessions, Tokens: tokens, Limiter: limiter})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

// openStoreWithUsers opens a Store over a hand-written accounts
// document holding exactly users -- for fixtures that need an account
// state no Store method can produce (an unrecognized role,
// MustChangePassword already set), written through persist.Memory.Save
// directly, the way a hand-edited accounts file would be.
func openStoreWithUsers(t *testing.T, users ...gauntlet.User) *gauntlet.Store {
	t.Helper()
	payload, err := json.Marshal(struct {
		Users []gauntlet.User `json:"users"`
	}{Users: users})
	if err != nil {
		t.Fatal(err)
	}
	backend := persist.NewMemory()
	if _, err := backend.Save(t.Context(), payload, 0); err != nil {
		t.Fatal(err)
	}
	store, err := gauntlet.OpenStore(backend, gauntlet.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// testProtectedHandler is what a real application's own session-gated
// route stands in for -- mikroview's /api/events, minus everything
// that route actually does.
func testProtectedHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// newTestServer mounts g's gate over a small application mux: a
// healthz route (bootstrap/session-exempt, like mikroview's), one
// ordinary protected route, and g.Routes() for everything under
// /api/auth and /api/tokens -- then wraps the whole thing in g.Protect,
// the same "mount Routes under the same Protect" shape docs/design.md
// §1.5 specifies.
func newTestServer(t *testing.T, g *Gate) *httptest.Server {
	t.Helper()
	appMux := http.NewServeMux()
	appMux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	appMux.Handle("GET /api/protected", testProtectedHandler())
	appMux.Handle("/", g.Routes())

	ts := httptest.NewServer(g.Protect(appMux))
	testServerGates.Store(ts, g)
	t.Cleanup(func() { testServerGates.Delete(ts); ts.Close() })
	return ts
}

// postJSON sends the CSRF header a real frontend always sends.
func postJSON(t *testing.T, client *http.Client, url string, body any) *http.Response {
	t.Helper()
	return doJSON(t, client, http.MethodPost, url, body)
}

// deleteJSON is postJSON's DELETE-with-a-body sibling -- for the routes
// that gate a removal behind a re-entered password (DELETE
// /api/auth/totp) rather than taking no body at all.
func deleteJSON(t *testing.T, client *http.Client, url string, body any) *http.Response {
	t.Helper()
	return doJSON(t, client, http.MethodDelete, url, body)
}

func doJSON(t *testing.T, client *http.Client, method, url string, body any) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrfHeaderName, testCSRFValue)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func mustCookieJar(t *testing.T) http.CookieJar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return jar
}

// registerAdmin registers the very first account against ts/g, enrols
// and confirms it a TOTP factor, and returns a client whose cookie jar
// carries its session. Every local-password account is stopped at the
// forced-enrolment door until it holds a second factor (#49), and what
// nearly every fixture in this package wants from "the admin" is a
// session that can reach ordinary routes, not one parked at that door
// -- so this is the default, and it leaves the account ready to act.
// registerAdminNoFactor is for the handful of tests about the door
// itself, which need an account that has not cleared it.
func registerAdmin(t *testing.T, ts *httptest.Server, username, password string) *http.Client {
	t.Helper()
	client := registerAdminNoFactor(t, ts, username, password)
	enrolTOTPFactor(t, client, ts, password)
	return client
}

// registerAdminNoFactor is registerAdmin without the automatic TOTP
// enrolment that clears the forced-enrolment door -- for pinning that
// door itself (gate/protect.go), or the enrolment routes it still
// admits.
func registerAdminNoFactor(t *testing.T, ts *httptest.Server, username, password string) *http.Client {
	t.Helper()
	g, ok := testServerGates.Load(ts)
	if !ok {
		t.Fatal("registerAdmin needs a server from newTestServer")
	}
	client := &http.Client{Jar: mustCookieJar(t)}
	resp := postJSON(t, client, ts.URL+"/api/auth/register", registerRequest{Username: username, Password: password, SetupCode: setupCodeFor(t, g.(*Gate))})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("registering %q: status = %d, want %d", username, resp.StatusCode, http.StatusCreated)
	}
	return client
}

// enrolTOTPFactor drives TOTP enrol+confirm end to end for client,
// already signed in with password and holding no second factor yet --
// the same two-step ceremony totpEnrolAndConfirm (totp_handler_test.go)
// drives for "bob", used here to clear the forced-enrolment door for an
// account whose fixture is not about that door.
func enrolTOTPFactor(t *testing.T, client *http.Client, ts *httptest.Server, password string) {
	t.Helper()
	resp := postJSON(t, client, ts.URL+"/api/auth/totp/enrol", totpEnrolRequest{Password: password})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("enrolling a TOTP factor: enrol returned %d: %s", resp.StatusCode, body)
	}
	var enrolled totpEnrolResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrolled); err != nil {
		t.Fatal(err)
	}
	secret, err := gauntlet.DecodeTOTPSecret(enrolled.Secret)
	if err != nil {
		t.Fatalf("decoding the enrolled secret: %v", err)
	}
	code := gauntlet.GenerateTOTPCode(secret, totpCounterNow(time.Now()))
	confirmResp := postJSON(t, client, ts.URL+"/api/auth/totp/confirm", totpConfirmRequest{Code: code})
	defer func() { _ = confirmResp.Body.Close() }()
	if confirmResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(confirmResp.Body)
		t.Fatalf("confirming a TOTP factor: confirm returned %d: %s", confirmResp.StatusCode, body)
	}
}
