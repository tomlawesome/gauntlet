package gate

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
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
func newTestGate(t *testing.T) *Gate {
	t.Helper()
	users, err := gauntlet.OpenStore(persist.NewMemory(), gauntlet.Options{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	tokens, err := gauntlet.OpenTokenStore(persist.NewMemory(), gauntlet.TokenOptions{})
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}
	sessions := gauntlet.NewSessionStore(24*time.Hour, 0)
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
	t.Cleanup(ts.Close)
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

// registerAdmin registers the very first account against ts/g and
// returns a client whose cookie jar carries its session.
func registerAdmin(t *testing.T, ts *httptest.Server, username, password string) *http.Client {
	t.Helper()
	client := &http.Client{Jar: mustCookieJar(t)}
	resp := postJSON(t, client, ts.URL+"/api/auth/register", credentialsRequest{Username: username, Password: password})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("registering %q: status = %d, want %d", username, resp.StatusCode, http.StatusCreated)
	}
	return client
}
