// Tests for Protect's bearer-token branch (docs/design.md §1.5): a
// token is tried against every kind registered with Handle, in
// registration order, dispatched to that kind's handler and never to
// next -- the structural guarantee mikroview's own
// TestIngestTokenCannotReachReadOnlyRoutes/TestBearerTokenCannotReach*
// tests exist for.
package gate

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// kindEchoHandler answers 200 with the dispatched token's name in the
// body, for kind -- a stand-in for an application's own read-only mux
// (mikroview's readOnlyRoutes) registered with Handle.
func kindEchoHandler(path string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
		tok := TokenFromContext(r)
		if tok == nil {
			http.Error(w, "no token in context", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(tok.Name))
	})
	return mux
}

// kindEchoHandlerAnyMethod is kindEchoHandler without a method
// restriction -- needed for a POST, since the CSRF check bearer
// dispatch is supposed to bypass only ever fires on an unsafe method.
func kindEchoHandlerAnyMethod(path string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		tok := TokenFromContext(r)
		if tok == nil {
			http.Error(w, "no token in context", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(tok.Name))
	})
	return mux
}

// registerUserDirect registers the first account directly through the
// store -- these tests only need Protect past its bootstrap state, not
// a real registration request.
func registerUserDirect(t *testing.T, g *Gate, username, password string) {
	t.Helper()
	if _, err := g.deps.Users.Register(username, password, nowUTC()); err != nil {
		t.Fatal(err)
	}
}

func nowUTC() time.Time { return time.Now() }

func bearerRequest(t *testing.T, ts string, path, raw string) *http.Response {
	t.Helper()
	return bearerRequestMethod(t, http.MethodGet, ts, path, raw)
}

// bearerRequestMethod is bearerRequest with an explicit method -- added
// because proving the bearer branch is tried before the CSRF check
// needs a POST, and bearerRequest's method was hard-coded to GET, which
// is always a safe method and so never reaches that check at all.
func bearerRequestMethod(t *testing.T, method, ts, path, raw string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, ts+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestBearerTokenDispatchesToItsRegisteredKind(t *testing.T) {
	g := newTestGate(t)
	registerUserDirect(t, g, "admin", "password123")
	raw, _, err := g.deps.Tokens.Create("integration", gauntlet.TokenKindAPI, "", nil, nowUTC())
	if err != nil {
		t.Fatalf("Tokens.Create: %v", err)
	}
	g.Handle(gauntlet.TokenKindAPI, kindEchoHandler("/api/readonly"))
	ts := newTestServer(t, g)

	resp := bearerRequest(t, ts.URL, "/api/readonly", raw)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "integration" {
		t.Errorf("expected the dispatched handler to see the token in context, got body %q", body)
	}
}

// TestBearerTokenNeverReachesNext pins the structural guarantee: a
// valid token dispatched to its kind's handler cannot fall through to
// next (the ordinary session-gated application mux) just because its
// own mux has no route for the path asked for.
func TestBearerTokenNeverReachesNext(t *testing.T) {
	g := newTestGate(t)
	registerUserDirect(t, g, "admin", "password123")
	raw, _, err := g.deps.Tokens.Create("integration", gauntlet.TokenKindAPI, "", nil, nowUTC())
	if err != nil {
		t.Fatalf("Tokens.Create: %v", err)
	}
	// Registered mux has no route for /api/protected at all.
	g.Handle(gauntlet.TokenKindAPI, kindEchoHandler("/api/readonly"))
	ts := newTestServer(t, g)

	resp := bearerRequest(t, ts.URL, "/api/protected", raw)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 (the kind's own mux has no such route, and next must never run), got %d", resp.StatusCode)
	}
}

// TestBearerTokenCannotReachAdminRoutes: a valid API token dispatched to
// its own mux cannot reach gate's own admin-only routes either -- they
// are registered on next's mux (via Routes()), not on the kind's mux.
func TestBearerTokenCannotReachAdminRoutes(t *testing.T) {
	g := newTestGate(t)
	registerUserDirect(t, g, "admin", "password123")
	raw, _, err := g.deps.Tokens.Create("integration", gauntlet.TokenKindAPI, "", nil, nowUTC())
	if err != nil {
		t.Fatalf("Tokens.Create: %v", err)
	}
	g.Handle(gauntlet.TokenKindAPI, kindEchoHandler("/api/readonly"))
	ts := newTestServer(t, g)

	resp := bearerRequest(t, ts.URL, "/api/auth/users", raw)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

// TestWrongKindTokenNeverAuthenticates: a token minted with a kind that
// was never registered with Handle authenticates against nothing --
// treated identically to an invalid or revoked one, never silently
// passed through to the session-cookie path.
func TestWrongKindTokenNeverAuthenticates(t *testing.T) {
	g := newTestGate(t)
	registerUserDirect(t, g, "admin", "password123")
	// Only TokenKindAPI is registered with Handle -- an ingest-kind
	// token exists in the store (opened with the default Kinds, which
	// include ingest) but has nowhere to dispatch to.
	raw, _, err := g.deps.Tokens.Create("router", gauntlet.TokenKindIngest, "device-1", nil, nowUTC())
	if err != nil {
		t.Fatalf("Tokens.Create: %v", err)
	}
	g.Handle(gauntlet.TokenKindAPI, kindEchoHandler("/api/readonly"))
	ts := newTestServer(t, g)

	resp := bearerRequest(t, ts.URL, "/api/readonly", raw)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for a token of an unregistered kind, got %d", resp.StatusCode)
	}
}

func TestBearerTokenInvalidValueRejected(t *testing.T) {
	g := newTestGate(t)
	registerUserDirect(t, g, "admin", "password123")
	g.Handle(gauntlet.TokenKindAPI, kindEchoHandler("/api/readonly"))
	ts := newTestServer(t, g)

	resp := bearerRequest(t, ts.URL, "/api/readonly", "not-a-real-token")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for an invalid token value, got %d", resp.StatusCode)
	}
}

func TestBearerTokenRevokedRejected(t *testing.T) {
	g := newTestGate(t)
	registerUserDirect(t, g, "admin", "password123")
	raw, tok, err := g.deps.Tokens.Create("integration", gauntlet.TokenKindAPI, "", nil, nowUTC())
	if err != nil {
		t.Fatalf("Tokens.Create: %v", err)
	}
	if err := g.deps.Tokens.Revoke(tok.ID); err != nil {
		t.Fatal(err)
	}
	g.Handle(gauntlet.TokenKindAPI, kindEchoHandler("/api/readonly"))
	ts := newTestServer(t, g)

	resp := bearerRequest(t, ts.URL, "/api/readonly", raw)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for a revoked token, got %d", resp.StatusCode)
	}
}

// TestBearerSchemeMatchedCaseInsensitively pins RFC 7235 §2.1: the
// auth-scheme token is case-insensitive, so "bearer <token>" is bearer
// authentication too, not "no token" silently falling through to the
// session-cookie path.
func TestBearerSchemeMatchedCaseInsensitively(t *testing.T) {
	g := newTestGate(t)
	registerUserDirect(t, g, "admin", "password123")
	raw, _, err := g.deps.Tokens.Create("integration", gauntlet.TokenKindAPI, "", nil, nowUTC())
	if err != nil {
		t.Fatalf("Tokens.Create: %v", err)
	}
	g.Handle(gauntlet.TokenKindAPI, kindEchoHandler("/api/readonly"))
	ts := newTestServer(t, g)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/readonly", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "bearer "+raw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("a lower-case \"bearer\" scheme got %d, want 200", resp.StatusCode)
	}
}

// TestBearerTokenKindOrderMatchesHandleRegistration: with two kinds
// registered, a token of the second-registered kind still authenticates
// -- Protect tries every registered kind, not just the first.
func TestBearerTokenKindOrderMatchesHandleRegistration(t *testing.T) {
	g := newTestGate(t)
	registerUserDirect(t, g, "admin", "password123")
	raw, _, err := g.deps.Tokens.Create("router", gauntlet.TokenKindIngest, "device-1", nil, nowUTC())
	if err != nil {
		t.Fatalf("Tokens.Create: %v", err)
	}
	// API registered first, ingest second -- the raw value is an
	// ingest-kind token, so this only passes if the loop keeps trying
	// after TokenKindAPI's Authenticate call fails to match it.
	g.Handle(gauntlet.TokenKindAPI, kindEchoHandler("/api/readonly"))
	g.Handle(gauntlet.TokenKindIngest, kindEchoHandler("/api/ingest"))
	ts := newTestServer(t, g)

	resp := bearerRequest(t, ts.URL, "/api/ingest", raw)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 dispatching to the ingest kind's handler, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "router" {
		t.Errorf("expected the ingest handler to see the token, got body %q", body)
	}

	// And the ingest token must not reach the API kind's own mux.
	crossResp := bearerRequest(t, ts.URL, "/api/readonly", raw)
	defer func() { _ = crossResp.Body.Close() }()
	if crossResp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for an ingest token presented at the API kind's mux, got %d", crossResp.StatusCode)
	}
}

// TestBearerTokenPOSTBypassesCSRF pins docs/design.md's claim that
// bearer requests bypass CSRF because no cookie is involved (line
// ~567) -- the rest of this file only ever sends GET, an always-safe
// method that would pass the CSRF check anyway, so it never actually
// exercised the bypass. A POST with a valid Bearer token and no
// X-Requested-With header must still reach its kind's handler, and the
// same POST with no Bearer token must be refused by the CSRF check.
func TestBearerTokenPOSTBypassesCSRF(t *testing.T) {
	g := newTestGate(t)
	registerUserDirect(t, g, "admin", "password123")
	raw, _, err := g.deps.Tokens.Create("integration", gauntlet.TokenKindAPI, "", nil, nowUTC())
	if err != nil {
		t.Fatalf("Tokens.Create: %v", err)
	}
	g.Handle(gauntlet.TokenKindAPI, kindEchoHandlerAnyMethod("/api/readonly"))
	ts := newTestServer(t, g)

	resp := bearerRequestMethod(t, http.MethodPost, ts.URL, "/api/readonly", raw)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST with a valid Bearer token and no X-Requested-With: expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "integration" {
		t.Errorf("expected the dispatched handler to see the token, got body %q", body)
	}

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	csrfResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = csrfResp.Body.Close() }()
	if csrfResp.StatusCode != http.StatusForbidden {
		t.Errorf("POST with no Bearer token and no X-Requested-With: expected 403 from the CSRF check, got %d", csrfResp.StatusCode)
	}
}

// TestBearerTokenPOSTBodyReachesKindHandler: every other test here
// sends no body, so none would notice Protect's bearer branch reading
// or dropping one on the way to the kind's handler. A POST carrying
// JSON must arrive intact, next to its token. The CSRF header is sent
// so this pins the body alone -- the bypass is
// TestBearerTokenPOSTBypassesCSRF's.
func TestBearerTokenPOSTBodyReachesKindHandler(t *testing.T) {
	g := newTestGate(t)
	registerUserDirect(t, g, "admin", "password123")
	raw, _, err := g.deps.Tokens.Create("router", gauntlet.TokenKindIngest, "device-1", nil, nowUTC())
	if err != nil {
		t.Fatalf("Tokens.Create: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/ingest", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Reading string `json:"reading"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "body did not decode: "+err.Error(), http.StatusBadRequest)
			return
		}
		tok := TokenFromContext(r)
		if tok == nil {
			http.Error(w, "no token in context", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(tok.Name + ":" + body.Reading))
	})
	g.Handle(gauntlet.TokenKindIngest, mux)
	ts := newTestServer(t, g)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/ingest", strings.NewReader(`{"reading":"42.5"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+raw)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrfHeaderName, testCSRFValue)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST with a JSON body under a valid Bearer token: got %d (%s), want 200", resp.StatusCode, body)
	}
	if string(body) != "router:42.5" {
		t.Errorf("expected the kind handler to see the token and the body, got %q", body)
	}
}
