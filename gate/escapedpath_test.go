// Regression tests for issue #13: Protect compared the DECODED
// r.URL.Path against its exempt/bootstrap/door path sets, but
// http.ServeMux matches the ESCAPED path per segment (confirmed against
// the stdlib: a request for "/api/auth%2Fsession" matches a registered
// "GET /api/{resource}" pattern, never "GET /api/auth/session", because
// %2F stays inside one path segment rather than splitting it in two).
// So a path that is exempt only after *decoding* -- "/api/auth%2Fsession"
// decodes to "/api/auth/session" -- was treated as exempt by Protect,
// while the actual mux dispatched it to whatever pattern matches its
// single real segment, bypassing whichever door the decoded form was
// supposed to satisfy.
//
// Each case below registers a generic catch-all route, the same shape
// an application's own resource routes take (mikroview has none, but a
// consuming application very plausibly does, and gate cannot assume
// otherwise), to make the bypass's actual effect observable: a request
// Protect believes it is exempting for a specific, narrow reason
// instead reaches a handler that has nothing to do with that reason.
package gate

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newEscapedPathTestServer is newTestServer's sibling for this file's
// tests: g.Routes() mounted at "/" (the least specific pattern, exactly
// as a real application mounts it), plus a generic single-segment
// catch-all -- "GET/POST /api/{resource}" -- standing in for an
// application's own resource routes, registered directly on the same
// top-level mux rather than under an "/api/" prefix, so it only shadows
// a *one-segment* resource path (e.g. "/api/tokens") and never a real
// two-or-more-segment gate route ("/api/auth/register" is three
// segments, so it always reaches g.Routes() regardless of this catch-
// all). None of this file's cases touch a one-segment gate route.
func newEscapedPathTestServer(t *testing.T, g *Gate) *httptest.Server {
	t.Helper()
	appMux := http.NewServeMux()
	appMux.HandleFunc("GET /api/{resource}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	appMux.HandleFunc("POST /api/{resource}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	appMux.Handle("/", g.Routes())
	ts := httptest.NewServer(g.Protect(appMux))
	testServerGates.Store(ts, g)
	t.Cleanup(ts.Close)
	return ts
}

// TestEncodedPathDoesNotBypassBootstrapGate: before an account exists,
// only bootstrapExemptPaths may be reached -- an encoded path that only
// *decodes* to one of them must still be refused.
func TestEncodedPathDoesNotBypassBootstrapGate(t *testing.T) {
	g := newTestGate(t)
	ts := newEscapedPathTestServer(t, g)

	resp, err := http.Get(ts.URL + "/api/auth%2Fsession")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("GET /api/auth%%2Fsession while undecided got %d, want 503 (setup required) -- "+
			"a 200 here means the encoded path reached the generic catch-all instead of being refused", resp.StatusCode)
	}
}

// TestEncodedPathDoesNotBypassSessionGate: once an account exists, an
// encoded path that decodes to an exempt one (e.g. /api/auth/session)
// must still require a session -- it must not reach next unauthenticated
// just because its decoded form matches exemptPaths.
func TestEncodedPathDoesNotBypassSessionGate(t *testing.T) {
	g := newTestGate(t)
	ts := newEscapedPathTestServer(t, g)
	registerAdmin(t, ts, "admin", "password123").Jar = nil

	resp, err := http.Get(ts.URL + "/api/auth%2Fsession")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/auth%%2Fsession with no session got %d, want 401 -- "+
			"a 200 here means the encoded path reached the generic catch-all unauthenticated", resp.StatusCode)
	}
}

// TestEncodedPathDoesNotEscapeMustChangePasswordDoor: a session stuck at
// the MustChangePassword door may reach exactly changePasswordPath and
// nothing else -- an encoded request that only *decodes* to that path
// must still be refused by the door, not quietly dispatched to whatever
// the mux actually matches its real (undecoded) segments against.
func TestEncodedPathDoesNotEscapeMustChangePasswordDoor(t *testing.T) {
	g := newTestGate(t)
	ts := newEscapedPathTestServer(t, g)
	registerAdmin(t, ts, "admin", "password123")

	u, ok := g.deps.Users.ByUsername("admin")
	if !ok {
		t.Fatal("admin account missing")
	}
	// IssueResetCode is what actually sets MustChangePassword, and it
	// bumps PasswordChangedAt -- which invalidates the session
	// registerAdmin's own login just issued, so a fresh sign-in with
	// the code (Store.Authenticate accepts a live one in place of the
	// password) is what carries a session that is actually still stuck
	// at this door, rather than merely revoked.
	_, code, err := g.deps.Users.IssueResetCode(u.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: mustCookieJar(t)}
	loginResp := postJSON(t, client, ts.URL+"/api/auth/login", credentialsRequest{Username: "admin", Password: code})
	_ = loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("signing in with the reset code returned %d, want 200", loginResp.StatusCode)
	}

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth%2Fpassword", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(csrfHeaderName, testCSRFValue)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST /api/auth%%2Fpassword while MustChangePassword got %d, want 403 -- "+
			"a 200 here means the door was escaped via the encoded path", resp.StatusCode)
	}
	if got := resp.Header.Get(authGateHeader); got != authGateMustChangePassword {
		t.Errorf("%s header = %q, want %q", authGateHeader, got, authGateMustChangePassword)
	}
}
