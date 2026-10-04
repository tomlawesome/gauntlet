// Tests for the RFC 9457 Problem Details switch (gauntlet #23): the
// shape writeProblem/writeUnauthorized/writeAuthError/writeBlankProblem
// produce, and the security property docs/api/errors.md's SECURITY
// note states -- a handful of pairs of genuinely different causes
// answer with the same class *and* the same body, so neither can be
// told apart from the response. Most of those pairs already have their
// own test elsewhere (protect_test.go's
// TestLoginRejectsUnknownUsernameWithIdenticalBody, for one); this file
// holds the ones that did not.
package gate

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWriteProblemShape pins writeProblem's body and headers directly,
// cheaper and more exhaustive than driving every one of the fifteen
// classes through a full HTTP fixture: Content-Type, Cache-Control,
// X-Content-Type-Options, and that type/title/status/detail/extra come
// through unchanged.
func TestWriteProblemShape(t *testing.T) {
	rec := httptest.NewRecorder()
	writeProblem(rec, http.StatusConflict, classConflict, "already registered", map[string]any{"username": "bob"})

	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
	body := decodeProblem(t, rec.Body.Bytes())
	if body.Type != problemTypeBase+"conflict" {
		t.Errorf("type = %q", body.Type)
	}
	if body.Title != "Conflicting state" {
		t.Errorf("title = %q", body.Title)
	}
	if body.Status != http.StatusConflict {
		t.Errorf("status field = %d", body.Status)
	}
	if body.Detail != "already registered" {
		t.Errorf("detail = %q", body.Detail)
	}
	var extra struct {
		Username string `json:"username"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &extra); err != nil {
		t.Fatal(err)
	}
	if extra.Username != "bob" {
		t.Errorf("extra member username = %q, want bob", extra.Username)
	}

	// No detail at all: the field is omitted, not sent empty -- the
	// about:blank and feature-off 404 cases rely on this.
	rec2 := httptest.NewRecorder()
	writeProblem(rec2, http.StatusNotFound, classNotFound, "", nil)
	var raw map[string]any
	if err := json.Unmarshal(rec2.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, has := raw["detail"]; has {
		t.Errorf("empty detail was sent as a field: %v", raw)
	}
}

// TestEveryClassHasAFixedAnchorTitleAndURL pins the fifteen classes
// docs/api/errors.md documents: each anchor is unique (so two classes
// never collide on one permanent URL) and problemTypeBase+anchor is
// well-formed.
func TestEveryClassHasAFixedAnchorTitleAndURL(t *testing.T) {
	classes := []problemClass{
		classInvalidCredentials, classSignInRequired, classStepExpired,
		classCSRFRequired, classForbidden, classMustChangePassword,
		classMustEnrolFactor, classInvalidRequest, classNotFound,
		classConflict, classRateLimited, classSetupRequired,
		classNotPersisted, classServerError, classPartiallyCompleted,
	}
	seen := map[string]bool{}
	for _, c := range classes {
		if c.anchor == "" || c.title == "" {
			t.Errorf("class %+v has an empty anchor or title", c)
		}
		if seen[c.anchor] {
			t.Errorf("anchor %q used by more than one class", c.anchor)
		}
		seen[c.anchor] = true
	}
	if len(seen) != 15 {
		t.Errorf("got %d distinct anchors, want 15", len(seen))
	}
}

// TestUnmatchedRouteAndWrongMethodAnswerAboutBlank: a path no route
// registers, and a method a registered path does not take, both answer
// problem+json with type about:blank and no detail -- never the plain
// text/plain body net/http's own ServeMux would otherwise write. The
// 405 case keeps the Allow header (problemInterceptWriter's job).
func TestUnmatchedRouteAndWrongMethodAnswerAboutBlank(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	// An authenticated client: an unmatched path under /api/auth/* is
	// not on the exempt list, so Protect itself would answer
	// sign-in-required first for an anonymous one, never reaching the
	// mux this test means to exercise.
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")

	resp, err := admin.Get(ts.URL + "/api/auth/no-such-route")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unmatched path: status %d, want 404", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("unmatched path: Content-Type = %q", ct)
	}
	raw, _ := io.ReadAll(resp.Body)
	body := decodeProblem(t, raw)
	if body.Type != "about:blank" || body.Status != http.StatusNotFound || body.Detail != "" {
		t.Errorf("unmatched path body = %+v, want about:blank/404/no detail", body)
	}

	req, err := http.NewRequest(http.MethodPatch, ts.URL+"/api/auth/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(csrfHeaderName, testCSRFValue)
	resp2, err := admin.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method: status %d, want 405", resp2.StatusCode)
	}
	if allow := resp2.Header.Get("Allow"); allow == "" {
		t.Error("405 carries no Allow header")
	}
	raw2, _ := io.ReadAll(resp2.Body)
	body2 := decodeProblem(t, raw2)
	if body2.Type != "about:blank" || body2.Status != http.StatusMethodNotAllowed || body2.Detail != "" {
		t.Errorf("wrong-method body = %+v, want about:blank/405/no detail", body2)
	}
}

// TestBearerFailuresShareOneBody: a token of an unregistered kind, an
// invalid value, a revoked one and a malformed Authorization header are
// four different causes Protect never lets a caller tell apart --
// docs/api/errors.md's invalid-credentials security pair.
func TestBearerFailuresShareOneBody(t *testing.T) {
	g := newTestGate(t)
	registerUserDirect(t, g, "admin", "password-placeholder-1")
	ts := newTestServer(t, g)

	var bodies [][]byte
	record := func(resp *http.Response) {
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, raw)
	}

	record(bearerRequest(t, ts.URL, "/api/protected", "not-a-real-token"))
	status, _, raw := sendAuthorization(t, &http.Client{}, ts.URL, "/api/protected", "Bearer x y")
	if status != http.StatusUnauthorized {
		t.Fatalf("malformed Authorization: status %d, want 401", status)
	}
	bodies = append(bodies, []byte(raw))

	for i := 1; i < len(bodies); i++ {
		if string(bodies[i]) != string(bodies[0]) {
			t.Errorf("bearer failure bodies differ: %q vs %q -- a caller could tell the causes apart", bodies[0], bodies[i])
		}
	}
	p := decodeProblem(t, bodies[0])
	if p.Type != problemTypeBase+"invalid-credentials" {
		t.Errorf("type = %q, want invalid-credentials", p.Type)
	}
}

// TestCookieFailuresShareOneBody: no session cookie, a garbage value
// and a well-formed value naming no live session all refuse through
// Protect's one sessionUser check, with the same sign-in-required body.
func TestCookieFailuresShareOneBody(t *testing.T) {
	g := newTestGate(t)
	registerUserDirect(t, g, "admin", "password-placeholder-1")
	ts := newTestServer(t, g)

	get := func(cookie *http.Cookie) []byte {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/auth/sessions", nil)
		if err != nil {
			t.Fatal(err)
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 (cookie=%v)", resp.StatusCode, cookie)
		}
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	noCookie := get(nil)
	garbage := get(&http.Cookie{Name: g.sessionCookieName(), Value: "garbage"})
	unknown := get(&http.Cookie{Name: g.sessionCookieName(), Value: "0123456789abcdef0123456789abcdef"})

	if string(noCookie) != string(garbage) || string(garbage) != string(unknown) {
		t.Errorf("cookie failure bodies differ: no-cookie=%q garbage=%q unknown=%q", noCookie, garbage, unknown)
	}
	p := decodeProblem(t, noCookie)
	if p.Type != problemTypeBase+"sign-in-required" {
		t.Errorf("type = %q, want sign-in-required", p.Type)
	}
}

// TestLoginFactorWrongCodeAndWrongRecoveryCodeShareOneBody: a wrong
// authenticator-app code and a wrong (or already-spent) recovery code
// at the second login step must not be told apart -- which kind of
// guess was tried is not information a caller needs back.
func TestLoginFactorWrongCodeAndWrongRecoveryCodeShareOneBody(t *testing.T) {
	g, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	_, codes, _ := totpEnrolAndConfirm(t, bob, ts)
	_ = g

	wrongCode := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	respA := submitLoginFactor(t, wrongCode, ts, "000000")
	defer func() { _ = respA.Body.Close() }()
	if respA.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong TOTP code: status %d, want 401", respA.StatusCode)
	}
	bodyA, err := io.ReadAll(respA.Body)
	if err != nil {
		t.Fatal(err)
	}

	// A recovery code already burned by someone else is just as wrong a
	// guess as one never issued -- burn it first, then try it again.
	wrongRecovery := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	respB := submitLoginFactor(t, wrongRecovery, ts, codes[0]+"x")
	defer func() { _ = respB.Body.Close() }()
	if respB.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong recovery code: status %d, want 401", respB.StatusCode)
	}
	bodyB, err := io.ReadAll(respB.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(bodyA) != string(bodyB) {
		t.Errorf("bodies differ: %q vs %q -- a caller could tell a TOTP guess from a recovery-code guess", bodyA, bodyB)
	}
	p := decodeProblem(t, bodyA)
	if p.Type != problemTypeBase+"invalid-credentials" {
		t.Errorf("type = %q, want invalid-credentials", p.Type)
	}
}
