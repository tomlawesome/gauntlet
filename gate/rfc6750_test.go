// Conformance tests for bearer tokens against RFC 6750 (#35). Where
// gate deliberately differs from the RFC the test pins what gate does,
// and docs/security-by-design.md ("Standards conformance") records why.
package gate

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/tomlawesome/gauntlet"
)

// bearerChallenge is the WWW-Authenticate value every 401 carries, the
// one docs/api/auth.yaml fixes.
const bearerChallenge = `Bearer realm="gate"`

// rfc6750Fixture is a gate with the API kind's handler registered at
// /api/readonly (any method), a signed-in admin client, and a valid API
// token's raw value.
func rfc6750Fixture(t *testing.T) (*Gate, string, *http.Client, string) {
	t.Helper()
	g := newTestGate(t)
	g.Handle(gauntlet.TokenKindAPI, kindEchoHandlerAnyMethod("/api/readonly"))
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")
	raw, _, err := g.deps.Tokens.Create("integration", gauntlet.TokenKindAPI, "", nil, nowUTC())
	if err != nil {
		t.Fatalf("Tokens.Create: %v", err)
	}
	return g, ts.URL, admin, raw
}

// sendAuthorization sends GET base+path through client with the given
// Authorization header ("" sends none) and returns the status, the
// WWW-Authenticate header and the body.
func sendAuthorization(t *testing.T, client *http.Client, base, path, authorization string) (int, string, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("WWW-Authenticate"), string(body)
}

// TestRFC6750AuthorizationHeaderForm: RFC 6750 §2.1's credentials are
// "Bearer" 1*SP b64token, and RFC 7235 §2.1 compares the scheme name
// case-insensitively. Gate folds case, but takes exactly one space: a
// second one is read as part of the token, which then matches nothing
// (a deviation, failing closed).
func TestRFC6750AuthorizationHeaderForm(t *testing.T) {
	_, base, _, raw := rfc6750Fixture(t)
	for _, tc := range []struct {
		header string
		want   int
	}{
		{"Bearer " + raw, http.StatusOK},
		{"bearer " + raw, http.StatusOK},
		{"BEARER " + raw, http.StatusOK},
		{"bEaReR " + raw, http.StatusOK},
		{"Bearer  " + raw, http.StatusUnauthorized},
	} {
		got, _, _ := sendAuthorization(t, http.DefaultClient, base, "/api/readonly", tc.header)
		if got != tc.want {
			t.Errorf("Authorization %q got %d, want %d", strings.Replace(tc.header, raw, "<token>", 1), got, tc.want)
		}
	}
}

// TestRFC6750InvalidTokenIsRefusedWithTheChallenge: a token that
// matches nothing -- including one that is not b64token syntax at all --
// gets 401 with gate's fixed challenge. Gate does not parse the token's
// syntax, so a malformed one is not the RFC's 400 invalid_request, and
// the challenge carries no error="invalid_token" (deviations). A valid
// session cookie on the same request must not rescue it: a request that
// presents a bearer token is judged by that token alone.
func TestRFC6750InvalidTokenIsRefusedWithTheChallenge(t *testing.T) {
	_, base, admin, _ := rfc6750Fixture(t)
	for _, token := range []string{"not-a-real-token", "has a space", `has"quote`, "=leading-equals"} {
		for name, client := range map[string]*http.Client{"no cookie": http.DefaultClient, "signed-in cookie": admin} {
			status, challenge, _ := sendAuthorization(t, client, base, "/api/protected", "Bearer "+token)
			if status != http.StatusUnauthorized || challenge != bearerChallenge {
				t.Errorf("token %q (%s): got %d with WWW-Authenticate %q, want 401 with %q",
					token, name, status, challenge, bearerChallenge)
			}
		}
	}
}

// TestMalformedAuthorizationIsRefusedNotSkipped is #41: an
// Authorization header that is present but is not a well-formed
// "Bearer <token>" is refused with the same 401 and challenge an
// unknown token gets, never ignored so that the request falls back to
// its session cookie. "Bearer " arrives as "Bearer": the server trims
// trailing spaces from a header value. Only a request with no
// Authorization header at all is judged by its cookie.
func TestMalformedAuthorizationIsRefusedNotSkipped(t *testing.T) {
	_, base, admin, _ := rfc6750Fixture(t)
	for _, header := range []string{"Bearer", "Bearer ", "Basic YWRtaW46cGFzc3dvcmQxMjM=", "Bearer\tabc"} {
		status, challenge, _ := sendAuthorization(t, admin, base, "/api/protected", header)
		if status != http.StatusUnauthorized || challenge != bearerChallenge {
			t.Errorf("Authorization %q with a signed-in cookie: got %d with WWW-Authenticate %q, want 401 with %q",
				header, status, challenge, bearerChallenge)
		}
	}
	if status, _, _ := sendAuthorization(t, admin, base, "/api/protected", ""); status != http.StatusOK {
		t.Errorf("no Authorization header with a signed-in cookie got %d, want 200", status)
	}
}

// TestRFC6750NoCredentialsGetTheChallenge: a request with no token and
// no session gets 401 with the same challenge and, as RFC 6750 §3.1
// asks of a request with no authentication information, no error code.
func TestRFC6750NoCredentialsGetTheChallenge(t *testing.T) {
	_, base, _, _ := rfc6750Fixture(t)
	status, challenge, _ := sendAuthorization(t, http.DefaultClient, base, "/api/protected", "")
	if status != http.StatusUnauthorized || challenge != bearerChallenge {
		t.Errorf("no credentials: got %d with WWW-Authenticate %q, want 401 with %q", status, challenge, bearerChallenge)
	}
}

// TestRFC6750TokenIsNotReadFromTheQueryOrBody: RFC 6750 §2.2 and §2.3
// allow a token in a form body or an access_token query parameter. Gate
// reads only the Authorization header (a deviation): a URL ends up in
// logs, history and Referer headers, and §2.3 itself says not to use it
// without good reason. A valid token sent either way is ignored, so the
// request is judged as having none.
func TestRFC6750TokenIsNotReadFromTheQueryOrBody(t *testing.T) {
	_, base, _, raw := rfc6750Fixture(t)

	status, _, body := sendAuthorization(t, http.DefaultClient, base, "/api/readonly?access_token="+url.QueryEscape(raw), "")
	if status != http.StatusUnauthorized || strings.Contains(body, "integration") {
		t.Errorf("token in the query string: got %d %q, want 401 without reaching the token's handler", status, body)
	}

	req, err := http.NewRequest(http.MethodPost, base+"/api/readonly", strings.NewReader(url.Values{"access_token": {raw}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(csrfHeaderName, testCSRFValue)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusUnauthorized || strings.Contains(string(got), "integration") {
		t.Errorf("token in a form body: got %d %q, want 401 without reaching the token's handler", resp.StatusCode, got)
	}
}
