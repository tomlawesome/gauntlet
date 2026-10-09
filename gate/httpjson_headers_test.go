package gate

import (
	"io"
	"net/http"
	"testing"
)

// Every JSON and problem response the gate writes carries the same
// headers, whichever handler wrote it (#90 item 19). The headers are
// written in more than one place; this test reads them off real
// responses, so a change that moves them into one helper cannot drop or
// add one for any kind of answer.
func TestEveryJSONAndProblemResponseCarriesTheSameHeaders(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	anon := &http.Client{}
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")

	const (
		jsonType    = "application/json; charset=utf-8"
		problemType = "application/problem+json"
		bearer      = `Bearer realm="gate"`
	)
	patch, err := http.NewRequest(http.MethodPatch, ts.URL+"/api/auth/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	patch.Header.Set(csrfHeaderName, testCSRFValue)

	cases := []struct {
		name            string
		do              func() (*http.Response, error)
		status          int
		contentType     string
		wwwAuthenticate string
	}{
		{"JSON answer to an anonymous caller", func() (*http.Response, error) { return anon.Get(ts.URL + "/api/auth/session") }, 200, jsonType, ""},
		{"JSON answer to a signed-in caller", func() (*http.Response, error) { return admin.Get(ts.URL + "/api/auth/session") }, 200, jsonType, ""},
		{"JSON list from an admin route", func() (*http.Response, error) { return admin.Get(ts.URL + "/api/auth/users") }, 200, jsonType, ""},
		{"JSON list from the tokens route", func() (*http.Response, error) { return admin.Get(ts.URL + "/api/tokens") }, 200, jsonType, ""},
		{"JSON list of sessions", func() (*http.Response, error) { return admin.Get(ts.URL + "/api/auth/sessions") }, 200, jsonType, ""},
		{"JSON answer to a first password step", func() (*http.Response, error) {
			return doJSON(t, anon, http.MethodPost, ts.URL+"/api/auth/login", map[string]any{"username": "admin", "password": "password-placeholder-1"}), nil
		}, 200, jsonType, ""},
		{"problem for an unmatched path", func() (*http.Response, error) { return admin.Get(ts.URL + "/api/auth/no-such-route") }, 404, problemType, ""},
		{"problem for a wrong method", func() (*http.Response, error) { return admin.Do(patch) }, 405, problemType, ""},
		{"problem for a wrong password", func() (*http.Response, error) {
			return doJSON(t, anon, http.MethodPost, ts.URL+"/api/auth/login", map[string]any{"username": "admin", "password": "wrong-password-1"}), nil
		}, 401, problemType, bearer},
		{"problem for a missing sign-in", func() (*http.Response, error) {
			return doJSON(t, anon, http.MethodPost, ts.URL+"/api/auth/logout-all", map[string]any{}), nil
		}, 401, problemType, bearer},
		// Last: it ends the admin's session.
		{"JSON answer that sets a cookie", func() (*http.Response, error) {
			return doJSON(t, admin, http.MethodPost, ts.URL+"/api/auth/logout", map[string]any{}), nil
		}, 200, jsonType, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, err := c.do()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.Copy(io.Discard, resp.Body)

			if resp.StatusCode != c.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, c.status)
			}
			if got := resp.Header.Get("Content-Type"); got != c.contentType {
				t.Errorf("Content-Type = %q, want %q", got, c.contentType)
			}
			if got := resp.Header.Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
			if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
			}
			if got := resp.Header.Get("WWW-Authenticate"); got != c.wwwAuthenticate {
				t.Errorf("WWW-Authenticate = %q, want %q", got, c.wwwAuthenticate)
			}
			if got := resp.Header.Values("Cache-Control"); len(got) != 1 {
				t.Errorf("Cache-Control sent %d times: %q", len(got), got)
			}
		})
	}
}
