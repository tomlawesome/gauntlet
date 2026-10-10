package gate

import (
	"net/http"
	"testing"
)

// v0.4.1 (P1-Q3): a username holding an invisible formatting character
// is refused at account creation with 400 invalid-request, and the
// detail names invisible characters.

const v041UsernameDetail = "that username contains characters that aren't allowed -- no control characters, no invisible formatting characters such as zero-width spaces, and no leading or trailing spaces"

func TestV041AdminCreateRefusesInvisibleCharactersInUsername(t *testing.T) {
	cases := []struct{ name, username string }{
		{"zero-width space", "ali​ce"},
		{"line separator", "ali ce"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newTestGate(t)
			ts := newTestServer(t, g)
			admin := registerAdmin(t, ts, "admin", testAdminPassword)

			status, raw := readAll(t, postJSON(t, admin, ts.URL+"/api/auth/users",
				createUserRequest{Username: tc.username, Password: totpBobPassword, Role: "user"}))
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", status, raw)
			}
			p := decodeProblem(t, []byte(raw))
			if p.Type != problemTypeBase+"invalid-request" {
				t.Errorf("problem type = %q, want class invalid-request", p.Type)
			}
			if p.Detail != v041UsernameDetail {
				t.Errorf("detail = %q, want %q", p.Detail, v041UsernameDetail)
			}
			if _, ok := g.deps.Users.ByUsername(tc.username); ok {
				t.Error("the refused account was created anyway")
			}
		})
	}
}

func TestV041AdminCreateAcceptsPlainUsernameOfTheSameLength(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", testAdminPassword)

	// "ali​ce" is six characters; "alicea" is a plain name of that length.
	status, raw := readAll(t, postJSON(t, admin, ts.URL+"/api/auth/users",
		createUserRequest{Username: "alicea", Password: totpBobPassword, Role: "user"}))
	if status != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", status, raw)
	}
	if _, ok := g.deps.Users.ByUsername("alicea"); !ok {
		t.Error("the plain account was not created")
	}
}

func TestV041FirstRunRegisterRefusesInvisibleCharactersInUsername(t *testing.T) {
	cases := []struct{ name, username string }{
		{"zero-width space", "ali​ce"},
		{"line separator", "ali ce"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newTestGate(t)
			ts := newTestServer(t, g)
			client := &http.Client{Jar: mustCookieJar(t)}

			status, raw := readAll(t, postJSON(t, client, ts.URL+"/api/auth/register",
				registerRequest{Username: tc.username, Password: testAdminPassword, SetupCode: setupCodeFor(t, g)}))
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", status, raw)
			}
			p := decodeProblem(t, []byte(raw))
			if p.Type != problemTypeBase+"invalid-request" {
				t.Errorf("problem type = %q, want class invalid-request", p.Type)
			}
			if p.Detail != v041UsernameDetail {
				t.Errorf("detail = %q, want %q", p.Detail, v041UsernameDetail)
			}
		})
	}
}

func TestV041FirstRunRegisterAcceptsPlainUsernameOfTheSameLength(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := &http.Client{Jar: mustCookieJar(t)}

	status, raw := readAll(t, postJSON(t, client, ts.URL+"/api/auth/register",
		registerRequest{Username: "alicea", Password: testAdminPassword, SetupCode: setupCodeFor(t, g)}))
	if status != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", status, raw)
	}
}
