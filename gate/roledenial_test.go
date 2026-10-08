// Regression tests for issue #14: docs/design.md §4's fail-closed list
// says "Unknown role → denied everything", but until this fix Protect
// only checked a caller's role at RequireRole-wrapped routes -- an
// ordinary session-gated route with no role requirement at all (most
// of an application's own routes, mikroview's /api/events among them)
// let an unknown-role account straight through, because
// Role.AtLeast(RoleViewer) or lower is never checked outside RequireRole.
//
// The only way a live User ever carries an unrecognized Role is a
// document written outside this package (user.go's own doc comment on
// Role.rank -- "a hand-edited accounts file") -- so these tests build
// exactly that: a persist.Memory document with a role no CreateUser/
// Register call could ever produce, opened as an ordinary Store.
package gate

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/persist"
)

// bogusRoleFixture opens a Store over a hand-written document holding
// one user with an unrecognized role, and returns a Gate/server built
// over it plus a session cookie for that account -- the same "written
// outside this package" scenario user.go's own doc comment describes,
// reached here through persist.Memory.Save directly rather than any
// Store method, since none of them can produce this role.
func bogusRoleFixture(t *testing.T) (*Gate, *httptest.Server, *http.Cookie) {
	t.Helper()
	hash, err := gauntlet.HashPassword("bogus-role-fixture-password")
	if err != nil {
		t.Fatal(err)
	}
	// An admin account rides along only so OpenStore accepts the
	// document at all: one holding accounts but no admin is refused
	// before any role is looked at.
	users := openStoreWithUsers(t, gauntlet.User{
		ID:               "bogus-role-user",
		Username:         "roguerole",
		PasswordHash:     hash,
		Role:             gauntlet.Role("bogus"),
		CreatedAt:        time.Now(),
		HasLocalPassword: true,
	}, gauntlet.User{
		ID:               "fixture-admin",
		Username:         "fixtureadmin",
		PasswordHash:     hash,
		Role:             gauntlet.RoleAdmin,
		CreatedAt:        time.Now(),
		HasLocalPassword: true,
	})
	tokens, err := gauntlet.OpenTokenStore(persist.NewMemory(), gauntlet.TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sessions := gauntlet.NewSessionStore(gauntlet.MaxSessionIdle, gauntlet.MaxSessionLifetime)
	limiter := mustNewLoginLimiter(t, 5, time.Minute)
	g, err := New(Config{
		CookieName:      testCookieName,
		CSRFHeaderValue: testCSRFValue,
		ClientIP:        func(r *http.Request) string { return "198.51.100.1" },
		ProductName:     testProductName,
		AdminPasskey:    AdminPasskeyOptional,
	}, Deps{Users: users, Sessions: sessions, Tokens: tokens, Limiter: limiter})
	if err != nil {
		t.Fatal(err)
	}
	ts := newTestServer(t, g)

	sess := sessions.Create("bogus-role-user", time.Now())
	cookie := &http.Cookie{Name: testCookieName, Value: sess.ID}
	return g, ts, cookie
}

// TestUnknownRoleDeniedOnAnOrdinaryProtectedRoute pins the fail-closed
// list's "denied everything": a plain session-gated route with no role
// requirement at all must still refuse an unknown-role session.
func TestUnknownRoleDeniedOnAnOrdinaryProtectedRoute(t *testing.T) {
	_, ts, cookie := bogusRoleFixture(t)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("an unknown-role session on a plain protected route got %d, want 403", resp.StatusCode)
	}
}

// TestUnknownRoleDeniedOnARoleGatedRoute is the RequireRole-wrapped
// sibling of the test above -- refused for the same underlying reason,
// pinned separately so a future change to either check independently
// cannot silently narrow this to "only the ungated routes."
func TestUnknownRoleDeniedOnARoleGatedRoute(t *testing.T) {
	_, ts, cookie := bogusRoleFixture(t)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/auth/users", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("an unknown-role session on an admin-only route got %d, want 403", resp.StatusCode)
	}
}

// TestRequireRolePanicsOnUnrecognizedMin covers the construction-time
// half of issue #14: a caller wiring RequireRole with a role that is
// not admin/user/viewer is a wiring mistake this package can catch
// immediately, at startup, rather than admit silently on every request
// forever after.
func TestRequireRolePanicsOnUnrecognizedMin(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected RequireRole to panic on an unrecognized min role")
		}
	}()
	RequireRole(gauntlet.Role("bogus"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
}
