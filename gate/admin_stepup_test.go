// The admin routes that take over, remove or hand out access to an
// account ask for the calling admin's own password (#72, ASVS 7.5.3).
package gate

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// stepUpRoute is one of the five routes: send makes the request with
// body as its JSON body, and effect reports whether it took effect.
type stepUpRoute struct {
	name   string
	send   func(t *testing.T, ts *httptest.Server, admin *http.Client, id string, body any) *http.Response
	effect func(g *Gate, id string) bool
}

func stepUpRoutes() []stepUpRoute {
	return []stepUpRoute{
		{
			name: "reset-password",
			send: func(t *testing.T, ts *httptest.Server, admin *http.Client, id string, body any) *http.Response {
				return postJSON(t, admin, ts.URL+"/api/auth/users/"+id+"/reset-password", body)
			},
			effect: func(g *Gate, id string) bool {
				u, ok := g.deps.Users.Get(id)
				return ok && !u.ResetCodeExpiresAt.IsZero()
			},
		},
		{
			name: "create token",
			send: func(t *testing.T, ts *httptest.Server, admin *http.Client, _ string, body any) *http.Response {
				// The route's own body, with only the password varying.
				req := createTokenRequest{Name: "ci"}
				if b, ok := body.(adminStepUpRequest); ok {
					req.Password = b.Password
				}
				return postJSON(t, admin, ts.URL+"/api/tokens", req)
			},
			effect: func(g *Gate, _ string) bool { return len(g.deps.Tokens.List()) > 0 },
		},
		{
			name: "delete user",
			send: func(t *testing.T, ts *httptest.Server, admin *http.Client, id string, body any) *http.Response {
				return deleteJSON(t, admin, ts.URL+"/api/auth/users/"+id, body)
			},
			effect: func(g *Gate, id string) bool { _, ok := g.deps.Users.Get(id); return !ok },
		},
		{
			name: "clear authenticator app",
			send: func(t *testing.T, ts *httptest.Server, admin *http.Client, id string, body any) *http.Response {
				return deleteJSON(t, admin, ts.URL+"/api/auth/users/"+id+"/totp", body)
			},
			// Nothing to see on an account with no app; the 200 is the signal.
			effect: func(*Gate, string) bool { return false },
		},
		{
			name: "clear passkeys",
			send: func(t *testing.T, ts *httptest.Server, admin *http.Client, id string, body any) *http.Response {
				return deleteJSON(t, admin, ts.URL+"/api/auth/users/"+id+"/passkeys", body)
			},
			effect: func(g *Gate, id string) bool { return g.deps.Users.PasskeyCount(id) == 0 },
		},
	}
}

// stepUpFixture is an admin and "bilbo" holding one passkey, the target
// of every route above.
func stepUpFixture(t *testing.T) (*Gate, *httptest.Server, *http.Client, string) {
	t.Helper()
	g, ts, admin := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	registerPasskey(t, bilbo, ts, g, "key")
	return g, ts, admin, passkeyBilboID(t, g)
}

func TestAdminRoutesNeedTheCallersPassword(t *testing.T) {
	for _, route := range stepUpRoutes() {
		t.Run(route.name+"/no password", func(t *testing.T) {
			g, ts, admin, id := stepUpFixture(t)
			wantProblem(t, route.send(t, ts, admin, id, adminStepUpRequest{}), http.StatusUnauthorized, classInvalidCredentials)
			if route.name != "clear authenticator app" && route.effect(g, id) {
				t.Error("the request took effect with no password")
			}
		})
		t.Run(route.name+"/wrong password", func(t *testing.T) {
			g, ts, admin, id := stepUpFixture(t)
			wantProblem(t, route.send(t, ts, admin, id, adminStepUpRequest{Password: "not-the-password"}), http.StatusUnauthorized, classInvalidCredentials)
			if route.name != "clear authenticator app" && route.effect(g, id) {
				t.Error("the request took effect with a wrong password")
			}
			if entry := findAuditEntry(t, g, "user.login_failed"); entry.Target != "admin" {
				t.Errorf("user.login_failed entry = %+v, want one for the admin", entry)
			}
		})
		t.Run(route.name+"/right password", func(t *testing.T) {
			g, ts, admin, id := stepUpFixture(t)
			resp := route.send(t, ts, admin, id, adminStepUpRequest{Password: testAdminPassword})
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
				t.Fatalf("status = %d, want success", resp.StatusCode)
			}
			if route.name != "clear authenticator app" && !route.effect(g, id) {
				t.Error("the request did not take effect with the right password")
			}
		})
		// A wrong guess counts on the account's re-check budget, so a run
		// of them shuts out even the right password -- the routes are not a
		// password oracle behind a stolen cookie.
		t.Run(route.name+"/counted", func(t *testing.T) {
			g, ts, admin, id := stepUpFixture(t)
			g.deps.Limiter = mustNewLoginLimiter(t, 2, time.Minute)
			for range 2 {
				_ = route.send(t, ts, admin, id, adminStepUpRequest{Password: "wrong"}).Body.Close()
			}
			wantProblem(t, route.send(t, ts, admin, id, adminStepUpRequest{Password: testAdminPassword}), http.StatusTooManyRequests, classRateLimited)
			if route.name != "clear authenticator app" && route.effect(g, id) {
				t.Error("the request took effect after the budget was spent")
			}
		})
	}
}

// A body that is not the route's JSON is a 400 before any password is
// checked, as on the self-service re-check routes.
func TestAdminRoutesRefuseAnUnreadableBody(t *testing.T) {
	_, ts, admin, id := stepUpFixture(t)
	for _, route := range stepUpRoutes() {
		if route.name == "create token" {
			continue // covered by badinput_test.go
		}
		wantProblem(t, route.send(t, ts, admin, id, "not an object"), http.StatusBadRequest, classInvalidRequest)
	}
}

// A request that reaches the check with no account in its context --
// not possible through Protect and adminOnly -- is refused, not waved
// through.
func TestRecheckAdminPasswordRefusesWithNoCaller(t *testing.T) {
	g := newTestGate(t)
	rec := httptest.NewRecorder()
	if g.recheckAdminPassword(rec, httptest.NewRequest(http.MethodPost, "/", nil), "anything", time.Now()) {
		t.Fatal("recheckAdminPassword passed with no caller in context")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// An SSO-only admin has no password to re-enter: every step-up route
// answers 409 telling it to set one, and none of those requests spends
// its re-check budget, however many there are.
func TestStepUpRoutesTellAnSSOOnlyAdminToSetAPassword(t *testing.T) {
	g, ts, _, bilboID := stepUpFixture(t)
	id, admin := ssoOnlyAdmin(t, g, ts, "subject-ann")

	routes := stepUpRoutes()
	routes = append(routes,
		stepUpRoute{
			name: "create admin",
			send: func(t *testing.T, ts *httptest.Server, admin *http.Client, _ string, _ any) *http.Response {
				return postJSON(t, admin, ts.URL+"/api/auth/users", createUserRequest{
					Username: "sam", Password: "password-placeholder-9", Role: "admin",
					AdminPassword: "anything-at-all", AdminCode: "123456",
				})
			},
			effect: func(g *Gate, _ string) bool { _, ok := g.deps.Users.ByUsername("sam"); return ok },
		},
		stepUpRoute{
			name: "grant admin",
			send: func(t *testing.T, ts *httptest.Server, admin *http.Client, id string, _ any) *http.Response {
				return doJSON(t, admin, http.MethodPut, ts.URL+"/api/auth/users/"+id+"/role",
					setRoleRequest{Role: "admin", Password: "anything-at-all", Code: "123456"})
			},
			effect: func(g *Gate, id string) bool {
				u, ok := g.deps.Users.Get(id)
				return ok && u.Role == gauntlet.RoleAdmin
			},
		},
	)
	for _, route := range routes {
		for range 2 {
			resp := route.send(t, ts, admin, bilboID, adminStepUpRequest{Password: "anything-at-all"})
			status, body := readAll(t, resp)
			if status != http.StatusConflict || !strings.Contains(body, "local password") {
				t.Errorf("%s by an SSO-only admin = %d %s, want 409 naming the local password", route.name, status, body)
			}
		}
		if route.effect(g, bilboID) {
			t.Errorf("%s took effect for an SSO-only admin", route.name)
		}
	}

	// Fourteen refusals, and the whole budget is still there.
	for i := range 5 {
		if !g.deps.Limiter.ReserveRecheck(id, time.Now()) {
			t.Fatalf("re-check reservation %d refused: the 409s spent the budget", i+1)
		}
	}
}
