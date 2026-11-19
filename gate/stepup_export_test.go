// An application steps up its own routes with the exported
// (*Gate).StepUp and StepUpProof (#133): gauntlet's one per-request
// re-check of the caller's password and a current second factor, run
// from an application handler under Protect. These tests drive it
// through a route an application would mount, /api/admin/thing, and
// pin that the passkey ceremony cookie reaches it.
package gate

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/internal/passkeytest"
)

const stepUpAppPath = "/api/admin/thing"

// stepUpThingRequest is the application route's own JSON body: the
// exported proof, inline.
type stepUpThingRequest struct {
	StepUpProof
}

// stepUpApp is an admin holding a password, an authenticator app with
// recovery codes and a passkey, plus an application route that steps up
// and counts how often it acted.
type stepUpApp struct {
	g        *Gate
	ts       *httptest.Server
	admin    *http.Client
	adminID  string
	secret   []byte
	recovery []string
	counter  uint64
	fake     *passkeytest.FakeAuthenticator
	acted    *atomic.Int32
	rawToken string
}

// stepUpAppHandler decodes the body, calls StepUp and acts on true.
func stepUpAppHandler(g *Gate, acted *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req stepUpThingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if !g.StepUp(w, r, req.StepUpProof) {
			return
		}
		acted.Add(1)
		w.WriteHeader(http.StatusOK)
	})
}

func newStepUpApp(t *testing.T) *stepUpApp {
	t.Helper()
	g := passkeyGate(t)
	acted := &atomic.Int32{}
	h := stepUpAppHandler(g, acted)

	// The bearer-token side serves the same handler with no RequireRole
	// in front, so StepUp itself is what must refuse.
	bearerMux := http.NewServeMux()
	bearerMux.Handle("POST "+stepUpAppPath, h)
	g.Handle(gauntlet.TokenKindAPI, bearerMux)

	appMux := http.NewServeMux()
	appMux.Handle("POST "+stepUpAppPath, RequireRole(gauntlet.RoleAdmin, h))
	appMux.Handle("/", g.Routes())
	ts := httptest.NewServer(g.Protect(appMux))
	testServerGates.Store(ts, g)
	t.Cleanup(func() { testServerGates.Delete(ts); ts.Close() })

	admin := registerAdminNoFactor(t, ts, "admin", doorTestPassword)
	secret, recovery, counter := enrolAdminTOTP(t, admin, ts)
	fake := registerPasskeyWith(t, admin, ts, g, doorTestPassword)
	raw, _, err := g.deps.Tokens.Create("integration", gauntlet.TokenKindAPI, "", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return &stepUpApp{g: g, ts: ts, admin: admin, adminID: passkeyAdminID(t, g), secret: secret, recovery: recovery, counter: counter, fake: fake, acted: acted, rawToken: raw}
}

// send posts body to the application route as client.
func (a *stepUpApp) send(t *testing.T, client *http.Client, body any) *http.Response {
	t.Helper()
	return postJSON(t, client, a.ts.URL+stepUpAppPath, body)
}

// wantRefusal fails unless resp is status with the class's problem type.
func wantRefusal(t *testing.T, resp *http.Response, status int, class problemClass) problemBody {
	t.Helper()
	code, body := readAll(t, resp)
	p := decodeProblem(t, []byte(body))
	if code != status || p.Type != problemTypeBase+class.anchor {
		t.Errorf("got %d %s, want %d %s", code, body, status, class.anchor)
	}
	return p
}

func (a *stepUpApp) wantNoAction(t *testing.T) {
	t.Helper()
	if n := a.acted.Load(); n != 0 {
		t.Errorf("the application acted %d times, want 0", n)
	}
}

func (a *stepUpApp) totp(offset uint64) string {
	return gauntlet.GenerateTOTPCode(a.secret, a.counter+offset)
}

// Design test 1: no session is 401 sign-in-required.
func TestStepUpAppRouteWithNoSessionIsSignInRequired(t *testing.T) {
	a := newStepUpApp(t)
	wantRefusal(t, a.send(t, &http.Client{}, StepUpProof{Password: doorTestPassword, Code: a.totp(1)}), http.StatusUnauthorized, classSignInRequired)
	a.wantNoAction(t)
}

// Design test 2: a signed-in viewer is turned away by RequireRole
// before any step-up, so its budget is untouched.
func TestStepUpAppRouteRefusesAViewerBeforeAnyStepUp(t *testing.T) {
	a := newStepUpApp(t)
	_ = postJSON(t, a.admin, a.ts.URL+"/api/auth/users",
		createUserRequest{Username: totpBobUsername, Password: totpBobPassword, Role: "viewer"}).Body.Close()
	viewer := loggedInClient(t, a.ts, totpBobUsername, totpBobPassword)
	totpEnrolAndConfirm(t, viewer, a.ts)
	full := recheckRoom(a.g, totpBobID(t, a.g))

	wantRefusal(t, a.send(t, viewer, StepUpProof{Password: totpBobPassword, Code: "123456"}), http.StatusForbidden, classForbidden)
	a.wantNoAction(t)
	if got := recheckRoom(a.g, totpBobID(t, a.g)); got != full {
		t.Errorf("the viewer's re-check budget has %d left, want all %d", got, full)
	}
}

// Design test 3: an admin with no local password is told to set one.
func TestStepUpAppRouteTellsAnSSOOnlyAdminToSetAPassword(t *testing.T) {
	a := newStepUpApp(t)
	id, sso := ssoOnlyAdmin(t, a.g, a.ts, "subject-ann")
	full := recheckRoom(a.g, id)
	wantRefusal(t, a.send(t, sso, StepUpProof{Password: "anything-at-all", Code: "123456"}), http.StatusConflict, classConflict)
	a.wantNoAction(t)
	if got := recheckRoom(a.g, id); got != full {
		t.Errorf("the 409 left %d re-checks, want all %d", got, full)
	}
}

// Design test 4: a body missing its password, or carrying both or
// neither of code and assertion, is 400 and spends nothing.
func TestStepUpAppRouteRefusesAnIncompleteProofWithoutSpendingTheBudget(t *testing.T) {
	a := newStepUpApp(t)
	full := recheckRoom(a.g, a.adminID)
	for name, proof := range map[string]StepUpProof{
		"no password":      {Code: a.totp(1)},
		"neither factor":   {Password: doorTestPassword},
		"both factors":     {Password: doorTestPassword, Code: a.totp(1), Assertion: json.RawMessage(`{}`)},
		"empty everything": {},
	} {
		wantRefusal(t, a.send(t, a.admin, proof), http.StatusBadRequest, classInvalidRequest)
		if got := recheckRoom(a.g, a.adminID); got != full {
			t.Errorf("%s: the re-check budget has %d left, want all %d", name, got, full)
		}
	}
	a.wantNoAction(t)

	resp := a.send(t, a.admin, StepUpProof{Password: doorTestPassword, Code: a.totp(1)})
	if status, body := readAll(t, resp); status != http.StatusOK {
		t.Errorf("a correct attempt after the refusals = %d %s, want 200", status, body)
	}
}

// Design test 5: a wrong password or a wrong code is the same 401 with
// the one message, audited as a failed re-check, and nothing happens.
func TestStepUpAppRouteWrongPasswordOrCodeIsOneRefusal(t *testing.T) {
	a := newStepUpApp(t)
	for name, proof := range map[string]StepUpProof{
		"wrong password right code": {Password: "not-the-password", Code: a.totp(1)},
		"right password wrong code": {Password: doorTestPassword, Code: wrongTOTPCode(a.secret, time.Now())},
	} {
		before := stepUpAuditCount(a.g, "user.login_failed")
		p := wantRefusal(t, a.send(t, a.admin, proof), http.StatusUnauthorized, classInvalidCredentials)
		if p.Detail != "incorrect password or code" {
			t.Errorf("%s: detail = %q, want %q", name, p.Detail, "incorrect password or code")
		}
		if stepUpAuditCount(a.g, "user.login_failed") != before+1 {
			t.Errorf("%s: no user.login_failed audit entry recorded", name)
		}
		if e := findAuditEntry(t, a.g, "user.login_failed"); !strings.Contains(e.Detail, "step=recheck") {
			t.Errorf("%s: audit detail = %q, want step=recheck", name, e.Detail)
		}
	}
	a.wantNoAction(t)
}

func stepUpAuditCount(g *Gate, action string) int {
	rec := g.cfg.Audit.(*auditRecorder)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	n := 0
	for _, e := range rec.entries {
		if e.Action == action {
			n++
		}
	}
	return n
}

// Design test 6: password and a current TOTP code pass; the same code
// again is refused.
func TestStepUpAppRoutePasswordAndTOTPPassOnceOnly(t *testing.T) {
	a := newStepUpApp(t)
	proof := StepUpProof{Password: doorTestPassword, Code: a.totp(1)}
	if status, body := readAll(t, a.send(t, a.admin, proof)); status != http.StatusOK {
		t.Fatalf("password and current code = %d %s, want 200", status, body)
	}
	if n := a.acted.Load(); n != 1 {
		t.Fatalf("the application acted %d times, want 1", n)
	}
	wantRefusal(t, a.send(t, a.admin, proof), http.StatusUnauthorized, classInvalidCredentials)
	if n := a.acted.Load(); n != 1 {
		t.Errorf("the replayed code acted: %d actions, want 1", n)
	}
}

// Design test 7: a recovery code passes once and is then burnt.
func TestStepUpAppRouteRecoveryCodePassesOnceOnly(t *testing.T) {
	a := newStepUpApp(t)
	proof := StepUpProof{Password: doorTestPassword, Code: a.recovery[0]}
	if status, body := readAll(t, a.send(t, a.admin, proof)); status != http.StatusOK {
		t.Fatalf("password and recovery code = %d %s, want 200", status, body)
	}
	wantRefusal(t, a.send(t, a.admin, proof), http.StatusUnauthorized, classInvalidCredentials)
	if n := a.acted.Load(); n != 1 {
		t.Errorf("the application acted %d times, want 1", n)
	}
}

// Design test 8: a passkey ceremony begun at /api/auth is finished on
// the application route: the cookie reaches a path outside /api/auth,
// and the response clears it.
func TestStepUpAppRoutePasskeyCeremonyCookieReachesTheRoute(t *testing.T) {
	a := newStepUpApp(t)
	fake := a.fake
	options := stepUpOptions(t, a.admin, a.ts)
	if !jarHolds(t, a.admin, a.ts, stepUpAppPath, passkeyStepUpCookieName) {
		t.Fatalf("the browser would not send %s to %s", passkeyStepUpCookieName, stepUpAppPath)
	}
	resp := a.send(t, a.admin, StepUpProof{Password: doorTestPassword, Assertion: signStepUp(t, fake, options)})
	cleared := cookieCleared(resp, passkeyStepUpCookieName)
	if status, body := readAll(t, resp); status != http.StatusOK {
		t.Fatalf("password and passkey on the application route = %d %s, want 200", status, body)
	}
	if !cleared {
		t.Error("the response did not clear the step-up cookie")
	}
	if n := a.acted.Load(); n != 1 {
		t.Errorf("the application acted %d times, want 1", n)
	}
}

// Design test 9: no ceremony, or one already finished, is 401
// step-expired and clears the cookie.
func TestStepUpAppRoutePasskeyWithNoLiveCeremonyIsStepExpired(t *testing.T) {
	t.Run("no begin", func(t *testing.T) {
		a := newStepUpApp(t)
		fake := a.fake
		// Options from a begin on another client: this one carries no cookie.
		other := sessionClient(t, a.ts.URL, a.g.deps.Sessions.Create(a.adminID, time.Now()).ID)
		assertion := signStepUp(t, fake, stepUpOptions(t, other, a.ts))
		resp := a.send(t, a.admin, StepUpProof{Password: doorTestPassword, Assertion: assertion})
		cleared := cookieCleared(resp, passkeyStepUpCookieName)
		wantRefusal(t, resp, http.StatusUnauthorized, classStepExpired)
		if !cleared {
			t.Error("the dead step-up cookie was not cleared")
		}
		a.wantNoAction(t)
	})
	t.Run("same assertion twice", func(t *testing.T) {
		a := newStepUpApp(t)
		fake := a.fake
		proof := StepUpProof{Password: doorTestPassword, Assertion: signStepUp(t, fake, stepUpOptions(t, a.admin, a.ts))}
		if status, body := readAll(t, a.send(t, a.admin, proof)); status != http.StatusOK {
			t.Fatalf("first use = %d %s, want 200", status, body)
		}
		resp := a.send(t, a.admin, proof)
		cleared := cookieCleared(resp, passkeyStepUpCookieName)
		wantRefusal(t, resp, http.StatusUnauthorized, classStepExpired)
		if !cleared {
			t.Error("the dead step-up cookie was not cleared")
		}
		if n := a.acted.Load(); n != 1 {
			t.Errorf("the application acted %d times, want 1", n)
		}
	})
}

// Design test 10: a ceremony begun by the admin cannot be finished with
// another account's passkey.
func TestStepUpAppRouteAnotherAccountsPasskeyIsRefused(t *testing.T) {
	a := newStepUpApp(t)
	_ = postJSON(t, a.admin, a.ts.URL+"/api/auth/users",
		createUserRequest{Username: passkeyBilboUsername, Password: passkeyBilboPassword, Role: "user"}).Body.Close()
	bilbo := loggedInPasskeyClient(t, a.ts, a.g)
	bilboKey := registerPasskeyWith(t, bilbo, a.ts, a.g, passkeyBilboPassword)

	options := stepUpOptions(t, a.admin, a.ts)
	p := wantRefusal(t, a.send(t, a.admin, StepUpProof{Password: doorTestPassword, Assertion: signStepUp(t, bilboKey, options)}), http.StatusUnauthorized, classInvalidCredentials)
	if p.Detail != "incorrect password or code" {
		t.Errorf("detail = %q, want %q", p.Detail, "incorrect password or code")
	}
	a.wantNoAction(t)
}

// Design test 11: a spent re-check budget is 429, and even the right
// proof is refused until the window passes.
func TestStepUpAppRouteSpentBudgetIsRateLimited(t *testing.T) {
	a := newStepUpApp(t)
	a.g.deps.Limiter = mustNewLoginLimiter(t, 2, time.Minute)
	for range 2 {
		wantRefusal(t, a.send(t, a.admin, StepUpProof{Password: "wrong", Code: a.totp(1)}), http.StatusUnauthorized, classInvalidCredentials)
	}
	wantRefusal(t, a.send(t, a.admin, StepUpProof{Password: doorTestPassword, Code: a.totp(1)}), http.StatusTooManyRequests, classRateLimited)
	a.wantNoAction(t)
}

// Design test 12: a bearer-token request has no signed-in user, so
// StepUp refuses with 401 sign-in-required instead of panicking.
func TestStepUpAppRouteBearerRequestIsSignInRequired(t *testing.T) {
	a := newStepUpApp(t)
	b, err := json.Marshal(StepUpProof{Password: doorTestPassword, Code: a.totp(1)})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, a.ts.URL+stepUpAppPath, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+a.rawToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	wantRefusal(t, resp, http.StatusUnauthorized, classSignInRequired)
	a.wantNoAction(t)
}

// Design test 14 (the cookie half of the spec/doc checks): the begin
// sets the step-up cookie for every path, like the session cookie, while
// the sign-in ceremony cookie stays under /api/auth. The spec says the
// same, so a drift between them shows here.
func TestStepUpCookiePathIsRootAndTheSignInCookieIsNot(t *testing.T) {
	a := newStepUpApp(t)
	resp := stepUpBegin(t, a.admin, a.ts)
	_ = resp.Body.Close()
	found := false
	for _, c := range resp.Cookies() {
		if c.Name == passkeyStepUpCookieName {
			found = true
			if c.Path != "/" {
				t.Errorf("%s Path = %q, want /", c.Name, c.Path)
			}
		}
	}
	if !found {
		t.Fatalf("begin set no %s cookie", passkeyStepUpCookieName)
	}
	if passkeyStepUpCookiePath != "/" {
		t.Errorf("passkeyStepUpCookiePath = %q, want /", passkeyStepUpCookiePath)
	}
	if passkeySignInCookiePath != "/api/auth" {
		t.Errorf("passkeySignInCookiePath = %q, want /api/auth", passkeySignInCookiePath)
	}
}
