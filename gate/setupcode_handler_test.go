package gate

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/tomlawesome/gauntlet/oidc"
	"github.com/tomlawesome/gauntlet/persist"
)

// The first account is created only with the setup code the store
// announced (issue #37): a wrong or missing code is refused before any
// account exists, counted against the client address, and logged.

func TestRegisterRefusesWrongOrMissingSetupCode(t *testing.T) {
	g := newTestGate(t)
	rec := &messageRecorder{}
	g.cfg.Log = slog.New(rec)
	ts := newTestServer(t, g)
	client := &http.Client{Jar: mustCookieJar(t)}

	for _, code := range []string{"", "AAAA-AAAA-AAAA-AAAA"} {
		resp := postJSON(t, client, ts.URL+"/api/auth/register", registerRequest{Username: "admin", Password: "password-placeholder-345", SetupCode: code})
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("register with setup code %q: status %d, want 401", code, resp.StatusCode)
		}
		if len(resp.Cookies()) != 0 {
			t.Errorf("register with setup code %q set a cookie", code)
		}
	}
	if g.deps.Users.Count() != 0 {
		t.Fatalf("a refused code created %d accounts", g.deps.Users.Count())
	}
	found := false
	for _, m := range rec.msgs {
		if strings.Contains(m, "setup code") && strings.Contains(m, `"198.51.100.1"`) {
			found = true
		}
	}
	if !found {
		t.Errorf("no warning naming the client address for a refused setup code; got %q", rec.msgs)
	}
}

func TestRegisterAcceptsSetupCodeInAnyTypedForm(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	code := setupCodeFor(t, g)
	typed := strings.ToLower(strings.ReplaceAll(code, "-", ""))

	client := &http.Client{Jar: mustCookieJar(t)}
	resp := postJSON(t, client, ts.URL+"/api/auth/register", registerRequest{Username: "admin", Password: "password-placeholder-345", SetupCode: typed})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register with the code typed as %q: status %d, want 201", typed, resp.StatusCode)
	}
	if u, ok := g.deps.Users.ByUsername("admin"); !ok || u.Role != "admin" {
		t.Fatalf("admin not created as admin: %+v %v", u, ok)
	}

	// Used up by state: the same code opens nothing once an account exists.
	resp = postJSON(t, &http.Client{}, ts.URL+"/api/auth/register", registerRequest{Username: "second", Password: "password-placeholder-345", SetupCode: code})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("register after the first account: status %d, want 409", resp.StatusCode)
	}
}

func TestRegisterSetupCodeGuessesAreRateLimited(t *testing.T) {
	g := newTestGate(t) // limiter: 5 per 5 minutes per address
	ts := newTestServer(t, g)
	client := &http.Client{}

	var last int
	for range 5 {
		resp := postJSON(t, client, ts.URL+"/api/auth/register", registerRequest{Username: "admin", Password: "password-placeholder-345", SetupCode: "AAAA-AAAA-AAAA-AAAA"})
		_ = resp.Body.Close()
		last = resp.StatusCode
	}
	if last != http.StatusUnauthorized {
		t.Fatalf("fifth wrong code: status %d, want 401", last)
	}
	resp := postJSON(t, client, ts.URL+"/api/auth/register", registerRequest{Username: "admin", Password: "password-placeholder-345", SetupCode: setupCodeFor(t, g)})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("sixth attempt from the same address: status %d, want 429 even with the right code", resp.StatusCode)
	}
}

func TestRegisterRightCodeReleasesTheAttempt(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	client := &http.Client{}
	code := setupCodeFor(t, g)

	// Five attempts with the right code but a password too short: the
	// budget guards the code, not the operator's typing, so none of
	// these count and the sixth, correct, request still goes through.
	for range 5 {
		resp := postJSON(t, client, ts.URL+"/api/auth/register", registerRequest{Username: "admin", Password: "short", SetupCode: code})
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("short password with the right code: status %d, want 400", resp.StatusCode)
		}
	}
	resp := postJSON(t, &http.Client{Jar: mustCookieJar(t)}, ts.URL+"/api/auth/register", registerRequest{Username: "admin", Password: "password-placeholder-345", SetupCode: code})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register after five right-code mistakes: status %d, want 201", resp.StatusCode)
	}
}

// SSO cannot create the first account: the OIDC routes are not in the
// bootstrap set, so they answer 503 like every other route until the
// first admin exists.
// TestRegisterOnALaggingProcessNamesTheSpentCode pins gauntlet#58 S11:
// two processes open on the same empty backend, each announcing its
// own setup code. One registers the first admin. The other's own
// CheckSetupCode has not reloaded and still sees no account, so its
// code passes that first check -- but Register (which does reload)
// then finds the admin already exists and refuses. That refusal used
// to read like the submitted code was simply wrong; it should say the
// code was spent instead, since the caller showed a code that really
// was valid an instant before.
func TestRegisterOnALaggingProcessNamesTheSpentCode(t *testing.T) {
	m := persist.NewMemory()
	usersA := openTrackedStore(t, m)
	usersB := openTrackedStore(t, m)
	gA := newTestGateWithUsers(t, usersA)
	gB := newTestGateWithUsers(t, usersB)
	tsA := newTestServer(t, gA)
	tsB := newTestServer(t, gB)
	codeA := setupCodeFor(t, gA)
	codeB := setupCodeFor(t, gB)
	if codeA == codeB {
		t.Fatal("precondition: the two processes announced the same code")
	}

	first := postJSON(t, &http.Client{}, tsA.URL+"/api/auth/register", registerRequest{Username: "admin", Password: "password-placeholder-345", SetupCode: codeA})
	_ = first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first registration: status %d, want 201", first.StatusCode)
	}

	second := postJSON(t, &http.Client{}, tsB.URL+"/api/auth/register", registerRequest{Username: "second", Password: "password-placeholder-345", SetupCode: codeB})
	body, _ := io.ReadAll(second.Body)
	_ = second.Body.Close()
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("second process's registration: status %d, want 409", second.StatusCode)
	}
	if want := "the setup code was already used to create the first admin"; !strings.Contains(string(body), want) {
		t.Errorf("body = %q, want it to mention %q", body, want)
	}
	if usersB.Count() != 1 {
		t.Errorf("the lagging process's refused registration created an account too: count = %d", usersB.Count())
	}
}

func TestOIDCRoutesClosedWhileSetupRequired(t *testing.T) {
	_, ts, _ := newEmptyOIDCTestGate(t, oidc.Policy{})
	for _, path := range []string{"/api/auth/oidc/login", "/api/auth/oidc/callback?state=x&code=y"} {
		resp, err := noRedirectClient().Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("GET %s while no account exists: status %d, want 503", path, resp.StatusCode)
		}
	}
}
