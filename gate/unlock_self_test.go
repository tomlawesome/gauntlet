package gate

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/persist"
)

// An admin unlocking their own disabled sign-in from a live session
// (owner, 2026-10-02, on #44): only with their password and a current
// second factor entered again, each wrong one counted on the account's
// re-check budget.

const selfUnlockAdminPassword = "password-placeholder-1"

// enrolAdminTOTP enrols and confirms an authenticator app on the
// fixture's admin, and confirms its held recovery codes, returning its secret, its recovery codes and the
// counter the confirmation used.
func enrolAdminTOTP(t *testing.T, admin *http.Client, ts *httptest.Server) ([]byte, []string, uint64) {
	t.Helper()
	resp := postJSON(t, admin, ts.URL+"/api/auth/totp/enrol", totpEnrolRequest{Password: selfUnlockAdminPassword})
	var enrolled totpEnrolResponse
	if status, body := readAll(t, resp); status != http.StatusOK {
		t.Fatalf("admin TOTP enrol = %d %s", status, body)
	} else if err := json.Unmarshal([]byte(body), &enrolled); err != nil {
		t.Fatal(err)
	}
	secret, err := gauntlet.DecodeTOTPSecret(enrolled.Secret)
	if err != nil {
		t.Fatal(err)
	}
	counter := totpCounterNow(time.Now())
	resp = postJSON(t, admin, ts.URL+"/api/auth/totp/confirm", totpConfirmRequest{Code: gauntlet.GenerateTOTPCode(secret, counter)})
	defer func() { _ = resp.Body.Close() }()
	var out totpConfirmResponse
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("admin TOTP confirm = %d %s", resp.StatusCode, body)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	confirmEnrolmentOK(t, admin, ts) // the first factor is held until its codes are confirmed (#58)
	return secret, out.RecoveryCodes, counter
}

// unlockSelf posts body (nil for none) to the admin's own unlock route.
func unlockSelf(t *testing.T, admin *http.Client, ts *httptest.Server, id string, body any) (int, unlockUserResponse) {
	t.Helper()
	resp := postJSON(t, admin, ts.URL+"/api/auth/users/"+id+"/unlock", body)
	defer func() { _ = resp.Body.Close() }()
	var out unlockUserResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode, out
}

// selfUnlockFixture is a gate whose admin holds an authenticator app
// and a live session, with their sign-in then disabled.
func selfUnlockFixture(t *testing.T) (g *Gate, ts *httptest.Server, admin *http.Client, adminID string, secret []byte, recovery []string, counter uint64) {
	t.Helper()
	return selfUnlockFixtureOn(t, newTestGate(t))
}

// selfUnlockFixtureOn is selfUnlockFixture on a given gate.
func selfUnlockFixtureOn(t *testing.T, g *Gate) (_ *Gate, ts *httptest.Server, admin *http.Client, adminID string, secret []byte, recovery []string, counter uint64) {
	t.Helper()
	ts = newTestServer(t, g)
	admin = registerAdminNoFactor(t, ts, "admin", selfUnlockAdminPassword)
	secret, recovery, counter = enrolAdminTOTP(t, admin, ts)
	u, _ := g.deps.Users.ByUsername("admin")
	adminID = u.ID
	disableAccount(t, g.deps.Users, adminID)
	if r := tryLogin(t, ts, "admin", selfUnlockAdminPassword); r.status != http.StatusTooManyRequests {
		t.Fatalf("precondition: the admin's right password on a disabled sign-in = %d, want 429", r.status)
	}
	return g, ts, admin, adminID, secret, recovery, counter
}

func stillDisabled(t *testing.T, g *Gate, id, after string) {
	t.Helper()
	if u, _ := g.deps.Users.Get(id); u.LoginDisabledAt.IsZero() {
		t.Fatalf("%s lifted the disable", after)
	}
}

// The password and a current TOTP code lift the admin's own disable;
// they then sign in as before, still asked for their second factor.
func TestAdminUnlocksTheirOwnSignInWithPasswordAndTOTPCode(t *testing.T) {
	g, ts, admin, id, secret, _, counter := selfUnlockFixture(t)

	status, out := unlockSelf(t, admin, ts, id, unlockSelfRequest{
		Password: selfUnlockAdminPassword, Code: gauntlet.GenerateTOTPCode(secret, counter+1)})
	if status != http.StatusOK || out.Username != "admin" || !out.WasDisabled {
		t.Fatalf("self-unlock with password and code = %d %+v, want 200 naming admin, wasDisabled", status, out)
	}
	if u, _ := g.deps.Users.Get(id); !u.LoginDisabledAt.IsZero() {
		t.Fatal("the disable is still on the record")
	}
	r := tryLogin(t, ts, "admin", selfUnlockAdminPassword)
	if r.status != http.StatusOK || !json.Valid([]byte(r.body)) {
		t.Fatalf("the admin's password after the unlock = %d %s, want 200", r.status, r.body)
	}
	var step struct {
		SecondFactor []string `json:"secondFactor"`
	}
	if err := json.Unmarshal([]byte(r.body), &step); err != nil || len(step.SecondFactor) == 0 {
		t.Errorf("the admin's sign-in after the unlock = %s, want the second-factor step", r.body)
	}
}

// A recovery code serves as the second factor too, and is spent.
func TestAdminUnlocksTheirOwnSignInWithARecoveryCode(t *testing.T) {
	g, ts, admin, id, _, recovery, _ := selfUnlockFixture(t)

	body := unlockSelfRequest{Password: selfUnlockAdminPassword, Code: recovery[0]}
	if status, out := unlockSelf(t, admin, ts, id, body); status != http.StatusOK || !out.WasDisabled {
		t.Fatalf("self-unlock with a recovery code = %d %+v, want 200, wasDisabled", status, out)
	}
	disableAccount(t, g.deps.Users, id)
	if status, _ := unlockSelf(t, admin, ts, id, body); status != http.StatusUnauthorized {
		t.Errorf("the same recovery code again = %d, want 401", status)
	}
	stillDisabled(t, g, id, "a spent recovery code")
}

// The session alone unlocks nothing, nor does a body missing either
// credential, nor a wrong password or a wrong code.
func TestAdminSelfUnlockRefusals(t *testing.T) {
	g, ts, admin, id, secret, _, counter := selfUnlockFixture(t)
	right := gauntlet.GenerateTOTPCode(secret, counter+1)

	cases := []struct {
		name string
		body any
		want int
	}{
		{"no body (the session alone)", nil, http.StatusBadRequest},
		{"an empty body", unlockSelfRequest{}, http.StatusBadRequest},
		{"no code", unlockSelfRequest{Password: selfUnlockAdminPassword}, http.StatusBadRequest},
		{"no password", unlockSelfRequest{Code: right}, http.StatusBadRequest},
		{"a wrong password", unlockSelfRequest{Password: "wrong-password-placeholder", Code: right}, http.StatusUnauthorized},
		{"a wrong code", unlockSelfRequest{Password: selfUnlockAdminPassword, Code: wrongTOTPCode(secret, time.Now())}, http.StatusUnauthorized},
	}
	for _, c := range cases {
		if status, _ := unlockSelf(t, admin, ts, id, c.body); status != c.want {
			t.Errorf("%s: %d, want %d", c.name, status, c.want)
		}
		stillDisabled(t, g, id, c.name)
	}

	// The wrong password above was refused before the code was checked,
	// so the right code it carried is still unused.
	body := unlockSelfRequest{Password: selfUnlockAdminPassword, Code: right}
	if status, _ := unlockSelf(t, admin, ts, id, body); status != http.StatusOK {
		t.Errorf("then the right password and code = %d, want 200", status)
	}
}

// Wrong passwords and wrong codes count on the account's re-check
// budget: once it is spent, even the right pair is refused with 429.
func TestAdminSelfUnlockGuessesCountOnTheRecheckBudget(t *testing.T) {
	g, ts, admin, id, secret, _, counter := selfUnlockFixture(t)
	wrongCode := wrongTOTPCode(secret, time.Now())

	for i := range 5 {
		body := unlockSelfRequest{Password: "wrong-password-placeholder", Code: wrongCode}
		if i%2 == 1 {
			body = unlockSelfRequest{Password: selfUnlockAdminPassword, Code: wrongCode}
		}
		if status, _ := unlockSelf(t, admin, ts, id, body); status != http.StatusUnauthorized {
			t.Fatalf("guess %d = %d, want 401", i+1, status)
		}
	}
	body := unlockSelfRequest{Password: selfUnlockAdminPassword, Code: gauntlet.GenerateTOTPCode(secret, counter+1)}
	if status, _ := unlockSelf(t, admin, ts, id, body); status != http.StatusTooManyRequests {
		t.Errorf("the right pair after five wrong guesses = %d, want 429", status)
	}
	stillDisabled(t, g, id, "the right pair over budget")
}

// A body that is not one JSON object is 400 before anything is checked.
func TestAdminSelfUnlockRefusesABadBody(t *testing.T) {
	g, ts, admin, id, _, _, _ := selfUnlockFixture(t)
	if status, _ := unlockSelf(t, admin, ts, id, "{"); status != http.StatusBadRequest {
		t.Errorf("a body that is not a JSON object = %d, want 400", status)
	}
	stillDisabled(t, g, id, "a bad body")
}

// A right code whose use cannot be saved is the backend failing, not a
// wrong guess: 500, nothing unlocked, and the re-check budget handed
// back, so the outage does not end in a 429 for an admin who never
// guessed wrong.
func TestAdminSelfUnlockWhenTheCodeCannotBeSaved(t *testing.T) {
	g := newTestGate(t)
	backend := &budgetBackend{inner: persist.NewMemory(), left: -1}
	g.deps.Users = openTrackedStore(t, backend)
	_, ts, admin, id, secret, _, counter := selfUnlockFixtureOn(t, g)

	backend.left = 0
	body := unlockSelfRequest{Password: selfUnlockAdminPassword, Code: gauntlet.GenerateTOTPCode(secret, counter+1)}
	for i := range 6 {
		if status, _ := unlockSelf(t, admin, ts, id, body); status != http.StatusInternalServerError {
			t.Fatalf("attempt %d with saves failing = %d, want 500", i+1, status)
		}
	}
	stillDisabled(t, g, id, "a code that could not be saved")
}

// The code step has its own reservation on the re-check budget, and
// refuses with 429 once the budget is spent -- reachable over HTTP only
// when requests race between the two steps, so checked directly.
func TestRecheckSecondFactorRefusesOverBudget(t *testing.T) {
	g, _, _, id, secret, _, counter := selfUnlockFixture(t)
	u, _ := g.deps.Users.Get(id)
	now := g.now()
	for range 5 {
		if !g.deps.Limiter.ReserveRecheck(id, now) {
			t.Fatal("the re-check budget refused early")
		}
	}
	w := httptest.NewRecorder()
	if g.recheckSecondFactor(w, httptest.NewRequest(http.MethodPost, "/api/auth/users/x/unlock", nil), u, gauntlet.GenerateTOTPCode(secret, counter+1), "wrong", now) {
		t.Fatal("a code over budget was accepted")
	}
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), "too many attempts") {
		t.Errorf("over budget = %d %q, want 429", w.Code, w.Body.String())
	}
}
