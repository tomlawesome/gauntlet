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

// Part 2 of #44 through the HTTP routes: the forced password change
// signs the account out everywhere, the admin unlock route, and the
// lone-admin unlock code.

// readAll returns resp's status and body, closing it.
func readAll(t *testing.T, resp *http.Response) (int, string) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

func getProtected(t *testing.T, client *http.Client, ts *httptest.Server) *http.Response {
	t.Helper()
	resp, err := client.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// The fifth failed second-factor step in a row ends every session the
// account holds, so the change-password door -- which asks for no
// current password -- is reached only by a fresh sign-in with both
// factors. That door's message does not claim an administrator reset
// the account.
func TestFiveSecondFactorFailuresSignTheAccountOutEverywhere(t *testing.T) {
	g, ts, clock := escalationFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	secret, _, _ := totpEnrolAndConfirm(t, bob, ts)
	if status, _ := readAll(t, getProtected(t, bob, ts)); status != http.StatusOK {
		t.Fatalf("bob's session before the failures: %d, want 200", status)
	}
	clock.set(clock.now().Add(time.Minute))

	guesser := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	for range 5 {
		_ = submitLoginFactor(t, guesser, ts, wrongTOTPCode(secret, clock.now())).Body.Close()
	}
	if status, _ := readAll(t, getProtected(t, bob, ts)); status != http.StatusUnauthorized {
		t.Errorf("bob's existing session after five second-factor failures: %d, want 401 (signed out)", status)
	}

	clock.set(g.deps.Users.LoginLockedUntil(totpBobID(t, g)).Add(time.Minute))
	owner := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	_ = submitLoginFactor(t, owner, ts, gauntlet.GenerateTOTPCode(secret, totpCounterNow(clock.now()))).Body.Close()
	resp := getProtected(t, owner, ts)
	status, body := readAll(t, resp)
	if status != http.StatusForbidden || resp.Header.Get(authGateHeader) != authGateMustChangePassword {
		t.Fatalf("the owner's fresh session: %d %s=%q, want 403 at the change-password door",
			status, authGateHeader, resp.Header.Get(authGateHeader))
	}
	if strings.Contains(body, "administrator") {
		t.Errorf("the door after second-factor failures says %q; no administrator reset this account", body)
	}
}

// disableAccount makes fifty failed sign-ins in a row on id, long
// enough ago that every lockout they started has ended, leaving its
// sign-in disabled.
func disableAccount(t *testing.T, users *gauntlet.Store, id string) {
	t.Helper()
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	at := time.Now().Add(-30 * 24 * time.Hour)
	for i := range gauntlet.MaxConsecutiveLoginFailures {
		if !l.ReserveAccount(users, id, at) {
			t.Fatalf("failure %d was refused", i+1)
		}
		if until := users.LoginLockedUntil(id); until.After(at) {
			at = until
		}
		at = at.Add(time.Second)
	}
	if u, _ := users.Get(id); u.LoginDisabledAt.IsZero() {
		t.Fatal("fifty failures did not disable the account")
	}
}

func unlockUser(t *testing.T, client *http.Client, ts *httptest.Server, id string) (int, unlockUserResponse) {
	t.Helper()
	resp := postJSON(t, client, ts.URL+"/api/auth/users/"+id+"/unlock", nil)
	defer func() { _ = resp.Body.Close() }()
	var out unlockUserResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode, out
}

// The admin unlocks a disabled account: 200, and its owner signs in with
// the password they already had. Again with nothing to lift is still
// 200. An unknown account is 404; the admin's own, with no password and
// code (unlock_self_test.go), 400.
func TestAdminUnlocksADisabledAccount(t *testing.T) {
	g, ts, admin := totpFixture(t)
	id := totpBobID(t, g)
	disableAccount(t, g.deps.Users, id)
	if r := tryLogin(t, ts, totpBobUsername, totpBobPassword); r.status != http.StatusTooManyRequests {
		t.Fatalf("the right password on a disabled account: %d, want 429", r.status)
	}

	status, out := unlockUser(t, admin, ts, id)
	if status != http.StatusOK || out.Username != totpBobUsername || !out.WasDisabled || out.WasLockedOut {
		t.Fatalf("unlock = %d %+v, want 200 naming bob, wasDisabled", status, out)
	}
	if r := tryLogin(t, ts, totpBobUsername, totpBobPassword); r.status != http.StatusOK {
		t.Errorf("bob's existing password after the unlock: %d %s, want 200", r.status, r.body)
	}

	if status, out = unlockUser(t, admin, ts, id); status != http.StatusOK || out.WasDisabled || out.WasLockedOut {
		t.Errorf("unlocking again = %d %+v, want 200 with nothing lifted", status, out)
	}
	if status, _ = unlockUser(t, admin, ts, "no-such-id"); status != http.StatusNotFound {
		t.Errorf("unlocking an unknown account = %d, want 404", status)
	}
	adminUser, _ := g.deps.Users.ByUsername("admin")
	if status, _ = unlockUser(t, admin, ts, adminUser.ID); status != http.StatusBadRequest {
		t.Errorf("the admin unlocking their own account with no password or code = %d, want 400", status)
	}
}

// The unlock also clears this process's own count of the account's
// recent wrong guesses: a lockout lifted inside its window lets the
// owner straight back in, not after the window.
func TestAdminUnlockClearsTheLimitersOwnCount(t *testing.T) {
	g, ts, admin := totpFixture(t)
	for range 5 {
		_ = tryLogin(t, ts, totpBobUsername, "wrong-password-placeholder")
	}
	if r := tryLogin(t, ts, totpBobUsername, totpBobPassword); r.status != http.StatusTooManyRequests {
		t.Fatalf("precondition: bob locked out, got %d", r.status)
	}
	// The fixture's one client address is at its limit too; the
	// account's own limit is what this is about.
	g.cfg.ClientIP = func(*http.Request) string { return "192.0.2.77" }
	if status, out := unlockUser(t, admin, ts, totpBobID(t, g)); status != http.StatusOK || !out.WasLockedOut {
		t.Fatalf("unlock = %d %+v, want 200 with wasLockedOut", status, out)
	}
	if r := tryLogin(t, ts, totpBobUsername, totpBobPassword); r.status != http.StatusOK {
		t.Errorf("bob straight after the unlock: %d, want 200", r.status)
	}
}

// Only an admin may unlock, and only with the CSRF header.
func TestAdminUnlockRefusals(t *testing.T) {
	g, ts, admin := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	totpEnrolAndConfirm(t, bob, ts) // past the enrolment door, so the role is what refuses
	adminUser, _ := g.deps.Users.ByUsername("admin")
	if status, _ := unlockUser(t, bob, ts, adminUser.ID); status != http.StatusForbidden {
		t.Errorf("a non-admin unlocking = %d, want 403", status)
	}

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/users/"+totpBobID(t, g)+"/unlock", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := admin.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := readAll(t, resp); status != http.StatusForbidden {
		t.Errorf("unlocking without the CSRF header = %d, want 403", status)
	}
}

// unlockCodeFixture is a gate over a store that opened with its admin,
// "admin", disabled -- so it announced an unlock code -- and holding bob.
// It returns the gate, its server and the code.
func unlockCodeFixture(t *testing.T) (*Gate, *httptest.Server, string) {
	t.Helper()
	m := persist.NewMemory()
	first := newTestGateWithUsers(t, openTrackedStore(t, m))
	firstTS := newTestServer(t, first)
	admin := registerAdmin(t, firstTS, "admin", "password-placeholder-1")
	_ = postJSON(t, admin, firstTS.URL+"/api/auth/users",
		createUserRequest{Username: totpBobUsername, Password: totpBobPassword, Role: "user"}).Body.Close()
	adminUser, _ := first.deps.Users.ByUsername("admin")
	disableAccount(t, first.deps.Users, adminUser.ID)

	var code string
	users, err := gauntlet.OpenStore(m, gauntlet.Options{
		OnUnlockCode: gauntlet.UnlockCodeFunc(func(username, c string) {
			if username != "admin" {
				t.Errorf("unlock code announced for %q, want admin", username)
			}
			code = c
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if code == "" {
		t.Fatal("a store opening with its admin disabled announced no unlock code")
	}
	g := newTestGateWithUsers(t, users)
	return g, newTestServer(t, g), code
}

func redeemUnlockCode(t *testing.T, client *http.Client, ts *httptest.Server, username, code string) (int, string) {
	t.Helper()
	return readAll(t, postJSON(t, client, ts.URL+"/api/auth/unlock", unlockCodeRequest{Username: username, UnlockCode: code}))
}

// The unlock code lifts the admin's disable and nothing else: no
// session is issued, and the admin then signs in with the password they
// already had, still asked for their second factor. Used again, the code
// is refused exactly as a wrong one is.
func TestUnlockCodeLiftsOnlyTheAdminsDisable(t *testing.T) {
	g, ts, code := unlockCodeFixture(t)
	client := &http.Client{Jar: mustCookieJar(t)}

	wantStatus, wantBody := redeemUnlockCode(t, client, ts, "admin", "AAAA-AAAA-AAAA-AAAA")
	if wantStatus != http.StatusUnauthorized {
		t.Fatalf("a wrong code = %d, want 401", wantStatus)
	}
	for _, c := range []struct{ username, code string }{
		{totpBobUsername, code}, // the right code, someone else's name
		{"nobody", code},
		{"admin", ""},
	} {
		if status, body := redeemUnlockCode(t, client, ts, c.username, c.code); status != wantStatus || body != wantBody {
			t.Errorf("unlock(%q, %q) = %d %q, want the wrong-code answer %d %q", c.username, c.code, status, body, wantStatus, wantBody)
		}
	}

	status, body := redeemUnlockCode(t, client, ts, "Admin", strings.ToLower(code))
	if status != http.StatusOK || !strings.Contains(body, `"unlocked":true`) {
		t.Fatalf("the right code = %d %s, want 200 unlocked", status, body)
	}
	if sessionAuthenticated(t, client, ts) {
		t.Error("redeeming the unlock code signed the caller in")
	}
	adminUser, _ := g.deps.Users.ByUsername("admin")
	if !adminUser.LoginDisabledAt.IsZero() || adminUser.MustChangePassword {
		t.Errorf("after the code: disabled %v, must change password %v; want only the disable lifted",
			adminUser.LoginDisabledAt, adminUser.MustChangePassword)
	}
	// startTOTPLogin requires the password step to answer with a TOTP
	// challenge rather than a session.
	startTOTPLogin(t, ts, "admin", "password-placeholder-1")

	if status, body := redeemUnlockCode(t, client, ts, "admin", code); status != wantStatus || body != wantBody {
		t.Errorf("the code a second time = %d %q, want the wrong-code answer", status, body)
	}
}

// Guesses at the code are counted against the client's address, as
// guesses at the setup code are, and it needs the CSRF header.
func TestUnlockCodeGuessesAreRateLimited(t *testing.T) {
	_, ts, code := unlockCodeFixture(t)
	client := &http.Client{Jar: mustCookieJar(t)}
	for i := range 5 {
		if status, _ := redeemUnlockCode(t, client, ts, "admin", "AAAA-AAAA-AAAA-AAAA"); status != http.StatusUnauthorized {
			t.Fatalf("wrong code %d = %d, want 401", i+1, status)
		}
	}
	if status, _ := redeemUnlockCode(t, client, ts, "admin", code); status != http.StatusTooManyRequests {
		t.Errorf("the right code after five wrong ones from the address = %d, want 429", status)
	}

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/unlock",
		strings.NewReader(`{"username":"admin","unlockCode":"`+code+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := readAll(t, resp); status != http.StatusForbidden {
		t.Errorf("the unlock route without the CSRF header = %d, want 403", status)
	}
}

// A deployment whose admin is not disabled has no code: anything typed
// is refused as a wrong code.
func TestUnlockRouteWithNoCodeOutstanding(t *testing.T) {
	_, ts, _ := totpFixture(t)
	if status, _ := redeemUnlockCode(t, &http.Client{Jar: mustCookieJar(t)}, ts, "admin", "AAAA-AAAA-AAAA-AAAA"); status != http.StatusUnauthorized {
		t.Errorf("an unlock code with none outstanding = %d, want 401", status)
	}
}
