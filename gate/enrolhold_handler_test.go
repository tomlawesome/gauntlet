package gate

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/internal/passkeytest"
)

// Hold until confirmed (#58): an account's first second factor and its
// recovery codes are saved together on hold, shown once, and become
// live only when POST /api/auth/recovery-codes/confirm says the codes
// were saved. Only then are the account's other sessions ended, this
// one renewed and the factor audited.

// testClock is a settable Config.Now, starting at the real time so the
// passkey library's own ceremony clock agrees with it.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// heldPasskeyFixture is passkeyFixture on a settable clock.
func heldPasskeyFixture(t *testing.T) (*Gate, *httptest.Server, *testClock) {
	t.Helper()
	clock := &testClock{t: time.Now()}
	g := passkeyGate(t)
	g.cfg.Now = clock.now
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")
	_ = postJSON(t, admin, ts.URL+"/api/auth/users",
		createUserRequest{Username: passkeyBilboUsername, Password: passkeyBilboPassword, Role: "user"}).Body.Close()
	return g, ts, clock
}

// hasAuditEntry reports whether action was recorded against target.
func hasAuditEntry(g *Gate, action, target string) bool {
	rec := g.cfg.Audit.(*auditRecorder)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, e := range rec.entries {
		if e.Action == action && e.Target == target {
			return true
		}
	}
	return false
}

// confirmEnrolment posts the confirm route and returns the response.
func confirmEnrolment(t *testing.T, client *http.Client, ts *httptest.Server) *http.Response {
	t.Helper()
	return postJSON(t, client, ts.URL+enrolmentConfirmPath, nil)
}

func confirmEnrolmentOK(t *testing.T, client *http.Client, ts *httptest.Server) enrolmentConfirmResponse {
	t.Helper()
	resp := confirmEnrolment(t, client, ts)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("confirming the held enrolment returned %d: %s", resp.StatusCode, body)
	}
	var out enrolmentConfirmResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// wantProblem fails unless resp has status and problem class.
func wantProblem(t *testing.T, resp *http.Response, status int, class problemClass) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != status {
		t.Fatalf("status = %d, want %d: %s", resp.StatusCode, status, raw)
	}
	if p := decodeProblem(t, raw); p.Type != problemTypeBase+class.anchor {
		t.Errorf("problem type = %q, want class %q: %s", p.Type, class.anchor, raw)
	}
}

func TestTheFirstPasskeyIsHeldUntilItsCodesAreConfirmed(t *testing.T) {
	g, ts, _ := heldPasskeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	elsewhere := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)

	fake, out := registerPasskeyHeld(t, bilbo, ts, g, "YubiKey")
	if !out.PendingConfirmation || len(out.RecoveryCodes) != 10 || out.AlreadyIssued {
		t.Fatalf("first passkey = %+v, want ten codes, pendingConfirmation, not alreadyIssued", out)
	}
	if out.Passkey.Name != "YubiKey" {
		t.Errorf("held passkey name = %q", out.Passkey.Name)
	}

	// On hold: not a factor yet, so the door still holds; nothing
	// rotated and nothing audited.
	sess := sessionOf(t, bilbo, ts)
	if !sess.Authenticated || !sess.MustEnrolSecondFactor || sess.Passkeys == nil || sess.Passkeys.Count != 0 {
		t.Fatalf("session while held = %+v, want signed in, at the door, no passkeys", sess)
	}
	if got := protectedStatus(t, bilbo, ts); got != http.StatusForbidden {
		t.Errorf("a protected route while held answered %d, want the door's 403", got)
	}
	if !sessionOf(t, elsewhere, ts).Authenticated {
		t.Error("holding the first passkey ended another session")
	}
	if hasAuditEntry(g, "account.passkey_added", passkeyBilboUsername) {
		t.Error("account.passkey_added was written before the codes were confirmed")
	}

	// Confirmed: live, the other session ends, this one is renewed, and
	// the audit line is written.
	before := bilbo.Jar.Cookies(mustParseURL(t, ts.URL))
	confirmed := confirmEnrolmentOK(t, bilbo, ts)
	if !confirmed.Confirmed || confirmed.Factor != "passkey" {
		t.Errorf("confirm = %+v, want confirmed passkey", confirmed)
	}
	if after := bilbo.Jar.Cookies(mustParseURL(t, ts.URL)); sameCookieValues(before, after) {
		t.Error("confirming did not renew this browser's session")
	}
	sess = sessionOf(t, bilbo, ts)
	if !sess.Authenticated || sess.MustEnrolSecondFactor || sess.Passkeys.Count != 1 {
		t.Errorf("session after confirming = %+v, want signed in, past the door, one passkey", sess)
	}
	if sessionOf(t, elsewhere, ts).Authenticated {
		t.Error("confirming did not end the account's other session")
	}
	if entry := findAuditEntry(t, g, "account.passkey_added"); entry.Detail != `name="YubiKey"`+fixtureFromSuffix {
		t.Errorf("account.passkey_added detail = %q", entry.Detail)
	}
	if got := passkeysList(t, bilbo, ts); len(got) != 1 {
		t.Errorf("passkey list after confirming = %+v, want one", got)
	}

	// And it signs in.
	pending := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	resp := submitPasskeyAssertion(t, pending, ts, fake, passkeyLoginFactorBegin(t, pending, ts))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("signing in with the confirmed passkey returned %d", resp.StatusCode)
	}
}

func TestAHeldPasskeyCannotSignIn(t *testing.T) {
	g, ts, _ := heldPasskeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	registerPasskeyHeld(t, bilbo, ts, g, "key")

	u, _ := g.deps.Users.ByUsername(passkeyBilboUsername)
	if n := g.usablePasskeyCount(u); n != 0 {
		t.Errorf("usablePasskeyCount = %d for a held passkey, want 0", n)
	}
	// The password step offers no second factor -- the held passkey is
	// not one -- so a fresh browser lands at the enrolment door, not at
	// a passkey challenge.
	client := &http.Client{Jar: mustCookieJar(t)}
	resp := postJSON(t, client, ts.URL+"/api/auth/login", credentialsRequest{Username: passkeyBilboUsername, Password: passkeyBilboPassword})
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if _, offered := out["secondFactor"]; offered {
		t.Errorf("the password step offered a second factor for a held passkey: %v", out)
	}
	if got := protectedStatus(t, client, ts); got != http.StatusForbidden {
		t.Errorf("a protected route answered %d, want the door's 403", got)
	}
	// login/factor/begin needs a pending login, which this account never
	// gets while its only passkey is held.
	if got := postStatus(t, client, ts.URL+"/api/auth/login/factor/begin"); got != http.StatusUnauthorized {
		t.Errorf("login/factor/begin answered %d, want 401", got)
	}
}

func TestTheFirstAuthenticatorAppIsHeldUntilItsCodesAreConfirmed(t *testing.T) {
	g, ts, _ := heldPasskeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	elsewhere := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)

	out := totpEnrolAndHold(t, bilbo, ts, g.now())
	if !out.PendingConfirmation || out.Enabled || len(out.RecoveryCodes) != 10 {
		t.Fatalf("first app = %+v, want ten codes, pendingConfirmation, not enabled", out)
	}
	sess := sessionOf(t, bilbo, ts)
	if sess.HasTOTP || !sess.MustEnrolSecondFactor {
		t.Errorf("session while held = %+v, want no app yet and the door", sess)
	}
	if !sessionOf(t, elsewhere, ts).Authenticated {
		t.Error("holding the first app ended another session")
	}
	if hasAuditEntry(g, "account.totp_enabled", passkeyBilboUsername) {
		t.Error("account.totp_enabled was written before the codes were confirmed")
	}

	confirmed := confirmEnrolmentOK(t, bilbo, ts)
	if confirmed.Factor != "totp" {
		t.Errorf("confirm = %+v, want totp", confirmed)
	}
	sess = sessionOf(t, bilbo, ts)
	if !sess.HasTOTP || sess.MustEnrolSecondFactor || !sess.Authenticated {
		t.Errorf("session after confirming = %+v", sess)
	}
	if sessionOf(t, elsewhere, ts).Authenticated {
		t.Error("confirming did not end the account's other session")
	}
	if entry := findAuditEntry(t, g, "account.totp_enabled"); entry.Detail != "authenticator app confirmed; recovery codes issued"+fixtureFromSuffix {
		t.Errorf("account.totp_enabled detail = %q", entry.Detail)
	}
}

func TestConfirmWithNothingHeldIsAConflict(t *testing.T) {
	_, ts, _ := heldPasskeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	wantProblem(t, confirmEnrolment(t, bilbo, ts), http.StatusConflict, classConflict)
	anon := &http.Client{Jar: mustCookieJar(t)}
	wantProblem(t, confirmEnrolment(t, anon, ts), http.StatusUnauthorized, classSignInRequired)
}

func TestAnUnconfirmedEnrolmentExpires(t *testing.T) {
	g, ts, clock := heldPasskeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	registerPasskeyHeld(t, bilbo, ts, g, "key")

	clock.advance(gauntlet.HeldEnrolmentLifetime)
	wantProblem(t, confirmEnrolment(t, bilbo, ts), http.StatusUnauthorized, classStepExpired)
	// Deleted, not just refused: the account holds nothing, and a new
	// enrolment can begin.
	u, _ := g.deps.Users.ByUsername(passkeyBilboUsername)
	if u.HeldEnrolment != nil || len(u.Passkeys) != 0 || len(u.RecoveryCodes) != 0 {
		t.Errorf("after expiry: held=%+v passkeys=%d codes=%d", u.HeldEnrolment, len(u.Passkeys), len(u.RecoveryCodes))
	}
	wantProblem(t, confirmEnrolment(t, bilbo, ts), http.StatusConflict, classConflict)
	_, out := registerPasskeyHeld(t, bilbo, ts, g, "again")
	if !out.PendingConfirmation {
		t.Errorf("registering after the expiry = %+v, want a new hold", out)
	}
}

func TestOnlyOneEnrolmentAtATime(t *testing.T) {
	t.Run("passkey held", func(t *testing.T) {
		g, ts, _ := heldPasskeyFixture(t)
		bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
		registerPasskeyHeld(t, bilbo, ts, g, "key")
		wantProblem(t, postJSON(t, bilbo, ts.URL+passkeyRegisterBeginPath, passkeyRegisterBeginRequest{Password: passkeyBilboPassword}), http.StatusConflict, classConflict)
		wantProblem(t, postJSON(t, bilbo, ts.URL+totpEnrolPath, totpEnrolRequest{Password: passkeyBilboPassword}), http.StatusConflict, classConflict)
	})
	t.Run("app held", func(t *testing.T) {
		g, ts, _ := heldPasskeyFixture(t)
		bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
		totpEnrolAndHold(t, bilbo, ts, g.now())
		wantProblem(t, postJSON(t, bilbo, ts.URL+passkeyRegisterBeginPath, passkeyRegisterBeginRequest{Password: passkeyBilboPassword}), http.StatusConflict, classConflict)
		wantProblem(t, postJSON(t, bilbo, ts.URL+totpEnrolPath, totpEnrolRequest{Password: passkeyBilboPassword}), http.StatusConflict, classConflict)
		wantProblem(t, postJSON(t, bilbo, ts.URL+totpConfirmPath, totpConfirmRequest{Code: "123456"}), http.StatusConflict, classConflict)
	})
	t.Run("a finish begun before the hold", func(t *testing.T) {
		g, ts, _ := heldPasskeyFixture(t)
		bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
		other := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
		early := passkeyRegisterBegin(t, other, ts)
		registerPasskeyHeld(t, bilbo, ts, g, "first")
		resp := passkeyRegisterFinishRaw(t, other, ts, newFake(g), early, "second")
		wantProblem(t, resp, http.StatusConflict, classConflict)
	})
}

func TestAPendingAppSecretExpires(t *testing.T) {
	g, ts, clock := heldPasskeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	enrolled := totpEnrolAs(t, bilbo, ts, passkeyBilboPassword)
	secret, err := gauntlet.DecodeTOTPSecret(enrolled.Secret)
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(gauntlet.TOTPPendingLifetime)
	code := gauntlet.GenerateTOTPCode(secret, totpCounterNow(g.now()))
	wantProblem(t, postJSON(t, bilbo, ts.URL+totpConfirmPath, totpConfirmRequest{Code: code}), http.StatusUnauthorized, classStepExpired)
	// A fresh enrolment replaces it.
	totpEnrolAndHold(t, bilbo, ts, g.now())
}

// A later factor, on an account whose first one is confirmed, is added
// live at once and gets no codes: one set per account.
func TestALaterFactorIsAddedLiveWithoutCodes(t *testing.T) {
	g, ts, _ := heldPasskeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	registerPasskeyHeld(t, bilbo, ts, g, "first")
	confirmEnrolmentOK(t, bilbo, ts)

	_, second := registerPasskeyHeld(t, bilbo, ts, g, "second")
	if second.PendingConfirmation || second.RecoveryCodes != nil || !second.AlreadyIssued {
		t.Errorf("second passkey = %+v, want live, no codes, alreadyIssued", second)
	}
	if got := passkeysList(t, bilbo, ts); len(got) != 2 {
		t.Errorf("listed %d passkeys, want 2", len(got))
	}
	if entry := findAuditEntry(t, g, "account.passkey_added"); entry.Detail != `name="second"`+fixtureFromSuffix {
		t.Errorf("the later passkey's audit = %q", entry.Detail)
	}

	elsewhere := loggedInPasskeyClient(t, ts, g)
	out := totpEnrolAndConfirmLive(t, bilbo, ts, g.now())
	if !out.Enabled || out.PendingConfirmation || out.RecoveryCodes != nil || !out.AlreadyIssued {
		t.Errorf("a later app = %+v, want enabled at once, no codes", out)
	}
	if sessionOf(t, elsewhere, ts).Authenticated {
		t.Error("confirming a later app live did not end the other session")
	}
	wantProblem(t, confirmEnrolment(t, bilbo, ts), http.StatusConflict, classConflict)
}

// -- helpers ------------------------------------------------------------

// registerPasskeyHeld drives register/begin+finish and returns the
// finish response as it is, held or live.
func registerPasskeyHeld(t *testing.T, client *http.Client, ts *httptest.Server, g *Gate, name string) (*passkeytest.FakeAuthenticator, passkeyRegisterFinishResponse) {
	t.Helper()
	fake := newFake(g)
	creation := passkeyRegisterBegin(t, client, ts)
	return fake, passkeyRegisterFinishOK(t, client, ts, fake, creation, name)
}

// totpEnrolAndHold enrols an app for bilbo and posts a good code at
// now, returning the confirm response.
func totpEnrolAndHold(t *testing.T, client *http.Client, ts *httptest.Server, now time.Time) totpConfirmResponse {
	t.Helper()
	enrolled := totpEnrolAs(t, client, ts, passkeyBilboPassword)
	secret, err := gauntlet.DecodeTOTPSecret(enrolled.Secret)
	if err != nil {
		t.Fatal(err)
	}
	resp := postJSON(t, client, ts.URL+totpConfirmPath, totpConfirmRequest{Code: gauntlet.GenerateTOTPCode(secret, totpCounterNow(now))})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("totp/confirm returned %d: %s", resp.StatusCode, body)
	}
	var out totpConfirmResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// totpEnrolAndConfirmLive is totpEnrolAndHold for an account that
// already has a factor, where the app goes live at once.
func totpEnrolAndConfirmLive(t *testing.T, client *http.Client, ts *httptest.Server, now time.Time) totpConfirmResponse {
	t.Helper()
	return totpEnrolAndHold(t, client, ts, now)
}

// loggedInPasskeyClient gives a fresh browser a session of bilbo's,
// straight from the session store -- bilbo has a live passkey, so the
// password step alone would not give one -- to see whether a later
// write ends it.
func loggedInPasskeyClient(t *testing.T, ts *httptest.Server, g *Gate) *http.Client {
	t.Helper()
	u, _ := g.deps.Users.ByUsername(passkeyBilboUsername)
	client := &http.Client{Jar: mustCookieJar(t)}
	sess := g.deps.Sessions.Create(u.ID, g.now())
	client.Jar.SetCookies(mustParseURL(t, ts.URL), []*http.Cookie{{Name: g.sessionCookieName(), Value: sess.ID, Path: "/"}})
	return client
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func sameCookieValues(a, b []*http.Cookie) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Value != b[i].Value {
			return false
		}
	}
	return true
}
