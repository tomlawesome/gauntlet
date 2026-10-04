// Ported from mikroview's internal/api/passkey_test.go: all 24 of its
// cases, adapted to gate's fixtures (newTestGate with Deps.Passkeys set
// to a ready gauntlet/passkey relying party; g.deps.Users for s.Auth;
// g.deps.Limiter for the limiter swap; /api/protected as the protected
// probe; 409 where mikroview answers 503 for a relying party that is
// not ready). Then the cases gate adds (ADR-0004 and the rulings on
// #20): passkeys off, an expired ceremony, a dead ceremony told apart
// from a refused credential, and a registration ceremony that survives
// a duplicate refusal.
//
// This file may import gauntlet/passkey and the WebAuthn library's
// protocol package: only gate's non-test code must not.
package gate

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/internal/passkeytest"
	"github.com/tomlawesome/gauntlet/passkey"
	"github.com/tomlawesome/gauntlet/persist"
)

// Obvious placeholders, never anything shaped like a real credential.
const (
	passkeyBilboUsername = "bilbo"
	passkeyBilboPassword = "bilbo-passkey-password-placeholder"
	passkeyTestPublicURL = "https://passkeys.example.org"
)

// auditRecorder is a Config.Audit that keeps every entry.
type auditRecorder struct {
	mu      sync.Mutex
	entries []auditEntry
}

type auditEntry struct{ Actor, Action, Target, Detail string }

func (a *auditRecorder) Record(actor, action, target, detail string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, auditEntry{actor, action, target, detail})
}

// findAuditEntry returns the last entry recorded for action.
func findAuditEntry(t *testing.T, g *Gate, action string) auditEntry {
	t.Helper()
	rec, ok := g.cfg.Audit.(*auditRecorder)
	if !ok {
		t.Fatal("this gate has no auditRecorder -- build it with passkeyGate")
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for i := len(rec.entries) - 1; i >= 0; i-- {
		if rec.entries[i].Action == action {
			return rec.entries[i]
		}
	}
	t.Fatalf("no %s audit entry among %+v", action, rec.entries)
	return auditEntry{}
}

func mustRelyingParty(t *testing.T, publicURL string) *passkey.RelyingParty {
	t.Helper()
	rp, err := passkey.New(passkey.Config{PublicURL: publicURL, DisplayName: testProductName})
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

// passkeyGate is newTestGate with a ready relying party and an audit
// recorder.
func passkeyGate(t *testing.T) *Gate {
	t.Helper()
	g := newTestGate(t)
	rp := mustRelyingParty(t, passkeyTestPublicURL)
	if rp.Status() != gauntlet.PasskeyStatusReady {
		t.Fatalf("test relying party Status = %q, want ready", rp.Status())
	}
	g.deps.Passkeys = rp
	g.cfg.Audit = &auditRecorder{}
	return g
}

// passkeyFixture stands up a server holding an admin and one ordinary
// account ("bilbo", user role, no factor yet) -- totpFixture plus the
// relying party TOTP never needed.
func passkeyFixture(t *testing.T) (*Gate, *httptest.Server, *http.Client) {
	t.Helper()
	g := passkeyGate(t)
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")
	_ = postJSON(t, admin, ts.URL+"/api/auth/users",
		createUserRequest{Username: passkeyBilboUsername, Password: passkeyBilboPassword, Role: "user"}).Body.Close()
	return g, ts, admin
}

func passkeyBilboID(t *testing.T, g *Gate) string {
	t.Helper()
	u, ok := g.deps.Users.ByUsername(passkeyBilboUsername)
	if !ok {
		t.Fatal("the bilbo account the passkey tests act on was not created")
	}
	return u.ID
}

func sessionOf(t *testing.T, client *http.Client, ts *httptest.Server) sessionResponse {
	t.Helper()
	resp, err := client.Get(ts.URL + "/api/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out sessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func protectedStatus(t *testing.T, client *http.Client, ts *httptest.Server) int {
	t.Helper()
	resp, err := client.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func passkeyRegisterBegin(t *testing.T, client *http.Client, ts *httptest.Server) *protocol.CredentialCreation {
	t.Helper()
	resp := postJSON(t, client, ts.URL+"/api/auth/passkeys/register/begin", passkeyRegisterBeginRequest{Password: passkeyBilboPassword})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("register/begin returned %d: %s", resp.StatusCode, body)
	}
	var out protocol.CredentialCreation
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return &out
}

func passkeyRegisterFinishRaw(t *testing.T, client *http.Client, ts *httptest.Server, fake *passkeytest.FakeAuthenticator, creation *protocol.CredentialCreation, name string) *http.Response {
	t.Helper()
	body, err := fake.RegisterResponse(creation)
	if err != nil {
		t.Fatal(err)
	}
	return postJSON(t, client, ts.URL+"/api/auth/passkeys/register/finish",
		passkeyRegisterFinishRequest{Credential: json.RawMessage(body), Name: name})
}

func passkeyRegisterFinishOK(t *testing.T, client *http.Client, ts *httptest.Server, fake *passkeytest.FakeAuthenticator, creation *protocol.CredentialCreation, name string) passkeyRegisterFinishResponse {
	t.Helper()
	resp := passkeyRegisterFinishRaw(t, client, ts, fake, creation, name)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("register/finish returned %d: %s", resp.StatusCode, body)
	}
	var out passkeyRegisterFinishResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// storedPasskeys is how many passkeys id's account holds, live or held
// for its first factor's codes to be confirmed (#58) -- for the tests
// about how many a ceremony stores, not whether they are live yet.
func storedPasskeys(g *Gate, id string) int {
	u, ok := g.deps.Users.Get(id)
	if !ok {
		return 0
	}
	n := len(u.Passkeys)
	if u.HeldEnrolment != nil && u.HeldEnrolment.Passkey != nil {
		n++
	}
	return n
}

func newFake(g *Gate) *passkeytest.FakeAuthenticator {
	return passkeytest.New(g.deps.Passkeys.RPID(), g.deps.Passkeys.Origin())
}

// registerPasskey drives register/begin+finish end to end with a fresh
// fake, returning both, and -- when the passkey was the account's first
// factor and so held with its codes (#58) -- confirms it, so the
// passkey is live either way. registerPasskeyHeld stops at the hold.
func registerPasskey(t *testing.T, client *http.Client, ts *httptest.Server, g *Gate, name string) (*passkeytest.FakeAuthenticator, passkeyRegisterFinishResponse) {
	t.Helper()
	fake, out := registerPasskeyHeld(t, client, ts, g, name)
	if out.PendingConfirmation {
		confirmEnrolmentOK(t, client, ts)
	}
	return fake, out
}

// startPasskeyLogin does the password step for an account whose usable
// factor is a passkey, asserting the shape: no session, secondFactor
// lists "passkey", passkeyOrigin set.
func startPasskeyLogin(t *testing.T, ts *httptest.Server, username, password string) *http.Client {
	t.Helper()
	client := &http.Client{Jar: mustCookieJar(t)}
	resp := postJSON(t, client, ts.URL+"/api/auth/login", credentialsRequest{Username: username, Password: password})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("password step returned %d: %s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	factors, _ := out["secondFactor"].([]any)
	if len(factors) == 0 || factors[0] != "passkey" {
		t.Fatalf("password step response = %v, want secondFactor to list \"passkey\" first", out)
	}
	if origin, ok := out["passkeyOrigin"].(string); !ok || origin != passkeyTestPublicURL {
		t.Errorf("password step response = %v, want passkeyOrigin %q", out, passkeyTestPublicURL)
	}
	return client
}

func passkeyLoginFactorBegin(t *testing.T, client *http.Client, ts *httptest.Server) *protocol.CredentialAssertion {
	t.Helper()
	resp := postJSON(t, client, ts.URL+"/api/auth/login/factor/begin", struct{}{})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("login/factor/begin returned %d: %s", resp.StatusCode, body)
	}
	var out protocol.CredentialAssertion
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return &out
}

func submitPasskeyAssertion(t *testing.T, client *http.Client, ts *httptest.Server, fake *passkeytest.FakeAuthenticator, assertion *protocol.CredentialAssertion) *http.Response {
	t.Helper()
	body, err := fake.AssertionResponse(assertion)
	if err != nil {
		t.Fatal(err)
	}
	return postJSON(t, client, ts.URL+"/api/auth/login/factor", loginFactorRequest{Assertion: json.RawMessage(body)})
}

func passkeysList(t *testing.T, client *http.Client, ts *httptest.Server) []passkeySummary {
	t.Helper()
	resp, err := client.Get(ts.URL + "/api/auth/passkeys")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("passkeys list returned %d: %s", resp.StatusCode, body)
	}
	var out []passkeySummary
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestPasskeyRegisterLoginRoundTrip is the happy path end to end:
// register (minting ten recovery codes without signing the enrolling
// browser out), then a fresh browser completing a login with the same
// authenticator.
func TestPasskeyRegisterLoginRoundTrip(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)

	fake, out := registerPasskey(t, bilbo, ts, g, "YubiKey")
	if out.Passkey.Name != "YubiKey" {
		t.Errorf("stored passkey name = %q, want %q", out.Passkey.Name, "YubiKey")
	}
	if len(out.RecoveryCodes) != 10 {
		t.Fatalf("registering the first factor should mint 10 recovery codes, got %d", len(out.RecoveryCodes))
	}
	if sess := sessionOf(t, bilbo, ts); !sess.Authenticated {
		t.Fatal("registering a passkey should not have signed this browser out")
	}
	if entry := findAuditEntry(t, g, "account.passkey_added"); entry.Detail != `name="YubiKey"`+fixtureFromSuffix {
		t.Errorf("account.passkey_added detail = %q, want %q", entry.Detail, `name="YubiKey"`+fixtureFromSuffix)
	}

	pending := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	if got := protectedStatus(t, pending, ts); got != http.StatusUnauthorized {
		t.Errorf("the password-only step reached a protected route with %d, want 401", got)
	}

	assertion := passkeyLoginFactorBegin(t, pending, ts)
	resp := submitPasskeyAssertion(t, pending, ts, fake, assertion)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("login/factor with a passkey assertion returned %d: %s", resp.StatusCode, body)
	}
	if sess := sessionOf(t, pending, ts); !sess.Authenticated {
		t.Fatal("expected the assertion step to establish a session")
	}
	if entry := findAuditEntry(t, g, "user.login"); entry.Target != passkeyBilboUsername {
		t.Errorf("user.login entry = %+v, want bilbo's", entry)
	}
}

// TestPasswordOnlyLoginOnPasskeyOnlyAccountNeverCreatesSession: a
// correct password on an account whose only factor is a passkey must
// not establish a session.
func TestPasswordOnlyLoginOnPasskeyOnlyAccountNeverCreatesSession(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	registerPasskey(t, bilbo, ts, g, "key")

	client := &http.Client{Jar: mustCookieJar(t)}
	resp := postJSON(t, client, ts.URL+"/api/auth/login", credentialsRequest{Username: passkeyBilboUsername, Password: passkeyBilboPassword})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("the password step itself returned %d, want 200: %s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if _, hasUsername := out["username"]; hasUsername {
		t.Errorf("the password step's response carried a username -- that shape means a session was created: %v", out)
	}
	if sess := sessionOf(t, client, ts); sess.Authenticated {
		t.Fatal("a correct password on a passkey-only account established a session")
	}
	if got := protectedStatus(t, client, ts); got != http.StatusUnauthorized {
		t.Errorf("got %d from a protected route after a password-only login on a passkey-only account, want 401", got)
	}
}

// TestPasskeyRegisterFinishWrongOriginRefused: the library's origin
// check surfaces as a refusal, paired with the identical ceremony
// succeeding at the right origin.
func TestPasskeyRegisterFinishWrongOriginRefused(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)

	creation := passkeyRegisterBegin(t, bilbo, ts)
	fake := newFake(g)
	fake.Origin = "https://not-the-relying-party.example"
	resp := passkeyRegisterFinishRaw(t, bilbo, ts, fake, creation, "wrong origin")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("wrong-origin register/finish got %d, want 400", resp.StatusCode)
	}
	if n := g.deps.Users.PasskeyCount(passkeyBilboID(t, g)); n != 0 {
		t.Fatalf("a wrong-origin registration stored %d passkeys", n)
	}

	// The same ceremony -- no new begin, the cookie is still there --
	// at the right origin succeeds.
	fake.Origin = g.deps.Passkeys.Origin()
	out := passkeyRegisterFinishOK(t, bilbo, ts, fake, creation, "right origin")
	if out.Passkey.Name != "right origin" {
		t.Errorf("the paired successful registration = %+v", out)
	}
}

// TestPasskeyLoginFactorWrongRPIDRefused mirrors the wrong-origin test
// for the login ceremony and the RP ID.
func TestPasskeyLoginFactorWrongRPIDRefused(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	fake, _ := registerPasskey(t, bilbo, ts, g, "key")

	fake.RPID = "not-the-relying-party.example"
	pending := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	resp := submitPasskeyAssertion(t, pending, ts, fake, passkeyLoginFactorBegin(t, pending, ts))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong-RPID assertion got %d, want 401", resp.StatusCode)
	}
	if sess := sessionOf(t, pending, ts); sess.Authenticated {
		t.Error("a wrong-RPID assertion must not establish a session")
	}

	fake.RPID = g.deps.Passkeys.RPID()
	pending2 := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	resp2 := submitPasskeyAssertion(t, pending2, ts, fake, passkeyLoginFactorBegin(t, pending2, ts))
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		t.Errorf("the paired correct-RPID login got %d, want 200: %s", resp2.StatusCode, body)
	}
}

// TestPasskeyCloneWarningRefusesRegressedSignCount: a first login
// advances the stored count to 5; a second reporting 3 is refused,
// audited with both counts, and leaves the stored count at 5.
func TestPasskeyCloneWarningRefusesRegressedSignCount(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	fake, out := registerPasskey(t, bilbo, ts, g, "yubikey")
	id := passkeyBilboID(t, g)

	storedSignCount := func() uint32 {
		u, ok := g.deps.Users.Get(id)
		if !ok {
			t.Fatal("bilbo account vanished")
		}
		for _, pk := range u.Passkeys {
			if base64.RawURLEncoding.EncodeToString(pk.ID) == out.Passkey.ID {
				return pk.SignCount
			}
		}
		t.Fatal("registered passkey not found on the account")
		return 0
	}

	fake.SignCount = 5
	pending := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	resp := submitPasskeyAssertion(t, pending, ts, fake, passkeyLoginFactorBegin(t, pending, ts))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the first login (sign count 0 -> 5) got %d, want 200", resp.StatusCode)
	}
	if got := storedSignCount(); got != 5 {
		t.Fatalf("stored sign count after the first login = %d, want 5", got)
	}

	fake.SignCount = 3
	pending2 := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	resp2 := submitPasskeyAssertion(t, pending2, ts, fake, passkeyLoginFactorBegin(t, pending2, ts))
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("a regressed sign count (5 -> 3) got %d, want 401", resp2.StatusCode)
	}
	if sess := sessionOf(t, pending2, ts); sess.Authenticated {
		t.Error("a clone-suspected assertion must not establish a session")
	}
	if got := storedSignCount(); got != 5 {
		t.Errorf("stored sign count after the regressed attempt = %d, want unchanged at 5", got)
	}

	entry := findAuditEntry(t, g, "account.passkey_clone_suspected")
	if entry.Target != passkeyBilboUsername {
		t.Errorf("account.passkey_clone_suspected entry target = %q, want %q", entry.Target, passkeyBilboUsername)
	}
	want := fmt.Sprintf("credential=%s presentedCount=3 storedCount=5", out.Passkey.ID) + fixtureFromSuffix
	if entry.Detail != want {
		t.Errorf("account.passkey_clone_suspected detail = %q, want %q", entry.Detail, want)
	}
}

// TestConcurrentPasskeyAssertionSubmissionsOnlyOneWins fires the same
// assertion body at the server many times in parallel (run with -race)
// and requires exactly one success -- for a counting authenticator the
// store's locked RecordPasskeyAssertionIfFresh decides, for a
// zero-reporting one the spent challenge has to.
func TestConcurrentPasskeyAssertionSubmissionsOnlyOneWins(t *testing.T) {
	t.Run("counting authenticator", func(t *testing.T) { concurrentPasskeyAssertionSubmissions(t, 5) })
	t.Run("zero-reporting authenticator", func(t *testing.T) { concurrentPasskeyAssertionSubmissions(t, 0) })
}

func concurrentPasskeyAssertionSubmissions(t *testing.T, signCount uint32) {
	g, ts, _ := passkeyFixture(t)
	// The 20 submissions below share one address and account; most are
	// refused, and must not trip the limiter before they are judged.
	g.deps.Limiter = mustNewLoginLimiter(t, 100, time.Minute)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	fake, _ := registerPasskey(t, bilbo, ts, g, "security key")
	fake.SignCount = signCount

	pending := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	credential, err := fake.AssertionResponse(passkeyLoginFactorBegin(t, pending, ts))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(loginFactorRequest{Assertion: json.RawMessage(credential)})
	if err != nil {
		t.Fatal(err)
	}

	const attempts = 20
	var wg sync.WaitGroup
	var successes int32
	errs := make(chan error, attempts)
	for range attempts {
		wg.Go(func() {
			req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/login/factor", bytes.NewReader(body))
			if err != nil {
				errs <- err
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(csrfHeaderName, testCSRFValue)
			resp, err := pending.Do(req)
			if err != nil {
				errs <- err
				return
			}
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				atomic.AddInt32(&successes, 1)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if successes != 1 {
		t.Errorf("%d of %d concurrent submissions of the same assertion succeeded, want exactly 1", successes, attempts)
	}
}

// TestPasskeyZeroReportingAuthenticatorSignsInFine: an authenticator
// that always reports 0 is never treated as a clone, across repeated
// logins.
func TestPasskeyZeroReportingAuthenticatorSignsInFine(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	fake, _ := registerPasskey(t, bilbo, ts, g, "platform authenticator")

	for i := range 2 {
		pending := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
		resp := submitPasskeyAssertion(t, pending, ts, fake, passkeyLoginFactorBegin(t, pending, ts))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("0 -> 0 login attempt %d got %d, want 200", i, resp.StatusCode)
		}
	}
}

// TestStalePasskeyExcludedFromLoginButListedAndRemovable: a passkey
// registered under an old RP ID is excluded from login, but still
// listed (stale, naming the old RP ID) and still removable.
func TestStalePasskeyExcludedFromLoginButListedAndRemovable(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	originalRPID := g.deps.Passkeys.RPID()
	_, out := registerPasskey(t, bilbo, ts, g, "Old Phone")

	// The public URL changes -- as a restart with a new setting would.
	newRP := mustRelyingParty(t, "https://new-passkeys.example.org")
	if newRP.Status() != gauntlet.PasskeyStatusReady {
		t.Fatalf("new relying party Status = %q, want ready", newRP.Status())
	}
	g.deps.Passkeys = newRP

	list := passkeysList(t, bilbo, ts)
	if len(list) != 1 {
		t.Fatalf("passkey list after the RP changed has %d entries, want 1", len(list))
	}
	if !list[0].Stale {
		t.Error("the passkey should be flagged stale after the public URL changed")
	}
	if list[0].RPID != originalRPID {
		t.Errorf("the passkey's recorded RPID = %q, want the original %q", list[0].RPID, originalRPID)
	}

	client := &http.Client{Jar: mustCookieJar(t)}
	resp := postJSON(t, client, ts.URL+"/api/auth/login", credentialsRequest{Username: passkeyBilboUsername, Password: passkeyBilboPassword})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the password step returned %d, want 200", resp.StatusCode)
	}
	var loginOut map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&loginOut); err != nil {
		t.Fatal(err)
	}
	if factors, _ := loginOut["secondFactor"].([]any); len(factors) != 0 {
		t.Errorf("secondFactor = %v after the only passkey went stale, want empty", factors)
	}
	if _, has := loginOut["passkeyOrigin"]; has {
		t.Errorf("passkeyOrigin offered with no usable passkey: %v", loginOut)
	}
	if _, hasUsername := loginOut["username"]; hasUsername {
		t.Errorf("a stale-passkey-only account's password step created a session: %v", loginOut)
	}

	beginResp := postJSON(t, client, ts.URL+"/api/auth/login/factor/begin", struct{}{})
	_ = beginResp.Body.Close()
	if beginResp.StatusCode != http.StatusConflict {
		t.Errorf("login/factor/begin with only a stale passkey got %d, want 409", beginResp.StatusCode)
	}

	delResp := deleteJSON(t, bilbo, ts.URL+"/api/auth/passkeys/"+out.Passkey.ID, passkeyDeleteRequest{Password: passkeyBilboPassword})
	defer func() { _ = delResp.Body.Close() }()
	if delResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(delResp.Body)
		t.Errorf("deleting a stale passkey returned %d, want 200: %s", delResp.StatusCode, body)
	}
}

// TestPasskeyRoutesRefusedWhenRelyingPartyNotReady: with the account
// already holding a passkey, the public URL goes away. The two
// ceremony-starting routes and the assertion step answer 409 (mikroview:
// 503), and list, rename and delete keep working so the passkey stays
// visible and removable.
func TestPasskeyRoutesRefusedWhenRelyingPartyNotReady(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	fake, out := registerPasskey(t, bilbo, ts, g, "key")
	pending := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	assertion := passkeyLoginFactorBegin(t, pending, ts)
	g.deps.Passkeys = mustRelyingParty(t, "")

	expect409 := func(t *testing.T, resp *http.Response) {
		t.Helper()
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), "(unset)") {
			t.Errorf("got %d %q, want 409 naming the status (unset)", resp.StatusCode, body)
		}
	}
	t.Run("register/begin", func(t *testing.T) {
		expect409(t, postJSON(t, bilbo, ts.URL+"/api/auth/passkeys/register/begin", passkeyRegisterBeginRequest{Password: passkeyBilboPassword}))
	})
	t.Run("register/finish", func(t *testing.T) {
		expect409(t, postJSON(t, bilbo, ts.URL+"/api/auth/passkeys/register/finish", passkeyRegisterFinishRequest{Credential: json.RawMessage(`{}`)}))
	})
	t.Run("login/factor/begin", func(t *testing.T) {
		fresh := &http.Client{Jar: mustCookieJar(t)}
		_ = postJSON(t, fresh, ts.URL+"/api/auth/login", credentialsRequest{Username: passkeyBilboUsername, Password: passkeyBilboPassword}).Body.Close()
		expect409(t, postJSON(t, fresh, ts.URL+"/api/auth/login/factor/begin", struct{}{}))
	})
	t.Run("login/factor assertion", func(t *testing.T) {
		expect409(t, submitPasskeyAssertion(t, pending, ts, fake, assertion))
	})
	t.Run("list, rename and delete still work", func(t *testing.T) {
		list := passkeysList(t, bilbo, ts)
		if len(list) != 1 || list[0].Stale {
			t.Fatalf("list = %+v, want the one passkey, not flagged stale", list)
		}
		req, err := http.NewRequest(http.MethodPatch, ts.URL+"/api/auth/passkeys/"+out.Passkey.ID, strings.NewReader(`{"name":"renamed"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(csrfHeaderName, testCSRFValue)
		resp, err := bilbo.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("rename got %d, want 200", resp.StatusCode)
		}
		del := deleteJSON(t, bilbo, ts.URL+"/api/auth/passkeys/"+out.Passkey.ID, passkeyDeleteRequest{Password: passkeyBilboPassword})
		_ = del.Body.Close()
		if del.StatusCode != http.StatusOK {
			t.Errorf("delete got %d, want 200", del.StatusCode)
		}
	})
}

// TestPasskeyRegisterFinishReplayRefused: a second finish with the same
// body, through the same browser, is refused -- here because the
// ceremony cookie is cleared on success. A client that kept a copy of
// the cookie is refused by AddPasskey's duplicate check instead (409).
func TestPasskeyRegisterFinishReplayRefused(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)

	creation := passkeyRegisterBegin(t, bilbo, ts)
	body, err := newFake(g).RegisterResponse(creation)
	if err != nil {
		t.Fatal(err)
	}
	req := passkeyRegisterFinishRequest{Credential: json.RawMessage(body), Name: "once"}

	first := postJSON(t, bilbo, ts.URL+"/api/auth/passkeys/register/finish", req)
	_ = first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("the first finish got %d, want 200", first.StatusCode)
	}
	replay := postJSON(t, bilbo, ts.URL+"/api/auth/passkeys/register/finish", req)
	_ = replay.Body.Close()
	if replay.StatusCode != http.StatusUnauthorized {
		t.Errorf("replaying the same register/finish request got %d, want 401", replay.StatusCode)
	}
}

// TestPasskeyDeleteWrongPassword: the passkey survives a wrong-password
// removal, and the attempt counts against the re-check budget.
func TestPasskeyDeleteWrongPassword(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	_, out := registerPasskey(t, bilbo, ts, g, "key")
	id := passkeyBilboID(t, g)

	resp := deleteJSON(t, bilbo, ts.URL+"/api/auth/passkeys/"+out.Passkey.ID, passkeyDeleteRequest{Password: "not-the-password"})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a wrong password got %d, want 401", resp.StatusCode)
	}
	if n := g.deps.Users.PasskeyCount(id); n != 1 {
		t.Error("the passkey must survive a wrong-password delete attempt")
	}

	g.deps.Limiter = mustNewLoginLimiter(t, 1, time.Minute)
	_ = deleteJSON(t, bilbo, ts.URL+"/api/auth/passkeys/"+out.Passkey.ID, passkeyDeleteRequest{Password: "not-the-password"}).Body.Close()
	limited := deleteJSON(t, bilbo, ts.URL+"/api/auth/passkeys/"+out.Passkey.ID, passkeyDeleteRequest{Password: passkeyBilboPassword})
	_ = limited.Body.Close()
	if limited.StatusCode != http.StatusTooManyRequests {
		t.Errorf("a delete after the re-check budget was spent got %d, want 429", limited.StatusCode)
	}
}

// TestPasskeyNameIsQuotedInTheAuditLog: a passkey's name is the user's
// own text, so a newline or terminal escape in it reaches the audit
// detail quoted, on adding and removing alike, never raw. The stored
// name is left as the user gave it.
func TestPasskeyNameIsQuotedInTheAuditLog(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	name := "key\nforged=1 \x1b[31mred"
	_, out := registerPasskey(t, bilbo, ts, g, name)
	if out.Passkey.Name != name {
		t.Errorf("stored passkey name = %q, want %q unchanged", out.Passkey.Name, name)
	}
	want := `name="key\nforged=1 \x1b[31mred"` + fixtureFromSuffix
	if entry := findAuditEntry(t, g, "account.passkey_added"); entry.Detail != want || strings.ContainsAny(entry.Detail, "\n\x1b") {
		t.Errorf("account.passkey_added detail = %q, want %q", entry.Detail, want)
	}

	resp := deleteJSON(t, bilbo, ts.URL+"/api/auth/passkeys/"+out.Passkey.ID, passkeyDeleteRequest{Password: passkeyBilboPassword})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete returned %d", resp.StatusCode)
	}
	if entry := findAuditEntry(t, g, "account.passkey_removed"); entry.Detail != want || strings.ContainsAny(entry.Detail, "\n\x1b") {
		t.Errorf("account.passkey_removed detail = %q, want %q", entry.Detail, want)
	}
}

// TestPasskeyDeleteLeavingNoFactorSignsOutEverySession: removing the
// only second factor signs out every session, the caller's included.
func TestPasskeyDeleteLeavingNoFactorSignsOutEverySession(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	deviceA := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	fake, out := registerPasskey(t, deviceA, ts, g, "only key")

	deviceB := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	factorResp := submitPasskeyAssertion(t, deviceB, ts, fake, passkeyLoginFactorBegin(t, deviceB, ts))
	_ = factorResp.Body.Close()
	if factorResp.StatusCode != http.StatusOK {
		t.Fatalf("deviceB's passkey login/factor returned %d", factorResp.StatusCode)
	}

	resp := deleteJSON(t, deviceA, ts.URL+"/api/auth/passkeys/"+out.Passkey.ID, passkeyDeleteRequest{Password: passkeyBilboPassword})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("delete returned %d: %s", resp.StatusCode, body)
	}
	var deleted map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&deleted); err != nil {
		t.Fatal(err)
	}
	if deleted["removed"] != true || deleted["signedOut"] != true {
		t.Errorf("delete response = %v, want removed=true signedOut=true", deleted)
	}
	for name, client := range map[string]*http.Client{"deviceA (the caller)": deviceA, "deviceB": deviceB} {
		if got := protectedStatus(t, client, ts); got != http.StatusUnauthorized {
			t.Errorf("%s's session got %d once the account lost its only factor, want 401", name, got)
		}
	}
	if u, ok := g.deps.Users.Get(passkeyBilboID(t, g)); !ok || len(u.RecoveryCodes) != 0 {
		t.Error("recovery codes outlived the account's last factor")
	}
	if entry := findAuditEntry(t, g, "account.passkey_removed"); entry.Detail != `name="only key"`+fixtureFromSuffix {
		t.Errorf("account.passkey_removed detail = %q", entry.Detail)
	}
}

// TestPasskeyDeleteLeavingAFactorStandingDoesNotSignOut: removing one of
// two passkeys keeps every session, and signedOut is false.
func TestPasskeyDeleteLeavingAFactorStandingDoesNotSignOut(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	client := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	_, first := registerPasskey(t, client, ts, g, "first key")
	registerPasskey(t, client, ts, g, "second key")

	resp := deleteJSON(t, client, ts.URL+"/api/auth/passkeys/"+first.Passkey.ID, passkeyDeleteRequest{Password: passkeyBilboPassword})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("delete returned %d: %s", resp.StatusCode, body)
	}
	var deleted map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&deleted); err != nil {
		t.Fatal(err)
	}
	if deleted["signedOut"] != false {
		t.Errorf("delete response = %v, want signedOut=false (the second key still stands)", deleted)
	}
	if got := protectedStatus(t, client, ts); got != http.StatusOK {
		t.Errorf("the session got %d after removing one of two passkeys, want 200", got)
	}

	again := deleteJSON(t, client, ts.URL+"/api/auth/passkeys/"+first.Passkey.ID, passkeyDeleteRequest{Password: passkeyBilboPassword})
	_ = again.Body.Close()
	if again.StatusCode != http.StatusNotFound {
		t.Errorf("deleting an already-removed passkey got %d, want 404", again.StatusCode)
	}
	bad := deleteJSON(t, client, ts.URL+"/api/auth/passkeys/not!base64", passkeyDeleteRequest{Password: passkeyBilboPassword})
	_ = bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Errorf("deleting a malformed id got %d, want 400", bad.StatusCode)
	}
}

// TestPasskeyRenameIsCosmeticNoPassword: PATCH needs no password and
// actually changes the stored name.
func TestPasskeyRenameIsCosmeticNoPassword(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	_, out := registerPasskey(t, bilbo, ts, g, "old name")

	rename := func(id, body string) *http.Response {
		req, err := http.NewRequest(http.MethodPatch, ts.URL+"/api/auth/passkeys/"+id, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(csrfHeaderName, testCSRFValue)
		resp, err := bilbo.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := rename(out.Passkey.ID, `{"name":"new name"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("rename returned %d: %s", resp.StatusCode, body)
	}
	var renamed passkeySummary
	if err := json.NewDecoder(resp.Body).Decode(&renamed); err != nil {
		t.Fatal(err)
	}
	if renamed.Name != "new name" {
		t.Errorf("renamed passkey name = %q, want %q", renamed.Name, "new name")
	}
	if list := passkeysList(t, bilbo, ts); len(list) != 1 || list[0].Name != "new name" {
		t.Errorf("passkey list after rename = %+v, want the new name to stick", list)
	}

	for _, tc := range []struct {
		id, body string
		want     int
	}{
		{base64.RawURLEncoding.EncodeToString([]byte("no-such-credential")), `{"name":"x"}`, http.StatusNotFound},
		{"not!base64", `{"name":"x"}`, http.StatusBadRequest},
		{out.Passkey.ID, `{"name":1}`, http.StatusBadRequest},
	} {
		r := rename(tc.id, tc.body)
		_ = r.Body.Close()
		if r.StatusCode != tc.want {
			t.Errorf("rename %s with %s got %d, want %d", tc.id, tc.body, r.StatusCode, tc.want)
		}
	}
}

// TestPasskeyCapAndNameBound: an 11th passkey is refused with 409.
func TestPasskeyCapAndNameBound(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	for i := range 10 {
		registerPasskey(t, bilbo, ts, g, fmt.Sprintf("key-%d", i))
	}
	creation := passkeyRegisterBegin(t, bilbo, ts)
	resp := passkeyRegisterFinishRaw(t, bilbo, ts, newFake(g), creation, "eleventh")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("an 11th passkey got %d, want 409", resp.StatusCode)
	}
}

func TestPasskeyNameIsTruncatedNotRefused(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	_, out := registerPasskey(t, bilbo, ts, g, strings.Repeat("x", 65))
	if got := len([]rune(out.Passkey.Name)); got != 64 {
		t.Errorf("a 65-rune name was stored as %d runes, want 64", got)
	}
}

// TestPasskeyRecoveryCodeMintOnce: whichever factor is enrolled first
// mints the ten codes (held with it until confirmed, #58), and the
// second is added live and reuses them.
func TestPasskeyRecoveryCodeMintOnce(t *testing.T) {
	t.Run("passkey first, TOTP confirm reuses the same codes", func(t *testing.T) {
		g, ts, _ := passkeyFixture(t)
		bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
		_, out := registerPasskey(t, bilbo, ts, g, "first")
		if len(out.RecoveryCodes) != 10 {
			t.Fatalf("passkey-first registration should mint codes, got %d", len(out.RecoveryCodes))
		}
		id := passkeyBilboID(t, g)
		before, ok := g.deps.Users.Get(id)
		if !ok {
			t.Fatal("bilbo account vanished")
		}

		enrolled := totpEnrolAs(t, bilbo, ts, passkeyBilboPassword)
		secret, err := gauntlet.DecodeTOTPSecret(enrolled.Secret)
		if err != nil {
			t.Fatal(err)
		}
		code := gauntlet.GenerateTOTPCode(secret, totpCounterNow(time.Now()))
		resp := postJSON(t, bilbo, ts.URL+"/api/auth/totp/confirm", totpConfirmRequest{Code: code})
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("TOTP confirm returned %d: %s", resp.StatusCode, body)
		}
		var confirmOut totpConfirmResponse
		if err := json.NewDecoder(resp.Body).Decode(&confirmOut); err != nil {
			t.Fatal(err)
		}
		if !confirmOut.AlreadyIssued || confirmOut.RecoveryCodes != nil {
			t.Errorf("TOTP confirm after an existing passkey = %+v, want alreadyIssued true and recoveryCodes null", confirmOut)
		}
		after, ok := g.deps.Users.Get(id)
		if !ok {
			t.Fatal("bilbo account vanished")
		}
		if !reflect.DeepEqual(before.RecoveryCodes, after.RecoveryCodes) {
			t.Error("the original recovery-code hashes changed after a second factor activation")
		}
	})

	t.Run("TOTP first, passkey registration reuses the same codes", func(t *testing.T) {
		g, ts, _ := passkeyFixture(t)
		bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
		enrolled := totpEnrolAs(t, bilbo, ts, passkeyBilboPassword)
		secret, err := gauntlet.DecodeTOTPSecret(enrolled.Secret)
		if err != nil {
			t.Fatal(err)
		}
		confirm := postJSON(t, bilbo, ts.URL+"/api/auth/totp/confirm", totpConfirmRequest{Code: gauntlet.GenerateTOTPCode(secret, totpCounterNow(time.Now()))})
		_ = confirm.Body.Close()
		if confirm.StatusCode != http.StatusOK {
			t.Fatalf("TOTP confirm returned %d", confirm.StatusCode)
		}
		confirmEnrolmentOK(t, bilbo, ts)
		id := passkeyBilboID(t, g)
		before, ok := g.deps.Users.Get(id)
		if !ok || len(before.RecoveryCodes) != 10 {
			t.Fatal("TOTP-first confirm should have minted codes")
		}

		_, out := registerPasskey(t, bilbo, ts, g, "second")
		if out.RecoveryCodes != nil || !out.AlreadyIssued {
			t.Errorf("passkey registration after an existing TOTP factor = %+v, want recoveryCodes null and alreadyIssued", out)
		}
		after, ok := g.deps.Users.Get(id)
		if !ok {
			t.Fatal("bilbo account vanished")
		}
		if !reflect.DeepEqual(before.RecoveryCodes, after.RecoveryCodes) {
			t.Error("the original recovery-code hashes changed after a second factor activation")
		}
	})
}

// totpEnrolAs is totpEnrol with the password given, for accounts other
// than totp_handler_test.go's bob.
func totpEnrolAs(t *testing.T, client *http.Client, ts *httptest.Server, password string) totpEnrolResponse {
	t.Helper()
	resp := postJSON(t, client, ts.URL+"/api/auth/totp/enrol", totpEnrolRequest{Password: password})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("enrol returned %d: %s", resp.StatusCode, body)
	}
	var out totpEnrolResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestAFirstPasskeyWhoseHoldCannotBeSavedHoldsNothing: the first
// passkey and its recovery codes are one write (#58), so a failed save
// leaves neither -- a 500, no passkey, no hold, no codes, nothing
// rotated and nothing audited -- where the old two-write order left a
// live passkey with no codes behind it.
func TestAFirstPasskeyWhoseHoldCannotBeSavedHoldsNothing(t *testing.T) {
	g := passkeyGate(t)
	backend := &budgetBackend{inner: persist.NewMemory(), left: -1}
	g.deps.Users = openTrackedStore(t, backend)
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")
	_ = postJSON(t, admin, ts.URL+"/api/auth/users",
		createUserRequest{Username: passkeyBilboUsername, Password: passkeyBilboPassword, Role: "user"}).Body.Close()

	browser := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	otherDevice := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	creation := passkeyRegisterBegin(t, browser, ts)

	backend.left = 0 // the hold's one save fails
	resp := passkeyRegisterFinishRaw(t, browser, ts, newFake(g), creation, "YubiKey")
	backend.left = -1
	wantProblem(t, resp, http.StatusInternalServerError, classServerError)

	u, _ := g.deps.Users.Get(passkeyBilboID(t, g))
	if len(u.Passkeys) != 0 || len(u.RecoveryCodes) != 0 || u.HeldEnrolment != nil {
		t.Fatalf("after a failed hold: passkeys=%d codes=%d held=%+v, want nothing", len(u.Passkeys), len(u.RecoveryCodes), u.HeldEnrolment)
	}
	if !sessionOf(t, otherDevice, ts).Authenticated || !sessionOf(t, browser, ts).Authenticated {
		t.Error("a failed hold ended a session")
	}
	if hasAuditEntry(g, "account.passkey_added", passkeyBilboUsername) {
		t.Error("a failed hold was audited as a passkey added")
	}
	// Nothing is half done: the same browser simply registers again.
	_, out := registerPasskeyHeld(t, browser, ts, g, "YubiKey")
	if !out.PendingConfirmation || len(out.RecoveryCodes) != 10 {
		t.Errorf("registering again = %+v, want a held passkey with ten codes", out)
	}
}

// TestPasskeyClearConditionalKeepsRecoveryCodes: removing one factor
// while the other remains must not strip the codes backing it.
func TestPasskeyClearConditionalKeepsRecoveryCodes(t *testing.T) {
	t.Run("clearing TOTP keeps codes while a passkey remains", func(t *testing.T) {
		g, ts, _ := passkeyFixture(t)
		bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
		enrolled := totpEnrolAs(t, bilbo, ts, passkeyBilboPassword)
		secret, err := gauntlet.DecodeTOTPSecret(enrolled.Secret)
		if err != nil {
			t.Fatal(err)
		}
		_ = postJSON(t, bilbo, ts.URL+"/api/auth/totp/confirm", totpConfirmRequest{Code: gauntlet.GenerateTOTPCode(secret, totpCounterNow(time.Now()))}).Body.Close()
		confirmEnrolmentOK(t, bilbo, ts)
		registerPasskey(t, bilbo, ts, g, "backup key")

		del := deleteJSON(t, bilbo, ts.URL+"/api/auth/totp", totpDeleteRequest{Password: passkeyBilboPassword})
		_ = del.Body.Close()
		if del.StatusCode != http.StatusOK {
			t.Fatalf("clearing TOTP returned %d, want 200", del.StatusCode)
		}
		if u, ok := g.deps.Users.Get(passkeyBilboID(t, g)); !ok || len(u.RecoveryCodes) == 0 {
			t.Error("recovery codes were cleared even though a passkey remains")
		}
	})

	t.Run("deleting the last passkey keeps codes while TOTP remains active", func(t *testing.T) {
		g, ts, _ := passkeyFixture(t)
		bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
		_, out := registerPasskey(t, bilbo, ts, g, "only key")
		enrolled := totpEnrolAs(t, bilbo, ts, passkeyBilboPassword)
		secret, err := gauntlet.DecodeTOTPSecret(enrolled.Secret)
		if err != nil {
			t.Fatal(err)
		}
		confirm := postJSON(t, bilbo, ts.URL+"/api/auth/totp/confirm", totpConfirmRequest{Code: gauntlet.GenerateTOTPCode(secret, totpCounterNow(time.Now()))})
		_ = confirm.Body.Close()
		if confirm.StatusCode != http.StatusOK {
			t.Fatalf("TOTP confirm returned %d", confirm.StatusCode)
		}

		del := deleteJSON(t, bilbo, ts.URL+"/api/auth/passkeys/"+out.Passkey.ID, passkeyDeleteRequest{Password: passkeyBilboPassword})
		_ = del.Body.Close()
		if del.StatusCode != http.StatusOK {
			t.Fatalf("deleting the passkey returned %d", del.StatusCode)
		}
		if u, ok := g.deps.Users.Get(passkeyBilboID(t, g)); !ok || len(u.RecoveryCodes) == 0 {
			t.Error("recovery codes were cleared even though TOTP remains active")
		}
	})
}

// TestPasskeyAdminClear: the admin route removes every one of a
// colleague's passkeys, is audited, and leaves the account able to sign
// in with its password alone.
func TestPasskeyAdminClear(t *testing.T) {
	g, ts, admin := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	registerPasskey(t, bilbo, ts, g, "key")
	id := passkeyBilboID(t, g)

	resp := deleteJSON(t, admin, ts.URL+"/api/auth/users/"+id+"/passkeys", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("admin clear returned %d: %s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["username"] != passkeyBilboUsername || out["cleared"] != true {
		t.Errorf("admin clear body = %v", out)
	}
	if g.deps.Users.PasskeyCount(id) != 0 {
		t.Error("expected every passkey to be cleared")
	}
	if entry := findAuditEntry(t, g, "user.passkeys_cleared"); entry.Target != passkeyBilboUsername || entry.Actor != "admin" {
		t.Errorf("user.passkeys_cleared entry = %+v, want admin acting on %s", entry, passkeyBilboUsername)
	}
	plain := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	if sess := sessionOf(t, plain, ts); !sess.Authenticated {
		t.Error("expected a plain password login to work once the admin cleared every passkey")
	}

	missing := deleteJSON(t, admin, ts.URL+"/api/auth/users/no-such-id/passkeys", nil)
	_ = missing.Body.Close()
	if missing.StatusCode != http.StatusNotFound {
		t.Errorf("clearing an unknown user got %d, want 404", missing.StatusCode)
	}
	notAdmin := deleteJSON(t, plain, ts.URL+"/api/auth/users/"+id+"/passkeys", nil)
	_ = notAdmin.Body.Close()
	if notAdmin.StatusCode != http.StatusForbidden {
		t.Errorf("a non-admin clearing passkeys got %d, want 403", notAdmin.StatusCode)
	}
}

func TestPasskeyAdminCannotClearOwnPasskeys(t *testing.T) {
	g, ts, admin := passkeyFixture(t)
	u, ok := g.deps.Users.ByUsername("admin")
	if !ok {
		t.Fatal("no admin account")
	}
	resp := deleteJSON(t, admin, ts.URL+"/api/auth/users/"+u.ID+"/passkeys", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("an admin clearing their own passkeys got %d, want 409", resp.StatusCode)
	}
}

// TestPasskeySessionAndUserListSurfaces: GET /api/auth/session's
// passkeys.count and GET /api/auth/users' passkeyCount both ask the
// store, not a List() copy whose Passkeys List blanks.
func TestPasskeySessionAndUserListSurfaces(t *testing.T) {
	g, ts, admin := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)

	before := sessionOf(t, bilbo, ts)
	if before.Passkeys == nil || before.Passkeys.Count != 0 {
		t.Fatalf("session passkeys before registering = %+v, want count 0", before.Passkeys)
	}
	if before.Passkeys.Status != gauntlet.PasskeyStatusReady || before.Passkeys.Origin != passkeyTestPublicURL {
		t.Errorf("session passkeys status/origin = %+v, want ready at %s", before.Passkeys, passkeyTestPublicURL)
	}

	registerPasskey(t, bilbo, ts, g, "key one")
	registerPasskey(t, bilbo, ts, g, "key two")

	if after := sessionOf(t, bilbo, ts); after.Passkeys == nil || after.Passkeys.Count != 2 {
		t.Errorf("session passkeys after registering two = %+v, want count 2", after.Passkeys)
	}
	if listed := listedPasskeyCount(t, admin, ts, passkeyBilboUsername); listed != 2 {
		t.Errorf("admin user list passkeyCount for %s = %d, want 2", passkeyBilboUsername, listed)
	}
	if adminCount := listedPasskeyCount(t, admin, ts, "admin"); adminCount != 0 {
		t.Errorf("admin user list reports %d passkeys for the admin, who never registered one", adminCount)
	}

	g.deps.Passkeys = mustRelyingParty(t, "https://192.0.2.10")
	if s := sessionOf(t, bilbo, ts); s.Passkeys == nil || s.Passkeys.Status != gauntlet.PasskeyStatusIP || s.Passkeys.Origin != "" {
		t.Errorf("session passkeys with an IP public URL = %+v, want status ip and no origin", s.Passkeys)
	}
}

func listedPasskeyCount(t *testing.T, admin *http.Client, ts *httptest.Server, username string) int {
	t.Helper()
	resp, err := admin.Get(ts.URL + "/api/auth/users")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out []userSummary
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	for _, u := range out {
		if u.Username == username {
			return u.PasskeyCount
		}
	}
	t.Fatalf("no row for %q in the user list", username)
	return -1
}

// TestPasskeyLoginFactorBeginIsRateLimited: starting a passkey prompt
// spends the pending login like every other second-step request -- the
// same reservations on the same keys, refused once they run out.
func TestPasskeyLoginFactorBeginIsRateLimited(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	registerPasskey(t, bilbo, ts, g, "YubiKey")
	pending := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)

	const threshold = 3
	g.deps.Limiter = mustNewLoginLimiter(t, threshold, time.Minute)
	for range threshold {
		passkeyLoginFactorBegin(t, pending, ts)
	}
	resp := postJSON(t, pending, ts.URL+"/api/auth/login/factor/begin", struct{}{})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("begin number %d got %d, want 429 once the sign-in limiter is spent", threshold+1, resp.StatusCode)
	}
	if g.deps.Limiter.Allow("ip:198.51.100.1", time.Now()) {
		t.Error("the begins were not counted against the address, the key the other steps share")
	}
	if g.deps.Limiter.ReserveAccount(g.deps.Users, passkeyBilboID(t, g), time.Now()) {
		t.Error("the begins were not counted against the account, the key the other steps share")
	}
}

// TestPasskeyLoginGivesTheBeginReservationBack: a passkey prompt that
// ends in a sign-in leaves nothing counted.
func TestPasskeyLoginGivesTheBeginReservationBack(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	fake, _ := registerPasskey(t, bilbo, ts, g, "YubiKey")
	pending := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)

	const threshold = 2
	g.deps.Limiter = mustNewLoginLimiter(t, threshold, time.Minute)
	resp := submitPasskeyAssertion(t, pending, ts, fake, passkeyLoginFactorBegin(t, pending, ts))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login/factor with a passkey assertion returned %d", resp.StatusCode)
	}

	now := time.Now()
	id := passkeyBilboID(t, g)
	for i := range threshold {
		if !g.deps.Limiter.Reserve("ip:198.51.100.1", now) {
			t.Errorf("address: only %d of %d attempts left after a successful passkey sign-in, want all of them", i, threshold)
			break
		}
	}
	for i := range threshold {
		if !g.deps.Limiter.ReserveAccount(g.deps.Users, id, now) {
			t.Errorf("account: only %d of %d attempts left after a successful passkey sign-in, want all of them", i, threshold)
			break
		}
	}
}

// -- cases gate adds (ADR-0004) -------------------------------------------

// TestPasskeyRoutesAnswer404WhenPasskeysAreOff: with Deps.Passkeys nil
// every passkey route answers 404, the session body has no "passkeys",
// and the password step never offers "passkey" -- even for an account
// that holds one (carried over from another deployment's documents).
func TestPasskeyRoutesAnswer404WhenPasskeysAreOff(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")
	_ = postJSON(t, admin, ts.URL+"/api/auth/users",
		createUserRequest{Username: passkeyBilboUsername, Password: passkeyBilboPassword, Role: "user"}).Body.Close()
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	id := passkeyBilboID(t, g)
	// Most of the routes below are not enrolment routes, so bilbo needs a
	// second factor to reach them at all -- a stored passkey credential,
	// not TOTP, so it stands in for exactly the carried-over-data case
	// this test is about (see the doc comment above) rather than adding
	// a TOTP factor that would taint the login's offered-factors check
	// further down.
	if _, err := g.deps.Users.AddPasskey(id, gauntlet.Passkey{ID: []byte("pre-existing-credential"), RPID: "passkeys.example.org", Name: "pre-existing"}); err != nil {
		t.Fatal(err)
	}
	credID := base64.RawURLEncoding.EncodeToString([]byte("carried-over-credential"))

	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/api/auth/passkeys", nil},
		{http.MethodPost, "/api/auth/passkeys/register/begin", passkeyRegisterBeginRequest{Password: passkeyBilboPassword}},
		{http.MethodPost, "/api/auth/passkeys/register/finish", passkeyRegisterFinishRequest{Credential: json.RawMessage(`{}`)}},
		{http.MethodPatch, "/api/auth/passkeys/" + credID, passkeyRenameRequest{Name: "x"}},
		{http.MethodDelete, "/api/auth/passkeys/" + credID, passkeyDeleteRequest{Password: passkeyBilboPassword}},
		{http.MethodPost, "/api/auth/login/factor/begin", struct{}{}},
		{http.MethodPost, "/api/auth/login/factor", loginFactorRequest{Assertion: json.RawMessage(`{"id":"x"}`)}},
		{http.MethodDelete, "/api/auth/users/" + id + "/passkeys", nil},
	} {
		client := bilbo
		if strings.HasPrefix(tc.path, "/api/auth/users/") {
			client = admin
		}
		var resp *http.Response
		if tc.body == nil && tc.method == http.MethodGet {
			r, err := client.Get(ts.URL + tc.path)
			if err != nil {
				t.Fatal(err)
			}
			resp = r
		} else {
			resp = doJSON(t, client, tc.method, ts.URL+tc.path, tc.body)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s with passkeys off got %d, want 404", tc.method, tc.path, resp.StatusCode)
		}
	}

	resp, err := bilbo.Get(ts.URL + "/api/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if _, has := raw["passkeys"]; has || raw["authenticated"] != true {
		t.Errorf("session body with passkeys off = %v, want authenticated and no passkeys key", raw)
	}

	if _, err := g.deps.Users.AddPasskey(id, gauntlet.Passkey{ID: []byte("carried-over-credential"), RPID: "passkeys.example.org", Name: "old"}); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: mustCookieJar(t)}
	login := postJSON(t, client, ts.URL+"/api/auth/login", credentialsRequest{Username: passkeyBilboUsername, Password: passkeyBilboPassword})
	var out map[string]any
	if err := json.NewDecoder(login.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	_ = login.Body.Close()
	if factors, _ := out["secondFactor"].([]any); factors == nil || len(factors) != 0 {
		t.Errorf("password step with passkeys off = %v, want an empty secondFactor list", out)
	}
	if _, has := out["passkeyOrigin"]; has {
		t.Errorf("password step with passkeys off offered passkeyOrigin: %v", out)
	}
}

// TestPasskeyRegisterCeremonyEndsAtAStoreRefusal (ruling S1 on #20,
// superseding addendum 1's B): a finish the library accepts spends the
// ceremony even when the store then refuses it. Finishing with an
// authenticator already on the account is a 409 duplicate that clears
// the ceremony cookie, and a further finish on a kept copy of it -- even
// with another authenticator -- answers 401.
func TestPasskeyRegisterCeremonyEndsAtAStoreRefusal(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	fakeA, _ := registerPasskey(t, bilbo, ts, g, "A")

	begin := postJSON(t, bilbo, ts.URL+"/api/auth/passkeys/register/begin", passkeyRegisterBeginRequest{Password: passkeyBilboPassword})
	var creation protocol.CredentialCreation
	if err := json.NewDecoder(begin.Body).Decode(&creation); err != nil {
		t.Fatal(err)
	}
	_ = begin.Body.Close()
	var sealed *http.Cookie
	for _, c := range begin.Cookies() {
		if c.Name == passkeyRegisterCookieName {
			sealed = c
		}
	}
	if sealed == nil || sealed.Path != passkeysPath || sealed.MaxAge != 300 || !sealed.HttpOnly {
		t.Fatalf("register/begin's ceremony cookie = %+v, want %s on %s for 300s, HttpOnly", sealed, passkeyRegisterCookieName, passkeysPath)
	}

	dup := passkeyRegisterFinishRaw(t, bilbo, ts, fakeA, &creation, "A again")
	_ = dup.Body.Close()
	if dup.StatusCode != http.StatusConflict {
		t.Fatalf("finishing with an authenticator already on the account got %d, want 409", dup.StatusCode)
	}
	if !cookieCleared(dup, passkeyRegisterCookieName) {
		t.Error("a duplicate refusal did not clear the spent ceremony cookie")
	}

	body, err := newFake(g).RegisterResponse(&creation)
	if err != nil {
		t.Fatal(err)
	}
	resp, raw := postWithCookie(t, bilbo, ts.URL+"/api/auth/passkeys/register/finish",
		passkeyRegisterFinishRequest{Credential: json.RawMessage(body), Name: "B"},
		&http.Cookie{Name: sealed.Name, Value: sealed.Value})
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(raw, "start registration again") {
		t.Errorf("a finish on a kept copy of the spent ceremony got %d %q, want 401 start registration again", resp.StatusCode, raw)
	}
	if n := g.deps.Users.PasskeyCount(passkeyBilboID(t, g)); n != 1 {
		t.Errorf("the account holds %d passkeys, want 1", n)
	}
	// The body is judged before the cookie, so a spent cookie with a
	// malformed body is a 400 that leaves the cookie for the next
	// request to clear.
	resp, raw = postWithCookie(t, bilbo, ts.URL+"/api/auth/passkeys/register/finish",
		map[string]any{"unknown": 1}, &http.Cookie{Name: sealed.Name, Value: sealed.Value})
	if resp.StatusCode != http.StatusBadRequest || cookieCleared(resp, passkeyRegisterCookieName) {
		t.Errorf("a spent ceremony cookie with a malformed body got %d %q, want 400 with the cookie left alone", resp.StatusCode, raw)
	}
}

// inProcess serves a client's requests straight from a handler, with no
// network in between -- what lets TestPasskeyRegisterExpiredCeremony run
// inside a synctest bubble, where time moves only when every goroutine
// is blocked on something the bubble controls.
type inProcess struct{ h http.Handler }

func (p inProcess) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	p.h.ServeHTTP(rec, req)
	return rec.Result(), nil
}

// TestPasskeyRegisterExpiredCeremony: a registration finished after its
// five minutes is refused, with the ceremony cookie sent anyway (a
// browser would have dropped it; an attacker holding a copy would not),
// so the refusal is the sealed expiry, not the missing cookie. Paired
// with the same flow a second inside the window succeeding.
func TestPasskeyRegisterExpiredCeremony(t *testing.T) {
	for _, wait := range []time.Duration{passkeyCeremonyCookieMaxAge - time.Second, passkeyCeremonyCookieMaxAge + time.Second} {
		expired := wait > passkeyCeremonyCookieMaxAge
		synctest.Test(t, func(t *testing.T) {
			g := passkeyGate(t)
			mux := http.NewServeMux()
			mux.Handle("/", g.Routes())
			const base = "http://gate.test"
			client := &http.Client{Jar: mustCookieJar(t), Transport: inProcess{g.Protect(mux)}}

			reg := postJSON(t, client, base+"/api/auth/register", registerRequest{Username: "admin", Password: "password-placeholder-1", SetupCode: setupCodeFor(t, g)})
			_ = reg.Body.Close()
			if reg.StatusCode != http.StatusCreated {
				t.Fatalf("register returned %d", reg.StatusCode)
			}

			begin := postJSON(t, client, base+"/api/auth/passkeys/register/begin", passkeyRegisterBeginRequest{Password: "password-placeholder-1"})
			var creation protocol.CredentialCreation
			if err := json.NewDecoder(begin.Body).Decode(&creation); err != nil {
				t.Fatal(err)
			}
			_ = begin.Body.Close()
			var sealed string
			for _, c := range begin.Cookies() {
				if c.Name == passkeyRegisterCookieName {
					sealed = c.Value
				}
			}
			body, err := newFake(g).RegisterResponse(&creation)
			if err != nil {
				t.Fatal(err)
			}

			time.Sleep(wait)

			b, err := json.Marshal(passkeyRegisterFinishRequest{Credential: json.RawMessage(body), Name: "late"})
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest(http.MethodPost, base+"/api/auth/passkeys/register/finish", bytes.NewReader(b))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(csrfHeaderName, testCSRFValue)
			req.AddCookie(&http.Cookie{Name: passkeyRegisterCookieName, Value: sealed})
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()

			want := http.StatusOK
			if expired {
				want = http.StatusUnauthorized
			}
			if resp.StatusCode != want {
				t.Errorf("register/finish %v after begin got %d, want %d", wait, resp.StatusCode, want)
			}
			if expired && !cookieCleared(resp, passkeyRegisterCookieName) {
				t.Error("an expired registration did not clear its ceremony cookie")
			}
			admin, _ := g.deps.Users.ByUsername("admin")
			if n, wantN := storedPasskeys(g, admin.ID), map[bool]int{true: 0, false: 1}[expired]; n != wantN {
				t.Errorf("after a finish %v late the account holds %d passkeys, want %d", wait, n, wantN)
			}
		})
	}
}

// TestPasskeyLoginFactorBeginNeedsAPendingLogin: begin is reached
// without a session, so the pending-login cookie is all that stands in
// for one -- missing, forged or naming a deleted account, it is refused
// before any challenge is minted. An assertion sent with no begin
// behind it is refused the same way.
func TestPasskeyLoginFactorBeginNeedsAPendingLogin(t *testing.T) {
	g, ts, admin := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	fake, _ := registerPasskey(t, bilbo, ts, g, "key")

	anon := &http.Client{Jar: mustCookieJar(t)}
	if got := postStatus(t, anon, ts.URL+"/api/auth/login/factor/begin"); got != http.StatusUnauthorized {
		t.Errorf("begin with no pending login got %d, want 401", got)
	}

	forged, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/login/factor/begin", nil)
	if err != nil {
		t.Fatal(err)
	}
	forged.Header.Set(csrfHeaderName, testCSRFValue)
	forged.AddCookie(&http.Cookie{Name: pendingLoginCookieName, Value: "forged"})
	resp, err := http.DefaultClient.Do(forged)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("begin with a forged pending login got %d, want 401", resp.StatusCode)
	}

	// An assertion with no begin behind it: no ceremony cookie.
	pending := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	body, err := fake.AssertionResponse(&protocol.CredentialAssertion{Response: protocol.PublicKeyCredentialRequestOptions{Challenge: []byte("0123456789abcdef0123456789abcdef")}})
	if err != nil {
		t.Fatal(err)
	}
	noBegin := postJSON(t, pending, ts.URL+"/api/auth/login/factor", loginFactorRequest{Assertion: json.RawMessage(body)})
	raw, _ := io.ReadAll(noBegin.Body)
	_ = noBegin.Body.Close()
	if noBegin.StatusCode != http.StatusUnauthorized || !strings.Contains(string(raw), "start passkey sign-in again") {
		t.Errorf("an assertion with no begin got %d %q, want 401 asking to start again", noBegin.StatusCode, raw)
	}

	// The account is deleted between the password step and begin.
	gone := deleteJSON(t, admin, ts.URL+"/api/auth/users/"+passkeyBilboID(t, g), nil)
	_ = gone.Body.Close()
	if got := postStatus(t, pending, ts.URL+"/api/auth/login/factor/begin"); got != http.StatusUnauthorized {
		t.Errorf("begin for a deleted account got %d, want 401", got)
	}
}

// postStatus posts an empty JSON object and returns only the status.
func postStatus(t *testing.T, client *http.Client, url string) int {
	t.Helper()
	resp := postJSON(t, client, url, struct{}{})
	_ = resp.Body.Close()
	return resp.StatusCode
}

// cookieCleared reports whether resp tells the browser to drop name.
func cookieCleared(resp *http.Response, name string) bool {
	for _, c := range resp.Cookies() {
		if c.Name == name && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

// jarHolds reports whether client would send cookie name to path.
func jarHolds(t *testing.T, client *http.Client, ts *httptest.Server, path, name string) bool {
	t.Helper()
	u, err := url.Parse(ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == name {
			return true
		}
	}
	return false
}

// postWithCookie posts body through client with one extra cookie, as a
// client holding a forged or stale copy would send it.
func postWithCookie(t *testing.T, client *http.Client, url string, body any, cookie *http.Cookie) (*http.Response, string) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(csrfHeaderName, testCSRFValue)
	req.AddCookie(cookie)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(raw)
}

// TestPasskeyRegisterFinishDeadCeremonyClearsCookie: a ceremony cookie
// that cannot be opened is a dead ceremony -- 401 "start registration
// again", and the cookie is cleared.
func TestPasskeyRegisterFinishDeadCeremonyClearsCookie(t *testing.T) {
	_, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	resp, body := postWithCookie(t, bilbo, ts.URL+"/api/auth/passkeys/register/finish",
		passkeyRegisterFinishRequest{Credential: json.RawMessage(`{}`), Name: "x"},
		&http.Cookie{Name: passkeyRegisterCookieName, Value: "garbage"})
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "start registration again") {
		t.Errorf("finish with a garbage ceremony cookie got %d %q, want 401 asking to start again", resp.StatusCode, body)
	}
	if !cookieCleared(resp, passkeyRegisterCookieName) {
		t.Error("the dead ceremony cookie was not cleared")
	}
}

// TestPasskeyRegisterFinishRefusedCredentialKeepsCookie: a credential
// the ceremony refuses (wrong origin) answers 400 and leaves the cookie
// where it is, for a corrected attempt.
func TestPasskeyRegisterFinishRefusedCredentialKeepsCookie(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	creation := passkeyRegisterBegin(t, bilbo, ts)
	fake := newFake(g)
	fake.Origin = "https://not-the-relying-party.example"
	resp := passkeyRegisterFinishRaw(t, bilbo, ts, fake, creation, "wrong origin")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("wrong-origin finish got %d, want 400", resp.StatusCode)
	}
	if cookieCleared(resp, passkeyRegisterCookieName) || !jarHolds(t, bilbo, ts, passkeyRegisterFinishPath, passkeyRegisterCookieName) {
		t.Error("a refused credential cleared the live ceremony cookie")
	}
}

// TestPasskeyAssertionDeadCeremonyClearsCookie: an assertion carrying a
// ceremony cookie that cannot be opened answers 401 "start passkey
// sign-in again" and clears the cookie.
func TestPasskeyAssertionDeadCeremonyClearsCookie(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	registerPasskey(t, bilbo, ts, g, "key")
	pending := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	resp, body := postWithCookie(t, pending, ts.URL+"/api/auth/login/factor",
		loginFactorRequest{Assertion: json.RawMessage(`{"id":"x"}`)},
		&http.Cookie{Name: passkeyAssertCookieName, Value: "garbage"})
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, passkeyStartAgain) {
		t.Errorf("an assertion on a garbage ceremony cookie got %d %q, want 401 %q", resp.StatusCode, body, passkeyStartAgain)
	}
	if !cookieCleared(resp, passkeyAssertCookieName) {
		t.Error("the dead ceremony cookie was not cleared")
	}
}

// TestPasskeyAssertionRefusedKeepsCookie: an assertion the ceremony
// refuses (wrong RP ID) answers 401 "couldn't be verified" and keeps
// the live cookie.
func TestPasskeyAssertionRefusedKeepsCookie(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	fake, _ := registerPasskey(t, bilbo, ts, g, "key")
	fake.RPID = "not-the-relying-party.example"
	pending := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	resp := submitPasskeyAssertion(t, pending, ts, fake, passkeyLoginFactorBegin(t, pending, ts))
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(raw), passkeyNotVerified) {
		t.Errorf("a wrong-RPID assertion got %d %q, want 401 %q", resp.StatusCode, raw, passkeyNotVerified)
	}
	if cookieCleared(resp, passkeyAssertCookieName) || !jarHolds(t, pending, ts, loginFactorPath, passkeyAssertCookieName) {
		t.Error("a refused assertion cleared the live ceremony cookie")
	}
}

// TestPasskeyCounterSaveFailureDoesNotSpendBudget: a counter that cannot
// be saved is the backend failing, not a wrong guess, so it hands back
// this request's reservation and the one login/factor/begin took for its
// challenge. Five such failures in a row -- the limiter's threshold --
// must leave the account free to sign in. Ported from the #20 review.
func TestPasskeyCounterSaveFailureDoesNotSpendBudget(t *testing.T) {
	g := passkeyGate(t)
	backend := &budgetBackend{inner: persist.NewMemory(), left: -1}
	g.deps.Users = openTrackedStore(t, backend)
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")
	_ = postJSON(t, admin, ts.URL+"/api/auth/users",
		createUserRequest{Username: passkeyBilboUsername, Password: passkeyBilboPassword, Role: "user"}).Body.Close()
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	fake, _ := registerPasskey(t, bilbo, ts, g, "key")

	for i := range 5 { // newTestGate's limiter threshold
		fake.SignCount = uint32(i + 1) // counting, so the save matters
		pending := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
		options := passkeyLoginFactorBegin(t, pending, ts)
		backend.left = 0
		resp := submitPasskeyAssertion(t, pending, ts, fake, options)
		backend.left = -1
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("cycle %d: got %d %q, want 500", i, resp.StatusCode, body)
		}
	}
	client := &http.Client{Jar: mustCookieJar(t)}
	resp := postJSON(t, client, ts.URL+"/api/auth/login", credentialsRequest{Username: passkeyBilboUsername, Password: passkeyBilboPassword})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("after 5 backend failures and no wrong guess, the password step got %d, want 200", resp.StatusCode)
	}
}

// TestPasskeyRegisterBeginNeedsThePassword (ruling R1 on #20, from the
// review's TestReviewSessionThiefPlantsPasskeyWithoutPassword): a caller
// holding only the session cookie cannot start a registration. A wrong
// password is 401 and no body is 400; neither sets a ceremony cookie,
// stores a passkey, mints recovery codes or ends the owner's session.
// Once the per-account re-check budget is spent the answer is 429.
func TestPasskeyRegisterBeginNeedsThePassword(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	owner := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	thief := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword) // stands in for a stolen cookie
	id := passkeyBilboID(t, g)

	wrong := postJSON(t, thief, ts.URL+"/api/auth/passkeys/register/begin", passkeyRegisterBeginRequest{Password: "not-the-password"})
	_ = wrong.Body.Close()
	if wrong.StatusCode != http.StatusUnauthorized {
		t.Errorf("register/begin with a wrong password got %d, want 401", wrong.StatusCode)
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/passkeys/register/begin", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(csrfHeaderName, testCSRFValue)
	noBody, err := thief.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = noBody.Body.Close()
	if noBody.StatusCode != http.StatusBadRequest {
		t.Errorf("register/begin with no body got %d, want 400", noBody.StatusCode)
	}
	for _, resp := range []*http.Response{wrong, noBody} {
		for _, c := range resp.Cookies() {
			if c.Name == passkeyRegisterCookieName && c.MaxAge > 0 {
				t.Errorf("a refused register/begin set a ceremony cookie (%d)", resp.StatusCode)
			}
		}
	}
	if jarHolds(t, thief, ts, passkeyRegisterFinishPath, passkeyRegisterCookieName) {
		t.Error("the thief holds a registration ceremony cookie")
	}
	u, ok := g.deps.Users.Get(id)
	if !ok || len(u.Passkeys) != 0 || len(u.RecoveryCodes) != 0 {
		t.Errorf("after refused begins the account holds %d passkeys and %d recovery codes, want none", len(u.Passkeys), len(u.RecoveryCodes))
	}
	if !sessionOf(t, owner, ts).Authenticated {
		t.Error("the owner's session did not survive the refused begins")
	}

	g.deps.Limiter = mustNewLoginLimiter(t, 1, time.Minute)
	_ = postJSON(t, thief, ts.URL+"/api/auth/passkeys/register/begin", passkeyRegisterBeginRequest{Password: "not-the-password"}).Body.Close()
	limited := postJSON(t, thief, ts.URL+"/api/auth/passkeys/register/begin", passkeyRegisterBeginRequest{Password: passkeyBilboPassword})
	_ = limited.Body.Close()
	if limited.StatusCode != http.StatusTooManyRequests {
		t.Errorf("register/begin after the re-check budget was spent got %d, want 429", limited.StatusCode)
	}
}

// TestPasskeyAssertionFromAnotherAccountIsRefused (ruling R3 on #20):
// with no allowed-credential list sealed into the ceremony, a passkey
// that belongs to another account is still refused at login/factor --
// paired with that passkey signing its own account in.
func TestPasskeyAssertionFromAnotherAccountIsRefused(t *testing.T) {
	g, ts, admin := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	registerPasskey(t, bilbo, ts, g, "bilbo's key")
	const frodoPassword = "frodo-passkey-password-placeholder"
	_ = postJSON(t, admin, ts.URL+"/api/auth/users", createUserRequest{Username: "frodo", Password: frodoPassword, Role: "user"}).Body.Close()
	frodo := loggedInClient(t, ts, "frodo", frodoPassword)
	creation := passkeyRegisterBeginAs(t, frodo, ts, frodoPassword)
	frodoKey := newFake(g)
	passkeyRegisterFinishOK(t, frodo, ts, frodoKey, creation, "frodo's key")
	confirmEnrolmentOK(t, frodo, ts)

	pending := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	resp := submitPasskeyAssertion(t, pending, ts, frodoKey, passkeyLoginFactorBegin(t, pending, ts))
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(raw), passkeyNotVerified) {
		t.Errorf("frodo's passkey on bilbo's sign-in got %d %q, want 401 %q", resp.StatusCode, raw, passkeyNotVerified)
	}
	if sessionOf(t, pending, ts).Authenticated {
		t.Fatal("another account's passkey signed bilbo in")
	}

	own := startPasskeyLogin(t, ts, "frodo", frodoPassword)
	ok := submitPasskeyAssertion(t, own, ts, frodoKey, passkeyLoginFactorBegin(t, own, ts))
	_ = ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Errorf("frodo's passkey on frodo's own sign-in got %d, want 200", ok.StatusCode)
	}
}

// passkeyRegisterBeginAs is passkeyRegisterBegin for an account other
// than bilbo.
func passkeyRegisterBeginAs(t *testing.T, client *http.Client, ts *httptest.Server, password string) *protocol.CredentialCreation {
	t.Helper()
	resp := postJSON(t, client, ts.URL+"/api/auth/passkeys/register/begin", passkeyRegisterBeginRequest{Password: password})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("register/begin returned %d: %s", resp.StatusCode, body)
	}
	var out protocol.CredentialCreation
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return &out
}

// TestPasskeyNotOfferedToAnAccountWithNoLocalPassword (ruling R4 on
// #20): an SSO-only account is refused at register/begin with 409,
// before any body is read, as TOTP enrolment refuses it. A passkey such
// an account already holds -- here hand-written into the accounts
// document, as mikroview's data or a converted account could carry one
// -- is still removed by the admin clear route.
func TestPasskeyNotOfferedToAnAccountWithNoLocalPassword(t *testing.T) {
	g := passkeyGate(t)
	hash, err := gauntlet.HashPassword("password-placeholder-1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	g.deps.Users = openStoreWithUsers(t, gauntlet.User{
		// TOTPSecret/TOTPConfirmedAt give admin-1 an active second factor
		// (gauntlet.User.HasActiveTOTP) so it clears the forced-enrolment
		// door for the DELETE below -- no code is ever verified against
		// this secret, so its value does not matter.
		ID: "admin-1", Username: "admin", PasswordHash: hash, Role: gauntlet.RoleAdmin,
		CreatedAt: now, HasLocalPassword: true,
		TOTPSecret: "placeholder-secret", TOTPConfirmedAt: now,
	}, gauntlet.User{
		ID: "sso-1", Username: "sam", Role: gauntlet.RoleUser, CreatedAt: now,
		OIDCIssuer: "https://idp.example.org", OIDCSubject: "sam-subject",
		Passkeys: []gauntlet.Passkey{{ID: []byte("carried-over"), RPID: g.deps.Passkeys.RPID(), Name: "old key", CreatedAt: now}},
	})
	ts := newTestServer(t, g)
	asSession := func(userID string) *http.Client {
		jar := mustCookieJar(t)
		u, err := url.Parse(ts.URL)
		if err != nil {
			t.Fatal(err)
		}
		jar.SetCookies(u, []*http.Cookie{{Name: testCookieName, Value: g.deps.Sessions.Create(userID, now).ID, Path: "/"}})
		return &http.Client{Jar: jar}
	}
	sam, admin := asSession("sso-1"), asSession("admin-1")

	for name, body := range map[string]any{"with a password": passkeyRegisterBeginRequest{Password: "anything"}, "with no body": nil} {
		var resp *http.Response
		if body == nil {
			req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/passkeys/register/begin", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(csrfHeaderName, testCSRFValue)
			if resp, err = sam.Do(req); err != nil {
				t.Fatal(err)
			}
		} else {
			resp = postJSON(t, sam, ts.URL+"/api/auth/passkeys/register/begin", body)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusConflict || !strings.Contains(string(raw), "identity provider") {
			t.Errorf("register/begin for an SSO-only account %s got %d %q, want 409 naming the identity provider", name, resp.StatusCode, raw)
		}
	}

	if list := passkeysList(t, sam, ts); len(list) != 1 {
		t.Fatalf("the SSO account lists %d passkeys, want its carried-over one", len(list))
	}
	clear := deleteJSON(t, admin, ts.URL+"/api/auth/users/sso-1/passkeys", nil)
	_ = clear.Body.Close()
	if clear.StatusCode != http.StatusOK || g.deps.Users.PasskeyCount("sso-1") != 0 {
		t.Errorf("admin clear on the SSO account got %d and left %d passkeys, want 200 and none", clear.StatusCode, g.deps.Users.PasskeyCount("sso-1"))
	}
}

// TestPasskeyRegisterFinishJudgesTheBodyBeforeTheCookie pins the order
// ruling R5 on #20 accepts and auth.yaml documents: a malformed body is
// refused with 400 before the ceremony cookie is examined, so a dead
// cookie sent with it is not cleared by that request. (The review's
// TestReviewDeadRegisterCookieWithBadBody observed this order.)
func TestPasskeyRegisterFinishJudgesTheBodyBeforeTheCookie(t *testing.T) {
	_, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	resp, body := postWithCookie(t, bilbo, ts.URL+"/api/auth/passkeys/register/finish",
		map[string]any{"credential": map[string]any{}, "name": "x", "extra": 1},
		&http.Cookie{Name: passkeyRegisterCookieName, Value: "garbage"})
	if resp.StatusCode != http.StatusBadRequest || cookieCleared(resp, passkeyRegisterCookieName) {
		t.Errorf("dead cookie + unknown body field: got %d %q cleared=%v, want 400 with the cookie left alone", resp.StatusCode, body, cookieCleared(resp, passkeyRegisterCookieName))
	}
}

// TestPasskeyRegisterFinishBadBodyIsA400WithOrWithoutACeremony: the
// body is judged before the ceremony cookie is even looked for, so a
// malformed body is 400 whether the cookie is absent or live, and a
// live cookie survives it for a corrected finish.
func TestPasskeyRegisterFinishBadBodyIsA400WithOrWithoutACeremony(t *testing.T) {
	_, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	bad := map[string]any{"credential": map[string]any{}, "name": "x", "extra": 1}

	resp := postJSON(t, bilbo, ts.URL+passkeyRegisterFinishPath, bad)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad body with no ceremony cookie got %d, want 400", resp.StatusCode)
	}

	passkeyRegisterBegin(t, bilbo, ts)
	resp = postJSON(t, bilbo, ts.URL+passkeyRegisterFinishPath, bad)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad body with a live ceremony cookie got %d, want 400", resp.StatusCode)
	}
	if cookieCleared(resp, passkeyRegisterCookieName) || !jarHolds(t, bilbo, ts, passkeyRegisterFinishPath, passkeyRegisterCookieName) {
		t.Error("a bad body cleared the live ceremony cookie")
	}
}

// pendingCookieOf is the pending-login cookie client holds now -- taken
// before a completion clears it, as a client keeping a copy would.
func pendingCookieOf(t *testing.T, client *http.Client, ts *httptest.Server) *http.Cookie {
	t.Helper()
	u, err := url.Parse(ts.URL + pendingLoginCookiePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == pendingLoginCookieName {
			return &http.Cookie{Name: c.Name, Value: c.Value}
		}
	}
	t.Fatal("the client holds no pending-login cookie")
	return nil
}

// postRaw posts body with exactly the cookies given, through a client
// with no jar, and returns the response with its body read.
func postRaw(t *testing.T, url string, body any, cookies ...*http.Cookie) (*http.Response, string) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(csrfHeaderName, testCSRFValue)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(raw)
}

// beginWith starts a passkey sign-in on the given pending-login cookie
// and returns the options and the ceremony cookie it set, or the
// refusal's status.
func beginWith(t *testing.T, ts *httptest.Server, pending *http.Cookie) (*protocol.CredentialAssertion, *http.Cookie, int) {
	t.Helper()
	resp, raw := postRaw(t, ts.URL+"/api/auth/login/factor/begin", struct{}{}, pending)
	if resp.StatusCode != http.StatusOK {
		return nil, nil, resp.StatusCode
	}
	var options protocol.CredentialAssertion
	if err := json.Unmarshal([]byte(raw), &options); err != nil {
		t.Fatal(err)
	}
	for _, c := range resp.Cookies() {
		if c.Name == passkeyAssertCookieName {
			return &options, &http.Cookie{Name: c.Name, Value: c.Value}, resp.StatusCode
		}
	}
	t.Fatal("login/factor/begin set no ceremony cookie")
	return nil, nil, 0
}

func assertionBody(t *testing.T, fake *passkeytest.FakeAuthenticator, options *protocol.CredentialAssertion) loginFactorRequest {
	t.Helper()
	body, err := fake.AssertionResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	return loginFactorRequest{Assertion: json.RawMessage(body)}
}

// TestPendingLoginIsSpentByTheSignInItCompletes (ruling R2 on #20, from
// the review's TestReviewPendingCookieReplayMintsUnboundedPasskeyLogins):
// one correct password yields one session. One pending-login cookie,
// replayed forty times through begin and an assertion, signs in exactly
// once; after that, begin and login/factor both refuse it with 401
// "sign in again" and clear it -- login/factor even for an assertion
// answering a challenge begun before the completion.
func TestPendingLoginIsSpentByTheSignInItCompletes(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	g.deps.Limiter = mustNewLoginLimiter(t, 100, time.Minute) // the limiter is not what is being tested
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	fake, _ := registerPasskey(t, bilbo, ts, g, "key")
	pending := pendingCookieOf(t, startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword), ts)

	// A challenge begun before any completion, kept for later.
	earlyOptions, earlyCeremony, status := beginWith(t, ts, pending)
	if status != http.StatusOK {
		t.Fatalf("the first begin got %d", status)
	}

	const n = 40
	signedIn, beginRefused := 0, 0
	for range n {
		options, ceremony, status := beginWith(t, ts, pending)
		if status != http.StatusOK {
			if status != http.StatusUnauthorized {
				t.Fatalf("begin on a replayed pending login got %d, want 200 or 401", status)
			}
			beginRefused++
			continue
		}
		resp, _ := postRaw(t, ts.URL+"/api/auth/login/factor", assertionBody(t, fake, options), pending, ceremony)
		if resp.StatusCode == http.StatusOK {
			signedIn++
		}
	}
	if signedIn != 1 || beginRefused != n-1 {
		t.Errorf("%d of %d replays of one pending login signed in and %d were refused at begin, want 1 and %d", signedIn, n, beginRefused, n-1)
	}

	resp, raw := postRaw(t, ts.URL+"/api/auth/login/factor", assertionBody(t, fake, earlyOptions), pending, earlyCeremony)
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(raw, "sign in again") || !cookieCleared(resp, pendingLoginCookieName) {
		t.Errorf("an assertion on the spent pending login got %d %q cleared=%v, want 401 sign in again, cleared", resp.StatusCode, raw, cookieCleared(resp, pendingLoginCookieName))
	}
	resp, raw = postRaw(t, ts.URL+"/api/auth/login/factor/begin", struct{}{}, pending)
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(raw, "sign in again") || !cookieCleared(resp, pendingLoginCookieName) {
		t.Errorf("begin on the spent pending login got %d %q cleared=%v, want 401 sign in again, cleared", resp.StatusCode, raw, cookieCleared(resp, pendingLoginCookieName))
	}
}

// TestConcurrentCompletionsOfOnePendingLoginHaveOneWinner: two passkey
// assertions, each answering its own challenge begun on the same pending
// login, arrive together. Both verify; only the one that claims the
// pending login first may sign in. Repeated, and run with -race.
func TestConcurrentCompletionsOfOnePendingLoginHaveOneWinner(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	g.deps.Limiter = mustNewLoginLimiter(t, 1000, time.Minute)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	fake, _ := registerPasskey(t, bilbo, ts, g, "key") // reports 0 every time

	for round := range 20 {
		pending := pendingCookieOf(t, startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword), ts)
		type attempt struct {
			body     loginFactorRequest
			ceremony *http.Cookie
		}
		var attempts [2]attempt
		for i := range attempts {
			options, ceremony, status := beginWith(t, ts, pending)
			if status != http.StatusOK {
				t.Fatalf("round %d: begin %d got %d", round, i, status)
			}
			attempts[i] = attempt{assertionBody(t, fake, options), ceremony}
		}
		var wins atomic.Int32
		var refusedReplay atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for _, a := range attempts {
			wg.Go(func() {
				<-start
				resp, raw := postRaw(t, ts.URL+"/api/auth/login/factor", a.body, pending, a.ceremony)
				switch {
				case resp.StatusCode == http.StatusOK:
					wins.Add(1)
				case resp.StatusCode == http.StatusUnauthorized && strings.Contains(raw, "sign in again"):
					refusedReplay.Add(1)
				}
			})
		}
		close(start)
		wg.Wait()
		if wins.Load() != 1 || refusedReplay.Load() != 1 {
			t.Fatalf("round %d: %d of 2 concurrent completions of one pending login won and %d was refused as a replay, want 1 and 1", round, wins.Load(), refusedReplay.Load())
		}
	}
}

// stealJar copies every cookie the owner's jar would send to the
// session-wide path and to register/finish into a fresh jar: the
// cookie-jar theft R1 is about. (From the #20 security re-review.)
func stealJar(t *testing.T, owner *http.Client, ts *httptest.Server) *http.Client {
	t.Helper()
	jar := mustCookieJar(t)
	for _, p := range []string{"/", passkeyRegisterFinishPath} {
		u, err := url.Parse(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		var cs []*http.Cookie
		for _, c := range owner.Jar.Cookies(u) {
			path := "/"
			if c.Name == passkeyRegisterCookieName {
				path = passkeyRegisterCookiePath
			}
			cs = append(cs, &http.Cookie{Name: c.Name, Value: c.Value, Path: path})
		}
		jar.SetCookies(u, cs)
	}
	return &http.Client{Jar: jar}
}

// TestPasskeyStolenRegisterCookieIsOneShot (ruling S1 on #20, the
// re-review's scenario B): the owner finishes their own registration;
// a copy of the cookie jar taken in the meantime cannot finish the same
// ceremony again with another authenticator. Both when the owner's
// passkey is the account's first factor and when one already exists.
func TestPasskeyStolenRegisterCookieIsOneShot(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("a factor already exists: %v", existing), func(t *testing.T) {
			g, ts, _ := passkeyFixture(t)
			owner := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
			want := 1
			if existing {
				registerPasskey(t, owner, ts, g, "first")
				want = 2
			}
			creation := passkeyRegisterBegin(t, owner, ts)
			thief := stealJar(t, owner, ts)
			passkeyRegisterFinishOK(t, owner, ts, newFake(g), creation, "owner")
			if !existing {
				// A first factor is held, not live (#58), so nothing is
				// rotated yet; the thief copies the owner's cookies again
				// anyway, so what stops them is the spent ceremony, not a
				// dead session.
				u, err := url.Parse(ts.URL + "/")
				if err != nil {
					t.Fatal(err)
				}
				thief.Jar.SetCookies(u, owner.Jar.Cookies(u))
			}

			resp := passkeyRegisterFinishRaw(t, thief, ts, newFake(g), creation, "thief")
			raw, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(raw), "start registration again") {
				t.Errorf("a second finish on the owner's spent ceremony got %d %q, want 401 start registration again", resp.StatusCode, raw)
			}
			if n := storedPasskeys(g, passkeyBilboID(t, g)); n != want {
				t.Errorf("the account holds %d passkeys, want %d -- one per password-proved begin", n, want)
			}
		})
	}
}

// TestConcurrentFinishesOfOneRegistrationStoreOnePasskey: two finishes
// on one ceremony cookie, with two different authenticators, arrive
// together. Both pass the library; only the one that claims the ceremony
// first may store. Repeated, and run with -race.
func TestConcurrentFinishesOfOneRegistrationStoreOnePasskey(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	g.deps.Limiter = mustNewLoginLimiter(t, 1000, time.Minute) // begin re-checks the password each round
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	// A first passkey up front, so no round's winner is a first factor
	// that ends the session the next round begins with.
	registerPasskey(t, bilbo, ts, g, "first")
	id := passkeyBilboID(t, g)
	for round := range 8 { // the account holds at most ten passkeys
		begin := postJSON(t, bilbo, ts.URL+"/api/auth/passkeys/register/begin", passkeyRegisterBeginRequest{Password: passkeyBilboPassword})
		var creation protocol.CredentialCreation
		if err := json.NewDecoder(begin.Body).Decode(&creation); err != nil {
			t.Fatal(err)
		}
		_ = begin.Body.Close()
		var sealed *http.Cookie
		for _, c := range begin.Cookies() {
			if c.Name == passkeyRegisterCookieName {
				sealed = &http.Cookie{Name: c.Name, Value: c.Value}
			}
		}
		session := &http.Cookie{Name: testCookieName}
		u, err := url.Parse(ts.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range bilbo.Jar.Cookies(u) {
			if c.Name == testCookieName {
				session.Value = c.Value
			}
		}
		var bodies [2]passkeyRegisterFinishRequest
		for i := range bodies {
			raw, err := newFake(g).RegisterResponse(&creation)
			if err != nil {
				t.Fatal(err)
			}
			bodies[i] = passkeyRegisterFinishRequest{Credential: json.RawMessage(raw), Name: fmt.Sprintf("round %d key %d", round, i)}
		}
		before := g.deps.Users.PasskeyCount(id)
		var wins atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for _, body := range bodies {
			wg.Go(func() {
				<-start
				resp, _ := postRaw(t, ts.URL+"/api/auth/passkeys/register/finish", body, session, sealed)
				if resp.StatusCode == http.StatusOK {
					wins.Add(1)
				}
			})
		}
		close(start)
		wg.Wait()
		if got := g.deps.Users.PasskeyCount(id) - before; wins.Load() != 1 || got != 1 {
			t.Fatalf("round %d: %d of 2 concurrent finishes of one ceremony succeeded and %d passkeys were stored, want 1 and 1", round, wins.Load(), got)
		}
	}
}

// TestPasskeyStolenRegisterCookieInTheOwnersWindowIsAnAcceptedResidual
// pins the re-review's scenario A, which ruling S1 on #20 accepts and
// ADR-0004 records: the owner begins a registration (giving the
// password) and cancels the browser prompt; someone who copied both of
// the owner's HttpOnly cookies inside those five minutes finishes it
// with their own authenticator. It stores one passkey -- at most one per
// such window -- and, on an account with no factor yet, holds it with
// its codes (#58) until the thief, still holding the owner's session,
// confirms them; it is then listed under its name and audited as
// account.passkey_added. If this test starts failing because the finish
// is refused, the residual has been closed: update ADR-0004.
func TestPasskeyStolenRegisterCookieInTheOwnersWindowIsAnAcceptedResidual(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	owner := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	creation := passkeyRegisterBegin(t, owner, ts) // the owner gave the password, then cancelled
	thief := stealJar(t, owner, ts)

	resp := passkeyRegisterFinishRaw(t, thief, ts, newFake(g), creation, "thief")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the accepted residual changed: the thief's finish got %d", resp.StatusCode)
	}
	if n := storedPasskeys(g, passkeyBilboID(t, g)); n != 1 {
		t.Errorf("the account holds %d passkeys, want exactly 1", n)
	}
	confirmEnrolmentOK(t, thief, ts)
	if entry := findAuditEntry(t, g, "account.passkey_added"); entry.Detail != `name="thief"`+fixtureFromSuffix {
		t.Errorf("account.passkey_added detail = %q, want the thief's passkey named", entry.Detail)
	}
	again := passkeyRegisterFinishRaw(t, thief, ts, newFake(g), creation, "thief again")
	_ = again.Body.Close()
	if again.StatusCode != http.StatusUnauthorized {
		t.Errorf("a second thief finish on the same window got %d, want 401", again.StatusCode)
	}
}

// TestARespelledRegisterCookieIsRefusedAfterTheOwnersFinish: the spent
// registration key is the hash of the cookie text, so a cookie that
// opened under several spellings would let a thief re-spell a copy of
// the owner's spent cookie and register a second passkey. The seal is
// read only in its canonical spelling, so the re-spelled copy is a dead
// ceremony: 401, and the account keeps the owner's one new passkey.
//
// The sealed value has unused bits only when its decoded length is not a
// multiple of three, and the one part of it that varies in length is the
// sealed Expires, whose fraction of a second is written without trailing
// zeros. The test runs in a synctest bubble, where the clock starts on a
// whole second and moves only when told to, and steps the begin time
// through fractions with 0, 1, 2 and 3 digits until the cookie has
// unused bits -- one of those four lengths always does.
func TestARespelledRegisterCookieIsRefusedAfterTheOwnersFinish(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := passkeyGate(t)
		mux := http.NewServeMux()
		mux.Handle("/", g.Routes())
		const base = "http://gate.test"
		client := &http.Client{Jar: mustCookieJar(t), Transport: inProcess{g.Protect(mux)}}
		reg := postJSON(t, client, base+"/api/auth/register", registerRequest{Username: "admin", Password: "password-placeholder-1", SetupCode: setupCodeFor(t, g)})
		_ = reg.Body.Close()
		if reg.StatusCode != http.StatusCreated {
			t.Fatalf("register returned %d", reg.StatusCode)
		}

		start := time.Now()
		var creation protocol.CredentialCreation
		var sealed, variant string
		for _, fraction := range []time.Duration{0, 100 * time.Millisecond, 120 * time.Millisecond, 123 * time.Millisecond} {
			time.Sleep(time.Until(start.Add(time.Second + fraction)))
			begin := postJSON(t, client, base+"/api/auth/passkeys/register/begin", passkeyRegisterBeginRequest{Password: "password-placeholder-1"})
			creation = protocol.CredentialCreation{}
			if err := json.NewDecoder(begin.Body).Decode(&creation); err != nil {
				t.Fatal(err)
			}
			_ = begin.Body.Close()
			for _, c := range begin.Cookies() {
				if c.Name == passkeyRegisterCookieName {
					sealed = c.Value
				}
			}
			if variant = respell(t, sealed); variant != "" {
				break
			}
			start = start.Add(time.Second)
		}
		if variant == "" {
			t.Fatal("no begin time gave a register cookie with unused bits")
		}

		finish := func(cookieValue, name string) int {
			body, err := newFake(g).RegisterResponse(&creation)
			if err != nil {
				t.Fatal(err)
			}
			b, err := json.Marshal(passkeyRegisterFinishRequest{Credential: json.RawMessage(body), Name: name})
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest(http.MethodPost, base+"/api/auth/passkeys/register/finish", bytes.NewReader(b))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(csrfHeaderName, testCSRFValue)
			req.AddCookie(&http.Cookie{Name: passkeyRegisterCookieName, Value: cookieValue})
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			return resp.StatusCode
		}
		if got := finish(sealed, "owner"); got != http.StatusOK {
			t.Fatalf("the owner's finish got %d, want 200", got)
		}
		if got := finish(variant, "thief"); got != http.StatusUnauthorized {
			t.Errorf("a re-spelled copy of the spent register cookie got %d, want 401", got)
		}
		admin, _ := g.deps.Users.ByUsername("admin")
		if n := storedPasskeys(g, admin.ID); n != 1 {
			t.Errorf("the account holds %d passkeys after one begin, want 1", n)
		}
	})
}
