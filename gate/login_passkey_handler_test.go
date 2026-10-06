// Signing in with a passkey alone (#77, ADR-0012) and a passkey resuming
// a timed-out session (#71): POST /api/auth/login/passkey/begin,
// POST /api/auth/login/passkey and the {assertion} body of
// POST /api/auth/reauthenticate. Driven with the shared fake
// authenticator (internal/passkeytest), shaped on passkey_handler_test.go.
package gate

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/internal/passkeytest"
	"github.com/tomlawesome/gauntlet/persist"
)

const (
	passkeyFrodoUsername = "frodo"
	passkeyFrodoPassword = "frodo-passkey-password-placeholder"
)

// aloneEnv is passkeyFixture with passkey sign-in on, bilbo holding one
// live discoverable passkey (his fake reports his account ID as the user
// handle), a hand-moved clock and the sign-in records captured. Every
// request comes from one address unless a test changes ClientIP.
type aloneEnv struct {
	g       *Gate
	ts      *httptest.Server
	admin   *http.Client
	fake    *passkeytest.FakeAuthenticator
	bilbo   *http.Client // bilbo's browser from before the passkey, signed in by password
	id      string
	clock   *escalationClock
	audit   *auditRecorder
	events  *signInEvents
	notices *noticeRecorder
	country string
}

func newAloneEnv(t *testing.T) *aloneEnv {
	t.Helper()
	g, ts, admin := passkeyFixture(t)
	g.cfg.PasskeySignIn = true
	e := &aloneEnv{g: g, ts: ts, admin: admin, clock: &escalationClock{t: time.Now()}, country: "GB", notices: &noticeRecorder{}}
	g.cfg.Now = e.clock.now
	g.cfg.Country = func(string) (string, bool) { return e.country, true }
	g.cfg.Notices = e.notices
	g.cfg.DeliverConfirmCode = e.notices.deliver
	e.bilbo = loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	e.fake, _ = registerPasskey(t, e.bilbo, ts, g, "YubiKey")
	e.id = passkeyBilboID(t, g)
	e.fake.UserHandle = []byte(e.id)
	e.audit, _, e.events = recordSignIns(g)
	g.notifying.Wait()
	return e
}

func newBrowserJar(t *testing.T) *http.Client { return &http.Client{Jar: mustCookieJar(t)} }

// signInBegin posts login/passkey/begin from c.
func (e *aloneEnv) signInBegin(t *testing.T, c *http.Client) *http.Response {
	t.Helper()
	return postJSON(t, c, e.ts.URL+loginPasskeyBeginPath, struct{}{})
}

// mustBegin is signInBegin requiring a 200, returning the options the
// browser would hand navigator.credentials.get().
func (e *aloneEnv) mustBegin(t *testing.T, c *http.Client) (*protocol.CredentialAssertion, *http.Response) {
	t.Helper()
	resp := e.signInBegin(t, c)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("login/passkey/begin returned %d: %s", resp.StatusCode, body)
	}
	var out protocol.CredentialAssertion
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return &out, resp
}

func signInAssertionBody(t *testing.T, fake *passkeytest.FakeAuthenticator, options *protocol.CredentialAssertion) json.RawMessage {
	t.Helper()
	body, err := fake.AssertionResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	return json.RawMessage(body)
}

// finish posts login/passkey from c with the assertion.
func (e *aloneEnv) finish(t *testing.T, c *http.Client, assertion json.RawMessage) (*http.Response, string) {
	t.Helper()
	resp := postJSON(t, c, e.ts.URL+loginPasskeyPath, loginPasskeyRequest{Assertion: assertion})
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp, string(raw)
}

// signIn is begin and finish with fake from c: the whole sign-in.
func (e *aloneEnv) signIn(t *testing.T, c *http.Client, fake *passkeytest.FakeAuthenticator) (*http.Response, string) {
	t.Helper()
	options, _ := e.mustBegin(t, c)
	return e.finish(t, c, signInAssertionBody(t, fake, options))
}

func wantStatusClass(t *testing.T, resp *http.Response, body string, status int, class problemClass) {
	t.Helper()
	wantResumeProblem(t, resp, []byte(body), status, class)
}

func cookieValue(resp *http.Response, name string) string {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// finishWithCookie posts login/passkey with only the sealed ceremony
// cookie given, as a browser holding exactly that cookie would.
func (e *aloneEnv) finishWithCookie(t *testing.T, sealed string, assertion json.RawMessage) (*http.Response, string) {
	t.Helper()
	b, err := json.Marshal(loginPasskeyRequest{Assertion: assertion})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+loginPasskeyPath, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(csrfHeaderName, testCSRFValue)
	req.Header.Set("Content-Type", "application/json")
	if sealed != "" {
		req.AddCookie(&http.Cookie{Name: passkeySignInCookieName, Value: sealed})
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp, string(raw)
}

func (e *aloneEnv) mustSignIn(t *testing.T, c *http.Client) {
	t.Helper()
	resp, body := e.signIn(t, c, e.fake)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("passkey sign-in returned %d: %s", resp.StatusCode, body)
	}
}

// registerFrodo makes frodo with a live discoverable passkey of his own.
func (e *aloneEnv) registerFrodo(t *testing.T) (*passkeytest.FakeAuthenticator, string) {
	t.Helper()
	_ = postJSON(t, e.admin, e.ts.URL+"/api/auth/users",
		createUserRequest{Username: passkeyFrodoUsername, Password: passkeyFrodoPassword, Role: "user"}).Body.Close()
	frodo := loggedInClient(t, e.ts, passkeyFrodoUsername, passkeyFrodoPassword)
	resp := postJSON(t, frodo, e.ts.URL+"/api/auth/passkeys/register/begin", passkeyRegisterBeginRequest{Password: passkeyFrodoPassword})
	var creation protocol.CredentialCreation
	if err := json.NewDecoder(resp.Body).Decode(&creation); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	fake := newFake(e.g)
	_ = passkeyRegisterFinishOK(t, frodo, e.ts, fake, &creation, "frodo's key")
	confirmEnrolmentOK(t, frodo, e.ts)
	u, ok := e.g.deps.Users.ByUsername(passkeyFrodoUsername)
	if !ok {
		t.Fatal("frodo was not created")
	}
	fake.UserHandle = []byte(u.ID)
	return fake, u.ID
}

// withFreshAddresses gives every address lookup a new address, so only
// an account's own limit can refuse a request.
func (e *aloneEnv) withFreshAddresses() {
	var n atomic.Int64
	e.g.cfg.ClientIP = func(*http.Request) string { return fmt.Sprintf("192.0.2.%d", n.Add(1)) }
}

func lastEvent(t *testing.T, e *aloneEnv) gauntlet.SignInEvent {
	t.Helper()
	all := e.events.all()
	if len(all) == 0 {
		t.Fatal("no sign-in events recorded")
	}
	return all[len(all)-1]
}

// -- begin and the happy path -----------------------------------------------

func TestPasskeySignInEndToEnd(t *testing.T) {
	e := newAloneEnv(t)
	c := newBrowserJar(t)

	options, beginResp := e.mustBegin(t, c)
	if n := len(options.Response.AllowedCredentials); n != 0 {
		t.Errorf("begin allows %d credentials, want none (the browser offers its own)", n)
	}
	if options.Response.UserVerification != protocol.VerificationRequired {
		t.Errorf("begin userVerification = %q, want required", options.Response.UserVerification)
	}
	if options.Response.RelyingPartyID != e.g.deps.Passkeys.RPID() {
		t.Errorf("begin rpId = %q, want the relying party's", options.Response.RelyingPartyID)
	}
	var ck *http.Cookie
	for _, c := range beginResp.Cookies() {
		if c.Name == passkeySignInCookieName {
			ck = c
		}
	}
	if ck == nil || ck.Path != "/api/auth" || !ck.HttpOnly || ck.MaxAge != 300 || ck.Value == "" {
		t.Fatalf("begin set cookie %+v, want gate_passkey_signin on /api/auth, HttpOnly, 300s", ck)
	}

	resp, body := e.finish(t, c, signInAssertionBody(t, e.fake, options))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login/passkey returned %d: %s", resp.StatusCode, body)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil || got["username"] != passkeyBilboUsername || got["role"] != "user" || len(got) != 2 {
		t.Errorf("body = %s, want login's success body", body)
	}
	if !cookieCleared(resp, passkeySignInCookieName) {
		t.Error("a completed sign-in left its ceremony cookie")
	}
	if got := protectedStatus(t, c, e.ts); got != http.StatusOK {
		t.Errorf("the new session reached a protected route with %d, want 200", got)
	}

	// The session, the history and the audit say how.
	status, list := listSessions(t, c, e.ts)
	if status != http.StatusOK || currentRow(t, list).Method != gauntlet.SignInMethodPasskeyAlone {
		t.Errorf("session list = %d %+v, want the current row's method passkey_alone", status, list.Sessions)
	}
	wantEvents(t, e.events.all(), "success/passkey_alone")
	entry := findAuditEntry(t, e.g, "user.login")
	if entry.Actor != passkeyBilboUsername || !strings.HasSuffix(entry.Detail, "via passkey"+fixtureFromSuffix) {
		t.Errorf("user.login = %+v, want bilbo, via passkey", entry)
	}

	// The account keeps its password and nothing about it changed.
	u, _ := e.g.deps.Users.Get(e.id)
	if !u.LocalPassword() || u.MustChangePassword || len(u.Passkeys) != 1 {
		t.Errorf("account after the sign-in = local password %v, must-change %v, %d passkeys", u.LocalPassword(), u.MustChangePassword, len(u.Passkeys))
	}
	if status := signInFrom(t, newBrowserJar(t), e.ts, passkeyBilboUsername, passkeyBilboPassword); status != http.StatusOK {
		t.Errorf("the password step after a passkey sign-in got %d, want 200 (the password still works)", status)
	}
}

// A completed sign-in costs none of the budget a wrong guess is limited
// by: both the begin step's address reservation and the finish step's
// come back, and the account's count is reset.
func TestPasskeySignInGivesBothReservationsBack(t *testing.T) {
	e := newAloneEnv(t)
	const threshold = 3
	e.g.deps.Limiter = mustNewLoginLimiter(t, threshold, time.Minute)
	e.mustSignIn(t, newBrowserJar(t))

	now := e.clock.now()
	for i := range threshold {
		if !e.g.deps.Limiter.Reserve("ip:198.51.100.1", now) {
			t.Errorf("address: %d of %d attempts left after a successful passkey sign-in, want all", i, threshold)
			break
		}
	}
	for i := range threshold {
		if !e.g.deps.Limiter.ReserveAccount(e.g.deps.Users, e.id, now) {
			t.Errorf("account: %d of %d attempts left after a successful passkey sign-in, want all", i, threshold)
			break
		}
	}
	for i := range threshold {
		if !e.g.deps.Limiter.Reserve(passkeyBeginKey("198.51.100.1"), now) {
			t.Errorf("begin: %d of %d attempts left after a successful passkey sign-in, want all", i, threshold)
			break
		}
	}
}

// Begin reserves one attempt on the address, so one address cannot mint
// challenges without limit; a banned address is refused outright.
func TestPasskeySignInBeginIsRateLimited(t *testing.T) {
	e := newAloneEnv(t)
	e.g.deps.Limiter = mustNewLoginLimiter(t, 2, time.Minute)
	c := newBrowserJar(t)
	for i := range 2 {
		resp := e.signInBegin(t, c)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("begin %d returned %d, want 200", i+1, resp.StatusCode)
		}
	}
	resp := e.signInBegin(t, c)
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	wantStatusClass(t, resp, string(raw), http.StatusTooManyRequests, classRateLimited)
	wantEvents(t, e.events.all(), "rate_limited/passkey_alone")

	e2 := newAloneEnv(t)
	for range gauntlet.AddressBanFailures {
		e2.g.deps.Limiter.RecordAddressFailure("198.51.100.1", e2.clock.now())
	}
	resp = e2.signInBegin(t, newBrowserJar(t))
	raw, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	wantStatusClass(t, resp, string(raw), http.StatusTooManyRequests, classRateLimited)
}

// A browser asks for a challenge on every load of a login page with
// passkey autofill and after every dismissed prompt, so begin has a
// budget of its own: begins that are never finished leave the address's
// sign-in attempts alone, and are still bounded.
func TestPasskeySignInBeginSpendsNoSignInAttempts(t *testing.T) {
	e := newAloneEnv(t)
	for i := range 5 { // newTestGate's limiter threshold
		resp := e.signInBegin(t, newBrowserJar(t))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("begin %d returned %d, want 200", i+1, resp.StatusCode)
		}
	}
	// A browser this account has never used, so only the address's
	// ordinary budget can admit it.
	if status := signInFrom(t, newBrowserJar(t), e.ts, passkeyBilboUsername, passkeyBilboPassword); status != http.StatusOK {
		t.Errorf("a password sign-in after five unfinished begins got %d, want 200", status)
	}
	resp := e.signInBegin(t, newBrowserJar(t))
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	wantStatusClass(t, resp, string(raw), http.StatusTooManyRequests, classRateLimited)
}

// -- refusals ---------------------------------------------------------------

// An assertion that did not verify the user is refused, keeps the
// ceremony open and keeps the reservations -- which is what counts it.
func TestPasskeySignInWithoutUserVerificationIsRefusedAndCounted(t *testing.T) {
	e := newAloneEnv(t)
	e.g.deps.Limiter = mustNewLoginLimiter(t, 3, time.Minute)
	c := newBrowserJar(t)

	e.fake.NoUserVerification = true
	resp, body := e.signIn(t, c, e.fake)
	wantStatusClass(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
	if cookieCleared(resp, passkeySignInCookieName) {
		t.Error("a refused assertion cleared the ceremony cookie, want it kept so a corrected one can finish")
	}
	if got := protectedStatus(t, c, e.ts); got != http.StatusUnauthorized {
		t.Errorf("a non-user-verified passkey reached a protected route with %d", got)
	}
	wantEvents(t, e.events.all(), "factor_refused/passkey_alone")
	if ev := lastEvent(t, e); ev.UserID != e.id || ev.Username != passkeyBilboUsername {
		t.Errorf("event = %+v, want it on bilbo's account", ev)
	}

	// The reservations stayed: the finish holds one of the address's
	// three attempts and one of the account's.
	now := e.clock.now()
	for i := range 3 {
		if ok := e.g.deps.Limiter.Reserve("ip:198.51.100.1", now); ok != (i < 2) {
			t.Errorf("address attempt %d after the refusal admitted = %v, want only two of three left", i+1, ok)
		}
	}
	for i := range 3 {
		if ok := e.g.deps.Limiter.ReserveAccount(e.g.deps.Users, e.id, now); ok != (i < 2) {
			t.Errorf("account attempt %d after the refusal admitted = %v, want only two of three left", i+1, ok)
		}
	}
}

// The same ceremony, finished again with user verification, signs in.
func TestPasskeySignInRefusalLeavesTheCeremonyOpen(t *testing.T) {
	e := newAloneEnv(t)
	c := newBrowserJar(t)
	options, _ := e.mustBegin(t, c)

	e.fake.NoUserVerification = true
	resp, body := e.finish(t, c, signInAssertionBody(t, e.fake, options))
	wantStatusClass(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
	e.fake.NoUserVerification = false
	if resp, body = e.finish(t, c, signInAssertionBody(t, e.fake, options)); resp.StatusCode != http.StatusOK {
		t.Fatalf("the corrected assertion on the same ceremony returned %d: %s", resp.StatusCode, body)
	}
}

func TestPasskeySignInUnknownHandle(t *testing.T) {
	e := newAloneEnv(t)
	e.fake.UserHandle = []byte("no-such-account")
	c := newBrowserJar(t)
	resp, body := e.signIn(t, c, e.fake)
	wantStatusClass(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
	wantEvents(t, e.events.all(), "no_such_user/passkey_alone")
	if ev := lastEvent(t, e); ev.UserID != "" {
		t.Errorf("an unknown handle's event names account %q", ev.UserID)
	}
	if got := protectedStatus(t, c, e.ts); got != http.StatusUnauthorized {
		t.Errorf("an unknown handle reached a protected route with %d", got)
	}

	// Neither a missing handle: the authenticator reported none.
	e.fake.UserHandle = nil
	resp, body = e.signIn(t, newBrowserJar(t), e.fake)
	wantStatusClass(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
}

// A handle that names an account the passkey does not belong to, or one
// whose passkey is stale or still held for its codes, signs nobody in.
func TestPasskeySignInRefusesAHandleWhosePasskeyIsNotLive(t *testing.T) {
	t.Run("another account's passkey", func(t *testing.T) {
		e := newAloneEnv(t)
		_, frodoID := e.registerFrodo(t)
		e.events.events = nil
		e.fake.UserHandle = []byte(frodoID)
		resp, body := e.signIn(t, newBrowserJar(t), e.fake)
		wantStatusClass(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
		if ev := lastEvent(t, e); ev.Outcome != gauntlet.SignInFactorRefused || ev.UserID != frodoID {
			t.Errorf("event = %+v, want factor_refused on the account the handle named", ev)
		}
	})
	t.Run("a held passkey", func(t *testing.T) {
		e := newAloneEnv(t)
		_ = postJSON(t, e.admin, e.ts.URL+"/api/auth/users",
			createUserRequest{Username: passkeyFrodoUsername, Password: passkeyFrodoPassword, Role: "user"}).Body.Close()
		frodo := loggedInClient(t, e.ts, passkeyFrodoUsername, passkeyFrodoPassword)
		resp := postJSON(t, frodo, e.ts.URL+"/api/auth/passkeys/register/begin", passkeyRegisterBeginRequest{Password: passkeyFrodoPassword})
		var creation protocol.CredentialCreation
		if err := json.NewDecoder(resp.Body).Decode(&creation); err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		held := newFake(e.g)
		out := passkeyRegisterFinishOK(t, frodo, e.ts, held, &creation, "held")
		if !out.PendingConfirmation {
			t.Fatal("frodo's first passkey was not held for its codes")
		}
		u, _ := e.g.deps.Users.ByUsername(passkeyFrodoUsername)
		held.UserHandle = []byte(u.ID)
		r, body := e.signIn(t, newBrowserJar(t), held)
		wantStatusClass(t, r, body, http.StatusUnauthorized, classInvalidCredentials)
	})
	t.Run("a stale passkey", func(t *testing.T) {
		e := newAloneEnv(t)
		newRP := mustRelyingParty(t, "https://new-passkeys.example.org")
		e.g.deps.Passkeys = newRP
		e.fake.RPID, e.fake.Origin = newRP.RPID(), newRP.Origin()
		resp, body := e.signIn(t, newBrowserJar(t), e.fake)
		wantStatusClass(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
	})
}

// An account with no local password signs in through its identity
// provider; a passkey carried over on it signs in nothing here.
func TestPasskeySignInRefusesAnAccountWithNoLocalPassword(t *testing.T) {
	e := newAloneEnv(t)
	bilbo, _ := e.g.deps.Users.Get(e.id)
	hash, err := gauntlet.HashPassword("password-placeholder-1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	e.g.deps.Users = openStoreWithUsers(t, gauntlet.User{
		ID: "admin-1", Username: "admin", PasswordHash: hash, Role: gauntlet.RoleAdmin,
		CreatedAt: now, HasLocalPassword: true,
		TOTPSecret: "placeholder-secret", TOTPConfirmedAt: now,
	}, gauntlet.User{
		ID: e.id, Username: "sam", Role: gauntlet.RoleUser, CreatedAt: now,
		OIDCIssuer: "https://idp.example.org", OIDCSubject: "sam-subject",
		Passkeys: bilbo.Passkeys,
	})
	resp, body := e.signIn(t, newBrowserJar(t), e.fake)
	wantStatusClass(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
	if got := lastEvent(t, e); got.Outcome != gauntlet.SignInFactorRefused {
		t.Errorf("event = %+v, want factor_refused", got)
	}
}

// A regressed counter is a clone warning: refused, audited with both
// counts, the stored count left alone, the ceremony left open.
func TestPasskeySignInCloneWarningRefuses(t *testing.T) {
	e := newAloneEnv(t)
	e.fake.SignCount = 5
	e.mustSignIn(t, newBrowserJar(t))

	e.fake.SignCount = 3
	c := newBrowserJar(t)
	resp, body := e.signIn(t, c, e.fake)
	wantStatusClass(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
	if got := protectedStatus(t, c, e.ts); got != http.StatusUnauthorized {
		t.Error("a clone-suspected assertion established a session")
	}
	u, _ := e.g.deps.Users.Get(e.id)
	if got := u.Passkeys[0].SignCount; got != 5 {
		t.Errorf("stored sign count after the regressed attempt = %d, want unchanged at 5", got)
	}
	entry := findAuditEntry(t, e.g, "account.passkey_clone_suspected")
	want := fmt.Sprintf("credential=%s presentedCount=3 storedCount=5", base64.RawURLEncoding.EncodeToString(e.fake.CredentialID())) + fixtureFromSuffix
	if entry.Target != passkeyBilboUsername || entry.Detail != want {
		t.Errorf("clone audit = %+v, want bilbo with %q", entry, want)
	}
	if ev := lastEvent(t, e); ev.Outcome != gauntlet.SignInFactorRefused || ev.Method != gauntlet.SignInMethodPasskeyAlone {
		t.Errorf("event = %+v, want factor_refused/passkey_alone", ev)
	}
}

// A sign count that does not advance is refused by the store when the
// library saw nothing wrong (the same assertion racing itself): of
// concurrent submissions of one assertion exactly one signs in.
func TestPasskeySignInConcurrentSubmissionsOnlyOneWins(t *testing.T) {
	e := newAloneEnv(t)
	e.g.deps.Limiter = mustNewLoginLimiter(t, 1000, time.Minute)
	e.fake.SignCount = 7 // counting, so the store's check matters too
	options, begin := e.mustBegin(t, newBrowserJar(t))
	sealed := cookieValue(begin, passkeySignInCookieName)
	body := signInAssertionBody(t, e.fake, options)

	const n = 8
	results := make(chan int, n)
	post := func() int {
		b, err := json.Marshal(loginPasskeyRequest{Assertion: body})
		if err != nil {
			return -1
		}
		req, err := http.NewRequest(http.MethodPost, e.ts.URL+loginPasskeyPath, bytes.NewReader(b))
		if err != nil {
			return -1
		}
		req.Header.Set(csrfHeaderName, testCSRFValue)
		req.AddCookie(&http.Cookie{Name: passkeySignInCookieName, Value: sealed})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return -1
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	for range n {
		go func() { results <- post() }()
	}
	ok := 0
	for range n {
		if <-results == http.StatusOK {
			ok++
		}
	}
	if ok != 1 {
		t.Errorf("%d of %d concurrent submissions of one assertion signed in, want exactly 1", ok, n)
	}
}

// A counter that cannot be saved is the backend failing, not a wrong
// guess: 500, and both reservations go back.
func TestPasskeySignInCounterSaveFailureDoesNotSpendBudget(t *testing.T) {
	g := passkeyGate(t)
	g.cfg.PasskeySignIn = true
	backend := &budgetBackend{inner: persist.NewMemory(), left: -1}
	g.deps.Users = openTrackedStore(t, backend)
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")
	_ = postJSON(t, admin, ts.URL+"/api/auth/users",
		createUserRequest{Username: passkeyBilboUsername, Password: passkeyBilboPassword, Role: "user"}).Body.Close()
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	fake, _ := registerPasskey(t, bilbo, ts, g, "key")
	fake.UserHandle = []byte(passkeyBilboID(t, g))
	e := &aloneEnv{g: g, ts: ts}

	for i := range 5 { // newTestGate's limiter threshold
		fake.SignCount = uint32(i + 1) // counting, so the save matters
		c := newBrowserJar(t)
		options, _ := e.mustBegin(t, c)
		backend.left = 0
		resp, body := e.finish(t, c, signInAssertionBody(t, fake, options))
		backend.left = -1
		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("cycle %d: got %d %q, want 500", i, resp.StatusCode, body)
		}
	}
	fake.SignCount = 10
	if resp, body := e.signIn(t, newBrowserJar(t), fake); resp.StatusCode != http.StatusOK {
		t.Errorf("after 5 backend failures and no wrong guess, the sign-in got %d %s, want 200", resp.StatusCode, body)
	}
}

// -- the ceremony cookie ------------------------------------------------------

func TestPasskeySignInDeadCeremoniesAreStepExpired(t *testing.T) {
	e := newAloneEnv(t)
	options, begin := e.mustBegin(t, newBrowserJar(t))
	body := signInAssertionBody(t, e.fake, options)
	sealed := cookieValue(begin, passkeySignInCookieName)

	// A second-step login's ceremony state, sealed under another key.
	pending := startPasskeyLogin(t, e.ts, passkeyBilboUsername, passkeyBilboPassword)
	_ = passkeyLoginFactorBegin(t, pending, e.ts)
	secondStep := ""
	u, _ := http.NewRequest(http.MethodGet, e.ts.URL+loginPath, nil)
	for _, c := range pending.Jar.Cookies(u.URL) {
		if c.Name == passkeyAssertCookieName {
			secondStep = c.Value
		}
	}
	if secondStep == "" {
		t.Fatal("no second-step ceremony cookie to cross over")
	}

	for name, cookie := range map[string]string{
		"no cookie":             "",
		"garbage":               "not-a-sealed-value",
		"a second-step login's": secondStep,
		"a tampered cookie":     sealed[:len(sealed)-2] + "AA",
		"a truncated cookie":    sealed[:10],
	} {
		resp, raw := e.finishWithCookie(t, cookie, body)
		wantStatusClass(t, resp, raw, http.StatusUnauthorized, classStepExpired)
		if !cookieCleared(resp, passkeySignInCookieName) {
			t.Errorf("%s: the dead ceremony's cookie was not cleared", name)
		}
	}
	// None of them spent the live one.
	if resp, raw := e.finishWithCookie(t, sealed, body); resp.StatusCode != http.StatusOK {
		t.Fatalf("the live ceremony after those refusals returned %d: %s", resp.StatusCode, raw)
	}
	// Spent now: the same cookie and assertion again.
	resp, raw := e.finishWithCookie(t, sealed, body)
	wantStatusClass(t, resp, raw, http.StatusUnauthorized, classStepExpired)
	if !cookieCleared(resp, passkeySignInCookieName) {
		t.Error("a spent ceremony's cookie was not cleared")
	}
}

// A ceremony finished after its five minutes is dead, the cookie sent
// anyway (a browser would have dropped it; an attacker holding a copy
// would not), so the refusal is the sealed expiry. Each is paired with
// the same ceremony finishing inside the window. Run in a synctest
// bubble, where the five minutes pass instantly.
func TestPasskeySignInExpiredCeremonyIsStepExpired(t *testing.T) {
	for _, wait := range []time.Duration{passkeyCeremonyCookieMaxAge - time.Second, passkeyCeremonyCookieMaxAge + time.Second} {
		expired := wait > passkeyCeremonyCookieMaxAge
		synctest.Test(t, func(t *testing.T) {
			g := passkeyGate(t)
			g.cfg.PasskeySignIn = true
			mux := http.NewServeMux()
			mux.Handle("/", g.Routes())
			const base = "http://gate.test"
			client := &http.Client{Jar: mustCookieJar(t), Transport: inProcess{g.Protect(mux)}}
			post := func(path string, body any) *http.Response { return postJSON(t, client, base+path, body) }

			reg := post("/api/auth/register", registerRequest{Username: "admin", Password: "password-placeholder-1", SetupCode: setupCodeFor(t, g)})
			_ = reg.Body.Close()
			if reg.StatusCode != http.StatusCreated {
				t.Fatalf("register returned %d", reg.StatusCode)
			}
			fake := newFake(g)
			begin := post("/api/auth/passkeys/register/begin", passkeyRegisterBeginRequest{Password: "password-placeholder-1"})
			var creation protocol.CredentialCreation
			if err := json.NewDecoder(begin.Body).Decode(&creation); err != nil {
				t.Fatal(err)
			}
			_ = begin.Body.Close()
			regBody, err := fake.RegisterResponse(&creation)
			if err != nil {
				t.Fatal(err)
			}
			fin := post("/api/auth/passkeys/register/finish", passkeyRegisterFinishRequest{Credential: json.RawMessage(regBody), Name: "key"})
			_ = fin.Body.Close()
			conf := post(enrolmentConfirmPath, struct{}{})
			_ = conf.Body.Close()
			admin, _ := g.deps.Users.ByUsername("admin")
			if conf.StatusCode != http.StatusOK || len(admin.Passkeys) != 1 {
				t.Fatalf("setting up the passkey: confirm %d, %d live passkeys", conf.StatusCode, len(admin.Passkeys))
			}
			fake.UserHandle = []byte(admin.ID)

			signedOut := &http.Client{Jar: mustCookieJar(t), Transport: inProcess{g.Protect(mux)}}
			sb := postJSON(t, signedOut, base+loginPasskeyBeginPath, struct{}{})
			var options protocol.CredentialAssertion
			if err := json.NewDecoder(sb.Body).Decode(&options); err != nil {
				t.Fatal(err)
			}
			_ = sb.Body.Close()
			sealed := cookieValue(sb, passkeySignInCookieName)
			assertion := signInAssertionBody(t, fake, &options)

			time.Sleep(wait)

			b, err := json.Marshal(loginPasskeyRequest{Assertion: assertion})
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest(http.MethodPost, base+loginPasskeyPath, bytes.NewReader(b))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(csrfHeaderName, testCSRFValue)
			req.AddCookie(&http.Cookie{Name: passkeySignInCookieName, Value: sealed})
			resp, err := signedOut.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			want := http.StatusOK
			if expired {
				want = http.StatusUnauthorized
			}
			if resp.StatusCode != want {
				t.Errorf("login/passkey %v after begin got %d, want %d", wait, resp.StatusCode, want)
			}
			if expired && !cookieCleared(resp, passkeySignInCookieName) {
				t.Error("an expired ceremony did not clear its cookie")
			}
		})
	}
}

func TestPasskeySignInMalformedBody(t *testing.T) {
	e := newAloneEnv(t)
	c := newBrowserJar(t)
	_, _ = e.mustBegin(t, c)
	for name, body := range map[string]any{
		"no assertion":     struct{}{},
		"an unknown field": map[string]any{"assertion": map[string]any{}, "x": 1},
	} {
		resp := postJSON(t, c, e.ts.URL+loginPasskeyPath, body)
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: login/passkey returned %d %s, want 400", name, resp.StatusCode, raw)
		}
	}
	// A body that is not an assertion at all is a refusal of the
	// credential, not of the request, and is counted on the address.
	resp, raw := e.finish(t, c, json.RawMessage(`{"id":1}`))
	wantStatusClass(t, resp, raw, http.StatusUnauthorized, classInvalidCredentials)
	wantEvents(t, e.events.all(), "no_such_user/passkey_alone")
}

// -- off and not ready ------------------------------------------------------

type ceremonyOnly struct{ gauntlet.PasskeyCeremony }

func TestPasskeySignInOffAnswers404(t *testing.T) {
	probe := func(t *testing.T, e *aloneEnv) {
		t.Helper()
		resp := e.signInBegin(t, newBrowserJar(t))
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		wantStatusClass(t, resp, string(raw), http.StatusNotFound, classNotFound)
		resp, raw2 := e.finish(t, newBrowserJar(t), json.RawMessage(`{}`))
		wantStatusClass(t, resp, raw2, http.StatusNotFound, classNotFound)
		if st := sessionState(t, newBrowserJar(t), e.ts); st["passkeys"] != nil {
			t.Errorf("session body = %v, want no passkeys block while sign-in is off", st)
		}
	}
	t.Run("the setting is off", func(t *testing.T) {
		e := newAloneEnv(t)
		e.g.cfg.PasskeySignIn = false
		probe(t, e)
		// The second-step passkey still works.
		pending := startPasskeyLogin(t, e.ts, passkeyBilboUsername, passkeyBilboPassword)
		if resp := submitPasskeyAssertion(t, pending, e.ts, e.fake, passkeyLoginFactorBegin(t, pending, e.ts)); resp.StatusCode != http.StatusOK {
			t.Errorf("the second-step passkey with sign-in off returned %d, want 200", resp.StatusCode)
		}
	})
	t.Run("no passkeys at all", func(t *testing.T) {
		e := newAloneEnv(t)
		e.g.deps.Passkeys = nil
		probe(t, e)
	})
	t.Run("a relying party that cannot do it", func(t *testing.T) {
		e := newAloneEnv(t)
		e.g.deps.Passkeys = ceremonyOnly{e.g.deps.Passkeys}
		probe(t, e)
	})
}

func TestPasskeySignInNotReadyAnswers409(t *testing.T) {
	e := newAloneEnv(t)
	e.g.deps.Passkeys = mustRelyingParty(t, "https://192.0.2.10") // an IP address: never ready
	resp := e.signInBegin(t, newBrowserJar(t))
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	wantStatusClass(t, resp, string(raw), http.StatusConflict, classConflict)
	resp, raw2 := e.finish(t, newBrowserJar(t), json.RawMessage(`{}`))
	wantStatusClass(t, resp, raw2, http.StatusConflict, classConflict)
	if st := sessionState(t, newBrowserJar(t), e.ts); st["passkeys"] != nil {
		t.Errorf("session body = %v, want no passkeys block (not ready)", st)
	}
}

func TestPasskeySignInRoutesNeedTheCSRFHeader(t *testing.T) {
	e := newAloneEnv(t)
	for _, path := range []string{loginPasskeyBeginPath, loginPasskeyPath} {
		req, err := http.NewRequest(http.MethodPost, e.ts.URL+path, strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("POST %s with no CSRF header returned %d, want 403", path, resp.StatusCode)
		}
	}
}

func TestSessionBodySaysWhenPasskeySignInIsOn(t *testing.T) {
	e := newAloneEnv(t)
	st := sessionState(t, newBrowserJar(t), e.ts)
	pk, _ := st["passkeys"].(map[string]any)
	if pk == nil || pk["signIn"] != true || pk["status"] != "ready" || pk["origin"] != passkeyTestPublicURL || pk["count"] != float64(0) {
		t.Errorf("signed-out session body passkeys = %v, want signIn true, ready, the origin, count 0", st["passkeys"])
	}
	st = sessionState(t, e.bilbo, e.ts)
	pk, _ = st["passkeys"].(map[string]any)
	if pk == nil || pk["signIn"] != true || pk["count"] != float64(1) {
		t.Errorf("signed-in session body passkeys = %v, want signIn true and count 1", st["passkeys"])
	}
	e.g.cfg.PasskeySignIn = false
	st = sessionState(t, e.bilbo, e.ts)
	pk, _ = st["passkeys"].(map[string]any)
	if pk == nil || pk["signIn"] != nil {
		t.Errorf("session body passkeys with sign-in off = %v, want it without signIn", st["passkeys"])
	}
}

// -- limits ------------------------------------------------------------------

// The account's lockout applies as for a password, before the signature
// is checked; a browser the account remembers gets its allowance.
func TestPasskeySignInLockoutAndTheKnownBrowser(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	known := newBrowserJar(t)
	e.mustSignIn(t, known) // remembers this browser

	failLoginWindow(t, e.g, e.ts, e.clock, passkeyBilboUsername)
	stranger := newBrowserJar(t)
	resp, body := e.signIn(t, stranger, e.fake)
	wantStatusClass(t, resp, body, http.StatusTooManyRequests, classRateLimited)
	if ev := lastEvent(t, e); ev.Outcome != gauntlet.SignInLocked || ev.Method != gauntlet.SignInMethodPasskeyAlone {
		t.Errorf("event = %+v, want locked/passkey_alone", ev)
	}
	if got := protectedStatus(t, stranger, e.ts); got != http.StatusUnauthorized {
		t.Errorf("a locked account's passkey signed in: %d", got)
	}

	if resp, body = e.signIn(t, known, e.fake); resp.StatusCode != http.StatusOK {
		t.Fatalf("the known browser through the lockout returned %d: %s", resp.StatusCode, body)
	}
	if u, _ := e.g.deps.Users.Get(e.id); u.LoginLockoutCount != 0 || !u.LoginLockedUntil.IsZero() {
		t.Errorf("after the sign-in the record holds count %d until %v, want both cleared", u.LoginLockoutCount, u.LoginLockedUntil)
	}
}

func TestPasskeySignInDisabledAccountIsRefusedEvenToAKnownBrowser(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	known := newBrowserJar(t)
	e.mustSignIn(t, known)

	for failed := 0; failed < gauntlet.MaxConsecutiveLoginFailures; failed += 5 {
		failLoginWindow(t, e.g, e.ts, e.clock, passkeyBilboUsername)
	}
	e.clock.set(e.clock.now().Add(2 * time.Hour)) // past the last lockout, inside the disable
	for name, c := range map[string]*http.Client{"a stranger": newBrowserJar(t), "the known browser": known} {
		resp, body := e.signIn(t, c, e.fake)
		wantStatusClass(t, resp, body, http.StatusTooManyRequests, classRateLimited)
		if ev := lastEvent(t, e); ev.Outcome != gauntlet.SignInDisabled {
			t.Errorf("%s: event = %+v, want disabled", name, ev)
		}
	}
}

// At the finish the address's own limit applies to an unknown browser
// and not to the one the account remembers.
func TestPasskeySignInKnownBrowserPassesTheAddressLimit(t *testing.T) {
	e := newAloneEnv(t)
	known := newBrowserJar(t)
	e.mustSignIn(t, known)
	e.g.deps.Limiter = mustNewLoginLimiter(t, 5, 5*time.Minute)

	knownOptions, _ := e.mustBegin(t, known)
	strangerClient := newBrowserJar(t)
	strangerOptions, _ := e.mustBegin(t, strangerClient)
	for range 5 { // the begins hold none of the address's five; fill them
		e.g.deps.Limiter.Reserve("ip:198.51.100.1", e.clock.now())
	}
	resp, body := e.finish(t, strangerClient, signInAssertionBody(t, e.fake, strangerOptions))
	wantStatusClass(t, resp, body, http.StatusTooManyRequests, classRateLimited)
	if resp, body = e.finish(t, known, signInAssertionBody(t, e.fake, knownOptions)); resp.StatusCode != http.StatusOK {
		t.Fatalf("the known browser at a full address returned %d: %s", resp.StatusCode, body)
	}
}

// -- after the sign-in ----------------------------------------------------

// A passkey is not a way past the forced password change: the door
// still holds, and the reset code that owes it stays valid.
func TestPasskeySignInStillMeetsTheMustChangePasswordDoor(t *testing.T) {
	e := newAloneEnv(t)
	resp := postJSON(t, e.admin, e.ts.URL+"/api/auth/users/"+e.id+"/reset-password", adminStepUpRequest{Password: testAdminPassword})
	var reset resetPasswordResponse
	if err := json.NewDecoder(resp.Body).Decode(&reset); err != nil || reset.Code == "" {
		t.Fatalf("reset-password: %v %+v", err, reset)
	}
	_ = resp.Body.Close()

	c := newBrowserJar(t)
	resp2, body := e.signIn(t, c, e.fake)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("the passkey sign-in after a reset returned %d: %s", resp2.StatusCode, body)
	}
	gate := getProtected(t, c, e.ts)
	_ = gate.Body.Close()
	if gate.StatusCode != http.StatusForbidden || gate.Header.Get(authGateHeader) != authGateMustChangePassword {
		t.Errorf("a protected route after a passkey sign-in = %d %q, want 403 at the must-change-password door", gate.StatusCode, gate.Header.Get(authGateHeader))
	}
	if st := sessionState(t, c, e.ts); st["mustChangePassword"] != true {
		t.Errorf("session body = %v, want mustChangePassword", st)
	}
	if status := signInFrom(t, newBrowserJar(t), e.ts, passkeyBilboUsername, reset.Code); status != http.StatusOK {
		t.Errorf("the reset code after the passkey sign-in got %d, want it still valid", status)
	}
}

// -- the unusual-sign-in policy ----------------------------------------------

func TestPasskeySignInIsJudged(t *testing.T) {
	t.Run("flag", func(t *testing.T) {
		e := newAloneEnv(t)
		e.country = "FR"
		resp, body := e.signIn(t, newBrowserJar(t), e.fake)
		if resp.StatusCode != http.StatusOK || strings.Contains(body, "unusual") {
			t.Fatalf("flagged passkey sign-in = %d %s, want 200 saying nothing of why", resp.StatusCode, body)
		}
		entry := findAuditEntry(t, e.g, "user.login")
		if !strings.HasPrefix(entry.Detail, "unusual=new-browser,new-country; action=flag; ") || !strings.Contains(entry.Detail, "; via passkey; ") {
			t.Errorf("user.login detail = %q", entry.Detail)
		}
		e.g.notifying.Wait()
		var found bool
		for _, n := range e.notices.all() {
			if n.Kind == NoticeUnusualSignIn && n.UnusualSignIn.Method == gauntlet.SignInMethodPasskeyAlone && n.UnusualSignIn.Action == UnusualSignInFlag {
				found = true
			}
		}
		if !found {
			t.Errorf("notices = %+v, want an unusual-sign-in notice with method passkey_alone", e.notices.all())
		}
	})
	t.Run("confirm is not skipped", func(t *testing.T) {
		e := newAloneEnv(t)
		e.g.cfg.UnusualSignIns = UnusualSignInPolicy{Action: UnusualSignInConfirm}
		e.country = "FR"
		c := newBrowserJar(t)
		resp, body := e.signIn(t, c, e.fake)
		if resp.StatusCode != http.StatusOK || strings.TrimSpace(body) != `{"confirm":true}` {
			t.Fatalf("passkey sign-in owing a code = %d %q, want 200 {\"confirm\":true}", resp.StatusCode, body)
		}
		if got := protectedStatus(t, c, e.ts); got != http.StatusUnauthorized {
			t.Errorf("a sign-in owing a code reached a protected route with %d", got)
		}
		code := e.notices.lastCode()
		if code == "" {
			t.Fatal("no confirmation code was delivered")
		}
		confirmed := postJSON(t, c, e.ts.URL+loginConfirmPath, loginConfirmRequest{Code: code})
		_ = confirmed.Body.Close()
		if confirmed.StatusCode != http.StatusOK {
			t.Fatalf("confirming returned %d", confirmed.StatusCode)
		}
		status, list := listSessions(t, c, e.ts)
		if status != http.StatusOK || currentRow(t, list).Method != gauntlet.SignInMethodPasskeyAlone {
			t.Errorf("session after the confirmation = %d %+v, want method passkey_alone", status, list.Sessions)
		}
	})
	t.Run("block", func(t *testing.T) {
		e := newAloneEnv(t)
		e.g.cfg.UnusualSignIns = UnusualSignInPolicy{Action: UnusualSignInBlock}
		e.country = "FR"
		c := newBrowserJar(t)
		resp, body := e.signIn(t, c, e.fake)
		wantStatusClass(t, resp, body, http.StatusForbidden, classSignInRefused)
		if got := protectedStatus(t, c, e.ts); got != http.StatusUnauthorized {
			t.Errorf("a blocked passkey sign-in reached a protected route with %d", got)
		}
		entry := findAuditEntry(t, e.g, "user.login_refused")
		if !strings.Contains(entry.Detail, "method=passkey_alone") {
			t.Errorf("user.login_refused detail = %q, want method=passkey_alone", entry.Detail)
		}
		wantEvents(t, e.events.all(), "refused/passkey_alone")
	})
	t.Run("Decide sees the method and may relax it", func(t *testing.T) {
		e := newAloneEnv(t)
		var seen gauntlet.SignInMethod
		e.g.cfg.UnusualSignIns = UnusualSignInPolicy{Action: UnusualSignInConfirm,
			Decide: func(_ context.Context, c UnusualSignInCase) (UnusualSignInAction, error) {
				seen = c.Method
				if c.Method == gauntlet.SignInMethodPasskeyAlone {
					return UnusualSignInFlag, nil
				}
				return UnusualSignInBlock, nil
			}}
		e.country = "FR"
		c := newBrowserJar(t)
		if resp, body := e.signIn(t, c, e.fake); resp.StatusCode != http.StatusOK || strings.Contains(body, "confirm") {
			t.Fatalf("a passkey sign-in Decide relaxed = %d %q, want 200 and a session", resp.StatusCode, body)
		}
		if seen != gauntlet.SignInMethodPasskeyAlone {
			t.Errorf("Decide saw method %q, want passkey_alone", seen)
		}
		if got := protectedStatus(t, c, e.ts); got != http.StatusOK {
			t.Errorf("the relaxed sign-in reached a protected route with %d, want 200", got)
		}
	})
}

// -- a passkey resumes a timed-out session (#71) ---------------------------

// timedOut signs bilbo in with fake alone at t0 and moves the clock two
// hours on, past the idle timeout and inside the ceiling.
func (e *aloneEnv) timedOutPasskeySession(t *testing.T) (c *http.Client, t0 time.Time) {
	t.Helper()
	c = newBrowserJar(t)
	e.mustSignIn(t, c)
	t0 = e.clock.now()
	e.clock.set(t0.Add(2 * time.Hour))
	if got := protectedStatus(t, c, e.ts); got != http.StatusUnauthorized {
		t.Fatalf("the session did not time out: %d", got)
	}
	return c, t0
}

func (e *aloneEnv) reauthAssertion(t *testing.T, c *http.Client, fake *passkeytest.FakeAuthenticator) (*http.Response, []byte) {
	t.Helper()
	options, _ := e.mustBegin(t, c)
	return e.reauthWith(t, c, reauthenticateRequest{Assertion: signInAssertionBody(t, fake, options)})
}

func (e *aloneEnv) reauthWith(t *testing.T, c *http.Client, req reauthenticateRequest) (*http.Response, []byte) {
	t.Helper()
	resp := postJSON(t, c, e.ts.URL+reauthenticatePath, req)
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

func TestAUserVerifyingPasskeyResumesATimedOutSession(t *testing.T) {
	e := newAloneEnv(t)
	c, t0 := e.timedOutPasskeySession(t)
	old := sessionCookie(t, c, e.ts)
	e.events.events = nil

	resp, body := e.reauthAssertion(t, c, e.fake)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resuming with a passkey returned %d: %s", resp.StatusCode, body)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil || got["username"] != passkeyBilboUsername || len(got) != 2 {
		t.Errorf("body = %s, want login's success body", body)
	}
	if sessionCookie(t, c, e.ts) == old {
		t.Error("the session ID did not change")
	}
	if got := protectedStatus(t, c, e.ts); got != http.StatusOK {
		t.Errorf("the resumed session was refused: %d", got)
	}
	if st := sessionState(t, c, e.ts); st["signedInSince"] != t0.Format(time.RFC3339) {
		t.Errorf("signedInSince = %v, want the original sign-in %s", st["signedInSince"], t0.Format(time.RFC3339))
	}
	if !cookieCleared(resp, passkeySignInCookieName) {
		t.Error("the ceremony cookie was not cleared by the resume")
	}
	// The resumed session continues the sign-in: its method stays.
	status, list := listSessions(t, c, e.ts)
	if status != http.StatusOK || currentRow(t, list).Method != gauntlet.SignInMethodPasskeyAlone {
		t.Errorf("resumed session list = %d %+v, want method passkey_alone kept", status, list.Sessions)
	}
	wantEvents(t, e.events.all(), "success/resume")
	if rec := auditEntries(e.audit, "user.reauthenticated"); len(rec) != 1 || rec[0].Detail != "session resumed with passkey"+fixtureFromSuffix {
		t.Errorf("user.reauthenticated records = %+v, want one, resumed with passkey", rec)
	}
	// The old ID is dead.
	if r, _ := withCookie(t, e.ts, http.MethodGet, "/api/protected", old, nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("the old ID reached a protected route: %d", r.StatusCode)
	}
}

// A passkey for a different account resumes nothing: the user handle
// must be the timed-out session's own account. The refusal counts, and
// the session stays resumable by its own owner.
func TestAPasskeyForAnotherAccountCannotResumeASession(t *testing.T) {
	e := newAloneEnv(t)
	frodo, _ := e.registerFrodo(t)
	c, _ := e.timedOutPasskeySession(t)
	e.events.events = nil

	resp, body := e.reauthAssertion(t, c, frodo)
	wantResumeProblem(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
	wantEvents(t, e.events.all(), "factor_refused/resume")
	if ev := lastEvent(t, e); ev.UserID != e.id {
		t.Errorf("event = %+v, want it counted on the session's account", ev)
	}
	if st := sessionState(t, c, e.ts); st["resumable"] != true {
		t.Errorf("session state after the refusal = %v, want still resumable", st)
	}
	if got := protectedStatus(t, c, e.ts); got != http.StatusUnauthorized {
		t.Errorf("another account's passkey resumed the session: %d", got)
	}

	// Its own owner's passkey still does.
	if resp, body = e.reauthAssertion(t, c, e.fake); resp.StatusCode != http.StatusOK {
		t.Fatalf("the owner's passkey after that refusal returned %d: %s", resp.StatusCode, body)
	}
}

func TestResumeWithAPasskeyNeedsUserVerification(t *testing.T) {
	e := newAloneEnv(t)
	c, _ := e.timedOutPasskeySession(t)
	e.fake.NoUserVerification = true
	resp, body := e.reauthAssertion(t, c, e.fake)
	wantResumeProblem(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
	if got := protectedStatus(t, c, e.ts); got != http.StatusUnauthorized {
		t.Errorf("a non-user-verified passkey resumed the session: %d", got)
	}
}

func TestResumeWithAPasskeyRefusalsAndOffSwitch(t *testing.T) {
	e := newAloneEnv(t)
	c, _ := e.timedOutPasskeySession(t)
	e.events.events = nil
	options, _ := e.mustBegin(t, c)
	assertion := signInAssertionBody(t, e.fake, options)

	// A password and an assertion together is a bad request.
	resp, body := e.reauthWith(t, c, reauthenticateRequest{Password: passkeyBilboPassword, Assertion: assertion})
	wantResumeProblem(t, resp, body, http.StatusBadRequest, classInvalidRequest)

	// No ceremony cookie: nothing to finish, and nothing counted.
	resp, body = withCookie(t, e.ts, http.MethodPost, reauthenticatePath, sessionCookie(t, c, e.ts), reauthenticateRequest{Assertion: assertion})
	wantResumeProblem(t, resp, body, http.StatusUnauthorized, classStepExpired)
	if n := len(e.events.all()); n != 0 {
		t.Errorf("a resume with no ceremony recorded %d events, want none", n)
	}

	// Sign-in off: an assertion is a request for a route that is not there.
	e.g.cfg.PasskeySignIn = false
	resp, body = e.reauthWith(t, c, reauthenticateRequest{Assertion: assertion})
	wantResumeProblem(t, resp, body, http.StatusNotFound, classNotFound)
	// The password still resumes.
	if resp, body = e.reauthWith(t, c, reauthenticateRequest{Password: passkeyBilboPassword}); resp.StatusCode != http.StatusOK {
		t.Errorf("the password with passkey sign-in off returned %d: %s", resp.StatusCode, body)
	}
}

// A resume spends its ceremony: the same assertion and cookie cannot
// resume the session again once it has timed out again.
func TestResumeWithAPasskeyIsOneShot(t *testing.T) {
	e := newAloneEnv(t)
	c, t0 := e.timedOutPasskeySession(t)
	options, begin := e.mustBegin(t, c)
	assertion := signInAssertionBody(t, e.fake, options)
	sealed := cookieValue(begin, passkeySignInCookieName)

	b, _ := json.Marshal(reauthenticateRequest{Assertion: assertion})
	do := func(sessionID string) (int, string) {
		req, err := http.NewRequest(http.MethodPost, e.ts.URL+reauthenticatePath, bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(csrfHeaderName, testCSRFValue)
		req.AddCookie(&http.Cookie{Name: testCookieName, Value: sessionID})
		req.AddCookie(&http.Cookie{Name: passkeySignInCookieName, Value: sealed})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode, cookieValue(resp, testCookieName)
	}
	status, resumed := do(sessionCookie(t, c, e.ts))
	if status != http.StatusOK || resumed == "" {
		t.Fatalf("first resume returned %d, want 200 with a new session", status)
	}
	e.clock.set(t0.Add(4 * time.Hour)) // timed out again, still inside the ceiling
	if status, _ = do(resumed); status != http.StatusUnauthorized {
		t.Errorf("replayed resume returned %d, want 401", status)
	}
}
