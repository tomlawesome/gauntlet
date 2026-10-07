// Proving an unusual sign-in with a passkey (#65, ADR-0009): the prove
// action, its fall-backs, and POST /api/auth/login/prove/begin and
// /api/auth/login/prove. Driven with the shared fake authenticator
// (internal/passkeytest) on aloneEnv, shaped on login_passkey_handler_test.go
// and the confirm tests in unusual_test.go.
package gate

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/internal/passkeytest"
	"github.com/tomlawesome/gauntlet/oidc"
)

// proveEnv is aloneEnv with bilbo holding a TOTP app besides his
// passkey, so he can sign in by password and a code, and a policy that
// asks for prove on every unusual sign-in. His browser from before
// (e.bilbo) is the one the account remembers; any fresh jar is new.
type proveEnv struct {
	*aloneEnv
	secret []byte
}

func newProveEnv(t *testing.T) *proveEnv {
	t.Helper()
	e := &proveEnv{aloneEnv: newAloneEnv(t)}
	e.g.cfg.UnusualSignIns = UnusualSignInPolicy{Action: UnusualSignInProve}
	enrolled := totpEnrolAs(t, e.bilbo, e.ts, passkeyBilboPassword)
	secret, err := gauntlet.DecodeTOTPSecret(enrolled.Secret)
	if err != nil {
		t.Fatal(err)
	}
	e.secret = secret
	resp := postJSON(t, e.bilbo, e.ts.URL+totpConfirmPath, totpConfirmRequest{Code: gauntlet.GenerateTOTPCode(secret, totpCounterNow(e.clock.now()))})
	if status, body := readAll(t, resp); status != http.StatusOK {
		t.Fatalf("totp/confirm = %d %s", status, body)
	}
	return e
}

// codeSignIn signs bilbo in from c by password and a fresh TOTP code and
// returns the second step's response.
func (e *proveEnv) codeSignIn(t *testing.T, c *http.Client) (*http.Response, string) {
	t.Helper()
	first := postJSON(t, c, e.ts.URL+"/api/auth/login", credentialsRequest{Username: passkeyBilboUsername, Password: passkeyBilboPassword})
	if status, body := readAll(t, first); status != http.StatusOK || !strings.Contains(body, `"secondFactor"`) {
		t.Fatalf("password step = %d %s", status, body)
	}
	e.clock.set(e.clock.now().Add(time.Minute)) // a counter the confirm did not use
	resp := submitLoginFactor(t, c, e.ts, gauntlet.GenerateTOTPCode(e.secret, totpCounterNow(e.clock.now())))
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(raw)
}

// held is a fresh browser signed in as far as the prove challenge.
func (e *proveEnv) held(t *testing.T) *http.Client {
	t.Helper()
	c := newBrowserJar(t)
	resp, body := e.codeSignIn(t, c)
	want := `{"passkeyOrigin":"` + passkeyTestPublicURL + `","prove":"passkey"}`
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(body) != want {
		t.Fatalf("code sign-in = %d %s, want 200 %s", resp.StatusCode, body, want)
	}
	return c
}

func (e *proveEnv) proveBegin(t *testing.T, c *http.Client) *http.Response {
	t.Helper()
	return postJSON(t, c, e.ts.URL+loginProveBeginPath, struct{}{})
}

func (e *proveEnv) mustProveBegin(t *testing.T, c *http.Client) *protocol.CredentialAssertion {
	t.Helper()
	resp := e.proveBegin(t, c)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("login/prove/begin = %d %s", resp.StatusCode, body)
	}
	var out protocol.CredentialAssertion
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return &out
}

func (e *proveEnv) proveFinish(t *testing.T, c *http.Client, assertion json.RawMessage) (*http.Response, string) {
	t.Helper()
	resp := postJSON(t, c, e.ts.URL+loginProvePath, loginProveRequest{Assertion: assertion})
	status, body := readAll(t, resp)
	_ = status
	return resp, body
}

// prove is begin and finish with fake from c.
func (e *proveEnv) prove(t *testing.T, c *http.Client, fake *passkeytest.FakeAuthenticator) (*http.Response, string) {
	t.Helper()
	return e.proveFinish(t, c, signInAssertionBody(t, fake, e.mustProveBegin(t, c)))
}

func (e *proveEnv) ticket(t *testing.T, c *http.Client) *http.Cookie {
	t.Helper()
	for _, ck := range c.Jar.Cookies(mustParseURL(t, e.ts.URL+loginProvePath)) {
		if ck.Name == confirmLoginCookieName {
			return ck
		}
	}
	t.Fatal("the browser holds no confirm ticket")
	return nil
}

// -- the happy path ---------------------------------------------------------

func TestProveHoldsACodeSignInUntilAPasskeyAnswers(t *testing.T) {
	e := newProveEnv(t)
	c := newBrowserJar(t)
	resp, body := e.codeSignIn(t, c)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"prove":"passkey"`) || strings.Contains(body, "confirm") {
		t.Fatalf("code sign-in = %d %s", resp.StatusCode, body)
	}
	if ck := cookieNamed(resp, confirmLoginCookieName); ck == nil || ck.MaxAge != 900 || ck.Path != "/api/auth/login" || !ck.HttpOnly {
		t.Errorf("ticket cookie = %+v", ck)
	}
	if cookieNamed(resp, e.g.sessionCookieName()) != nil {
		t.Error("a session cookie was set before the passkey")
	}
	if got := protectedStatus(t, c, e.ts); got != http.StatusUnauthorized {
		t.Errorf("the held sign-in reached a protected route with %d", got)
	}
	if len(e.notices.allCodes()) != 0 {
		t.Error("a confirmation code was delivered under prove")
	}
	if ev := lastEvent(t, e.aloneEnv); ev.Outcome != gauntlet.SignInConfirmSent || ev.Client.Unusual != gauntlet.SignalNewBrowser {
		t.Errorf("held row = %+v", ev)
	}

	resp, body = e.prove(t, c, e.fake)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"username":"bilbo"`) {
		t.Fatalf("login/prove = %d %s", resp.StatusCode, body)
	}
	if ck := cookieNamed(resp, confirmLoginCookieName); ck == nil || ck.MaxAge >= 0 {
		t.Error("the ticket was not cleared")
	}
	if got := protectedStatus(t, c, e.ts); got != http.StatusOK {
		t.Errorf("the proved sign-in reached a protected route with %d", got)
	}
	ev := lastEvent(t, e.aloneEnv)
	if ev.Outcome != gauntlet.SignInSuccess || !ev.Confirmed || ev.Method != gauntlet.SignInMethodCode || ev.Client.Unusual != gauntlet.SignalNewBrowser {
		t.Errorf("success row = %+v", ev)
	}
	entry := findAuditEntry(t, e.g, "user.login")
	if !strings.HasPrefix(entry.Detail, "unusual=new-browser; action=prove; ") {
		t.Errorf("user.login detail = %q", entry.Detail)
	}
	_, list := listSessions(t, c, e.ts)
	if row := currentRow(t, list); row.Method != gauntlet.SignInMethodCode {
		t.Errorf("session row = %+v, want method code", row)
	}
	// The passkey's counter was recorded by the shared helper.
	if u, _ := e.g.deps.Users.Get(e.id); u.Passkeys[0].LastUsedAt.IsZero() {
		t.Error("the passkey's use was not recorded")
	}
}

// -- refusals -----------------------------------------------------------------

func TestProveRefusesAPasskeyThatIsNotTheAccounts(t *testing.T) {
	e := newProveEnv(t)
	c := e.held(t)
	frodo, _ := e.registerFrodo(t)
	options := e.mustProveBegin(t, c)

	for name, fake := range map[string]*passkeytest.FakeAuthenticator{
		"another account's passkey":   frodo,
		"a passkey nobody registered": newFake(e.g),
	} {
		resp, body := e.proveFinish(t, c, signInAssertionBody(t, fake, options))
		wantStatusClass(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
		if !strings.Contains(body, passkeyNotVerified) {
			t.Errorf("%s: body = %s", name, body)
		}
		if got := protectedStatus(t, c, e.ts); got != http.StatusUnauthorized {
			t.Fatalf("%s reached a protected route with %d", name, got)
		}
		if ev := lastEvent(t, e.aloneEnv); ev.Outcome != gauntlet.SignInConfirmRefused || ev.Method != gauntlet.SignInMethodPasskey {
			t.Errorf("%s: row = %+v", name, ev)
		}
	}
	// A wrong try keeps the ticket and the ceremony: the right passkey
	// can still finish inside the window.
	resp, body := e.proveFinish(t, c, signInAssertionBody(t, e.fake, options))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the right passkey after two wrong ones = %d %s", resp.StatusCode, body)
	}
}

func TestProveRefusalsAreCountedAndLimited(t *testing.T) {
	e := newProveEnv(t)
	c := e.held(t)
	options := e.mustProveBegin(t, c)
	stranger := newFake(e.g)
	for i := range 5 {
		resp, body := e.proveFinish(t, c, signInAssertionBody(t, stranger, options))
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong passkey %d = %d %s", i+1, resp.StatusCode, body)
		}
	}
	if u, _ := e.g.deps.Users.Get(e.id); !u.MustChangePassword {
		t.Error("five refused assertions in a row did not force a password change")
	}
	resp, body := e.proveFinish(t, c, signInAssertionBody(t, e.fake, options))
	wantStatusClass(t, resp, body, http.StatusTooManyRequests, classRateLimited)
	if got := protectedStatus(t, c, e.ts); got != http.StatusUnauthorized {
		t.Errorf("a limited prove reached a protected route with %d", got)
	}
}

func TestProveFinishDeadCeremony(t *testing.T) {
	e := newProveEnv(t)
	c := e.held(t)
	body := signInAssertionBody(t, e.fake, e.mustProveBegin(t, c))
	// No ceremony cookie: the ticket stays, the answer is step-expired.
	c.Jar.SetCookies(mustParseURL(t, e.ts.URL), []*http.Cookie{{Name: passkeyAssertCookieName, Value: "", Path: passkeyAssertCookiePath, MaxAge: -1}})
	resp, raw := e.proveFinish(t, c, body)
	wantStatusClass(t, resp, raw, http.StatusUnauthorized, classStepExpired)
	// A ceremony from login/passkey/begin is sealed for another ceremony.
	c.Jar.SetCookies(mustParseURL(t, e.ts.URL), []*http.Cookie{{Name: passkeyAssertCookieName, Value: "garbage", Path: passkeyAssertCookiePath}})
	resp, raw = e.proveFinish(t, c, body)
	wantStatusClass(t, resp, raw, http.StatusUnauthorized, classStepExpired)
	if cookieNamed(resp, passkeyAssertCookieName) == nil {
		t.Error("a dead ceremony's cookie was not cleared")
	}
	// The ticket survives: begin again and finish.
	if resp, raw := e.prove(t, c, e.fake); resp.StatusCode != http.StatusOK {
		t.Fatalf("a fresh ceremony on the same ticket = %d %s", resp.StatusCode, raw)
	}
}

func TestProveTicketChecks(t *testing.T) {
	e := newProveEnv(t)
	c := e.held(t)
	body := signInAssertionBody(t, e.fake, e.mustProveBegin(t, c))
	ticket := e.ticket(t, c)

	// Another browser holds no ticket: begin and finish both.
	other := newBrowserJar(t)
	if resp := e.proveBegin(t, other); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("begin with no ticket = %d", resp.StatusCode)
	} else {
		_ = resp.Body.Close()
	}
	resp, raw := e.proveFinish(t, other, body)
	wantStatusClass(t, resp, raw, http.StatusUnauthorized, classStepExpired)

	// Malformed bodies are 400, before the ticket.
	for _, b := range []any{struct{}{}, []int{}, "text"} {
		if status, _ := readAll(t, postJSON(t, c, e.ts.URL+loginProvePath, b)); status != http.StatusBadRequest {
			t.Errorf("body %v = %d, want 400", b, status)
		}
	}

	// Complete it, then put the spent ticket back: a replay.
	if resp, raw := e.proveFinish(t, c, body); resp.StatusCode != http.StatusOK {
		t.Fatalf("finish = %d %s", resp.StatusCode, raw)
	}
	c.Jar.SetCookies(mustParseURL(t, e.ts.URL), []*http.Cookie{ticket})
	if resp := e.proveBegin(t, c); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("begin on a spent ticket = %d", resp.StatusCode)
	} else {
		_ = resp.Body.Close()
	}
	resp, raw = e.proveFinish(t, c, body)
	wantStatusClass(t, resp, raw, http.StatusUnauthorized, classStepExpired)
}

func TestProveTicketExpires(t *testing.T) {
	e := newProveEnv(t)
	c := e.held(t)
	body := signInAssertionBody(t, e.fake, e.mustProveBegin(t, c))
	e.clock.set(e.clock.now().Add(ConfirmCodeLifetime))
	resp, raw := e.proveFinish(t, c, body)
	wantStatusClass(t, resp, raw, http.StatusUnauthorized, classStepExpired)
	if ck := cookieNamed(resp, confirmLoginCookieName); ck == nil || ck.MaxAge >= 0 {
		t.Error("an expired ticket's cookie was not cleared")
	}
	if resp := e.proveBegin(t, c); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("begin on an expired ticket = %d", resp.StatusCode)
	} else {
		_ = resp.Body.Close()
	}
}

// A prove ticket is not a confirm ticket, and the other way round.
func TestProveAndConfirmTicketsAreNotInterchangeable(t *testing.T) {
	e := newProveEnv(t)
	c := e.held(t)
	status, body := readAll(t, postJSON(t, c, e.ts.URL+loginConfirmPath, loginConfirmRequest{Code: "00000000"}))
	if status != http.StatusUnauthorized || problemType(t, body) != "step-expired" {
		t.Errorf("a prove ticket at login/confirm = %d %s", status, body)
	}

	// A confirm ticket (a stale-passkey account is held for a code).
	e2 := newProveEnv(t)
	e2.g.deps.Passkeys = mustRelyingParty(t, "https://new-passkeys.example.org")
	c2 := newBrowserJar(t)
	if _, body := e2.codeSignIn(t, c2); strings.TrimSpace(body) != `{"confirm":true}` {
		t.Fatalf("code sign-in = %s", body)
	}
	resp, raw := e2.proveFinish(t, c2, json.RawMessage(`{"id":"x"}`))
	wantStatusClass(t, resp, raw, http.StatusUnauthorized, classStepExpired)
}

// -- begin ----------------------------------------------------------------------

func TestProveBeginNeedsUsablePasskeysAndAReadyRelyingParty(t *testing.T) {
	e := newProveEnv(t)
	c := e.held(t)
	rp := e.g.deps.Passkeys
	e.g.deps.Passkeys = mustRelyingParty(t, "https://new-passkeys.example.org") // the passkey is now stale
	resp := e.proveBegin(t, c)
	wantStatusClass(t, resp, readBody(t, resp), http.StatusConflict, classConflict)
	e.g.deps.Passkeys = rp
	if resp := e.proveBegin(t, c); resp.StatusCode != http.StatusOK {
		t.Errorf("begin with the passkey usable again = %d", resp.StatusCode)
	} else {
		_ = resp.Body.Close()
	}
	// The relying party goes away: the routes do not exist.
	e.g.deps.Passkeys = nil
	for _, path := range []string{loginProveBeginPath, loginProvePath} {
		body := any(struct{}{})
		if path == loginProvePath {
			body = loginProveRequest{Assertion: json.RawMessage(`{}`)}
		}
		if status, _ := readAll(t, postJSON(t, c, e.ts.URL+path, body)); status != http.StatusNotFound {
			t.Errorf("%s with no passkeys = %d, want 404", path, status)
		}
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	_, body := readAll(t, resp)
	return body
}

func TestProveRoutesNeedTheCSRFHeader(t *testing.T) {
	e := newProveEnv(t)
	for _, path := range []string{loginProveBeginPath, loginProvePath} {
		req, _ := http.NewRequest(http.MethodPost, e.ts.URL+path, strings.NewReader(`{}`))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if status, _ := readAll(t, resp); status != http.StatusForbidden && status != http.StatusBadRequest {
			t.Errorf("%s without the CSRF header = %d", path, status)
		}
	}
}

// A passkey removed between the ceremony and the proof is refused.
func TestProveRefusesAPasskeyRemovedMidCeremony(t *testing.T) {
	e := newProveEnv(t)
	c := e.held(t)
	body := signInAssertionBody(t, e.fake, e.mustProveBegin(t, c))
	// Remove the passkey between the ceremony's read and the record.
	pk := e.g.deps.Users
	u, _ := pk.Get(e.id)
	if _, err := pk.DeletePasskey(e.id, u.Passkeys[0].ID); err != nil {
		t.Fatal(err)
	}
	resp, raw := e.proveFinish(t, c, body)
	wantStatusClass(t, resp, raw, http.StatusUnauthorized, classInvalidCredentials)
}

// A clone warning refuses a proof, as it does a sign-in.
func TestProveCloneWarningRefuses(t *testing.T) {
	e := newProveEnv(t)
	c := e.held(t)
	// Raise the stored counter above what the fake will report.
	u, _ := e.g.deps.Users.Get(e.id)
	if _, err := e.g.deps.Users.RecordPasskeyAssertionIfFresh(e.id, u.Passkeys[0].ID, 1000, e.clock.now()); err != nil {
		t.Fatal(err)
	}
	e.fake.SignCount = 5
	resp, body := e.prove(t, c, e.fake)
	wantStatusClass(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
	_ = findAuditEntry(t, e.g, "account.passkey_clone_suspected")
}

// -- what prove resolves to -----------------------------------------------------

// A passkey sign-in, alone or behind the password, is already proved.
func TestProveDegradesToFlagForPasskeySignIns(t *testing.T) {
	t.Run("passkey alone", func(t *testing.T) {
		e := newProveEnv(t)
		e.country = "FR"
		resp, body := e.signIn(t, newBrowserJar(t), e.fake)
		if resp.StatusCode != http.StatusOK || strings.Contains(body, "prove") {
			t.Fatalf("passkey-alone sign-in under prove = %d %s, want a session", resp.StatusCode, body)
		}
		if entry := findAuditEntry(t, e.g, "user.login"); !strings.HasPrefix(entry.Detail, "unusual=new-browser,new-country; action=flag; ") {
			t.Errorf("user.login detail = %q", entry.Detail)
		}
	})
	t.Run("passkey as the second factor", func(t *testing.T) {
		e := newProveEnv(t)
		c := startPasskeyLogin(t, e.ts, passkeyBilboUsername, passkeyBilboPassword)
		resp := submitPasskeyAssertion(t, c, e.ts, e.fake, passkeyLoginFactorBegin(t, c, e.ts))
		if status, body := readAll(t, resp); status != http.StatusOK || strings.Contains(body, "prove") {
			t.Fatalf("passkey second step under prove = %d %s", status, body)
		}
		if entry := findAuditEntry(t, e.g, "user.login"); !strings.HasPrefix(entry.Detail, "unusual=new-browser; action=flag; ") {
			t.Errorf("user.login detail = %q", entry.Detail)
		}
	})
}

// An account with no passkey usable here cannot prove: it is held for a
// code when one can be delivered, else refused.
func TestProveWithNoUsablePasskeyFallsBack(t *testing.T) {
	t.Run("confirm when a code can be delivered", func(t *testing.T) {
		e := newProveEnv(t)
		e.g.deps.Passkeys = mustRelyingParty(t, "https://new-passkeys.example.org")
		c := newBrowserJar(t)
		resp, body := e.codeSignIn(t, c)
		if resp.StatusCode != http.StatusOK || strings.TrimSpace(body) != `{"confirm":true}` {
			t.Fatalf("= %d %s, want 200 {\"confirm\":true}", resp.StatusCode, body)
		}
		code := e.notices.lastCode()
		if code == "" {
			t.Fatal("no code delivered")
		}
		if status, body := readAll(t, postJSON(t, c, e.ts.URL+loginConfirmPath, loginConfirmRequest{Code: code})); status != http.StatusOK {
			t.Fatalf("confirm = %d %s", status, body)
		}
		if entry := findAuditEntry(t, e.g, "user.login"); !strings.HasPrefix(entry.Detail, "unusual=new-browser; action=confirm; ") {
			t.Errorf("user.login detail = %q", entry.Detail)
		}
	})
	t.Run("block when none can", func(t *testing.T) {
		e := newProveEnv(t)
		e.g.deps.Passkeys = mustRelyingParty(t, "https://new-passkeys.example.org")
		e.g.cfg.DeliverConfirmCode = nil
		c := newBrowserJar(t)
		resp, body := e.codeSignIn(t, c)
		wantStatusClass(t, resp, body, http.StatusForbidden, classSignInRefused)
		if got := protectedStatus(t, c, e.ts); got != http.StatusUnauthorized {
			t.Errorf("a blocked sign-in reached a protected route with %d", got)
		}
		if entry := findAuditEntry(t, e.g, "user.login_refused"); !strings.Contains(entry.Detail, "reason=policy") {
			t.Errorf("user.login_refused detail = %q", entry.Detail)
		}
	})
	t.Run("an account with no passkey at all", func(t *testing.T) {
		e := newProveEnv(t)
		u, _ := e.g.deps.Users.Get(e.id)
		if _, err := e.g.deps.Users.DeletePasskey(e.id, u.Passkeys[0].ID); err != nil {
			t.Fatal(err)
		}
		c := newBrowserJar(t)
		if _, body := e.codeSignIn(t, c); strings.TrimSpace(body) != `{"confirm":true}` {
			t.Fatalf("body = %s", body)
		}
	})
}

func TestResolveProve(t *testing.T) {
	e := newProveEnv(t)
	u, _ := e.g.deps.Users.Get(e.id)
	for _, c := range []struct {
		method gauntlet.SignInMethod
		want   UnusualSignInAction
	}{
		{gauntlet.SignInMethodCode, UnusualSignInProve},
		{gauntlet.SignInMethodPassword, UnusualSignInProve},
		{gauntlet.SignInMethodSSO, UnusualSignInProve},
		{gauntlet.SignInMethodPasskey, UnusualSignInFlag},
		{gauntlet.SignInMethodPasskeyAlone, UnusualSignInFlag},
	} {
		if got := e.g.resolveProve(u, c.method); got != c.want {
			t.Errorf("resolveProve(%s) = %q, want %q", c.method, got, c.want)
		}
	}
	nobody := &gauntlet.User{ID: "x"}
	if got := e.g.resolveProve(nobody, gauntlet.SignInMethodCode); got != UnusualSignInConfirm {
		t.Errorf("no passkey, deliverable = %q, want confirm", got)
	}
	e.g.cfg.DeliverConfirmCode = nil
	if got := e.g.resolveProve(nobody, gauntlet.SignInMethodCode); got != UnusualSignInBlock {
		t.Errorf("no passkey, not deliverable = %q, want block", got)
	}
}

// -- Decide ---------------------------------------------------------------------

func TestDecideCanReturnProve(t *testing.T) {
	e := newProveEnv(t)
	d := &decideRecorder{answer: answering(UnusualSignInProve)}
	e.g.cfg.UnusualSignIns = UnusualSignInPolicy{Action: UnusualSignInFlag, Decide: d.decide}
	e.held(t)
	got := d.all()
	if len(got) != 1 || got[0].Default != UnusualSignInFlag || !got[0].CanProve || got[0].Method != gauntlet.SignInMethodCode {
		t.Fatalf("cases = %+v, want one: default flag, CanProve, method code", got)
	}

	// With no passkey usable here Decide is told, and its prove still
	// resolves to a code.
	e.g.deps.Passkeys = mustRelyingParty(t, "https://new-passkeys.example.org")
	_, body := e.codeSignIn(t, newBrowserJar(t))
	if strings.TrimSpace(body) != `{"confirm":true}` {
		t.Errorf("body = %s", body)
	}
	got = d.all()
	if len(got) != 2 || got[1].CanProve {
		t.Errorf("second case = %+v, want CanProve false", got[len(got)-1])
	}
}

// Decide's prove is not decide-invalid, even with nothing to deliver a code.
func TestDecideProveWithoutDeliveryBlocksAsPolicy(t *testing.T) {
	e := newProveEnv(t)
	e.g.cfg.DeliverConfirmCode = nil
	e.g.deps.Passkeys = mustRelyingParty(t, "https://new-passkeys.example.org")
	e.g.cfg.UnusualSignIns = UnusualSignInPolicy{Decide: func(context.Context, UnusualSignInCase) (UnusualSignInAction, error) {
		return UnusualSignInProve, nil
	}}
	resp, body := e.codeSignIn(t, newBrowserJar(t))
	wantStatusClass(t, resp, body, http.StatusForbidden, classSignInRefused)
	if entry := findAuditEntry(t, e.g, "user.login_refused"); !strings.Contains(entry.Detail, "reason=policy") {
		t.Errorf("detail = %q", entry.Detail)
	}
}

// -- policy ---------------------------------------------------------------------

func TestProveRanksBetweenConfirmAndBlock(t *testing.T) {
	if UnusualSignInConfirm.rank() >= UnusualSignInProve.rank() || UnusualSignInProve.rank() >= UnusualSignInBlock.rank() {
		t.Error("prove does not rank between confirm and block")
	}
	g := &Gate{cfg: Config{UnusualSignIns: UnusualSignInPolicy{
		NewBrowser: UnusualSignInConfirm, NewCountry: UnusualSignInProve, ImpossibleTravel: UnusualSignInFlag}}}
	signals := gauntlet.SignalNewBrowser | gauntlet.SignalNewCountry | gauntlet.SignalImpossibleTravel
	if a, kept := g.resolveUnusual(signals); a != UnusualSignInProve || kept != signals {
		t.Errorf("resolveUnusual = %q %q, want prove over confirm and flag", a, kept)
	}
	g.cfg.UnusualSignIns.NewCountry = UnusualSignInBlock
	if a, _ := g.resolveUnusual(signals); a != UnusualSignInBlock {
		t.Errorf("block over prove = %q", a)
	}
}

// The challenge a held sign-in is answered with, and who can be held.
func TestProveChallengeShape(t *testing.T) {
	e := newProveEnv(t)
	u, _ := e.g.deps.Users.Get(e.id)
	if !e.g.canProve(u, gauntlet.SignInMethodSSO) || e.g.canProve(u, gauntlet.SignInMethodPasskey) {
		t.Error("canProve disagrees with the method")
	}
	v := unusualVerdict{action: UnusualSignInProve}
	body, _ := json.Marshal(e.g.heldChallenge(v))
	if string(body) != `{"passkeyOrigin":"`+passkeyTestPublicURL+`","prove":"passkey"}` {
		t.Errorf("challenge = %s", body)
	}
	if e.g.heldChallenge(unusualVerdict{action: UnusualSignInConfirm}) == nil {
		t.Error("no confirm challenge")
	}
}

// An SSO sign-in can be proved too, once the account holds a passkey
// usable here: the callback sends the browser to the login page with
// prove=1 and a prove ticket; without one it falls back to a code.
func TestProveSSOCallback(t *testing.T) {
	for _, withPasskey := range []bool{true, false} {
		g, ts, fp := newOIDCTestGate(t, oidc.Policy{})
		rec := &noticeRecorder{}
		g.cfg.DeliverConfirmCode = rec.deliver
		g.cfg.UnusualSignIns = UnusualSignInPolicy{NewBrowser: UnusualSignInProve}
		g.deps.Passkeys = mustRelyingParty(t, passkeyTestPublicURL)
		callback := func(jar http.CookieJar) *http.Response {
			t.Helper()
			fs, err := oidc.NewFlowState(time.Now())
			if err != nil {
				t.Fatal(err)
			}
			fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))
			client := noRedirectClient()
			client.Jar = jar
			resp, err := client.Do(oidcCallbackRequest(t, g, ts, fs, "state="+fs.State+"&code=test-code"))
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			return resp
		}
		callback(mustCookieJar(t))
		if withPasskey {
			for _, u := range g.deps.Users.List() {
				if u.OIDCIssuer == "" {
					continue
				}
				if _, err := g.deps.Users.AddPasskey(u.ID, gauntlet.Passkey{ID: []byte("credential"), PublicKey: []byte("key"), RPID: g.deps.Passkeys.RPID(), Name: "key"}); err != nil {
					t.Fatal(err)
				}
			}
		}
		resp := callback(mustCookieJar(t))
		want, held := "?confirm=1", confirmLoginCookieName
		if withPasskey {
			want = "?prove=1"
		}
		if resp.Header.Get("Location") != testLoginPath+want {
			t.Fatalf("withPasskey=%v: redirect = %q, want %s", withPasskey, resp.Header.Get("Location"), want)
		}
		ck := cookieNamed(resp, held)
		if ck == nil || cookieNamed(resp, testCookieName) != nil {
			t.Fatal("want the ticket cookie and no session cookie")
		}
		st, ok := decodeConfirmLogin(ck.Value, time.Now())
		if !ok || st.Prove != withPasskey || st.Method != gauntlet.SignInMethodSSO {
			t.Errorf("withPasskey=%v: ticket = %+v", withPasskey, st)
		}
		if got := len(rec.allCodes()) == 1; got == withPasskey {
			t.Errorf("withPasskey=%v: codes delivered = %d", withPasskey, len(rec.allCodes()))
		}
	}
}
