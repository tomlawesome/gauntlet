// v0.4.1, A1a-R1 (GitLab #101, fail closed): the other routes that
// complete a sign-in -- POST /api/auth/login/factor, POST
// /api/auth/login/passkey and the SSO callback -- refuse when the store
// write that spends an admin's allowance fails, and leave the allowance
// live. POST /api/auth/login is covered by
// v041_allowance_spend_fail_test.go.
//
// These routes also save other things (a spent recovery code, a TOTP
// replay counter, a passkey's use, a newly provisioned SSO account), so
// the backend here refuses exactly the write that clears the allowance
// and lets every other save through: the failure under test is the
// spend, not an earlier step.
package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/oidc"
	"github.com/tomlawesome/gauntlet/persist"
)

// v041SpendBackend is a memory backend that, once armed, refuses any
// Save that would clear a live allowance (the accounts document goes
// from holding a signInAllowedUntil to holding none) and saves
// everything else.
type v041SpendBackend struct {
	*persist.Memory
	armed   atomic.Bool
	refused atomic.Int32
	mu      sync.Mutex
	held    bool // the last saved document held an allowance
}

var v041AllowanceKey = []byte(`"signInAllowedUntil"`)

func (b *v041SpendBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	has := bytes.Contains(payload, v041AllowanceKey)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.armed.Load() && b.held && !has {
		b.refused.Add(1)
		return 0, errors.New("spend-failing test backend: allowance write refused")
	}
	rev, err := b.Memory.Save(ctx, payload, expect)
	if err == nil {
		b.held = has
	}
	return rev, err
}

// -- POST /api/auth/login/factor ---------------------------------------------

func TestV041AllowedSignInWhoseAllowanceCannotBeSpentFailsClosedAtLoginFactor(t *testing.T) {
	for _, factor := range []string{"recovery code", "authenticator app code"} {
		t.Run(factor, func(t *testing.T) {
			backend := &v041SpendBackend{Memory: persist.NewMemory()}
			e := newUnusualEnvWith(t, backend, func(c *Config) {
				c.UnusualSignIns = UnusualSignInPolicy{NewBrowser: UnusualSignInBlock}
			})
			// bob's remembered browser signs in (no factor yet) and then
			// enrols an authenticator app, which brings recovery codes.
			first := newTestBrowser(t)
			e.mustSignIn(t, first, addrLondon)
			secret, codes, _ := totpEnrolAndConfirm(t, first.at(addrLondon), e.ts)
			e.advance(time.Hour)

			used := 0
			next := func() string {
				if factor == "recovery code" {
					used++
					return codes[used-1]
				}
				e.advance(time.Minute) // a fresh counter every time
				return gauntlet.GenerateTOTPCode(secret, totpCounterNow(e.clock.now()))
			}

			// passwordStep starts a sign-in of b; the response asks for the
			// second factor.
			passwordStep := func(b *browser) {
				t.Helper()
				status, body := e.signIn(t, b, addrLondon)
				if status != http.StatusOK || !bytes.Contains([]byte(body), []byte(`"secondFactor"`)) {
					t.Fatalf("bob's password step = %d %s, want 200 asking for the second factor", status, body)
				}
			}
			factorStep := func(b *browser) (*http.Response, int, string) {
				t.Helper()
				resp := postJSON(t, b.at(addrLondon), e.ts.URL+"/api/auth/login/factor", loginFactorRequest{Code: next()})
				status, body := readAll(t, resp)
				return resp, status, body
			}

			// Without the allowance the policy stops this browser.
			b := newTestBrowser(t)
			passwordStep(b)
			if _, status, body := factorStep(b); status != http.StatusForbidden {
				t.Fatalf("a new browser's second step under block = %d %s, want 403", status, body)
			}
			e.allow(t, e.bobID)
			before, _ := e.g.deps.Users.Get(e.bobID)
			if !before.SignInAllowanceLive(e.clock.now()) {
				t.Fatalf("the allowance is not live: %v", before.SignInAllowedUntil)
			}

			// The write that spends the allowance fails.
			backend.armed.Store(true)
			passwordStep(b)
			resp, status, body := factorStep(b)
			backend.armed.Store(false)

			if backend.refused.Load() == 0 {
				t.Fatal("no write that spends the allowance was attempted, so the failing write was never reached")
			}
			if status != http.StatusInternalServerError {
				t.Fatalf("the second step whose allowance could not be spent = %d %s, want 500", status, body)
			}
			p := decodeProblem(t, []byte(body))
			if p.Type != problemTypeBase+classServerError.anchor {
				t.Errorf("problem type = %q, want class server-error", p.Type)
			}
			if p.Detail != "unable to complete sign-in" {
				t.Errorf("detail = %q, want %q", p.Detail, "unable to complete sign-in")
			}
			if c := cookieNamed(resp, e.g.sessionCookieName()); c != nil && c.Value != "" && c.MaxAge >= 0 {
				t.Errorf("a session cookie was set on the failed sign-in: %+v", c)
			}
			if sessionAuthenticated(t, b.at(addrLondon), e.ts) {
				t.Error("the failed sign-in left the browser signed in")
			}
			during, _ := e.g.deps.Users.Get(e.bobID)
			if !during.SignInAllowedUntil.Equal(before.SignInAllowedUntil) || !during.SignInAllowanceLive(e.clock.now()) {
				t.Errorf("allowance after the failure ends %v, want still %v and live", during.SignInAllowedUntil, before.SignInAllowedUntil)
			}

			// Once the backend recovers, signing in again from the start
			// completes and spends the allowance.
			passwordStep(b)
			resp, status, body = factorStep(b)
			if status != http.StatusOK {
				t.Fatalf("the sign-in retried from the start = %d %s, want 200", status, body)
			}
			if c := cookieNamed(resp, e.g.sessionCookieName()); c == nil || c.Value == "" || c.MaxAge < 0 {
				t.Errorf("no session cookie on the retried sign-in: %+v", c)
			}
			if !sessionAuthenticated(t, b.at(addrLondon), e.ts) {
				t.Error("the retried sign-in did not leave the browser signed in")
			}
			after, _ := e.g.deps.Users.Get(e.bobID)
			if !after.SignInAllowedUntil.IsZero() {
				t.Errorf("the allowance is still set after the sign-in it was for: %v", after.SignInAllowedUntil)
			}
		})
	}
}

// -- POST /api/auth/login/passkey --------------------------------------------

func TestV041AllowedSignInWhoseAllowanceCannotBeSpentFailsClosedAtLoginPasskey(t *testing.T) {
	backend := &v041SpendBackend{Memory: persist.NewMemory()}
	e := newUnusualEnvWith(t, backend, func(c *Config) {
		c.UnusualSignIns = UnusualSignInPolicy{NewBrowser: UnusualSignInBlock}
	})
	e.g.deps.Passkeys = mustRelyingParty(t, passkeyTestPublicURL)
	e.g.cfg.PasskeySignIn = true

	// bob's remembered browser signs in by password, then registers a
	// discoverable passkey (register/begin takes bob's password, so this
	// does not use registerPasskey, which sends bilbo's).
	first := newTestBrowser(t)
	e.mustSignIn(t, first, addrLondon)
	c1 := first.at(addrLondon)
	fake := newFake(e.g)
	fake.UserHandle = []byte(e.bobID)
	resp := postJSON(t, c1, e.ts.URL+"/api/auth/passkeys/register/begin", passkeyRegisterBeginRequest{Password: totpBobPassword})
	var creation protocol.CredentialCreation
	if err := json.NewDecoder(resp.Body).Decode(&creation); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	_ = passkeyRegisterFinishOK(t, c1, e.ts, fake, &creation, "bob's key")
	confirmEnrolmentOK(t, c1, e.ts)
	e.advance(time.Hour)

	passkeySignIn := func(b *browser) (*http.Response, int, string) {
		t.Helper()
		c := b.at(addrLondon)
		begin := postJSON(t, c, e.ts.URL+loginPasskeyBeginPath, struct{}{})
		var options protocol.CredentialAssertion
		if begin.StatusCode != http.StatusOK {
			_, body := readAll(t, begin)
			t.Fatalf("login/passkey/begin = %d %s", begin.StatusCode, body)
		}
		if err := json.NewDecoder(begin.Body).Decode(&options); err != nil {
			t.Fatal(err)
		}
		_ = begin.Body.Close()
		resp := postJSON(t, c, e.ts.URL+loginPasskeyPath, loginPasskeyRequest{Assertion: signInAssertionBody(t, fake, &options)})
		status, body := readAll(t, resp)
		return resp, status, body
	}

	// Without the allowance the policy stops this browser.
	b := newTestBrowser(t)
	if _, status, body := passkeySignIn(b); status != http.StatusForbidden {
		t.Fatalf("a new browser's passkey sign-in under block = %d %s, want 403", status, body)
	}
	e.allow(t, e.bobID)
	before, _ := e.g.deps.Users.Get(e.bobID)
	if !before.SignInAllowanceLive(e.clock.now()) {
		t.Fatalf("the allowance is not live: %v", before.SignInAllowedUntil)
	}

	backend.armed.Store(true)
	resp, status, body := passkeySignIn(b)
	backend.armed.Store(false)

	if backend.refused.Load() == 0 {
		t.Fatal("no write that spends the allowance was attempted, so the failing write was never reached")
	}
	if status != http.StatusInternalServerError {
		t.Fatalf("the passkey sign-in whose allowance could not be spent = %d %s, want 500", status, body)
	}
	p := decodeProblem(t, []byte(body))
	if p.Type != problemTypeBase+classServerError.anchor {
		t.Errorf("problem type = %q, want class server-error", p.Type)
	}
	if p.Detail != "unable to complete sign-in" {
		t.Errorf("detail = %q, want %q", p.Detail, "unable to complete sign-in")
	}
	if c := cookieNamed(resp, e.g.sessionCookieName()); c != nil && c.Value != "" && c.MaxAge >= 0 {
		t.Errorf("a session cookie was set on the failed sign-in: %+v", c)
	}
	if sessionAuthenticated(t, b.at(addrLondon), e.ts) {
		t.Error("the failed sign-in left the browser signed in")
	}
	during, _ := e.g.deps.Users.Get(e.bobID)
	if !during.SignInAllowedUntil.Equal(before.SignInAllowedUntil) || !during.SignInAllowanceLive(e.clock.now()) {
		t.Errorf("allowance after the failure ends %v, want still %v and live", during.SignInAllowedUntil, before.SignInAllowedUntil)
	}

	// Recovered: the same sign-in completes and spends the allowance.
	resp, status, body = passkeySignIn(b)
	if status != http.StatusOK {
		t.Fatalf("the retried passkey sign-in = %d %s, want 200", status, body)
	}
	if c := cookieNamed(resp, e.g.sessionCookieName()); c == nil || c.Value == "" || c.MaxAge < 0 {
		t.Errorf("no session cookie on the retried sign-in: %+v", c)
	}
	if after, _ := e.g.deps.Users.Get(e.bobID); !after.SignInAllowedUntil.IsZero() {
		t.Errorf("the allowance is still set after the sign-in it was for: %v", after.SignInAllowedUntil)
	}
}

// -- GET /api/auth/oidc/callback ---------------------------------------------

func TestV041AllowedSignInWhoseAllowanceCannotBeSpentFailsClosedAtSSOCallback(t *testing.T) {
	backend := &v041SpendBackend{Memory: persist.NewMemory()}
	g, ts, fp := newEmptyOIDCTestGate(t, oidc.Policy{})
	g.deps.Users = openTrackedStore(t, backend)
	registerAdmin(t, ts, "setup-admin", "setup-admin-password")
	g.cfg.Audit = &auditRecorder{}
	g.cfg.ClientIP = func(*http.Request) string { return addrLondon }
	g.cfg.UnusualSignIns = UnusualSignInPolicy{NewBrowser: UnusualSignInBlock}

	callback := func() *http.Response {
		t.Helper()
		fs, err := oidc.NewFlowState(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))
		client := noRedirectClient()
		client.Jar = mustCookieJar(t) // a new browser every time
		resp, err := client.Do(oidcCallbackRequest(t, g, ts, fs, "state="+fs.State+"&code=test-code"))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}
	if resp := callback(); resp.Header.Get("Location") != "/" {
		t.Fatalf("the first SSO sign-in went to %q", resp.Header.Get("Location"))
	}
	if resp := callback(); resp.Header.Get("Location") != testLoginPath+"?ssoError=refused" {
		t.Fatalf("a new browser's SSO sign-in went to %q, want refused", resp.Header.Get("Location"))
	}
	var ssoID string
	for _, u := range g.deps.Users.List() {
		if u.OIDCSubject != "" {
			ssoID = u.ID
		}
	}
	if ssoID == "" {
		t.Fatal("no SSO account was provisioned")
	}
	if _, err := g.deps.Users.AllowNextSignIn(ssoID, time.Now()); err != nil {
		t.Fatal(err)
	}
	before, _ := g.deps.Users.Get(ssoID)
	if !before.SignInAllowanceLive(time.Now()) {
		t.Fatalf("the allowance is not live: %v", before.SignInAllowedUntil)
	}

	backend.armed.Store(true)
	resp := callback()
	backend.armed.Store(false)

	if backend.refused.Load() == 0 {
		t.Fatal("no write that spends the allowance was attempted, so the failing write was never reached")
	}
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != testLoginPath+"?ssoError=login_failed" {
		t.Errorf("the SSO sign-in whose allowance could not be spent = %d to %q, want 302 to %s?ssoError=login_failed",
			resp.StatusCode, resp.Header.Get("Location"), testLoginPath)
	}
	if c := cookieNamed(resp, testCookieName); c != nil && c.Value != "" && c.MaxAge >= 0 {
		t.Errorf("a session cookie was set on the failed SSO sign-in: %+v", c)
	}
	during, _ := g.deps.Users.Get(ssoID)
	if !during.SignInAllowedUntil.Equal(before.SignInAllowedUntil) || !during.SignInAllowanceLive(time.Now()) {
		t.Errorf("allowance after the failure ends %v, want still %v and live", during.SignInAllowedUntil, before.SignInAllowedUntil)
	}

	// Recovered: the same sign-in completes and spends the allowance.
	resp = callback()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Errorf("the retried SSO sign-in = %d to %q, want 302 to /", resp.StatusCode, resp.Header.Get("Location"))
	}
	if c := cookieNamed(resp, testCookieName); c == nil || c.Value == "" || c.MaxAge < 0 {
		t.Errorf("no session cookie on the retried SSO sign-in: %+v", c)
	}
	if after, _ := g.deps.Users.Get(ssoID); !after.SignInAllowedUntil.IsZero() {
		t.Errorf("the allowance is still set after the sign-in it was for: %v", after.SignInAllowedUntil)
	}
}
