// #103 R1: a one-time allowance is spent at most once. A sign-in that
// was let through by an allowance another process has meanwhile spent
// (between this request's judgement and its spend) is refused with the
// policy's own answer, sign-in-refused, not a 500, and completes
// nothing: no session, no user.login record.
//
// The window is reached the way contractfix99_admingone_test.go reaches
// it: the gate's store sits on a backend that, on the next Save that
// clears the allowance, first lets a second store on the same document
// (another process) spend it. The gate's store has already judged the
// allowance live; its Save then conflicts, it reloads, and the
// allowance is gone.
package gate

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/oidc"
	"github.com/tomlawesome/gauntlet/persist"
)

// allowanceRaceBackend is a memory backend that, once armed, runs
// beforeSave once, just before the first Save that would clear a live
// allowance (the accounts document goes from holding a
// signInAllowedUntil to holding none), and saves everything else
// untouched.
type allowanceRaceBackend struct {
	*persist.Memory
	mu         sync.Mutex
	held       bool // the last document saved through here held an allowance
	beforeSave func()
	fired      bool
}

func (b *allowanceRaceBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	has := bytes.Contains(payload, []byte(`"signInAllowedUntil"`))
	b.mu.Lock()
	var f func()
	if b.beforeSave != nil && b.held && !has {
		f, b.beforeSave = b.beforeSave, nil
		b.fired = true
	}
	b.mu.Unlock()
	if f != nil {
		f()
	}
	rev, err := b.Memory.Save(ctx, payload, expect)
	if err == nil {
		b.mu.Lock()
		b.held = has
		b.mu.Unlock()
	}
	return rev, err
}

func (b *allowanceRaceBackend) arm(f func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.beforeSave, b.fired = f, false
}

func (b *allowanceRaceBackend) didFire() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.fired
}

func (e *unusualEnv) auditCount(action string) int {
	e.audit.mu.Lock()
	defer e.audit.mu.Unlock()
	n := 0
	for _, a := range e.audit.entries {
		if a.Action == action {
			n++
		}
	}
	return n
}

func (e *unusualEnv) auditHasAllowedLogin() bool {
	e.audit.mu.Lock()
	defer e.audit.mu.Unlock()
	for _, a := range e.audit.entries {
		if a.Action == "user.login" && strings.Contains(a.Detail, "allowed=used") {
			return true
		}
	}
	return false
}

// otherProcessSpends are the two ways the other process spends bob's
// allowance.
var otherProcessSpends = []struct {
	name  string
	spend func(t *testing.T, other *gauntlet.Store, id string, now time.Time)
}{
	{"by an ordinary sign-in", func(t *testing.T, other *gauntlet.Store, id string, now time.Time) {
		if _, err := other.RememberSignIn(id, "", "GB", nil, now); err != nil {
			t.Errorf("the other process's RememberSignIn: %v", err)
		}
	}},
	{"by an allowed sign-in", func(t *testing.T, other *gauntlet.Store, id string, now time.Time) {
		if _, err := other.RememberAllowedSignIn(id, "", "GB", nil, now); err != nil {
			t.Errorf("the other process's RememberAllowedSignIn: %v", err)
		}
	}},
}

func TestAllowedSignInSpentByAnotherProcessIsRefusedAtLogin(t *testing.T) {
	for _, sp := range otherProcessSpends {
		t.Run(sp.name, func(t *testing.T) {
			backend := &allowanceRaceBackend{Memory: persist.NewMemory()}
			e := newUnusualEnvWith(t, backend, func(c *Config) {
				c.UnusualSignIns = UnusualSignInPolicy{NewBrowser: UnusualSignInBlock}
			})
			e.mustSignIn(t, newTestBrowser(t), addrLondon)
			e.advance(time.Hour)

			b := newTestBrowser(t)
			if status, body := e.signIn(t, b, addrLondon); status != http.StatusForbidden {
				t.Fatalf("a new browser under block = %d %s, want 403", status, body)
			}
			e.allow(t, e.bobID)
			if u, _ := e.g.deps.Users.Get(e.bobID); !u.SignInAllowanceLive(e.clock.now()) {
				t.Fatalf("the allowance is not live: %v", u.SignInAllowedUntil)
			}
			refusedBefore := e.auditCount("user.login_refused")
			sessionsBefore := len(e.g.deps.Sessions.ListForUser(e.bobID, e.clock.now()))

			other, err := gauntlet.OpenStore(backend.Memory, gauntlet.Options{})
			if err != nil {
				t.Fatal(err)
			}
			now := e.clock.now()
			backend.arm(func() { sp.spend(t, other, e.bobID, now) })

			resp, status, body := e.signInResponse(t, b, addrLondon)
			if !backend.didFire() {
				t.Fatalf("the request saved nothing that clears the allowance, so the window was not reached (status %d %s)", status, body)
			}
			if status != http.StatusForbidden {
				t.Fatalf("the sign-in whose allowance was spent under it = %d %s, want 403", status, body)
			}
			p := decodeProblem(t, []byte(body))
			if p.Type != problemTypeBase+classSignInRefused.anchor {
				t.Errorf("problem type = %q, want class sign-in-refused", p.Type)
			}
			if p.Detail != wantRefusedDetail {
				t.Errorf("detail = %q, want the policy's own: %q", p.Detail, wantRefusedDetail)
			}
			if c := cookieNamed(resp, e.g.sessionCookieName()); c != nil && c.Value != "" && c.MaxAge >= 0 {
				t.Errorf("a session cookie was set on the refused sign-in: %+v", c)
			}
			if sessionAuthenticated(t, b.at(addrLondon), e.ts) {
				t.Error("the refused sign-in left the browser signed in")
			}
			if got := len(e.g.deps.Sessions.ListForUser(e.bobID, e.clock.now())); got != sessionsBefore {
				t.Errorf("bob holds %d sessions, want %d", got, sessionsBefore)
			}
			if u, _ := e.g.deps.Users.Get(e.bobID); !u.SignInAllowedUntil.IsZero() {
				t.Errorf("the allowance ends %v, want spent by the other process", u.SignInAllowedUntil)
			}
			if got := e.auditCount("user.login_refused"); got != refusedBefore+1 {
				t.Errorf("%d user.login_refused records, want %d (one more for this attempt)", got, refusedBefore+1)
			}
			if e.auditHasAllowedLogin() {
				t.Error("a user.login record says allowed=used for a sign-in that was refused")
			}
		})
	}
}

func TestAllowedSignInSpentByAnotherProcessIsRefusedAtSSOCallback(t *testing.T) {
	for _, sp := range otherProcessSpends {
		t.Run(sp.name, func(t *testing.T) {
			backend := &allowanceRaceBackend{Memory: persist.NewMemory()}
			g, ts, fp := newEmptyOIDCTestGate(t, oidc.Policy{})
			g.deps.Users = openTrackedStore(t, backend)
			registerAdmin(t, ts, "setup-admin", "setup-admin-password")
			rec := &auditRecorder{}
			g.cfg.Audit = rec
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
			if u, _ := g.deps.Users.Get(ssoID); !u.SignInAllowanceLive(time.Now()) {
				t.Fatalf("the allowance is not live: %v", u.SignInAllowedUntil)
			}

			other, err := gauntlet.OpenStore(backend.Memory, gauntlet.Options{})
			if err != nil {
				t.Fatal(err)
			}
			backend.arm(func() { sp.spend(t, other, ssoID, time.Now()) })
			resp := callback()
			if !backend.didFire() {
				t.Fatalf("the callback saved nothing that clears the allowance, so the window was not reached (to %q)", resp.Header.Get("Location"))
			}

			if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != testLoginPath+"?ssoError=refused" {
				t.Errorf("the SSO sign-in whose allowance was spent under it = %d to %q, want 302 to %s?ssoError=refused",
					resp.StatusCode, resp.Header.Get("Location"), testLoginPath)
			}
			if c := cookieNamed(resp, testCookieName); c != nil && c.Value != "" && c.MaxAge >= 0 {
				t.Errorf("a session cookie was set on the refused SSO sign-in: %+v", c)
			}
			if u, _ := g.deps.Users.Get(ssoID); !u.SignInAllowedUntil.IsZero() {
				t.Errorf("the allowance ends %v, want spent by the other process", u.SignInAllowedUntil)
			}
		})
	}
}

// Control, passes before and after: with nobody else spending it, the
// allowed sign-in completes and spends the allowance.
func TestAllowedSignInStillCompletesWithoutInterference(t *testing.T) {
	backend := &allowanceRaceBackend{Memory: persist.NewMemory()}
	e := newUnusualEnvWith(t, backend, func(c *Config) {
		c.UnusualSignIns = UnusualSignInPolicy{NewBrowser: UnusualSignInBlock}
	})
	e.mustSignIn(t, newTestBrowser(t), addrLondon)
	e.advance(time.Hour)

	b := newTestBrowser(t)
	if status, body := e.signIn(t, b, addrLondon); status != http.StatusForbidden {
		t.Fatalf("a new browser under block = %d %s, want 403", status, body)
	}
	e.allow(t, e.bobID)

	resp, status, body := e.signInResponse(t, b, addrLondon)
	if status != http.StatusOK {
		t.Fatalf("the allowed sign-in = %d %s, want 200", status, body)
	}
	if c := cookieNamed(resp, e.g.sessionCookieName()); c == nil || c.Value == "" || c.MaxAge < 0 {
		t.Errorf("no session cookie on the allowed sign-in: %+v", c)
	}
	if !sessionAuthenticated(t, b.at(addrLondon), e.ts) {
		t.Error("the allowed sign-in did not leave the browser signed in")
	}
	if u, _ := e.g.deps.Users.Get(e.bobID); !u.SignInAllowedUntil.IsZero() {
		t.Errorf("the allowance is still set after the sign-in it was for: %v", u.SignInAllowedUntil)
	}
	if !e.auditHasAllowedLogin() {
		t.Error("no user.login record says allowed=used")
	}
}
