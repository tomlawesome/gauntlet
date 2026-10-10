// v0.4.1, A1a-R1: an allowed sign-in whose allowance cannot be spent
// fails closed. The allowance is spent by the same store write that
// remembers the signing-in browser; when that write fails, the sign-in
// answers 500 server-error with no session, the allowance stays live,
// and the same sign-in retried once the store recovers completes and
// spends it.
package gate

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// v041FlakyBackend is a memory backend whose Save fails while failing
// is set.
type v041FlakyBackend struct {
	*persist.Memory
	failing atomic.Bool
	refused atomic.Int32
}

func (b *v041FlakyBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	if b.failing.Load() {
		b.refused.Add(1)
		return 0, errors.New("flaky test backend: save refused")
	}
	return b.Memory.Save(ctx, payload, expect)
}

func TestV041AllowedSignInWhoseAllowanceCannotBeSpentFailsClosed(t *testing.T) {
	backend := &v041FlakyBackend{Memory: persist.NewMemory()}
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
	before, _ := e.g.deps.Users.Get(e.bobID)
	if !before.SignInAllowanceLive(e.clock.now()) {
		t.Fatalf("the allowance is not live: %v", before.SignInAllowedUntil)
	}

	// The write that remembers the browser and spends the allowance fails.
	backend.failing.Store(true)
	resp, status, body := e.signInResponse(t, b, addrLondon)
	backend.failing.Store(false)

	if backend.refused.Load() == 0 {
		t.Fatal("the sign-in saved nothing, so the failing write was never reached")
	}
	// 1: 500 server-error, "unable to complete sign-in".
	if status != http.StatusInternalServerError {
		t.Fatalf("the sign-in whose allowance could not be spent = %d %s, want 500", status, body)
	}
	p := decodeProblem(t, []byte(body))
	if p.Type != problemTypeBase+classServerError.anchor {
		t.Errorf("problem type = %q, want class server-error", p.Type)
	}
	if p.Detail != "unable to complete sign-in" {
		t.Errorf("detail = %q, want %q", p.Detail, "unable to complete sign-in")
	}

	// 2: no session cookie, and not signed in.
	if c := cookieNamed(resp, e.g.sessionCookieName()); c != nil && c.Value != "" && c.MaxAge >= 0 {
		t.Errorf("a session cookie was set on the failed sign-in: %+v", c)
	}
	if sessionAuthenticated(t, b.at(addrLondon), e.ts) {
		t.Error("the failed sign-in left the browser signed in")
	}
	if got := e.g.deps.Sessions.ListForUser(e.bobID, e.clock.now()); len(got) != 1 {
		t.Errorf("bob holds %d sessions, want only the first sign-in's", len(got))
	}

	// 3: the allowance is untouched.
	during, _ := e.g.deps.Users.Get(e.bobID)
	if !during.SignInAllowedUntil.Equal(before.SignInAllowedUntil) || !during.SignInAllowanceLive(e.clock.now()) {
		t.Errorf("allowance after the failure ends %v, want still %v and live", during.SignInAllowedUntil, before.SignInAllowedUntil)
	}

	// 4 and 5: once the backend recovers the same sign-in completes,
	// is not held back by lockout or rate limit, and spends the allowance.
	resp, status, body = e.signInResponse(t, b, addrLondon)
	if status != http.StatusOK {
		t.Fatalf("the retried sign-in = %d %s, want 200", status, body)
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
}

// An ordinary sign-in, with no allowance, on an account the policy does
// not stop, is unchanged when the remembering write fails: it still
// completes. (Control: passes before and after the fix.)
func TestV041OrdinarySignInStillCompletesWhenRememberingFails(t *testing.T) {
	backend := &v041FlakyBackend{Memory: persist.NewMemory()}
	e := newUnusualEnvWith(t, backend, func(c *Config) {
		c.UnusualSignIns = UnusualSignInPolicy{}
	})
	u, _ := e.g.deps.Users.Get(e.bobID)
	if !u.SignInAllowedUntil.IsZero() {
		t.Fatalf("bob has an allowance: %v", u.SignInAllowedUntil)
	}

	b := newTestBrowser(t)
	backend.failing.Store(true)
	resp, status, body := e.signInResponse(t, b, addrLondon)
	backend.failing.Store(false)

	if backend.refused.Load() == 0 {
		t.Fatal("the sign-in saved nothing, so the failing write was never reached")
	}
	if status != http.StatusOK {
		t.Fatalf("an ordinary sign-in whose remembering write fails = %d %s, want 200", status, body)
	}
	if c := cookieNamed(resp, e.g.sessionCookieName()); c == nil || c.Value == "" || c.MaxAge < 0 {
		t.Errorf("no session cookie on the ordinary sign-in: %+v", c)
	}
	if !sessionAuthenticated(t, b.at(addrLondon), e.ts) {
		t.Error("the ordinary sign-in did not leave the browser signed in")
	}
}
