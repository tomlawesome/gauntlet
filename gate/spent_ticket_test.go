package gate

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/internal/spent"
)

// A used ticket stays refused until the moment it expires (#90 item 1):
// the replay memory must not forget it early. Each test uses a ticket
// once, then presents the same cookie one nanosecond before
// IssuedAt+lifetime, where the ticket itself is still young enough to be
// read, so only the memory of its use can refuse it.

// freshSpentSets gives the test its own replay memories, restored when it
// ends. The package-level sets are shared by every gate test, and a set
// forgets keys in the order they were claimed: a key another test left
// with a later forget time keeps a wrongly early one held, so these
// guards passed in the full run against code that forgot too early.
// Gate tests do not run in parallel, so swapping the variables is safe.
func freshSpentSets(t *testing.T) {
	t.Helper()
	pending, confirm, escape := spentPendingLogins, spentConfirmLogins, spentEscapeLogins
	spentPendingLogins = spent.New(pendingLoginCookieMaxAge)
	spentConfirmLogins = spent.New(ConfirmCodeLifetime)
	spentEscapeLogins = spent.New(EscapeCodeLifetime)
	t.Cleanup(func() {
		spentPendingLogins, spentConfirmLogins, spentEscapeLogins = pending, confirm, escape
	})
}

func TestSpentPendingLoginRefusedUntilItsExpiry(t *testing.T) {
	freshSpentSets(t)
	g, ts, _ := totpFixture(t)
	var mu sync.Mutex
	clock := time.Now().Round(0)
	g.cfg.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	setClock := func(c time.Time) { mu.Lock(); clock = c; mu.Unlock() }
	issuedAt := clock

	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	_, codes, _ := totpEnrolAndConfirm(t, bob, ts)
	client := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	kept := pendingCookieOf(t, client, ts)
	first := submitLoginFactor(t, client, ts, codes[0])
	_ = first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("the sign-in got %d, want 200", first.StatusCode)
	}

	setClock(issuedAt.Add(pendingLoginCookieMaxAge - time.Nanosecond))
	resp, raw := postRaw(t, ts.URL+"/api/auth/login/factor", loginFactorRequest{Code: codes[1]}, kept)
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(raw, "sign in again") {
		t.Errorf("a used pending login replayed 1ns before its expiry got %d %q, want 401 sign in again", resp.StatusCode, raw)
	}
}

func TestSpentConfirmTicketRefusedUntilItsExpiry(t *testing.T) {
	freshSpentSets(t)
	e, rec, b := confirmEnv(t)
	if status, _ := e.signIn(t, b, addrParis); status != http.StatusOK {
		t.Fatal("no challenge")
	}
	issuedAt := e.clock.now()
	code := confirmCode(t, rec)
	u, _ := url.Parse(e.ts.URL + loginConfirmPath)
	ticket := b.jar.Cookies(u)
	if _, status, body := e.postConfirm(t, b, addrParis, code); status != http.StatusOK {
		t.Fatalf("confirm = %d %s", status, body)
	}

	e.clock.set(issuedAt.Add(ConfirmCodeLifetime - time.Nanosecond))
	b.jar.SetCookies(u, ticket)
	if _, status, body := e.postConfirm(t, b, addrParis, code); status != http.StatusUnauthorized || problemType(t, body) != "step-expired" {
		t.Errorf("a used confirm ticket replayed 1ns before its expiry = %d %s, want 401 step-expired", status, body)
	}
}

func TestSpentProveTicketRefusedUntilItsExpiry(t *testing.T) {
	freshSpentSets(t)
	e := newProveEnv(t)
	c := e.held(t)
	issuedAt := e.clock.now()
	body := signInAssertionBody(t, e.fake, e.mustProveBegin(t, c))
	ticket := e.ticket(t, c)
	if resp, raw := e.proveFinish(t, c, body); resp.StatusCode != http.StatusOK {
		t.Fatalf("finish = %d %s", resp.StatusCode, raw)
	}

	e.clock.set(issuedAt.Add(ConfirmCodeLifetime - time.Nanosecond))
	c.Jar.SetCookies(mustParseURL(t, e.ts.URL), []*http.Cookie{ticket})
	if resp := e.proveBegin(t, c); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("begin on a used ticket 1ns before its expiry = %d, want 401", resp.StatusCode)
	} else {
		_ = resp.Body.Close()
	}
	resp, raw := e.proveFinish(t, c, body)
	wantStatusClass(t, resp, raw, http.StatusUnauthorized, classStepExpired)
}

func TestSpentEscapeTicketRefusedUntilItsExpiry(t *testing.T) {
	freshSpentSets(t)
	e := loneAdminEnv(t)
	b, resp := e.refusedFrom(t, addrLondon2)
	issuedAt := e.clock.now()
	code := e.loggedCode()
	if _, status, body := e.postEscape(t, b, addrLondon2, code); status != http.StatusOK {
		t.Fatalf("escape = %d %s", status, body)
	}

	e.clock.set(issuedAt.Add(EscapeCodeLifetime - time.Nanosecond))
	sessions := e.sessions() // counted at the replay's clock: idle sessions may have lapsed
	replay := newTestBrowser(t)
	setCookie(t, replay, e.ts.URL, escapeLoginCookieName, cookieNamed(resp, escapeLoginCookieName).Value)
	_, status, body := e.postEscape(t, replay, addrLondon2, code)
	if status != http.StatusUnauthorized || problemType(t, body) != "step-expired" {
		t.Errorf("a used escape ticket replayed 1ns before its expiry = %d %s, want 401 step-expired", status, body)
	}
	if e.sessions() != sessions {
		t.Error("the replay issued a session")
	}
}
