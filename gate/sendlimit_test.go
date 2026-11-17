package gate

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/oidc"
)

// The send limit (#84, #83): confirmation codes and escape codes are
// counted per account as they go out (gauntlet.LoginLimiter.ReserveDelivery)
// and never handed back: five per window at the fixtures' limiter (5 per
// 5 minutes), a resend cooldown of 30 seconds doubling with each send in
// the hour, and five in any hour. A held sign-in past any of them is
// answered 429 rate-limited with no code, no ticket and no cookie.

// sendGaps are the waits before each of an hour's five sends that just
// clear the resend cooldown: none, then 30 s, 1, 2 and 4 minutes (#83).
var sendGaps = []time.Duration{0, 30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute}

// pastLastCooldown is a wait after the fifth send that clears its
// cooldown (8 minutes) and the fixtures' window, so only the hourly cap
// refuses a sixth.
const pastLastCooldown = 8 * time.Minute

// newBrowserConfirmEnv is newNotifiedEnv confirming a new browser, with
// bob signed in once from London in the returned known browser.
func newBrowserConfirmEnv(t *testing.T) (*unusualEnv, *noticeRecorder, *browser) {
	t.Helper()
	e, rec := newNotifiedEnv(t, UnusualSignInPolicy{NewBrowser: UnusualSignInConfirm})
	known := newTestBrowser(t)
	e.mustSignIn(t, known, addrLondon)
	e.advance(time.Hour)
	return e, rec, known
}

// heldFrom signs bob in from a new browser at address and returns the
// response, its status and body.
func (e *unusualEnv) heldFrom(t *testing.T, address string) (*http.Response, int, string) {
	t.Helper()
	resp := postJSON(t, newTestBrowser(t).at(address), e.ts.URL+"/api/auth/login",
		credentialsRequest{Username: totpBobUsername, Password: totpBobPassword})
	status, body := readAll(t, resp)
	return resp, status, body
}

// checkSendLimited checks a held sign-in past the send limit: 429
// rate-limited, no ticket of either kind, no session, a rate_limited row,
// and nothing that counts toward a lockout or the address ban.
func checkSendLimited(t *testing.T, e *unusualEnv, resp *http.Response, status int, body string) {
	t.Helper()
	if status != http.StatusTooManyRequests || problemType(t, body) != "rate-limited" ||
		decodeProblem(t, []byte(body)).Detail != "too many attempts, try again later" {
		t.Fatalf("past the send limit = %d %s, want 429 rate-limited", status, body)
	}
	for _, name := range []string{confirmLoginCookieName, escapeLoginCookieName, e.g.sessionCookieName(), knownBrowserCookieName} {
		if c := cookieNamed(resp, name); c != nil && c.MaxAge >= 0 {
			t.Errorf("cookie %s was set past the send limit: %+v", name, c)
		}
	}
	if row := e.newestRow(t); row.Outcome != gauntlet.SignInRateLimited || row.UserID != e.bobID || !row.LockedUntil.IsZero() || row.Disabled {
		t.Errorf("row = %+v, want rate_limited for bob, no lockout", row)
	}
	for _, action := range []string{"user.login_failed", "user.login_refused", "account.locked", "address.banned"} {
		if entry, ok := e.lastAudit(action); ok {
			t.Errorf("past the send limit wrote %s: %+v", action, entry)
		}
	}
	if !strings.Contains(e.logText(), "outcome=rate_limited") {
		t.Error("no rated Warn line for the refusal")
	}
}

// Six holds from one address, each past the last one's cooldown: five
// codes, then 429 and no sixth call to Config.DeliverConfirmCode. No
// notice, no escape (bob is a user), and a browser the account knows
// still signs in.
func TestSendLimitConfirmFromOneAddress(t *testing.T) {
	e, rec, known := newBrowserConfirmEnv(t)
	start := e.clock.now()
	for i, gap := range sendGaps {
		e.advance(gap)
		resp, status, body := e.heldFrom(t, addrParis)
		if status != http.StatusOK || strings.TrimSpace(body) != `{"confirm":true}` || cookieNamed(resp, confirmLoginCookieName) == nil {
			t.Fatalf("hold %d = %d %s, want the confirm challenge and its ticket", i+1, status, body)
		}
	}
	e.advance(pastLastCooldown)
	resp, status, body := e.heldFrom(t, addrParis)
	checkSendLimited(t, e, resp, status, body)
	if n := len(rec.allCodes()); n != 5 {
		t.Errorf("codes delivered = %d, want 5", n)
	}
	if got := e.notices(rec); len(got) != 0 {
		t.Errorf("notices = %+v, want none", got)
	}
	// The budget is the unfamiliar side only: a browser the account
	// knows is never held, so never sends.
	e.mustSignIn(t, known, addrLondon)
	e.expectSignals(t, 0)
	// Once the first send leaves the hour there is room again.
	e.clock.set(start.Add(time.Hour + time.Second))
	if _, status, body := e.heldFrom(t, addrParis); status != http.StatusOK {
		t.Errorf("an hour after the first = %d %s, want the confirm challenge", status, body)
	}
}

// The resend cooldown (#83): a second hold 29 seconds after the first is
// 429 with no code, from any address, and does not push the wait out; at
// 30 seconds it gets its code, and the next waits a minute.
func TestSendLimitConfirmCooldown(t *testing.T) {
	e, rec, _ := newBrowserConfirmEnv(t)
	if _, status, body := e.heldFrom(t, addrParis); status != http.StatusOK {
		t.Fatalf("the first hold = %d %s", status, body)
	}
	e.advance(29 * time.Second)
	resp, status, body := e.heldFrom(t, "198.51.100.7")
	checkSendLimited(t, e, resp, status, body)
	e.advance(time.Second)
	if _, status, body := e.heldFrom(t, addrParis); status != http.StatusOK {
		t.Fatalf("30 seconds after the first = %d %s, want the confirm challenge", status, body)
	}
	e.advance(59 * time.Second)
	resp, status, body = e.heldFrom(t, addrParis)
	checkSendLimited(t, e, resp, status, body)
	if n := len(rec.allCodes()); n != 2 {
		t.Errorf("codes delivered = %d, want 2", n)
	}
}

// The budget is the account's, not the address's: six addresses share it.
func TestSendLimitConfirmAcrossAddresses(t *testing.T) {
	e, rec, _ := newBrowserConfirmEnv(t)
	for i, gap := range sendGaps {
		e.advance(gap)
		if _, status, body := e.heldFrom(t, fmt.Sprintf("198.51.100.%d", i+1)); status != http.StatusOK {
			t.Fatalf("hold %d = %d %s", i+1, status, body)
		}
	}
	e.advance(pastLastCooldown)
	resp, status, body := e.heldFrom(t, "198.51.100.6")
	checkSendLimited(t, e, resp, status, body)
	if n := len(rec.allCodes()); n != 5 {
		t.Errorf("codes delivered = %d, want 5", n)
	}
}

// A delivery that reported an error is spent all the same: the mailer
// may have sent it, and a mail outage must not become a refund loop.
func TestSendLimitFailedDeliveryIsSpent(t *testing.T) {
	e, rec, _ := newBrowserConfirmEnv(t)
	rec.fail = func(context.Context) error { return errors.New("mailer down") }
	for _, gap := range sendGaps {
		e.advance(gap)
		resp := postJSON(t, newTestBrowser(t).at(addrParis), e.ts.URL+"/api/auth/login",
			credentialsRequest{Username: totpBobUsername, Password: totpBobPassword})
		checkRefused(t, e.g, resp)
	}
	if entry, _ := e.lastAudit("user.login_refused"); !strings.Contains(entry.Detail, "reason=notify-failed") {
		t.Errorf("audit = %q", entry.Detail)
	}
	rec.mu.Lock()
	rec.fail = nil
	rec.mu.Unlock()
	e.audit.mu.Lock()
	e.audit.entries = nil
	e.audit.mu.Unlock()
	e.advance(pastLastCooldown)
	resp, status, body := e.heldFrom(t, addrParis)
	checkSendLimited(t, e, resp, status, body)
	if n := len(rec.allCodes()); n != 5 {
		t.Errorf("delivery calls = %d, want the 5 that failed and no sixth", n)
	}
}

// Four wrong passwords, then a held sign-in: the hold hands its
// attempt back as before, so its own code still completes it and no
// lockout is counted.
func TestSendLimitHeldSignInStillCompletesAfterWrongPasswords(t *testing.T) {
	e, rec, _ := newBrowserConfirmEnv(t)
	b := newTestBrowser(t)
	for i := range 4 {
		status, body := readAll(t, postJSON(t, b.at(addrParis), e.ts.URL+"/api/auth/login",
			credentialsRequest{Username: totpBobUsername, Password: "wrong-password-placeholder"}))
		if status != http.StatusUnauthorized {
			t.Fatalf("wrong password %d = %d %s", i+1, status, body)
		}
	}
	if status, body := e.signIn(t, b, addrParis); status != http.StatusOK || strings.TrimSpace(body) != `{"confirm":true}` {
		t.Fatalf("the held sign-in = %d %s", status, body)
	}
	if _, status, body := e.postConfirm(t, b, addrParis, confirmCode(t, rec)); status != http.StatusOK {
		t.Fatalf("its code = %d %s, want 200", status, body)
	}
	if u, _ := e.g.deps.Users.Get(e.bobID); u.LoginLockoutCount != 0 || !u.LoginLockedUntil.IsZero() {
		t.Errorf("record holds count %d until %v, want neither", u.LoginLockoutCount, u.LoginLockedUntil)
	}
}

// escapeCodesLogged counts the escape codes in the log.
func (e *escapeEnv) escapeCodesLogged() int {
	return len(escapeCodeRE.FindAllString(e.logText(), -1))
}

// A lone admin refused six times in an hour, each past the last one's
// cooldown: five escape codes, then the same refusal with none. A
// refusal inside the cooldown carries none either.
func TestSendLimitEscapeCodesWhenBlocked(t *testing.T) {
	e := loneAdminEnv(t)
	for i, gap := range sendGaps {
		e.advance(gap)
		if _, resp := e.refusedFrom(t, addrParis); cookieNamed(resp, escapeLoginCookieName) == nil {
			t.Fatalf("refusal %d carried no escape ticket", i+1)
		}
		if i == 0 {
			e.advance(time.Second)
			if _, resp := e.refusedFrom(t, addrParis); cookieNamed(resp, escapeLoginCookieName) != nil {
				t.Fatal("a refusal inside the cooldown carried an escape ticket")
			}
		}
	}
	e.advance(pastLastCooldown)
	_, resp := e.refusedFrom(t, addrParis)
	if c := cookieNamed(resp, escapeLoginCookieName); c != nil {
		t.Errorf("the sixth refusal set an escape ticket: %+v", c)
	}
	if n := e.escapeCodesLogged(); n != 5 {
		t.Errorf("escape codes logged = %d, want 5", n)
	}
	entry, _ := e.lastAudit("user.login_refused")
	if strings.Contains(entry.Detail, "escape=issued") || !strings.Contains(entry.Detail, "reason=policy") {
		t.Errorf("the sixth refusal's audit = %q", entry.Detail)
	}
	if row := e.newestRow(t); row.Outcome != gauntlet.SignInRefused {
		t.Errorf("row = %+v, want the refusal", row)
	}
}

// A lone admin held under confirm: each hold sends a code and an escape
// code, each on its own channel, so five holds get five of each. The
// sixth in the hour is past the confirm budget: 429, and no escape code
// either.
func TestSendLimitConfirmAndEscapeAreSeparateChannels(t *testing.T) {
	rec := &noticeRecorder{}
	e := newEscapeEnv(t, gauntlet.RoleAdmin, true, func(c *Config) {
		c.UnusualSignIns = UnusualSignInPolicy{NewBrowser: UnusualSignInConfirm}
		c.DeliverConfirmCode = rec.deliver
	})
	for i, gap := range sendGaps {
		e.advance(gap)
		resp, status, body := e.heldFrom(t, addrParis)
		if status != http.StatusOK || cookieNamed(resp, confirmLoginCookieName) == nil || cookieNamed(resp, escapeLoginCookieName) == nil {
			t.Fatalf("hold %d = %d %s, want a confirm and an escape ticket", i+1, status, body)
		}
	}
	if codes, escapes := len(rec.allCodes()), e.escapeCodesLogged(); codes != 5 || escapes != 5 {
		t.Fatalf("after five holds: %d codes, %d escape codes; want 5 and 5", codes, escapes)
	}
	e.advance(pastLastCooldown)
	resp, status, body := e.heldFrom(t, addrParis)
	checkSendLimited(t, e.unusualEnv, resp, status, body)
	if codes, escapes := len(rec.allCodes()), e.escapeCodesLogged(); codes != 5 || escapes != 5 {
		t.Errorf("after the sixth: %d codes, %d escape codes; want still 5 and 5", codes, escapes)
	}
}

// The SSO callback's sixth hold in an hour redirects refused, with no
// code and no ticket.
func TestSendLimitSSO(t *testing.T) {
	g, ts, fp := newOIDCTestGate(t, oidc.Policy{})
	// The gate's clock runs ahead of the provider's by offset, so the
	// holds can be spaced past each cooldown while the tokens stay fresh.
	var offset time.Duration
	g.cfg.Now = func() time.Time { return time.Now().Add(offset) }
	rec := &noticeRecorder{}
	g.cfg.DeliverConfirmCode = rec.deliver
	g.cfg.UnusualSignIns = UnusualSignInPolicy{NewBrowser: UnusualSignInConfirm}
	callback := func() *http.Response {
		t.Helper()
		fs, err := oidc.NewFlowState(g.now())
		if err != nil {
			t.Fatal(err)
		}
		fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))
		client := noRedirectClient()
		client.Jar = mustCookieJar(t)
		resp, err := client.Do(oidcCallbackRequest(t, g, ts, fs, "state="+fs.State+"&code=test-code"))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}
	callback() // the first sign-in raises nothing
	for i, gap := range sendGaps {
		offset += gap
		if loc := callback().Header.Get("Location"); loc != testLoginPath+"?confirm=1" {
			t.Fatalf("hold %d redirect = %q", i+1, loc)
		}
	}
	offset += pastLastCooldown
	resp := callback()
	if loc := resp.Header.Get("Location"); loc != testLoginPath+"?ssoError=refused" {
		t.Errorf("the sixth hold's redirect = %q, want ssoError=refused", loc)
	}
	if c := cookieNamed(resp, confirmLoginCookieName); c != nil {
		t.Errorf("the sixth hold set a confirm ticket: %+v", c)
	}
	if n := len(rec.allCodes()); n != 5 {
		t.Errorf("codes delivered = %d, want 5", n)
	}
}
