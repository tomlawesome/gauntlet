package gate

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/persist"
)

// The escape code (#66, ADR-0011): a lone admin refused under block
// gets a one-time code in the server's log, redeemed on the refused
// sign-in. Bob is the account under test; he is made the lone admin (or
// a user or viewer) by the fixture.

// escapeCodeRE finds the code in the log line.
var escapeCodeRE = regexp.MustCompile(`escape code ([A-Z0-9]{4}(?:-[A-Z0-9]{4}){3})`)

// escapeEnv is a notified fixture under a block-new-browser policy,
// with bob, signed in once from London in known (so a second browser is
// the unusual one).
type escapeEnv struct {
	*unusualEnv
	rec     *noticeRecorder
	known   *browser
	adminID string
}

// newEscapeEnv makes bob a role and, when dropAdmin, deletes the
// fixture's own admin, leaving bob the lone admin if his role is admin.
func newEscapeEnv(t *testing.T, role gauntlet.Role, dropAdmin bool, configure func(*Config)) *escapeEnv {
	t.Helper()
	rec := &noticeRecorder{}
	e := &escapeEnv{rec: rec}
	e.unusualEnv = newUnusualEnvWith(t, persist.NewMemory(), func(c *Config) {
		c.UnusualSignIns = UnusualSignInPolicy{NewBrowser: UnusualSignInBlock}
		c.Notices = rec
		if configure != nil {
			configure(c)
		}
	})
	users := e.g.deps.Users
	admin, ok := users.ByUsername("admin")
	if !ok {
		t.Fatal("no fixture admin")
	}
	e.adminID = admin.ID
	if role != gauntlet.RoleUser {
		if _, _, err := users.SetRole(e.bobID, role, e.clock.now()); err != nil {
			t.Fatal(err)
		}
	}
	if dropAdmin {
		if _, err := users.DeleteUser(admin.ID); err != nil {
			t.Fatal(err)
		}
	}
	e.known = newTestBrowser(t)
	e.mustSignIn(t, e.known, addrLondon)
	e.advance(time.Hour)
	return e
}

func loneAdminEnv(t *testing.T) *escapeEnv {
	t.Helper()
	return newEscapeEnv(t, gauntlet.RoleAdmin, true, nil)
}

// refusedFrom signs bob in from a new browser at address, expecting the
// 403, and returns the browser (holding any ticket) and the response.
func (e *escapeEnv) refusedFrom(t *testing.T, address string) (*browser, *http.Response) {
	t.Helper()
	b := newTestBrowser(t)
	resp := postJSON(t, b.at(address), e.ts.URL+"/api/auth/login", credentialsRequest{Username: totpBobUsername, Password: totpBobPassword})
	checkRefused(t, e.g, resp)
	return b, resp
}

// loggedCode is the escape code in the log, "" when none.
func (e *escapeEnv) loggedCode() string {
	m := escapeCodeRE.FindStringSubmatch(e.logText())
	if m == nil {
		return ""
	}
	return m[1]
}

func (e *escapeEnv) postEscape(t *testing.T, b *browser, address, code string) (*http.Response, int, string) {
	t.Helper()
	resp := postJSON(t, b.at(address), e.ts.URL+loginEscapePath, loginEscapeRequest{Code: code})
	status, body := readAll(t, resp)
	return resp, status, body
}

func (e *escapeEnv) sessions() int {
	return len(e.g.deps.Sessions.ListForUser(e.bobID, e.clock.now()))
}

// A lone admin refused under block gets the ticket and the log line,
// and the refusal is unchanged.
func TestEscapeLoneAdminGetsACodeInTheLog(t *testing.T) {
	e := loneAdminEnv(t)
	sessionsBefore := e.sessions()
	_, resp := e.refusedFrom(t, addrLondon2)

	c := cookieNamed(resp, escapeLoginCookieName)
	if c == nil || c.MaxAge != 900 || c.Path != "/api/auth/login" || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("escape cookie = %+v", c)
	}
	code := e.loggedCode()
	if code == "" {
		t.Fatalf("no escape code in the log: %s", e.logText())
	}
	for _, want := range []string{"level=WARN", `bob`, addrLondon2, "valid 15 minutes", "unusual-sign-in policy"} {
		if !strings.Contains(e.logText(), want) {
			t.Errorf("the log line lacks %q: %s", want, e.logText())
		}
	}
	if e.sessions() != sessionsBefore {
		t.Error("a session was issued before the code")
	}
	rows, _ := e.history.List(gauntlet.SignInQuery{Limit: 2})
	if len(rows) != 2 || rows[0].Outcome != gauntlet.SignInRefused || rows[1].Outcome != gauntlet.SignInEscapeIssued ||
		rows[1].Client.Unusual != gauntlet.SignalNewBrowser {
		t.Errorf("newest rows = %+v, want refused after escape_issued", rows)
	}
	entry, _ := e.lastAudit("user.login_refused")
	if !strings.Contains(entry.Detail, "escape=issued; ") || strings.Contains(entry.Detail, code) {
		t.Errorf("user.login_refused = %q", entry.Detail)
	}
	// The block notice goes out as today.
	if got := e.notices(e.rec); len(got) != 1 || got[0].UnusualSignIn.Action != UnusualSignInBlock || got[0].UnusualSignIn.Reason != "policy" {
		t.Errorf("notices = %+v", got)
	}
}

// The right code, typed any way the reset code can be, signs the
// browser in, marks it known and records the confirmed row.
func TestEscapeRightCodeSignsIn(t *testing.T) {
	for name, form := range map[string]func(string) string{
		"as logged":          func(c string) string { return c },
		"lower, no dashes":   func(c string) string { return strings.ToLower(strings.ReplaceAll(c, "-", "")) },
		"spaces and padding": func(c string) string { return "  " + strings.ReplaceAll(c, "-", " ") + " " },
	} {
		t.Run(name, func(t *testing.T) {
			e := loneAdminEnv(t)
			b, _ := e.refusedFrom(t, addrLondon2)
			resp, status, body := e.postEscape(t, b, addrLondon2, form(e.loggedCode()))
			if status != http.StatusOK || strings.TrimSpace(body) != `{"role":"admin","username":"`+totpBobUsername+`"}` {
				t.Fatalf("escape = %d %s", status, body)
			}
			if c := cookieNamed(resp, e.g.sessionCookieName()); c == nil || c.MaxAge <= 0 {
				t.Errorf("session cookie = %+v", c)
			}
			if cookieNamed(resp, knownBrowserCookieName) == nil {
				t.Error("the browser was not marked known")
			}
			if c := cookieNamed(resp, escapeLoginCookieName); c == nil || c.MaxAge >= 0 {
				t.Error("the escape cookie was not cleared")
			}
			row := e.newestRow(t)
			if row.Outcome != gauntlet.SignInSuccess || !row.Confirmed || row.Client.Unusual != gauntlet.SignalNewBrowser {
				t.Errorf("row = %+v", row)
			}
			entry, _ := e.lastAudit("user.login")
			if want := `unusual=new-browser; action=block; escape=used; notify=quiet; via escape code; from="` + addrLondon2 + `"`; entry.Detail != want {
				t.Errorf("user.login = %q, want %q", entry.Detail, want)
			}
			if e.newestSession(t).Client.Unusual != gauntlet.SignalNewBrowser {
				t.Error("the session does not carry the signal")
			}
			// Remembered: the same browser signs in quietly now.
			e.advance(time.Minute)
			e.mustSignIn(t, b, addrLondon2)
			e.expectSignals(t, 0)
		})
	}
}

// The completed sign-in sends the flag-style notice naming the block and
// the escape, once the hourly quiet allows.
func TestEscapeSuccessSendsANotice(t *testing.T) {
	old := unusualNoticeInterval
	unusualNoticeInterval = time.Minute
	t.Cleanup(func() { unusualNoticeInterval = old })
	e := loneAdminEnv(t)
	b, _ := e.refusedFrom(t, addrLondon2)
	e.advance(2 * time.Minute)
	if _, status, body := e.postEscape(t, b, addrLondon2, e.loggedCode()); status != http.StatusOK {
		t.Fatalf("escape = %d %s", status, body)
	}
	got := e.notices(e.rec)
	if len(got) != 2 {
		t.Fatalf("notices = %+v, want the block and the escape", got)
	}
	d := got[1].UnusualSignIn
	if got[1].Kind != NoticeUnusualSignIn || d.Action != UnusualSignInBlock || d.Reason != "escape" || d.SessionRef == "" || d.Signals != gauntlet.SignalNewBrowser {
		t.Errorf("escape notice = %+v", got[1])
	}
	if entry, _ := e.lastAudit("user.login"); !strings.Contains(entry.Detail, "escape=used; notify=asked; ") {
		t.Errorf("user.login = %q", entry.Detail)
	}
}

// The factor path issues the code too.
func TestEscapeOnTheFactorPath(t *testing.T) {
	e := loneAdminEnv(t)
	e.advance(-time.Hour) // the enrolment's code is checked against the wall clock
	_, codes, _ := totpEnrolAndConfirm(t, e.known.at(addrLondon), e.ts)
	e.advance(time.Hour)
	b := newTestBrowser(t)
	e.mustSignIn(t, b, addrLondon2) // the password step owes a factor: no code yet
	if e.loggedCode() != "" {
		t.Fatal("a code was written at the password step")
	}
	checkRefused(t, e.g, submitLoginFactor(t, b.at(addrLondon2), e.ts, codes[0]))
	code := e.loggedCode()
	if code == "" {
		t.Fatalf("no escape code after the factor step: %s", e.logText())
	}
	if _, status, body := e.postEscape(t, b, addrLondon2, code); status != http.StatusOK {
		t.Fatalf("escape = %d %s", status, body)
	}
	if row := e.newestRow(t); row.Outcome != gauntlet.SignInSuccess || row.Method != gauntlet.SignInMethodCode || !row.Confirmed {
		t.Errorf("row = %+v", row)
	}
}

// With another admin able to act nothing is issued: block is as before.
func TestEscapeNotWithAnotherAbleAdmin(t *testing.T) {
	e := newEscapeEnv(t, gauntlet.RoleAdmin, false, nil)
	_, resp := e.refusedFrom(t, addrLondon2)
	if cookieNamed(resp, escapeLoginCookieName) != nil || e.loggedCode() != "" || strings.Contains(e.logText(), "escape") {
		t.Errorf("two able admins: cookie %v, log %s", cookieNamed(resp, escapeLoginCookieName), e.logText())
	}
	if entry, _ := e.lastAudit("user.login_refused"); strings.Contains(entry.Detail, "escape") {
		t.Errorf("user.login_refused = %q", entry.Detail)
	}
	if row := e.newestRow(t); row.Outcome != gauntlet.SignInRefused {
		t.Errorf("row = %+v", row)
	}
}

// ... but a disabled other admin cannot act, so the code is issued; once
// the disable lifts by itself (#70), it is not.
func TestEscapeWhenTheOtherAdminIsDisabled(t *testing.T) {
	e := newEscapeEnv(t, gauntlet.RoleAdmin, false, nil)
	disableAccount(t, e.g.deps.Users, e.adminID)
	if _, resp := e.refusedFrom(t, addrLondon2); cookieNamed(resp, escapeLoginCookieName) == nil || e.loggedCode() == "" {
		t.Fatalf("a disabled other admin: no code. log: %s", e.logText())
	}
	e.logs.buf.Reset()
	e.advance(gauntlet.LoginDisableDuration)
	if _, resp := e.refusedFrom(t, addrNewYork); cookieNamed(resp, escapeLoginCookieName) != nil || e.loggedCode() != "" {
		t.Errorf("the disable had lifted, and a code was issued")
	}
}

// A locked-out other admin can still act soon: no code.
func TestEscapeNotWhenTheOtherAdminIsOnlyLockedOut(t *testing.T) {
	e := newEscapeEnv(t, gauntlet.RoleAdmin, false, nil)
	failLoginWindow(t, e.g, e.ts, e.clock, "admin")
	if _, resp := e.refusedFrom(t, addrLondon2); cookieNamed(resp, escapeLoginCookieName) != nil || e.loggedCode() != "" {
		t.Error("a code was issued while the other admin was only locked out")
	}
}

// Users and viewers have an admin to reset them: nothing issued.
func TestEscapeNeverForAUserOrViewer(t *testing.T) {
	for _, role := range []gauntlet.Role{gauntlet.RoleUser, gauntlet.RoleViewer} {
		t.Run(string(role), func(t *testing.T) {
			e := newEscapeEnv(t, role, false, nil)
			_, resp := e.refusedFrom(t, addrLondon2)
			if cookieNamed(resp, escapeLoginCookieName) != nil || strings.Contains(e.logText(), "escape") {
				t.Errorf("a %s was offered an escape code: %s", role, e.logText())
			}
		})
	}
}

// Nothing that could announce the code: no ticket, no line.
func TestEscapeFailsClosedWithNoLogAndNoHandler(t *testing.T) {
	e := newEscapeEnv(t, gauntlet.RoleAdmin, true, func(c *Config) { c.Log = nil })
	_, resp := e.refusedFrom(t, addrLondon2)
	if cookieNamed(resp, escapeLoginCookieName) != nil || strings.Contains(e.logText(), "escape") {
		t.Error("an escape code was issued with nowhere to announce it")
	}
	if row := e.newestRow(t); row.Outcome != gauntlet.SignInRefused {
		t.Errorf("row = %+v", row)
	}
}

// Config.OnEscapeCode takes the code instead of the log; one that
// panics issues nothing.
func TestEscapeHandler(t *testing.T) {
	t.Run("takes the code", func(t *testing.T) {
		var gotName, gotAddr, gotCode string
		e := newEscapeEnv(t, gauntlet.RoleAdmin, true, func(c *Config) {
			c.OnEscapeCode = EscapeCodeFunc(func(u, a, code string) { gotName, gotAddr, gotCode = u, a, code })
		})
		b, resp := e.refusedFrom(t, addrLondon2)
		if cookieNamed(resp, escapeLoginCookieName) == nil {
			t.Fatal("no ticket")
		}
		if gotName != totpBobUsername || gotAddr != addrLondon2 || len(gotCode) != 19 || strings.Contains(e.logText(), gotCode) || strings.Contains(e.logText(), "escape code") {
			t.Errorf("handler got %q %q %q; log: %s", gotName, gotAddr, gotCode, e.logText())
		}
		if _, status, body := e.postEscape(t, b, addrLondon2, gotCode); status != http.StatusOK {
			t.Fatalf("escape = %d %s", status, body)
		}
	})
	t.Run("handler alone, no Log", func(t *testing.T) {
		var gotCode string
		e := newEscapeEnv(t, gauntlet.RoleAdmin, true, func(c *Config) {
			c.Log = nil
			c.OnEscapeCode = EscapeCodeFunc(func(_, _, code string) { gotCode = code })
		})
		b, _ := e.refusedFrom(t, addrLondon2)
		if _, status, _ := e.postEscape(t, b, addrLondon2, gotCode); status != http.StatusOK {
			t.Errorf("escape = %d", status)
		}
	})
	t.Run("panics", func(t *testing.T) {
		e := newEscapeEnv(t, gauntlet.RoleAdmin, true, func(c *Config) {
			c.OnEscapeCode = EscapeCodeFunc(func(_, _, _ string) { panic("boom") })
		})
		_, resp := e.refusedFrom(t, addrLondon2)
		if cookieNamed(resp, escapeLoginCookieName) != nil {
			t.Error("a ticket was set though the handler panicked")
		}
		if !strings.Contains(e.logText(), "OnEscapeCode could not take the escape code") {
			t.Errorf("no error line: %s", e.logText())
		}
	})
}

// Never on the SSO callback: every admin keeps a local password.
func TestEscapeNotOfferedForSSO(t *testing.T) {
	e := loneAdminEnv(t)
	u, _ := e.g.deps.Users.Get(e.bobID)
	if !e.g.escapeOffered(u, gauntlet.SignInMethodPassword, e.clock.now()) {
		t.Fatal("precondition: the lone admin is offered the escape on the password path")
	}
	if e.g.escapeOffered(u, gauntlet.SignInMethodSSO, e.clock.now()) {
		t.Error("the escape was offered on the SSO path")
	}
}

// A wrong code is 401 invalid-credentials, counted as a failed second
// factor; the run of them forces a new password and then the limiter
// refuses.
func TestEscapeWrongCodeIsCounted(t *testing.T) {
	e := loneAdminEnv(t)
	b, _ := e.refusedFrom(t, addrLondon2)
	code := e.loggedCode()
	wrong := "AAAA-AAAA-AAAA-AAAA"
	for i := range 5 {
		_, status, body := e.postEscape(t, b, addrLondon2, wrong)
		if status != http.StatusUnauthorized || problemType(t, body) != "invalid-credentials" || decodeProblem(t, []byte(body)).Detail != "invalid escape code" {
			t.Fatalf("wrong code %d = %d %s", i+1, status, body)
		}
		if i == 0 {
			if row := e.newestRow(t); row.Outcome != gauntlet.SignInEscapeRefused || row.Method != gauntlet.SignInMethodCode {
				t.Errorf("row = %+v", row)
			}
			if entry, _ := e.lastAudit("user.login_failed"); entry.Detail != `outcome=escape_refused method=code from="`+addrLondon2+`"` {
				t.Errorf("audit = %q", entry.Detail)
			}
		}
	}
	if u, _ := e.g.deps.Users.Get(e.bobID); !u.MustChangePassword {
		t.Error("five wrong codes in a row did not force a password change")
	}
	if _, status, _ := e.postEscape(t, b, addrLondon2, code); status != http.StatusTooManyRequests {
		t.Errorf("the sixth attempt = %d, want 429", status)
	}
}

// The ticket and the code are each useless alone.
func TestEscapeTicketChecks(t *testing.T) {
	e := loneAdminEnv(t)
	b, resp := e.refusedFrom(t, addrLondon2)
	code := e.loggedCode()
	// Another browser holds no ticket.
	if _, status, body := e.postEscape(t, newTestBrowser(t), addrLondon2, code); status != http.StatusUnauthorized || problemType(t, body) != "step-expired" {
		t.Errorf("from another browser = %d %s", status, body)
	}
	// A confirm ticket is not an escape ticket, nor the reverse.
	if _, status, body := e.postConfirm(t, b, addrLondon2, "12345678"); status != http.StatusUnauthorized || problemType(t, body) != "step-expired" {
		t.Errorf("login/confirm with an escape cookie = %d %s", status, body)
	}
	// A tampered ticket.
	forged := newTestBrowser(t)
	setCookie(t, forged, e.ts.URL, escapeLoginCookieName, cookieNamed(resp, escapeLoginCookieName).Value+"x")
	if _, status, body := e.postEscape(t, forged, addrLondon2, code); status != http.StatusUnauthorized || problemType(t, body) != "step-expired" {
		t.Errorf("a tampered ticket = %d %s", status, body)
	}
	// Malformed body.
	if status, _ := readAll(t, postJSON(t, b.at(addrLondon2), e.ts.URL+loginEscapePath, map[string]any{"code": 5})); status != http.StatusBadRequest {
		t.Errorf("a bad body = %d", status)
	}
	// The ticket still works with the code.
	if _, status, body := e.postEscape(t, b, addrLondon2, code); status != http.StatusOK {
		t.Errorf("the right code after all that = %d %s", status, body)
	}
}

func setCookie(t *testing.T, b *browser, rawURL, name, value string) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	b.jar.SetCookies(u, []*http.Cookie{{Name: name, Value: value, Path: "/"}})
}

// Single use: a replay of the same ticket, however it is presented, is
// told to sign in again.
func TestEscapeCodeIsSingleUse(t *testing.T) {
	e := loneAdminEnv(t)
	b, resp := e.refusedFrom(t, addrLondon2)
	code := e.loggedCode()
	if _, status, body := e.postEscape(t, b, addrLondon2, code); status != http.StatusOK {
		t.Fatalf("escape = %d %s", status, body)
	}
	sessions := e.sessions()
	replay := newTestBrowser(t)
	setCookie(t, replay, e.ts.URL, escapeLoginCookieName, cookieNamed(resp, escapeLoginCookieName).Value)
	_, status, body := e.postEscape(t, replay, addrLondon2, code)
	if status != http.StatusUnauthorized || problemType(t, body) != "step-expired" {
		t.Errorf("a replay = %d %s", status, body)
	}
	if e.sessions() != sessions {
		t.Error("a replay issued a session")
	}
}

// Fifteen minutes and the ticket is dead.
func TestEscapeTicketExpires(t *testing.T) {
	e := loneAdminEnv(t)
	b, _ := e.refusedFrom(t, addrLondon2)
	code := e.loggedCode()
	e.advance(EscapeCodeLifetime)
	resp, status, body := e.postEscape(t, b, addrLondon2, code)
	if status != http.StatusUnauthorized || problemType(t, body) != "step-expired" {
		t.Errorf("at 15 minutes = %d %s", status, body)
	}
	if c := cookieNamed(resp, escapeLoginCookieName); c == nil || c.MaxAge >= 0 {
		t.Error("an expired ticket's cookie was not cleared")
	}
}

// So is one whose account is gone.
func TestEscapeTicketOfADeletedAccountIsDead(t *testing.T) {
	e := newEscapeEnv(t, gauntlet.RoleAdmin, true, nil)
	b, _ := e.refusedFrom(t, addrLondon2)
	code := e.loggedCode()
	// Another admin makes bob deletable.
	if _, err := e.g.deps.Users.CreateUser("carol-admin", "password-placeholder-2", gauntlet.RoleAdmin, e.clock.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.g.deps.Users.DeleteUser(e.bobID); err != nil {
		t.Fatal(err)
	}
	if _, status, body := e.postEscape(t, b, addrLondon2, code); status != http.StatusUnauthorized || problemType(t, body) != "step-expired" {
		t.Errorf("the ticket of a deleted account = %d %s", status, body)
	}
}

// The escape runs through the login limiter: a lockout and an address
// ban refuse it, as they refuse confirm.
func TestEscapeIsRefusedByALockoutAndByAnAddressBan(t *testing.T) {
	t.Run("lockout", func(t *testing.T) {
		e := loneAdminEnv(t)
		b, _ := e.refusedFrom(t, addrLondon2)
		code := e.loggedCode()
		for range 5 {
			_ = postJSON(t, newTestBrowser(t).at(addrNewYork), e.ts.URL+"/api/auth/login",
				credentialsRequest{Username: totpBobUsername, Password: "wrong-password-placeholder"}).Body.Close()
		}
		if _, status, _ := e.postEscape(t, b, addrLondon2, code); status != http.StatusTooManyRequests {
			t.Errorf("escape while locked out = %d, want 429", status)
		}
	})
	t.Run("address ban", func(t *testing.T) {
		e := loneAdminEnv(t)
		// Ban the address, then present a ticket sealed for now: the ban
		// takes two hours of failures, longer than a ticket lives.
		for i := range gauntlet.AddressBanFailures {
			resp := postJSON(t, newTestBrowser(t).at(addrLondon2), e.ts.URL+"/api/auth/login",
				credentialsRequest{Username: "nobody-" + string(rune('a'+i%26)) + strings.Repeat("x", i/26), Password: "wrong-password-placeholder"})
			_ = resp.Body.Close()
			if (i+1)%5 == 0 {
				e.advance(6 * time.Minute)
			}
		}
		display, canonical := gauntlet.NewOneTimeCode()
		ticket, err := escapeLoginCodec.seal(escapeLoginState{
			UserID: e.bobID, IssuedAt: e.clock.now(), ID: "forged-for-the-test",
			CodeHash: escapeCodeHash(canonical), Signals: gauntlet.SignalNewBrowser, Method: gauntlet.SignInMethodPassword,
		})
		if err != nil {
			t.Fatal(err)
		}
		b := newTestBrowser(t)
		setCookie(t, b, e.ts.URL, escapeLoginCookieName, ticket)
		if _, status, body := e.postEscape(t, b, addrLondon2, display); status != http.StatusTooManyRequests {
			t.Errorf("escape from a banned address = %d %s, want 429", status, body)
		}
		// From another address the same ticket and code do work.
		if _, status, body := e.postEscape(t, b, addrNewYork, display); status != http.StatusOK {
			t.Errorf("escape from another address = %d %s", status, body)
		}
	})
}
