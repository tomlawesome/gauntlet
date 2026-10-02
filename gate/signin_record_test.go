package gate

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/oidc"
)

// Every sign-in attempt is recorded (#45, #53): failures as
// user.login_failed, the attempt that starts a lockout or a disable as
// account.locked or account.disabled, successes as user.login with the
// client address, and limiter refusals as a rated Warn line. The
// events gate hands its history hook (recordSignIn) are checked too.

// signInEvents keeps every event recordSignIn hands the history hook.
type signInEvents struct {
	mu     sync.Mutex
	events []gauntlet.SignInEvent
}

func (s *signInEvents) add(ev gauntlet.SignInEvent, _ time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *signInEvents) all() []gauntlet.SignInEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]gauntlet.SignInEvent(nil), s.events...)
}

// recordSignIns points g's audit, log and history hook at fresh
// recorders, from this moment on.
func recordSignIns(g *Gate) (*auditRecorder, *messageRecorder, *signInEvents) {
	audit, logs, events := &auditRecorder{}, &messageRecorder{}, &signInEvents{}
	g.cfg.Audit = audit
	g.cfg.Log = slog.New(logs)
	g.signInHook = events.add
	return audit, logs, events
}

// auditEntries is every entry audit holds for action, oldest first.
func auditEntries(audit *auditRecorder, action string) []auditEntry {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	var out []auditEntry
	for _, e := range audit.entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

// logLines is every logged message containing substr.
func logLines(logs *messageRecorder, substr string) []string {
	logs.mu.Lock()
	defer logs.mu.Unlock()
	var out []string
	for _, m := range logs.msgs {
		if strings.Contains(m, substr) {
			out = append(out, m)
		}
	}
	return out
}

// wantEvents compares the outcome and method of each event, in order.
func wantEvents(t *testing.T, got []gauntlet.SignInEvent, want ...string) {
	t.Helper()
	var have []string
	for _, ev := range got {
		have = append(have, string(ev.Outcome)+"/"+string(ev.Method))
	}
	if strings.Join(have, " ") != strings.Join(want, " ") {
		t.Fatalf("sign-in events = %v, want %v", have, want)
	}
}

const fixtureFrom = `from="198.51.100.1"`

// fixtureFromSuffix is what gate.audit appends to a request's record.
const fixtureFromSuffix = "; " + fixtureFrom

// A wrong password is exactly one user.login_failed record, naming the
// account in full, and no user.login.
func TestWrongPasswordIsOneLoginFailedRecord(t *testing.T) {
	g, ts, _ := totpFixture(t)
	audit, _, events := recordSignIns(g)

	if r := tryLogin(t, ts, totpBobUsername, "wrong-password-placeholder"); r.status != http.StatusUnauthorized {
		t.Fatalf("wrong password: status %d", r.status)
	}
	failed := auditEntries(audit, "user.login_failed")
	if len(failed) != 1 {
		t.Fatalf("%d user.login_failed records, want 1: %+v", len(failed), audit.entries)
	}
	want := auditEntry{totpBobUsername, "user.login_failed", totpBobUsername, "outcome=wrong_password method=password " + fixtureFrom}
	if failed[0] != want {
		t.Errorf("record = %+v, want %+v", failed[0], want)
	}
	if n := len(auditEntries(audit, "user.login")); n != 0 {
		t.Errorf("a wrong password wrote %d user.login records", n)
	}
	got := events.all()
	wantEvents(t, got, "wrong_password/password")
	if ev := got[0]; ev.UserID != totpBobID(t, g) || ev.Username != totpBobUsername || ev.Client.Address != "198.51.100.1" {
		t.Errorf("event = %+v, want bob's id and name and the client address", ev)
	}
}

// A name that matched no account is recorded masked, never as typed --
// in the audit record, the event and every log line.
func TestUnknownUsernameIsRecordedMasked(t *testing.T) {
	g, ts, _ := totpFixture(t)
	audit, logs, events := recordSignIns(g)
	typed := "Hunter2024!"

	if r := tryLogin(t, ts, typed, "anything-placeholder"); r.status != http.StatusUnauthorized {
		t.Fatalf("unknown name: status %d", r.status)
	}
	failed := auditEntries(audit, "user.login_failed")
	if len(failed) != 1 {
		t.Fatalf("%d user.login_failed records, want 1", len(failed))
	}
	want := auditEntry{"unknown", "user.login_failed", "unknown", `outcome=no_such_user method=password ` + fixtureFrom + ` name="Hu•••••••••"`}
	if failed[0] != want {
		t.Errorf("record = %+v, want %+v", failed[0], want)
	}
	got := events.all()
	wantEvents(t, got, "no_such_user/password")
	if got[0].UserID != "" || got[0].Username != "Hu•••••••••" {
		t.Errorf("event = %+v, want no account and the masked name", got[0])
	}
	audit.mu.Lock()
	for _, e := range audit.entries {
		if strings.Contains(fmt.Sprint(e), "Hunter") {
			t.Errorf("the typed name reached the audit: %+v", e)
		}
	}
	audit.mu.Unlock()
	if lines := logLines(logs, "Hunter"); len(lines) != 0 {
		t.Errorf("the typed name reached the log: %q", lines)
	}
}

// A right password with a factor still owed is password_ok, then the
// code completes the sign-in: success by code, and one user.login with
// the address.
func TestSecondFactorSignInRecordsPasswordOKThenSuccess(t *testing.T) {
	g, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	secret, codes, _ := totpEnrolAndConfirm(t, bob, ts)
	audit, _, events := recordSignIns(g)

	client := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	wrong := submitLoginFactor(t, client, ts, wrongTOTPCode(secret, time.Now()))
	_ = wrong.Body.Close()
	if wrong.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a wrong code: status %d", wrong.StatusCode)
	}
	right := submitLoginFactor(t, client, ts, codes[0])
	_ = right.Body.Close()
	if right.StatusCode != http.StatusOK {
		t.Fatalf("a recovery code: status %d", right.StatusCode)
	}

	wantEvents(t, events.all(), "password_ok/password", "factor_refused/code", "success/code")
	failed := auditEntries(audit, "user.login_failed")
	if len(failed) != 1 || failed[0].Detail != "outcome=factor_refused method=code "+fixtureFrom {
		t.Errorf("user.login_failed = %+v, want one factor_refused by code", failed)
	}
	logins := auditEntries(audit, "user.login")
	if len(logins) != 1 || logins[0].Detail != "via second factor; "+fixtureFrom {
		t.Errorf("user.login = %+v, want one, via second factor with the address", logins)
	}
}

// A one-step sign-in's user.login carries the address too.
func TestOneStepSignInRecordsTheAddress(t *testing.T) {
	g, ts, _ := totpFixture(t)
	audit, _, events := recordSignIns(g)
	_ = loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	wantEvents(t, events.all(), "success/password")
	logins := auditEntries(audit, "user.login")
	if len(logins) != 1 || logins[0].Detail != fixtureFrom || logins[0].Target != totpBobUsername {
		t.Errorf("user.login = %+v, want bob's with %s", logins, fixtureFrom)
	}
}

// A refused passkey assertion is factor_refused by passkey; an accepted
// one is success by passkey.
func TestPasskeyAttemptsAreRecorded(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	fake, _ := registerPasskey(t, bilbo, ts, g, "key")
	audit, _, events := recordSignIns(g)

	pending := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	resp, body := postWithCookie(t, pending, ts.URL+"/api/auth/login/factor",
		loginFactorRequest{Assertion: json.RawMessage(`{"id":"x"}`)},
		&http.Cookie{Name: passkeyAssertCookieName, Value: "garbage"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("refused assertion: status %d %q", resp.StatusCode, body)
	}
	ok := submitPasskeyAssertion(t, pending, ts, fake, passkeyLoginFactorBegin(t, pending, ts))
	_ = ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("accepted assertion: status %d", ok.StatusCode)
	}

	wantEvents(t, events.all(), "password_ok/password", "factor_refused/passkey", "success/passkey")
	failed := auditEntries(audit, "user.login_failed")
	if len(failed) != 1 || failed[0].Target != passkeyBilboUsername || failed[0].Detail != "outcome=factor_refused method=passkey "+fixtureFrom {
		t.Errorf("user.login_failed = %+v, want one for bilbo's refused passkey", failed)
	}
}

// The attempt that starts a lockout writes one account.locked beside its
// user.login_failed; refusals during the lockout are no audit at all,
// only events and a rated Warn line.
func TestLockoutIsAuditedOnce(t *testing.T) {
	g, ts, clock := escalationFixture(t)
	audit, logs, events := recordSignIns(g)
	start := clock.now()

	failLoginWindow(t, g, ts, clock, totpBobUsername)
	if n := len(auditEntries(audit, "user.login_failed")); n != 5 {
		t.Errorf("%d user.login_failed records for five wrong passwords, want 5", n)
	}
	locked := auditEntries(audit, "account.locked")
	if len(locked) != 1 {
		t.Fatalf("%d account.locked records, want 1", len(locked))
	}
	until := start.Add(5 * time.Minute).UTC().Format(time.RFC3339)
	if want := (auditEntry{totpBobUsername, "account.locked", totpBobUsername, `until=` + until + ` lockouts=1 from="192.0.2.5"`}); locked[0] != want {
		t.Errorf("account.locked = %+v, want %+v", locked[0], want)
	}
	last := events.all()[4]
	if last.Outcome != gauntlet.SignInWrongPassword || last.LockedUntil.IsZero() {
		t.Errorf("the attempt that started the lockout = %+v, want wrong_password with LockedUntil", last)
	}

	for range 3 {
		if r := tryLogin(t, ts, totpBobUsername, totpBobPassword); r.status != http.StatusTooManyRequests {
			t.Fatalf("an attempt during the lockout: status %d, want 429", r.status)
		}
	}
	if n := len(auditEntries(audit, "user.login_failed")); n != 5 {
		t.Errorf("refusals during the lockout wrote audit records: %d user.login_failed", n)
	}
	got := events.all()
	if len(got) != 8 || got[7].Outcome != gauntlet.SignInLocked || got[7].LockedUntil.IsZero() {
		t.Errorf("refusal events = %+v, want three locked refusals carrying the lockout's end", got[5:])
	}
	if lines := logLines(logs, "outcome=locked"); len(lines) != 3 {
		// Every refusal came from a fresh address here, so each is its own key.
		t.Errorf("Warn lines for three refusals from three addresses = %q, want 3", lines)
	}
}

// The fiftieth failure in a row writes one account.disabled; a refusal
// after it is a disabled event.
func TestDisableIsAuditedOnce(t *testing.T) {
	g, ts, clock := escalationFixture(t)
	audit, _, events := recordSignIns(g)
	for range gauntlet.MaxConsecutiveLoginFailures / 5 {
		failLoginWindow(t, g, ts, clock, totpBobUsername)
	}
	disabled := auditEntries(audit, "account.disabled")
	if len(disabled) != 1 || !strings.HasPrefix(disabled[0].Detail, "after 50 consecutive failures; from=") {
		t.Fatalf("account.disabled = %+v, want one", disabled)
	}
	clock.set(clock.now().Add(365 * 24 * time.Hour))
	if r := tryLogin(t, ts, totpBobUsername, totpBobPassword); r.status != http.StatusTooManyRequests {
		t.Fatalf("an attempt on a disabled account: status %d", r.status)
	}
	got := events.all()
	if last := got[len(got)-1]; last.Outcome != gauntlet.SignInDisabled || !last.Disabled {
		t.Errorf("the refusal = %+v, want a disabled event", last)
	}
	if n := len(auditEntries(audit, "account.disabled")); n != 1 {
		t.Errorf("%d account.disabled records after the refusal, want still 1", n)
	}
}

// The admitted attempt that fills the window but turns out right hands
// the lockout back: no account.locked.
func TestASuccessfulAttemptAuditsNoLockout(t *testing.T) {
	g, ts, _ := escalationFixture(t)
	audit, _, _ := recordSignIns(g)
	for range 4 {
		tryLogin(t, ts, totpBobUsername, "wrong-password-placeholder")
	}
	if r := tryLogin(t, ts, totpBobUsername, totpBobPassword); r.status != http.StatusOK {
		t.Fatalf("the right password as the fifth attempt: status %d", r.status)
	}
	if n := len(auditEntries(audit, "account.locked")); n != 0 {
		t.Errorf("a successful fifth attempt wrote %d account.locked records", n)
	}
	if n := len(auditEntries(audit, "user.login")); n != 1 {
		t.Errorf("%d user.login records, want 1", n)
	}
}

// The address at its limit refuses with rate_limited, and a flood of
// such refusals is one Warn line, not one per request.
func TestAddressLimitIsRateLimitedAndRated(t *testing.T) {
	g, ts, _ := totpFixture(t)
	audit, logs, events := recordSignIns(g)
	for i := range 5 {
		tryLogin(t, ts, fmt.Sprintf("nobody-%d", i), "anything-placeholder")
	}
	for range 20 {
		if r := tryLogin(t, ts, totpBobUsername, totpBobPassword); r.status != http.StatusTooManyRequests {
			t.Fatalf("an attempt past the address limit: status %d", r.status)
		}
	}
	got := events.all()
	if len(got) != 25 || got[24].Outcome != gauntlet.SignInRateLimited || got[24].Username != totpBobUsername {
		t.Fatalf("the refusal events = %+v, want rate_limited for bob", got[5:])
	}
	if n := len(auditEntries(audit, "user.login_failed")); n != 5 {
		t.Errorf("%d user.login_failed records, want 5: refusals are not audited", n)
	}
	lines := logLines(logs, "refused by the login limiter")
	if len(lines) != 1 || !strings.Contains(lines[0], fixtureFrom) {
		t.Errorf("Warn lines = %q, want one carrying %s", lines, fixtureFrom)
	}
}

// A refused SSO identity is sso_refused with its name hint masked, and
// a completed SSO sign-in now writes user.login.
func TestSSOAttemptsAreRecorded(t *testing.T) {
	g, ts, fp := newOIDCTestGate(t, oidc.Policy{AllowedEmails: []string{"someone-else@example.com"}})
	audit, _, events := recordSignIns(g)
	callback := func() int {
		fs, err := oidc.NewFlowState(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))
		resp, err := noRedirectClient().Do(oidcCallbackRequest(t, g, ts, fs, "state="+fs.State+"&code=test-code"))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	if s := callback(); s != http.StatusFound {
		t.Fatalf("refused callback: status %d", s)
	}
	failed := auditEntries(audit, "user.login_failed")
	want := auditEntry{"unknown", "user.login_failed", "unknown", `outcome=sso_refused method=sso ` + fixtureFrom + ` name="pe••••"`}
	if len(failed) != 1 || failed[0] != want {
		t.Errorf("user.login_failed = %+v, want %+v", failed, want)
	}

	g.deps.OIDCPolicy = oidc.Policy{}
	if s := callback(); s != http.StatusFound {
		t.Fatalf("permitted callback: status %d", s)
	}
	logins := auditEntries(audit, "user.login")
	if len(logins) != 1 || logins[0].Target != "person" || logins[0].Detail != "via sso; "+fixtureFrom {
		t.Errorf("user.login = %+v, want person's, via sso with the address", logins)
	}
	wantEvents(t, events.all(), "sso_refused/sso", "success/sso")
}

// A spent pending login answered "sign in again" is not a credential
// check: nothing is recorded.
func TestSignInAgainRecordsNothing(t *testing.T) {
	g, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	_, codes, _ := totpEnrolAndConfirm(t, bob, ts)
	client := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	kept := pendingCookieOf(t, client, ts)
	first := submitLoginFactor(t, client, ts, codes[0])
	_ = first.Body.Close()
	audit, _, events := recordSignIns(g)

	resp, raw := postRaw(t, ts.URL+"/api/auth/login/factor", loginFactorRequest{Code: codes[1]}, kept)
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(raw, "sign in again") {
		t.Fatalf("replay: %d %q", resp.StatusCode, raw)
	}
	if got := events.all(); len(got) != 0 {
		t.Errorf("the replay recorded events %+v", got)
	}
	if n := len(auditEntries(audit, "user.login_failed")) + len(auditEntries(audit, "user.login")); n != 0 {
		t.Errorf("the replay wrote %d sign-in audit records", n)
	}
}

// protectRecorder runs one request through g's Protect over Routes.
func protectRecorder(g *Gate, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	mux.Handle("GET /api/protected", testProtectedHandler())
	mux.Handle("/", g.Routes())
	g.Protect(mux).ServeHTTP(w, r)
	return w
}

// A thousand refused CSRF requests from one address are at most two
// Warn lines, each carrying the address; the next after a minute says
// how many were left out.
func TestRefusedCSRFWarnLinesAreRated(t *testing.T) {
	g, _, _ := totpFixture(t)
	clock := &escalationClock{t: time.Now()}
	g.cfg.Now = clock.now
	_, logs, _ := recordSignIns(g)

	for range 1000 {
		r := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
		if w := protectRecorder(g, r); w.Code != http.StatusForbidden {
			t.Fatalf("a POST without the CSRF header: status %d", w.Code)
		}
	}
	lines := logLines(logs, "CSRF")
	if len(lines) < 1 || len(lines) > 2 {
		t.Fatalf("1000 refused CSRF requests made %d Warn lines, want 1 or 2: %q", len(lines), lines)
	}
	if !strings.Contains(lines[0], fixtureFrom) {
		t.Errorf("Warn line %q does not carry the address", lines[0])
	}

	clock.set(clock.now().Add(61 * time.Second))
	protectRecorder(g, httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil))
	lines = logLines(logs, "CSRF")
	if len(lines) != 2 || !strings.Contains(lines[1], "999") {
		t.Errorf("the line a minute later = %q, want it to count the 999 left out", lines)
	}
}

// A malformed Authorization header, a role refusal and the
// forced-enrolment door each leave a Warn line with the address.
func TestRefusalsLeaveAWarnLine(t *testing.T) {
	g, ts, _ := totpFixture(t)
	_, logs, _ := recordSignIns(g)

	r := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	r.Header.Set("Authorization", "Basic Zm9vOmJhcg==")
	if w := protectRecorder(g, r); w.Code != http.StatusUnauthorized {
		t.Fatalf("malformed Authorization: status %d", w.Code)
	}
	if lines := logLines(logs, "Authorization"); len(lines) != 1 || !strings.Contains(lines[0], fixtureFrom) {
		t.Errorf("malformed Authorization Warn lines = %q", lines)
	}

	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	resp, err := bob.Get(ts.URL + "/api/protected")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bob with no factor at the door: status %d", resp.StatusCode)
	}
	if lines := logLines(logs, authGateMustEnrolFactor); len(lines) != 1 || !strings.Contains(lines[0], fixtureFrom) {
		t.Errorf("door Warn lines = %q", lines)
	}

	totpEnrolAndConfirm(t, bob, ts)
	resp, err = bob.Get(ts.URL + "/api/auth/users")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bob listing users: status %d", resp.StatusCode)
	}
	if lines := logLines(logs, "insufficient role"); len(lines) != 1 || !strings.Contains(lines[0], fixtureFrom) {
		t.Errorf("role Warn lines = %q", lines)
	}
}

// Past the key cap, new sources share one line rather than each getting
// their own.
func TestWarnRatingIsBoundedBeyondTheKeyCap(t *testing.T) {
	g := newTestGate(t)
	logs := &messageRecorder{}
	g.cfg.Log = slog.New(logs)
	old := maxWarnRateKeys
	maxWarnRateKeys = 2
	t.Cleanup(func() { maxWarnRateKeys = old })

	for i := range 50 {
		g.warnRated(fmt.Sprintf("key-%d", i), fmt.Sprintf("line %d", i))
	}
	logs.mu.Lock()
	n := len(logs.msgs)
	logs.mu.Unlock()
	if n != 3 {
		t.Errorf("50 keys past a cap of 2 made %d lines, want 3 (two keys and one shared)", n)
	}
}
