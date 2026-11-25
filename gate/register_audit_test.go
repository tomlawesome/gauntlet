package gate

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tomlawesome/gauntlet"
)

// #125: a refused first-run registration leaves one user.register_failed
// audit record with a reason, the address and the masked typed name --
// never the setup code or the password.

const (
	regAuditWrongCode = "wrong-setup-code-placeholder-7f3a"
	regAuditPassword  = "distinctive-reg-password-4821"
)

type regAuditCase struct {
	name       string
	username   string
	password   string
	wrongCode  bool // send a wrong setup code instead of the right one
	closeFirst bool // register the first admin before the attempt
	noRecord   bool // the refusal leaves no audit record (a rated log line instead)
	status     int
	reason     string
}

func regAuditGate(t *testing.T) (*Gate, *auditRecorder, *messageRecorder, *httptest.Server) {
	t.Helper()
	g := newTestGate(t)
	audit, logs := &auditRecorder{}, &messageRecorder{}
	g.cfg.Audit = audit
	g.cfg.Log = slog.New(logs)
	return g, audit, logs, newTestServer(t, g)
}

func TestRegisterRefusalRecordsAFailureEvent(t *testing.T) {
	cases := []regAuditCase{
		{name: "wrong setup code", username: "newadmin", password: regAuditPassword, wrongCode: true, status: http.StatusUnauthorized, reason: "setup_code"},
		{name: "closed", username: "newadmin", password: regAuditPassword, closeFirst: true, noRecord: true, status: http.StatusConflict},
		{name: "password too short", username: "newadmin", password: "short1", status: http.StatusBadRequest, reason: "password"},
		{name: "password on the blocklist", username: "newadmin", password: "password1234", status: http.StatusBadRequest, reason: "password"},
		{name: "password is the product name", username: "newadmin", password: "Gate Test Suite", status: http.StatusBadRequest, reason: "password"},
		{name: "password is the username", username: "newadmin", password: "newadmin2026!", status: http.StatusBadRequest, reason: "password"},
		{name: "username has invalid characters", username: "bad\x00name", password: regAuditPassword, status: http.StatusBadRequest, reason: "username"},
		{name: "username too long", username: strings.Repeat("a", 200), password: regAuditPassword, status: http.StatusBadRequest, reason: "username"},
		{name: "username is an email", username: "someone@example.org", password: regAuditPassword, status: http.StatusBadRequest, reason: "username"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, audit, _, ts := regAuditGate(t)
			url := ts.URL
			code := setupCodeFor(t, g)
			if tc.closeFirst {
				registerAdmin(t, ts, "firstadmin", "first-admin-password-placeholder-1")
			}
			sent := code
			if tc.wrongCode {
				sent = regAuditWrongCode
			}
			resp := postJSON(t, &http.Client{Jar: mustCookieJar(t)}, url+"/api/auth/register",
				registerRequest{Username: tc.username, Password: tc.password, SetupCode: sent})
			status, body := readAll(t, resp)
			if status != tc.status {
				t.Fatalf("status = %d (%s), want %d", status, body, tc.status)
			}
			got := auditEntries(audit, "user.register_failed")
			if tc.noRecord {
				if len(got) != 0 {
					t.Fatalf("user.register_failed records = %+v, want none", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("user.register_failed records = %+v, want exactly one", got)
			}
			e := got[0]
			if e.Actor != "unknown" || e.Target != "unknown" {
				t.Errorf("actor/target = %q/%q, want unknown/unknown", e.Actor, e.Target)
			}
			for _, want := range []string{
				"reason=" + tc.reason,
				fixtureFrom,
				`name="` + gauntlet.MaskUnknownUsername(tc.username) + `"`,
			} {
				if !strings.Contains(e.Detail, want) {
					t.Errorf("detail %q lacks %q", e.Detail, want)
				}
			}
			for _, secret := range []string{code, regAuditWrongCode, tc.password} {
				for _, field := range []string{e.Actor, e.Action, e.Target, e.Detail} {
					if secret != "" && strings.Contains(field, secret) {
						t.Errorf("record field %q leaks %q", field, secret)
					}
				}
			}
			// The closed case's own setup registers the first admin.
			wantRegister := 0
			if tc.closeFirst {
				wantRegister = 1
			}
			if n := len(auditEntries(audit, "user.register")); n != wantRegister {
				t.Errorf("user.register records = %d, want %d: a refused registration recorded one", n, wantRegister)
			}
		})
	}
}

// A malformed body is not recorded.
func TestRegisterMalformedBodyIsNotRecorded(t *testing.T) {
	_, audit, _, ts := regAuditGate(t)
	url := ts.URL
	req, err := http.NewRequest(http.MethodPost, url+"/api/auth/register", strings.NewReader("{not json"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrfHeaderName, testCSRFValue)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	status, body := readAll(t, resp)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d (%s), want 400", status, body)
	}
	if n := len(auditEntries(audit, "user.register_failed")); n != 0 {
		t.Errorf("a malformed body recorded %d register_failed events", n)
	}
}

// A throttled attempt (429) stays a log line, not an audit record; the
// refusals before the limit are recorded, the throttled one is not.
func TestRegisterThrottledAttemptIsNotRecorded(t *testing.T) {
	_, audit, _, ts := regAuditGate(t)
	url := ts.URL
	client := &http.Client{Jar: mustCookieJar(t)}
	var throttled int
	for range 10 {
		resp := postJSON(t, client, url+"/api/auth/register",
			registerRequest{Username: "newadmin", Password: regAuditPassword, SetupCode: regAuditWrongCode})
		status, _ := readAll(t, resp)
		if status == http.StatusTooManyRequests {
			throttled++
		}
	}
	if throttled == 0 {
		t.Fatal("the limiter never refused; the scenario did not reach a 429")
	}
	if got := len(auditEntries(audit, "user.register_failed")); got != 10-throttled {
		t.Errorf("register_failed records = %d, want %d (one per non-throttled refusal, none for the %d throttled)", got, 10-throttled, throttled)
	}
}

// A successful registration records user.register and no failure.
func TestRegisterSuccessRecordsNoFailure(t *testing.T) {
	g, audit, _, ts := regAuditGate(t)
	url := ts.URL
	resp := postJSON(t, &http.Client{Jar: mustCookieJar(t)}, url+"/api/auth/register",
		registerRequest{Username: "newadmin", Password: regAuditPassword, SetupCode: setupCodeFor(t, g)})
	if status, body := readAll(t, resp); status != http.StatusCreated {
		t.Fatalf("status = %d (%s), want 201", status, body)
	}
	if n := len(auditEntries(audit, "user.register")); n != 1 {
		t.Errorf("user.register records = %d, want 1", n)
	}
	if n := len(auditEntries(audit, "user.register_failed")); n != 0 {
		t.Errorf("a successful registration recorded %d register_failed events", n)
	}
}

// A throttled registration (429) leaves a Warn line naming the address,
// without the setup code or password, and repeats from one address are
// rated like the sign-in refusals: one line within the window.
func TestRegisterThrottledAttemptLeavesARatedWarning(t *testing.T) {
	g, _, logs, ts := regAuditGate(t)
	code := setupCodeFor(t, g)
	key := addressKey("198.51.100.1")
	for g.deps.Limiter.Reserve(key, g.now()) {
	}
	client := &http.Client{Jar: mustCookieJar(t)}
	for range 4 {
		resp := postJSON(t, client, ts.URL+"/api/auth/register",
			registerRequest{Username: "newadmin", Password: regAuditPassword, SetupCode: code})
		if status, body := readAll(t, resp); status != http.StatusTooManyRequests {
			t.Fatalf("status = %d (%s), want 429", status, body)
		}
	}
	logs.mu.Lock()
	defer logs.mu.Unlock()
	if len(logs.msgs) != 1 {
		t.Fatalf("log lines = %q, want exactly one for four throttled attempts", logs.msgs)
	}
	line := logs.msgs[0]
	if !strings.Contains(line, "198.51.100.1") {
		t.Errorf("line %q does not name the address", line)
	}
	for _, secret := range []string{code, regAuditPassword} {
		if strings.Contains(line, secret) {
			t.Errorf("line %q leaks %q", line, secret)
		}
	}
}

// A flood of registration attempts on a closed install (the first admin
// exists) writes no audit record -- the closed decision comes before any
// code is compared, so it is not a guess, and one record per request
// would let a flood fill the audit store -- and leaves at most one rated
// Warn line within one warnRateInterval.
func TestRegisterClosedFloodWritesNoAuditRecords(t *testing.T) {
	_, audit, logs, ts := regAuditGate(t)
	registerAdmin(t, ts, "firstadmin", "first-admin-password-placeholder-1")
	client := &http.Client{Jar: mustCookieJar(t)}
	const n = 20
	for i := range n {
		resp := postJSON(t, client, ts.URL+"/api/auth/register",
			registerRequest{Username: "newadmin", Password: regAuditPassword, SetupCode: regAuditWrongCode})
		if status, body := readAll(t, resp); status != http.StatusConflict {
			t.Fatalf("request %d: status = %d (%s), want 409", i, status, body)
		}
	}
	if got := auditEntries(audit, "user.register_failed"); len(got) != 0 {
		t.Errorf("%d user.register_failed records for %d closed-install attempts, want none", len(got), n)
	}
	lines := logLines(logs, "registration refused, the first admin already exists")
	if len(lines) != 1 {
		t.Errorf("rated closed-install log lines = %q, want exactly one for %d attempts in one interval", lines, n)
	}
	for _, l := range lines {
		if !strings.Contains(l, fixtureFrom) {
			t.Errorf("line %q does not name the address %s", l, fixtureFrom)
		}
		if strings.Contains(l, regAuditWrongCode) || strings.Contains(l, regAuditPassword) {
			t.Errorf("line %q leaks a secret", l)
		}
	}
}
