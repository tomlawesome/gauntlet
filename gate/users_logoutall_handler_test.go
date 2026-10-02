package gate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// POST /api/auth/users/{id}/logout-all (#53): an admin ends every
// session another account holds, and the application is asked to tell
// its owner (Config.Notify).

// adminLogoutFixture is totpFixture with bob holding a confirmed TOTP
// factor and two sessions, one per browser, and the audit recorded. It
// returns the admin's client and bob's two.
func adminLogoutFixture(t *testing.T) (*Gate, *httptest.Server, *http.Client, []*http.Client) {
	t.Helper()
	g, ts, admin := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	_, codes, _ := totpEnrolAndConfirm(t, bob, ts)
	phone := signInBob(t, ts, "Safari/18.0 (phone)", "192.0.2.44", codes[0])
	g.cfg.Audit = &auditRecorder{}
	return g, ts, admin, []*http.Client{bob, phone}
}

// adminLogoutAll sends the request as client, with body unless it is
// nil, and returns the status and the decoded 200 body.
func adminLogoutAll(t *testing.T, client *http.Client, ts *httptest.Server, id string, body any) (int, adminLogoutAllResponse, string) {
	t.Helper()
	url := ts.URL + "/api/auth/users/" + id + "/logout-all"
	var resp *http.Response
	if body == nil {
		req, err := http.NewRequest(http.MethodPost, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(csrfHeaderName, testCSRFValue)
		if resp, err = client.Do(req); err != nil {
			t.Fatal(err)
		}
	} else {
		resp = postJSON(t, client, url, body)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out adminLogoutAllResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decoding %s: %v", raw, err)
		}
	}
	return resp.StatusCode, out, string(raw)
}

func requireSignedIn(t *testing.T, ts *httptest.Server, clients []*http.Client, want bool) {
	t.Helper()
	for i, c := range clients {
		status, _ := listSessions(t, c, ts)
		if got := status == http.StatusOK; got != want {
			t.Errorf("bob's browser %d: GET /api/auth/sessions = %d, want signed in %v", i+1, status, want)
		}
	}
}

func TestAdminLogoutAllEndsEverySession(t *testing.T) {
	g, ts, admin, bobs := adminLogoutFixture(t)
	bobID := totpBobID(t, g)
	if u, _ := g.deps.Users.Get(bobID); len(u.KnownBrowsers) == 0 {
		t.Fatal("bob's sign-ins remembered no browser; the test needs one to see it forgotten")
	}

	status, out, raw := adminLogoutAll(t, admin, ts, bobID, adminLogoutAllRequest{Reason: "laptop reported stolen"})
	if status != http.StatusOK {
		t.Fatalf("status %d %q, want 200", status, raw)
	}
	if want := (adminLogoutAllResponse{Username: totpBobUsername, Ended: 2, Notified: false}); out != want {
		t.Errorf("response = %+v, want %+v", out, want)
	}
	requireSignedIn(t, ts, bobs, false)
	if u, _ := g.deps.Users.Get(bobID); len(u.KnownBrowsers) != 0 {
		t.Errorf("bob's remembered browsers survived: %d", len(u.KnownBrowsers))
	}
	if status, _ := listSessions(t, admin, ts); status != http.StatusOK {
		t.Errorf("the admin's own session ended too: %d", status)
	}

	entries := auditEntries(g.cfg.Audit.(*auditRecorder), "user.sessions_ended")
	want := auditEntry{"admin", "user.sessions_ended", totpBobUsername,
		`sessions ended: all (n=2), reason="laptop reported stolen", notify=none, remembered browsers forgotten` + fixtureFromSuffix}
	if len(entries) != 1 || entries[0] != want {
		t.Errorf("audit = %+v, want exactly %+v", entries, want)
	}
}

// The body is optional: no body is no reason.
func TestAdminLogoutAllWithoutABody(t *testing.T) {
	g, ts, admin, bobs := adminLogoutFixture(t)
	if status, out, raw := adminLogoutAll(t, admin, ts, totpBobID(t, g), nil); status != http.StatusOK || out.Ended != 2 {
		t.Fatalf("no body: %d %q", status, raw)
	}
	requireSignedIn(t, ts, bobs, false)
	if e := findAuditEntry(t, g, "user.sessions_ended"); !strings.Contains(e.Detail, `reason=""`) {
		t.Errorf("audit detail = %q, want an empty reason", e.Detail)
	}
}

// Every refusal ends nothing.
func TestAdminLogoutAllRefusals(t *testing.T) {
	g, ts, admin, bobs := adminLogoutFixture(t)
	bobID := totpBobID(t, g)
	adminUser, _ := g.deps.Users.ByUsername("admin")

	cases := []struct {
		name   string
		client *http.Client
		id     string
		body   any
		want   int
	}{
		{"own account", admin, adminUser.ID, nil, http.StatusConflict},
		{"no such account", admin, "no-such-id", nil, http.StatusNotFound},
		{"reason over 200 bytes", admin, bobID, adminLogoutAllRequest{Reason: strings.Repeat("é", 101)}, http.StatusBadRequest},
		{"reason with a newline", admin, bobID, adminLogoutAllRequest{Reason: "line\nforged"}, http.StatusBadRequest},
		{"reason with a bidi override", admin, bobID, adminLogoutAllRequest{Reason: "abc\u202Edef"}, http.StatusBadRequest},
		{"unknown field", admin, bobID, map[string]string{"why": "x"}, http.StatusBadRequest},
		{"not an admin", bobs[0], bobID, nil, http.StatusForbidden},
	}
	for _, tc := range cases {
		if status, _, raw := adminLogoutAll(t, tc.client, ts, tc.id, tc.body); status != tc.want {
			t.Errorf("%s: status %d %q, want %d", tc.name, status, raw, tc.want)
		}
	}
	requireSignedIn(t, ts, bobs, true)
	if n := len(auditEntries(g.cfg.Audit.(*auditRecorder), "user.sessions_ended")); n != 0 {
		t.Errorf("refusals wrote %d user.sessions_ended records", n)
	}

	// Without the CSRF header Protect refuses it, and with no session
	// it is 401.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/users/"+bobID+"/logout-all", nil)
	resp, err := admin.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("without the CSRF header: %d, want 403", resp.StatusCode)
	}
	if status, _, _ := adminLogoutAll(t, &http.Client{}, ts, bobID, nil); status != http.StatusUnauthorized {
		t.Errorf("anonymous: %d, want 401", status)
	}
	requireSignedIn(t, ts, bobs, true)

	// A reason of exactly MaxSessionEndReason bytes is accepted.
	if status, _, raw := adminLogoutAll(t, admin, ts, bobID, adminLogoutAllRequest{Reason: strings.Repeat("é", MaxSessionEndReason/2)}); status != http.StatusOK {
		t.Errorf("a %d-byte reason: %d %q, want 200", MaxSessionEndReason, status, raw)
	}
}

// notifierFunc adapts a function to Notifier.
type notifierFunc func(ctx context.Context, n SessionsEndedNotice) error

func (f notifierFunc) SessionsEnded(ctx context.Context, n SessionsEndedNotice) error {
	return f(ctx, n)
}

// The notifier is called exactly once, after the response, with the
// notice the application needs to write its mail.
func TestAdminLogoutAllNotifiesAfterTheResponse(t *testing.T) {
	g, ts, admin, _ := adminLogoutFixture(t)
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	g.cfg.Now = func() time.Time { return at }
	release := make(chan struct{})
	var mu sync.Mutex
	var got []SessionsEndedNotice
	g.cfg.Notify = notifierFunc(func(_ context.Context, n SessionsEndedNotice) error {
		<-release // the response must not wait for this
		mu.Lock()
		defer mu.Unlock()
		got = append(got, n)
		return nil
	})

	status, out, raw := adminLogoutAll(t, admin, ts, totpBobID(t, g), adminLogoutAllRequest{Reason: "lost phone"})
	if status != http.StatusOK || !out.Notified {
		t.Fatalf("status %d %q, want 200 with notified", status, raw)
	}
	close(release)
	g.notifying.Wait()

	want := SessionsEndedNotice{UserID: totpBobID(t, g), Username: totpBobUsername, EndedBy: "admin", Reason: "lost phone", Ended: 2, At: at}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != want {
		t.Errorf("notices = %+v, want exactly %+v", got, want)
	}
	if e := findAuditEntry(t, g, "user.sessions_ended"); !strings.Contains(e.Detail, "notify=requested") {
		t.Errorf("audit detail = %q, want notify=requested", e.Detail)
	}
}

// A notifier that is slow, fails or panics never changes the admin's
// answer, and leaves one log line.
func TestAdminLogoutAllNotifierFailures(t *testing.T) {
	old := notifyTimeout
	notifyTimeout = 50 * time.Millisecond
	t.Cleanup(func() { notifyTimeout = old })

	for name, notify := range map[string]notifierFunc{
		"slow": func(ctx context.Context, _ SessionsEndedNotice) error {
			<-ctx.Done()
			return ctx.Err()
		},
		"erroring": func(context.Context, SessionsEndedNotice) error { return errors.New("mail relay refused") },
		"panicking": func(context.Context, SessionsEndedNotice) error {
			panic("notifier bug")
		},
	} {
		t.Run(name, func(t *testing.T) {
			g, ts, admin, bobs := adminLogoutFixture(t)
			logs := &messageRecorder{}
			g.cfg.Log = slog.New(logs)
			g.cfg.Notify = notify

			status, out, raw := adminLogoutAll(t, admin, ts, totpBobID(t, g), nil)
			if status != http.StatusOK || !out.Notified || out.Ended != 2 {
				t.Fatalf("status %d %q, want 200 with notified", status, raw)
			}
			g.notifying.Wait()
			requireSignedIn(t, ts, bobs, false)
			if lines := logLines(logs, "notif"); len(lines) != 1 || !strings.Contains(lines[0], totpBobUsername) {
				t.Errorf("log lines = %q, want one naming the account", lines)
			}
		})
	}
}

// Ending the sessions does not depend on the notifier: with none set,
// notified is false and nothing is asked.
func TestAdminLogoutAllWithoutNotifier(t *testing.T) {
	g, ts, admin, _ := adminLogoutFixture(t)
	if status, out, _ := adminLogoutAll(t, admin, ts, totpBobID(t, g), nil); status != http.StatusOK || out.Notified {
		t.Fatalf("status %d, out %+v, want 200 with notified false", status, out)
	}
	if !strings.Contains(findAuditEntry(t, g, "user.sessions_ended").Detail, "notify=none") {
		t.Error("audit does not say no notification was asked for")
	}
}
