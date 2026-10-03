package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/persist"
)

// GET /api/auth/sign-ins (#53): the admin's view of the sign-in history
// recordSignIn appends to through Deps.SignIns.

// signInsFixture is totpFixture with a sign-in history in memory behind
// Deps.SignIns, the address read from each browser's header, and the
// audit recorded.
func signInsFixture(t *testing.T, b persist.Backend) (*Gate, *httptest.Server, *http.Client, *gauntlet.SignInHistory) {
	t.Helper()
	g, ts, admin := totpFixture(t)
	g.cfg.ClientIP = func(r *http.Request) string {
		if ip := r.Header.Get(sessionsTestIPHeader); ip != "" {
			return ip
		}
		return "198.51.100.1"
	}
	h, err := gauntlet.OpenSignInHistory(b, gauntlet.SignInHistoryOptions{})
	if err != nil {
		t.Fatalf("OpenSignInHistory: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	g.deps.SignIns = h
	g.cfg.Audit = &auditRecorder{}
	return g, ts, admin, h
}

// getSignIns asks for the history as client with query, returning the
// status, the decoded 200 body and the raw body.
func getSignIns(t *testing.T, client *http.Client, ts *httptest.Server, query string) (int, signInListResponse, string) {
	t.Helper()
	resp, err := client.Get(ts.URL + "/api/auth/sign-ins" + query)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out signInListResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decoding %s: %v", raw, err)
		}
	}
	return resp.StatusCode, out, string(raw)
}

// attempt sends one password step from a browser at address.
func attempt(t *testing.T, ts *httptest.Server, address, username, password string) int {
	t.Helper()
	resp := postJSON(t, newBrowser(t, "Firefox/131.0", address), ts.URL+"/api/auth/login", credentialsRequest{Username: username, Password: password})
	_ = resp.Body.Close()
	return resp.StatusCode
}

// Every attempt is a row: a wrong password with the account in full, an
// unknown name masked and never as typed, the browser and address as
// sent; newest first, with total and since.
func TestSignInsRouteListsRecordedAttempts(t *testing.T) {
	g, ts, admin, h := signInsFixture(t, nil)
	before, _ := h.Summary()
	if attempt(t, ts, "203.0.113.20", totpBobUsername, "wrong-password-placeholder") != http.StatusUnauthorized {
		t.Fatal("wrong password not refused")
	}
	if attempt(t, ts, "203.0.113.21", "Hunter2024!", "anything") != http.StatusUnauthorized {
		t.Fatal("unknown name not refused")
	}

	status, out, raw := getSignIns(t, admin, ts, "")
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, raw)
	}
	if strings.Contains(raw, "Hunter") {
		t.Errorf("the typed name reached the response: %s", raw)
	}
	if out.Total != before+2 || len(out.SignIns) != out.Total || out.More || out.Since.IsZero() {
		t.Fatalf("list = %+v", out)
	}
	unknown, wrong := out.SignIns[0], out.SignIns[1]
	if unknown.Outcome != gauntlet.SignInNoSuchUser || unknown.Username != "Hu•••••••••" || unknown.UserID != "" || unknown.Address != "203.0.113.21" {
		t.Errorf("unknown-name row = %+v", unknown)
	}
	if wrong.Outcome != gauntlet.SignInWrongPassword || wrong.Username != totpBobUsername || wrong.UserID != totpBobID(t, g) ||
		wrong.Method != gauntlet.SignInMethodPassword || wrong.Address != "203.0.113.20" || wrong.UserAgent != "Firefox/131.0" || wrong.Count != 1 {
		t.Errorf("wrong-password row = %+v", wrong)
	}
	if !strings.Contains(raw, `"signIns":[`) || strings.Contains(raw, `"lockedUntil"`) || strings.Contains(raw, `"disabled"`) {
		t.Errorf("absent fields should be left out: %s", raw)
	}
}

// Filters by account, address and outcome, and pages by before.
func TestSignInsRouteFiltersAndPages(t *testing.T) {
	g, ts, admin, _ := signInsFixture(t, nil)
	for i := range 3 {
		attempt(t, ts, fmt.Sprintf("203.0.113.%d", 30+i), totpBobUsername, "wrong-password-placeholder")
		attempt(t, ts, fmt.Sprintf("203.0.113.%d", 40+i), "nobody-here", "x")
	}
	bobID := totpBobID(t, g)

	_, out, _ := getSignIns(t, admin, ts, "?user="+bobID)
	if len(out.SignIns) != 3 {
		t.Fatalf("user filter: %+v", out.SignIns)
	}
	_, out, _ = getSignIns(t, admin, ts, "?address=203.0.113.41")
	if len(out.SignIns) != 1 || out.SignIns[0].Outcome != gauntlet.SignInNoSuchUser {
		t.Errorf("address filter: %+v", out.SignIns)
	}
	_, out, _ = getSignIns(t, admin, ts, "?outcome=no_such_user&limit=2")
	if len(out.SignIns) != 2 || !out.More {
		t.Fatalf("outcome filter, limit 2: %+v", out)
	}
	_, next, _ := getSignIns(t, admin, ts, fmt.Sprintf("?outcome=no_such_user&limit=2&before=%d", out.SignIns[1].Seq))
	if len(next.SignIns) != 1 || next.More || next.SignIns[0].Seq >= out.SignIns[1].Seq {
		t.Errorf("second page: %+v", next)
	}
}

// Every refusal: anonymous 401, a non-admin 403, a bearer token never
// reaches it, and each bad query 400.
func TestSignInsRouteRefusals(t *testing.T) {
	g, ts, admin, _ := signInsFixture(t, nil)
	if status, _, _ := getSignIns(t, &http.Client{}, ts, ""); status != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", status)
	}
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	if status, _, _ := getSignIns(t, bob, ts, ""); status != http.StatusForbidden {
		t.Errorf("non-admin: %d", status)
	}

	raw, _, err := g.deps.Tokens.Create("integration", gauntlet.TokenKindAPI, "", nil, nowUTC())
	if err != nil {
		t.Fatal(err)
	}
	g.Handle(gauntlet.TokenKindAPI, kindEchoHandler("/api/readonly"))
	resp := bearerRequest(t, ts.URL, "/api/auth/sign-ins", raw)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "signIns") {
		t.Errorf("a bearer token read the history: %s", body)
	}

	for _, q := range []string{
		"?outcome=bogus", "?before=x", "?before=0", "?before=-1", "?limit=0", "?limit=201", "?limit=x",
		"?address=" + strings.Repeat("a", gauntlet.MaxSessionAddress+1),
	} {
		if status, _, raw := getSignIns(t, admin, ts, q); status != http.StatusBadRequest {
			t.Errorf("%s: %d %s", q, status, raw)
		}
	}
	for _, q := range []string{"?limit=1", "?limit=200", "?before=1", "?outcome=unrecorded", "?address=" + strings.Repeat("a", gauntlet.MaxSessionAddress)} {
		if status, _, raw := getSignIns(t, admin, ts, q); status != http.StatusOK {
			t.Errorf("%s: %d %s", q, status, raw)
		}
	}
}

// With no history configured the route answers 404, and sign-ins are
// still audited.
func TestSignInsRouteOffWhenNoHistory(t *testing.T) {
	g, ts, admin := totpFixture(t)
	audit := &auditRecorder{}
	g.cfg.Audit = audit
	if status, _, _ := getSignIns(t, admin, ts, ""); status != http.StatusNotFound {
		t.Errorf("no history: %d, want 404", status)
	}
	attempt(t, ts, "203.0.113.50", totpBobUsername, "wrong-password-placeholder")
	if n := len(auditEntries(audit, "user.login_failed")); n != 1 {
		t.Errorf("%d user.login_failed records with no history, want 1", n)
	}
}

// A row per outcome from the gate's own sign-in paths: the password
// step that passes with a factor owed, the factor that completes it, a
// refused code, and a limiter refusal.
func TestSignInsRecordEveryStep(t *testing.T) {
	g, ts, _, h := signInsFixture(t, nil)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	_, codes, _ := totpEnrolAndConfirm(t, bob, ts)
	start, _ := h.Summary()

	browser := newBrowser(t, "Safari/18.0", "192.0.2.60")
	_ = postJSON(t, browser, ts.URL+"/api/auth/login", credentialsRequest{Username: totpBobUsername, Password: totpBobPassword}).Body.Close()
	_ = submitLoginFactor(t, browser, ts, "000000").Body.Close()
	_ = submitLoginFactor(t, browser, ts, codes[0]).Body.Close()
	for range 6 {
		attempt(t, ts, "192.0.2.61", "nobody-at-all", "x")
	}

	rows, _ := h.List(gauntlet.SignInQuery{Limit: 50})
	var got []string
	for _, r := range rows[:len(rows)-start] {
		got = append(got, fmt.Sprintf("%s/%s/%d", r.Outcome, r.Method, r.Count))
	}
	want := "rate_limited/password/1 no_such_user/password/5 success/code/1 factor_refused/code/1 password_ok/password/1"
	if strings.Join(got, " ") != want {
		t.Errorf("rows = %v\nwant %s", got, want)
	}
	_ = g
}

// The stored document never holds the name as typed.
func TestSignInsStoredDocumentNeverHoldsTheTypedName(t *testing.T) {
	m := persist.NewMemory()
	_, ts, _, h := signInsFixture(t, m)
	attempt(t, ts, "203.0.113.70", "Correct-Horse-Battery-Staple", "anything")
	if err := h.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	snap, err := m.Load(context.Background())
	if err != nil || !snap.Exists {
		t.Fatalf("nothing stored: %v", err)
	}
	if strings.Contains(string(snap.Payload), "Horse") || !strings.Contains(string(snap.Payload), "Co••") {
		t.Errorf("stored document: %s", snap.Payload)
	}
}

// heldSaveBackend holds every Save until release is closed.
type heldSaveBackend struct {
	*persist.Memory
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (b *heldSaveBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return b.Memory.Save(ctx, payload, expect)
}

// A history save in flight -- however slow -- does not hold up a
// sign-in: the save works outside the history's lock.
func TestSignInsSlowSaveDoesNotBlockSignIn(t *testing.T) {
	b := &heldSaveBackend{Memory: persist.NewMemory(), entered: make(chan struct{}), release: make(chan struct{})}
	_, ts, _, _ := signInsFixture(t, b)
	defer close(b.release)
	attempt(t, ts, "203.0.113.80", totpBobUsername, "wrong-password-placeholder")
	select {
	case <-b.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("no save started")
	}
	done := make(chan int, 2)
	go func() {
		for _, password := range []string{totpBobPassword, "wrong-password-placeholder"} {
			done <- rawLoginStatus(ts.URL, totpBobUsername, password)
		}
	}()
	for _, want := range []int{http.StatusOK, http.StatusUnauthorized} {
		select {
		case got := <-done:
			if got != want {
				t.Errorf("sign-in during a held save: %d, want %d", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a sign-in waited behind the history's save")
		}
	}
}

// rawLoginStatus is one password step, for a goroutine that cannot call
// t.Fatal: 0 when the request itself failed.
func rawLoginStatus(base, username, password string) int {
	body, _ := json.Marshal(credentialsRequest{Username: username, Password: password})
	req, err := http.NewRequest(http.MethodPost, base+"/api/auth/login", strings.NewReader(string(body)))
	if err != nil {
		return 0
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrfHeaderName, testCSRFValue)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}
