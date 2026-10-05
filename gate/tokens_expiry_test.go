package gate

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// Token expiry, the gnt_ prefix and the sweep (#74).

// createTokenAs posts a token request as the admin and returns the
// status and decoded response.
func createTokenAs(t *testing.T, admin *http.Client, url string, req createTokenRequest) (int, tokenResponse) {
	t.Helper()
	req.Password = testAdminPassword
	resp := postJSON(t, admin, url+"/api/tokens", req)
	defer func() { _ = resp.Body.Close() }()
	var out tokenResponse
	if resp.StatusCode == http.StatusCreated {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode, out
}

func strp(s string) *string { return &s }

func TestCreateTokenDefaultsToAYearAndCarriesThePrefix(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", testAdminPassword)

	before := time.Now()
	status, created := createTokenAs(t, admin, ts.URL, createTokenRequest{Name: "default"})
	if status != http.StatusCreated {
		t.Fatalf("status = %d", status)
	}
	if !strings.HasPrefix(created.Value, gauntlet.TokenPrefix) {
		t.Errorf("value %q does not start with %q", created.Value, gauntlet.TokenPrefix)
	}
	want := before.Add(gauntlet.DefaultTokenLifetime)
	if d := created.ExpiresAt.Sub(want); d < 0 || d > time.Minute {
		t.Errorf("expiresAt = %v, want about %v", created.ExpiresAt, want)
	}

	listResp, err := admin.Get(ts.URL + "/api/tokens")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listResp.Body.Close() }()
	var list struct {
		Tokens []tokenResponse `json:"tokens"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list.Tokens) != 1 || !list.Tokens[0].ExpiresAt.Equal(created.ExpiresAt) {
		t.Errorf("list = %+v, want the created token's expiresAt", list.Tokens)
	}
}

func TestCreateTokenNeverIsExplicitAndOmittedFromJSON(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", testAdminPassword)

	resp := postJSON(t, admin, ts.URL+"/api/tokens", createTokenRequest{
		Name: "router", Kind: "ingest", Device: "r1", ExpiresAt: strp("never"), Password: testAdminPassword})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if _, present := body["expiresAt"]; present {
		t.Errorf("a never-expiring token's response carries expiresAt: %v", body)
	}
	if toks := g.deps.Tokens.List(); len(toks) != 1 || !toks[0].ExpiresAt.IsZero() {
		t.Errorf("stored token = %+v, want no expiry", toks)
	}
}

func TestCreateTokenWithAnExplicitDate(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", testAdminPassword)

	at := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	status, created := createTokenAs(t, admin, ts.URL, createTokenRequest{Name: "month", ExpiresAt: strp(at.Format(time.RFC3339))})
	if status != http.StatusCreated {
		t.Fatalf("status = %d", status)
	}
	if !created.ExpiresAt.Equal(at) {
		t.Errorf("expiresAt = %v, want %v", created.ExpiresAt, at)
	}
}

func TestCreateTokenRefusesAPastOrUnreadableExpiry(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", testAdminPassword)

	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	for name, v := range map[string]string{
		"past":      past,
		"garbage":   "next tuesday",
		"empty":     "",
		"uppercase": "NEVER",
		"date only": "2099-01-01",
	} {
		status, _ := createTokenAs(t, admin, ts.URL, createTokenRequest{Name: "x", ExpiresAt: strp(v)})
		if status != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, status)
		}
	}
	if len(g.deps.Tokens.List()) != 0 {
		t.Error("a refused token was created anyway")
	}

	// A number is not a string: the body does not decode.
	resp := postJSON(t, admin, ts.URL+"/api/tokens", map[string]any{"name": "x", "expiresAt": 12345, "password": testAdminPassword})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("numeric expiresAt: status = %d, want 400", resp.StatusCode)
	}
}

// sweepFixture is a gate with an admin account, a recorder for notices
// and one for audit, and a helper to mint tokens as that admin.
type sweepFixture struct {
	g     *Gate
	notes *noticeRecorder
	audit *auditRecorder
	admin *gauntlet.User
	raw   map[string]string // token id -> raw value
}

func newSweepFixture(t *testing.T) *sweepFixture {
	t.Helper()
	g := newTestGate(t)
	ts := newTestServer(t, g)
	registerAdmin(t, ts, "admin", testAdminPassword)
	admin, ok := g.deps.Users.ByUsername("admin")
	if !ok {
		t.Fatal("no admin account")
	}
	f := &sweepFixture{g: g, notes: &noticeRecorder{}, audit: &auditRecorder{}, admin: admin, raw: map[string]string{}}
	g.cfg.Notices = f.notes
	g.cfg.Audit = f.audit
	return f
}

func (f *sweepFixture) mint(t *testing.T, name string, creator *gauntlet.User, now, expiresAt time.Time) string {
	t.Helper()
	raw, tok, err := f.g.deps.Tokens.CreateWithExpiry(name, gauntlet.TokenKindAPI, "", creator, now, expiresAt)
	if err != nil {
		t.Fatalf("CreateWithExpiry: %v", err)
	}
	f.raw[tok.ID] = raw
	return tok.ID
}

// use authenticates the token at at, which is what records its last use.
func (f *sweepFixture) use(t *testing.T, id string, at time.Time) {
	t.Helper()
	if _, ok := f.g.deps.Tokens.Authenticate(f.raw[id], gauntlet.TokenKindAPI, at); !ok {
		t.Fatalf("token %s did not authenticate at %v", id, at)
	}
}

func (f *sweepFixture) has(id string) bool {
	for _, t := range f.g.deps.Tokens.List() {
		if t.ID == id {
			return true
		}
	}
	return false
}

func TestSweepTokensRemovesTheUnusedAndAuditsIt(t *testing.T) {
	f := newSweepFixture(t)
	now := time.Now()
	year := gauntlet.TokenUnusedLimit

	stale := f.mint(t, "stale", f.admin, now.Add(-year-48*time.Hour), time.Time{}) // never used, created over a year ago
	fresh := f.mint(t, "fresh", f.admin, now.Add(-year+48*time.Hour), time.Time{}) // never used, created under a year ago

	// "used" was created long ago but used last week; it must stay.
	used := f.mint(t, "used", f.admin, now.Add(-2*year), time.Time{})
	f.use(t, used, now.Add(-7*24*time.Hour))
	// "lapsed" was used, but over a year ago.
	lapsed := f.mint(t, "lapsed", f.admin, now.Add(-3*year), time.Time{})
	f.use(t, lapsed, now.Add(-year-24*time.Hour))

	res, err := f.g.SweepTokens(context.Background(), now)
	if err != nil {
		t.Fatalf("SweepTokens: %v", err)
	}
	if res.Removed != 2 || res.Warned != 0 {
		t.Errorf("result = %+v, want 2 removed, 0 warned", res)
	}
	for id, want := range map[string]bool{stale: false, lapsed: false, fresh: true, used: true} {
		if f.has(id) != want {
			t.Errorf("token %s present = %v, want %v", id, !want, want)
		}
	}
	var audited []auditEntry
	for _, e := range f.audit.entries {
		if e.Action == "token.removed_unused" {
			audited = append(audited, e)
		}
	}
	if len(audited) != 2 || audited[0].Actor != "system" {
		t.Errorf("audit entries = %+v, want two token.removed_unused by system", audited)
	}
}

func TestSweepTokensWarnsOnceWithinAWeek(t *testing.T) {
	f := newSweepFixture(t)
	now := time.Now()

	soon := f.mint(t, "soon", f.admin, now.Add(-24*time.Hour), now.Add(5*24*time.Hour))
	f.mint(t, "later", f.admin, now.Add(-24*time.Hour), now.Add(30*24*time.Hour))
	f.mint(t, "never", f.admin, now.Add(-24*time.Hour), time.Time{})
	f.mint(t, "orphan", nil, now.Add(-24*time.Hour), now.Add(2*24*time.Hour)) // no owner account

	res, err := f.g.SweepTokens(context.Background(), now)
	if err != nil {
		t.Fatalf("SweepTokens: %v", err)
	}
	if res.Removed != 0 || res.Warned != 2 {
		t.Errorf("first sweep = %+v, want 0 removed, 2 warned (soon and the orphan)", res)
	}
	f.g.notifying.Wait()
	got := f.notes.all()
	if len(got) != 1 {
		t.Fatalf("notices = %+v, want exactly one (the orphan has nobody to tell)", got)
	}
	n := got[0]
	if n.Kind != NoticeTokenExpiring || n.UserID != f.admin.ID || n.Username != "admin" || n.Role != gauntlet.RoleAdmin ||
		n.TokenExpiring == nil || n.TokenExpiring.TokenID != soon || n.TokenExpiring.Name != "soon" ||
		n.TokenExpiring.Kind != gauntlet.TokenKindAPI || n.TokenExpiring.ExpiresAt.IsZero() {
		t.Errorf("notice = %+v", n)
	}

	// A second sweep, a day later, warns about nothing new.
	res, err = f.g.SweepTokens(context.Background(), now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("second SweepTokens: %v", err)
	}
	f.g.notifying.Wait()
	if res != (TokenSweep{}) || len(f.notes.all()) != 1 {
		t.Errorf("second sweep = %+v with %d notices, want nothing new", res, len(f.notes.all()))
	}
}

func TestSweepTokensIgnoresAnAlreadyExpiredToken(t *testing.T) {
	f := newSweepFixture(t)
	now := time.Now()
	id := f.mint(t, "gone", f.admin, now.Add(-48*time.Hour), now.Add(time.Hour))

	res, err := f.g.SweepTokens(context.Background(), now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if res != (TokenSweep{}) {
		t.Errorf("result = %+v, want nothing: it expired before the sweep saw it", res)
	}
	if !f.has(id) {
		t.Error("an expired but recently created token was removed")
	}
}

func TestSweepTokensStopsOnACancelledContext(t *testing.T) {
	f := newSweepFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.g.SweepTokens(ctx, time.Now()); err == nil {
		t.Error("a cancelled context swept anyway")
	}
}
