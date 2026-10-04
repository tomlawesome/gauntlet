package gate

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/oidc"
	"github.com/tomlawesome/gauntlet/persist"
)

// Unusual sign-ins (#55) through the public routes, with Config.Country
// and Config.Locate stubbed and the clock moved by hand.

// testPlace is what the stubbed lookups answer for one address.
type testPlace struct {
	country string
	loc     *gauntlet.Location
}

// The addresses the fixture's lookups know. Every other address is
// "not known" to both, as a private address is.
const (
	addrLondon    = "203.0.113.10"
	addrLondon2   = "203.0.113.11"
	addrEdinburgh = "203.0.113.12" // GB, about 530 km from London
	addrParis     = "203.0.113.20" // FR, about 340 km from London
	addrNewYork   = "203.0.113.30" // US
	addrCountry   = "203.0.113.40" // GB by country, no location
	addrPrivate   = "10.0.0.5"     // nothing known
)

var testPlaces = map[string]testPlace{
	addrLondon:    {"GB", &gauntlet.Location{Latitude: 51.5074, Longitude: -0.1278, RadiusKm: 20}},
	addrLondon2:   {"GB", &gauntlet.Location{Latitude: 51.52, Longitude: -0.10, RadiusKm: 20}},
	addrEdinburgh: {"GB", &gauntlet.Location{Latitude: 55.9533, Longitude: -3.1883, RadiusKm: 10}},
	addrParis:     {"FR", &gauntlet.Location{Latitude: 48.8566, Longitude: 2.3522, RadiusKm: 20}},
	addrNewYork:   {"US", &gauntlet.Location{Latitude: 40.7128, Longitude: -74.006, RadiusKm: 20}},
	addrCountry:   {"GB", nil},
}

func stubCountry(address string) (string, bool) {
	p, ok := testPlaces[address]
	return p.country, ok && p.country != ""
}

func stubLocate(address string) (gauntlet.Location, bool) {
	p, ok := testPlaces[address]
	if !ok || p.loc == nil {
		return gauntlet.Location{}, false
	}
	return *p.loc, true
}

// unusualEnv is a gate with an admin and "bob" (no second factor, so he
// signs in in one step), a sign-in history, an audit recorder, a log
// recorder, the stubbed lookups and a hand-moved clock.
type unusualEnv struct {
	g       *Gate
	ts      *httptest.Server
	admin   *http.Client
	clock   *escalationClock
	audit   *auditRecorder
	logs    *lockedBuffer
	history *gauntlet.SignInHistory
	bobID   string
}

func newUnusualEnv(t *testing.T, policy UnusualSignInPolicy) *unusualEnv {
	t.Helper()
	return newUnusualEnvWith(t, persist.NewMemory(), func(c *Config) { c.UnusualSignIns = policy })
}

func newUnusualEnvWith(t *testing.T, backend persist.Backend, configure func(*Config)) *unusualEnv {
	t.Helper()
	g := newTestGateWithUsers(t, openTrackedStore(t, backend))
	e := &unusualEnv{g: g, audit: &auditRecorder{}, logs: &lockedBuffer{}}
	g.cfg.ClientIP = func(r *http.Request) string {
		if ip := r.Header.Get(sessionsTestIPHeader); ip != "" {
			return ip
		}
		return addrPrivate
	}
	g.cfg.Audit = e.audit
	g.cfg.Country = stubCountry
	g.cfg.Locate = stubLocate
	g.cfg.Log = slog.New(slog.NewTextHandler(e.logs, nil))
	h, err := gauntlet.OpenSignInHistory(nil, gauntlet.SignInHistoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	g.deps.SignIns = h
	e.history = h
	if configure != nil {
		configure(&g.cfg)
	}
	// Re-check what New checks, on the configured policy.
	if err := checkUnusualPolicy(g.cfg); err != nil {
		t.Fatalf("the fixture's policy: %v", err)
	}
	e.ts = newTestServer(t, g)
	e.admin = registerAdmin(t, e.ts, "admin", "password-placeholder-1")
	resp := postJSON(t, e.admin, e.ts.URL+"/api/auth/users", createUserRequest{Username: totpBobUsername, Password: totpBobPassword, Role: "user"})
	if status, body := readAll(t, resp); status != http.StatusCreated {
		t.Fatalf("creating bob = %d %s", status, body)
	}
	e.bobID = totpBobID(t, g)
	e.clock = &escalationClock{t: time.Now()}
	g.cfg.Now = e.clock.now
	return e
}

func (e *unusualEnv) advance(d time.Duration) { e.clock.set(e.clock.now().Add(d)) }

func (e *unusualEnv) logText() string { return e.logs.String() }

// browser is one browser: a cookie jar that keeps its cookies whichever
// address a request leaves from.
type browser struct{ jar http.CookieJar }

func newTestBrowser(t *testing.T) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &browser{jar: jar}
}

// at is a client for this browser sending from address.
func (b *browser) at(address string) *http.Client {
	return &http.Client{Jar: b.jar, Transport: browserTransport{agent: "Firefox/131.0 (test)", address: address},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// signIn sends bob's password from b at address and returns the status
// and body.
func (e *unusualEnv) signIn(t *testing.T, b *browser, address string) (int, string) {
	t.Helper()
	return readAll(t, postJSON(t, b.at(address), e.ts.URL+"/api/auth/login",
		credentialsRequest{Username: totpBobUsername, Password: totpBobPassword}))
}

// mustSignIn is signIn requiring a 200.
func (e *unusualEnv) mustSignIn(t *testing.T, b *browser, address string) {
	t.Helper()
	if status, body := e.signIn(t, b, address); status != http.StatusOK {
		t.Fatalf("bob's sign-in from %s = %d %s", address, status, body)
	}
}

// newestSession is the signals on bob's newest session.
func (e *unusualEnv) newestSession(t *testing.T) gauntlet.Session {
	t.Helper()
	sessions := e.g.deps.Sessions.ListForUser(e.bobID, e.clock.now())
	if len(sessions) == 0 {
		t.Fatal("bob holds no session")
	}
	newest := sessions[0]
	for _, s := range sessions {
		if s.IssuedAt.After(newest.IssuedAt) {
			newest = s
		}
	}
	return newest
}

// newestRow is the newest history row.
func (e *unusualEnv) newestRow(t *testing.T) gauntlet.SignInRow {
	t.Helper()
	rows, _ := e.history.List(gauntlet.SignInQuery{Limit: 1})
	if len(rows) == 0 {
		t.Fatal("the history is empty")
	}
	return rows[0]
}

// lastAudit is the newest audit entry for action, or the zero entry.
func (e *unusualEnv) lastAudit(action string) (auditEntry, bool) {
	e.audit.mu.Lock()
	defer e.audit.mu.Unlock()
	for i := len(e.audit.entries) - 1; i >= 0; i-- {
		if e.audit.entries[i].Action == action {
			return e.audit.entries[i], true
		}
	}
	return auditEntry{}, false
}

// expectSignals checks bob's newest session, the newest history row
// and the newest user.login record all carry want.
func (e *unusualEnv) expectSignals(t *testing.T, want gauntlet.SignInSignals) {
	t.Helper()
	if got := e.newestSession(t).Client.Unusual; got != want {
		t.Errorf("session signals = %q, want %q", got, want)
	}
	row := e.newestRow(t)
	if row.Outcome != gauntlet.SignInSuccess || row.Client.Unusual != want {
		t.Errorf("history row = %s %q, want success %q", row.Outcome, row.Client.Unusual, want)
	}
	entry, ok := e.lastAudit("user.login")
	if !ok {
		t.Fatal("no user.login record")
	}
	if want == 0 {
		if strings.Contains(entry.Detail, "unusual=") || strings.Contains(entry.Detail, "action=") {
			t.Errorf("an ordinary sign-in's audit detail = %q", entry.Detail)
		}
		return
	}
	if !strings.HasPrefix(entry.Detail, "unusual="+want.String()+"; action=flag; ") {
		t.Errorf("audit detail = %q, want it to start unusual=%s; action=flag;", entry.Detail, want)
	}
}

func TestUnusualFirstSignInRaisesNothing(t *testing.T) {
	e := newUnusualEnv(t, UnusualSignInPolicy{})
	e.mustSignIn(t, newTestBrowser(t), addrLondon)
	e.expectSignals(t, 0)
}

func TestUnusualNewCountryWithTheCookie(t *testing.T) {
	e := newUnusualEnv(t, UnusualSignInPolicy{})
	b := newTestBrowser(t)
	e.mustSignIn(t, b, addrLondon)
	e.advance(time.Hour)
	e.mustSignIn(t, b, addrCountry) // GB again, no location: quiet
	e.expectSignals(t, 0)
	e.advance(time.Hour)
	status, body := e.signIn(t, b, addrParis)
	if status != http.StatusOK {
		t.Fatalf("= %d %s", status, body)
	}
	if strings.Contains(body, "unusual") || strings.Contains(body, "new-country") {
		t.Errorf("the login response says why: %s", body)
	}
	e.expectSignals(t, gauntlet.SignalNewCountry)
	// Remembered now: the next sign-in from Paris is quiet.
	e.advance(time.Hour)
	e.mustSignIn(t, b, addrParis)
	e.expectSignals(t, 0)
}

func TestUnusualNewBrowser(t *testing.T) {
	e := newUnusualEnv(t, UnusualSignInPolicy{})
	e.mustSignIn(t, newTestBrowser(t), addrLondon)
	e.advance(time.Hour)
	e.mustSignIn(t, newTestBrowser(t), addrLondon2)
	e.expectSignals(t, gauntlet.SignalNewBrowser)
	e.advance(time.Hour)
	e.mustSignIn(t, newTestBrowser(t), addrParis)
	e.expectSignals(t, gauntlet.SignalNewBrowser|gauntlet.SignalNewCountry)
	if entry, _ := e.lastAudit("user.login"); !strings.HasPrefix(entry.Detail, "unusual=new-browser,new-country; action=flag; ") {
		t.Errorf("audit detail = %q, want the signals in their fixed order", entry.Detail)
	}
}

func TestUnusualImpossibleTravel(t *testing.T) {
	e := newUnusualEnv(t, UnusualSignInPolicy{})
	b := newTestBrowser(t)
	e.mustSignIn(t, b, addrLondon)
	e.advance(10 * time.Minute)
	e.mustSignIn(t, b, addrEdinburgh)
	e.expectSignals(t, gauntlet.SignalImpossibleTravel)
	// Edinburgh is now the last place; London four hours later is fine.
	e.advance(4 * time.Hour)
	e.mustSignIn(t, b, addrLondon)
	e.expectSignals(t, 0)
}

func TestUnusualNeedsTheLookups(t *testing.T) {
	t.Run("no Country", func(t *testing.T) {
		e := newUnusualEnvWith(t, persist.NewMemory(), func(c *Config) { c.Country = nil })
		b := newTestBrowser(t)
		e.mustSignIn(t, b, addrLondon)
		e.advance(10 * time.Hour)
		e.mustSignIn(t, b, addrParis)
		e.expectSignals(t, 0)
	})
	t.Run("no Locate", func(t *testing.T) {
		e := newUnusualEnvWith(t, persist.NewMemory(), func(c *Config) { c.Locate = nil })
		b := newTestBrowser(t)
		e.mustSignIn(t, b, addrLondon)
		e.advance(10 * time.Minute)
		e.mustSignIn(t, b, addrEdinburgh)
		e.expectSignals(t, 0)
	})
	t.Run("Locate not ok", func(t *testing.T) {
		e := newUnusualEnv(t, UnusualSignInPolicy{})
		b := newTestBrowser(t)
		e.mustSignIn(t, b, addrLondon)
		e.advance(time.Minute)
		e.mustSignIn(t, b, addrPrivate)
		e.expectSignals(t, 0)
		e.advance(time.Minute)
		e.mustSignIn(t, b, addrCountry)
		e.expectSignals(t, 0)
	})
}

// The second-factor step judges, by code; the password step that owes
// it does not.
func TestUnusualCodePathJudges(t *testing.T) {
	e := newUnusualEnv(t, UnusualSignInPolicy{})
	first := newTestBrowser(t)
	e.mustSignIn(t, first, addrLondon)
	_, codes, _ := totpEnrolAndConfirm(t, first.at(addrLondon), e.ts)
	e.advance(time.Hour)
	b := newTestBrowser(t)
	e.mustSignIn(t, b, addrParis) // password step only
	if row := e.newestRow(t); row.Outcome != gauntlet.SignInPasswordOK || row.Client.Unusual != 0 {
		t.Errorf("the password step's row = %s %q, want password_ok with nothing raised", row.Outcome, row.Client.Unusual)
	}
	status, body := readAll(t, submitLoginFactor(t, b.at(addrParis), e.ts, codes[0]))
	if status != http.StatusOK {
		t.Fatalf("code step = %d %s", status, body)
	}
	if strings.Contains(body, "unusual") {
		t.Errorf("the factor response says why: %s", body)
	}
	e.expectSignals(t, gauntlet.SignalNewBrowser|gauntlet.SignalNewCountry)
	if entry, _ := e.lastAudit("user.login"); !strings.HasSuffix(entry.Detail, `via second factor; from="`+addrParis+`"`) {
		t.Errorf("audit detail = %q, want the existing detail after the signals", entry.Detail)
	}
}

// The sessions route shows the signals on the session they arrived
// with, and only there.
func TestUnusualSessionRow(t *testing.T) {
	e := newUnusualEnv(t, UnusualSignInPolicy{})
	first := newTestBrowser(t)
	e.mustSignIn(t, first, addrLondon)
	_, codes, _ := totpEnrolAndConfirm(t, first.at(addrLondon), e.ts)
	e.advance(time.Hour)
	b := newTestBrowser(t)
	e.mustSignIn(t, b, addrParis)
	if status, body := readAll(t, submitLoginFactor(t, b.at(addrParis), e.ts, codes[0])); status != http.StatusOK {
		t.Fatalf("code step = %d %s", status, body)
	}
	resp, err := b.at(addrParis).Get(e.ts.URL + "/api/auth/sessions")
	if err != nil {
		t.Fatal(err)
	}
	status, body := readAll(t, resp)
	if status != http.StatusOK {
		t.Fatalf("sessions = %d %s", status, body)
	}
	var list struct {
		Sessions []map[string]any `json:"sessions"`
	}
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatal(err)
	}
	var flagged, plain int
	for _, s := range list.Sessions {
		switch u := s["unusual"].(type) {
		case nil:
			plain++
		case []any:
			if len(u) != 2 || u[0] != "new-browser" || u[1] != "new-country" {
				t.Errorf("unusual = %v", u)
			}
			flagged++
		}
	}
	if flagged != 1 || plain != 1 {
		t.Errorf("sessions = %s, want one flagged and one without the field", body)
	}
}

// Sessions issued by anything but a sign-in never judge, but still
// remember; after sign out everywhere the caller's next sign-in from
// the same place is quiet.
func TestUnusualOnlySignInsJudge(t *testing.T) {
	e := newUnusualEnv(t, UnusualSignInPolicy{})
	b := newTestBrowser(t)
	e.mustSignIn(t, b, addrLondon)
	totpEnrolAndConfirm(t, b.at(addrLondon), e.ts)
	e.advance(time.Hour)
	// A password change from Paris: a session, no judgement.
	resp := postJSON(t, b.at(addrParis), e.ts.URL+"/api/auth/password",
		changePasswordRequest{CurrentPassword: totpBobPassword, NewPassword: totpBobPassword + "-2"})
	if status, body := readAll(t, resp); status != http.StatusOK {
		t.Fatalf("password change = %d %s", status, body)
	}
	if got := e.newestSession(t).Client.Unusual; got != 0 {
		t.Errorf("a password change's session carries %q", got)
	}
	e.advance(time.Hour)
	// Sign out everywhere from New York: forgets, then remembers New York.
	if status, body := readAll(t, postJSON(t, b.at(addrNewYork), e.ts.URL+"/api/auth/logout-all", nil)); status != http.StatusOK {
		t.Fatalf("logout-all = %d %s", status, body)
	}
	if got := e.newestSession(t).Client.Unusual; got != 0 {
		t.Errorf("sign out everywhere's session carries %q", got)
	}
	u, _ := e.g.deps.Users.Get(e.bobID)
	if len(u.SeenCountries) != 1 || u.SeenCountries[0].Code != "US" || u.LastPlace == nil || u.LastPlace.Country != "US" {
		t.Errorf("after sign out everywhere bob remembers %+v and %+v, want New York only", u.SeenCountries, u.LastPlace)
	}
	e.audit.mu.Lock()
	defer e.audit.mu.Unlock()
	for _, entry := range e.audit.entries {
		if strings.Contains(entry.Detail, "unusual=") {
			t.Errorf("a non-sign-in session issue was judged: %+v", entry)
		}
	}
}

func TestUnusualPolicyChecks(t *testing.T) {
	for _, c := range []struct {
		name   string
		policy UnusualSignInPolicy
		locate bool
		want   string
	}{
		{"unknown action", UnusualSignInPolicy{Action: "warn"}, true, "Action"},
		{"unknown per-signal action", UnusualSignInPolicy{NewCountry: "Flag"}, true, "NewCountry"},
		{"confirm with no notifier", UnusualSignInPolicy{NewBrowser: UnusualSignInConfirm}, true, "NotifyUnusualSignIn"},
		{"confirm as the base with no notifier", UnusualSignInPolicy{Action: UnusualSignInConfirm}, true, "NotifyUnusualSignIn"},
		{"impossible travel with no Locate", UnusualSignInPolicy{ImpossibleTravel: UnusualSignInFlag}, false, "Locate"},
		{"ok: impossible travel off with no Locate", UnusualSignInPolicy{ImpossibleTravel: UnusualSignInOff}, false, ""},
		{"ok: nothing set, no Locate", UnusualSignInPolicy{}, false, ""},
		{"ok: off", UnusualSignInPolicy{Action: UnusualSignInOff, NewCountry: UnusualSignInFlag}, true, ""},
		{"ok: block", UnusualSignInPolicy{Action: UnusualSignInBlock, ImpossibleTravel: UnusualSignInBlock}, true, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := Config{
				CookieName: testCookieName, CSRFHeaderValue: testCSRFValue, ProductName: testProductName,
				ClientIP: func(*http.Request) string { return "" }, UnusualSignIns: c.policy,
			}
			if c.locate {
				cfg.Locate = stubLocate
			}
			users := openTrackedStore(t, persist.NewMemory())
			tokens, _ := gauntlet.OpenTokenStore(persist.NewMemory(), gauntlet.TokenOptions{})
			_, err := New(cfg, Deps{Users: users, Tokens: tokens,
				Sessions: gauntlet.NewSessionStore(gauntlet.MaxSessionIdle, gauntlet.MaxSessionLifetime),
				Limiter:  mustNewLoginLimiter(t, 5, 5*time.Minute)})
			if c.want == "" {
				if err != nil {
					t.Fatalf("New = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("New = %v, want an error naming %s", err, c.want)
			}
		})
	}
}

// resolveUnusual: each raised signal takes its own field, else Action,
// else flag; off drops it; the strictest kept action wins.
func TestResolveUnusual(t *testing.T) {
	const (
		nb = gauntlet.SignalNewBrowser
		nc = gauntlet.SignalNewCountry
		it = gauntlet.SignalImpossibleTravel
	)
	for _, c := range []struct {
		name    string
		policy  UnusualSignInPolicy
		signals gauntlet.SignInSignals
		action  UnusualSignInAction
		kept    gauntlet.SignInSignals
	}{
		{"nothing raised", UnusualSignInPolicy{}, 0, "", 0},
		{"default is flag", UnusualSignInPolicy{}, nb | nc, UnusualSignInFlag, nb | nc},
		{"Action off", UnusualSignInPolicy{Action: UnusualSignInOff}, nb | nc | it, "", 0},
		{"per-signal beats Action", UnusualSignInPolicy{Action: UnusualSignInOff, NewCountry: UnusualSignInFlag}, nb | nc, UnusualSignInFlag, nc},
		{"per-signal off drops", UnusualSignInPolicy{NewBrowser: UnusualSignInOff}, nb, "", 0},
		{"strictest wins", UnusualSignInPolicy{NewBrowser: UnusualSignInFlag, NewCountry: UnusualSignInBlock, ImpossibleTravel: UnusualSignInConfirm}, nb | nc | it, UnusualSignInBlock, nb | nc | it},
		{"confirm over flag", UnusualSignInPolicy{Action: UnusualSignInConfirm, NewBrowser: UnusualSignInFlag}, nb | it, UnusualSignInConfirm, nb | it},
		{"block not raised", UnusualSignInPolicy{NewCountry: UnusualSignInBlock}, nb, UnusualSignInFlag, nb},
	} {
		g := &Gate{cfg: Config{UnusualSignIns: c.policy}}
		action, kept := g.resolveUnusual(c.signals)
		if action != c.action || kept != c.kept {
			t.Errorf("%s: = %q %q, want %q %q", c.name, action, kept, c.action, c.kept)
		}
	}
}

// A signal resolving to off is dropped; a sign-in with only dropped
// signals is ordinary, and its country is still remembered, so turning
// the signal on afterwards raises nothing for it.
func TestUnusualOffStillRemembers(t *testing.T) {
	e := newUnusualEnv(t, UnusualSignInPolicy{NewCountry: UnusualSignInOff})
	b := newTestBrowser(t)
	e.mustSignIn(t, b, addrLondon)
	e.advance(time.Hour)
	e.mustSignIn(t, b, addrParis)
	e.expectSignals(t, 0)
	e.g.cfg.UnusualSignIns = UnusualSignInPolicy{}
	e.advance(time.Hour)
	e.mustSignIn(t, b, addrParis)
	e.expectSignals(t, 0)
	e.g.cfg.UnusualSignIns = UnusualSignInPolicy{Action: UnusualSignInOff}
	e.advance(time.Hour)
	e.mustSignIn(t, newTestBrowser(t), addrNewYork)
	e.expectSignals(t, 0)
	if u, _ := e.g.deps.Users.Get(e.bobID); len(u.SeenCountries) != 3 {
		t.Errorf("under off bob remembers %+v, want GB, FR and US", u.SeenCountries)
	}
}

// A sign-in whose memory write fails still succeeds, flags nothing and
// logs one line.
func TestUnusualFailedRememberFlagsNothing(t *testing.T) {
	backend := &budgetBackend{inner: persist.NewMemory(), left: -1}
	e := newUnusualEnvWith(t, backend, nil)
	b := newTestBrowser(t)
	e.mustSignIn(t, b, addrLondon)
	e.advance(time.Hour)
	before := strings.Count(e.logText(), "level=ERROR")
	backend.left = 0
	e.mustSignIn(t, newTestBrowser(t), addrParis)
	backend.left = -1
	e.expectSignals(t, 0)
	if got := strings.Count(e.logText(), "level=ERROR") - before; got != 1 {
		t.Errorf("%d error lines, want 1:\n%s", got, e.logText())
	}
}

// adminNow is a client holding a fresh admin session at the fixture's
// clock, which has usually moved past the idle limit of the one
// registerAdmin made.
func (e *unusualEnv) adminNow(t *testing.T) *http.Client {
	t.Helper()
	u, _ := e.g.deps.Users.ByUsername("admin")
	client := &http.Client{Jar: mustCookieJar(t)}
	sess := e.g.deps.Sessions.Create(u.ID, e.clock.now())
	client.Jar.SetCookies(mustParseURL(t, e.ts.URL), []*http.Cookie{{Name: e.g.sessionCookieName(), Value: sess.ID, Path: "/"}})
	return client
}

// The admin's history shows the signals, and ?unusual=true lists only
// the rows that raised one; anything but true is refused.
func TestUnusualSignInsRoute(t *testing.T) {
	e := newUnusualEnv(t, UnusualSignInPolicy{})
	b := newTestBrowser(t)
	e.mustSignIn(t, b, addrLondon)
	e.advance(time.Hour)
	e.mustSignIn(t, b, addrParis)
	e.admin = e.adminNow(t)
	status, out, raw := getSignIns(t, e.admin, e.ts, "?unusual=true")
	if status != http.StatusOK {
		t.Fatalf("= %d %s", status, raw)
	}
	if len(out.SignIns) != 1 || out.SignIns[0].Unusual != gauntlet.SignalNewCountry || out.SignIns[0].Address != addrParis {
		t.Errorf("unusual rows = %s", raw)
	}
	if !strings.Contains(raw, `"unusual":["new-country"]`) {
		t.Errorf("the row does not carry unusual as an array of names: %s", raw)
	}
	_, all, rawAll := getSignIns(t, e.admin, e.ts, "")
	if strings.Count(rawAll, `"unusual"`) != 1 || len(all.SignIns) != 2 {
		t.Errorf("all rows = %s", rawAll)
	}
	if status, _, _ := getSignIns(t, e.admin, e.ts, "?unusual=maybe"); status != http.StatusBadRequest {
		t.Errorf("unusual=maybe = %d, want 400", status)
	}
	if status, _, _ := getSignIns(t, e.admin, e.ts, "?outcome=confirm_sent"); status != http.StatusOK {
		t.Errorf("outcome=confirm_sent = %d, want 200", status)
	}
	if status, _, _ := getSignIns(t, b.at(addrParis), e.ts, "?unusual=true"); status != http.StatusForbidden {
		t.Errorf("a non-admin = %d, want 403", status)
	}
}

// The passkey branch of the second-factor step judges too.
func TestUnusualPasskeyPathJudges(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	country := "GB"
	g.cfg.Country = func(string) (string, bool) { return country, true }
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	fake, _ := registerPasskey(t, bilbo, ts, g, "YubiKey")
	country = "FR"
	pending := startPasskeyLogin(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	status, body := readAll(t, submitPasskeyAssertion(t, pending, ts, fake, passkeyLoginFactorBegin(t, pending, ts)))
	if status != http.StatusOK {
		t.Fatalf("passkey step = %d %s", status, body)
	}
	if strings.Contains(body, "unusual") {
		t.Errorf("the factor response says why: %s", body)
	}
	entry := findAuditEntry(t, g, "user.login")
	if !strings.HasPrefix(entry.Detail, "unusual=new-browser,new-country; action=flag; via second factor; ") {
		t.Errorf("user.login detail = %q", entry.Detail)
	}
}

// The SSO callback's sign-in branch judges.
func TestUnusualSSOPathJudges(t *testing.T) {
	g, ts, fp := newOIDCTestGate(t, oidc.Policy{})
	g.cfg.Audit = &auditRecorder{}
	signIn := func(jar http.CookieJar) {
		t.Helper()
		fs, err := oidc.NewFlowState(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))
		client := noRedirectClient()
		client.Jar = jar
		resp, err := client.Do(oidcCallbackRequest(t, g, ts, fs, "state="+fs.State+"&code=test-code"))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
			t.Fatalf("callback = %d to %q", resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	signIn(mustCookieJar(t))
	if entry := findAuditEntry(t, g, "user.login"); strings.Contains(entry.Detail, "unusual=") {
		t.Errorf("the first SSO sign-in was flagged: %q", entry.Detail)
	}
	signIn(mustCookieJar(t))
	if entry := findAuditEntry(t, g, "user.login"); !strings.HasPrefix(entry.Detail, "unusual=new-browser; action=flag; via sso; ") {
		t.Errorf("a second browser's SSO sign-in: %q", entry.Detail)
	}
}

// noticeRecorder is a Config.NotifyUnusualSignIn that keeps every notice
// and does what fail says.
type noticeRecorder struct {
	mu      sync.Mutex
	notices []UnusualSignInNotice
	fail    func(ctx context.Context) error
}

func (n *noticeRecorder) UnusualSignIn(ctx context.Context, notice UnusualSignInNotice) error {
	n.mu.Lock()
	n.notices = append(n.notices, notice)
	fail := n.fail
	n.mu.Unlock()
	if fail != nil {
		return fail(ctx)
	}
	return nil
}

func (n *noticeRecorder) all() []UnusualSignInNotice {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]UnusualSignInNotice(nil), n.notices...)
}

// newNotifiedEnv is newUnusualEnv with a notice recorder.
func newNotifiedEnv(t *testing.T, policy UnusualSignInPolicy) (*unusualEnv, *noticeRecorder) {
	t.Helper()
	rec := &noticeRecorder{}
	e := newUnusualEnvWith(t, persist.NewMemory(), func(c *Config) {
		c.UnusualSignIns = policy
		c.NotifyUnusualSignIn = rec
	})
	return e, rec
}

// notices waits for the background notices and returns them.
func (e *unusualEnv) notices(rec *noticeRecorder) []UnusualSignInNotice {
	e.g.notifying.Wait()
	return rec.all()
}

func TestUnusualFlagNotice(t *testing.T) {
	e, rec := newNotifiedEnv(t, UnusualSignInPolicy{})
	b := newTestBrowser(t)
	e.mustSignIn(t, b, addrLondon)
	if got := e.notices(rec); len(got) != 0 {
		t.Fatalf("the first sign-in told the application: %+v", got)
	}
	if entry, _ := e.lastAudit("user.login"); strings.Contains(entry.Detail, "notify=") {
		t.Errorf("an ordinary sign-in's detail = %q", entry.Detail)
	}
	e.advance(time.Hour)
	e.mustSignIn(t, b, addrParis)
	got := e.notices(rec)
	if len(got) != 1 {
		t.Fatalf("%d notices, want 1", len(got))
	}
	n := got[0]
	sess := e.newestSession(t)
	if n.UserID != e.bobID || n.Username != totpBobUsername || n.Role != gauntlet.RoleUser || n.Action != UnusualSignInFlag ||
		n.Signals != gauntlet.SignalNewCountry || n.Method != gauntlet.SignInMethodPassword ||
		n.Client.Address != addrParis || n.Client.Country != "FR" || n.Client.UserAgent == "" ||
		!n.At.Equal(e.clock.now()) || n.SessionRef != sess.Ref() || n.Code != "" || !n.ExpiresAt.IsZero() || n.Reason != "" {
		t.Errorf("notice = %+v (session ref %s)", n, sess.Ref())
	}
	if entry, _ := e.lastAudit("user.login"); !strings.HasPrefix(entry.Detail, "unusual=new-country; action=flag; notify=asked; from=") {
		t.Errorf("detail = %q", entry.Detail)
	}
}

// At most one flag notice per account per hour; the held one is
// notify=quiet in the audit.
func TestUnusualNoticesAreHourly(t *testing.T) {
	e, rec := newNotifiedEnv(t, UnusualSignInPolicy{})
	e.mustSignIn(t, newTestBrowser(t), addrLondon)
	e.advance(time.Minute)
	e.mustSignIn(t, newTestBrowser(t), addrLondon)
	e.advance(time.Minute)
	e.mustSignIn(t, newTestBrowser(t), addrLondon)
	if got := e.notices(rec); len(got) != 1 {
		t.Fatalf("%d notices in an hour, want 1", len(got))
	}
	if entry, _ := e.lastAudit("user.login"); !strings.HasPrefix(entry.Detail, "unusual=new-browser; action=flag; notify=quiet; ") {
		t.Errorf("the held notice's detail = %q", entry.Detail)
	}
	e.advance(time.Hour)
	e.mustSignIn(t, newTestBrowser(t), addrLondon)
	if got := e.notices(rec); len(got) != 2 {
		t.Errorf("%d notices after the hour, want 2", len(got))
	}
}

// A notifier that errors, panics or outlasts notifyTimeout changes
// nothing about the sign-in, and leaves one log line.
func TestUnusualNoticeFailuresAreLogged(t *testing.T) {
	was := notifyTimeout
	notifyTimeout = time.Millisecond
	t.Cleanup(func() { notifyTimeout = was })
	for name, fail := range map[string]func(context.Context) error{
		"error":   func(context.Context) error { return errors.New("mailer down") },
		"panic":   func(context.Context) error { panic("mailer exploded") },
		"timeout": func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() },
	} {
		t.Run(name, func(t *testing.T) {
			e, rec := newNotifiedEnv(t, UnusualSignInPolicy{})
			rec.fail = fail
			e.mustSignIn(t, newTestBrowser(t), addrLondon)
			e.advance(time.Hour)
			before := strings.Count(e.logText(), "level=ERROR")
			e.mustSignIn(t, newTestBrowser(t), addrLondon)
			if len(e.notices(rec)) != 1 {
				t.Fatal("the notifier was not asked")
			}
			e.expectSignals(t, gauntlet.SignalNewBrowser)
			if got := strings.Count(e.logText(), "level=ERROR") - before; got != 1 {
				t.Errorf("%d error lines, want 1:\n%s", got, e.logText())
			}
		})
	}
}

// With no notifier the signals are still shown, and the detail has no
// notify=; under Action off nobody is told anything.
func TestUnusualWithoutANotifierOrUnderOff(t *testing.T) {
	e := newUnusualEnv(t, UnusualSignInPolicy{})
	e.mustSignIn(t, newTestBrowser(t), addrLondon)
	e.advance(time.Hour)
	e.mustSignIn(t, newTestBrowser(t), addrLondon)
	e.expectSignals(t, gauntlet.SignalNewBrowser)
	if entry, _ := e.lastAudit("user.login"); strings.Contains(entry.Detail, "notify=") {
		t.Errorf("detail = %q", entry.Detail)
	}

	off, rec := newNotifiedEnv(t, UnusualSignInPolicy{Action: UnusualSignInOff})
	off.mustSignIn(t, newTestBrowser(t), addrLondon)
	off.advance(time.Hour)
	off.mustSignIn(t, newTestBrowser(t), addrParis)
	if got := off.notices(rec); len(got) != 0 {
		t.Errorf("under off the notifier was asked: %+v", got)
	}
}

// A sign-in whose memory write fails tells nobody.
func TestUnusualFailedRememberTellsNobody(t *testing.T) {
	backend := &budgetBackend{inner: persist.NewMemory(), left: -1}
	rec := &noticeRecorder{}
	e := newUnusualEnvWith(t, backend, func(c *Config) { c.NotifyUnusualSignIn = rec })
	e.mustSignIn(t, newTestBrowser(t), addrLondon)
	e.advance(time.Hour)
	backend.left = 0
	e.mustSignIn(t, newTestBrowser(t), addrParis)
	backend.left = -1
	if got := e.notices(rec); len(got) != 0 {
		t.Errorf("a sign-in whose memory write failed told the application: %+v", got)
	}
}

// wantRefusedDetail is the sign-in-refused class's one detail, as the
// design words it.
const wantRefusedDetail = "this sign-in was refused by the account's sign-in policy -- use a browser or place this account has signed in from before, or ask an administrator to reset the account"

// cookieNamed is the cookie resp sets under name, or nil.
func cookieNamed(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// checkRefused checks resp is the sign-in-refused 403 with no session or
// known-browser cookie and no X-Auth-Gate.
func checkRefused(t *testing.T, g *Gate, resp *http.Response) {
	t.Helper()
	status, body := readAll(t, resp)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d %s, want 403", status, body)
	}
	p := decodeProblem(t, []byte(body))
	if p.Type != problemTypeBase+"sign-in-refused" || p.Title != "Sign-in refused" || p.Detail != wantRefusedDetail {
		t.Errorf("problem = %+v", p)
	}
	if strings.Contains(body, "new-") || strings.Contains(body, "impossible") {
		t.Errorf("the refusal says which signal: %s", body)
	}
	if resp.Header.Get(authGateHeader) != "" {
		t.Errorf("X-Auth-Gate = %q on a refusal", resp.Header.Get(authGateHeader))
	}
	if c := cookieNamed(resp, g.sessionCookieName()); c != nil && c.MaxAge >= 0 {
		t.Errorf("a session cookie was set: %+v", c)
	}
	if c := cookieNamed(resp, knownBrowserCookieName); c != nil {
		t.Errorf("a known-browser cookie was set: %+v", c)
	}
}

func TestUnusualBlockOneStep(t *testing.T) {
	e, rec := newNotifiedEnv(t, UnusualSignInPolicy{NewCountry: UnusualSignInBlock})
	b := newTestBrowser(t)
	e.mustSignIn(t, b, addrLondon)
	// A lockout, so there is a count of lockouts a sign-in would reset.
	for range 5 {
		_ = postJSON(t, newTestBrowser(t).at(addrPrivate), e.ts.URL+"/api/auth/login",
			credentialsRequest{Username: totpBobUsername, Password: "wrong-password-placeholder"}).Body.Close()
	}
	e.advance(time.Hour)
	u, _ := e.g.deps.Users.Get(e.bobID)
	if u.LoginLockoutCount == 0 {
		t.Fatal("precondition: no lockout counted")
	}
	before, _ := e.g.deps.Users.Get(e.bobID)
	sessionsBefore := len(e.g.deps.Sessions.ListForUser(e.bobID, e.clock.now()))

	// Six refusals in a row from one address: each attempt is handed
	// back, so none is ever 429.
	for i := range 6 {
		resp := postJSON(t, b.at(addrParis), e.ts.URL+"/api/auth/login",
			credentialsRequest{Username: totpBobUsername, Password: totpBobPassword})
		if i == 0 {
			checkRefused(t, e.g, resp)
		} else if status, body := readAll(t, resp); status != http.StatusForbidden {
			t.Fatalf("refusal %d = %d %s", i+1, status, body)
		}
	}
	if n := len(e.g.deps.Sessions.ListForUser(e.bobID, e.clock.now())); n != sessionsBefore {
		t.Errorf("a refusal issued a session: %d, was %d", n, sessionsBefore)
	}
	after, _ := e.g.deps.Users.Get(e.bobID)
	if after.LoginLockoutCount != before.LoginLockoutCount {
		t.Errorf("lockout count %d after refusals, was %d: a refusal reset it", after.LoginLockoutCount, before.LoginLockoutCount)
	}
	if len(after.SeenCountries) != 1 || after.SeenCountries[0].Code != "GB" || len(after.KnownBrowsers) != 1 {
		t.Errorf("a refusal was remembered: %+v %+v", after.SeenCountries, after.KnownBrowsers)
	}
	row := e.newestRow(t)
	if row.Outcome != gauntlet.SignInRefused || row.Client.Unusual != gauntlet.SignalNewCountry || row.Method != gauntlet.SignInMethodPassword {
		t.Errorf("history row = %+v", row)
	}
	entry, ok := e.lastAudit("user.login_refused")
	if !ok || entry.Actor != totpBobUsername || entry.Target != totpBobUsername ||
		entry.Detail != `unusual=new-country; reason=policy; method=password; notify=quiet; from="`+addrParis+`"` {
		t.Errorf("user.login_refused = %+v", entry)
	}
	got := e.notices(rec)
	if len(got) != 1 || got[0].Action != UnusualSignInBlock || got[0].Reason != "policy" || got[0].SessionRef != "" ||
		got[0].Signals != gauntlet.SignalNewCountry || got[0].Client.Country != "FR" {
		t.Errorf("notices = %+v, want one block notice (the hourly rate holds the rest)", got)
	}

	// The real owner, from a place the account trusts, gets in.
	e.mustSignIn(t, b, addrLondon)
	if u, _ := e.g.deps.Users.Get(e.bobID); u.LoginLockoutCount != 0 {
		t.Errorf("a completed sign-in left the lockout count at %d", u.LoginLockoutCount)
	}

	// After an admin's reset code, the refused place sets the baseline.
	admin := e.adminNow(t)
	resp := postJSON(t, admin, e.ts.URL+"/api/auth/users/"+e.bobID+"/reset-password", nil)
	status, body := readAll(t, resp)
	if status != http.StatusOK {
		t.Fatalf("reset = %d %s", status, body)
	}
	var reset resetPasswordResponse
	if err := json.Unmarshal([]byte(body), &reset); err != nil {
		t.Fatal(err)
	}
	status, body = readAll(t, postJSON(t, newTestBrowser(t).at(addrParis), e.ts.URL+"/api/auth/login",
		credentialsRequest{Username: totpBobUsername, Password: reset.Code}))
	if status != http.StatusOK {
		t.Fatalf("sign-in with the reset code from Paris = %d %s", status, body)
	}
	e.expectSignals(t, 0)
}

// The pending cookie is cleared, and the pending login is spent: one
// correct code yields one refusal, never a refusal and a session.
func TestUnusualBlockFactorStep(t *testing.T) {
	e, _ := newNotifiedEnv(t, UnusualSignInPolicy{NewBrowser: UnusualSignInBlock})
	first := newTestBrowser(t)
	e.mustSignIn(t, first, addrLondon)
	_, codes, _ := totpEnrolAndConfirm(t, first.at(addrLondon), e.ts)
	e.advance(time.Hour)
	b := newTestBrowser(t)
	e.mustSignIn(t, b, addrLondon) // password step
	resp := submitLoginFactor(t, b.at(addrLondon), e.ts, codes[0])
	if c := cookieNamed(resp, pendingLoginCookieName); c == nil || c.MaxAge >= 0 {
		t.Errorf("the pending cookie was not cleared: %+v", c)
	}
	checkRefused(t, e.g, resp)
	if row := e.newestRow(t); row.Outcome != gauntlet.SignInRefused || row.Method != gauntlet.SignInMethodCode || row.Client.Unusual != gauntlet.SignalNewBrowser {
		t.Errorf("row = %+v", row)
	}
	// Replaying the pending cookie the browser had is step-expired.
	replay := newTestBrowser(t)
	e.mustSignIn(t, replay, addrLondon)
	u, _ := url.Parse(e.ts.URL + loginFactorPath)
	pending := replay.jar.Cookies(u)
	resp = submitLoginFactor(t, replay.at(addrLondon), e.ts, codes[1])
	checkRefused(t, e.g, resp)
	replay.jar.SetCookies(u, pending)
	status, body := readAll(t, submitLoginFactor(t, replay.at(addrLondon), e.ts, codes[2]))
	if status != http.StatusUnauthorized || decodeProblem(t, []byte(body)).Type != problemTypeBase+"step-expired" {
		t.Errorf("a replayed pending login after a refusal = %d %s, want step-expired", status, body)
	}
}

func TestUnusualBlockSSO(t *testing.T) {
	g, ts, fp := newOIDCTestGate(t, oidc.Policy{})
	g.cfg.Audit = &auditRecorder{}
	g.cfg.UnusualSignIns = UnusualSignInPolicy{NewBrowser: UnusualSignInBlock}
	callback := func() *http.Response {
		t.Helper()
		fs, err := oidc.NewFlowState(time.Now())
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
	if resp := callback(); resp.Header.Get("Location") != "/" {
		t.Fatalf("the first SSO sign-in went to %q", resp.Header.Get("Location"))
	}
	resp := callback()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != testLoginPath+"?ssoError=refused" {
		t.Errorf("a refused SSO sign-in = %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if c := cookieNamed(resp, testCookieName); c != nil && c.MaxAge >= 0 {
		t.Errorf("a refused SSO sign-in set a session cookie")
	}
	if entry := findAuditEntry(t, g, "user.login_refused"); !strings.HasPrefix(entry.Detail, "unusual=new-browser; reason=policy; method=sso; from=") {
		t.Errorf("user.login_refused = %q", entry.Detail)
	}
}

// block and flag share one hourly rate per account.
func TestUnusualBlockSharesTheRate(t *testing.T) {
	e, rec := newNotifiedEnv(t, UnusualSignInPolicy{NewCountry: UnusualSignInBlock})
	b := newTestBrowser(t)
	e.mustSignIn(t, b, addrLondon)
	e.advance(time.Hour)
	e.mustSignIn(t, newTestBrowser(t), addrLondon) // new-browser: flag, notice sent
	status, _ := e.signIn(t, b, addrParis)         // new-country: block, held
	if status != http.StatusForbidden {
		t.Fatalf("= %d", status)
	}
	if got := e.notices(rec); len(got) != 1 || got[0].Action != UnusualSignInFlag {
		t.Errorf("notices = %+v, want the flag one only", got)
	}
	if entry, _ := e.lastAudit("user.login_refused"); !strings.Contains(entry.Detail, "notify=quiet") {
		t.Errorf("the held block notice = %q", entry.Detail)
	}
}

// confirmEnv is newNotifiedEnv under a policy that confirms a new
// country, with bob signed in once from London in browser b.
func confirmEnv(t *testing.T) (*unusualEnv, *noticeRecorder, *browser) {
	t.Helper()
	e, rec := newNotifiedEnv(t, UnusualSignInPolicy{NewCountry: UnusualSignInConfirm})
	b := newTestBrowser(t)
	e.mustSignIn(t, b, addrLondon)
	e.advance(time.Hour)
	return e, rec, b
}

// confirmCode is the code in the newest confirm notice.
func confirmCode(t *testing.T, rec *noticeRecorder) string {
	t.Helper()
	all := rec.all()
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].Action == UnusualSignInConfirm {
			return all[i].Code
		}
	}
	t.Fatal("no confirm notice")
	return ""
}

// postConfirm posts code to login/confirm from b at address.
func (e *unusualEnv) postConfirm(t *testing.T, b *browser, address, code string) (*http.Response, int, string) {
	t.Helper()
	resp := postJSON(t, b.at(address), e.ts.URL+loginConfirmPath, loginConfirmRequest{Code: code})
	status, body := readAll(t, resp)
	return resp, status, body
}

func problemType(t *testing.T, body string) string {
	t.Helper()
	return strings.TrimPrefix(decodeProblem(t, []byte(body)).Type, problemTypeBase)
}

func TestUnusualConfirmSendsACode(t *testing.T) {
	e, rec, b := confirmEnv(t)
	sessionsBefore := len(e.g.deps.Sessions.ListForUser(e.bobID, e.clock.now()))
	auditBefore := len(e.audit.entries)
	resp := postJSON(t, b.at(addrParis), e.ts.URL+"/api/auth/login", credentialsRequest{Username: totpBobUsername, Password: totpBobPassword})
	status, body := readAll(t, resp)
	if status != http.StatusOK || strings.TrimSpace(body) != `{"confirm":true}` {
		t.Fatalf("= %d %s, want 200 {\"confirm\":true}", status, body)
	}
	c := cookieNamed(resp, confirmLoginCookieName)
	if c == nil || c.MaxAge != 900 || c.Path != "/api/auth/login" || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("confirm cookie = %+v", c)
	}
	if cookieNamed(resp, e.g.sessionCookieName()) != nil || cookieNamed(resp, knownBrowserCookieName) != nil {
		t.Error("a session or known-browser cookie was set before the code")
	}
	if n := len(e.g.deps.Sessions.ListForUser(e.bobID, e.clock.now())); n != sessionsBefore {
		t.Error("a session was issued before the code")
	}
	if row := e.newestRow(t); row.Outcome != gauntlet.SignInConfirmSent || row.Client.Unusual != gauntlet.SignalNewCountry {
		t.Errorf("row = %+v", row)
	}
	if len(e.audit.entries) != auditBefore {
		t.Errorf("confirm_sent wrote audit records: %+v", e.audit.entries[auditBefore:])
	}
	if u, _ := e.g.deps.Users.Get(e.bobID); len(u.SeenCountries) != 1 {
		t.Errorf("the country was remembered before the code: %+v", u.SeenCountries)
	}
	got := e.notices(rec)
	if len(got) != 1 {
		t.Fatalf("notices = %+v", got)
	}
	n := got[0]
	if n.Action != UnusualSignInConfirm || n.Signals != gauntlet.SignalNewCountry || n.SessionRef != "" || n.Reason != "" ||
		!n.ExpiresAt.Equal(e.clock.now().Add(ConfirmCodeLifetime)) || len(n.Code) != 9 || n.Code[4] != '-' {
		t.Errorf("notice = %+v", n)
	}
	for i, r := range n.Code {
		if i != 4 && (r < '0' || r > '9') {
			t.Errorf("code %q is not eight digits", n.Code)
		}
	}
	if strings.Contains(e.logText(), n.Code) || strings.Contains(e.logText(), strings.ReplaceAll(n.Code, "-", "")) {
		t.Error("the code reached the log")
	}
}

// The code completes the same sign-in, in any of its spellings, once.
func TestUnusualConfirmCompletes(t *testing.T) {
	for name, spell := range map[string]func(string) string{
		"dashed":   func(c string) string { return c },
		"undashed": func(c string) string { return strings.ReplaceAll(c, "-", "") },
		"padded":   func(c string) string { return "  " + c + "\t" },
	} {
		t.Run(name, func(t *testing.T) {
			e, rec, b := confirmEnv(t)
			if status, _ := e.signIn(t, b, addrParis); status != http.StatusOK {
				t.Fatal("no challenge")
			}
			code := confirmCode(t, rec)
			u, _ := url.Parse(e.ts.URL + loginConfirmPath)
			ticket := b.jar.Cookies(u)
			resp, status, body := e.postConfirm(t, b, addrParis, spell(code))
			if status != http.StatusOK || !strings.Contains(body, `"username":"bob"`) {
				t.Fatalf("confirm = %d %s", status, body)
			}
			if c := cookieNamed(resp, confirmLoginCookieName); c == nil || c.MaxAge >= 0 {
				t.Error("the confirm cookie was not cleared")
			}
			if got := e.newestSession(t).Client.Unusual; got != gauntlet.SignalNewCountry {
				t.Errorf("session signals = %q", got)
			}
			row := e.newestRow(t)
			if row.Outcome != gauntlet.SignInSuccess || !row.Confirmed || row.Client.Unusual != gauntlet.SignalNewCountry || row.Method != gauntlet.SignInMethodPassword {
				t.Errorf("row = %+v", row)
			}
			if entry, _ := e.lastAudit("user.login"); entry.Detail != `unusual=new-country; action=confirm; via confirmation code; from="`+addrParis+`"` {
				t.Errorf("audit = %q", entry.Detail)
			}
			// Remembered: the next sign-in from Paris is quiet.
			e.advance(time.Minute)
			e.mustSignIn(t, b, addrParis)
			e.expectSignals(t, 0)
			// The same code again, with the old ticket put back.
			b.jar.SetCookies(u, ticket)
			if _, status, body := e.postConfirm(t, b, addrParis, code); status != http.StatusUnauthorized || problemType(t, body) != "step-expired" {
				t.Errorf("the same code again = %d %s", status, body)
			}
		})
	}
}

// A browser the account does not know (so with no known-browser
// allowance to fall back on) guessing at the code.
func TestUnusualConfirmWrongCodes(t *testing.T) {
	e, rec := newNotifiedEnv(t, UnusualSignInPolicy{NewBrowser: UnusualSignInConfirm})
	e.mustSignIn(t, newTestBrowser(t), addrLondon)
	e.advance(time.Hour)
	b := newTestBrowser(t)
	if status, _ := e.signIn(t, b, addrParis); status != http.StatusOK {
		t.Fatal("no challenge")
	}
	code := strings.ReplaceAll(confirmCode(t, rec), "-", "")
	wrong := "00000000"
	if wrong == code {
		wrong = "11111111"
	}
	for i := range 5 {
		_, status, body := e.postConfirm(t, b, addrParis, wrong)
		if status != http.StatusUnauthorized || problemType(t, body) != "invalid-credentials" || decodeProblem(t, []byte(body)).Detail != "invalid confirmation code" {
			t.Fatalf("wrong code %d = %d %s", i+1, status, body)
		}
		if i == 0 {
			row := e.newestRow(t)
			if row.Outcome != gauntlet.SignInConfirmRefused || row.Method != gauntlet.SignInMethodCode {
				t.Errorf("row = %+v", row)
			}
			if entry, _ := e.lastAudit("user.login_failed"); entry.Detail != `outcome=confirm_refused method=code from="`+addrParis+`"` {
				t.Errorf("audit = %q", entry.Detail)
			}
		}
	}
	if u, _ := e.g.deps.Users.Get(e.bobID); !u.MustChangePassword {
		t.Error("five wrong codes in a row did not force a password change")
	}
	if _, status, _ := e.postConfirm(t, b, addrParis, code); status != http.StatusTooManyRequests {
		t.Errorf("the sixth attempt = %d, want 429", status)
	}
}

func TestUnusualConfirmTicketChecks(t *testing.T) {
	e, rec, b := confirmEnv(t)
	if status, _ := e.signIn(t, b, addrParis); status != http.StatusOK {
		t.Fatal("no challenge")
	}
	code := confirmCode(t, rec)
	// Another browser holds no ticket.
	if _, status, body := e.postConfirm(t, newTestBrowser(t), addrParis, code); status != http.StatusUnauthorized || problemType(t, body) != "step-expired" {
		t.Errorf("from another browser = %d %s", status, body)
	}
	// login/factor with only the confirm cookie.
	status, body := readAll(t, submitLoginFactor(t, b.at(addrParis), e.ts, "123456"))
	if status != http.StatusUnauthorized || problemType(t, body) != "step-expired" {
		t.Errorf("login/factor with a confirm cookie = %d %s", status, body)
	}
	// Malformed body.
	resp := postJSON(t, b.at(addrParis), e.ts.URL+loginConfirmPath, map[string]any{"code": 5})
	if status, _ := readAll(t, resp); status != http.StatusBadRequest {
		t.Errorf("a bad body = %d", status)
	}
	// At fifteen minutes the ticket is dead.
	e.advance(ConfirmCodeLifetime)
	resp, status, body = e.postConfirm(t, b, addrParis, code)
	if status != http.StatusUnauthorized || problemType(t, body) != "step-expired" {
		t.Errorf("at 15 minutes = %d %s", status, body)
	}
	if c := cookieNamed(resp, confirmLoginCookieName); c == nil || c.MaxAge >= 0 {
		t.Error("an expired ticket's cookie was not cleared")
	}
}

// The notice is sent before the response: the response waits on it.
func TestUnusualConfirmNoticeIsSynchronous(t *testing.T) {
	e, rec, b := confirmEnv(t)
	entered, release := make(chan struct{}), make(chan struct{})
	rec.fail = func(context.Context) error {
		close(entered)
		<-release
		return nil
	}
	done := make(chan int, 1)
	go func() {
		resp, err := b.at(addrParis).Do(mustLoginRequest(t, e.ts.URL))
		if err != nil {
			done <- 0
			return
		}
		_ = resp.Body.Close()
		done <- resp.StatusCode
	}()
	<-entered
	select {
	case <-done:
		t.Fatal("the response came back before the notifier returned")
	default:
	}
	close(release)
	if status := <-done; status != http.StatusOK {
		t.Errorf("= %d", status)
	}
}

func mustLoginRequest(t *testing.T, base string) *http.Request {
	t.Helper()
	body, _ := json.Marshal(credentialsRequest{Username: totpBobUsername, Password: totpBobPassword})
	req, err := http.NewRequest(http.MethodPost, base+"/api/auth/login", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrfHeaderName, testCSRFValue)
	return req
}

// A notifier that cannot take the code makes the attempt a block.
func TestUnusualConfirmNotifyFailedBlocks(t *testing.T) {
	for name, fail := range map[string]func(context.Context) error{
		"error": func(context.Context) error { return errors.New("mailer down") },
		"panic": func(context.Context) error { panic("mailer exploded") },
	} {
		t.Run(name, func(t *testing.T) {
			e, rec, b := confirmEnv(t)
			rec.fail = fail
			resp := postJSON(t, b.at(addrParis), e.ts.URL+"/api/auth/login", credentialsRequest{Username: totpBobUsername, Password: totpBobPassword})
			if c := cookieNamed(resp, confirmLoginCookieName); c != nil {
				t.Error("a ticket was set though no code was delivered")
			}
			checkRefused(t, e.g, resp)
			if entry, _ := e.lastAudit("user.login_refused"); !strings.Contains(entry.Detail, "reason=notify-failed") {
				t.Errorf("audit = %q", entry.Detail)
			}
			if !strings.Contains(e.logText(), "level=ERROR") {
				t.Error("no error line")
			}
		})
	}
}

// The factor step and the SSO callback confirm too.
func TestUnusualConfirmFactorStep(t *testing.T) {
	e, rec := newNotifiedEnv(t, UnusualSignInPolicy{NewBrowser: UnusualSignInConfirm})
	first := newTestBrowser(t)
	e.mustSignIn(t, first, addrLondon)
	_, codes, _ := totpEnrolAndConfirm(t, first.at(addrLondon), e.ts)
	e.advance(time.Hour)
	b := newTestBrowser(t)
	e.mustSignIn(t, b, addrLondon)
	resp := submitLoginFactor(t, b.at(addrLondon), e.ts, codes[0])
	if c := cookieNamed(resp, pendingLoginCookieName); c == nil || c.MaxAge >= 0 {
		t.Error("the pending cookie was not cleared")
	}
	if status, body := readAll(t, resp); status != http.StatusOK || strings.TrimSpace(body) != `{"confirm":true}` {
		t.Fatalf("= %d %s", status, body)
	}
	if _, status, body := e.postConfirm(t, b, addrLondon, confirmCode(t, rec)); status != http.StatusOK {
		t.Fatalf("confirm = %d %s", status, body)
	}
	if row := e.newestRow(t); !row.Confirmed || row.Method != gauntlet.SignInMethodCode {
		t.Errorf("row = %+v", row)
	}
}

func TestUnusualConfirmSSO(t *testing.T) {
	g, ts, fp := newOIDCTestGate(t, oidc.Policy{})
	rec := &noticeRecorder{}
	g.cfg.NotifyUnusualSignIn = rec
	g.cfg.UnusualSignIns = UnusualSignInPolicy{NewBrowser: UnusualSignInConfirm}
	callback := func(jar http.CookieJar) *http.Response {
		t.Helper()
		fs, err := oidc.NewFlowState(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		fp.NextIDToken = fp.SignRS256(t, fp.DefaultClaims(oidcTestClientID, fs.Nonce))
		client := noRedirectClient()
		client.Jar = jar
		resp, err := client.Do(oidcCallbackRequest(t, g, ts, fs, "state="+fs.State+"&code=test-code"))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}
	callback(mustCookieJar(t))
	jar := mustCookieJar(t)
	resp := callback(jar)
	if resp.Header.Get("Location") != testLoginPath+"?confirm=1" {
		t.Fatalf("redirect = %q", resp.Header.Get("Location"))
	}
	if cookieNamed(resp, confirmLoginCookieName) == nil || cookieNamed(resp, testCookieName) != nil {
		t.Fatal("want the confirm cookie and no session cookie")
	}
	client := &http.Client{Jar: jar}
	status, body := readAll(t, postJSON(t, client, ts.URL+loginConfirmPath, loginConfirmRequest{Code: confirmCode(t, rec)}))
	if status != http.StatusOK {
		t.Fatalf("confirm = %d %s", status, body)
	}
	if !sessionAuthenticated(t, client, ts) {
		t.Error("no session after the code")
	}
}

// decideRecorder is a Decide that keeps every case and answers with
// answer.
type decideRecorder struct {
	mu     sync.Mutex
	cases  []UnusualSignInCase
	answer func(ctx context.Context, c UnusualSignInCase) (UnusualSignInAction, error)
}

func (d *decideRecorder) decide(ctx context.Context, c UnusualSignInCase) (UnusualSignInAction, error) {
	d.mu.Lock()
	d.cases = append(d.cases, c)
	answer := d.answer
	d.mu.Unlock()
	return answer(ctx, c)
}

func (d *decideRecorder) all() []UnusualSignInCase {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]UnusualSignInCase(nil), d.cases...)
}

func answering(a UnusualSignInAction) func(context.Context, UnusualSignInCase) (UnusualSignInAction, error) {
	return func(context.Context, UnusualSignInCase) (UnusualSignInAction, error) { return a, nil }
}

// decideEnv is newNotifiedEnv (or, withoutNotifier, newUnusualEnv)
// with a Decide over the given policy, bob signed in once from London
// in browser b.
func decideEnv(t *testing.T, policy UnusualSignInPolicy, withoutNotifier bool) (*unusualEnv, *noticeRecorder, *decideRecorder, *browser) {
	t.Helper()
	d := &decideRecorder{answer: answering(UnusualSignInFlag)}
	policy.Decide = d.decide
	var e *unusualEnv
	rec := &noticeRecorder{}
	if withoutNotifier {
		e = newUnusualEnv(t, policy)
	} else {
		e = newUnusualEnvWith(t, persist.NewMemory(), func(c *Config) {
			c.UnusualSignIns = policy
			c.NotifyUnusualSignIn = rec
		})
	}
	b := newTestBrowser(t)
	e.mustSignIn(t, b, addrLondon)
	e.advance(time.Hour)
	return e, rec, d, b
}

// Decide is asked once per unusual sign-in, with the settings' answer,
// and its answer replaces it.
func TestUnusualDecideBeatsTheSettings(t *testing.T) {
	e, rec, d, b := decideEnv(t, UnusualSignInPolicy{NewCountry: UnusualSignInBlock}, false)
	if got := d.all(); len(got) != 0 {
		t.Fatalf("Decide was asked about an ordinary sign-in: %+v", got)
	}
	// A wrong password is never judged.
	if status, _ := readAll(t, postJSON(t, b.at(addrParis), e.ts.URL+"/api/auth/login",
		credentialsRequest{Username: totpBobUsername, Password: "wrong-password-placeholder"})); status != http.StatusUnauthorized {
		t.Fatal("precondition")
	}
	if len(d.all()) != 0 {
		t.Error("Decide was asked about a wrong password")
	}
	e.mustSignIn(t, b, addrParis) // block by settings, flag by Decide
	got := d.all()
	if len(got) != 1 {
		t.Fatalf("Decide asked %d times, want 1", len(got))
	}
	c := got[0]
	if c.UserID != e.bobID || c.Username != totpBobUsername || c.Role != gauntlet.RoleUser || c.Signals != gauntlet.SignalNewCountry ||
		c.Country != "FR" || c.PreviousCountry != "" || c.Method != gauntlet.SignInMethodPassword ||
		c.Client.Address != addrParis || c.Client.Country != "FR" || c.Default != UnusualSignInBlock {
		t.Errorf("case = %+v", c)
	}
	e.expectSignals(t, gauntlet.SignalNewCountry)
	if len(e.notices(rec)) != 1 {
		t.Error("the flag Decide chose sent no notice")
	}
	// Decide can block what the settings would flag.
	d.answer = answering(UnusualSignInBlock)
	e.advance(time.Hour)
	status, _ := e.signIn(t, newTestBrowser(t), addrParis)
	if status != http.StatusForbidden {
		t.Errorf("Decide's block = %d", status)
	}
	if entry, _ := e.lastAudit("user.login_refused"); !strings.Contains(entry.Detail, "reason=policy") {
		t.Errorf("audit = %q", entry.Detail)
	}
}

// Impossible travel hands Decide the country the account last signed in
// from.
func TestUnusualDecidePreviousCountry(t *testing.T) {
	e, _, d, b := decideEnv(t, UnusualSignInPolicy{}, false)
	e.advance(-time.Hour + 10*time.Minute) // ten minutes after London
	e.mustSignIn(t, b, addrNewYork)
	got := d.all()
	if len(got) != 1 || got[0].Signals != gauntlet.SignalNewCountry|gauntlet.SignalImpossibleTravel || got[0].PreviousCountry != "GB" || got[0].Country != "US" {
		t.Errorf("cases = %+v", got)
	}
}

// Decide runs after the second factor, on the factor step.
func TestUnusualDecideAfterTheFactor(t *testing.T) {
	e, _, d, first := decideEnv(t, UnusualSignInPolicy{}, false)
	// Enrolled at the fixture's clock, which has moved an hour on.
	enrolled := totpEnrol(t, first.at(addrLondon), e.ts)
	secret, err := gauntlet.DecodeTOTPSecret(enrolled.Secret)
	if err != nil {
		t.Fatal(err)
	}
	resp := postJSON(t, first.at(addrLondon), e.ts.URL+"/api/auth/totp/confirm",
		totpConfirmRequest{Code: gauntlet.GenerateTOTPCode(secret, totpCounterNow(e.clock.now()))})
	status, body := readAll(t, resp)
	if status != http.StatusOK {
		t.Fatalf("confirm = %d %s", status, body)
	}
	var confirmed totpConfirmResponse
	if err := json.Unmarshal([]byte(body), &confirmed); err != nil {
		t.Fatal(err)
	}
	codes := confirmed.RecoveryCodes
	confirmEnrolmentOK(t, first.at(addrLondon), e.ts)
	e.advance(time.Hour)
	b := newTestBrowser(t)
	e.mustSignIn(t, b, addrLondon)
	if len(d.all()) != 0 {
		t.Fatal("Decide was asked at the password step")
	}
	_ = submitLoginFactor(t, b.at(addrLondon), e.ts, "000000").Body.Close()
	if len(d.all()) != 0 {
		t.Fatal("Decide was asked about a wrong code")
	}
	if status, _ := readAll(t, submitLoginFactor(t, b.at(addrLondon), e.ts, codes[0])); status != http.StatusOK {
		t.Fatal("factor step")
	}
	if got := d.all(); len(got) != 1 || got[0].Method != gauntlet.SignInMethodCode {
		t.Errorf("cases = %+v", got)
	}
}

// Every way Decide can fail refuses the attempt, with its reason.
func TestUnusualDecideFailsClosed(t *testing.T) {
	was := decideTimeout
	decideTimeout = 10 * time.Millisecond
	t.Cleanup(func() { decideTimeout = was })
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	for _, c := range []struct {
		name            string
		answer          func(context.Context, UnusualSignInCase) (UnusualSignInAction, error)
		withoutNotifier bool
		reason          string
	}{
		{"panic", func(context.Context, UnusualSignInCase) (UnusualSignInAction, error) { panic("decide exploded") }, false, "decide-failed"},
		{"error", func(context.Context, UnusualSignInCase) (UnusualSignInAction, error) {
			return UnusualSignInFlag, errors.New("lookup down")
		}, false, "decide-failed"},
		{"ignores ctx past the deadline", func(context.Context, UnusualSignInCase) (UnusualSignInAction, error) {
			<-release
			return UnusualSignInFlag, nil
		}, false, "decide-timeout"},
		{"off", answering(UnusualSignInOff), false, "decide-invalid"},
		{"empty", answering(""), false, "decide-invalid"},
		{"unknown", answering("allow"), false, "decide-invalid"},
		{"confirm with no notifier", answering(UnusualSignInConfirm), true, "decide-invalid"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, rec, d, b := decideEnv(t, UnusualSignInPolicy{}, c.withoutNotifier)
			d.answer = c.answer
			sessionsBefore := len(e.g.deps.Sessions.ListForUser(e.bobID, e.clock.now()))
			errorsBefore := strings.Count(e.logText(), "level=ERROR")
			resp := postJSON(t, b.at(addrParis), e.ts.URL+"/api/auth/login", credentialsRequest{Username: totpBobUsername, Password: totpBobPassword})
			checkRefused(t, e.g, resp)
			if n := len(e.g.deps.Sessions.ListForUser(e.bobID, e.clock.now())); n != sessionsBefore {
				t.Error("a session was issued")
			}
			if row := e.newestRow(t); row.Outcome != gauntlet.SignInRefused || row.Client.Unusual != gauntlet.SignalNewCountry {
				t.Errorf("row = %+v", row)
			}
			entry, _ := e.lastAudit("user.login_refused")
			if !strings.Contains(entry.Detail, "reason="+c.reason+";") || strings.Contains(entry.Detail, "exploded") || strings.Contains(entry.Detail, "lookup down") {
				t.Errorf("audit = %q, want reason %s and no error text", entry.Detail, c.reason)
			}
			if c.withoutNotifier {
				if strings.Contains(entry.Detail, "notify=") {
					t.Errorf("audit = %q", entry.Detail)
				}
			} else if got := e.notices(rec); len(got) != 1 || got[0].Action != UnusualSignInBlock || got[0].Reason != c.reason {
				t.Errorf("notices = %+v", got)
			}
			if got := strings.Count(e.logText(), "level=ERROR") - errorsBefore; got != 1 {
				t.Errorf("%d error lines, want 1:\n%s", got, e.logText())
			}
		})
	}
}

// Decide is not asked when nothing is kept, and a confirm it chooses
// sends a code.
func TestUnusualDecideNotAskedWhenNothingIsKept(t *testing.T) {
	e, rec, d, b := decideEnv(t, UnusualSignInPolicy{NewCountry: UnusualSignInOff}, false)
	e.mustSignIn(t, b, addrParis)
	if got := d.all(); len(got) != 0 {
		t.Errorf("Decide was asked about a dropped signal: %+v", got)
	}
	d.answer = answering(UnusualSignInConfirm)
	e.advance(time.Hour)
	status, body := e.signIn(t, newTestBrowser(t), addrParis)
	if status != http.StatusOK || strings.TrimSpace(body) != `{"confirm":true}` {
		t.Errorf("Decide's confirm = %d %s", status, body)
	}
	if code := confirmCode(t, rec); len(code) != 9 {
		t.Errorf("code = %q", code)
	}
}
