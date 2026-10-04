package gate

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
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
