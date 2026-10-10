// Tests for (*Gate).StillSignedIn and Refusal (#104, ADR-0016), written
// from the ADR before the code. The "stream" here is the request a
// long-lived handler holds: built once, re-checked with StillSignedIn,
// and -- for every refusal -- the same request sent through Protect at
// that moment must answer the same status and problem class. Every
// refusal is paired with the same fixture admitted, before the condition
// or on the path its door admits, so none can pass against a
// StillSignedIn that refuses everything.
package gate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/persist"
)

// stillClock is a hand-moved Config.Now, safe across goroutines.
type stillClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *stillClock) now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *stillClock) set(t time.Time) { c.mu.Lock(); defer c.mu.Unlock(); c.t = t }

// stillReq describes the request a stream was opened with.
type stillReq struct {
	method string // GET when empty
	path   string
	cookie string // session cookie value; none when empty
	auth   string // Authorization header; none when empty
	csrf   bool   // send the CSRF header
}

func (s stillReq) build() *http.Request {
	method := s.method
	if method == "" {
		method = http.MethodGet
	}
	r := httptest.NewRequest(method, "http://gate.test"+s.path, nil)
	if s.csrf {
		r.Header.Set(csrfHeaderName, testCSRFValue)
	}
	if s.cookie != "" {
		r.AddCookie(&http.Cookie{Name: testCookieName, Value: s.cookie})
	}
	if s.auth != "" {
		r.Header.Set("Authorization", s.auth)
	}
	return r
}

// stillOK answers 200 to anything Protect lets through.
var stillOK = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

// throughProtect sends rq through g.Protect over stillOK and returns the
// status and, for a refusal, the problem type.
func throughProtect(t *testing.T, g *Gate, rq stillReq) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	g.Protect(stillOK).ServeHTTP(rec, rq.build())
	if rec.Code < 400 {
		return rec.Code, ""
	}
	return rec.Code, decodeProblem(t, rec.Body.Bytes()).Type
}

// wantStillAdmitted fails unless StillSignedIn returns nil for rq and
// Protect lets the same request through. The Protect half is a real
// request: it slides the session, so a test about idling must use
// g.StillSignedIn alone.
func wantStillAdmitted(t *testing.T, g *Gate, rq stillReq) {
	t.Helper()
	if err := g.StillSignedIn(rq.build()); err != nil {
		t.Errorf("StillSignedIn(%s %s) = %v, want nil", rq.method, rq.path, err)
	}
	if status, class := throughProtect(t, g, rq); status != http.StatusOK {
		t.Errorf("Protect(%s %s) = %d %s, want 200", rq.method, rq.path, status, class)
	}
}

// wantStillRefused fails unless StillSignedIn returns a *Refusal with
// status and class for rq, and Protect answers the same request at the
// same moment with that status and that problem class. StillSignedIn
// goes first: Protect may revoke what it refuses.
func wantStillRefused(t *testing.T, g *Gate, rq stillReq, status int, class string) {
	t.Helper()
	err := g.StillSignedIn(rq.build())
	var ref *Refusal
	if !errors.As(err, &ref) {
		t.Errorf("StillSignedIn(%s %s) = %v, want a *Refusal{%d, %q}", rq.method, rq.path, err, status, class)
	} else if ref.Status != status || ref.Class != class {
		t.Errorf("StillSignedIn(%s %s) = Refusal{%d, %q}, want {%d, %q}", rq.method, rq.path, ref.Status, ref.Class, status, class)
	}
	gotStatus, gotType := throughProtect(t, g, rq)
	if gotStatus != status || gotType != problemTypeBase+class {
		t.Errorf("Protect(%s %s) = %d %q, want %d %q", rq.method, rq.path, gotStatus, gotType, status, problemTypeBase+class)
	}
}

// stillAdminFixture is a gate on a hand-moved clock, its server, and an
// admin signed in past every door; cookie is the admin's session.
type stillAdminFixture struct {
	g      *Gate
	ts     *httptest.Server
	clock  *stillClock
	t0     time.Time
	admin  *http.Client
	cookie string
}

func newStillAdminFixture(t *testing.T) *stillAdminFixture {
	t.Helper()
	g := newTestGate(t)
	clock := &stillClock{t: time.Now()}
	g.cfg.Now = clock.now
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", testAdminPassword)
	return &stillAdminFixture{g: g, ts: ts, clock: clock, t0: clock.now(), admin: admin, cookie: sessionCookie(t, admin, ts)}
}

func (f *stillAdminFixture) stream() stillReq {
	return stillReq{path: "/api/protected", cookie: f.cookie}
}

func (f *stillAdminFixture) adminID(t *testing.T) string {
	t.Helper()
	u, ok := f.g.deps.Users.ByUsername("admin")
	if !ok {
		t.Fatal("no admin account")
	}
	return u.ID
}

// Signed in, re-checked every 5s with nothing else happening: admitted
// until MaxSessionIdle has passed since sign-in, then refused -- the
// checks never kept the session awake -- and the session is then
// timed out and resumable, not ended.
func TestStillSignedInIdlesOutWithoutOtherRequests(t *testing.T) {
	f := newStillAdminFixture(t)
	idleAt := f.t0.Add(gauntlet.MaxSessionIdle)
	r := f.stream().build()

	sawLive, sawRefused := false, false
	for d := 5 * time.Second; d <= gauntlet.MaxSessionIdle+time.Minute; d += 5 * time.Second {
		now := f.t0.Add(d)
		f.clock.set(now)
		err := f.g.StillSignedIn(r)
		switch {
		case now.Before(idleAt):
			sawLive = true
			if err != nil {
				t.Fatalf("at +%v, inside the idle limit: %v, want nil", d, err)
			}
		case now.After(idleAt):
			sawRefused = true
			var ref *Refusal
			if !errors.As(err, &ref) || ref.Status != http.StatusUnauthorized || ref.Class != "sign-in-required" {
				t.Fatalf("at +%v, past the idle limit: %v, want Refusal{401, sign-in-required} -- the checks kept the session awake", d, err)
			}
		}
	}
	if !sawLive || !sawRefused {
		t.Fatal("the loop did not cover both sides of the idle limit")
	}
	wantStillRefused(t, f.g, f.stream(), http.StatusUnauthorized, "sign-in-required")
	if st := sessionState(t, f.admin, f.ts); st["authenticated"] != false || st["resumable"] != true {
		t.Errorf("session state after idling out under the checks = %v, want unauthenticated and resumable", st)
	}
}

// A real request every 10 minutes keeps the session alive while the
// stream re-checks every 5s: admitted all the way to MaxSessionLifetime,
// then refused at the ceiling like any request.
func TestStillSignedInStaysWhileRealRequestsContinue(t *testing.T) {
	f := newStillAdminFixture(t)
	ceiling := f.t0.Add(gauntlet.MaxSessionLifetime)
	r := f.stream().build()

	sawLive, sawRefused := false, false
	for d := 5 * time.Second; d <= gauntlet.MaxSessionLifetime+time.Minute; d += 5 * time.Second {
		now := f.t0.Add(d)
		f.clock.set(now)
		if d%(10*time.Minute) == 0 && now.Before(ceiling) {
			if got := protectedStatus(t, f.admin, f.ts); got != http.StatusOK {
				t.Fatalf("the real request at +%v = %d, want 200", d, got)
			}
		}
		err := f.g.StillSignedIn(r)
		switch {
		case now.Before(ceiling):
			sawLive = true
			if err != nil {
				t.Fatalf("at +%v, with real requests every 10 minutes: %v, want nil", d, err)
			}
		case now.After(ceiling):
			sawRefused = true
			var ref *Refusal
			if !errors.As(err, &ref) || ref.Status != http.StatusUnauthorized || ref.Class != "sign-in-required" {
				t.Fatalf("at +%v, past the lifetime ceiling: %v, want Refusal{401, sign-in-required}", d, err)
			}
		}
	}
	if !sawLive || !sawRefused {
		t.Fatal("the loop did not cover both sides of the lifetime ceiling")
	}
	wantStillRefused(t, f.g, f.stream(), http.StatusUnauthorized, "sign-in-required")
}

// A check never extends: after many checks, the session's lastUsedAt
// as GET /api/auth/sessions shows it from another browser, and its
// ExpiresAt in the store, are unchanged. A real request then moves
// lastUsedAt, so the list can show a move.
func TestStillSignedInNeverExtendsTheSession(t *testing.T) {
	f := newStillAdminFixture(t)
	adminID := f.adminID(t)
	streamRef := currentRow(t, mustListSessions(t, f.admin, f.ts)).Ref
	other := sessionClient(t, f.ts.URL, f.g.deps.Sessions.Create(adminID, f.t0).ID)

	rowOf := func() sessionRow {
		t.Helper()
		for _, row := range mustListSessions(t, other, f.ts).Sessions {
			if row.Ref == streamRef {
				return row
			}
		}
		t.Fatalf("the stream's session %s is not listed", streamRef)
		return sessionRow{}
	}
	expiresOf := func(now time.Time) time.Time {
		t.Helper()
		for _, s := range f.g.deps.Sessions.ListForUser(adminID, now) {
			if s.ID == f.cookie {
				return s.ExpiresAt
			}
		}
		t.Fatal("the stream's session is not in the store")
		return time.Time{}
	}

	before := rowOf()
	expires := expiresOf(f.t0)
	r := f.stream().build()
	for i := 1; i <= 20; i++ {
		f.clock.set(f.t0.Add(time.Duration(i) * 5 * time.Second))
		if err := f.g.StillSignedIn(r); err != nil {
			t.Fatalf("check %d: %v, want nil", i, err)
		}
	}
	after := rowOf()
	if !after.LastUsedAt.Equal(before.LastUsedAt) {
		t.Errorf("lastUsedAt after 20 checks = %v, want unchanged %v", after.LastUsedAt, before.LastUsedAt)
	}
	if got := expiresOf(f.clock.now()); !got.Equal(expires) {
		t.Errorf("ExpiresAt after 20 checks = %v, want unchanged %v", got, expires)
	}

	if got := protectedStatus(t, f.admin, f.ts); got != http.StatusOK {
		t.Fatalf("a real request = %d, want 200", got)
	}
	if moved := rowOf(); !moved.LastUsedAt.After(before.LastUsedAt) {
		t.Errorf("lastUsedAt after a real request = %v, want later than %v", moved.LastUsedAt, before.LastUsedAt)
	}
}

func TestStillSignedInRefusesAfterLogout(t *testing.T) {
	f := newStillAdminFixture(t)
	wantStillAdmitted(t, f.g, f.stream())
	_ = postJSON(t, f.admin, f.ts.URL+"/api/auth/logout", map[string]any{}).Body.Close()
	wantStillRefused(t, f.g, f.stream(), http.StatusUnauthorized, "sign-in-required")
}

func TestStillSignedInRefusesARevokedSession(t *testing.T) {
	f := newStillAdminFixture(t)
	wantStillAdmitted(t, f.g, f.stream())
	f.g.deps.Sessions.Revoke(f.cookie)
	wantStillRefused(t, f.g, f.stream(), http.StatusUnauthorized, "sign-in-required")
}

// "Sign out everywhere" from another browser ends the stream's session.
func TestStillSignedInRefusesAfterSignOutEverywhere(t *testing.T) {
	f := newStillAdminFixture(t)
	other := sessionClient(t, f.ts.URL, f.g.deps.Sessions.Create(f.adminID(t), f.clock.now()).ID)
	wantStillAdmitted(t, f.g, f.stream())

	resp := postJSON(t, other, f.ts.URL+"/api/auth/logout-all", logoutAllRequest{Password: testAdminPassword})
	if status, body := readAll(t, resp); status != http.StatusOK {
		t.Fatalf("sign out everywhere = %d %s, want 200", status, body)
	}
	wantStillRefused(t, f.g, f.stream(), http.StatusUnauthorized, "sign-in-required")
}

// An account deleted through the store, its session left in place:
// refused for the account, not the session.
func TestStillSignedInRefusesWhenTheAccountIsDeleted(t *testing.T) {
	f := newStillAdminFixture(t)
	const bobPassword = "password-placeholder-7"
	bob, err := f.g.deps.Users.CreateUser("bob", bobPassword, gauntlet.RoleUser, f.clock.now())
	if err != nil {
		t.Fatal(err)
	}
	bobClient := sessionClient(t, f.ts.URL, f.g.deps.Sessions.Create(bob.ID, f.clock.now()).ID)
	enrolTOTPFactor(t, bobClient, f.ts, bobPassword)
	stream := stillReq{path: "/api/protected", cookie: sessionCookie(t, bobClient, f.ts)}
	wantStillAdmitted(t, f.g, stream)

	if _, err := f.g.deps.Users.DeleteUser(bob.ID); err != nil {
		t.Fatal(err)
	}
	wantStillRefused(t, f.g, stream, http.StatusUnauthorized, "sign-in-required")
}

// The password changed in another browser, through the route.
func TestStillSignedInRefusesAfterAPasswordChangeElsewhere(t *testing.T) {
	f := newStillAdminFixture(t)
	f.clock.set(f.t0.Add(time.Minute))
	other := sessionClient(t, f.ts.URL, f.g.deps.Sessions.Create(f.adminID(t), f.clock.now()).ID)
	wantStillAdmitted(t, f.g, f.stream())

	f.clock.set(f.t0.Add(2 * time.Minute))
	resp := postJSON(t, other, f.ts.URL+changePasswordPath, changePasswordRequest{CurrentPassword: testAdminPassword, NewPassword: "password-placeholder-8"})
	if status, body := readAll(t, resp); status != http.StatusOK {
		t.Fatalf("changing the password in the other browser = %d %s, want 200", status, body)
	}
	wantStillRefused(t, f.g, f.stream(), http.StatusUnauthorized, "sign-in-required")
}

// The password reset from another process (the CLI): only the persisted
// cutoff says the session is over. StillSignedIn refuses it but, unlike
// Protect, does not revoke it -- the session is still in the store
// until the next real request.
func TestStillSignedInRefusesASessionBeforeTheCutoffWithoutRevokingIt(t *testing.T) {
	f := newStillAdminFixture(t)
	adminID := f.adminID(t)
	inStore := func() bool {
		for _, s := range f.g.deps.Sessions.ListForUser(adminID, f.clock.now()) {
			if s.ID == f.cookie {
				return true
			}
		}
		return false
	}
	wantStillAdmitted(t, f.g, f.stream())

	f.clock.set(f.t0.Add(time.Minute))
	if err := f.g.deps.Users.SetPassword("admin", "password-placeholder-9", f.t0.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	var ref *Refusal
	if err := f.g.StillSignedIn(f.stream().build()); !errors.As(err, &ref) || ref.Status != http.StatusUnauthorized || ref.Class != "sign-in-required" {
		t.Fatalf("StillSignedIn after the cutoff = %v, want Refusal{401, sign-in-required}", err)
	}
	if !inStore() {
		t.Fatal("StillSignedIn revoked the pre-cutoff session; it must touch nothing")
	}
	wantStillRefused(t, f.g, f.stream(), http.StatusUnauthorized, "sign-in-required")
	if inStore() {
		t.Error("Protect left the pre-cutoff session in the store; the check above cannot tell a revoke from none")
	}
}

// An unrecognised role is refused 403 forbidden; an account identical
// but for a known role is admitted.
func TestStillSignedInRefusesAnUnrecognisedRole(t *testing.T) {
	hash, err := gauntlet.HashPassword("password-placeholder-1")
	if err != nil {
		t.Fatal(err)
	}
	sso := func(id, name string, role gauntlet.Role) gauntlet.User {
		return gauntlet.User{
			ID: id, Username: name, PasswordHash: hash, Role: role, CreatedAt: time.Now(),
			OIDCIssuer: "https://idp.example", OIDCSubject: "subject-" + id, HasLocalPassword: false,
		}
	}
	g := newTestGate(t)
	g.deps.Users = openStoreWithUsers(t,
		gauntlet.User{ID: "admin-1", Username: "admin", PasswordHash: hash, Role: gauntlet.RoleAdmin, CreatedAt: time.Now(), HasLocalPassword: true},
		sso("known-1", "known", gauntlet.RoleUser),
		sso("bogus-1", "bogus", gauntlet.Role("bogus")),
	)
	known := g.deps.Sessions.Create("known-1", time.Now())
	bogus := g.deps.Sessions.Create("bogus-1", time.Now())

	wantStillAdmitted(t, g, stillReq{path: "/api/protected", cookie: known.ID})
	wantStillRefused(t, g, stillReq{path: "/api/protected", cookie: bogus.ID}, http.StatusForbidden, "forbidden")
}

// MustChangePassword holds the stream everywhere but the password
// route; once changed, the any-factor door holds it everywhere but the
// enrolment routes; once a factor is enrolled, it is admitted. Each
// door is checked against the request's own path.
func TestStillSignedInFollowsTheMustChangeAndFactorDoors(t *testing.T) {
	const password, newPassword = "password-placeholder-1", "password-placeholder-2"
	hash, err := gauntlet.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	g := newTestGate(t)
	g.deps.Users = openStoreWithUsers(t, gauntlet.User{
		ID: "admin-1", Username: "admin", PasswordHash: hash, Role: gauntlet.RoleAdmin,
		CreatedAt: time.Now(), HasLocalPassword: true, MustChangePassword: true,
	})
	ts := newTestServer(t, g)
	client := sessionClient(t, ts.URL, g.deps.Sessions.Create("admin-1", time.Now()).ID)
	// The browser's current cookie: the routes below may rotate it.
	at := func(method, path string) stillReq {
		return stillReq{method: method, path: path, cookie: sessionCookie(t, client, ts), csrf: true}
	}

	wantStillRefused(t, g, at(http.MethodGet, "/api/protected"), http.StatusForbidden, "must-change-password")
	wantStillRefused(t, g, at(http.MethodPost, totpEnrolPath), http.StatusForbidden, "must-change-password")
	wantStillAdmitted(t, g, at(http.MethodPost, changePasswordPath))

	resp := postJSON(t, client, ts.URL+changePasswordPath, changePasswordRequest{CurrentPassword: password, NewPassword: newPassword})
	if status, body := readAll(t, resp); status != http.StatusOK {
		t.Fatalf("changing the password at the door = %d %s, want 200", status, body)
	}
	wantStillRefused(t, g, at(http.MethodGet, "/api/protected"), http.StatusForbidden, "must-enrol-factor")
	wantStillAdmitted(t, g, at(http.MethodPost, totpEnrolPath))

	enrolTOTPFactor(t, client, ts, newPassword)
	wantStillAdmitted(t, g, at(http.MethodGet, "/api/protected"))
}

// A local account with no second factor, from registration: held at
// the any-factor door except on an enrolment route, admitted once
// enrolled.
func TestStillSignedInRefusesALocalAccountWithNoSecondFactor(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	admin := registerAdminNoFactor(t, ts, "admin", testAdminPassword)
	at := func(method, path string) stillReq {
		return stillReq{method: method, path: path, cookie: sessionCookie(t, admin, ts), csrf: true}
	}

	wantStillRefused(t, g, at(http.MethodGet, "/api/protected"), http.StatusForbidden, "must-enrol-factor")
	wantStillAdmitted(t, g, at(http.MethodPost, totpEnrolPath))

	enrolTOTPFactor(t, admin, ts, testAdminPassword)
	wantStillAdmitted(t, g, at(http.MethodGet, "/api/protected"))
}

// Under AdminPasskeyRequired, an SSO-only admin (no local password) is
// held at the password door, admitted on the password route; with a
// password set, held at the passkey door, admitted on a passkey
// enrolment route; with a passkey, admitted.
func TestStillSignedInFollowsTheAdminPasskeyRule(t *testing.T) {
	g := adminPasskeyGate(t)
	ts := newTestServer(t, g)
	first := registerAdminNoFactor(t, ts, "admin", doorTestPassword)
	registerPasskeyWith(t, first, ts, g, doorTestPassword)
	_, ann := ssoOnlyAdmin(t, g, ts, "subject-ann")
	at := func(method, path string) stillReq {
		return stillReq{method: method, path: path, cookie: sessionCookie(t, ann, ts), csrf: true}
	}

	wantStillRefused(t, g, at(http.MethodGet, "/api/protected"), http.StatusForbidden, "must-change-password")
	wantStillAdmitted(t, g, at(http.MethodPost, changePasswordPath))

	const annPassword = "password-placeholder-3"
	resp := postJSON(t, ann, ts.URL+changePasswordPath, changePasswordRequest{NewPassword: annPassword})
	if status, body := readAll(t, resp); status != http.StatusOK {
		t.Fatalf("setting the first local password = %d %s, want 200", status, body)
	}
	wantStillRefused(t, g, at(http.MethodGet, "/api/protected"), http.StatusForbidden, "must-enrol-passkey")
	wantStillAdmitted(t, g, at(http.MethodPost, passkeyRegisterBeginPath))

	registerPasskeyWith(t, ann, ts, g, annPassword)
	wantStillAdmitted(t, g, at(http.MethodGet, "/api/protected"))
}

// An admin admitted with a passkey is held at the passkey door once that
// passkey stops being usable here (the public URL changed).
func TestStillSignedInRefusesAnAdminWhosePasskeyIsNoLongerUsable(t *testing.T) {
	g := adminPasskeyGate(t)
	ts := newTestServer(t, g)
	admin := registerAdminNoFactor(t, ts, "admin", doorTestPassword)
	registerPasskeyWith(t, admin, ts, g, doorTestPassword)
	stream := stillReq{path: "/api/protected", cookie: sessionCookie(t, admin, ts)}
	wantStillAdmitted(t, g, stream)

	g.deps.Passkeys = mustRelyingParty(t, "https://new-passkeys.example.org")
	wantStillRefused(t, g, stream, http.StatusForbidden, "must-enrol-passkey")
}

func TestStillSignedInRefusesARequestWithNoCookie(t *testing.T) {
	f := newStillAdminFixture(t)
	wantStillAdmitted(t, f.g, f.stream())
	wantStillRefused(t, f.g, stillReq{path: "/api/protected"}, http.StatusUnauthorized, "sign-in-required")
}

// A POST stream is held to the CSRF header, as Protect holds it.
func TestStillSignedInRefusesAnUnsafeMethodWithoutTheCSRFHeader(t *testing.T) {
	f := newStillAdminFixture(t)
	wantStillAdmitted(t, f.g, stillReq{method: http.MethodPost, path: "/api/protected", cookie: f.cookie, csrf: true})
	wantStillRefused(t, f.g, stillReq{method: http.MethodPost, path: "/api/protected", cookie: f.cookie}, http.StatusForbidden, "csrf-required")
}

// Every account gone (the store swapped for an empty one): back in the
// undecided state, a non-bootstrap path is 503 setup-required and a
// bootstrap-exempt one is admitted.
func TestStillSignedInRefusesOnceNoAccountExists(t *testing.T) {
	f := newStillAdminFixture(t)
	wantStillAdmitted(t, f.g, f.stream())

	f.g.deps.Users = openTrackedStore(t, persist.NewMemory())
	wantStillRefused(t, f.g, f.stream(), http.StatusServiceUnavailable, "setup-required")
	wantStillAdmitted(t, f.g, stillReq{path: sessionPath, cookie: f.cookie})
}

// An Exempt path is admitted whatever its cookie says, as Protect admits
// it; the same dead cookie on a path that is not exempt is refused.
func TestStillSignedInAdmitsAnExemptPathWithADeadCookie(t *testing.T) {
	g := newTestGate(t)
	g.Exempt("/api/public-stream")
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", testAdminPassword)
	cookie := sessionCookie(t, admin, ts)
	g.deps.Sessions.Revoke(cookie)

	wantStillRefused(t, g, stillReq{path: "/api/protected", cookie: cookie}, http.StatusUnauthorized, "sign-in-required")
	wantStillAdmitted(t, g, stillReq{path: "/api/public-stream", cookie: cookie})
}

// stillBearerFixture is a gate past its bootstrap state on a hand-moved
// clock, with TokenKindAPI dispatched to stillOK.
func stillBearerFixture(t *testing.T) (*Gate, *stillClock) {
	t.Helper()
	g := newTestGate(t)
	clock := &stillClock{t: time.Now()}
	g.cfg.Now = clock.now
	registerUserDirect(t, g, "admin", testAdminPassword)
	g.Handle(gauntlet.TokenKindAPI, stillOK)
	return g, clock
}

func bearerStream(raw string) stillReq {
	return stillReq{path: "/api/readonly", auth: "Bearer " + raw}
}

// A live token on its kind's handler is admitted, and the checks record
// no use; a real request through Protect does.
func TestStillSignedInAdmitsALiveTokenWithoutRecordingAUse(t *testing.T) {
	g, clock := stillBearerFixture(t)
	raw, tok, err := g.deps.Tokens.Create("integration", gauntlet.TokenKindAPI, "", nil, clock.now())
	if err != nil {
		t.Fatal(err)
	}
	lastUsed := func() time.Time {
		t.Helper()
		for _, l := range g.deps.Tokens.List() {
			if l.ID == tok.ID {
				return l.LastUsedAt
			}
		}
		t.Fatal("token not listed")
		return time.Time{}
	}
	before := lastUsed()
	r := bearerStream(raw).build()
	start := clock.now()
	for i := 1; i <= 20; i++ {
		clock.set(start.Add(time.Duration(i) * 5 * time.Minute))
		if err := g.StillSignedIn(r); err != nil {
			t.Fatalf("check %d: %v, want nil", i, err)
		}
	}
	if got := lastUsed(); !got.Equal(before) {
		t.Errorf("LastUsedAt after 20 checks = %v, want unchanged %v", got, before)
	}

	if status, class := throughProtect(t, g, bearerStream(raw)); status != http.StatusOK {
		t.Fatalf("Protect with the token = %d %s, want 200", status, class)
	}
	if got := lastUsed(); !got.Equal(clock.now()) {
		t.Errorf("LastUsedAt after a real request = %v, want %v", got, clock.now())
	}
}

func TestStillSignedInRefusesARevokedToken(t *testing.T) {
	g, clock := stillBearerFixture(t)
	raw, tok, err := g.deps.Tokens.Create("integration", gauntlet.TokenKindAPI, "", nil, clock.now())
	if err != nil {
		t.Fatal(err)
	}
	wantStillAdmitted(t, g, bearerStream(raw))
	if err := g.deps.Tokens.Revoke(tok.ID); err != nil {
		t.Fatal(err)
	}
	wantStillRefused(t, g, bearerStream(raw), http.StatusUnauthorized, "invalid-credentials")
}

func TestStillSignedInRefusesAnExpiredToken(t *testing.T) {
	g, clock := stillBearerFixture(t)
	start := clock.now()
	raw, _, err := g.deps.Tokens.CreateWithExpiry("short", gauntlet.TokenKindAPI, "", nil, start, start.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	clock.set(start.Add(30 * time.Minute))
	wantStillAdmitted(t, g, bearerStream(raw))
	clock.set(start.Add(time.Hour + time.Second))
	wantStillRefused(t, g, bearerStream(raw), http.StatusUnauthorized, "invalid-credentials")
}

// A token whose kind has no Handle is refused; once its kind is
// registered, the same request is admitted.
func TestStillSignedInRefusesATokenOfAnUnregisteredKind(t *testing.T) {
	g, clock := stillBearerFixture(t)
	raw, _, err := g.deps.Tokens.Create("router-1", gauntlet.TokenKindIngest, "router-1", nil, clock.now())
	if err != nil {
		t.Fatal(err)
	}
	wantStillRefused(t, g, bearerStream(raw), http.StatusUnauthorized, "invalid-credentials")
	g.Handle(gauntlet.TokenKindIngest, stillOK)
	wantStillAdmitted(t, g, bearerStream(raw))
}

// An Authorization header that is not "Bearer <token>" is refused, the
// token in it live or not.
func TestStillSignedInRefusesAMalformedAuthorizationHeader(t *testing.T) {
	g, clock := stillBearerFixture(t)
	raw, _, err := g.deps.Tokens.Create("integration", gauntlet.TokenKindAPI, "", nil, clock.now())
	if err != nil {
		t.Fatal(err)
	}
	wantStillAdmitted(t, g, bearerStream(raw))
	for _, h := range []string{"Basic " + raw, "Token " + raw} {
		wantStillRefused(t, g, stillReq{path: "/api/readonly", auth: h}, http.StatusUnauthorized, "invalid-credentials")
	}
}

// A token whose creating account was deleted through the store -- so
// its revoke never ran -- is still admitted by both StillSignedIn and
// Protect, as today; once SweepTokens removes it, both refuse it
// (ADR-0016's refusal list, closing paragraph).
func TestStillSignedInKeepsParityForATokenWhoseCreatorIsGone(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	registerAdmin(t, ts, "admin", testAdminPassword)
	g.Handle(gauntlet.TokenKindAPI, stillOK)
	now := time.Now()
	bob, err := g.deps.Users.CreateUser("bob", "password-placeholder-1", gauntlet.RoleUser, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := g.deps.Tokens.CreateWithExpiry("bob-integration", gauntlet.TokenKindAPI, "", bob, now.Add(-time.Hour), now.Add(300*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.deps.Users.DeleteUser(bob.ID); err != nil {
		t.Fatal(err)
	}
	wantStillAdmitted(t, g, bearerStream(raw))

	res, err := g.SweepTokens(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("SweepTokens: %v", err)
	}
	if res.Orphaned != 1 {
		t.Fatalf("SweepTokens = %+v, want 1 orphaned", res)
	}
	wantStillRefused(t, g, bearerStream(raw), http.StatusUnauthorized, "invalid-credentials")
}

func TestRefusalErrorNamesStatusAndClass(t *testing.T) {
	r := &Refusal{Status: http.StatusForbidden, Class: "must-enrol-factor"}
	if got, want := r.Error(), "gate: no longer admitted: 403 must-enrol-factor"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}

	f := newStillAdminFixture(t)
	f.g.deps.Sessions.Revoke(f.cookie)
	err := f.g.StillSignedIn(f.stream().build())
	if err == nil {
		t.Fatal("StillSignedIn admitted a revoked session")
	}
	for _, e := range []error{err, fmt.Errorf("stream ended: %w", err)} {
		var ref *Refusal
		if !errors.As(e, &ref) {
			t.Errorf("errors.As(%v) found no *Refusal", e)
			continue
		}
		if ref.Status != http.StatusUnauthorized || ref.Class != "sign-in-required" {
			t.Errorf("recovered Refusal = %+v, want {401, sign-in-required}", ref)
		}
	}
	if got, want := err.Error(), "gate: no longer admitted: 401 sign-in-required"; got != want {
		t.Errorf("returned error's text = %q, want %q", got, want)
	}
}

// One request checked from several goroutines while Protect serves
// other requests. Meaningful under -race, which CI runs.
func TestStillSignedInConcurrentWithProtect(t *testing.T) {
	f := newStillAdminFixture(t)
	r := f.stream().build()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if err := f.g.StillSignedIn(r); err != nil {
					t.Errorf("StillSignedIn from a goroutine = %v, want nil", err)
					return
				}
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				resp, err := f.admin.Get(f.ts.URL + "/api/protected")
				if err != nil {
					t.Errorf("GET /api/protected: %v", err)
					return
				}
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("GET /api/protected = %d alongside the checks, want 200", resp.StatusCode)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// A refusal from StillSignedIn leaves nothing in Config.Log. The same
// signed-out request through Protect does log, so the recorder can see a
// line when there is one.
func TestStillSignedInRefusalLeavesNoLogLine(t *testing.T) {
	f := newStillAdminFixture(t)
	raw, _, err := f.g.deps.Tokens.Create("integration", gauntlet.TokenKindAPI, "", nil, f.clock.now())
	if err != nil {
		t.Fatal(err)
	}
	f.g.Handle(gauntlet.TokenKindAPI, stillOK)
	_ = postJSON(t, f.admin, f.ts.URL+"/api/auth/logout", map[string]any{}).Body.Close()

	logs := &messageRecorder{}
	f.g.cfg.Log = slog.New(logs)
	count := func() int { logs.mu.Lock(); defer logs.mu.Unlock(); return len(logs.msgs) }

	for _, rq := range []stillReq{
		f.stream(), // signed out
		{method: http.MethodPost, path: "/api/protected", cookie: f.cookie}, // no CSRF header
		{path: "/api/readonly", auth: "Basic " + raw},                       // malformed header
		bearerStream(raw + "x"),                                             // unknown token
	} {
		if err := f.g.StillSignedIn(rq.build()); err == nil {
			t.Fatalf("StillSignedIn(%s %s) admitted a request it should refuse", rq.method, rq.path)
		}
	}
	if n := count(); n != 0 {
		t.Errorf("StillSignedIn's refusals left %d log lines, want none: %v", n, logs.msgs)
	}

	if status, _ := throughProtect(t, f.g, f.stream()); status != http.StatusUnauthorized {
		t.Fatalf("Protect with the signed-out cookie = %d, want 401", status)
	}
	if count() == 0 {
		t.Error("Protect's refusal of the signed-out cookie logged nothing; the absence above proves nothing")
	}
}
