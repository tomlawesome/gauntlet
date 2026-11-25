// Tests for (*Gate).ProtectBackground (#126), written from the design
// note on the issue before the code. A background request is Protect
// minus the activity: same rules, same refusals, same dispatch, but the
// session's ExpiresAt and LastUsedAt do not move and a bearer token's
// last use is not recorded. Each refusal is compared byte for byte with
// what Protect writes for the same request, and is paired with the same
// fixture admitted, so none can pass against a wrapper that refuses
// everything. Fixtures are those of stillsignedin_test.go.
package gate

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// bgSeen records what the handler behind a wrapper saw.
type bgSeen struct {
	called bool
	user   *gauntlet.User
}

func (s *bgSeen) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.called = true
		s.user = UserFromContext(r)
		w.WriteHeader(http.StatusOK)
	})
}

// bgServe sends rq through wrap over a recording handler.
func bgServe(wrap func(http.Handler) http.Handler, rq stillReq) (*httptest.ResponseRecorder, *bgSeen) {
	seen := &bgSeen{}
	rec := httptest.NewRecorder()
	wrap(seen.handler()).ServeHTTP(rec, rq.build())
	return rec, seen
}

// wantBackgroundRefused fails unless ProtectBackground refuses rq with
// status and problem class, and answers exactly as Protect does (status,
// body, WWW-Authenticate, X-Auth-Gate).
func wantBackgroundRefused(t *testing.T, g *Gate, rq stillReq, status int, class string) {
	t.Helper()
	bg, seen := bgServe(g.ProtectBackground, rq)
	if seen.called {
		t.Errorf("ProtectBackground(%s %s) reached next, want a refusal", rq.method, rq.path)
	}
	if bg.Code != status || decodeProblem(t, bg.Body.Bytes()).Type != problemTypeBase+class {
		t.Errorf("ProtectBackground(%s %s) = %d %s, want %d %s", rq.method, rq.path, bg.Code, bg.Body.String(), status, problemTypeBase+class)
	}
	pr, _ := bgServe(g.Protect, rq)
	if bg.Code != pr.Code || bg.Body.String() != pr.Body.String() {
		t.Errorf("ProtectBackground answered %d %q, Protect %d %q; want identical", bg.Code, bg.Body.String(), pr.Code, pr.Body.String())
	}
	for _, h := range []string{"WWW-Authenticate", authGateHeader, "Content-Type"} {
		if bg.Header().Get(h) != pr.Header().Get(h) {
			t.Errorf("header %s: ProtectBackground %q, Protect %q; want identical", h, bg.Header().Get(h), pr.Header().Get(h))
		}
	}
}

func wantBackgroundAdmitted(t *testing.T, g *Gate, rq stillReq) *bgSeen {
	t.Helper()
	rec, seen := bgServe(g.ProtectBackground, rq)
	if rec.Code != http.StatusOK || !seen.called {
		t.Errorf("ProtectBackground(%s %s) = %d %s (next called %v), want 200 from next", rq.method, rq.path, rec.Code, rec.Body.String(), seen.called)
	}
	return seen
}

// sessionOf reads the stream's session from the store's own listing.
func (f *stillAdminFixture) sessionOf(t *testing.T) gauntlet.Session {
	t.Helper()
	for _, s := range f.g.deps.Sessions.ListForUser(f.adminID(t), f.clock.now()) {
		if s.ID == f.cookie {
			return s
		}
	}
	t.Fatal("the session is not in the store")
	return gauntlet.Session{}
}

// A valid session: served, the handler sees the user, and neither
// ExpiresAt nor LastUsedAt moves. The same request through Protect
// slides both, so the unchanged values mean something.
func TestProtectBackgroundServesAValidSessionWithoutSliding(t *testing.T) {
	f := newStillAdminFixture(t)
	before := f.sessionOf(t)

	f.clock.set(f.t0.Add(10 * time.Minute))
	seen := wantBackgroundAdmitted(t, f.g, f.stream())
	if seen.user == nil || seen.user.Username != "admin" {
		t.Errorf("handler saw user %+v, want admin in context", seen.user)
	}
	for i := 0; i < 5; i++ {
		f.clock.set(f.t0.Add(time.Duration(11+i) * time.Minute))
		wantBackgroundAdmitted(t, f.g, f.stream())
	}
	after := f.sessionOf(t)
	if !after.ExpiresAt.Equal(before.ExpiresAt) {
		t.Errorf("ExpiresAt after background requests = %v, want unchanged %v", after.ExpiresAt, before.ExpiresAt)
	}
	if !after.LastUsedAt.Equal(before.LastUsedAt) {
		t.Errorf("LastUsedAt after background requests = %v, want unchanged %v", after.LastUsedAt, before.LastUsedAt)
	}

	if status, class := throughProtect(t, f.g, f.stream()); status != http.StatusOK {
		t.Fatalf("Protect = %d %s, want 200", status, class)
	}
	slid := f.sessionOf(t)
	if !slid.ExpiresAt.After(before.ExpiresAt) || !slid.LastUsedAt.After(before.LastUsedAt) {
		t.Errorf("after Protect: ExpiresAt %v, LastUsedAt %v; want both later than %v, %v", slid.ExpiresAt, slid.LastUsedAt, before.ExpiresAt, before.LastUsedAt)
	}
}

// A tab left open: background polls every 30s do not keep the session
// awake, so it is refused 401 sign-in-required once the idle limit has
// passed. The control, a real request that does slide the expiry, is
// TestProtectBackgroundHonoursActivityFromProtect below.
func TestProtectBackgroundRefusesAnIdleExpiredSession(t *testing.T) {
	f := newStillAdminFixture(t)
	idleAt := f.t0.Add(gauntlet.MaxSessionIdle)

	f.clock.set(idleAt.Add(-time.Minute))
	wantBackgroundAdmitted(t, f.g, f.stream())
	for d := time.Duration(0); d < gauntlet.MaxSessionIdle; d += 30 * time.Second {
		f.clock.set(f.t0.Add(d))
		wantBackgroundAdmitted(t, f.g, f.stream())
	}
	f.clock.set(idleAt.Add(time.Minute))
	wantBackgroundRefused(t, f.g, f.stream(), http.StatusUnauthorized, "sign-in-required")
}

// A real request still slides: Protect at +50m moves the expiry, so a
// background request at +70m (past the original idle limit) is admitted.
func TestProtectBackgroundHonoursActivityFromProtect(t *testing.T) {
	f := newStillAdminFixture(t)
	f.clock.set(f.t0.Add(gauntlet.MaxSessionIdle - 10*time.Minute))
	if status, class := throughProtect(t, f.g, f.stream()); status != http.StatusOK {
		t.Fatalf("Protect = %d %s, want 200", status, class)
	}
	f.clock.set(f.t0.Add(gauntlet.MaxSessionIdle + 10*time.Minute))
	wantBackgroundAdmitted(t, f.g, f.stream())
}

// A revoked session and a missing cookie are refused as Protect refuses.
func TestProtectBackgroundRefusesARevokedSessionAndNoCookie(t *testing.T) {
	f := newStillAdminFixture(t)
	wantBackgroundAdmitted(t, f.g, f.stream())
	wantBackgroundRefused(t, f.g, stillReq{path: "/api/protected"}, http.StatusUnauthorized, "sign-in-required")
	f.g.deps.Sessions.Revoke(f.cookie)
	wantBackgroundRefused(t, f.g, f.stream(), http.StatusUnauthorized, "sign-in-required")
}

// An unsafe method is held to the CSRF header as under Protect.
func TestProtectBackgroundHoldsUnsafeMethodsToTheCSRFHeader(t *testing.T) {
	f := newStillAdminFixture(t)
	wantBackgroundAdmitted(t, f.g, stillReq{method: http.MethodPost, path: "/api/protected", cookie: f.cookie, csrf: true})
	wantBackgroundRefused(t, f.g, stillReq{method: http.MethodPost, path: "/api/protected", cookie: f.cookie}, http.StatusForbidden, "csrf-required")
}

// A session issued before the account's SessionCutoff is refused 401 on
// both wrappers, but only Protect revokes it: background leaves it in
// place, then Protect revokes it.
func TestProtectBackgroundLeavesAPreCutoffSessionForProtectToRevoke(t *testing.T) {
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
	f.clock.set(f.t0.Add(time.Minute))
	if err := f.g.deps.Users.SetPassword("admin", "password-placeholder-9", f.t0.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	rec, seen := bgServe(f.g.ProtectBackground, f.stream())
	if rec.Code != http.StatusUnauthorized || seen.called {
		t.Fatalf("ProtectBackground after the cutoff = %d (next called %v), want 401", rec.Code, seen.called)
	}
	if !inStore() {
		t.Fatal("ProtectBackground revoked the pre-cutoff session; only Protect may")
	}
	if status, class := throughProtect(t, f.g, f.stream()); status != http.StatusUnauthorized {
		t.Fatalf("Protect after the cutoff = %d %s, want 401", status, class)
	}
	if inStore() {
		t.Error("Protect left the pre-cutoff session in the store; the check above cannot tell a revoke from none")
	}
}

// A bearer token is dispatched to its kind handler with the token in
// context and never reaches next; its last use is not recorded, where
// Protect records it. Revoked and unknown tokens are refused as Protect
// refuses them.
func TestProtectBackgroundDispatchesATokenWithoutRecordingAUse(t *testing.T) {
	g, clock := stillBearerFixture(t)
	var gotToken *gauntlet.Token
	g.Handle(gauntlet.TokenKindAPI, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = TokenFromContext(r)
		w.WriteHeader(http.StatusOK)
	}))
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
	start := clock.now()
	for i := 1; i <= 5; i++ {
		clock.set(start.Add(time.Duration(i) * 5 * time.Minute))
		gotToken = nil
		rec, seen := bgServe(g.ProtectBackground, bearerStream(raw))
		if rec.Code != http.StatusOK || seen.called {
			t.Fatalf("request %d = %d (next called %v), want 200 from the kind handler only", i, rec.Code, seen.called)
		}
		if gotToken == nil || gotToken.Name != "integration" {
			t.Fatalf("request %d: kind handler saw token %+v, want integration", i, gotToken)
		}
	}
	if got := lastUsed(); !got.Equal(before) {
		t.Errorf("token LastUsedAt after background requests = %v, want unchanged %v", got, before)
	}
	if status, class := throughProtect(t, g, bearerStream(raw)); status != http.StatusOK {
		t.Fatalf("Protect with the token = %d %s, want 200", status, class)
	}
	if got := lastUsed(); !got.Equal(clock.now()) {
		t.Errorf("token LastUsedAt after Protect = %v, want %v", got, clock.now())
	}

	wantBackgroundRefused(t, g, bearerStream("not-a-real-token"), http.StatusUnauthorized, "invalid-credentials")
	if err := g.deps.Tokens.Revoke(tok.ID); err != nil {
		t.Fatal(err)
	}
	wantBackgroundRefused(t, g, bearerStream(raw), http.StatusUnauthorized, "invalid-credentials")
}

// The three doors answer through ProtectBackground exactly as through
// Protect, and each is paired with the path or state that admits.
func TestProtectBackgroundFollowsTheMustChangeAndFactorDoors(t *testing.T) {
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
	at := func(method, path string) stillReq {
		return stillReq{method: method, path: path, cookie: sessionCookie(t, client, ts), csrf: true}
	}

	wantBackgroundRefused(t, g, at(http.MethodGet, "/api/protected"), http.StatusForbidden, "must-change-password")
	wantBackgroundAdmitted(t, g, at(http.MethodPost, changePasswordPath))

	resp := postJSON(t, client, ts.URL+changePasswordPath, changePasswordRequest{CurrentPassword: password, NewPassword: newPassword})
	if status, body := readAll(t, resp); status != http.StatusOK {
		t.Fatalf("changing the password at the door = %d %s, want 200", status, body)
	}
	wantBackgroundRefused(t, g, at(http.MethodGet, "/api/protected"), http.StatusForbidden, "must-enrol-factor")
	wantBackgroundAdmitted(t, g, at(http.MethodPost, totpEnrolPath))

	enrolTOTPFactor(t, client, ts, newPassword)
	wantBackgroundAdmitted(t, g, at(http.MethodGet, "/api/protected"))
}

func TestProtectBackgroundRefusesALocalAccountWithNoSecondFactor(t *testing.T) {
	g := newTestGate(t)
	ts := newTestServer(t, g)
	admin := registerAdminNoFactor(t, ts, "admin", testAdminPassword)
	at := func(method, path string) stillReq {
		return stillReq{method: method, path: path, cookie: sessionCookie(t, admin, ts), csrf: true}
	}
	wantBackgroundRefused(t, g, at(http.MethodGet, "/api/protected"), http.StatusForbidden, "must-enrol-factor")
	enrolTOTPFactor(t, admin, ts, testAdminPassword)
	wantBackgroundAdmitted(t, g, at(http.MethodGet, "/api/protected"))
}

func TestProtectBackgroundFollowsTheAdminPasskeyRule(t *testing.T) {
	g := adminPasskeyGate(t)
	ts := newTestServer(t, g)
	first := registerAdminNoFactor(t, ts, "admin", doorTestPassword)
	registerPasskeyWith(t, first, ts, g, doorTestPassword)
	_, ann := ssoOnlyAdmin(t, g, ts, "subject-ann")
	at := func(method, path string) stillReq {
		return stillReq{method: method, path: path, cookie: sessionCookie(t, ann, ts), csrf: true}
	}

	wantBackgroundRefused(t, g, at(http.MethodGet, "/api/protected"), http.StatusForbidden, "must-change-password")
	const annPassword = "password-placeholder-3"
	resp := postJSON(t, ann, ts.URL+changePasswordPath, changePasswordRequest{NewPassword: annPassword})
	if status, body := readAll(t, resp); status != http.StatusOK {
		t.Fatalf("setting the first local password = %d %s, want 200", status, body)
	}
	wantBackgroundRefused(t, g, at(http.MethodGet, "/api/protected"), http.StatusForbidden, "must-enrol-passkey")
	wantBackgroundAdmitted(t, g, at(http.MethodPost, passkeyRegisterBeginPath))

	registerPasskeyWith(t, ann, ts, g, annPassword)
	wantBackgroundAdmitted(t, g, at(http.MethodGet, "/api/protected"))
}

// Before any account exists a non-bootstrap path is 503 setup-required
// and a bootstrap path is admitted. An Exempt path is setup-required too,
// as under Protect: Exempt cannot widen the bootstrap set (protect.go).
// Once an account exists, an Exempt path is admitted whatever its cookie
// says, while the same dead cookie elsewhere is refused.
func TestProtectBackgroundUndecidedStateAndExemptPaths(t *testing.T) {
	g := newTestGate(t)
	g.Exempt("/api/public-poll")
	wantBackgroundRefused(t, g, stillReq{path: "/api/protected"}, http.StatusServiceUnavailable, "setup-required")
	wantBackgroundAdmitted(t, g, stillReq{path: sessionPath})
	wantBackgroundRefused(t, g, stillReq{path: "/api/public-poll"}, http.StatusServiceUnavailable, "setup-required")

	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", testAdminPassword)
	cookie := sessionCookie(t, admin, ts)
	g.deps.Sessions.Revoke(cookie)
	wantBackgroundRefused(t, g, stillReq{path: "/api/protected", cookie: cookie}, http.StatusUnauthorized, "sign-in-required")
	wantBackgroundAdmitted(t, g, stillReq{path: "/api/public-poll", cookie: cookie})
}

// Real requests every 10 minutes keep the session alive, so a background
// request is admitted up to MaxSessionLifetime and refused past it: the
// ceiling applies on a background route as on any other.
func TestProtectBackgroundRefusesPastTheLifetimeCeiling(t *testing.T) {
	f := newStillAdminFixture(t)
	ceiling := f.t0.Add(gauntlet.MaxSessionLifetime)
	for d := 10 * time.Minute; ; d += 10 * time.Minute {
		now := f.t0.Add(d)
		if !now.Before(ceiling.Add(-time.Minute)) {
			break
		}
		f.clock.set(now)
		if got := protectedStatus(t, f.admin, f.ts); got != http.StatusOK {
			t.Fatalf("the real request at +%v = %d, want 200", d, got)
		}
	}
	f.clock.set(ceiling.Add(-time.Minute))
	wantBackgroundAdmitted(t, f.g, f.stream())
	f.clock.set(ceiling.Add(time.Minute))
	wantBackgroundRefused(t, f.g, f.stream(), http.StatusUnauthorized, "sign-in-required")
}
