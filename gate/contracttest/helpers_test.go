package contracttest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/gate"
	"github.com/tomlawesome/gauntlet/internal/hashcost"
	"github.com/tomlawesome/gauntlet/internal/testutil"
	"github.com/tomlawesome/gauntlet/oidc"
	"github.com/tomlawesome/gauntlet/persist"
)

// TestMain runs with cheap password hashes (internal/hashcost), as
// package gate's own tests do: nothing here is about the Argon2id cost.
func TestMain(m *testing.M) {
	hashcost.Use(true)
	os.Exit(m.Run())
}

// Fixture configuration, the same values package gate's own tests use.
const (
	testCSRFValue    = "test-frontend"
	testCookieName   = "gate_test_session"
	testProductName  = "Gate Test Suite"
	testLoginPath    = "/login"
	oidcTestClientID = "test-client"
)

// Wire names the document fixes (docs/api/auth.yaml); gate's own
// constants for them are unexported.
const (
	csrfHeaderName             = "X-Requested-With"
	authGateHeader             = "X-Auth-Gate"
	authGateMustChangePassword = "must-change-password"
)

// fixture is a gate built only from exported API, with the store behind
// it and the setup code that store announced when it opened.
type fixture struct {
	g         *gate.Gate
	users     *gauntlet.Store
	setupCode string
}

// newTestGate builds a gate over fresh, empty, in-memory stores.
func newTestGate(t *testing.T) *fixture {
	t.Helper()
	return newTestGateWith(t, persist.NewMemory(), nil)
}

// newTestGateWith is newTestGate with the accounts kept in backend and,
// when tokens is non-nil, that token store.
func newTestGateWith(t *testing.T, backend persist.Backend, tokens *gauntlet.TokenStore) *fixture {
	t.Helper()
	users, code := openStore(t, backend)
	return &fixture{g: newGate(t, gate.Deps{Users: users, Tokens: tokens}), users: users, setupCode: code}
}

// openStore opens a store over backend and returns the setup code it
// announced, the one an operator would read from the log.
func openStore(t *testing.T, backend persist.Backend) (*gauntlet.Store, string) {
	t.Helper()
	var code string
	users, err := gauntlet.OpenStore(backend, gauntlet.Options{
		OnSetupCode: gauntlet.SetupCodeFunc(func(c string) { code = c }),
	})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	return users, code
}

// newGate builds a gate over deps, giving it fresh in-memory session,
// token and limiter stores wherever deps leaves one nil.
func newGate(t *testing.T, deps gate.Deps) *gate.Gate {
	t.Helper()
	if deps.Tokens == nil {
		tokens, err := gauntlet.OpenTokenStore(persist.NewMemory(), gauntlet.TokenOptions{})
		if err != nil {
			t.Fatalf("OpenTokenStore: %v", err)
		}
		deps.Tokens = tokens
	}
	if deps.Limiter == nil {
		limiter, err := gauntlet.NewLoginLimiter(5, 5*time.Minute)
		if err != nil {
			t.Fatalf("NewLoginLimiter: %v", err)
		}
		deps.Limiter = limiter
	}
	if deps.Sessions == nil {
		deps.Sessions = gauntlet.NewSessionStore(24*time.Hour, 0)
	}
	g, err := gate.New(gate.Config{
		CookieName:      testCookieName,
		CSRFHeaderValue: testCSRFValue,
		ClientIP:        func(*http.Request) string { return "198.51.100.1" },
		ProductName:     testProductName,
		LoginPath:       testLoginPath,
	}, deps)
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	return g
}

// budgetBackend is package gate's test backend of the same name: once
// armed (left >= 0) it allows left more saves, then refuses every one.
type budgetBackend struct {
	inner persist.Backend
	left  int // saves allowed once armed; -1 = unarmed
}

func (b *budgetBackend) Load(ctx context.Context) (persist.Snapshot, error) {
	return b.inner.Load(ctx)
}

func (b *budgetBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	if b.left >= 0 {
		if b.left == 0 {
			return 0, errors.New("budget backend: save refused")
		}
		b.left--
	}
	return b.inner.Save(ctx, payload, expect)
}

func (b *budgetBackend) Close() error     { return b.inner.Close() }
func (b *budgetBackend) Describe() string { return "budget test backend" }

// newOIDCTestServer serves a gate with SSO on against a fake provider,
// with "setup-admin" already registered as the local admin. It returns
// the gate's flow-cookie codec, so a test can read the nonce the way the
// callback does.
func newOIDCTestServer(t *testing.T) (*oidc.StateCodec, *httptest.Server, *testutil.FakeProvider) {
	t.Helper()
	fp := testutil.NewFakeProvider(t)
	client, err := oidc.New(context.Background(), oidc.Config{
		IssuerURL:   fp.Issuer(),
		ClientID:    oidcTestClientID,
		RedirectURL: "http://app.example/api/auth/oidc/callback",
	})
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}
	codec, err := oidc.NewStateCodec()
	if err != nil {
		t.Fatalf("oidc.NewStateCodec: %v", err)
	}
	users, code := openStore(t, persist.NewMemory())
	g := newGate(t, gate.Deps{Users: users, OIDC: client, OIDCState: codec})
	ts := newTestServer(t, g)

	b, err := json.Marshal(registerRequest{"setup-admin", "setup-admin-password", code})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/register", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrfHeaderName, testCSRFValue)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("registering setup-admin: status %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	return codec, ts, fp
}

// testProtectedHandler stands in for an application's own protected
// route.
func testProtectedHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// newTestServer mounts g.Routes() beside one protected application route
// and wraps both in g.Protect, the shape docs/design.md §1.5 specifies.
func newTestServer(t *testing.T, g *gate.Gate) *httptest.Server {
	t.Helper()
	appMux := http.NewServeMux()
	appMux.Handle("GET /api/protected", testProtectedHandler())
	appMux.Handle("/", g.Routes())
	ts := httptest.NewServer(g.Protect(appMux))
	t.Cleanup(ts.Close)
	return ts
}

func bearerRequest(t *testing.T, base, path, raw string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+raw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func totpCounterNow(now time.Time) uint64 {
	return uint64(now.Unix()) / 30
}

func mustCookieJar(t *testing.T) http.CookieJar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return jar
}

// The bodies below are this test's own copies of the document's
// schemas: gate's handler types are unexported, so out of reach from
// this module. Every request sent is checked against the document
// (contractTransport), and TestContractRequestBodiesMatchHandlers checks
// gate's own request types against the document, so a field cannot
// drift on either side unnoticed. Response copies hold only the fields
// the test reads; the full response is checked on the wire.

type credentialsRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type registerRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	SetupCode string `json:"setupCode"`
}

type loginFactorRequest struct {
	Code      string          `json:"code,omitempty"`
	Assertion json.RawMessage `json:"assertion,omitempty"`
}

type passkeyRegisterFinishRequest struct {
	Credential json.RawMessage `json:"credential"`
	Name       string          `json:"name"`
}

type passkeyRenameRequest struct {
	Name string `json:"name"`
}

type passwordRequest struct {
	Password string `json:"password"`
}

type passkeyRow struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	LastUsedAt time.Time `json:"lastUsedAt"`
	Stale      bool      `json:"stale"`
}

type passkeyRegisterFinishResponse struct {
	Passkey       passkeyRow `json:"passkey"`
	RecoveryCodes []string   `json:"recoveryCodes"`
	AlreadyIssued bool       `json:"alreadyIssued"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type totpEnrolRequest struct {
	Password string `json:"password"`
}

type totpConfirmRequest struct {
	Code string `json:"code"`
}

type totpDeleteRequest struct {
	Password string `json:"password"`
}

type recoveryCodesRegenerateRequest struct {
	Password string `json:"password"`
}

type createTokenRequest struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Device string `json:"device"`
}

type sessionResponse struct {
	SetupRequired bool   `json:"setupRequired"`
	Authenticated bool   `json:"authenticated"`
	Role          string `json:"role"`
	SignedInSince string `json:"signedInSince"`
	Passkeys      *struct {
		Count  int    `json:"count"`
		Status string `json:"status"`
		Origin string `json:"origin"`
	} `json:"passkeys"`
}

type userSummary struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	PasskeyCount int    `json:"passkeyCount"`
}

type totpEnrolResponse struct {
	Secret string `json:"secret"`
}

type totpConfirmResponse struct {
	AlreadyIssued bool `json:"alreadyIssued"`
}

type recoveryCodesRegenerateResponse struct {
	RecoveryCodes []string `json:"recoveryCodes"`
}

type resetPasswordResponse struct {
	Code string `json:"code"`
}

type tokenResponse struct {
	ID         string             `json:"id"`
	Kind       gauntlet.TokenKind `json:"kind"`
	Value      string             `json:"value"`
	LastUsedAt time.Time          `json:"lastUsedAt"`
}
