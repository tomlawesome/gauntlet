package gate

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/oidc"
	"github.com/tomlawesome/gauntlet/persist"
)

// accountEventFunc adapts a function to AccountNotifier.
type accountEventFunc func(ctx context.Context, n AccountNotice) error

func (f accountEventFunc) AccountEvent(ctx context.Context, n AccountNotice) error { return f(ctx, n) }

// validDeps returns a Deps with every required field set, so each
// subtest below can null out exactly the one it is testing.
func validDeps(t *testing.T) Deps {
	t.Helper()
	users, err := gauntlet.OpenStore(persist.NewMemory(), gauntlet.Options{})
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := gauntlet.OpenTokenStore(persist.NewMemory(), gauntlet.TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return Deps{
		Users:    users,
		Sessions: gauntlet.NewSessionStore(gauntlet.MaxSessionIdle, gauntlet.MaxSessionLifetime),
		Tokens:   tokens,
		Limiter:  mustNewLoginLimiter(t, 5, time.Minute),
	}
}

func validConfig() Config {
	return Config{
		CookieName:      "session",
		CSRFHeaderValue: "app",
		ClientIP:        func(r *http.Request) string { return "1.2.3.4" },
		ProductName:     "Test Product",
		AdminPasskey:    AdminPasskeyOptional,
	}
}

// TestNewFailsClosedOnMissingConfig and TestNewFailsClosedOnMissingDeps
// pin New's "fail closed on missing required deps" contract (docs/
// design.md, stage 1 scope): a Gate must never start with a hole that
// would either panic on the first request or -- for CSRFHeaderValue --
// silently accept a forged one.
func TestNewFailsClosedOnMissingConfig(t *testing.T) {
	deps := validDeps(t)
	cases := []struct {
		name string
		cfg  Config
	}{
		{"no cookie name", func() Config { c := validConfig(); c.CookieName = ""; return c }()},
		{"no CSRF header value", func() Config { c := validConfig(); c.CSRFHeaderValue = ""; return c }()},
		{"no ClientIP", func() Config { c := validConfig(); c.ClientIP = nil; return c }()},
		{"no ProductName", func() Config { c := validConfig(); c.ProductName = ""; return c }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg, deps); err == nil {
				t.Error("expected New to refuse an incomplete Config")
			}
		})
	}
}

func TestNewFailsClosedOnMissingDeps(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Deps)
	}{
		{"no Users", func(d *Deps) { d.Users = nil }},
		{"no Sessions", func(d *Deps) { d.Sessions = nil }},
		{"no Tokens", func(d *Deps) { d.Tokens = nil }},
		{"no Limiter", func(d *Deps) { d.Limiter = nil }},
		// SSO wired without the codec that seals its flow cookie would
		// panic on the first "sign in with SSO" click, not at startup.
		{"OIDC without OIDCState", func(d *Deps) { d.OIDC = &oidc.Client{}; d.OIDCState = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := validDeps(t)
			tc.mut(&deps)
			if _, err := New(validConfig(), deps); err == nil {
				t.Error("expected New to refuse an incomplete Deps")
			}
		})
	}
}

// TestNewRefusesSessionLimitsOutsideAAL2Caps pins New's refusal of a
// Deps.Sessions store configured looser than gauntlet.MaxSessionIdle/
// MaxSessionLifetime (the NIST SP 800-63B-4 AAL2 caps, gauntlet#51):
// an application wiring its own, longer-lived store must fail at
// start-up, not silently outlive the limit the rest of the module
// assumes.
func TestNewRefusesSessionLimitsOutsideAAL2Caps(t *testing.T) {
	cases := []struct {
		name          string
		idle, ceiling time.Duration
	}{
		{"idle exceeds MaxSessionIdle", gauntlet.MaxSessionIdle + time.Minute, gauntlet.MaxSessionLifetime},
		{"ceiling exceeds MaxSessionLifetime", gauntlet.MaxSessionIdle, gauntlet.MaxSessionLifetime + time.Hour},
		{"no ceiling", gauntlet.MaxSessionIdle, 0},
		{"idle not positive", 0, gauntlet.MaxSessionLifetime},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := validDeps(t)
			deps.Sessions = gauntlet.NewSessionStore(tc.idle, tc.ceiling)
			if _, err := New(validConfig(), deps); err == nil {
				t.Error("expected New to refuse a Deps.Sessions store outside the AAL2 caps")
			}
		})
	}
}

// TestNewAcceptsSessionLimitsAtExactlyTheAAL2Caps pins the boundary:
// exactly MaxSessionIdle/MaxSessionLifetime is within the cap, not
// over it.
func TestNewAcceptsSessionLimitsAtExactlyTheAAL2Caps(t *testing.T) {
	deps := validDeps(t)
	deps.Sessions = gauntlet.NewSessionStore(gauntlet.MaxSessionIdle, gauntlet.MaxSessionLifetime)
	if _, err := New(validConfig(), deps); err != nil {
		t.Errorf("expected New to accept session limits exactly at the AAL2 caps, got %v", err)
	}
}

func TestNewDefaultsNowToTimeNow(t *testing.T) {
	g, err := New(validConfig(), validDeps(t))
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	got := g.now()
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Errorf("expected now() to default to time.Now, got %v (window %v..%v)", got, before, after)
	}
}

// Config.Notices replaces the deprecated Config.Notify (#73): New
// refuses a Config setting both, so an application migrating cannot
// leave the old and new hooks both wired and get two notices for one
// event.
func TestNewRefusesBothNotifyAndNotices(t *testing.T) {
	cfg := validConfig()
	cfg.Notify = notifierFunc(func(context.Context, SessionsEndedNotice) error { return nil })
	cfg.Notices = accountEventFunc(func(context.Context, AccountNotice) error { return nil })
	if _, err := New(cfg, validDeps(t)); err == nil || !strings.Contains(err.Error(), "Notify") || !strings.Contains(err.Error(), "Notices") {
		t.Errorf("New = %v, want a refusal naming Notify and Notices", err)
	}
}

// TestNewRefusesAGroupThatGivesAdminOrAnUnknownRole pins ADR-0013
// decision 1: an identity provider never mints an admin, and the
// refusal comes at startup, naming the decision.
func TestNewRefusesAGroupThatGivesAdminOrAnUnknownRole(t *testing.T) {
	cases := map[string]oidc.Policy{
		"admin from a group":      {RoleFromGroups: map[string]string{"ops": "admin"}},
		"unknown role from group": {RoleFromGroups: map[string]string{"ops": "root"}},
		"admin as the fallback":   {RoleFromGroups: map[string]string{"ops": "user"}, RoleWithoutGroup: "admin"},
		"unknown fallback":        {RoleFromGroups: map[string]string{"ops": "user"}, RoleWithoutGroup: "guest"},
	}
	for name, policy := range cases {
		t.Run(name, func(t *testing.T) {
			deps := validDeps(t)
			deps.OIDCPolicy = policy
			_, err := New(validConfig(), deps)
			if err == nil {
				t.Fatal("expected New to refuse the policy")
			}
			if !strings.Contains(err.Error(), "0013") {
				t.Errorf("error %q does not name ADR-0013", err)
			}
		})
	}

	deps := validDeps(t)
	deps.OIDCPolicy = oidc.Policy{RoleFromGroups: map[string]string{"staff": "user", "guests": "viewer"}, RoleWithoutGroup: "user"}
	if _, err := New(validConfig(), deps); err != nil {
		t.Errorf("a user/viewer map was refused: %v", err)
	}
}

// TestNewRefusesASharedIssuerItsPolicyDoesNotPin pins ADR-0014 at the
// gate: the tenant pin must be in the policy gate enforces, so a client
// built for a shared issuer is refused when Deps.OIDCPolicy leaves the
// tenant open, even though oidc.New accepted it under its own policy.
func TestNewRefusesASharedIssuerItsPolicyDoesNotPin(t *testing.T) {
	const google = "https://accounts.google.com"
	// A discovery document naming the shared issuer, served locally so
	// the test never dials the real provider.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 google,
			"authorization_endpoint": google + "/authorize",
			"token_endpoint":         google + "/token",
			"jwks_uri":               google + "/jwks",
		})
	}))
	t.Cleanup(srv.Close)
	pinned := oidc.Policy{RequiredClaims: map[string][]string{"hd": {"example.com"}}}
	client, err := oidc.New(gooidc.InsecureIssuerURLContext(context.Background(), google), oidc.Config{
		IssuerURL:   srv.URL,
		ClientID:    "test-client",
		RedirectURL: "https://app.example/callback",
		Policy:      pinned,
	})
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}
	codec, err := oidc.NewStateCodec()
	if err != nil {
		t.Fatal(err)
	}

	deps := validDeps(t)
	deps.OIDC, deps.OIDCState = client, codec
	_, err = New(validConfig(), deps)
	if !errors.Is(err, oidc.ErrMultiTenantIssuer) {
		t.Fatalf("New with an empty Deps.OIDCPolicy = %v, want oidc.ErrMultiTenantIssuer", err)
	}
	if !strings.Contains(err.Error(), "0014") {
		t.Errorf("error %q does not name ADR-0014", err)
	}

	deps.OIDCPolicy = pinned
	if _, err := New(validConfig(), deps); err != nil {
		t.Errorf("a shared issuer with its tenant pinned was refused: %v", err)
	}
}

// TestNewRequiresTheAdminPasskeyRule pins #82 decision 4: the app says
// whether every admin must hold a passkey, with no default either way.
// New refuses an unset or unknown value, and refuses "required" unless
// a relying party is wired and ready, rather than lock every admin out
// or silently waive the rule. The chosen value is logged once.
func TestNewRequiresTheAdminPasskeyRule(t *testing.T) {
	cases := []struct {
		name     string
		rule     AdminPasskeyRule
		passkeys gauntlet.PasskeyCeremony
		want     []string // substrings of the refusal; nil means New succeeds
	}{
		{"unset", "", nil, []string{"Config.AdminPasskey", "not set", "AdminPasskeyRequired", "AdminPasskeyOptional"}},
		{"unknown value", "sometimes", nil, []string{"Config.AdminPasskey", `"sometimes"`}},
		{"required, no passkeys wired", AdminPasskeyRequired, nil, []string{"Config.AdminPasskey", "Deps.Passkeys is nil", "AdminPasskeyOptional"}},
		{"required, relying party on an IP", AdminPasskeyRequired, mustRelyingParty(t, "https://192.0.2.10"), []string{"Config.AdminPasskey", "(ip)", "AdminPasskeyOptional"}},
		{"required, no public URL", AdminPasskeyRequired, mustRelyingParty(t, ""), []string{"Config.AdminPasskey", "(unset)"}},
		{"required, plain http", AdminPasskeyRequired, mustRelyingParty(t, "http://app.example"), []string{"Config.AdminPasskey", "(insecure)"}},
		{"optional, no passkeys", AdminPasskeyOptional, nil, nil},
		{"optional, relying party not ready", AdminPasskeyOptional, mustRelyingParty(t, "https://192.0.2.10"), nil},
		{"required, ready relying party", AdminPasskeyRequired, mustRelyingParty(t, passkeyTestPublicURL), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &messageRecorder{}
			cfg := validConfig()
			cfg.AdminPasskey = tc.rule
			cfg.Log = slog.New(rec)
			deps := validDeps(t)
			deps.Passkeys = tc.passkeys
			_, err := New(cfg, deps)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("New = %v, want it to start", err)
				}
				var logged []string
				for _, m := range rec.msgs {
					if strings.Contains(m, "admin passkey rule") {
						logged = append(logged, m)
					}
				}
				if want := "gate: admin passkey rule: " + string(tc.rule); len(logged) != 1 || logged[0] != want {
					t.Errorf("New logged %q, want exactly %q once", logged, want)
				}
				return
			}
			if err == nil {
				t.Fatal("New started, want a refusal")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("New = %q, want it to name %q", err, w)
				}
			}
		})
	}
}
