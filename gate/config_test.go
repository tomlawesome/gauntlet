package gate

import (
	"net/http"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/oidc"
	"github.com/tomlawesome/gauntlet/persist"
)

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
		Sessions: gauntlet.NewSessionStore(time.Hour, 0),
		Tokens:   tokens,
		Limiter:  gauntlet.NewLoginLimiter(5, time.Minute),
	}
}

func validConfig() Config {
	return Config{
		CookieName:      "session",
		CSRFHeaderValue: "app",
		ClientIP:        func(r *http.Request) string { return "1.2.3.4" },
		ProductName:     "Test Product",
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
