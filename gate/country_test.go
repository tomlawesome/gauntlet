package gate

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tomlawesome/gauntlet"
)

// Config.Country (#54): signInClient is the one place a sign-in
// record's and a session's client are built, so it is the one place
// this is tested against both. nil means no country is ever recorded;
// a lookup that returns ok=false leaves the field absent, never an
// error.

// TestSignInClientFillsCountryFromConfig is signInClient on its own,
// without a request round trip: nil Config.Country leaves Country
// empty, a configured lookup fills it for an address it knows, and
// leaves it empty for one it does not.
func TestSignInClientFillsCountryFromConfig(t *testing.T) {
	g := newTestGate(t)
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)

	if c := g.signInClient(r, "203.0.113.5"); c.Country != "" {
		t.Errorf("Country = %q with Config.Country nil, want empty", c.Country)
	}

	g.cfg.Country = func(address string) (string, bool) {
		if address == "203.0.113.5" {
			return "GB", true
		}
		return "", false
	}
	if c := g.signInClient(r, "203.0.113.5"); c.Country != "GB" {
		t.Errorf("Country = %q, want GB", c.Country)
	}
	if c := g.signInClient(r, "203.0.113.9"); c.Country != "" {
		t.Errorf("Country = %q for an address the lookup has nothing for, want empty", c.Country)
	}
}

// countryFixture is sessionsFixture's shape (an admin and "bob", TOTP-
// confirmed so neither is stuck at the forced-enrolment door and both
// can list their own sessions) plus a sign-in history attached the way
// signInsFixture attaches one, and the admin client itself, so both the
// admin's sign-in view and a session list can be read for the same
// logins. Returns bob's ten unused recovery codes, one per fresh
// sign-in a test wants from a new address.
func countryFixture(t *testing.T) (g *Gate, ts *httptest.Server, admin *http.Client, codes []string) {
	t.Helper()
	g = newTestGate(t)
	g.cfg.ClientIP = func(r *http.Request) string {
		if ip := r.Header.Get(sessionsTestIPHeader); ip != "" {
			return ip
		}
		return "198.51.100.1"
	}
	g.cfg.Audit = &auditRecorder{}
	h, err := gauntlet.OpenSignInHistory(nil, gauntlet.SignInHistoryOptions{})
	if err != nil {
		t.Fatalf("OpenSignInHistory: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	g.deps.SignIns = h

	ts = newTestServer(t, g)
	admin = registerAdmin(t, ts, "admin", "password-placeholder-1")
	_ = postJSON(t, admin, ts.URL+"/api/auth/users",
		createUserRequest{Username: totpBobUsername, Password: totpBobPassword, Role: "user"}).Body.Close()

	first := newBrowser(t, "Firefox/131.0 (laptop)", "203.0.113.10")
	resp := postJSON(t, first, ts.URL+"/api/auth/login", credentialsRequest{Username: totpBobUsername, Password: totpBobPassword})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bob's first sign-in returned %d", resp.StatusCode)
	}
	_, codes, _ = totpEnrolAndConfirm(t, first, ts)
	return g, ts, admin, codes
}

// rawBody reads and closes resp's body.
func rawBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A sign-in and the session it issues share one client (signInClient,
// cookie.go's issueSession), so a login's country reaches both the
// sign-in history row and the caller's own session row, in the same
// shape: present and matching when the lookup knows the address, absent
// when it does not -- never sent as "".
func TestLoginRecordsCountryOnSignInRowAndSession(t *testing.T) {
	g, ts, admin, codes := countryFixture(t)
	g.cfg.Country = func(address string) (string, bool) {
		if address == "203.0.113.50" {
			return "GB", true
		}
		return "", false // 203.0.113.51 is a known address with no match
	}

	cases := []struct{ name, address, want string }{
		{"configured and matched", "203.0.113.50", "GB"},
		{"configured but no match", "203.0.113.51", ""},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bob := signInBob(t, ts, "Firefox/131.0", tc.address, codes[i])

			// Newest first: the password step (password_ok) and the
			// recovery-code step (success) are two rows at this address,
			// both carrying the same country -- out.SignIns[0] is the
			// completed sign-in.
			_, out, raw := getSignIns(t, admin, ts, "?address="+tc.address)
			if len(out.SignIns) == 0 || out.SignIns[0].Country != tc.want {
				t.Fatalf("sign-in row country = %+v, want %q: %s", out.SignIns, tc.want, raw)
			}
			if tc.want == "" && strings.Contains(raw, `"country"`) {
				t.Errorf("country key present in the sign-in row with nothing known: %s", raw)
			}

			status, sessions := listSessions(t, bob, ts)
			if status != http.StatusOK {
				t.Fatalf("GET /api/auth/sessions returned %d", status)
			}
			var current *sessionRow
			for i := range sessions.Sessions {
				if sessions.Sessions[i].Current {
					current = &sessions.Sessions[i]
				}
			}
			if current == nil || current.Country != tc.want {
				t.Fatalf("this browser's session country = %+v, want %q", current, tc.want)
			}
		})
	}
}

// With no Config.Country at all, neither the sign-in row nor the
// session row ever carries the field, not even as an empty string.
func TestLoginWithoutCountryConfiguredLeavesTheFieldAbsent(t *testing.T) {
	_, ts, admin, codes := countryFixture(t)

	bob := signInBob(t, ts, "Firefox/131.0", "203.0.113.52", codes[0])

	_, out, raw := getSignIns(t, admin, ts, "?address=203.0.113.52")
	if len(out.SignIns) == 0 || out.SignIns[0].Country != "" || strings.Contains(raw, `"country"`) {
		t.Errorf("sign-in row = %+v, want no country key: %s", out.SignIns, raw)
	}

	resp, err := bob.Get(ts.URL + "/api/auth/sessions")
	if err != nil {
		t.Fatal(err)
	}
	if body := rawBody(t, resp); strings.Contains(body, `"country"`) {
		t.Errorf("session list carries a country key with none configured: %s", body)
	}
}

// The first session a local account ever gets, issued from
// handleRegister, goes through the same signInClient/issueSession
// every other login path does -- register_handler.go is not a second
// place a session's client is built.
func TestRegisterRecordsCountryOnTheFirstSession(t *testing.T) {
	g := newTestGate(t)
	g.cfg.ClientIP = func(*http.Request) string { return "203.0.113.60" }
	g.cfg.Country = func(address string) (string, bool) { return "FR", address == "203.0.113.60" }
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")

	status, sessions := listSessions(t, admin, ts)
	if status != http.StatusOK {
		t.Fatalf("GET /api/auth/sessions returned %d", status)
	}
	if len(sessions.Sessions) != 1 || sessions.Sessions[0].Country != "FR" {
		t.Fatalf("session after registration = %+v, want one session with country FR", sessions.Sessions)
	}
}
