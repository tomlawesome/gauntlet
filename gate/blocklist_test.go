package gate

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/persist"
)

// fakeList is an injected common-password list: the embedded one is a
// placeholder that blocks nothing until the first signed CI run
// (ADR-0005), so these tests bring their own.
type fakeList map[string]bool

func (l fakeList) Contains(password string) bool { return l[password] }

// blockedPassword is on every fixture's list below.
const blockedPassword = "qwerty12345"

// newBlocklistServer is newTestServer over a store whose common-password
// list holds blockedPassword.
func newBlocklistServer(t *testing.T) *httptest.Server {
	t.Helper()
	var code string
	users, err := gauntlet.OpenStore(persist.NewMemory(), gauntlet.Options{
		OnSetupCode:       gauntlet.SetupCodeFunc(func(c string) { code = c }),
		PasswordBlocklist: fakeList{blockedPassword: true},
	})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	testSetupCodes.Store(users, code)
	t.Cleanup(func() { testSetupCodes.Delete(users) })
	return newTestServer(t, newTestGateWithUsers(t, users))
}

// assertRefused fails unless resp is a 400 whose body says why, in
// words that contain want.
func assertRefused(t *testing.T, resp *http.Response, want string) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d (%s), want 400", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), want) {
		t.Errorf("body %q does not say why (%q)", body, want)
	}
}

const (
	blockedReason = "common or breached"
	contextReason = "too close to"
)

func TestRegisterRefusesABlockedPasswordAndSaysWhy(t *testing.T) {
	ts := newBlocklistServer(t)
	g, _ := testServerGates.Load(ts)
	client := &http.Client{Jar: mustCookieJar(t)}
	register := func(password string) *http.Response {
		return postJSON(t, client, ts.URL+"/api/auth/register", registerRequest{
			Username: "admin", Password: password, SetupCode: setupCodeFor(t, g.(*Gate)),
		})
	}
	assertRefused(t, register(blockedPassword), blockedReason)
	assertRefused(t, register("Admin2026!"), contextReason)
	// gate adds Config.ProductName to the account's own name.
	assertRefused(t, register("Gate-Test-Suite-1"), contextReason)

	ok := register("a long first-admin passphrase")
	_ = ok.Body.Close()
	if ok.StatusCode != http.StatusCreated {
		t.Errorf("a passphrase was refused: %d", ok.StatusCode)
	}
}

func TestCreateUserRefusesABlockedPasswordAndSaysWhy(t *testing.T) {
	ts := newBlocklistServer(t)
	admin := registerAdmin(t, ts, "admin", "a long first-admin passphrase")
	create := func(password string) *http.Response {
		return postJSON(t, admin, ts.URL+"/api/auth/users", createUserRequest{Username: "operator", Password: password, Role: "user"})
	}
	assertRefused(t, create(blockedPassword), blockedReason)
	assertRefused(t, create("Operator99"), contextReason)
	assertRefused(t, create("gatetestsuite"), contextReason)
}

func TestChangePasswordRefusesABlockedPasswordAndSaysWhy(t *testing.T) {
	ts := newBlocklistServer(t)
	const current = "a long first-admin passphrase"
	admin := registerAdmin(t, ts, "admin", current)
	change := func(password string) *http.Response {
		return postJSON(t, admin, ts.URL+"/api/auth/password", changePasswordRequest{CurrentPassword: current, NewPassword: password})
	}
	assertRefused(t, change(blockedPassword), blockedReason)
	assertRefused(t, change("@Admin1234"), contextReason)
	assertRefused(t, change("GATE TEST SUITE 2026"), contextReason)
}
