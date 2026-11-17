package gate

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/persist"
)

// What the user.login audit line says about a sign-in an administrator's
// allowance let through (#97): it went in on the allowance, never on a
// code or a passkey proof. The per-action and SSO details are checked in
// allow_signin_test.go; this is the case where remembering the browser
// fails.

// An allowed sign-in whose remembering write fails is refused, not let
// through (#101, A1a-R1, fail closed; this test once pinned a 200 audited
// as an allowance). Nothing is recorded as a sign-in for that attempt: no
// user.login audit record and no history success row. The failure is only
// logged.
func TestAnAllowedSignInWhoseRememberingFailsRecordsNoSignIn(t *testing.T) {
	backend := &budgetBackend{inner: persist.NewMemory(), left: -1}
	e := newUnusualEnvWith(t, backend, func(c *Config) {
		c.UnusualSignIns = UnusualSignInPolicy{NewBrowser: UnusualSignInBlock}
	})
	e.mustSignIn(t, newTestBrowser(t), addrLondon)
	e.advance(time.Hour)
	e.allow(t, e.bobID)

	loginsBefore := len(auditEntries(e.audit, "user.login"))
	successesBefore := e.successRows()

	backend.left = 0
	status, body := e.signIn(t, newTestBrowser(t), addrLondon)
	backend.left = -1
	if status != http.StatusInternalServerError {
		t.Fatalf("the allowed sign-in with a failing save = %d %s, want 500", status, body)
	}
	if p := decodeProblem(t, []byte(body)); p.Type != problemTypeBase+classServerError.anchor {
		t.Errorf("problem type = %q, want class server-error", p.Type)
	}
	logins := auditEntries(e.audit, "user.login")
	if len(logins) != loginsBefore {
		t.Errorf("user.login records = %d, want %d: the refused attempt must record none", len(logins), loginsBefore)
	}
	for _, entry := range logins {
		if strings.Contains(entry.Detail, "allowed=used") {
			t.Errorf("user.login detail %q notes a used allowance for a refused sign-in", entry.Detail)
		}
	}
	if got := e.successRows(); got != successesBefore {
		t.Errorf("history success rows = %d, want %d: the refused attempt must add none", got, successesBefore)
	}
}

// successRows counts the sign-in history rows with a success outcome.
func (e *unusualEnv) successRows() int {
	rows, _ := e.history.List(gauntlet.SignInQuery{})
	n := 0
	for _, r := range rows {
		if r.Outcome == gauntlet.SignInSuccess {
			n++
		}
	}
	return n
}
