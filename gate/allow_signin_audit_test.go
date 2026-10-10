package gate

import (
	"net/http"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// What the user.login audit line says about a sign-in an administrator's
// allowance let through (#97): it went in on the allowance, never on a
// code or a passkey proof. The per-action and SSO details are checked in
// allow_signin_test.go; this is the case where remembering the browser
// fails.

// A failed remember write drops the signals, so the line loses its
// unusual= and action= part, but it must still say the sign-in was an
// allowance and not a confirmation.
func TestAnAllowedSignInIsAuditedAsAnAllowanceWhenRememberingFails(t *testing.T) {
	backend := &budgetBackend{inner: persist.NewMemory(), left: -1}
	e := newUnusualEnvWith(t, backend, func(c *Config) {
		c.UnusualSignIns = UnusualSignInPolicy{NewBrowser: UnusualSignInBlock}
	})
	e.mustSignIn(t, newTestBrowser(t), addrLondon)
	e.advance(time.Hour)
	e.allow(t, e.bobID)

	backend.left = 0
	status, body := e.signIn(t, newTestBrowser(t), addrLondon)
	backend.left = -1
	if status != http.StatusOK {
		t.Fatalf("the allowed sign-in with a failing save = %d %s, want 200", status, body)
	}
	entry, ok := e.lastAudit("user.login")
	if want := `allowed=used; via admin allowance; from="` + addrLondon + `"`; !ok || entry.Detail != want {
		t.Errorf("user.login detail = %q, want %q", entry.Detail, want)
	}
}
