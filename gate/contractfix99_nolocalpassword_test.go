// #99, part 1: the self-service routes that re-check the caller's
// password -- DELETE /api/auth/totp, DELETE /api/auth/passkeys/{id} and
// POST /api/auth/recovery-codes -- answer an account with no local
// password (SSO-only) 409 conflict, naming POST /api/auth/password,
// before any password is read: nothing is spent from the account's
// re-check budget and nothing changes.
package gate

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// contractFix99SSOOnlyUser provisions an SSO-only "user"-role account
// holding a live authenticator app, its ten recovery codes and one
// passkey, all written through the store (no route enrols a factor
// without a password), and returns its ID, the passkey's route ID and a
// client holding a fresh SSO session for it.
func contractFix99SSOOnlyUser(t *testing.T, g *Gate, ts *httptest.Server) (string, string, *http.Client) {
	t.Helper()
	now := time.Now()
	u, _, err := g.deps.Users.FindOrCreateOIDCUser("https://idp.example", "subject-frodo", "frodo", now)
	if err != nil {
		t.Fatal(err)
	}
	if u.LocalPassword() {
		t.Fatal("an SSO-provisioned account has a local password")
	}
	secret, err := gauntlet.GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	enc := gauntlet.EncodeTOTPSecret(secret)
	if err := g.deps.Users.SetPendingTOTPSecretAt(u.ID, enc, now); err != nil {
		t.Fatalf("SetPendingTOTPSecretAt: %v", err)
	}
	if _, err := g.deps.Users.HoldFirstTOTP(u.ID, enc, totpCounterNow(now), now); err != nil {
		t.Fatalf("HoldFirstTOTP: %v", err)
	}
	if _, err := g.deps.Users.ConfirmHeldEnrolment(u.ID, now); err != nil {
		t.Fatalf("ConfirmHeldEnrolment: %v", err)
	}
	credID := []byte("contractfix99-credential")
	if _, err := g.deps.Users.AddLaterPasskey(u.ID, gauntlet.Passkey{
		ID:        credID,
		PublicKey: []byte("placeholder-public-key"),
		RPID:      g.deps.Passkeys.RPID(),
		Name:      "key",
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("AddLaterPasskey: %v", err)
	}
	sess := g.deps.Sessions.CreateFrom(u.ID, gauntlet.SessionClient{Method: gauntlet.SignInMethodSSO}, time.Now())
	return u.ID, base64.RawURLEncoding.EncodeToString(credID), sessionClient(t, ts.URL, sess.ID)
}

func TestContractFix99NoLocalPasswordIs409AndSpendsNothing(t *testing.T) {
	g := passkeyGate(t)
	ts := newTestServer(t, g)
	registerAdmin(t, ts, "admin", testAdminPassword)
	id, passkeyID, client := contractFix99SSOOnlyUser(t, g, ts)

	if got := protectedStatus(t, client, ts); got != http.StatusOK {
		t.Fatalf("the SSO-only account's session got %d before any request, want 200", got)
	}
	before, ok := g.deps.Users.Get(id)
	if !ok || !before.HasActiveTOTP() || before.PasskeyCount() != 1 || len(before.RecoveryCodes) != 10 {
		t.Fatalf("fixture account = %+v, want a live app, one passkey and ten recovery codes", before)
	}

	routes := []struct {
		name string
		send func(body any) *http.Response
	}{
		{"DELETE /api/auth/totp", func(body any) *http.Response {
			return deleteJSON(t, client, ts.URL+"/api/auth/totp", body)
		}},
		{"DELETE /api/auth/passkeys/{id}", func(body any) *http.Response {
			return deleteJSON(t, client, ts.URL+"/api/auth/passkeys/"+passkeyID, body)
		}},
		{"POST /api/auth/recovery-codes", func(body any) *http.Response {
			return postJSON(t, client, ts.URL+"/api/auth/recovery-codes", body)
		}},
	}
	bodies := map[string]any{
		"a password":  map[string]string{"password": "anything-at-all"},
		"no password": map[string]string{"password": ""},
	}
	// Twelve requests in all, against a re-check budget of five
	// (newTestGate's limiter): were any of them counted, the budget
	// check below would refuse.
	for _, route := range routes {
		for bodyName, body := range bodies {
			for range 2 {
				status, raw := readAll(t, route.send(body))
				if status != http.StatusConflict {
					t.Errorf("%s with %s by an SSO-only account = %d %s, want 409", route.name, bodyName, status, raw)
					continue
				}
				p := decodeProblem(t, []byte(raw))
				if !strings.HasSuffix(p.Type, "#conflict") || p.Type != problemTypeBase+classConflict.anchor {
					t.Errorf("%s with %s: problem type = %q, want class conflict", route.name, bodyName, p.Type)
				}
				if !strings.Contains(p.Detail, "local password") || !strings.Contains(p.Detail, "POST /api/auth/password") {
					t.Errorf("%s with %s: detail = %q, want it to say a local password must be set first with POST /api/auth/password", route.name, bodyName, p.Detail)
				}
			}
		}
	}

	after, ok := g.deps.Users.Get(id)
	if !ok {
		t.Fatal("the account is gone")
	}
	if after.LocalPassword() {
		t.Error("a refused request gave the account a local password")
	}
	if !after.HasActiveTOTP() || after.TOTPSecret != before.TOTPSecret || !after.TOTPConfirmedAt.Equal(before.TOTPConfirmedAt) {
		t.Error("a refused request changed the authenticator app")
	}
	if after.PasskeyCount() != 1 || !reflect.DeepEqual(after.Passkeys[0].ID, before.Passkeys[0].ID) {
		t.Errorf("a refused request changed the passkeys: %d left", after.PasskeyCount())
	}
	if !reflect.DeepEqual(after.RecoveryCodes, before.RecoveryCodes) {
		t.Error("a refused request changed the recovery codes")
	}
	if got := protectedStatus(t, client, ts); got != http.StatusOK {
		t.Errorf("the caller's session got %d after the refused requests, want 200: a refusal ends nothing", got)
	}

	// The whole re-check budget is still there.
	now := time.Now()
	for i := range 5 {
		if !g.deps.Limiter.ReserveRecheck(id, now) {
			t.Fatalf("re-check reservation %d refused: the 409s spent the budget", i+1)
		}
	}
}
