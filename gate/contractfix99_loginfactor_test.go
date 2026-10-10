// #99, part 3: POST /api/auth/login/factor with both a code and an
// assertion, or with neither, is 400 invalid-request before any sign-in
// attempt is counted against the account or the address, and the
// pending login still works for a correct retry.
package gate

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
)

func TestContractFix99LoginFactorNeedsExactlyOneOfCodeAndAssertion(t *testing.T) {
	assertion := json.RawMessage(`{"id":"AAAA","rawId":"AAAA","type":"public-key","response":{}}`)
	bodies := []struct {
		name string
		body any
	}{
		{"both", loginFactorRequest{Code: "000000", Assertion: assertion}},
		{"neither, empty code", loginFactorRequest{}},
		{"neither, empty object", map[string]any{}},
	}
	const threshold = 3
	for _, tc := range bodies {
		t.Run(tc.name, func(t *testing.T) {
			g, ts, _ := totpFixture(t)
			bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
			secret, _, counter := totpEnrolAndConfirm(t, bob, ts)
			pending := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)

			// A fresh limiter after the password step, so only what the
			// factor requests below do is on it.
			g.deps.Limiter = mustNewLoginLimiter(t, threshold, time.Minute)
			for i := range threshold {
				resp := postJSON(t, pending, ts.URL+"/api/auth/login/factor", tc.body)
				status, raw := readAll(t, resp)
				if status != http.StatusBadRequest {
					t.Errorf("attempt %d = %d %s, want 400", i+1, status, raw)
					continue
				}
				if p := decodeProblem(t, []byte(raw)); p.Type != problemTypeBase+classInvalidRequest.anchor {
					t.Errorf("attempt %d: problem type = %q, want class invalid-request", i+1, p.Type)
				}
			}

			now := time.Now()
			id := totpBobID(t, g)
			for i := range threshold {
				if !g.deps.Limiter.Reserve("ip:198.51.100.1", now) {
					t.Errorf("address: only %d of %d attempts left after %d malformed requests, want all of them", i, threshold, threshold)
					break
				}
			}
			for i := range threshold {
				if !g.deps.Limiter.ReserveAccount(g.deps.Users, id, now) {
					t.Errorf("account: only %d of %d attempts left after %d malformed requests, want all of them", i, threshold, threshold)
					break
				}
			}

			// The reservations above filled the account's window, which
			// writes a lockout to the account (ReserveAccount); the retry
			// is about the pending login, so lift that and start a fresh
			// limiter.
			if err := g.deps.Limiter.UnlockLogin(g.deps.Users, id); err != nil {
				t.Fatalf("UnlockLogin: %v", err)
			}
			g.deps.Limiter = mustNewLoginLimiter(t, threshold, time.Minute)
			right := submitLoginFactor(t, pending, ts, gauntlet.GenerateTOTPCode(secret, counter+1))
			status, raw := readAll(t, right)
			if status != http.StatusOK || !sessionAuthenticated(t, pending, ts) {
				t.Errorf("the right code on the same pending login after malformed requests = %d %s, want 200 and a session", status, raw)
			}
		})
	}
}
