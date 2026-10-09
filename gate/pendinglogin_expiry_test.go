package gate

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestPendingLoginRefusedFromItsExpiryInstant (#90 item 1, owner call): a
// pending-login cookie is valid only while now is before IssuedAt plus
// its maximum age, as a confirm or escape ticket already is. At exactly
// that instant it gets the "sign in again" 401 even though its ID was
// never spent; one nanosecond earlier the same kind of cookie signs in.
func TestPendingLoginRefusedFromItsExpiryInstant(t *testing.T) {
	g, ts, _ := totpFixture(t)
	var mu sync.Mutex
	clock := time.Now().Round(0)
	g.cfg.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	setClock := func(c time.Time) { mu.Lock(); clock = c; mu.Unlock() }
	issuedAt := clock

	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	_, codes, _ := totpEnrolAndConfirm(t, bob, ts)
	// Two pending logins issued at the same instant, neither spent.
	early := pendingCookieOf(t, startTOTPLogin(t, ts, totpBobUsername, totpBobPassword), ts)
	atExpiry := pendingCookieOf(t, startTOTPLogin(t, ts, totpBobUsername, totpBobPassword), ts)

	setClock(issuedAt.Add(pendingLoginCookieMaxAge - time.Nanosecond))
	resp, raw := postRaw(t, ts.URL+"/api/auth/login/factor", loginFactorRequest{Code: codes[0]}, early)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("a pending login one nanosecond before its expiry got %d %q, want 200", resp.StatusCode, raw)
	}

	setClock(issuedAt.Add(pendingLoginCookieMaxAge))
	resp, raw = postRaw(t, ts.URL+"/api/auth/login/factor", loginFactorRequest{Code: codes[1]}, atExpiry)
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(raw, "sign in again") {
		t.Errorf("an unspent pending login at exactly its expiry got %d %q, want 401 sign in again", resp.StatusCode, raw)
	}
}
