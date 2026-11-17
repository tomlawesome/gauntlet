// Ported from mikroview's internal/api/recoverycodes_test.go.
package gate

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestRecoveryCodesRegenerateHappyPath(t *testing.T) {
	_, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	_, oldCodes, _ := totpEnrolAndConfirm(t, bob, ts)

	resp := postJSON(t, bob, ts.URL+"/api/auth/recovery-codes", recoveryCodesRegenerateRequest{Password: totpBobPassword})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("regenerate returned %d", resp.StatusCode)
	}
	var out recoveryCodesRegenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.RecoveryCodes) != 10 {
		t.Fatalf("got %d fresh codes, want 10", len(out.RecoveryCodes))
	}
	for _, oc := range oldCodes {
		for _, nc := range out.RecoveryCodes {
			if oc == nc {
				t.Errorf("a regenerated code matched an old one: %q", oc)
			}
		}
	}

	// The old set must no longer work.
	pending := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	reuse := submitLoginFactor(t, pending, ts, oldCodes[0])
	defer func() { _ = reuse.Body.Close() }()
	if reuse.StatusCode != http.StatusUnauthorized {
		t.Errorf("an old, pre-regeneration code got %d, want 401", reuse.StatusCode)
	}
}

func TestRecoveryCodesRegenerateWrongPasswordRefusesAndKeepsOldCodes(t *testing.T) {
	_, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	_, oldCodes, _ := totpEnrolAndConfirm(t, bob, ts)

	resp := postJSON(t, bob, ts.URL+"/api/auth/recovery-codes", recoveryCodesRegenerateRequest{Password: "not-the-password"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a wrong password got %d, want 401", resp.StatusCode)
	}

	// The original codes must still work.
	pending := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	first := submitLoginFactor(t, pending, ts, oldCodes[0])
	defer func() { _ = first.Body.Close() }()
	if first.StatusCode != http.StatusOK {
		t.Errorf("an original code after a refused regeneration got %d, want 200", first.StatusCode)
	}
}

// TestRecoveryCodesRegenerateRefusedWithoutASecondFactor: an account
// with no second factor at all cannot regenerate recovery codes.
// handleRecoveryCodesRegenerate's own !HasSecondFactor() check (409)
// used to be what caught this; since #49 the forced-enrolment door in
// Protect already refuses every non-enrolment route to such an account
// before the handler runs, so the door's 403 is what this test now
// observes -- the handler's own check is unreachable through the normal
// session-cookie path but is left in place as defence in depth.
func TestRecoveryCodesRegenerateRefusedWithoutASecondFactor(t *testing.T) {
	_, ts, _ := totpFixture(t)
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)

	resp := postJSON(t, bob, ts.URL+"/api/auth/recovery-codes", recoveryCodesRegenerateRequest{Password: totpBobPassword})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("regenerating with no second factor got %d, want 403", resp.StatusCode)
	}
	if got := resp.Header.Get(authGateHeader); got != authGateMustEnrolFactor {
		t.Errorf("%s header = %q, want %q", authGateHeader, got, authGateMustEnrolFactor)
	}
}
