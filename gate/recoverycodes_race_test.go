package gate

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// #94. The invariant (#80): an account with a live second factor holds
// recovery codes, and one with none holds none. Regenerating the codes
// must check for a live factor in the same locked write that stores
// them; checked earlier, a concurrent removal of the only factor lands
// in between and the regeneration writes a fresh set onto an account
// with no factor. Races POST /api/auth/recovery-codes against removing
// the only passkey, over and over.
//
// The removal goes through the store, not the route: the route ends the
// account's sessions, which would stop the regenerate request from ever
// reaching the write being tested.
func TestRegeneratingRecoveryCodesWhileRemovingTheOnlyPasskeyKeepsThemConsistent(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	id := passkeyBilboID(t, g)
	for round := range factorRaceRounds {
		client := raceFixtureReset(t, g, ts, id)
		raceSeedPasskey(t, g, id, time.Now())
		var regenStatus int
		var regenErr, delErr error
		raceTogether(
			func() {
				regenStatus, regenErr = factorRaceRequest(client, http.MethodPost,
					ts.URL+"/api/auth/recovery-codes",
					recoveryCodesRegenerateRequest{Password: passkeyBilboPassword})
			},
			func() {
				_, delErr = g.deps.Users.DeletePasskey(id, []byte{1})
			},
		)
		if regenErr != nil || delErr != nil {
			t.Fatalf("round %d: errors: regenerate %v / delete passkey %v", round, regenErr, delErr)
		}
		if regenStatus >= 500 {
			t.Errorf("round %d: regenerate answered %d", round, regenStatus)
		}
		wantRecoveryCodesToMatchFactors(t, g, id, fmt.Sprintf("round %d (regenerate %d)", round, regenStatus))
		if t.Failed() {
			return
		}
	}
}
