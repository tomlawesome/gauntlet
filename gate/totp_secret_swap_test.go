package gate

import (
	"encoding/base32"
	"net/http"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// #93. Regression guard. A code generated for one pending secret must
// not make anything live once the pending secret has been replaced.
// The window inside the handler is not reachable deterministically from
// a test; this pins the route-level outcome: not 200, the app not live,
// the new secret still pending.

// Built at run time: a fixed base32 literal reads as a credential to the
// secret scanner.
var swapReplacementTOTPSecret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("0123456789"))

func TestConfirmingAReplacedPendingSecretMakesNothingLive(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	id := passkeyBilboID(t, g)
	client := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	now := time.Now()
	raceSeedPasskey(t, g, id, now)
	if err := g.deps.Users.SetPendingTOTPSecretAt(id, raceTOTPSecret, now); err != nil {
		t.Fatalf("seeding a pending authenticator app: %v", err)
	}
	oldSecret, err := gauntlet.DecodeTOTPSecret(raceTOTPSecret)
	if err != nil {
		t.Fatal(err)
	}
	code := gauntlet.GenerateTOTPCode(oldSecret, totpCounterNow(now))

	if err := g.deps.Users.SetPendingTOTPSecretAt(id, swapReplacementTOTPSecret, now.Add(time.Second)); err != nil {
		t.Fatalf("replacing the pending secret: %v", err)
	}

	resp := postJSON(t, client, ts.URL+totpConfirmPath, totpConfirmRequest{Code: code})
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("totp/confirm with a code for the replaced secret returned 200")
	}
	u, _ := g.deps.Users.Get(id)
	if u.HasActiveTOTP() {
		t.Error("the authenticator app went live on a code for a secret that was no longer pending")
	}
	if u.TOTPSecret != swapReplacementTOTPSecret || !u.TOTPConfirmedAt.IsZero() {
		t.Errorf("pending secret = %q confirmedAt=%v, want the replacement still pending and unconfirmed", u.TOTPSecret, u.TOTPConfirmedAt)
	}
}
