// Direct codec-level tests for pendingLoginStateCodec -- the malformed-
// input branches decode refuses are hard to reach meaningfully through
// the full HTTP route (login_factor_test.go's TestPendingLoginCookieExpiry
// covers the age check that way), so they are exercised here directly,
// the same way oidc.StateCodec's own tests do for the equivalent OIDC
// flow cookie.
package gate

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPendingLoginCodecRoundTrip(t *testing.T) {
	now := time.Now()
	encoded, err := pendingLoginCodec.encode(pendingLoginState{UserID: "user-1", IssuedAt: now, ID: newTestPendingID(t)})
	if err != nil {
		t.Fatal(err)
	}
	st, err := pendingLoginCodec.decode(encoded, now)
	if err != nil {
		t.Fatal(err)
	}
	if st.UserID != "user-1" {
		t.Errorf("UserID = %q, want %q", st.UserID, "user-1")
	}
}

func TestPendingLoginCodecRefusesMalformedBase64(t *testing.T) {
	if _, err := pendingLoginCodec.decode("not valid base64!!", time.Now()); err != errPendingLoginInvalid {
		t.Errorf("got %v, want errPendingLoginInvalid", err)
	}
}

func TestPendingLoginCodecRefusesTooShortValue(t *testing.T) {
	// Valid base64, but far shorter than the AEAD's nonce size.
	if _, err := pendingLoginCodec.decode("YQ", time.Now()); err != errPendingLoginInvalid {
		t.Errorf("got %v, want errPendingLoginInvalid", err)
	}
}

func TestPendingLoginCodecRefusesTamperedCiphertext(t *testing.T) {
	encoded, err := pendingLoginCodec.encode(pendingLoginState{UserID: "user-1", IssuedAt: time.Now(), ID: newTestPendingID(t)})
	if err != nil {
		t.Fatal(err)
	}
	// Flip one bit of the sealed bytes themselves, in the auth tag at the
	// end. Editing the last base64 character instead only sometimes
	// changes a byte: its low bits are padding a non-strict decoder
	// ignores, so that version passed about 1 run in 150 with nothing
	// tampered at all.
	sealed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 0x01
	tampered := base64.RawURLEncoding.EncodeToString(sealed)
	if _, err := pendingLoginCodec.decode(tampered, time.Now()); err != errPendingLoginInvalid {
		t.Errorf("got %v, want errPendingLoginInvalid", err)
	}
}

// newTestPendingID is a fresh pending-login ID for a hand-built state.
// spentPendingLogins is process-wide, so a fixed ID would be spent by
// the first run of a test and refused by the next (-count=2).
func newTestPendingID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// TestPendingLoginCodecRefusesAStateWithNoID: a pending login sealed
// without an ID -- by a version before the one-shot rule -- cannot be
// spent, so it is refused.
func TestPendingLoginCodecRefusesAStateWithNoID(t *testing.T) {
	encoded, err := pendingLoginCodec.encode(pendingLoginState{UserID: "user-1", IssuedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pendingLoginCodec.decode(encoded, time.Now()); err != errPendingLoginInvalid {
		t.Errorf("got %v, want errPendingLoginInvalid", err)
	}
}

// TestSpentPendingLoginOutlivesABackwardClockStep (addendum 3 to the
// G8 design note): the clock steps back an hour between the password
// step and the sign-in that completes it, so the claim is made with now
// an hour before IssuedAt. The kept cookie must still be refused on
// replay right up to IssuedAt plus the maximum age on the wall clock --
// the instant decode stops accepting it -- because the forget time comes
// from IssuedAt, not from the moment of the claim.
func TestSpentPendingLoginOutlivesABackwardClockStep(t *testing.T) {
	g, ts, _ := totpFixture(t)
	var mu sync.Mutex
	clock := time.Now().Round(0)
	g.cfg.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	setClock := func(c time.Time) { mu.Lock(); clock = c; mu.Unlock() }
	issuedAt := clock

	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	_, codes, _ := totpEnrolAndConfirm(t, bob, ts)
	client := startTOTPLogin(t, ts, totpBobUsername, totpBobPassword)
	kept := pendingCookieOf(t, client, ts)

	setClock(issuedAt.Add(-time.Hour)) // the clock steps back
	first := submitLoginFactor(t, client, ts, codes[0])
	_ = first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("the sign-in after the clock stepped back got %d, want 200", first.StatusCode)
	}

	setClock(issuedAt.Add(pendingLoginCookieMaxAge - time.Second)) // decode still accepts the cookie
	resp, raw := postRaw(t, ts.URL+"/api/auth/login/factor", loginFactorRequest{Code: codes[1]}, kept)
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(raw, "sign in again") {
		t.Errorf("the kept pending login, replayed just before its wall-clock expiry, got %d %q, want 401 sign in again", resp.StatusCode, raw)
	}
}
