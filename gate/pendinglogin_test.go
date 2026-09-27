// Direct codec-level tests for pendingLoginStateCodec -- the malformed-
// input branches decode refuses are hard to reach meaningfully through
// the full HTTP route (login_factor_test.go's TestPendingLoginCookieExpiry
// covers the age check that way), so they are exercised here directly,
// the same way oidc.StateCodec's own tests do for the equivalent OIDC
// flow cookie.
package gate

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestPendingLoginCodecRoundTrip(t *testing.T) {
	now := time.Now()
	encoded, err := pendingLoginCodec.encode(pendingLoginState{UserID: "user-1", IssuedAt: now})
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
	encoded, err := pendingLoginCodec.encode(pendingLoginState{UserID: "user-1", IssuedAt: time.Now()})
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
