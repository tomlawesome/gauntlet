// Direct codec-level tests for pendingLoginStateCodec -- the malformed-
// input branches decode refuses are hard to reach meaningfully through
// the full HTTP route (login_factor_test.go's TestPendingLoginCookieExpiry
// covers the age check that way), so they are exercised here directly,
// the same way oidc.StateCodec's own tests do for the equivalent OIDC
// flow cookie.
package gate

import (
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
	tampered := []byte(encoded)
	// Flip one character well past the nonce prefix -- anywhere in the
	// ciphertext or its auth tag fails GCM's Open.
	i := len(tampered) - 1
	if tampered[i] == 'A' {
		tampered[i] = 'B'
	} else {
		tampered[i] = 'A'
	}
	if _, err := pendingLoginCodec.decode(string(tampered), time.Now()); err != errPendingLoginInvalid {
		t.Errorf("got %v, want errPendingLoginInvalid", err)
	}
}
