// Ported from mikroview's internal/api/webauthn_test.go
// (TestWebAuthnSessionCodec{RoundTrip,RejectsTampering,sAreIndependent,
// RejectsMalformedInput}), renamed for this package's codec.
package passkey

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/tomlawesome/gauntlet"
)

// testSessionData is a representative webauthn.SessionData: every field
// populated with a value that will reveal a round-trip bug (a zero
// Challenge or nil UserID would round-trip "successfully" even if the
// codec dropped it). Expires is a fixed UTC time rather than time.Now(),
// so DeepEqual is not at the mercy of the monotonic clock reading JSON
// strips.
func testSessionData() webauthn.SessionData {
	return webauthn.SessionData{
		Challenge:            "test-challenge-000000000000000000",
		RelyingPartyID:       "app.home.lan",
		Origin:               "https://app.home.lan:8443",
		UserID:               []byte("user-000000000000000000000000000000000000000000000000000000000001"),
		AllowedCredentialIDs: [][]byte{[]byte("cred-one"), []byte("cred-two")},
		Expires:              time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC),
		UserVerification:     protocol.VerificationRequired,
		CredParams:           []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: -7}},
		Mediation:            protocol.MediationDefault,
	}
}

func TestSessionCodecRoundTrip(t *testing.T) {
	for _, codec := range []*sessionCodec{registerCodec, assertCodec} {
		want := testSessionData()
		encoded, err := codec.encode(want)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		got, err := codec.decode(encoded)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("round trip changed the session data:\n got:  %#v\n want: %#v", got, want)
		}
	}
}

// TestSessionCodecRejectsTampering flips one bit inside the sealed
// ciphertext (past the nonce, so it lands in what GCM authenticates)
// and checks decode refuses it rather than returning a plausible but
// wrong SessionData.
func TestSessionCodecRejectsTampering(t *testing.T) {
	codec := registerCodec
	encoded, err := codec.encode(testSessionData())
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	sealed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decoding test fixture: %v", err)
	}
	ns := codec.aead.NonceSize()
	if len(sealed) <= ns {
		t.Fatalf("sealed value too short to tamper with: %d bytes", len(sealed))
	}
	sealed[ns] ^= 0xFF
	if _, err := codec.decode(base64.RawURLEncoding.EncodeToString(sealed)); !errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		t.Fatalf("decode(tampered) error = %v, want ErrPasskeyCeremonyInvalid", err)
	}
}

// TestSessionCodecsAreIndependent proves a value sealed for one ceremony
// cannot be opened as the other -- what guarantees a registration's state
// can never finish a login, or the other way round.
func TestSessionCodecsAreIndependent(t *testing.T) {
	registerSealed, err := registerCodec.encode(testSessionData())
	if err != nil {
		t.Fatalf("encode with the register codec: %v", err)
	}
	if _, err := assertCodec.decode(registerSealed); !errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		t.Fatalf("the assert codec opened a register-sealed value: err = %v, want ErrPasskeyCeremonyInvalid", err)
	}
	assertSealed, err := assertCodec.encode(testSessionData())
	if err != nil {
		t.Fatalf("encode with the assert codec: %v", err)
	}
	if _, err := registerCodec.decode(assertSealed); !errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		t.Fatalf("the register codec opened an assert-sealed value: err = %v, want ErrPasskeyCeremonyInvalid", err)
	}
}

func TestSessionCodecRejectsMalformedInput(t *testing.T) {
	codec := registerCodec
	cases := map[string]string{
		"not base64url at all":                  "not valid base64url!!!",
		"valid base64 but shorter than a nonce": base64.RawURLEncoding.EncodeToString([]byte("x")),
		"empty string":                          "",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := codec.decode(value); !errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
				t.Fatalf("decode(%q) error = %v, want ErrPasskeyCeremonyInvalid", value, err)
			}
		})
	}
}

// TestSessionCodecRejectsAnAuthenticNonSessionPayload covers decode's
// last refusal: a value that opens under the right key but does not
// hold session JSON.
func TestSessionCodecRejectsAnAuthenticNonSessionPayload(t *testing.T) {
	codec := registerCodec
	nonce := make([]byte, codec.aead.NonceSize())
	sealed := codec.aead.Seal(nonce, nonce, []byte("not json"), nil)
	if _, err := codec.decode(base64.RawURLEncoding.EncodeToString(sealed)); !errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		t.Fatalf("decode(non-JSON payload) error = %v, want ErrPasskeyCeremonyInvalid", err)
	}
}

// TestSpentChallengesClaimOnce: a challenge is accepted once, refused
// until its sealed expiry, and forgotten once the ceremony has expired.
func TestSpentChallengesClaimOnce(t *testing.T) {
	var c spentChallenges
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	expires := now.Add(ceremonyLifetime)
	if !c.claim("a", expires, now) {
		t.Fatal("the first claim of a fresh challenge was refused")
	}
	if c.claim("a", expires, now.Add(time.Second)) {
		t.Fatal("a second claim of the same challenge was accepted")
	}
	if c.claim("a", expires, expires.Add(-time.Second)) {
		t.Fatal("the challenge was forgotten before its ceremony expired")
	}
	if !c.claim("b", expires.Add(time.Minute), expires) {
		t.Fatal("a fresh challenge was refused")
	}
	if _, kept := c.seen["a"]; kept {
		t.Error("a challenge whose ceremony has expired was not dropped")
	}
}

// TestSpentChallengeLivesOnTheSealedWallClockExpiry: the entry's expiry
// is the sealed ceremony's own Expires, with no monotonic reading, so it
// is dropped on the same wall clock open checks the ceremony against.
//
// No test here can show the failure this guards against end to end:
// that needs a monotonic reading that disagrees with the wall clock (a
// wall clock stepped back), and Go hands out monotonic readings only
// from time.Now, with no way to construct or shift one apart from the
// wall reading. So this pins the mechanism instead: the code it replaced
// stored now.Add(ceremonyLifetime), which carries time.Now's monotonic
// reading, and fails both checks below.
func TestSpentChallengeLivesOnTheSealedWallClockExpiry(t *testing.T) {
	var c spentChallenges
	now := time.Now() // carries a monotonic reading, as FinishLogin's does
	// The sealed Expires, as it comes back out of the JSON round trip:
	// wall clock only.
	var sealedExpires time.Time
	raw, err := json.Marshal(now.Add(ceremonyLifetime - time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &sealedExpires); err != nil {
		t.Fatal(err)
	}
	if !c.claim("a", sealedExpires, now) {
		t.Fatal("the first claim was refused")
	}
	until := c.seen["a"]
	if !until.Equal(sealedExpires) {
		t.Errorf("the entry expires at %v, want the sealed Expires %v", until, sealedExpires)
	}
	if strings.Contains(until.String(), "m=") {
		t.Errorf("the entry's expiry %v carries a monotonic reading; it must be wall clock only", until)
	}
}
