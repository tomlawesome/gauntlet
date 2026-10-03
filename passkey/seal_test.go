// Ported from mikroview's internal/api/webauthn_test.go
// (TestWebAuthnSessionCodec{RoundTrip,RejectsTampering,sAreIndependent,
// RejectsMalformedInput}), renamed for this package's codec.
package passkey

import (
	"bytes"
	"encoding/base64"
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

// respell returns another spelling of s that base64.RawURLEncoding,
// read leniently, decodes to the same bytes: the last character with one
// of its unused low bits set. "" when s has no unused bits (its decoded
// length is a multiple of three).
func respell(t *testing.T, s string) string {
	t.Helper()
	want, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for _, c := range alphabet {
		v := s[:len(s)-1] + string(c)
		if v == s {
			continue
		}
		if got, err := base64.RawURLEncoding.DecodeString(v); err == nil && bytes.Equal(got, want) {
			return v
		}
	}
	return ""
}

// TestSessionCodecRefusesANonCanonicalSpelling: a sealed value whose
// last character carries unused bits can be spelled several ways that a
// lenient decoder reads as the same bytes. gate keys a spent
// registration on the cookie text, so every other spelling must be
// refused as an invalid ceremony, or a re-spelled copy of a spent cookie
// would get past it. The session data is padded until the sealed value
// has unused bits, so the test does not depend on a random length.
func TestSessionCodecRefusesANonCanonicalSpelling(t *testing.T) {
	for _, codec := range []*sessionCodec{registerCodec, assertCodec} {
		var encoded, variant string
		for pad := range 3 {
			sd := testSessionData()
			sd.Challenge += strings.Repeat("x", pad)
			var err error
			if encoded, err = codec.encode(sd); err != nil {
				t.Fatal(err)
			}
			if variant = respell(t, encoded); variant != "" {
				break
			}
		}
		if variant == "" {
			t.Fatal("no padding gave a sealed value with unused bits")
		}
		if _, err := codec.decode(encoded); err != nil {
			t.Fatalf("the canonical spelling was refused: %v", err)
		}
		if _, err := codec.decode(variant); !errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
			t.Errorf("a re-spelling of a sealed value decoded: error = %v, want ErrPasskeyCeremonyInvalid", err)
		}
	}
}
