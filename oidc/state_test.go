package oidc

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestNewFlowStateProducesDistinctValues(t *testing.T) {
	now := time.Now()
	a, err := NewFlowState(now)
	if err != nil {
		t.Fatalf("NewFlowState: %v", err)
	}
	b, err := NewFlowState(now)
	if err != nil {
		t.Fatalf("NewFlowState: %v", err)
	}
	if a.State == b.State {
		t.Error("two FlowStates got the same State token")
	}
	if a.Nonce == b.Nonce {
		t.Error("two FlowStates got the same Nonce")
	}
	if a.CodeVerifier == b.CodeVerifier {
		t.Error("two FlowStates got the same PKCE CodeVerifier")
	}
}

func TestFlowStateRoundTrip(t *testing.T) {
	codec, err := NewStateCodec()
	if err != nil {
		t.Fatalf("NewStateCodec: %v", err)
	}
	now := time.Now()
	fs, err := NewFlowState(now)
	if err != nil {
		t.Fatalf("NewFlowState: %v", err)
	}

	encoded, err := codec.Encode(fs)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := codec.Decode(encoded, 10*time.Minute, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if decoded.State != fs.State || decoded.Nonce != fs.Nonce || decoded.CodeVerifier != fs.CodeVerifier {
		t.Errorf("Decode round-trip mismatch: got %+v, want %+v", decoded, fs)
	}
}

// TestFlowStateLinkUserIDRoundTrips pins the field a plain rename or
// struct-literal refactor could silently drop -- LinkUserID is what
// distinguishes an OIDC-link flow from an ordinary login (IsLink), and it
// travels only inside the sealed cookie, never as a separate parameter.
func TestFlowStateLinkUserIDRoundTrips(t *testing.T) {
	codec, err := NewStateCodec()
	if err != nil {
		t.Fatalf("NewStateCodec: %v", err)
	}
	now := time.Now()
	fs, err := NewFlowState(now)
	if err != nil {
		t.Fatalf("NewFlowState: %v", err)
	}
	fs.LinkUserID = "user-42"
	if !fs.IsLink() {
		t.Fatal("test setup: FlowState with LinkUserID set should report IsLink")
	}

	encoded, err := codec.Encode(fs)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := codec.Decode(encoded, 10*time.Minute, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.LinkUserID != "user-42" {
		t.Errorf("LinkUserID = %q, want user-42", decoded.LinkUserID)
	}
	if !decoded.IsLink() {
		t.Error("decoded FlowState lost IsLink")
	}
}

func TestFlowStateOrdinaryLoginIsNotALink(t *testing.T) {
	fs, err := NewFlowState(time.Now())
	if err != nil {
		t.Fatalf("NewFlowState: %v", err)
	}
	if fs.IsLink() {
		t.Error("a freshly created FlowState with no LinkUserID reports IsLink")
	}
}

func TestFlowStateDecodeRejectsTamperedCiphertext(t *testing.T) {
	codec, err := NewStateCodec()
	if err != nil {
		t.Fatalf("NewStateCodec: %v", err)
	}
	fs, err := NewFlowState(time.Now())
	if err != nil {
		t.Fatalf("NewFlowState: %v", err)
	}
	encoded, err := codec.Encode(fs)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Flip a bit in the middle of the *decoded* bytes, not a character of
	// the base64 text -- base64's last one or two characters can carry as
	// few as 2 real bits (the rest is structural zero padding Go's
	// non-strict decoder doesn't validate), so an ASCII-level XOR on the
	// text near either end has a real, if rare, chance of only touching a
	// padding bit and silently round-tripping to the same underlying
	// byte. Flipping a byte in the middle of the actual ciphertext, then
	// re-encoding, unambiguously corrupts real data every time,
	// regardless of how the plaintext length (which varies with
	// FlowState.IssuedAt's trailing-zero-trimmed fractional seconds)
	// happens to align base64's 3-byte grouping.
	sealed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decoding own Encode output: %v", err)
	}
	sealed[len(sealed)/2] ^= 1
	tampered := base64.RawURLEncoding.EncodeToString(sealed)
	if _, err := codec.Decode(tampered, 10*time.Minute, time.Now()); err != ErrFlowStateInvalid {
		t.Errorf("Decode(tampered) = %v, want ErrFlowStateInvalid", err)
	}
}

func TestFlowStateDecodeRejectsGarbage(t *testing.T) {
	codec, err := NewStateCodec()
	if err != nil {
		t.Fatalf("NewStateCodec: %v", err)
	}
	if _, err := codec.Decode("not-valid-base64!!!", 10*time.Minute, time.Now()); err != ErrFlowStateInvalid {
		t.Errorf("Decode(garbage) = %v, want ErrFlowStateInvalid", err)
	}
}

func TestFlowStateDecodeRejectsExpired(t *testing.T) {
	codec, err := NewStateCodec()
	if err != nil {
		t.Fatalf("NewStateCodec: %v", err)
	}
	issuedAt := time.Now()
	fs, err := NewFlowState(issuedAt)
	if err != nil {
		t.Fatalf("NewFlowState: %v", err)
	}
	encoded, err := codec.Encode(fs)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	tooLate := issuedAt.Add(11 * time.Minute)
	if _, err := codec.Decode(encoded, 10*time.Minute, tooLate); err != ErrFlowStateInvalid {
		t.Errorf("Decode(expired) = %v, want ErrFlowStateInvalid", err)
	}
}

func TestFlowStateDecodeRejectsWrongCodecKey(t *testing.T) {
	codecA, err := NewStateCodec()
	if err != nil {
		t.Fatalf("NewStateCodec: %v", err)
	}
	codecB, err := NewStateCodec()
	if err != nil {
		t.Fatalf("NewStateCodec: %v", err)
	}
	fs, err := NewFlowState(time.Now())
	if err != nil {
		t.Fatalf("NewFlowState: %v", err)
	}
	encoded, err := codecA.Encode(fs)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// A cookie sealed by one process's key must never decode under a
	// different key -- relevant if an application is ever restarted (a
	// new process, a fresh in-memory key) mid-flow: the flow should fail
	// cleanly, not partially decode.
	if _, err := codecB.Decode(encoded, 10*time.Minute, time.Now()); err != ErrFlowStateInvalid {
		t.Errorf("Decode under a different codec's key = %v, want ErrFlowStateInvalid", err)
	}
}

// respell returns another spelling of s that base64.RawURLEncoding,
// read leniently, decodes to the same bytes: the last character with one
// of its unused low bits set. "" when s has no unused bits.
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

// TestFlowStateDecodeRefusesANonCanonicalSpelling: a sealed flow state
// is accepted only in the one spelling Encode wrote, so a value can
// never be told apart from itself by its text. LinkUserID is padded
// until the sealed value has unused bits, so the test does not depend on
// a random length.
func TestFlowStateDecodeRefusesANonCanonicalSpelling(t *testing.T) {
	codec, err := NewStateCodec()
	if err != nil {
		t.Fatalf("NewStateCodec: %v", err)
	}
	now := time.Now()
	var encoded, variant string
	for pad := range 3 {
		fs, err := NewFlowState(now)
		if err != nil {
			t.Fatal(err)
		}
		fs.LinkUserID = strings.Repeat("x", pad+1)
		if encoded, err = codec.Encode(fs); err != nil {
			t.Fatal(err)
		}
		if variant = respell(t, encoded); variant != "" {
			break
		}
	}
	if variant == "" {
		t.Fatal("no padding gave a sealed value with unused bits")
	}
	if _, err := codec.Decode(encoded, time.Minute, now); err != nil {
		t.Fatalf("the canonical spelling was refused: %v", err)
	}
	if _, err := codec.Decode(variant, time.Minute, now); err != ErrFlowStateInvalid {
		t.Errorf("a re-spelling of a sealed flow state decoded: error = %v, want ErrFlowStateInvalid", err)
	}
}

// TestFlowStateDecodeRefusesAtExactlyItsExpiry (#90 item 1, owner call):
// a flow state is valid only while now is before IssuedAt plus the
// maximum age, so at that very instant it is refused; one nanosecond
// earlier it still decodes.
func TestFlowStateDecodeRefusesAtExactlyItsExpiry(t *testing.T) {
	codec, err := NewStateCodec()
	if err != nil {
		t.Fatalf("NewStateCodec: %v", err)
	}
	issuedAt := time.Now()
	fs, err := NewFlowState(issuedAt)
	if err != nil {
		t.Fatalf("NewFlowState: %v", err)
	}
	encoded, err := codec.Encode(fs)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	const maxAge = 10 * time.Minute

	if _, err := codec.Decode(encoded, maxAge, issuedAt.Add(maxAge-time.Nanosecond)); err != nil {
		t.Errorf("Decode one nanosecond before the expiry = %v, want it accepted", err)
	}
	if _, err := codec.Decode(encoded, maxAge, issuedAt.Add(maxAge)); err != ErrFlowStateInvalid {
		t.Errorf("Decode at exactly IssuedAt+maxAge = %v, want ErrFlowStateInvalid", err)
	}
}
