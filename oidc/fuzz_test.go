// Fuzzes StateCodec.Decode over an arbitrary cookie value. Gauntlet
// issue #10.
package oidc

import (
	"testing"
	"time"
)

func FuzzStateCodecDecode(f *testing.F) {
	codec, err := NewStateCodec()
	if err != nil {
		f.Fatalf("NewStateCodec: %v", err)
	}
	now := time.Now()
	valid, err := codec.Encode(FlowState{State: "s", Nonce: "n", CodeVerifier: "v", IssuedAt: now})
	if err != nil {
		f.Fatalf("Encode: %v", err)
	}
	linked, err := codec.Encode(FlowState{State: "s2", Nonce: "n2", CodeVerifier: "v2", IssuedAt: now, LinkUserID: "user-1"})
	if err != nil {
		f.Fatalf("Encode: %v", err)
	}
	expired, err := codec.Encode(FlowState{State: "s3", Nonce: "n3", CodeVerifier: "v3", IssuedAt: now.Add(-24 * time.Hour)})
	if err != nil {
		f.Fatalf("Encode: %v", err)
	}

	f.Add(valid)
	f.Add(linked)
	f.Add(expired)
	f.Add("")
	f.Add("not-base64!!")
	f.Add(valid[:len(valid)-1])
	f.Add(valid + "x")

	f.Fuzz(func(t *testing.T, cookieValue string) {
		fs, err := codec.Decode(cookieValue, time.Hour, now)
		if err != nil {
			return
		}
		// Must never successfully decode to a state this codec didn't
		// itself seal.
		if cookieValue != valid && cookieValue != linked {
			t.Fatalf("Decode accepted a cookie value this codec never sealed: %q -> %+v", cookieValue, fs)
		}
	})
}
