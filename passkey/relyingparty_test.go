// Ported from mikroview's internal/api/webauthn_test.go
// (TestNewRelyingParty), with DisplayName in place of the literal
// "MikroView" and two cases mikroview has no equivalent for: the empty
// DisplayName refusal and the explicit policy.
package passkey

import (
	"testing"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/tomlawesome/gauntlet"
)

const testDisplayName = "Passkey Test Suite"

func TestNewRelyingParty(t *testing.T) {
	cases := []struct {
		name       string
		publicURL  string
		wantStatus gauntlet.PasskeyStatus
		wantRPID   string
		wantOrigin string
	}{
		{name: "unset", publicURL: "", wantStatus: gauntlet.PasskeyStatusUnset},
		{name: "unparsable is ignored same as unset", publicURL: "://not a url", wantStatus: gauntlet.PasskeyStatusUnset},
		{name: "relative URL has no host, ignored", publicURL: "/just/a/path", wantStatus: gauntlet.PasskeyStatusUnset},
		{name: "IP literal host", publicURL: "https://192.0.2.10:8443", wantStatus: gauntlet.PasskeyStatusIP},
		{name: "IPv6 literal host", publicURL: "https://[2001:db8::1]", wantStatus: gauntlet.PasskeyStatusIP},
		{name: "http on a real host is insecure", publicURL: "http://app.example", wantStatus: gauntlet.PasskeyStatusInsecure},
		{name: "non-http(s) scheme is insecure", publicURL: "ftp://app.example", wantStatus: gauntlet.PasskeyStatusInsecure},
		{
			name: "http on localhost is allowed", publicURL: "http://localhost:5173",
			wantStatus: gauntlet.PasskeyStatusReady, wantRPID: "localhost", wantOrigin: "http://localhost:5173",
		},
		{
			name: "https ready, plain", publicURL: "https://app.home.lan:8443",
			wantStatus: gauntlet.PasskeyStatusReady, wantRPID: "app.home.lan", wantOrigin: "https://app.home.lan:8443",
		},
		{
			name: "path, query and fragment are stripped but still usable", publicURL: "https://app.home.lan:8443/setup?x=1#y",
			wantStatus: gauntlet.PasskeyStatusReady, wantRPID: "app.home.lan", wantOrigin: "https://app.home.lan:8443",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rp, err := New(Config{PublicURL: tc.publicURL, DisplayName: testDisplayName})
			if err != nil {
				t.Fatalf("New(%q): unexpected error: %v", tc.publicURL, err)
			}
			if rp.Status() != tc.wantStatus {
				t.Fatalf("Status = %q, want %q", rp.Status(), tc.wantStatus)
			}
			if tc.wantStatus != gauntlet.PasskeyStatusReady {
				if rp.wa != nil || rp.RPID() != "" || rp.Origin() != "" {
					t.Fatalf("status %q: want no library instance and empty RPID/Origin, got wa=%v rpID=%q origin=%q", rp.Status(), rp.wa != nil, rp.RPID(), rp.Origin())
				}
				return
			}
			if rp.wa == nil {
				t.Fatal("library instance is nil despite Status being ready")
			}
			if rp.RPID() != tc.wantRPID {
				t.Fatalf("RPID = %q, want %q", rp.RPID(), tc.wantRPID)
			}
			if rp.Origin() != tc.wantOrigin {
				t.Fatalf("Origin = %q, want %q", rp.Origin(), tc.wantOrigin)
			}
			if got := rp.wa.Config.RPID; got != tc.wantRPID {
				t.Fatalf("webauthn.Config.RPID = %q, want %q", got, tc.wantRPID)
			}
			if got := rp.wa.Config.RPOrigins; len(got) != 1 || got[0] != tc.wantOrigin {
				t.Fatalf("webauthn.Config.RPOrigins = %v, want [%q]", got, tc.wantOrigin)
			}
			if got := rp.wa.Config.RPDisplayName; got != testDisplayName {
				t.Fatalf("webauthn.Config.RPDisplayName = %q, want %q", got, testDisplayName)
			}
		})
	}
}

// TestNewRefusesAnEmptyDisplayName: the one setting New fails closed on,
// as gate.New does for an empty Config.ProductName -- an empty name would
// reach the browser's passkey prompt.
func TestNewRefusesAnEmptyDisplayName(t *testing.T) {
	for _, url := range []string{"", "https://app.example"} {
		if rp, err := New(Config{PublicURL: url}); err == nil {
			t.Errorf("New with no DisplayName (PublicURL %q) = %+v, want an error", url, rp)
		}
	}
}

// TestNewWritesThePolicyOut pins ADR-0004 decision 5: user verification
// asked for but not required, attestation "none", no metadata service,
// resident-key preference left unset.
func TestNewWritesThePolicyOut(t *testing.T) {
	rp, err := New(Config{PublicURL: "https://app.example", DisplayName: testDisplayName})
	if err != nil {
		t.Fatal(err)
	}
	cfg := rp.wa.Config
	if got := cfg.AuthenticatorSelection.UserVerification; got != protocol.VerificationPreferred {
		t.Errorf("UserVerification = %q, want %q", got, protocol.VerificationPreferred)
	}
	if got := cfg.AttestationPreference; got != protocol.PreferNoAttestation {
		t.Errorf("AttestationPreference = %q, want %q", got, protocol.PreferNoAttestation)
	}
	if cfg.MDS != nil {
		t.Error("a metadata service is configured, want none")
	}
	if cfg.AuthenticatorSelection.ResidentKey != "" || cfg.AuthenticatorSelection.RequireResidentKey != nil {
		t.Errorf("resident-key preference = %q/%v, want unset", cfg.AuthenticatorSelection.ResidentKey, cfg.AuthenticatorSelection.RequireResidentKey)
	}
}
