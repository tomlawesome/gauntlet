// The ceremony methods, driven with the shared fake authenticator
// (internal/passkeytest). gate/passkey_handler_test.go covers the same
// behaviour through the routes; these pin the package's own contract:
// which error each refusal returns, and what a verified login reports.
package passkey

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/internal/passkeytest"
)

func mustReady(t *testing.T) *RelyingParty {
	t.Helper()
	rp, err := New(Config{PublicURL: "https://passkeys.example.org", DisplayName: testDisplayName})
	if err != nil {
		t.Fatal(err)
	}
	if rp.Status() != gauntlet.PasskeyStatusReady {
		t.Fatalf("Status = %q, want ready", rp.Status())
	}
	return rp
}

func testUser() *gauntlet.User {
	return &gauntlet.User{ID: "user-0001", Username: "bilbo"}
}

// beginRegistration starts a registration and decodes the options the
// way a browser (or the fake) receives them.
func beginRegistration(t *testing.T, rp *RelyingParty, u *gauntlet.User) (*protocol.CredentialCreation, string) {
	t.Helper()
	raw, sealed, err := rp.BeginRegistration(u)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	var creation protocol.CredentialCreation
	if err := json.Unmarshal(raw, &creation); err != nil {
		t.Fatalf("decoding the creation options: %v", err)
	}
	return &creation, sealed
}

func beginLogin(t *testing.T, rp *RelyingParty, u *gauntlet.User) (*protocol.CredentialAssertion, string) {
	t.Helper()
	raw, sealed, err := rp.BeginLogin(u)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	var assertion protocol.CredentialAssertion
	if err := json.Unmarshal(raw, &assertion); err != nil {
		t.Fatalf("decoding the assertion options: %v", err)
	}
	return &assertion, sealed
}

// registerOn registers fake on u through rp and stores the result on u,
// the way gate does through Store.AddPasskey.
func registerOn(t *testing.T, rp *RelyingParty, u *gauntlet.User, fake *passkeytest.FakeAuthenticator) gauntlet.Passkey {
	t.Helper()
	creation, sealed := beginRegistration(t, rp, u)
	body, err := fake.RegisterResponse(creation)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := rp.FinishRegistration(u, sealed, body)
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	u.Passkeys = append(u.Passkeys, pk)
	return pk
}

func assertWith(t *testing.T, rp *RelyingParty, u *gauntlet.User, fake *passkeytest.FakeAuthenticator) (string, json.RawMessage) {
	t.Helper()
	options, sealed := beginLogin(t, rp, u)
	body, err := fake.AssertionResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	return sealed, body
}

func TestCeremonyRegisterAndLogin(t *testing.T) {
	rp := mustReady(t)
	u := testUser()
	fake := passkeytest.New(rp.RPID(), rp.Origin())
	pk := registerOn(t, rp, u, fake)
	if string(pk.ID) != string(fake.CredentialID()) || pk.RPID != rp.RPID() || len(pk.PublicKey) == 0 {
		t.Fatalf("registered passkey = %+v, want the fake's credential under %q", pk, rp.RPID())
	}
	if pk.Name != "" || !pk.CreatedAt.IsZero() {
		t.Errorf("FinishRegistration set Name %q / CreatedAt %v, want both left for the caller", pk.Name, pk.CreatedAt)
	}
	if !pk.Flags.UserPresent || !pk.Flags.BackupEligible {
		t.Errorf("flags = %+v, want the fake's flags carried over", pk.Flags)
	}

	sealed, body := assertWith(t, rp, u, fake)
	got, err := rp.FinishLogin(u, sealed, body)
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if string(got.CredentialID) != string(fake.CredentialID()) || got.SignCount != 0 || got.CloneWarning {
		t.Fatalf("assertion = %+v, want the fake's credential at 0 with no clone warning", got)
	}
}

// TestCeremonyReplayIsRefusedBySpentChallenge: the same sealed login
// state and assertion cannot finish twice -- for a zero-reporting
// authenticator this is the whole replay defence.
func TestCeremonyReplayIsRefusedBySpentChallenge(t *testing.T) {
	rp := mustReady(t)
	u := testUser()
	fake := passkeytest.New(rp.RPID(), rp.Origin())
	registerOn(t, rp, u, fake)

	sealedLogin, assertion := assertWith(t, rp, u, fake)
	if _, err := rp.FinishLogin(u, sealedLogin, assertion); err != nil {
		t.Fatalf("first FinishLogin: %v", err)
	}
	if _, err := rp.FinishLogin(u, sealedLogin, assertion); !errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		t.Fatalf("replayed FinishLogin error = %v, want ErrPasskeyCeremonyInvalid", err)
	}
}

// TestRegistrationCeremonyFinishesAgainAfterARefusal: registration
// challenges are not spent (ruling B on #20), so a finish the library
// refuses leaves the same sealed state usable by a correct response.
func TestRegistrationCeremonyFinishesAgainAfterARefusal(t *testing.T) {
	rp := mustReady(t)
	u := testUser()
	creation, sealed := beginRegistration(t, rp, u)

	wrong := passkeytest.New(rp.RPID(), "https://not-the-relying-party.example")
	body, err := wrong.RegisterResponse(creation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.FinishRegistration(u, sealed, body); err == nil || errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		t.Fatalf("wrong-origin FinishRegistration error = %v, want a refused credential", err)
	}

	right := passkeytest.New(rp.RPID(), rp.Origin())
	if body, err = right.RegisterResponse(creation); err != nil {
		t.Fatal(err)
	}
	pk, err := rp.FinishRegistration(u, sealed, body)
	if err != nil {
		t.Fatalf("the same ceremony with a correct authenticator: %v", err)
	}
	if !bytes.Equal(pk.ID, right.CredentialID()) {
		t.Errorf("registered credential %x, want the correct authenticator's %x", pk.ID, right.CredentialID())
	}
}

// TestCeremonyStateDoesNotCrossCeremonies: a registration's sealed state
// cannot finish a login, nor a login's a registration.
func TestCeremonyStateDoesNotCrossCeremonies(t *testing.T) {
	rp := mustReady(t)
	u := testUser()
	fake := passkeytest.New(rp.RPID(), rp.Origin())
	registerOn(t, rp, u, fake)

	_, registerSealed := beginRegistration(t, rp, u)
	loginSealed, assertion := assertWith(t, rp, u, fake)
	if _, err := rp.FinishLogin(u, registerSealed, assertion); !errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		t.Errorf("FinishLogin with a registration's state: error = %v, want ErrPasskeyCeremonyInvalid", err)
	}
	if _, err := rp.FinishRegistration(u, loginSealed, json.RawMessage(`{}`)); !errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		t.Errorf("FinishRegistration with a login's state: error = %v, want ErrPasskeyCeremonyInvalid", err)
	}
}

// TestCeremonyExpires runs in a synctest bubble, whose clock moves only
// when every goroutine in it is blocked: sleeping past the ceremony's
// lifetime is instant, and both this package and the library read the
// bubble's clock. Each case is paired with the same ceremony finishing
// inside the window, so the refusal is the clock and nothing else.
func TestCeremonyExpires(t *testing.T) {
	for _, wait := range []time.Duration{ceremonyLifetime - time.Second, ceremonyLifetime + time.Second} {
		expired := wait > ceremonyLifetime
		synctest.Test(t, func(t *testing.T) {
			rp := mustReady(t)
			u := testUser()
			fake := passkeytest.New(rp.RPID(), rp.Origin())

			creation, sealed := beginRegistration(t, rp, u)
			body, err := fake.RegisterResponse(creation)
			if err != nil {
				t.Fatal(err)
			}
			time.Sleep(wait)
			pk, err := rp.FinishRegistration(u, sealed, body)
			if expired != errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
				t.Fatalf("FinishRegistration after %v: error = %v, want ErrPasskeyCeremonyInvalid: %v", wait, err, expired)
			}
			if !expired && err != nil {
				t.Fatalf("FinishRegistration after %v: %v", wait, err)
			}
			if expired {
				registerOn(t, rp, u, fake)
			} else {
				u.Passkeys = append(u.Passkeys, pk)
			}

			loginSealed, assertion := assertWith(t, rp, u, fake)
			time.Sleep(wait)
			_, err = rp.FinishLogin(u, loginSealed, assertion)
			if expired != errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) || (!expired && err != nil) {
				t.Fatalf("FinishLogin after %v: error = %v, want ErrPasskeyCeremonyInvalid: %v", wait, err, expired)
			}
		})
	}
}

// TestCeremonyCloneWarningDoesNotSpendTheChallenge: a regressed counter
// comes back as CloneWarning with a nil error and leaves the ceremony
// open, as mikroview does -- the caller refuses it, and an authenticator
// that is not suspect can still finish the same ceremony.
func TestCeremonyCloneWarningDoesNotSpendTheChallenge(t *testing.T) {
	rp := mustReady(t)
	u := testUser()
	fake := passkeytest.New(rp.RPID(), rp.Origin())
	registerOn(t, rp, u, fake)
	u.Passkeys[0].SignCount = 5

	options, sealed := beginLogin(t, rp, u)
	fake.SignCount = 3
	regressed, err := fake.AssertionResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	got, err := rp.FinishLogin(u, sealed, regressed)
	if err != nil {
		t.Fatalf("FinishLogin(5 -> 3): %v", err)
	}
	if !got.CloneWarning || got.SignCount != 3 {
		t.Fatalf("assertion = %+v, want CloneWarning with the presented count 3", got)
	}

	fake.SignCount = 6
	advanced, err := fake.AssertionResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	got, err = rp.FinishLogin(u, sealed, advanced)
	if err != nil || got.CloneWarning || got.SignCount != 6 {
		t.Fatalf("FinishLogin(5 -> 6) on the same ceremony = %+v, %v; want accepted at 6", got, err)
	}
}

// TestCeremonyRefusals covers the library's own refusals (each paired
// with the same flow succeeding in TestCeremonyRegisterAndLogin) and
// the not-ready and no-usable-passkey states.
func TestCeremonyRefusals(t *testing.T) {
	t.Run("wrong origin at registration", func(t *testing.T) {
		rp := mustReady(t)
		u := testUser()
		fake := passkeytest.New(rp.RPID(), "https://not-the-relying-party.example")
		creation, sealed := beginRegistration(t, rp, u)
		body, err := fake.RegisterResponse(creation)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rp.FinishRegistration(u, sealed, body); err == nil || errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
			t.Fatalf("wrong-origin FinishRegistration error = %v, want a library refusal", err)
		}
	})
	t.Run("wrong RP ID at login", func(t *testing.T) {
		rp := mustReady(t)
		u := testUser()
		fake := passkeytest.New(rp.RPID(), rp.Origin())
		registerOn(t, rp, u, fake)
		fake.RPID = "not-the-relying-party.example"
		sealed, body := assertWith(t, rp, u, fake)
		if _, err := rp.FinishLogin(u, sealed, body); err == nil || errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
			t.Fatalf("wrong-RPID FinishLogin error = %v, want a library refusal", err)
		}
	})
	t.Run("unparsable responses", func(t *testing.T) {
		rp := mustReady(t)
		u := testUser()
		fake := passkeytest.New(rp.RPID(), rp.Origin())
		_, regSealed := beginRegistration(t, rp, u)
		if _, err := rp.FinishRegistration(u, regSealed, json.RawMessage(`{"id":1}`)); err == nil {
			t.Error("FinishRegistration accepted an unparsable credential")
		}
		registerOn(t, rp, u, fake)
		_, loginSealed := beginLogin(t, rp, u)
		if _, err := rp.FinishLogin(u, loginSealed, json.RawMessage(`{"id":1}`)); err == nil {
			t.Error("FinishLogin accepted an unparsable assertion")
		}
		if _, err := rp.FinishLogin(u, "garbage", json.RawMessage(`{}`)); !errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
			t.Errorf("FinishLogin with garbage state: error = %v, want ErrPasskeyCeremonyInvalid", err)
		}
	})
	t.Run("stale passkeys are neither allowed nor excluded", func(t *testing.T) {
		rp := mustReady(t)
		u := testUser()
		u.Passkeys = []gauntlet.Passkey{{ID: []byte("old-credential"), RPID: "old.example.org"}}
		if _, _, err := rp.BeginLogin(u); !errors.Is(err, ErrNoUsablePasskey) {
			t.Fatalf("BeginLogin with only a stale passkey: error = %v, want ErrNoUsablePasskey", err)
		}
		creation, _ := beginRegistration(t, rp, u)
		if n := len(creation.Response.CredentialExcludeList); n != 0 {
			t.Errorf("registration excludes %d credentials, want 0 (the only one is stale)", n)
		}
		fake := passkeytest.New(rp.RPID(), rp.Origin())
		registerOn(t, rp, u, fake)
		creation, _ = beginRegistration(t, rp, u)
		if n := len(creation.Response.CredentialExcludeList); n != 1 {
			t.Errorf("registration excludes %d credentials, want the 1 under the current RP ID", n)
		}
		options, _ := beginLogin(t, rp, u)
		if n := len(options.Response.AllowedCredentials); n != 1 {
			t.Errorf("login allows %d credentials, want the 1 under the current RP ID", n)
		}
	})
	t.Run("not ready", func(t *testing.T) {
		rp, err := New(Config{PublicURL: "https://192.0.2.10", DisplayName: testDisplayName})
		if err != nil {
			t.Fatal(err)
		}
		u := testUser()
		if _, _, err := rp.BeginRegistration(u); !errors.Is(err, ErrNotReady) {
			t.Errorf("BeginRegistration: %v, want ErrNotReady", err)
		}
		if _, err := rp.FinishRegistration(u, "", nil); !errors.Is(err, ErrNotReady) {
			t.Errorf("FinishRegistration: %v, want ErrNotReady", err)
		}
		if _, _, err := rp.BeginLogin(u); !errors.Is(err, ErrNotReady) {
			t.Errorf("BeginLogin: %v, want ErrNotReady", err)
		}
		if _, err := rp.FinishLogin(u, "", nil); !errors.Is(err, ErrNotReady) {
			t.Errorf("FinishLogin: %v, want ErrNotReady", err)
		}
	})
}

// TestSealedLoginStateIsSmallWhateverTheAccountHolds (ruling R3 on #20):
// the sealed login state carries no allowed-credential list, so its size
// does not grow with the account's passkeys -- a credential ID may be up
// to 1023 bytes, and a list sealed into a cookie would cap an account at
// a handful. The library then requires the asserted credential to be one
// of the account's usable passkeys, read at finish: a login still round
// trips, and an assertion from a credential on another account is
// refused, paired with that same credential succeeding on its own
// account.
func TestSealedLoginStateIsSmallWhateverTheAccountHolds(t *testing.T) {
	rp := mustReady(t)
	u := testUser()
	fake := passkeytest.New(rp.RPID(), rp.Origin())
	registerOn(t, rp, u, fake)
	for i := range 10 {
		id := bytes.Repeat([]byte{byte(i + 1)}, 256)
		u.Passkeys = append(u.Passkeys, gauntlet.Passkey{ID: id, PublicKey: []byte{0xa0}, RPID: rp.RPID()})
	}

	options, sealed := beginLogin(t, rp, u)
	if n := len(options.Response.AllowedCredentials); n != 11 {
		t.Fatalf("the browser's options allow %d credentials, want all 11", n)
	}
	if len(sealed) >= 1024 {
		t.Errorf("the sealed login state is %d bytes with eleven passkeys on the account, want under 1 KB", len(sealed))
	}
	body, err := fake.AssertionResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.FinishLogin(u, sealed, body); err != nil {
		t.Fatalf("a login on the account's own passkey: %v", err)
	}

	// Another account's passkey, asserted on this account's ceremony.
	other := &gauntlet.User{ID: "user-0002", Username: "frodo"}
	foreign := passkeytest.New(rp.RPID(), rp.Origin())
	registerOn(t, rp, other, foreign)
	options, sealed = beginLogin(t, rp, u)
	body, err = foreign.AssertionResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.FinishLogin(u, sealed, body); err == nil || errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		t.Errorf("an assertion from another account's passkey: error = %v, want it refused", err)
	}
	options, sealed = beginLogin(t, rp, other)
	if body, err = foreign.AssertionResponse(options); err != nil {
		t.Fatal(err)
	}
	if _, err := rp.FinishLogin(other, sealed, body); err != nil {
		t.Errorf("the same passkey on its own account: %v", err)
	}
}

// TestSpentLoginChallengeIsHeldUntilTheSealedExpiry takes over from
// 6806f33's TestSpentChallengeLivesOnTheSealedWallClockExpiry and
// TestSpentChallengesClaimOnce, which tested the set this package used to
// keep (now internal/spent, whose own tests pin the wall-clock and
// claim-once rules). This one goes through FinishLogin: the challenge it
// spends must stay spent right up to the sealed Expires that open checks
// -- so a replay a nanosecond before is refused as a used challenge, not
// as an expired ceremony -- and not a moment less. Run in a synctest
// bubble so the five minutes pass instantly.
func TestSpentLoginChallengeIsHeldUntilTheSealedExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rp := mustReady(t)
		u := testUser()
		fake := passkeytest.New(rp.RPID(), rp.Origin())
		registerOn(t, rp, u, fake)

		sealed, assertion := assertWith(t, rp, u, fake)
		sd, err := assertCodec.decode(sealed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rp.FinishLogin(u, sealed, assertion); err != nil {
			t.Fatalf("FinishLogin: %v", err)
		}
		if _, err := rp.FinishLogin(u, sealed, assertion); !errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) || !strings.Contains(err.Error(), "challenge already used") {
			t.Fatalf("an immediate replay: error = %v, want a used challenge", err)
		}

		time.Sleep(time.Until(sd.Expires) - time.Nanosecond)
		_, err = rp.FinishLogin(u, sealed, assertion)
		if !errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) || !strings.Contains(err.Error(), "challenge already used") {
			t.Fatalf("a replay a nanosecond before the sealed expiry: error = %v, want a used challenge", err)
		}
	})
}

// TestPasskeyCredentialConversionRoundTrip: a stored passkey survives the
// trip to the library's credential and back field for field --
// transports and all four flags included, which the fake authenticator
// never reports and so no ceremony test exercises.
func TestPasskeyCredentialConversionRoundTrip(t *testing.T) {
	want := gauntlet.Passkey{
		ID:         []byte("credential-id"),
		PublicKey:  []byte("cose-public-key"),
		SignCount:  42,
		Transports: []string{"usb", "nfc"},
		Flags:      gauntlet.PasskeyFlags{UserPresent: true, UserVerified: true, BackupEligible: true, BackupState: true},
		RPID:       "passkeys.example.org",
	}
	got := credentialToPasskey(passkeyToCredential(want), want.RPID)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip changed the passkey:\n got:  %+v\n want: %+v", got, want)
	}
}

// -- Signing in with a passkey alone (#77, ADR-0012) -------------------

// registerDiscoverable registers a fake that reports u's ID as its user
// handle, as a discoverable credential's authenticator does.
func registerDiscoverable(t *testing.T, rp *RelyingParty, u *gauntlet.User) *passkeytest.FakeAuthenticator {
	t.Helper()
	fake := passkeytest.New(rp.RPID(), rp.Origin())
	fake.UserHandle = []byte(u.ID)
	registerOn(t, rp, u, fake)
	return fake
}

func beginSignIn(t *testing.T, rp *RelyingParty) (*protocol.CredentialAssertion, string) {
	t.Helper()
	raw, sealed, err := rp.BeginSignIn()
	if err != nil {
		t.Fatalf("BeginSignIn: %v", err)
	}
	var assertion protocol.CredentialAssertion
	if err := json.Unmarshal(raw, &assertion); err != nil {
		t.Fatalf("decoding the sign-in options: %v", err)
	}
	return &assertion, sealed
}

// lookupOf is the lookup gate gives FinishSignIn, over a fixed set of
// accounts keyed by ID, recording each handle it was asked about.
func lookupOf(asked *[][]byte, accounts ...*gauntlet.User) func([]byte) (*gauntlet.User, bool) {
	return func(handle []byte) (*gauntlet.User, bool) {
		*asked = append(*asked, handle)
		for _, u := range accounts {
			if u.ID == string(handle) {
				return u, true
			}
		}
		return nil, false
	}
}

// Every registration asks for a discoverable credential, preferred and
// not required, so one that cannot hold it still registers (ADR-0012
// decision 7); user verification stays preferred.
func TestRegistrationAsksForAResidentKeyButDoesNotRequireOne(t *testing.T) {
	rp := mustReady(t)
	creation, _ := beginRegistration(t, rp, testUser())
	sel := creation.Response.AuthenticatorSelection
	if sel.ResidentKey != protocol.ResidentKeyRequirementPreferred {
		t.Errorf("residentKey = %q, want preferred", sel.ResidentKey)
	}
	if sel.RequireResidentKey != nil && *sel.RequireResidentKey {
		t.Error("requireResidentKey is true, want a key that cannot hold a discoverable credential still accepted")
	}
	if sel.UserVerification != protocol.VerificationPreferred {
		t.Errorf("registration userVerification = %q, want preferred", sel.UserVerification)
	}
}

func TestSignInBeginOptions(t *testing.T) {
	rp := mustReady(t)
	options, sealed := beginSignIn(t, rp)
	if n := len(options.Response.AllowedCredentials); n != 0 {
		t.Errorf("sign-in allows %d credentials, want none (the browser offers its own)", n)
	}
	if options.Response.UserVerification != protocol.VerificationRequired {
		t.Errorf("userVerification = %q, want required", options.Response.UserVerification)
	}
	if options.Response.RelyingPartyID != rp.RPID() {
		t.Errorf("rpId = %q, want %q", options.Response.RelyingPartyID, rp.RPID())
	}
	sd, err := signInCodec.decode(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if len(sd.UserID) != 0 || sd.UserVerification != protocol.VerificationRequired || sd.Expires.IsZero() {
		t.Errorf("sealed state = %+v, want no user, UV required and an expiry", sd)
	}
}

func TestSignInNamesTheAccountFromTheUserHandle(t *testing.T) {
	rp := mustReady(t)
	u := testUser()
	fake := registerDiscoverable(t, rp, u)
	other := &gauntlet.User{ID: "user-0002", Username: "frodo"}

	options, sealed := beginSignIn(t, rp)
	body, err := fake.AssertionResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	var asked [][]byte
	got, assertion, err := rp.FinishSignIn(lookupOf(&asked, other, u), sealed, body)
	if err != nil {
		t.Fatalf("FinishSignIn: %v", err)
	}
	if got != u {
		t.Errorf("FinishSignIn named %+v, want the account lookup gave for the handle", got)
	}
	if len(asked) != 1 || string(asked[0]) != u.ID {
		t.Errorf("lookup asked about %q, want exactly the user handle %q", asked, u.ID)
	}
	if !assertion.UserVerified || assertion.CloneWarning || string(assertion.CredentialID) != string(fake.CredentialID()) {
		t.Errorf("assertion = %+v, want the fake's credential, user verified, no clone warning", assertion)
	}
}

// The lookup runs before the signature is checked -- that is what lets
// gate take the account's limiter reservation first -- so an assertion
// no key signed still reaches it; and a refusal from it leaves the
// ceremony open, as any refused response does.
func TestSignInLooksTheAccountUpBeforeTheSignatureAndRefusesWhatItDeclines(t *testing.T) {
	rp := mustReady(t)
	u := testUser()
	fake := registerDiscoverable(t, rp, u)
	options, sealed := beginSignIn(t, rp)

	forged := passkeytest.New(rp.RPID(), rp.Origin())
	forged.UserHandle = []byte(u.ID)
	forgery, err := forged.AssertionResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	var asked [][]byte
	if _, _, err := rp.FinishSignIn(lookupOf(&asked, u), sealed, forgery); err == nil || errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		t.Fatalf("an assertion another key signed: error = %v, want a refusal that leaves the ceremony open", err)
	}
	if len(asked) != 1 {
		t.Errorf("lookup was called %d times for the forgery, want once, before the signature", len(asked))
	}

	genuine, err := fake.AssertionResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	asked = nil
	if _, _, err := rp.FinishSignIn(lookupOf(&asked), sealed, genuine); err == nil || errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		t.Fatalf("a handle that names no account: error = %v, want a refusal", err)
	}
	if len(asked) != 1 {
		t.Errorf("lookup was called %d times for an unknown handle, want once", len(asked))
	}
	if _, _, err := rp.FinishSignIn(lookupOf(&asked, u), sealed, genuine); err != nil {
		t.Fatalf("the genuine assertion on the same ceremony after those refusals: %v", err)
	}
}

func TestSignInRefusesWhatDidNotVerifyTheUser(t *testing.T) {
	rp := mustReady(t)
	u := testUser()
	fake := registerDiscoverable(t, rp, u)
	options, sealed := beginSignIn(t, rp)

	fake.NoUserVerification = true
	body, err := fake.AssertionResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	var asked [][]byte
	if _, _, err := rp.FinishSignIn(lookupOf(&asked, u), sealed, body); err == nil || errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		t.Fatalf("an assertion without user verification: error = %v, want it refused, ceremony left open", err)
	}
	fake.NoUserVerification = false
	if body, err = fake.AssertionResponse(options); err != nil {
		t.Fatal(err)
	}
	if _, assertion, err := rp.FinishSignIn(lookupOf(&asked, u), sealed, body); err != nil || !assertion.UserVerified {
		t.Fatalf("the same ceremony with user verification = %+v, %v; want it accepted", assertion, err)
	}
}

// The second-step ceremony asks for user verification and does not
// require it, and says what it saw.
func TestLoginReportsWhetherTheUserWasVerified(t *testing.T) {
	rp := mustReady(t)
	u := testUser()
	fake := passkeytest.New(rp.RPID(), rp.Origin())
	registerOn(t, rp, u, fake)
	for _, noUV := range []bool{false, true} {
		fake.NoUserVerification = noUV
		sealed, body := assertWith(t, rp, u, fake)
		got, err := rp.FinishLogin(u, sealed, body)
		if err != nil {
			t.Fatalf("FinishLogin (no UV: %v): %v", noUV, err)
		}
		if got.UserVerified == noUV {
			t.Errorf("UserVerified = %v with the authenticator's UV flag %v", got.UserVerified, !noUV)
		}
	}
}

func TestSignInRefusesAMissingUserHandleWithoutAskingLookup(t *testing.T) {
	rp := mustReady(t)
	u := testUser()
	fake := passkeytest.New(rp.RPID(), rp.Origin()) // no handle reported
	registerOn(t, rp, u, fake)
	options, sealed := beginSignIn(t, rp)
	body, err := fake.AssertionResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	var asked [][]byte
	if _, _, err := rp.FinishSignIn(lookupOf(&asked, u), sealed, body); err == nil {
		t.Fatal("an assertion with no user handle signed in")
	}
	if len(asked) != 0 {
		t.Errorf("lookup was asked about %q, want it not called with nothing to look up", asked)
	}
}

// A handle that names an account which does not hold the credential --
// another account's passkey, a stale one, or one on hold (not in
// Passkeys at all) -- is refused.
func TestSignInRefusesACredentialTheNamedAccountDoesNotUse(t *testing.T) {
	rp := mustReady(t)
	owner := testUser()
	fake := registerDiscoverable(t, rp, owner)
	other := &gauntlet.User{ID: "user-0002", Username: "frodo"}
	fake.UserHandle = []byte(other.ID) // claims to belong to another account

	t.Run("another account's passkey", func(t *testing.T) {
		options, sealed := beginSignIn(t, rp)
		body, err := fake.AssertionResponse(options)
		if err != nil {
			t.Fatal(err)
		}
		var asked [][]byte
		if _, _, err := rp.FinishSignIn(lookupOf(&asked, owner, other), sealed, body); err == nil {
			t.Fatal("a passkey signed in as an account it is not registered on")
		}
	})
	t.Run("stale and held passkeys", func(t *testing.T) {
		fake.UserHandle = []byte(owner.ID)
		stale := &gauntlet.User{ID: owner.ID, Username: owner.Username, Passkeys: []gauntlet.Passkey{owner.Passkeys[0]}}
		stale.Passkeys[0].RPID = "old.example.org"
		held := &gauntlet.User{ID: owner.ID, Username: owner.Username} // not in Passkeys until its codes are confirmed
		for name, account := range map[string]*gauntlet.User{"stale": stale, "held": held} {
			options, sealed := beginSignIn(t, rp)
			body, err := fake.AssertionResponse(options)
			if err != nil {
				t.Fatal(err)
			}
			var asked [][]byte
			if _, _, err := rp.FinishSignIn(lookupOf(&asked, account), sealed, body); err == nil {
				t.Errorf("a %s passkey signed in", name)
			}
		}
		options, sealed := beginSignIn(t, rp)
		body, err := fake.AssertionResponse(options)
		if err != nil {
			t.Fatal(err)
		}
		var asked [][]byte
		if _, _, err := rp.FinishSignIn(lookupOf(&asked, owner), sealed, body); err != nil {
			t.Fatalf("the live passkey on its own account: %v", err)
		}
	})
}

func TestSignInReplayAndCrossCeremony(t *testing.T) {
	rp := mustReady(t)
	u := testUser()
	fake := registerDiscoverable(t, rp, u)
	var asked [][]byte
	lookup := lookupOf(&asked, u)

	options, sealed := beginSignIn(t, rp)
	body, err := fake.AssertionResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := rp.FinishSignIn(lookup, sealed, body); err != nil {
		t.Fatalf("FinishSignIn: %v", err)
	}
	if _, _, err := rp.FinishSignIn(lookup, sealed, body); !errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		t.Errorf("a replayed sign-in: error = %v, want ErrPasskeyCeremonyInvalid", err)
	}

	// A second-step login's sealed state cannot sign in alone, nor can a
	// sign-in's finish a second-step login.
	loginSealed, loginBody := assertWith(t, rp, u, fake)
	if _, _, err := rp.FinishSignIn(lookup, loginSealed, loginBody); !errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		t.Errorf("FinishSignIn with a login's state: error = %v, want ErrPasskeyCeremonyInvalid", err)
	}
	options, signInSealed := beginSignIn(t, rp)
	if body, err = fake.AssertionResponse(options); err != nil {
		t.Fatal(err)
	}
	if _, err := rp.FinishLogin(u, signInSealed, body); !errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		t.Errorf("FinishLogin with a sign-in's state: error = %v, want ErrPasskeyCeremonyInvalid", err)
	}
	if _, _, err := rp.FinishSignIn(lookup, "garbage", body); !errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		t.Errorf("FinishSignIn with garbage state: error = %v, want ErrPasskeyCeremonyInvalid", err)
	}
}

// A regressed counter comes back as CloneWarning with the ceremony left
// open, as FinishLogin does.
func TestSignInCloneWarningDoesNotSpendTheChallenge(t *testing.T) {
	rp := mustReady(t)
	u := testUser()
	fake := registerDiscoverable(t, rp, u)
	u.Passkeys[0].SignCount = 5
	var asked [][]byte
	lookup := lookupOf(&asked, u)

	options, sealed := beginSignIn(t, rp)
	fake.SignCount = 3
	regressed, err := fake.AssertionResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	_, got, err := rp.FinishSignIn(lookup, sealed, regressed)
	if err != nil || !got.CloneWarning || got.SignCount != 3 {
		t.Fatalf("FinishSignIn(5 -> 3) = %+v, %v; want CloneWarning at the presented 3", got, err)
	}
	fake.SignCount = 6
	advanced, err := fake.AssertionResponse(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, got, err = rp.FinishSignIn(lookup, sealed, advanced); err != nil || got.CloneWarning || got.SignCount != 6 {
		t.Fatalf("FinishSignIn(5 -> 6) on the same ceremony = %+v, %v; want accepted", got, err)
	}
}

func TestSignInExpires(t *testing.T) {
	for _, wait := range []time.Duration{ceremonyLifetime - time.Second, ceremonyLifetime + time.Second} {
		expired := wait > ceremonyLifetime
		synctest.Test(t, func(t *testing.T) {
			rp := mustReady(t)
			u := testUser()
			fake := registerDiscoverable(t, rp, u)
			options, sealed := beginSignIn(t, rp)
			body, err := fake.AssertionResponse(options)
			if err != nil {
				t.Fatal(err)
			}
			time.Sleep(wait)
			var asked [][]byte
			_, _, err = rp.FinishSignIn(lookupOf(&asked, u), sealed, body)
			if expired != errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) || (!expired && err != nil) {
				t.Fatalf("FinishSignIn after %v: error = %v, want ErrPasskeyCeremonyInvalid: %v", wait, err, expired)
			}
		})
	}
}

func TestSignInNotReady(t *testing.T) {
	rp, err := New(Config{PublicURL: "https://192.0.2.10", DisplayName: testDisplayName})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := rp.BeginSignIn(); !errors.Is(err, ErrNotReady) {
		t.Errorf("BeginSignIn: %v, want ErrNotReady", err)
	}
	if _, _, err := rp.FinishSignIn(nil, "", nil); !errors.Is(err, ErrNotReady) {
		t.Errorf("FinishSignIn: %v, want ErrNotReady", err)
	}
}
