package gate

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// A3b-R1 (#80). An enrolment begun while another second factor was live
// is an "additional factor": live at once, no new codes, alreadyIssued.
// If that other factor is removed before the enrolment finishes (removal
// clears the recovery codes), the route must not make the new factor
// live with no codes behind it. It holds the new factor as the account's
// first one: 200, ten codes, pendingConfirmation, nothing live until the
// enrolment is confirmed -- exactly as for a first factor.
//
// The removal goes through the store: the delete routes end every
// session when they take an account's last factor, which would end the
// very session the enrolment is finishing on.

// factorFallbackSeedTOTP gives the account a live authenticator app and
// the recovery codes that back it.
func factorFallbackSeedTOTP(t *testing.T, g *Gate, id string) {
	t.Helper()
	now := time.Now()
	if err := g.deps.Users.SetPendingTOTPSecretAt(id, raceTOTPSecret, now); err != nil {
		t.Fatalf("seeding a pending authenticator app: %v", err)
	}
	if err := g.deps.Users.ConfirmTOTP(id, now, 42); err != nil {
		t.Fatalf("confirming the authenticator app: %v", err)
	}
	if _, err := g.deps.Users.GenerateRecoveryCodes(id, now); err != nil {
		t.Fatalf("seeding recovery codes: %v", err)
	}
}

// factorFallbackConfirmTOTP posts a valid code for the pending secret
// seeded by factorFallbackSeedPending and decodes the answer.
func factorFallbackConfirmTOTP(t *testing.T, client *http.Client, ts *httptest.Server) totpConfirmResponse {
	t.Helper()
	secret, err := gauntlet.DecodeTOTPSecret(raceTOTPSecret)
	if err != nil {
		t.Fatal(err)
	}
	resp := postJSON(t, client, ts.URL+totpConfirmPath,
		totpConfirmRequest{Code: gauntlet.GenerateTOTPCode(secret, totpCounterNow(time.Now()))})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("totp/confirm returned %d, want 200: %s", resp.StatusCode, body)
	}
	var out totpConfirmResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAPasskeyEnrolmentWhoseOtherFactorWentIsHeldWithCodes(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	id := passkeyBilboID(t, g)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	factorFallbackSeedTOTP(t, g, id)

	fake := newFake(g)
	creation := passkeyRegisterBegin(t, bilbo, ts)

	// The authenticator app goes before the passkey ceremony finishes;
	// its removal takes the recovery codes with it.
	if err := g.deps.Users.ClearTOTP(id); err != nil {
		t.Fatalf("removing the authenticator app: %v", err)
	}
	if u, _ := g.deps.Users.Get(id); u.HasSecondFactor() || len(u.RecoveryCodes) != 0 {
		t.Fatalf("setup: after the removal factor=%v codes=%d, want neither", u.HasSecondFactor(), len(u.RecoveryCodes))
	}

	out := passkeyRegisterFinishOK(t, bilbo, ts, fake, creation, "late key")
	if !out.PendingConfirmation || len(out.RecoveryCodes) != 10 || out.AlreadyIssued {
		t.Fatalf("register/finish = %+v, want ten codes, pendingConfirmation, not alreadyIssued", out)
	}

	u, ok := g.deps.Users.Get(id)
	if !ok {
		t.Fatal("the account vanished")
	}
	if u.HasSecondFactor() || len(u.Passkeys) != 0 {
		t.Errorf("while held: live factor=%v live passkeys=%d, want none", u.HasSecondFactor(), len(u.Passkeys))
	}
	if u.HeldEnrolment == nil || u.HeldEnrolment.Passkey == nil {
		t.Fatalf("the passkey is not held: %+v", u.HeldEnrolment)
	}
	if storedPasskeys(g, id) != 1 {
		t.Errorf("stored passkeys = %d, want the one held", storedPasskeys(g, id))
	}
	// The invariant holds while held: no live factor, no live codes.
	wantRecoveryCodesToMatchFactors(t, g, id, "passkey held after the app went")

	confirmEnrolmentOK(t, bilbo, ts)
	u, _ = g.deps.Users.Get(id)
	if !u.HasSecondFactor() || len(u.Passkeys) != 1 || len(u.RecoveryCodes) != 10 || u.HeldEnrolment != nil {
		t.Errorf("after confirming: factor=%v passkeys=%d codes=%d held=%+v, want a live passkey with ten codes and no hold",
			u.HasSecondFactor(), len(u.Passkeys), len(u.RecoveryCodes), u.HeldEnrolment)
	}
	wantRecoveryCodesToMatchFactors(t, g, id, "passkey confirmed after the app went")
}

// The control: the same setup without the removal is an additional
// factor -- live at once, no new codes, the existing codes untouched.
func TestAPasskeyEnrolmentWhoseOtherFactorStandsIsAnAdditionalFactor(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	id := passkeyBilboID(t, g)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	factorFallbackSeedTOTP(t, g, id)
	before, _ := g.deps.Users.Get(id)

	fake := newFake(g)
	creation := passkeyRegisterBegin(t, bilbo, ts)
	out := passkeyRegisterFinishOK(t, bilbo, ts, fake, creation, "second factor")
	if out.PendingConfirmation || out.RecoveryCodes != nil || !out.AlreadyIssued {
		t.Fatalf("register/finish = %+v, want live, no codes, alreadyIssued", out)
	}

	after, _ := g.deps.Users.Get(id)
	if len(after.Passkeys) != 1 || !after.HasActiveTOTP() || after.HeldEnrolment != nil {
		t.Errorf("passkeys=%d totp=%v held=%+v, want the passkey live beside the app and no hold",
			len(after.Passkeys), after.HasActiveTOTP(), after.HeldEnrolment)
	}
	if !reflect.DeepEqual(before.RecoveryCodes, after.RecoveryCodes) {
		t.Error("the existing recovery codes changed")
	}
	wantRecoveryCodesToMatchFactors(t, g, id, "additional passkey")
}

func TestATOTPEnrolmentWhoseOtherFactorWentIsHeldWithCodes(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	id := passkeyBilboID(t, g)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	now := time.Now()
	raceSeedPasskey(t, g, id, now)
	if err := g.deps.Users.SetPendingTOTPSecretAt(id, raceTOTPSecret, now); err != nil {
		t.Fatalf("seeding a pending authenticator app: %v", err)
	}

	// The passkey goes before the app is confirmed; its removal takes
	// the recovery codes with it.
	if _, err := g.deps.Users.DeletePasskey(id, []byte{1}); err != nil {
		t.Fatalf("removing the passkey: %v", err)
	}
	if u, _ := g.deps.Users.Get(id); u.HasSecondFactor() || len(u.RecoveryCodes) != 0 {
		t.Fatalf("setup: after the removal factor=%v codes=%d, want neither", u.HasSecondFactor(), len(u.RecoveryCodes))
	}

	out := factorFallbackConfirmTOTP(t, bilbo, ts)
	if !out.PendingConfirmation || out.Enabled || out.AlreadyIssued || len(out.RecoveryCodes) != 10 {
		t.Fatalf("totp/confirm = %+v, want ten codes, pendingConfirmation, not enabled, not alreadyIssued", out)
	}

	u, _ := g.deps.Users.Get(id)
	if u.HasActiveTOTP() || u.HasSecondFactor() {
		t.Errorf("while held: active app=%v live factor=%v, want neither", u.HasActiveTOTP(), u.HasSecondFactor())
	}
	if u.HeldEnrolment == nil {
		t.Fatal("the authenticator app is not held")
	}
	wantRecoveryCodesToMatchFactors(t, g, id, "app held after the passkey went")

	confirmEnrolmentOK(t, bilbo, ts)
	u, _ = g.deps.Users.Get(id)
	if !u.HasActiveTOTP() || !u.HasSecondFactor() || len(u.RecoveryCodes) != 10 || u.HeldEnrolment != nil {
		t.Errorf("after confirming: app=%v factor=%v codes=%d held=%+v, want a live app with ten codes and no hold",
			u.HasActiveTOTP(), u.HasSecondFactor(), len(u.RecoveryCodes), u.HeldEnrolment)
	}
	wantRecoveryCodesToMatchFactors(t, g, id, "app confirmed after the passkey went")
}

// The control: the same setup without the removal is an additional
// factor -- live at once, no new codes, the existing codes untouched.
func TestATOTPEnrolmentWhoseOtherFactorStandsIsAnAdditionalFactor(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	id := passkeyBilboID(t, g)
	bilbo := loggedInClient(t, ts, passkeyBilboUsername, passkeyBilboPassword)
	now := time.Now()
	raceSeedPasskey(t, g, id, now)
	if err := g.deps.Users.SetPendingTOTPSecretAt(id, raceTOTPSecret, now); err != nil {
		t.Fatalf("seeding a pending authenticator app: %v", err)
	}
	before, _ := g.deps.Users.Get(id)

	out := factorFallbackConfirmTOTP(t, bilbo, ts)
	if !out.Enabled || out.PendingConfirmation || out.RecoveryCodes != nil || !out.AlreadyIssued {
		t.Fatalf("totp/confirm = %+v, want enabled, no codes, alreadyIssued", out)
	}

	after, _ := g.deps.Users.Get(id)
	if !after.HasActiveTOTP() || len(after.Passkeys) != 1 || after.HeldEnrolment != nil {
		t.Errorf("app=%v passkeys=%d held=%+v, want the app live beside the passkey and no hold",
			after.HasActiveTOTP(), len(after.Passkeys), after.HeldEnrolment)
	}
	if !reflect.DeepEqual(before.RecoveryCodes, after.RecoveryCodes) {
		t.Error("the existing recovery codes changed")
	}
	wantRecoveryCodesToMatchFactors(t, g, id, "additional app")
}

// A3b-R1 (#80), the race itself. The handlers re-read the account at
// finish time, so the hold is only reached for certain when the other
// factor goes between that read and the write. Each round, an account
// with a live authenticator app and its codes has begun a passkey
// registration; the finish is raced against removing the app (through
// the store: the delete route would end the finishing session). Either
// order is legal; the codes must match the factors afterwards.
func TestAdditionalPasskeyRacingTheRemovalOfTheOnlyOtherFactorKeepsRecoveryCodesConsistent(t *testing.T) {
	g, ts, _ := passkeyFixture(t)
	id := passkeyBilboID(t, g)
	for round := range factorRaceRounds {
		client := raceFixtureReset(t, g, ts, id)
		factorFallbackSeedTOTP(t, g, id)
		fake := newFake(g)
		creation := passkeyRegisterBegin(t, client, ts)
		cred, err := fake.RegisterResponse(creation)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		var finishStatus int
		var finishErr, clearErr error
		raceTogether(
			func() {
				finishStatus, finishErr = factorRaceRequest(client, http.MethodPost,
					ts.URL+"/api/auth/passkeys/register/finish",
					passkeyRegisterFinishRequest{Credential: json.RawMessage(cred), Name: "racing key"})
			},
			func() { clearErr = g.deps.Users.ClearTOTP(id) },
		)
		if finishErr != nil {
			t.Fatalf("round %d: transport error: %v", round, finishErr)
		}
		if clearErr != nil {
			t.Fatalf("round %d: removing the authenticator app: %v", round, clearErr)
		}
		if finishStatus >= 500 {
			t.Errorf("round %d: register/finish answered %d", round, finishStatus)
		}
		wantRecoveryCodesToMatchFactors(t, g, id, fmt.Sprintf("round %d (register/finish %d)", round, finishStatus))
		if t.Failed() {
			return
		}
	}
}
