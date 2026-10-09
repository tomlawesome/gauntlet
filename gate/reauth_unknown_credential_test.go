// A passkey the server does not hold is named when it fails to resume a
// timed-out session (#92, owner decision 7a). The {assertion} branch of
// POST /api/auth/reauthenticate answers its 401 invalid-credentials with
// the same "unknownCredential" member as login/passkey:
//
//	"unknownCredential": {"rpId": "<the relying party's ID>", "credentialId": "<base64url, no padding>"}
//
// but only when the assertion's user handle is the timed-out session's own
// account and that account holds no passkey with the credential ID (live,
// registered under another RP ID, or held). A handle for any other account
// is never named: that passkey may be good for its own account. Written
// from the design on the issue; the cases are T13a-T13f.
package gate

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
)

// wantResumeNamesCredential fails unless the 401 invalid-credentials body
// names fake's credential under rpID, in exactly the two documented
// fields, with today's four members beside it.
func wantResumeNamesCredential(t *testing.T, body []byte, rpID string, wantID []byte) {
	t.Helper()
	members := bodyMembers(t, string(body))
	if got, want := sortedKeys(members), []string{"detail", "status", "title", "type", unknownCredentialKey}; !slices.Equal(got, want) {
		t.Errorf("body members = %v, want exactly %v: %s", got, want, body)
	}
	raw, has := members[unknownCredentialKey]
	if !has {
		t.Errorf("body has no %q member: %s", unknownCredentialKey, body)
		return
	}
	var got unknownCredentialPayload
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Errorf("decoding %q: %v: %s", unknownCredentialKey, err, raw)
		return
	}
	want := unknownCredentialPayload{RPID: rpID, CredentialID: base64.RawURLEncoding.EncodeToString(wantID)}
	if got != want {
		t.Errorf("%s = %+v, want %+v", unknownCredentialKey, got, want)
	}
}

// wantResumeNamesNothing fails if the body carries the member.
func wantResumeNamesNothing(t *testing.T, body []byte) {
	t.Helper()
	if _, has := bodyMembers(t, string(body))[unknownCredentialKey]; has {
		t.Errorf("body names a credential, want today's body without %q: %s", unknownCredentialKey, body)
	}
}

// removeBilboPasskeyFromStore deletes bilbo's passkey straight from the
// store, so the timed-out session that signed in with it survives.
func removeBilboPasskeyFromStore(t *testing.T, e *aloneEnv) {
	t.Helper()
	if _, err := e.g.deps.Users.DeletePasskey(e.id, e.fake.CredentialID()); err != nil {
		t.Fatalf("deleting bilbo's passkey from the store: %v", err)
	}
	if n := e.g.deps.Users.PasskeyCount(e.id); n != 0 {
		t.Fatalf("bilbo still holds %d passkeys", n)
	}
}

// T13a: bilbo's session timed out and his passkey was removed meanwhile.
// The refusal to resume names it, with the relying party's ID.
func TestReauthUnknownCredentialRemovedPasskeyIsNamed(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	c, _ := e.timedOutPasskeySession(t)
	removeBilboPasskeyFromStore(t, e)
	if st := sessionState(t, c, e.ts); st["resumable"] != true {
		t.Fatalf("session state after the removal = %v, want still resumable", st)
	}

	resp, body := e.reauthAssertion(t, c, e.fake)
	wantResumeProblem(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
	rpID := e.g.deps.Passkeys.RPID()
	if rpID == "" {
		t.Fatal("the relying party has no ID")
	}
	wantResumeNamesCredential(t, body, rpID, e.fake.CredentialID())
	if got := protectedStatus(t, c, e.ts); got != http.StatusUnauthorized {
		t.Errorf("a removed passkey resumed the session: %d", got)
	}
}

// T13b: frodo's good passkey, presented on bilbo's timed-out session, is
// refused without naming it: it may be good for frodo's own account.
func TestReauthUnknownCredentialAnotherAccountsPasskeyIsNotNamed(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	frodo, _ := e.registerFrodo(t)
	c, _ := e.timedOutPasskeySession(t)

	resp, body := e.reauthAssertion(t, c, frodo)
	wantResumeProblem(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
	wantResumeNamesNothing(t, body)
}

// T13b (variant): the same holds when bilbo's own passkey is gone, so a
// foreign credential cannot be told apart by the member either.
func TestReauthUnknownCredentialAnotherAccountsPasskeyIsNotNamedWhenBilboHasNone(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	frodo, _ := e.registerFrodo(t)
	c, _ := e.timedOutPasskeySession(t)
	removeBilboPasskeyFromStore(t, e)

	resp, body := e.reauthAssertion(t, c, frodo)
	wantResumeProblem(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
	wantResumeNamesNothing(t, body)
}

// T13c: a user handle that names no account is not named either.
func TestReauthUnknownCredentialUnknownHandleIsNotNamed(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	c, _ := e.timedOutPasskeySession(t)
	unknown := newFake(e.g)
	unknown.UserHandle = []byte(unknownAccountHandle)

	resp, body := e.reauthAssertion(t, c, unknown)
	wantResumeProblem(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
	wantResumeNamesNothing(t, body)
}

// T13d: bilbo holds the passkey and the assertion is refused (the user
// was not verified): no member, and the same body as an unknown handle's.
func TestReauthUnknownCredentialHeldPasskeyRefusedIsNotNamed(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	c, _ := e.timedOutPasskeySession(t)

	unknown := newFake(e.g)
	unknown.UserHandle = []byte(unknownAccountHandle)
	resp, unknownBody := e.reauthAssertion(t, c, unknown)
	wantResumeProblem(t, resp, unknownBody, http.StatusUnauthorized, classInvalidCredentials)
	wantResumeNamesNothing(t, unknownBody)

	e.fake.NoUserVerification = true
	resp, body := e.reauthAssertion(t, c, e.fake)
	wantResumeProblem(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
	wantResumeNamesNothing(t, body)
	if string(body) != string(unknownBody) {
		t.Errorf("a held passkey refused got %s, want the unknown handle's %s", body, unknownBody)
	}
}

// T13e: the password branch answers a wrong password with today's body.
func TestReauthUnknownCredentialWrongPasswordIsNotNamed(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	c, _ := e.timedOutPasskeySession(t)
	removeBilboPasskeyFromStore(t, e)

	resp, body := e.reauthWith(t, c, reauthenticateRequest{Password: "wrong-password-placeholder"})
	wantResumeProblem(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
	wantResumeNamesNothing(t, body)
}

// T13f: a dead ceremony is step-expired and names nothing, even for the
// removed passkey of the session's own account.
func TestReauthUnknownCredentialDeadCeremonyIsNotNamed(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	c, _ := e.timedOutPasskeySession(t)
	removeBilboPasskeyFromStore(t, e)
	options, _ := e.mustBegin(t, c)
	assertion := signInAssertionBody(t, e.fake, options)

	// No ceremony cookie is sent: only the session cookie.
	resp, body := withCookie(t, e.ts, http.MethodPost, reauthenticatePath, sessionCookie(t, c, e.ts), reauthenticateRequest{Assertion: assertion})
	wantResumeProblem(t, resp, body, http.StatusUnauthorized, classStepExpired)
	wantResumeNamesNothing(t, body)
}
