// Ported from mikroview's internal/api/webauthn_test.go (the five
// TestFakeAuthenticator* cases). They prove the fake against the real
// library, built with webauthn.New directly, not against gauntlet's own
// passkey package -- a fake proven only through the code it is meant to
// test would prove nothing.
package passkeytest

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	testRPID   = "passkeys.example.org"
	testOrigin = "https://passkeys.example.org"
)

// testUser is the minimal webauthn.User the ceremony functions need.
// credentials is set directly between the register and login steps,
// standing in for a store a real caller would reload.
type testUser struct {
	id          []byte
	credentials []webauthn.Credential
}

func (u *testUser) WebAuthnID() []byte                         { return u.id }
func (u *testUser) WebAuthnName() string                       { return "test-user" }
func (u *testUser) WebAuthnDisplayName() string                { return "Test User" }
func (u *testUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func mustLibrary(t *testing.T) *webauthn.WebAuthn {
	t.Helper()
	wa, err := webauthn.New(&webauthn.Config{RPID: testRPID, RPDisplayName: "Fake Test", RPOrigins: []string{testOrigin}})
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	return wa
}

// register runs a registration through the real library and returns the
// credential it produced, failing the test on any error.
func register(t *testing.T, wa *webauthn.WebAuthn, fake *FakeAuthenticator, user *testUser) *webauthn.Credential {
	t.Helper()
	creation, session, err := wa.BeginRegistration(user)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	body, err := fake.RegisterResponse(creation)
	if err != nil {
		t.Fatalf("RegisterResponse: %v", err)
	}
	req := httptest.NewRequest("POST", testOrigin+"/api/auth/passkeys/register/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	cred, err := wa.FinishRegistration(user, *session, req)
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	return cred
}

// login runs a login through the real library, returning the credential
// as it stands after the login so callers can inspect SignCount and
// CloneWarning.
func login(t *testing.T, wa *webauthn.WebAuthn, fake *FakeAuthenticator, user *testUser) (*webauthn.Credential, error) {
	t.Helper()
	assertion, session, err := wa.BeginLogin(user)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	body, err := fake.AssertionResponse(assertion)
	if err != nil {
		t.Fatalf("AssertionResponse: %v", err)
	}
	req := httptest.NewRequest("POST", testOrigin+"/api/auth/login/factor", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return wa.FinishLogin(user, *session, req)
}

func TestFakeAuthenticatorRegistrationAcceptedByRealLibrary(t *testing.T) {
	wa := mustLibrary(t)
	fake := New(testRPID, testOrigin)
	cred := register(t, wa, fake, &testUser{id: []byte("user-id-for-registration-test-0001")})
	if !bytes.Equal(cred.ID, fake.CredentialID()) {
		t.Fatalf("credential ID = %x, want %x", cred.ID, fake.CredentialID())
	}
	if cred.AttestationType != "basic_surrogate" {
		t.Fatalf("AttestationType = %q, want basic_surrogate (self-attested)", cred.AttestationType)
	}
}

// TestFakeAuthenticatorRegistrationRejectedOnWrongOrigin proves the fake
// can produce input the real library refuses, paired with the identical
// request succeeding at the right origin in the test above.
func TestFakeAuthenticatorRegistrationRejectedOnWrongOrigin(t *testing.T) {
	wa := mustLibrary(t)
	user := &testUser{id: []byte("user-id-for-wrong-origin-test-0001")}
	creation, session, err := wa.BeginRegistration(user)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	fake := New(testRPID, testOrigin)
	fake.Origin = "https://not-the-relying-party.example"
	body, err := fake.RegisterResponse(creation)
	if err != nil {
		t.Fatalf("RegisterResponse: %v", err)
	}
	req := httptest.NewRequest("POST", testOrigin+"/api/auth/passkeys/register/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if _, err := wa.FinishRegistration(user, *session, req); err == nil {
		t.Fatal("FinishRegistration succeeded with a response from the wrong origin, want an error")
	}
}

func TestFakeAuthenticatorLoginRoundTrip(t *testing.T) {
	wa := mustLibrary(t)
	fake := New(testRPID, testOrigin)
	user := &testUser{id: []byte("user-id-for-login-round-trip-0001")}
	user.credentials = []webauthn.Credential{*register(t, wa, fake, user)}

	// A zero-reporting platform authenticator: SignCount stays 0, and the
	// library must not treat 0 -> 0 as a clone.
	got, err := login(t, wa, fake, user)
	if err != nil {
		t.Fatalf("FinishLogin: unexpected error: %v", err)
	}
	if got.Authenticator.CloneWarning {
		t.Fatal("CloneWarning is true for a 0 -> 0 sign count, want false")
	}
	if got.Authenticator.SignCount != 0 {
		t.Fatalf("SignCount = %d, want 0", got.Authenticator.SignCount)
	}
}

// TestFakeAuthenticatorLoginRejectedOnWrongRPID mirrors the wrong-origin
// test for the login ceremony and the RP ID -- the library checks the
// two independently (the RP ID is hashed into the authenticator data,
// the origin is only in the client data).
func TestFakeAuthenticatorLoginRejectedOnWrongRPID(t *testing.T) {
	wa := mustLibrary(t)
	fake := New(testRPID, testOrigin)
	user := &testUser{id: []byte("user-id-for-wrong-rpid-test-00001")}
	user.credentials = []webauthn.Credential{*register(t, wa, fake, user)}

	fake.RPID = "not-the-relying-party.example"
	if _, err := login(t, wa, fake, user); err == nil {
		t.Fatal("FinishLogin succeeded with an assertion signed for the wrong RP ID, want an error")
	}
}

// TestFakeAuthenticatorCloneWarningOnRegressedSignCount: two logins in a
// row, the second reporting a lower count than the first, must come back
// with CloneWarning -- and the count must stay at the first login's 5,
// not move to the regressed 3.
func TestFakeAuthenticatorCloneWarningOnRegressedSignCount(t *testing.T) {
	wa := mustLibrary(t)
	fake := New(testRPID, testOrigin)
	user := &testUser{id: []byte("user-id-for-clone-warning-test-01")}
	user.credentials = []webauthn.Credential{*register(t, wa, fake, user)}

	fake.SignCount = 5
	afterFirst, err := login(t, wa, fake, user)
	if err != nil {
		t.Fatalf("first FinishLogin: unexpected error: %v", err)
	}
	if afterFirst.Authenticator.CloneWarning {
		t.Fatal("CloneWarning is true after the first login (5, up from registration's 0), want false")
	}
	if afterFirst.Authenticator.SignCount != 5 {
		t.Fatalf("SignCount after the first login = %d, want 5", afterFirst.Authenticator.SignCount)
	}

	user.credentials = []webauthn.Credential{*afterFirst}
	fake.SignCount = 3
	afterSecond, err := login(t, wa, fake, user)
	if err != nil {
		t.Fatalf("second FinishLogin: unexpected error: %v", err)
	}
	if !afterSecond.Authenticator.CloneWarning {
		t.Fatal("CloneWarning is false after a regressed sign count (5 -> 3), want true")
	}
	if afterSecond.Authenticator.SignCount != 5 {
		t.Fatalf("SignCount after the regressed login = %d, want 5 (unchanged)", afterSecond.Authenticator.SignCount)
	}
}
