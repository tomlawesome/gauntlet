package contracttest

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-webauthn/webauthn/protocol"

	"github.com/tomlawesome/gauntlet/internal/passkeytest"
)

// TestContractReauthenticateUnknownCredentialMember (#92, decision 7a):
// the 401 invalid-credentials answer of POST /api/auth/reauthenticate to
// an {assertion} for a passkey the timed-out session's own account no
// longer holds names it, and the operation's 401 response schema accepts
// that body, as login/passkey's does.
func TestContractReauthenticateUnknownCredentialMember(t *testing.T) {
	const adminPass = "contract-admin-password"
	const publicURL = "https://passkeys.example.org"
	c := newContractChecker(t)

	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); defer mu.Unlock(); now = now.Add(d) }
	f, ts, admin := passkeySignInGate(t, c, publicURL, true, clock)
	u := ts.URL

	register := func(fake *passkeytest.FakeAuthenticator, confirm bool) {
		t.Helper()
		var creation protocol.CredentialCreation
		c.do(admin, u, call{method: "POST", path: "/api/auth/passkeys/register/begin", body: passwordRequest{adminPass}}, 200, &creation)
		regBody, err := fake.RegisterResponse(&creation)
		if err != nil {
			t.Fatal(err)
		}
		c.do(admin, u, call{method: "POST", path: "/api/auth/passkeys/register/finish", body: passkeyRegisterFinishRequest{json.RawMessage(regBody), "key"}}, 200, nil)
		if confirm {
			c.do(admin, u, call{method: "POST", path: enrolmentConfirmPath}, 200, nil)
		}
	}
	removed := passkeytest.New("passkeys.example.org", publicURL)
	kept := passkeytest.New("passkeys.example.org", publicURL)
	register(removed, true)
	register(kept, false)
	adminUser, ok := f.users.ByUsername("admin")
	if !ok {
		t.Fatal("admin was not created")
	}
	removed.UserHandle = []byte(adminUser.ID)
	kept.UserHandle = []byte(adminUser.ID)

	// The first passkey is removed (the admin keeps the second), then the
	// admin's session, signed in by password, times out inside its ceiling.
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/passkeys/" + base64.RawURLEncoding.EncodeToString(removed.CredentialID()), body: passwordRequest{adminPass}}, 200, nil)
	advance(2 * time.Hour)
	var state map[string]any
	c.do(admin, u, call{method: "GET", path: "/api/auth/session"}, 200, &state)
	if state["authenticated"] != false || state["resumable"] != true {
		t.Fatalf("a timed-out session reports %v, want unauthenticated and resumable", state)
	}

	var options protocol.CredentialAssertion
	c.do(admin, u, call{method: "POST", path: "/api/auth/login/passkey/begin"}, 200, &options)
	assertion, err := removed.AssertionResponse(&options)
	if err != nil {
		t.Fatal(err)
	}
	resp, raw := c.send(admin, u, call{method: "POST", path: "/api/auth/reauthenticate", body: reauthenticateRequest{Assertion: assertion}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reauthenticate with a removed passkey = %d %s, want 401", resp.StatusCode, raw)
	}

	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	if _, has := body["unknownCredential"]; !has {
		t.Errorf("the 401 names no credential, want the unknownCredential member: %s", raw)
		// Check the document against the body it should have, too.
		body["unknownCredential"] = map[string]any{"rpId": "passkeys.example.org", "credentialId": base64.RawURLEncoding.EncodeToString(removed.CredentialID())}
	}

	op := c.doc.Paths.Find("/api/auth/reauthenticate").Post
	resp401 := op.Responses.Status(http.StatusUnauthorized)
	if resp401 == nil || resp401.Value == nil {
		t.Fatal("reauthenticate documents no 401")
	}
	media := resp401.Value.Content.Get("application/problem+json")
	if media == nil {
		t.Fatal("reauthenticate's 401 documents no application/problem+json body")
	}
	if err := media.Schema.Value.VisitJSON(body, openapi3.MultiErrors()); err != nil {
		t.Errorf("the named 401 does not validate against reauthenticate's 401 schema: %v: %s", err, raw)
	}

	// Closed, as login/passkey's: an undocumented member beside it fails.
	body["extra"] = true
	if err := media.Schema.Value.VisitJSON(body, openapi3.MultiErrors()); err == nil {
		t.Errorf("reauthenticate's 401 schema accepts an undocumented member: %s", raw)
	}
}
