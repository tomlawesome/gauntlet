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

// TestContractUnknownCredentialMember (#92): the 401 invalid-credentials
// answer of POST /api/auth/login/passkey names a passkey the server does
// not hold in a closed UnknownCredentialProblem, only when the user handle
// names one of its own accounts (T3); a handle naming no account (T2) and
// the refusal of a passkey it does hold (T6) stay a plain Problem. Any member beyond the documented
// ones fails the closed schema.
func TestContractUnknownCredentialMember(t *testing.T) {
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

	// The first passkey is removed (the admin keeps the second), so the
	// browser's copy of it is now one the server does not hold.
	c.do(admin, u, call{method: "DELETE", path: "/api/auth/passkeys/" + base64.RawURLEncoding.EncodeToString(removed.CredentialID()), body: passwordRequest{adminPass}}, 200, nil)

	finish := func(who *passkeytest.FakeAuthenticator) []byte {
		t.Helper()
		advance(6 * time.Minute)
		client := c.client()
		var options protocol.CredentialAssertion
		c.do(client, u, call{method: "POST", path: "/api/auth/login/passkey/begin"}, 200, &options)
		assertion, err := who.AssertionResponse(&options)
		if err != nil {
			t.Fatal(err)
		}
		_, raw := c.send(client, u, call{method: "POST", path: "/api/auth/login/passkey", body: loginPasskeyRequest{assertion}})
		return raw
	}
	t1 := finish(removed) // T1: a passkey the server no longer holds
	noUV := *kept
	noUV.NoUserVerification = true
	t6 := finish(&noUV) // T6: a passkey it holds, refused for a wrong assertion

	// T2: a handle naming no account. T3: a credential nobody holds,
	// presented with the admin's own handle.
	unknownHandle := passkeytest.New("passkeys.example.org", publicURL)
	unknownHandle.UserHandle = []byte("no-such-account")
	t2 := finish(unknownHandle)
	strangerOnAccount := *unknownHandle
	strangerOnAccount.UserHandle = []byte(adminUser.ID)
	t3 := finish(&strangerOnAccount)

	doc := c.doc
	named := doc.Components.Schemas["UnknownCredentialProblem"]
	if named == nil || named.Value == nil {
		t.Fatalf("docs/api/auth.yaml has no components.schemas.UnknownCredentialProblem; T1's body is %s", t1)
	}
	plain := doc.Components.Schemas["Problem"]
	validate := func(what string, schema *openapi3.SchemaRef, raw []byte, wantValid bool) {
		t.Helper()
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("%s: %v: %s", what, err, raw)
		}
		err := schema.Value.VisitJSON(v, openapi3.MultiErrors())
		if wantValid && err != nil {
			t.Errorf("%s does not validate: %v: %s", what, err, raw)
		}
		if !wantValid && err == nil {
			t.Errorf("%s validates, want it refused: %s", what, raw)
		}
	}
	// T15: T1's body is the closed UnknownCredentialProblem and, being
	// closed, is not a plain Problem; T6's body is a plain Problem and has
	// no member to fit the closed one.
	validate("T1 body against UnknownCredentialProblem", named, t1, true)
	validate("T1 body against Problem (the member must not slip into the open class)", plain, t1, false)
	validate("T6 body against Problem", plain, t6, true)

	// T20: T2's body is a plain Problem and not the closed
	// UnknownCredentialProblem, and is T6's body byte for byte; T3's body is
	// the closed UnknownCredentialProblem.
	validate("T2 body against Problem", plain, t2, true)
	validate("T2 body against UnknownCredentialProblem (an unknown handle must not be named)", named, t2, false)
	if string(t2) != string(t6) {
		t.Errorf("T2 body = %s, want T6's %s byte for byte", t2, t6)
	}
	validate("T3 body against UnknownCredentialProblem", named, t3, true)
	validate("T3 body against Problem (the member must not slip into the open class)", plain, t3, false)

	// Any other extra member fails the closed schema.
	var withExtra map[string]any
	if err := json.Unmarshal(t1, &withExtra); err != nil {
		t.Fatal(err)
	}
	withExtra["extra"] = true
	extra, _ := json.Marshal(withExtra)
	validate("T1 body plus an undocumented member", named, extra, false)
	var inner map[string]any
	if err := json.Unmarshal(t1, &inner); err != nil {
		t.Fatal(err)
	}
	if m, ok := inner["unknownCredential"].(map[string]any); ok {
		m["extra"] = true
		extraInner, _ := json.Marshal(inner)
		validate("T1 body plus an undocumented member inside unknownCredential", named, extraInner, false)
	}

	// The 401 of login/passkey admits it: the operation's response schema
	// accepts T1's body and T6's.
	op := doc.Paths.Find("/api/auth/login/passkey").Post
	resp401 := op.Responses.Status(http.StatusUnauthorized)
	if resp401 == nil || resp401.Value == nil {
		t.Fatal("login/passkey documents no 401")
	}
	media := resp401.Value.Content.Get("application/problem+json")
	if media == nil {
		t.Fatal("login/passkey's 401 documents no application/problem+json body")
	}
	validate("T1 body against login/passkey's 401", media.Schema, t1, true)
	validate("T6 body against login/passkey's 401", media.Schema, t6, true)
	validate("T2 body against login/passkey's 401", media.Schema, t2, true)
	validate("T3 body against login/passkey's 401", media.Schema, t3, true)
}
