// A passkey the server does not hold is named in the refusal (#92). The
// 401 invalid-credentials answer of POST /api/auth/login/passkey carries
// one extra RFC 9457 member, "unknownCredential", shaped as the argument
// of the browser's PublicKeyCredential.signalUnknownCredential() (W3C
// WebAuthn Level 3 section 5.1.10.2):
//
//	"unknownCredential": {"rpId": "<the relying party's ID>", "credentialId": "<base64url, no padding>"}
//
// It is present only when the assertion's rawId decoded to a non-empty ID
// and the account the user handle names either does not exist or holds no
// passkey with that ID in any form (live, registered under another RP ID,
// or held for its recovery codes). Everywhere else the body is today's.
// Written from the design on the issue; the cases are T1-T12 and T14, with
// T13 (reauthenticate) left out until the owner decides it.
package gate

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/internal/passkeytest"
)

const (
	unknownCredentialKey = "unknownCredential"
	todaysPasskeyDetail  = "that passkey couldn't be verified -- use another way in"
	todaysRefusalTitle   = "Invalid credentials"
	unknownAccountHandle = "no-such-account"
)

// unknownCredentialPayload is the member's two fields. Decoding is strict,
// so a third field fails the test.
type unknownCredentialPayload struct {
	RPID         string `json:"rpId"`
	CredentialID string `json:"credentialId"`
}

// bodyMembers decodes body as a JSON object, member by member.
func bodyMembers(t *testing.T, body string) map[string]json.RawMessage {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &members); err != nil {
		t.Fatalf("decoding a problem body: %v: %s", err, body)
	}
	return members
}

func sortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// wantTodaysFields fails unless the members type, title, status and
// detail are the invalid-credentials answer of login/passkey.
func wantTodaysFields(t *testing.T, members map[string]json.RawMessage, body string) {
	t.Helper()
	var got struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}
	raw, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decoding the problem fields: %v: %s", err, body)
	}
	if got.Type != problemTypeBase+classInvalidCredentials.anchor || got.Title != todaysRefusalTitle ||
		got.Status != http.StatusUnauthorized || got.Detail != todaysPasskeyDetail {
		t.Errorf("fields = %+v, want invalid-credentials, %q, 401, %q: %s", got, todaysRefusalTitle, todaysPasskeyDetail, body)
	}
}

// wantNoUnknownCredential fails unless body is exactly today's four-member
// refusal, with no unknownCredential member and nothing else added.
func wantNoUnknownCredential(t *testing.T, body string) {
	t.Helper()
	members := bodyMembers(t, body)
	if _, has := members[unknownCredentialKey]; has {
		t.Errorf("body names a credential, want today's body without %q: %s", unknownCredentialKey, body)
	}
	if got, want := sortedKeys(members), []string{"detail", "status", "title", "type"}; !slices.Equal(got, want) {
		t.Errorf("body members = %v, want exactly %v: %s", got, want, body)
	}
}

// wantUnknownCredential fails unless body is today's four members plus
// unknownCredential naming rpID and fake's credential ID (base64url, no
// padding), and nothing else.
func wantUnknownCredential(t *testing.T, body, rpID string, fake *passkeytest.FakeAuthenticator) {
	t.Helper()
	members := bodyMembers(t, body)
	if got, want := sortedKeys(members), []string{"detail", "status", "title", "type", unknownCredentialKey}; !slices.Equal(got, want) {
		t.Errorf("body members = %v, want exactly %v: %s", got, want, body)
	}
	wantTodaysFields(t, members, body)
	raw, has := members[unknownCredentialKey]
	if !has {
		t.Errorf("body has no %q member: %s", unknownCredentialKey, body)
		return
	}
	var got unknownCredentialPayload
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&got); err != nil {
		t.Errorf("decoding %q: %v: %s", unknownCredentialKey, err, raw)
		return
	}
	want := unknownCredentialPayload{RPID: rpID, CredentialID: base64.RawURLEncoding.EncodeToString(fake.CredentialID())}
	if got != want {
		t.Errorf("%s = %+v, want %+v", unknownCredentialKey, got, want)
	}
	if strings.ContainsAny(got.CredentialID, "=+/") {
		t.Errorf("credentialId %q is not unpadded base64url", got.CredentialID)
	}
}

// attemptWith is begin and finish from c with fake, returning begin's rpId.
func (e *aloneEnv) attemptWith(t *testing.T, c *http.Client, fake *passkeytest.FakeAuthenticator) (string, *http.Response, string) {
	t.Helper()
	options, _ := e.mustBegin(t, c)
	resp, body := e.finish(t, c, signInAssertionBody(t, fake, options))
	return options.Response.RelyingPartyID, resp, body
}

// removeBilboPasskey deletes bilbo's passkey the way he would, from his
// own signed-in session.
func removeBilboPasskey(t *testing.T, e *aloneEnv) {
	t.Helper()
	if status, body := deletePasskey(t, e.bilbo, e.ts, e.fake, passkeyBilboPassword); status != http.StatusOK {
		t.Fatalf("deleting bilbo's passkey = %d %s, want 200", status, body)
	}
}

// refusedWith runs the sign-in and requires 401 invalid-credentials.
func (e *aloneEnv) refusedWith(t *testing.T, fake *passkeytest.FakeAuthenticator) (rpID string, resp *http.Response, body string) {
	t.Helper()
	rpID, resp, body = e.attemptWith(t, newBrowserJar(t), fake)
	wantStatusClass(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
	return rpID, resp, body
}

// frodoWithHeldPasskey makes frodo with a first passkey held for his
// recovery codes (not yet live), returning his browser and the fake.
func (e *aloneEnv) frodoWithHeldPasskey(t *testing.T) (*http.Client, *passkeytest.FakeAuthenticator) {
	t.Helper()
	_ = postJSON(t, e.admin, e.ts.URL+"/api/auth/users",
		createUserRequest{Username: passkeyFrodoUsername, Password: passkeyFrodoPassword, Role: "user"}).Body.Close()
	frodo := loggedInClient(t, e.ts, passkeyFrodoUsername, passkeyFrodoPassword)
	resp := postJSON(t, frodo, e.ts.URL+"/api/auth/passkeys/register/begin", passkeyRegisterBeginRequest{Password: passkeyFrodoPassword})
	var creation protocol.CredentialCreation
	if err := json.NewDecoder(resp.Body).Decode(&creation); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	held := newFake(e.g)
	out := passkeyRegisterFinishOK(t, frodo, e.ts, held, &creation, "held")
	if !out.PendingConfirmation {
		t.Fatal("frodo's first passkey was not held for its codes")
	}
	u, ok := e.g.deps.Users.ByUsername(passkeyFrodoUsername)
	if !ok {
		t.Fatal("frodo was not created")
	}
	held.UserHandle = []byte(u.ID)
	return frodo, held
}

// -- T1 ----------------------------------------------------------------------

// T1: the passkey was removed; the browser still offers it. The refusal
// names it, with begin's own rpId, and changes nothing else.
func TestUnknownCredentialRemovedPasskeyIsNamed(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	removeBilboPasskey(t, e)

	rpID, resp, body := e.refusedWith(t, e.fake)
	if rpID == "" || rpID != e.g.deps.Passkeys.RPID() {
		t.Fatalf("begin offered rpId %q, want the relying party's %q", rpID, e.g.deps.Passkeys.RPID())
	}
	wantUnknownCredential(t, body, rpID, e.fake)
	if got := resp.Header.Get("WWW-Authenticate"); got != `Bearer realm="gate"` {
		t.Errorf("WWW-Authenticate = %q, want Bearer realm=\"gate\" unchanged", got)
	}
}

// -- T2, T3 ------------------------------------------------------------------

// T2: a user handle that names no account still gets the member, with the
// credential the browser presented.
func TestUnknownCredentialUnknownHandleIsNamed(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	unknown := newFake(e.g)
	unknown.UserHandle = []byte(unknownAccountHandle)

	rpID, _, body := e.refusedWith(t, unknown)
	wantUnknownCredential(t, body, rpID, unknown)
}

// T3: a credential bilbo's account does not hold, presented with his
// handle, answers byte for byte like the same credential with an unknown
// handle: the member says nothing of whether the account exists.
func TestUnknownCredentialForeignCredentialAnswersLikeAnUnknownHandle(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	fake := newFake(e.g)

	fake.UserHandle = []byte(unknownAccountHandle)
	rpID, _, unknownBody := e.refusedWith(t, fake)
	wantUnknownCredential(t, unknownBody, rpID, fake)

	fake.UserHandle = []byte(e.id)
	_, _, foreignBody := e.refusedWith(t, fake)
	wantUnknownCredential(t, foreignBody, rpID, fake)
	if foreignBody != unknownBody {
		t.Errorf("a credential the account does not hold got %s, want the unknown handle's %s", foreignBody, unknownBody)
	}
}

// -- T4, T6 ------------------------------------------------------------------

// T6: bilbo holds the credential and the assertion is wrong (the user was
// not verified): today's body, no member.
func TestUnknownCredentialHeldCredentialWrongAssertionIsNotNamed(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	e.fake.NoUserVerification = true

	_, _, body := e.refusedWith(t, e.fake)
	wantNoUnknownCredential(t, body)
	wantTodaysFields(t, bodyMembers(t, body), body)
}

// T4: an SSO-owned account that still holds the passkey: the refusal is
// not signalled, and its body is the same as T6's.
func TestUnknownCredentialSSOOwnedAccountHoldingThePasskeyIsNotNamed(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	e.fake.NoUserVerification = true
	_, _, heldBody := e.refusedWith(t, e.fake)
	e.fake.NoUserVerification = false

	makeBilboSSOOwned(t, e)
	_, _, body := e.refusedWith(t, e.fake)
	wantNoUnknownCredential(t, body)
	if body != heldBody {
		t.Errorf("an SSO-owned account got %s, want the held-credential refusal's %s", body, heldBody)
	}
}

// -- T5 ----------------------------------------------------------------------

// T5: a passkey on hold for the account's recovery codes is not signalled
// (it goes live on confirmation); once confirmed it signs in.
func TestUnknownCredentialPasskeyOnHoldIsNotNamed(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	frodo, held := e.frodoWithHeldPasskey(t)

	_, _, body := e.refusedWith(t, held)
	wantNoUnknownCredential(t, body)

	confirmEnrolmentOK(t, frodo, e.ts)
	resp, signedIn := e.signIn(t, newBrowserJar(t), held)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the confirmed passkey signed in with %d: %s, want 200", resp.StatusCode, signedIn)
	}
}

// -- T7 ----------------------------------------------------------------------

// T7: a passkey registered under another RP ID is stale, not unknown: the
// account still holds it, so it is not signalled.
func TestUnknownCredentialStaleRPIDIsNotNamed(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	newRP := mustRelyingParty(t, "https://new-passkeys.example.org")
	e.g.deps.Passkeys = newRP
	e.fake.RPID, e.fake.Origin = newRP.RPID(), newRP.Origin()

	_, _, body := e.refusedWith(t, e.fake)
	wantNoUnknownCredential(t, body)
}

// -- T8 ----------------------------------------------------------------------

// T8: a dead ceremony is step-expired and says nothing of the credential,
// even one nobody holds.
func TestUnknownCredentialDeadCeremonyIsNotNamed(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	unknown := newFake(e.g)
	unknown.UserHandle = []byte(unknownAccountHandle)
	options, _ := e.mustBegin(t, newBrowserJar(t))
	assertion := signInAssertionBody(t, unknown, options)

	for name, cookie := range map[string]string{"no cookie": "", "garbage": "not-a-sealed-value"} {
		resp, body := e.finishWithCookie(t, cookie, assertion)
		wantStatusClass(t, resp, body, http.StatusUnauthorized, classStepExpired)
		if _, has := bodyMembers(t, body)[unknownCredentialKey]; has {
			t.Errorf("%s: a step-expired body names a credential: %s", name, body)
		}
	}
}

// -- T9 ----------------------------------------------------------------------

// T9: an assertion whose rawId is missing, empty or not base64url is still
// 401 invalid-credentials, with no member: there is no credential ID to
// name. bilbo's passkey is removed, so a decodable ID would have been named.
func TestUnknownCredentialMissingOrBadRawIDIsNotNamed(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	removeBilboPasskey(t, e)

	for name, change := range map[string]func(map[string]any){
		"rawId missing":          func(m map[string]any) { delete(m, "rawId") },
		"rawId empty":            func(m map[string]any) { m["rawId"] = "" },
		"rawId not base64url":    func(m map[string]any) { m["rawId"] = "%%% not base64url %%%" },
		"rawId not a string":     func(m map[string]any) { m["rawId"] = 7 },
		"rawId null":             func(m map[string]any) { m["rawId"] = nil },
		"rawId and id both gone": func(m map[string]any) { delete(m, "rawId"); delete(m, "id") },
	} {
		c := newBrowserJar(t)
		options, _ := e.mustBegin(t, c)
		var assertion map[string]any
		if err := json.Unmarshal(signInAssertionBody(t, e.fake, options), &assertion); err != nil {
			t.Fatal(err)
		}
		change(assertion)
		mangled, err := json.Marshal(assertion)
		if err != nil {
			t.Fatal(err)
		}
		resp, body := e.finish(t, c, mangled)
		if resp.StatusCode != http.StatusUnauthorized || decodeProblem(t, []byte(body)).Type != problemTypeBase+classInvalidCredentials.anchor {
			t.Errorf("%s: got %d %s, want 401 invalid-credentials", name, resp.StatusCode, body)
			continue
		}
		if _, has := bodyMembers(t, body)[unknownCredentialKey]; has {
			t.Errorf("%s: the body names a credential: %s", name, body)
		}
	}
}

// -- T10 ---------------------------------------------------------------------

// T10: a refusal that is a rate limit (the begin limit, or a locked
// account) is 429 and names nothing.
func TestUnknownCredentialRateLimitedAnswersAreNotNamed(t *testing.T) {
	t.Run("begin limit", func(t *testing.T) {
		e := newAloneEnv(t)
		e.g.deps.Limiter = mustNewLoginLimiter(t, 2, time.Minute)
		c := newBrowserJar(t)
		for i := range 2 {
			resp := e.signInBegin(t, c)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("begin %d returned %d, want 200", i+1, resp.StatusCode)
			}
		}
		resp := e.signInBegin(t, c)
		_, raw := readAll(t, resp)
		wantStatusClass(t, resp, raw, http.StatusTooManyRequests, classRateLimited)
		if _, has := bodyMembers(t, raw)[unknownCredentialKey]; has {
			t.Errorf("a begin limited with 429 names a credential: %s", raw)
		}
	})
	t.Run("locked account on a held credential", func(t *testing.T) {
		e := newAloneEnv(t)
		e.withFreshAddresses()
		failLoginWindow(t, e.g, e.ts, e.clock, passkeyBilboUsername)
		_, resp, body := e.attemptWith(t, newBrowserJar(t), e.fake)
		wantStatusClass(t, resp, body, http.StatusTooManyRequests, classRateLimited)
		if _, has := bodyMembers(t, body)[unknownCredentialKey]; has {
			t.Errorf("a locked account's 429 names a credential: %s", body)
		}
	})
}

// -- T11 ---------------------------------------------------------------------

// T11: a rawId sent with base64 padding is named without it.
func TestUnknownCredentialPaddedRawIDIsNamedUnpadded(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	removeBilboPasskey(t, e)

	padded := base64.URLEncoding.EncodeToString(e.fake.CredentialID())
	if !strings.HasSuffix(padded, "=") {
		t.Fatalf("the fake's %d-byte credential ID has no base64 padding to test with", len(e.fake.CredentialID()))
	}
	c := newBrowserJar(t)
	options, _ := e.mustBegin(t, c)
	var assertion map[string]any
	if err := json.Unmarshal(signInAssertionBody(t, e.fake, options), &assertion); err != nil {
		t.Fatal(err)
	}
	assertion["rawId"] = padded
	mangled, err := json.Marshal(assertion)
	if err != nil {
		t.Fatal(err)
	}
	resp, body := e.finish(t, c, mangled)
	wantStatusClass(t, resp, body, http.StatusUnauthorized, classInvalidCredentials)
	wantUnknownCredential(t, body, options.Response.RelyingPartyID, e.fake)
}

// -- T12 ---------------------------------------------------------------------

// T12: counting is unchanged. The removed passkey, the unknown handle and
// the foreign credential are each recorded no_such_user, and past the
// lockout and disable thresholds nothing is charged to bilbo's account.
func TestUnknownCredentialRefusalsStillChargeNothing(t *testing.T) {
	const threshold = 3
	attempts := gauntlet.MaxConsecutiveLoginFailures + 1
	t.Run("removed passkey", func(t *testing.T) {
		e := newAloneEnv(t)
		e.withFreshAddresses()
		removeBilboPasskey(t, e)
		e.g.deps.Limiter = mustNewLoginLimiter(t, threshold, time.Minute)
		failedUncharged(t, e, e.fake, attempts)
		wantNothingChargedTo(t, e, e.id, threshold)
	})
	t.Run("unknown handle", func(t *testing.T) {
		e := newAloneEnv(t)
		e.withFreshAddresses()
		e.g.deps.Limiter = mustNewLoginLimiter(t, threshold, time.Minute)
		unknown := newFake(e.g)
		unknown.UserHandle = []byte(unknownAccountHandle)
		failedUncharged(t, e, unknown, attempts)
		wantNothingChargedTo(t, e, e.id, threshold)
	})
	t.Run("foreign credential", func(t *testing.T) {
		e := newAloneEnv(t)
		e.withFreshAddresses()
		e.g.deps.Limiter = mustNewLoginLimiter(t, threshold, time.Minute)
		stranger := newFake(e.g)
		stranger.UserHandle = []byte(e.id)
		failedUncharged(t, e, stranger, attempts)
		wantNothingChargedTo(t, e, e.id, threshold)
	})
}

// -- T14 ---------------------------------------------------------------------

// T14: the passkey is removed between login/factor/begin and login/factor.
// The server names allowed credentials on that route, so its refusal never
// carries the member.
func TestUnknownCredentialFactorRefusalAfterRemovalIsNotNamed(t *testing.T) {
	e := newAloneEnv(t)
	e.withFreshAddresses()
	pending := startPasskeyLogin(t, e.ts, passkeyBilboUsername, passkeyBilboPassword)
	options := passkeyLoginFactorBegin(t, pending, e.ts)
	removeBilboPasskey(t, e)

	resp := submitPasskeyAssertion(t, pending, e.ts, e.fake, options)
	status, body := readAll(t, resp)
	if status != http.StatusUnauthorized {
		t.Fatalf("login/factor with a removed passkey = %d %s, want 401", status, body)
	}
	if _, has := bodyMembers(t, body)[unknownCredentialKey]; has {
		t.Errorf("login/factor names a credential: %s", body)
	}
}
