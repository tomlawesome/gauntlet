// Every passkey sign-in finish is one counted attempt on the address (#96).
// POST /api/auth/login/passkey used to reserve on the address only when the
// user handle named an account holding the credential; a finish the lookup
// declined (no such account, no local password, credential not held), or
// one that never reached the lookup (no handle, unparsable assertion), cost
// nothing, so one begin cookie bought unbounded declined finishes. Now the
// finish is the attempt (NIST SP 800-63B-4 3.2.2, OWASP ASVS V2.2.1):
//
//   - once the address's attempts in the window are used, or it is banned,
//     a finish is 429 rate-limited before any credential is looked at, with
//     no unknownCredential member, the ceremony cookie kept, and a
//     rate_limited/passkey_alone event naming no account;
//   - an admitted declined finish is the 401 it always was, and its
//     reservation is kept (that is what counts it);
//   - a refused finish leaves the ceremony open for a corrected assertion
//     inside the window (ADR-0004 decision 5);
//   - dead ceremonies count nothing, and the account path is unchanged.
//
// Written from the design on the issue (cases U1-U9); whether a 401 carries
// the unknownCredential member is deliberately not asserted here.
package gate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/internal/passkeytest"
)

const (
	finishLimitAddress = "198.51.100.1"
	finishLimitWindow  = time.Minute
)

// strangerAt is a fake no account holds, reporting handle as its user
// handle (none when empty).
func (e *aloneEnv) strangerAt(handle string) *passkeytest.FakeAuthenticator {
	f := newFake(e.g)
	if handle != "" {
		f.UserHandle = []byte(handle)
	}
	return f
}

// finishWith finishes the open ceremony on c with an assertion of fake.
func (e *aloneEnv) finishWith(t *testing.T, c *http.Client, fake *passkeytest.FakeAuthenticator, options *protocol.CredentialAssertion) (*http.Response, string) {
	t.Helper()
	return e.finish(t, c, signInAssertionBody(t, fake, options))
}

// wantDeclined requires a 401 invalid-credentials, whatever else it says.
func wantDeclined(t *testing.T, resp *http.Response, body string, step string) {
	t.Helper()
	if resp.StatusCode != http.StatusUnauthorized || decodeProblem(t, []byte(body)).Type != problemTypeBase+classInvalidCredentials.anchor {
		t.Fatalf("%s: got %d %s, want 401 invalid-credentials", step, resp.StatusCode, body)
	}
}

// wantFinishLimited requires the finish's 429: rate-limited, no
// unknownCredential member, and the ceremony cookie not cleared.
func wantFinishLimited(t *testing.T, resp *http.Response, body string, step string) {
	t.Helper()
	if resp.StatusCode != http.StatusTooManyRequests || decodeProblem(t, []byte(body)).Type != problemTypeBase+classRateLimited.anchor {
		t.Fatalf("%s: got %d %s, want 429 rate-limited", step, resp.StatusCode, body)
	}
	if _, has := bodyMembers(t, body)[unknownCredentialKey]; has {
		t.Errorf("%s: a 429 names a credential: %s", step, body)
	}
	if cookieCleared(resp, passkeySignInCookieName) {
		t.Errorf("%s: the 429 cleared the ceremony cookie, want it kept", step)
	}
}

// wantNoAccountNamed requires every recorded event to name no account.
func wantNoAccountNamed(t *testing.T, e *aloneEnv) {
	t.Helper()
	for i, ev := range e.events.all() {
		if ev.UserID != "" {
			t.Errorf("event %d (%s/%s) names account %q, want none", i+1, ev.Outcome, ev.Method, ev.UserID)
		}
	}
}

// -- U1 ----------------------------------------------------------------------

// U1: one begin, one cookie, an unknown handle: the first three finishes
// are today's 401, the fourth is 429 with the cookie kept.
func TestPasskeyFinishUnknownHandleIsCountedOnTheAddress(t *testing.T) {
	e := newAloneEnv(t)
	e.g.deps.Limiter = mustNewLoginLimiter(t, 3, finishLimitWindow)
	c := newBrowserJar(t)
	options, _ := e.mustBegin(t, c)
	unknown := e.strangerAt(unknownAccountHandle)

	for i := 1; i <= 3; i++ {
		resp, body := e.finishWith(t, c, unknown, options)
		wantDeclined(t, resp, body, fmt.Sprintf("finish %d", i))
	}
	resp, body := e.finishWith(t, c, unknown, options)
	wantFinishLimited(t, resp, body, "finish 4")

	wantEvents(t, e.events.all(),
		"no_such_user/passkey_alone", "no_such_user/passkey_alone", "no_such_user/passkey_alone", "rate_limited/passkey_alone")
	wantNoAccountNamed(t, e)
	if ev := lastEvent(t, e); ev.Client.Address != finishLimitAddress {
		t.Errorf("the refusal's event is from %q, want %q", ev.Client.Address, finishLimitAddress)
	}
}

// -- U2 ----------------------------------------------------------------------

// U2: a stranger's credential at bilbo's handle is counted the same, charges
// nothing to bilbo, and once the window passes bilbo signs in as usual.
func TestPasskeyFinishForeignCredentialIsCountedAndChargesNoAccount(t *testing.T) {
	const threshold = 3
	e := newAloneEnv(t)
	e.g.deps.Limiter = mustNewLoginLimiter(t, threshold, finishLimitWindow)
	c := newBrowserJar(t)
	options, _ := e.mustBegin(t, c)
	stranger := e.strangerAt(e.id)

	for i := 1; i <= threshold; i++ {
		resp, body := e.finishWith(t, c, stranger, options)
		wantDeclined(t, resp, body, fmt.Sprintf("finish %d", i))
	}
	resp, body := e.finishWith(t, c, stranger, options)
	wantFinishLimited(t, resp, body, "finish 4")

	wantEvents(t, e.events.all(),
		"no_such_user/passkey_alone", "no_such_user/passkey_alone", "no_such_user/passkey_alone", "rate_limited/passkey_alone")
	wantNoAccountNamed(t, e)
	wantNothingChargedTo(t, e, e.id, threshold)

	e.clock.set(e.clock.now().Add(finishLimitWindow + time.Second))
	if resp, body := e.signIn(t, newBrowserJar(t), e.fake); resp.StatusCode != http.StatusOK {
		t.Fatalf("bilbo after the window returned %d: %s, want 200", resp.StatusCode, body)
	}
}

// -- U3 ----------------------------------------------------------------------

// U3: the address is banned between begin and finish. The finish is 429
// before the credential is looked at, the cookie kept; begin is 429 too.
func TestPasskeyFinishFromABannedAddressIsRefused(t *testing.T) {
	e := newAloneEnv(t)
	c := newBrowserJar(t)
	options, _ := e.mustBegin(t, c)

	for range gauntlet.AddressBanFailures {
		e.g.deps.Limiter.RecordAddressFailure(finishLimitAddress, e.clock.now())
	}
	if _, banned := e.g.deps.Limiter.AddressBanned(finishLimitAddress, e.clock.now()); !banned {
		t.Fatal("the address is not banned after AddressBanFailures failures")
	}

	resp, body := e.finishWith(t, c, e.strangerAt(unknownAccountHandle), options)
	wantFinishLimited(t, resp, body, "finish at a banned address")
	wantEvents(t, e.events.all(), "rate_limited/passkey_alone")
	wantNoAccountNamed(t, e)

	resp = e.signInBegin(t, newBrowserJar(t))
	_, raw := readAll(t, resp)
	wantStatusClass(t, resp, raw, http.StatusTooManyRequests, classRateLimited)
}

// -- U4 ----------------------------------------------------------------------

// U4: a 429 does not spend the ceremony. Once the window has passed (and
// the ceremony is still inside its five minutes) the same cookie is judged
// again, and the right passkey signs in.
func TestPasskeyFinishRefusalLeavesTheCeremonyOpenForALaterAttempt(t *testing.T) {
	e := newAloneEnv(t)
	e.g.deps.Limiter = mustNewLoginLimiter(t, 3, finishLimitWindow)
	c := newBrowserJar(t)
	options, _ := e.mustBegin(t, c)
	unknown := e.strangerAt(unknownAccountHandle)

	for i := 1; i <= 3; i++ {
		resp, body := e.finishWith(t, c, unknown, options)
		wantDeclined(t, resp, body, fmt.Sprintf("finish %d", i))
	}
	resp, body := e.finishWith(t, c, unknown, options)
	wantFinishLimited(t, resp, body, "finish 4")

	e.clock.set(e.clock.now().Add(finishLimitWindow + time.Second))
	resp, body = e.finishWith(t, c, unknown, options)
	wantDeclined(t, resp, body, "the unknown handle after the window")
	if resp, body = e.finishWith(t, c, e.fake, options); resp.StatusCode != http.StatusOK {
		t.Fatalf("the right passkey on the same ceremony returned %d: %s, want 200", resp.StatusCode, body)
	}
}

// -- U5 ----------------------------------------------------------------------

// U5: declined finishes and password attempts draw on the one address
// bucket.
func TestPasskeyFinishSharesTheAddressBucketWithPasswordLogins(t *testing.T) {
	e := newAloneEnv(t)
	e.g.deps.Limiter = mustNewLoginLimiter(t, 2, finishLimitWindow)
	c := newBrowserJar(t)
	options, _ := e.mustBegin(t, c)

	resp, body := e.finishWith(t, c, e.strangerAt(unknownAccountHandle), options)
	wantDeclined(t, resp, body, "the declined finish")

	const nobody = "nobody-by-this-name"
	if got := tryLogin(t, e.ts, nobody, "a-wrong-password-placeholder"); got.status != http.StatusUnauthorized {
		t.Fatalf("the password attempt after one declined finish = %d %s, want 401", got.status, got.body)
	}
	if got := tryLogin(t, e.ts, nobody, "a-wrong-password-placeholder"); got.status != http.StatusTooManyRequests {
		t.Fatalf("the next password attempt = %d %s, want 429: the declined finish should have used one of the two", got.status, got.body)
	}
}

// -- U6 ----------------------------------------------------------------------

// U6: a finish that never reaches the lookup counts too: no user handle at
// all, or an assertion body of {}.
func TestPasskeyFinishWithoutALookupIsCounted(t *testing.T) {
	t.Run("no user handle", func(t *testing.T) {
		e := newAloneEnv(t)
		e.g.deps.Limiter = mustNewLoginLimiter(t, 2, finishLimitWindow)
		e.fake.UserHandle = nil
		c := newBrowserJar(t)
		options, _ := e.mustBegin(t, c)

		for i := 1; i <= 2; i++ {
			resp, body := e.finishWith(t, c, e.fake, options)
			wantDeclined(t, resp, body, fmt.Sprintf("finish %d", i))
		}
		resp, body := e.finishWith(t, c, e.fake, options)
		wantFinishLimited(t, resp, body, "finish 3")
		wantNoAccountNamed(t, e)
	})
	t.Run("empty assertion", func(t *testing.T) {
		e := newAloneEnv(t)
		e.g.deps.Limiter = mustNewLoginLimiter(t, 2, finishLimitWindow)
		c := newBrowserJar(t)
		_, _ = e.mustBegin(t, c)

		for i := 1; i <= 2; i++ {
			resp, body := e.finish(t, c, json.RawMessage(`{}`))
			wantDeclined(t, resp, body, fmt.Sprintf("finish %d", i))
		}
		resp, body := e.finish(t, c, json.RawMessage(`{}`))
		wantFinishLimited(t, resp, body, "finish 3")
		wantNoAccountNamed(t, e)
	})
}

// -- U7 ----------------------------------------------------------------------

// U7: a dead ceremony is step-expired as before, records nothing and uses
// none of the address's allowance.
func TestPasskeyFinishDeadCeremoniesCountNothing(t *testing.T) {
	e := newAloneEnv(t)
	e.g.deps.Limiter = mustNewLoginLimiter(t, 1, finishLimitWindow)
	c := newBrowserJar(t)
	options, begin := e.mustBegin(t, c)
	unknown := e.strangerAt(unknownAccountHandle)
	assertion := signInAssertionBody(t, unknown, options)
	sealed := cookieValue(begin, passkeySignInCookieName)
	if len(sealed) < 11 {
		t.Fatalf("ceremony cookie %q is too short to truncate", sealed)
	}

	for name, cookie := range map[string]string{
		"no cookie":        "",
		"garbage cookie":   "not-a-sealed-value",
		"truncated cookie": sealed[:10],
	} {
		resp, body := e.finishWithCookie(t, cookie, assertion)
		wantStatusClass(t, resp, body, http.StatusUnauthorized, classStepExpired)
		if !cookieCleared(resp, passkeySignInCookieName) {
			t.Errorf("%s: the dead ceremony's cookie was not cleared", name)
		}
	}
	wantEvents(t, e.events.all())

	resp, body := e.finishWithCookie(t, sealed, assertion)
	wantDeclined(t, resp, body, "the live ceremony's unknown-handle finish after the dead ones")
	wantEvents(t, e.events.all(), "no_such_user/passkey_alone")
}

// -- U8 ----------------------------------------------------------------------

// U8: a declined finish has no known-browser pass: nothing names an
// account, so a browser bilbo remembers, presenting a stranger's credential
// at his handle, is refused at a full address.
func TestPasskeyFinishDeclinedPathHasNoKnownBrowserPass(t *testing.T) {
	e := newAloneEnv(t)
	known := newBrowserJar(t)
	e.mustSignIn(t, known) // bilbo's account remembers this browser
	e.g.deps.Limiter = mustNewLoginLimiter(t, 5, 5*time.Minute)
	e.events.events = nil

	options, _ := e.mustBegin(t, known)
	for range 5 { // the begin holds none of the address's five; fill them
		e.g.deps.Limiter.Reserve("ip:"+finishLimitAddress, e.clock.now())
	}
	resp, body := e.finishWith(t, known, e.strangerAt(e.id), options)
	wantFinishLimited(t, resp, body, "the known browser's stranger credential")
	wantEvents(t, e.events.all(), "rate_limited/passkey_alone")
	wantNoAccountNamed(t, e)
}

// -- U9 ----------------------------------------------------------------------

// U9: the account path is as before. At a full address a stranger's browser
// holding bilbo's real passkey is 429 and the browser his account remembers
// is 200.
func TestPasskeyFinishAccountPathAtAFullAddressIsUnchanged(t *testing.T) {
	e := newAloneEnv(t)
	known := newBrowserJar(t)
	e.mustSignIn(t, known)
	e.g.deps.Limiter = mustNewLoginLimiter(t, 5, 5*time.Minute)

	knownOptions, _ := e.mustBegin(t, known)
	strangerBrowser := newBrowserJar(t)
	strangerOptions, _ := e.mustBegin(t, strangerBrowser)
	for range 5 {
		e.g.deps.Limiter.Reserve("ip:"+finishLimitAddress, e.clock.now())
	}
	resp, body := e.finishWith(t, strangerBrowser, e.fake, strangerOptions)
	wantFinishLimited(t, resp, body, "a stranger's browser with bilbo's passkey")
	if resp, body = e.finishWith(t, known, e.fake, knownOptions); resp.StatusCode != http.StatusOK {
		t.Fatalf("the known browser at a full address returned %d: %s, want 200", resp.StatusCode, body)
	}
}

// U9, counting: a good sign-in is not charged twice and does not erase an
// earlier declined finish. With two attempts a window: one declined finish,
// bilbo's correct finish, then one more declined finish is 401 and the
// next 429.
func TestPasskeyFinishAccountPathIsNeverChargedTwice(t *testing.T) {
	e := newAloneEnv(t)
	e.g.deps.Limiter = mustNewLoginLimiter(t, 2, finishLimitWindow)
	declined := newBrowserJar(t)
	declinedOptions, _ := e.mustBegin(t, declined)
	good := newBrowserJar(t)
	goodOptions, _ := e.mustBegin(t, good)
	unknown := e.strangerAt(unknownAccountHandle)

	resp, body := e.finishWith(t, declined, unknown, declinedOptions)
	wantDeclined(t, resp, body, "the first declined finish")
	if resp, body = e.finishWith(t, good, e.fake, goodOptions); resp.StatusCode != http.StatusOK {
		t.Fatalf("bilbo's correct finish returned %d: %s, want 200", resp.StatusCode, body)
	}
	resp, body = e.finishWith(t, declined, unknown, declinedOptions)
	wantDeclined(t, resp, body, "the second declined finish")
	resp, body = e.finishWith(t, declined, unknown, declinedOptions)
	wantFinishLimited(t, resp, body, "the third declined finish")
}
