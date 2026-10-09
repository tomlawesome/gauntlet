package gate

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// -- Signing in with a passkey alone (#77, docs/adr/0012-passkey-alone-sign-in.md)
//
// A WebAuthn Level 3 client-side discoverable credential login: nobody
// types a username, the browser offers the passkeys it holds for this
// relying party, and the one chosen names its account through the user
// handle (the account ID). User verification is required, so the passkey
// is a multi-factor cryptographic authenticator on its own (NIST SP
// 800-63B-4, AAL2) and replaces the password -- at sign-in only: every
// account keeps its password.
//
// The ceremony runs behind gauntlet.PasskeySignIn, an optional second
// interface on Deps.Passkeys (gauntlet/passkey implements it), and the
// routes are offered only when Config.PasskeySignIn is set. This file
// owns what goes around it: the cookie, the login limiter, the
// unusual-sign-in judgement, the session, the history and the audit.

// passkeySignIn is Deps.Passkeys as a gauntlet.PasskeySignIn when
// Config.PasskeySignIn is set and it implements one.
func (g *Gate) passkeySignIn() (gauntlet.PasskeySignIn, bool) {
	if !g.cfg.PasskeySignIn || g.deps.Passkeys == nil {
		return nil, false
	}
	ps, ok := g.deps.Passkeys.(gauntlet.PasskeySignIn)
	return ps, ok
}

// passkeySignInOn is true when this application offers passkey sign-in
// and its relying party is ready: what the session body's signIn says.
func (g *Gate) passkeySignInOn() bool {
	_, ok := g.passkeySignIn()
	return ok && g.passkeysReady()
}

// passkeySignInOrNotFound answers 404 when passkey sign-in is not
// offered, as every passkey route does when there are no passkeys.
func (g *Gate) passkeySignInOrNotFound(w http.ResponseWriter) (gauntlet.PasskeySignIn, bool) {
	ps, ok := g.passkeySignIn()
	if !ok {
		writeProblem(w, http.StatusNotFound, classNotFound, "", nil)
	}
	return ps, ok
}

// -- POST /api/auth/login/passkey/begin -----------------------------------

// handleLoginPasskeyBegin starts a passkey-alone sign-in and answers the
// W3C request options for navigator.credentials.get(), with no allowed
// list: the browser offers its own passkeys, or its autofill does
// (conditional mediation). It reads no body, and is reached with no
// session and no cookie.
//
// Nothing names an account yet, so it reserves one attempt on the
// address alone, keeping it until a sign-in completes, so a stranger
// cannot mint challenges without limit; the finish step takes the
// address's and the account's own reservations, and gives all of them
// back when the sign-in completes. A banned address or one at its begin
// limit is refused 429 here; the known-browser allowance, which belongs
// to an account, applies at the finish.
//
// The begin attempt is on a bucket of its own (passkeyBeginKey), not the
// address bucket a password is tried on. A browser asks for a challenge
// on every load of a login page that offers passkey autofill and after
// every prompt the user dismisses, and a challenge costs the caller
// nothing to mint and guesses nothing: on the shared bucket, a few page
// views would leave the address at its limit and every way of signing
// in from it answering 429. It must still be bounded, so it gets the
// same limit on its own.
func (g *Gate) handleLoginPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	ps, ok := g.passkeySignInOrNotFound(w)
	if !ok {
		return
	}
	if !g.passkeysReady() {
		g.writePasskeysNotReady(w)
		return
	}
	now := g.now()
	address := g.cfg.ClientIP(r)
	beginKey := passkeyBeginKey(address)
	res := loginReservation{address: address}
	if _, banned := g.deps.Limiter.AddressBanned(address, now); banned || !g.deps.Limiter.Reserve(beginKey, now) {
		g.refusePasskeyAloneAtAddress(w, r, res, now)
		return
	}
	options, sealed, err := ps.BeginSignIn()
	if err != nil {
		// This server's failure, not the caller's attempt.
		g.deps.Limiter.Release(beginKey, now)
		g.logError("beginning passkey-alone sign-in: " + err.Error())
		writeProblem(w, http.StatusInternalServerError, classServerError, "unable to start passkey sign-in", nil)
		return
	}
	g.setPasskeySignInCookie(w, sealed)
	writeJSON(w, http.StatusOK, options)
}

// refusePasskeyAloneAtAddress answers a passkey-alone attempt the
// address's ban or limit refused before any account was named -- at
// begin, or at a finish the lookup declined (#96): 429 rate-limited,
// recorded as rate_limited with method passkey_alone and no account.
func (g *Gate) refusePasskeyAloneAtAddress(w http.ResponseWriter, r *http.Request, res loginReservation, now time.Time) {
	res.refusal = gauntlet.SignInRateLimited
	g.recordSignIn(r, gauntlet.SignInEvent{Outcome: res.refusal, Method: gauntlet.SignInMethodPasskeyAlone}, res, now)
	writeProblem(w, http.StatusTooManyRequests, classRateLimited, "too many attempts, try again later", nil)
}

// passkeyBeginKey is the limiter bucket login/passkey/begin reserves on
// for address: its own, so asking for challenges spends none of the
// address's sign-in attempts (see handleLoginPasskeyBegin). Whatever
// hands the begin step's reservation back releases this key.
func passkeyBeginKey(address string) string {
	return "passkey-begin:" + address
}

// assertionCredentialID reads the credential ID (rawId) from a WebAuthn
// assertion's JSON as go-webauthn v0.18.2 decodes it for the ceremony
// (protocol.URLEncodedBase64.UnmarshalJSON, through encoding/json: the
// value must be a JSON string, trailing "=" padding is trimmed, the rest
// is unpadded base64url), so gate compares the bytes the ceremony will
// without importing it (the leaf rule). read is false when the ID cannot
// be read or is empty; the caller then treats the credential as possibly
// held. The ceremony parses the assertion before it calls lookup, so in
// practice this fails only on a difference between the two parsers.
func assertionCredentialID(assertion json.RawMessage) (id []byte, read bool) {
	var body struct {
		RawID *string `json:"rawId"`
	}
	if err := json.Unmarshal(assertion, &body); err != nil || body.RawID == nil {
		return nil, false
	}
	id, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(*body.RawID, "="))
	if err != nil || len(id) == 0 {
		return nil, false
	}
	return id, true
}

// accountHoldsCredential reports whether credID is one of u's passkeys
// the ceremony checks a signature against: those registered under the
// current relying-party ID, as gauntlet/passkey's RelyingParty.usable
// selects them. A stale passkey (registered under an earlier public URL)
// can never complete a ceremony here, so it does not count; a passkey
// still held for its recovery codes is not in u.Passkeys at all.
func (g *Gate) accountHoldsCredential(u *gauntlet.User, credID []byte) bool {
	rpID := g.deps.Passkeys.RPID()
	return slices.ContainsFunc(u.Passkeys, func(pk gauntlet.Passkey) bool {
		return pk.RPID == rpID && bytes.Equal(pk.ID, credID)
	})
}

// -- naming a passkey the server does not hold (#92) ------------------------
//
// A browser keeps offering a passkey the server has forgotten (removed by
// its owner, or never held) until it is told not to. W3C WebAuthn Level 3
// section 5.1.10.2 gives the call for that, signalUnknownCredential, and
// section 14.6.3 names it as the one to use for a caller who is not signed
// in. Making it is the application's; gate's part is the refusal naming
// the credential in an RFC 9457 extension member shaped as that call's
// argument, so the application can pass it on unchanged.

// unknownCredential is the unknownCredential member: the W3C
// UnknownCredentialOptions for the credential a refusal names.
type unknownCredential struct {
	RPID         string `json:"rpId"`
	CredentialID string `json:"credentialId"` // base64url, no padding
}

// accountKnowsCredential reports whether credID is one of u's passkeys in
// any form: live, registered under another relying-party ID (stale), or
// held for its recovery codes (#58), expired or not. It is wider than
// accountHoldsCredential on purpose: a passkey the server still holds is
// never named, since the browser's deletion cannot be undone and a stale
// or held passkey can work again (the old public URL comes back, the
// codes are confirmed).
func accountKnowsCredential(u *gauntlet.User, credID []byte) bool {
	if slices.ContainsFunc(u.Passkeys, func(pk gauntlet.Passkey) bool { return bytes.Equal(pk.ID, credID) }) {
		return true
	}
	held := u.HeldEnrolment
	return held != nil && held.Passkey != nil && bytes.Equal(held.Passkey.ID, credID)
}

// credentialToForget is the credential ID a refused assertion may name:
// the one assertionCredentialID reads, when u -- the account the user
// handle names, nil when it names none -- does not know it. nil when
// there is nothing to name. A handle naming no account and one naming an
// account without the credential give the same answer, so the member
// says nothing of whether an account exists.
func credentialToForget(u *gauntlet.User, assertion json.RawMessage) []byte {
	id, read := assertionCredentialID(assertion)
	if !read || (u != nil && accountKnowsCredential(u, id)) {
		return nil
	}
	return id
}

// unknownCredentialMember is writeProblem's extra for a refusal naming
// credID, or nil when credID is nil. The ID is the bytes gate decoded,
// encoded again, never the caller's own text.
func (g *Gate) unknownCredentialMember(credID []byte) map[string]any {
	if credID == nil {
		return nil
	}
	return map[string]any{"unknownCredential": unknownCredential{
		RPID:         g.deps.Passkeys.RPID(),
		CredentialID: base64.RawURLEncoding.EncodeToString(credID),
	}}
}

// -- the assertion check both finishes share ------------------------------

// signInAssertionOutcome is how checkSignInAssertion ended.
type signInAssertionOutcome int

const (
	// signInAssertionAccepted: verified, user verified, count recorded.
	signInAssertionAccepted signInAssertionOutcome = iota
	// signInAssertionDead: the ceremony can never succeed (no usable
	// state: expired, tampered with, already used, sealed for another
	// ceremony). The caller clears the cookie.
	signInAssertionDead
	// signInAssertionRefused: the assertion was not accepted, for any
	// reason a caller need not tell apart -- a handle lookup declined,
	// a wrong or unknown credential, no user verification, a clone
	// warning, a counter that did not advance.
	signInAssertionRefused
	// signInAssertionBackendFailed: the counter could not be saved.
	signInAssertionBackendFailed
)

// checkSignInAssertion runs the ceremony's FinishSignIn with lookup and
// then what any passkey sign-in owes after it: the user-verified flag
// read again (the ceremony requires it too; defence in depth) and
// recordVerifiedAssertion. It writes no response and touches no
// reservation. The account is the one lookup returned for the verified
// assertion, nil unless the outcome is accepted.
func (g *Gate) checkSignInAssertion(r *http.Request, ps gauntlet.PasskeySignIn, sealed string, assertion json.RawMessage, lookup func([]byte) (*gauntlet.User, bool), now time.Time) (*gauntlet.User, signInAssertionOutcome) {
	user, verified, err := ps.FinishSignIn(lookup, sealed, assertion)
	if errors.Is(err, gauntlet.ErrPasskeyCeremonyInvalid) {
		return nil, signInAssertionDead
	}
	if err != nil || user == nil || !verified.UserVerified {
		return nil, signInAssertionRefused
	}
	switch g.recordVerifiedAssertion(r, user, verified, now) {
	case assertionRefused:
		return nil, signInAssertionRefused
	case assertionBackendFailed:
		return nil, signInAssertionBackendFailed
	}
	return user, signInAssertionAccepted
}

// -- POST /api/auth/login/passkey ------------------------------------------

type loginPasskeyRequest struct {
	// Assertion is the browser's PublicKeyCredential JSON from
	// navigator.credentials.get(), handed to the ceremony unchanged.
	Assertion json.RawMessage `json:"assertion"`
}

// handleLoginPasskey completes a passkey-alone sign-in. It is judged
// like any completed sign-in (#55: method passkey_alone reaches Decide,
// so an application may relax it) and answers the Account, or the
// ConfirmationChallenge when the policy asks for a confirmation code.
//
// The account is named by the assertion's user handle, read before the
// signature is checked (the ceremony calls lookup first). The handle is
// not covered by the signature (WebAuthn Level 3), so whoever holds any
// passkey can name any account. Lookup therefore checks before it
// charges: the account must be one this credential can sign in with --
// it has a local password (an account single sign-on owns cannot be
// signed into this way, as it cannot resume a session; ruling R4 on
// #20), and the assertion's credential ID is one of its passkeys under
// the current relying-party ID (accountHoldsCredential). If not, nothing
// is reserved or counted on the account -- no lockout, no disable, no
// notice -- and the refusal is no_such_user naming no account, on the
// address alone, exactly as for an unknown handle (#80; NIST SP
// 800-63B-4 3.2.2 counts failures "using a specific authenticator on a
// single subscriber account").
//
// Such a declined finish -- and one that never reached lookup (no user
// handle, an assertion the ceremony could not read) -- is still one
// attempt on the address (#96; NIST SP 800-63B-4 3.2.2 and OWASP ASVS
// V2.2.1 count the attempt, and the finish is the attempt), so one
// begin cookie cannot buy unbounded tries. Before its 401 it is checked
// against the address ban (AddressBanned) and reserves on the address
// bucket a password attempt uses (addressKey); a refusal there is 429
// rate-limited, recorded as begin's is, with no unknownCredential and
// the ceremony cookie kept, as the ceremony expires on its own. An
// admitted one keeps its reservation, which counts it. Nothing names an
// account, so there is no known-browser pass on this path; a finish the
// account path reserved for never reaches it, so none is charged to the
// address twice. A dead ceremony reserves and records nothing.
//
// If the credential ID cannot be read here
// (assertionCredentialID), the credential is treated as possibly held
// and the ceremony decides, so a parsing difference never refuses a
// real user.
//
// Once the credential is one the account holds, the attempt is treated
// as a password attempt on the account would be: reserveLogin applies
// the account's lockout and disable, the address ban and limit and the
// known-browser allowance (#70, #44) -- a refusal is the 429 and the
// signature is never checked. Everything after keeps the reservation,
// which is what counts a failure: a refused or non-user-verified
// assertion from a held credential is factor_refused against the
// account. Unlike a wrong second factor after a password, it does not
// count toward the account's run of second-factor failures: the caller
// holds no password, and letting anyone holding an account ID force a
// password change would be a denial of service.
//
// Every refusal answers 401 invalid-credentials, saying nothing of which
// check failed -- except that one naming a passkey the handle's account
// does not know at all, or a handle naming no account, carries the
// credential in unknownCredential (#92, credentialToForget), so the
// browser can be told to stop offering it. A dead ceremony (no cookie,
// expired, tampered with, already used) answers 401 step-expired and
// clears the cookie.
func (g *Gate) handleLoginPasskey(w http.ResponseWriter, r *http.Request) {
	ps, ok := g.passkeySignInOrNotFound(w)
	if !ok {
		return
	}
	if !g.passkeysReady() {
		g.writePasskeysNotReady(w)
		return
	}
	var req loginPasskeyRequest
	if err := g.decodeJSONBody(w, r, &req); err != nil || len(req.Assertion) == 0 {
		writeProblem(w, http.StatusBadRequest, classInvalidRequest, "invalid request body", nil)
		return
	}
	cookie, err := r.Cookie(passkeySignInCookieName)
	if err != nil {
		g.clearPasskeySignInCookie(w)
		writeUnauthorized(w, classStepExpired, passkeyStartAgain)
		return
	}
	now := g.now()

	// The begin step's reservation (passkeyBeginKey) is kept until this
	// completes. res is the address alone until the user handle names an
	// account, then the address's and the account's, as reserveLogin
	// takes them.
	address := g.cfg.ClientIP(r)
	res := loginReservation{ipKey: addressKey(address), address: address}
	var (
		named    *gauntlet.User // the account the handle named, once admitted
		reserved bool
		limited  bool
		forget   []byte // the credential a refusal names (#92), nil for none
	)
	lookup := func(handle []byte) (*gauntlet.User, bool) {
		u, ok := g.deps.Users.Get(string(handle))
		if !ok {
			forget = credentialToForget(nil, req.Assertion)
			return nil, false
		}
		forget = credentialToForget(u, req.Assertion)
		// Check before charging (#80): a credential this account cannot
		// sign in with is refused before reserveLogin, so the refusal
		// below is on the address alone, as for an unknown handle.
		if !u.LocalPassword() {
			return nil, false
		}
		if id, read := assertionCredentialID(req.Assertion); read && !g.accountHoldsCredential(u, id) {
			return nil, false
		}
		admitted := false
		res, admitted = g.reserveLogin(w, r, u.ID, u.Username, gauntlet.SignInMethodPasskeyAlone, now)
		if !admitted {
			limited = true
			return nil, false
		}
		reserved, named = true, u
		return u, true
	}
	user, outcome := g.checkSignInAssertion(r, ps, cookie.Value, req.Assertion, lookup, now)
	if limited {
		return // reserveLogin wrote the 429 and recorded it
	}

	// A refusal keeps the reservations -- that is what counts the
	// failure. Only a handle that named an account holds the account's;
	// every other refusal is on the address alone and recorded as
	// no_such_user. A dead ceremony with no account named checked no
	// credential, so records nothing.
	refuse := func(class problemClass, msg string, record bool, extra map[string]any) {
		switch {
		case reserved && record:
			g.recordSignIn(r, loginEvent(named, "", gauntlet.SignInFactorRefused, gauntlet.SignInMethodPasskeyAlone), res, now)
		case record:
			g.recordSignIn(r, loginEvent(nil, "", gauntlet.SignInNoSuchUser, gauntlet.SignInMethodPasskeyAlone), res, now)
		}
		writeUnauthorizedWith(w, class, msg, extra)
	}
	switch outcome {
	case signInAssertionDead:
		g.clearPasskeySignInCookie(w)
		refuse(classStepExpired, passkeyStartAgain, reserved, nil)
		return
	case signInAssertionRefused:
		// A finish no account was reserved for is still one attempt on
		// the address (#96): the ban, then the address bucket.
		if !reserved {
			if _, banned := g.deps.Limiter.AddressBanned(address, now); banned || !g.deps.Limiter.Reserve(res.ipKey, now) {
				g.refusePasskeyAloneAtAddress(w, r, res, now)
				return
			}
		}
		refuse(classInvalidCredentials, passkeyNotVerified, true, g.unknownCredentialMember(forget))
		return
	case signInAssertionBackendFailed:
		// The credential was right but could not be recorded: this
		// request's reservations and the begin step's go back, as
		// login/factor's do.
		g.releaseLogin(res, now)
		g.deps.Limiter.Release(passkeyBeginKey(address), now)
		writeProblem(w, http.StatusInternalServerError, classServerError, "unable to complete sign-in", nil)
		return
	}

	// Every credential has passed: judge the sign-in (#55) before any
	// session exists. The ceremony is spent either way.
	g.clearPasskeySignInCookie(w)
	g.deps.Limiter.Release(passkeyBeginKey(address), now) // the begin step's reservation
	place := g.placeOf(r, res.address)
	verdict := g.judgeSignIn(r, user, gauntlet.SignInMethodPasskeyAlone, place, now)
	if verdict.stopsSignIn() {
		// The credential was right, so the attempt is handed back rather
		// than completed; nothing completed, so the account's count is
		// not reset.
		g.releaseLogin(res, now)
		out, notice := g.stopSignIn(w, r, user, res, gauntlet.SignInMethodPasskeyAlone, place, verdict, now)
		g.answerStopped(w, r, verdict, out, notice)
		return
	}
	g.completeLogin(res, now)
	// The session this browser already held for the account ends here,
	// as for every sign-in (ASVS 7.2.4; see revokeReplacedSession).
	notice := g.completeSignIn(w, r, user, res, gauntlet.SignInMethodPasskeyAlone, place, verdict, now)
	writeJSON(w, http.StatusOK, map[string]any{"username": user.Username, "role": user.Role})
	g.notify(r.Context(), notice)
}
