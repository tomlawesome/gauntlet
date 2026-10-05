package gate

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/tomlawesome/gauntlet"
)

// Divergences from mikroview (gauntlet #15), both deliberate:
//
//   - decodeJSONBody below refuses an unrecognized JSON field and any
//     data left over after the JSON value (DisallowUnknownFields, and
//     the dec.More() check), 400 either way. mikroview's own
//     decodeJSONBody (rest.go) accepts both silently -- an unknown field
//     is just ignored, and a body holding a JSON value followed by more
//     data only ever has the first value read. Every field a real
//     client sends here is already named in that handler's own request
//     struct (see each struct's comment, and each one's mikroview
//     original), so this can only ever refuse a body no real client
//     sends.
//   - gateErrorMessages gives ErrCannotDeleteAdmin and ErrLastAdmin
//     their own message below, so the admin UI can say why a request
//     was refused instead of "unable to complete the request".
//     mikroview's own authErrorMessages (auth.go) has neither entry, so
//     both fall through to that same generic message there too.

// maxJSONBodyBytes bounds every JSON request body a gate handler
// accepts -- mikroview's own rest.go constant and reasoning: every
// payload here is small, bounded structured data, and several of these
// routes are reachable before authentication (login, register), so an
// unbounded decode would let a handful of concurrent, credential-free
// requests allocate memory proportional to whatever body size they
// chose to send.
const maxJSONBodyBytes = 64 * 1024

// errTrailingJSON is decodeJSONBody's error for a body holding more data
// after its JSON value -- two concatenated objects, or a valid document
// followed by garbage. See this file's header comment.
var errTrailingJSON = errors.New("gate: unexpected data after JSON value")

// decodeJSONBody is json.NewDecoder(r.Body).Decode(v), wrapped with
// http.MaxBytesReader (see maxJSONBodyBytes), DisallowUnknownFields, and
// a check that nothing follows the decoded value -- see this file's
// header comment for why both are stricter than mikroview's own.
//
// A body over the limit also leaves a rated Warn line with the address
// (#45, ASVS 16.3.3): it is a request no frontend sends.
func (g *Gate) decodeJSONBody(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			g.warnRefused(r, "oversize", fmt.Sprintf("gate: request body over %d bytes refused", maxJSONBodyBytes))
		}
		return err
	}
	if dec.More() {
		return errTrailingJSON
	}
	return nil
}

// writeJSON is the only place gate writes a successful JSON response
// body -- every handler goes through it rather than setting headers of
// its own, so these three headers only have to be right once (#46).
// writeProblem below is its sibling for every error body (#23): the
// same three headers, Content-Type aside.
//
//   - Content-Type: application/json; charset=utf-8 -- the charset is
//     explicit rather than assumed, the same reasoning RFC 8259 gives
//     for naming it even though UTF-8 is JSON's only legal encoding.
//   - Cache-Control: no-store -- every response here either carries
//     this account's own state or says why a request failed; a shared
//     or browser cache holding either across accounts or across a state
//     change (a password just changed, a token just revoked) is wrong
//     regardless of how short its TTL is.
//   - X-Content-Type-Options: nosniff -- stops a browser that ignores
//     Content-Type from sniffing a JSON body as HTML and rendering it,
//     which would turn a reflected value into script execution.
func writeJSON(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	// Best-effort: the status line is already on the wire, so a write
	// failure here cannot become a different status code. There is
	// nothing left to do with it but let the client see a short body.
	_ = json.NewEncoder(w).Encode(v)
}

// gateErrorMessages maps a gauntlet sentinel error a client can
// plausibly trigger to a message worth showing them -- gauntlet's own
// error text is written for a developer reading Go source (e.g.
// ErrNotPersisted's "refusing to create a user that would not survive a
// restart"), not for a stranger looking at a login screen. Anything not
// listed here -- including a genuinely unexpected error -- falls back to
// a generic message via writeAuthError, never echoed verbatim to the
// client, only logged server-side. Mirrors mikroview's own
// authErrorMessages (auth.go), narrowed to the errors gate's handlers
// can actually produce.
var gateErrorMessages = map[error]string{
	gauntlet.ErrRegistrationClosed:    "registration is closed -- an account already exists",
	gauntlet.ErrSetupCodeInvalid:      "invalid setup code -- the current one is in the server's log",
	gauntlet.ErrSetupRequired:         "no account exists yet -- create the first admin with the setup code before signing in through SSO",
	gauntlet.ErrNotPersisted:          "this deployment has no persistent storage configured -- an administrator needs to set one up before an account can be created",
	gauntlet.ErrUsernameTaken:         "that username is already taken",
	gauntlet.ErrPasswordTooShort:      gauntlet.ErrPasswordTooShort.Error(), // already phrased for an end user
	gauntlet.ErrPasswordBlocked:       "that password is on a list of common or breached passwords -- choose a different one",
	gauntlet.ErrPasswordContext:       "that password is too close to the username or the product's name -- choose a different one",
	gauntlet.ErrUsernameInvalid:       "that username contains characters that aren't allowed -- no control characters, and no leading or trailing spaces",
	gauntlet.ErrUsernameLength:        gauntlet.ErrUsernameLength.Error(), // already phrased for an end user
	gauntlet.ErrUsernameIsEmail:       "a local account's username can't be an email address -- pick a plain name",
	gauntlet.ErrInvalidRole:           `role must be "admin", "user" or "viewer"`,
	gauntlet.ErrLastAdmin:             "this is the last admin account -- make another account an admin first",
	gauntlet.ErrRoleUnchanged:         "that account already has that role",
	gauntlet.ErrTokenNotPersisted:     "this deployment has no persistent storage configured -- an administrator needs to set one up before a token can be created",
	gauntlet.ErrTokenKindInvalid:      gauntlet.ErrTokenKindInvalid.Error(),
	gauntlet.ErrTokenDeviceRequired:   gauntlet.ErrTokenDeviceRequired.Error(),
	gauntlet.ErrTokenDeviceNotAllowed: gauntlet.ErrTokenDeviceNotAllowed.Error(),
	gauntlet.ErrTokenDeviceInvalid:    gauntlet.ErrTokenDeviceInvalid.Error(),
	gauntlet.ErrTokenNameInvalid:      gauntlet.ErrTokenNameInvalid.Error(),
	gauntlet.ErrTokenExpiryInvalid:    gauntlet.ErrTokenExpiryInvalid.Error(),
	gauntlet.ErrUserNotFound:          "no such user",
	gauntlet.ErrCannotDeleteAdmin:     "the last admin account cannot be deleted -- make another account an admin first",
	gauntlet.ErrTOTPAlreadyActive:     gauntlet.ErrTOTPAlreadyActive.Error(), // already phrased for an end user
	gauntlet.ErrNoPendingTOTP:         gauntlet.ErrNoPendingTOTP.Error(),     // already phrased for an end user
	gauntlet.ErrNoLocalPassword:       gauntlet.ErrNoLocalPassword.Error(),   // already phrased for an end user
	gauntlet.ErrPasskeyDuplicate:      "this passkey is already registered to this account",
	gauntlet.ErrPasskeyLimitReached:   gauntlet.ErrPasskeyLimitReached.Error(), // already phrased for an end user
	gauntlet.ErrPasskeyNotFound:       "no such passkey on this account",
	gauntlet.ErrEnrolmentHeld:         "a second factor is waiting for you to confirm you have saved its recovery codes -- confirm it, or wait ten minutes for it to expire, before setting up another",
	gauntlet.ErrNoHeldEnrolment:       "no second factor is waiting to be confirmed",
	gauntlet.ErrHeldEnrolmentExpired:  "that second factor was not confirmed within ten minutes and has been removed -- set it up again",
}

// writeAuthError translates err into a safe, user-facing message via
// gateErrorMessages (falling back to a generic one for anything not
// listed, logging the real error server-side so it stays diagnosable)
// and writes it as detail on a problem body of class, with status.
// class is always passed explicitly by the call site, never derived
// from status: several classes share a status (400, 409, 500, 503 each
// back more than one), so status alone cannot say which.
func (g *Gate) writeAuthError(w http.ResponseWriter, r *http.Request, err error, status int, class problemClass) {
	msg, ok := gateErrorMessages[err]
	if !ok {
		g.logWarn(authErrorLogLine(r.Method, r.URL.Path, err))
		msg = "unable to complete the request"
	}
	writeProblem(w, status, class, msg, nil)
}

// problemClass is one of the fixed error classes every error Routes or
// Protect answers with belongs to (gauntlet #23, RFC 9457 Problem
// Details): type and title never vary by call site, only detail (and,
// for partially-completed, extra) do. status is not part of the type --
// it is passed separately at each writeProblem/writeAuthError call --
// but every class here in fact has exactly one fixed status, held to by
// convention at the call site and pinned by the tests in
// problem_test.go, not enforced by the type itself.
//
// docs/api/errors.md has one permanent section per anchor: the anchor
// is part of a public URL once released, so it is never renamed, and a
// class already shipped is never removed, only deprecated in that
// document.
type problemClass struct {
	anchor string
	title  string
}

// problemTypeBase, with a class's anchor appended, is that class's
// "type" member.
const problemTypeBase = "https://github.com/tomlawesome/gauntlet/blob/main/docs/api/errors.md#"

// The seventeen classes docs/api/errors.md documents, one var each --
// Go has no constant struct literal, so these stand in for the
// constants the design calls for: built once at package load and never
// written to again.
var (
	classInvalidCredentials = problemClass{"invalid-credentials", "Invalid credentials"}
	classSignInRequired     = problemClass{"sign-in-required", "Sign-in required"}
	classStepExpired        = problemClass{"step-expired", "Start again"}
	classCSRFRequired       = problemClass{"csrf-required", "Missing required header"}
	classForbidden          = problemClass{"forbidden", "Not permitted"}
	classMustChangePassword = problemClass{"must-change-password", "Password change required"}
	classMustEnrolFactor    = problemClass{"must-enrol-factor", "Second factor enrolment required"}
	classInvalidRequest     = problemClass{"invalid-request", "Invalid request"}
	classNotFound           = problemClass{"not-found", "Not found"}
	classConflict           = problemClass{"conflict", "Conflicting state"}
	classRateLimited        = problemClass{"rate-limited", "Too many attempts"}
	classSetupRequired      = problemClass{"setup-required", "Setup required"}
	classNotPersisted       = problemClass{"not-persisted", "No persistent storage"}
	classServerError        = problemClass{"server-error", "Server error"}
	classPartiallyCompleted = problemClass{"partially-completed", "Partly completed"}
	// classSignInRefused (#55) is every credential right and the
	// attempt refused by the account's unusual-sign-in policy (block).
	classSignInRefused = problemClass{"sign-in-refused", "Sign-in refused"}
	// classLastAdmin (#67) is a change refused because it would leave
	// the deployment with no admin: deleting or demoting the last one.
	classLastAdmin = problemClass{"last-admin", "Last admin"}
)

// writeProblem writes an RFC 9457 application/problem+json body: type
// (problemTypeBase+class.anchor), title (class.title) and status always;
// detail (the call site's own message text, unchanged -- gauntlet #23)
// only when it is not empty. extra adds further top-level members --
// only partially-completed's username does (its totpActive is no longer
// sent, #58); every other call site passes nil.
//
// The same two of writeJSON's three headers (Cache-Control: no-store,
// X-Content-Type-Options: nosniff; see that function's own doc comment)
// plus Content-Type: application/problem+json, with no charset
// parameter -- RFC 9457 does not define one for this media type.
func writeProblem(w http.ResponseWriter, status int, class problemClass, detail string, extra map[string]any) {
	h := w.Header()
	h.Set("Content-Type", "application/problem+json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	body := map[string]any{
		"type":   problemTypeBase + class.anchor,
		"title":  class.title,
		"status": status,
	}
	if detail != "" {
		body["detail"] = detail
	}
	for k, v := range extra {
		body[k] = v
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeBlankProblem is writeProblem for problemRouter's own "no route
// matched" and "wrong method" answers (routes.go): RFC 9457's
// about:blank type, title the plain status text, and no detail -- not
// one of the documented classes, since no frontend ever branches on
// which path or method it mistyped.
func writeBlankProblem(w http.ResponseWriter, status int) {
	h := w.Header()
	h.Set("Content-Type", "application/problem+json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "about:blank",
		"title":  http.StatusText(status),
		"status": status,
	})
}

// authErrorLogLine renders the server-side line for an auth error with
// no user-facing message, naming the route so a bare error says where
// to look. Every field is quoted -- r.URL.Path is the decoded request
// target, so a request for a path containing an encoded newline arrives
// here carrying a real one, and %q is what stops a forged log line
// looking genuine (mikroview #528; see its authErrorLogLine).
func authErrorLogLine(method, path string, err error) string {
	return fmt.Sprintf("%q %q: %q", method, path, fmt.Sprint(err))
}
