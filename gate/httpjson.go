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
//   - gateErrorMessages gives ErrSingleAdmin and ErrCannotDeleteAdmin
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
func decodeJSONBody(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errTrailingJSON
	}
	return nil
}

// writeJSON is the only place gate writes a JSON response body -- every
// handler goes through it (directly, or through writeAuthError's two
// JSON cases) rather than setting headers of its own, so these three
// headers only have to be right once (#46):
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
	gauntlet.ErrUsernameInvalid:       "that username contains characters that aren't allowed -- no control characters, and no leading or trailing spaces",
	gauntlet.ErrUsernameLength:        gauntlet.ErrUsernameLength.Error(), // already phrased for an end user
	gauntlet.ErrUsernameIsEmail:       "a local account's username can't be an email address -- pick a plain name",
	gauntlet.ErrInvalidRole:           `role must be "user" or "viewer"`,
	gauntlet.ErrTokenNotPersisted:     "this deployment has no persistent storage configured -- an administrator needs to set one up before a token can be created",
	gauntlet.ErrTokenKindInvalid:      gauntlet.ErrTokenKindInvalid.Error(),
	gauntlet.ErrTokenDeviceRequired:   gauntlet.ErrTokenDeviceRequired.Error(),
	gauntlet.ErrTokenDeviceNotAllowed: gauntlet.ErrTokenDeviceNotAllowed.Error(),
	gauntlet.ErrTokenDeviceInvalid:    gauntlet.ErrTokenDeviceInvalid.Error(),
	gauntlet.ErrTokenNameInvalid:      gauntlet.ErrTokenNameInvalid.Error(),
	gauntlet.ErrUserNotFound:          "no such user",
	gauntlet.ErrSingleAdmin:           "this deployment allows only one admin account -- transfer the admin role to this user first",
	gauntlet.ErrCannotDeleteAdmin:     "the admin account cannot be deleted -- transfer the admin role to another account first",
	gauntlet.ErrTOTPAlreadyActive:     gauntlet.ErrTOTPAlreadyActive.Error(), // already phrased for an end user
	gauntlet.ErrNoPendingTOTP:         gauntlet.ErrNoPendingTOTP.Error(),     // already phrased for an end user
	gauntlet.ErrNoLocalPassword:       gauntlet.ErrNoLocalPassword.Error(),   // already phrased for an end user
	gauntlet.ErrPasskeyDuplicate:      "this passkey is already registered to this account",
	gauntlet.ErrPasskeyLimitReached:   gauntlet.ErrPasskeyLimitReached.Error(), // already phrased for an end user
	gauntlet.ErrPasskeyNotFound:       "no such passkey on this account",
}

// writeAuthError translates err into a safe, user-facing message via
// gateErrorMessages (falling back to a generic one for anything not
// listed, logging the real error server-side so it stays diagnosable)
// and writes it with status.
func (g *Gate) writeAuthError(w http.ResponseWriter, r *http.Request, err error, status int) {
	msg, ok := gateErrorMessages[err]
	if !ok {
		g.logWarn(authErrorLogLine(r.Method, r.URL.Path, err))
		msg = "unable to complete the request"
	}
	http.Error(w, msg, status)
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
