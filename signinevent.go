package gauntlet

import "time"

// SignInOutcome is how one sign-in attempt ended (#45, #53). A closed
// set: new values may be added, existing ones keep their meaning.
type SignInOutcome string

const (
	// SignInSuccess is a completed sign-in: a session was issued.
	SignInSuccess SignInOutcome = "success"
	// SignInPasswordOK is a right password on an account that still
	// owes a second factor: no session yet.
	SignInPasswordOK SignInOutcome = "password_ok"
	// SignInNoSuchUser is a name that matched no account.
	SignInNoSuchUser SignInOutcome = "no_such_user"
	// SignInWrongPassword is a wrong password for an account that exists.
	SignInWrongPassword SignInOutcome = "wrong_password"
	// SignInFactorRefused is a refused second factor: a wrong or used
	// code, or a refused passkey assertion.
	SignInFactorRefused SignInOutcome = "factor_refused"
	// SignInLocked is an attempt refused because a lockout is in force.
	SignInLocked SignInOutcome = "locked"
	// SignInDisabled is an attempt refused because the account's
	// sign-in is disabled.
	SignInDisabled SignInOutcome = "disabled"
	// SignInRateLimited is an attempt the login limiter refused for any
	// other reason: the address at its limit, or the name's own count.
	SignInRateLimited SignInOutcome = "rate_limited"
	// SignInSSORefused is an identity the provider vouched for that this
	// deployment's SSO policy refused.
	SignInSSORefused SignInOutcome = "sso_refused"
	// SignInRefused is a sign-in whose every credential was right but
	// which gate's unusual-sign-in policy refused (#55, the block
	// action): no session.
	SignInRefused SignInOutcome = "refused"
	// SignInConfirmSent is a sign-in whose every credential was right
	// and which owes a confirmation code (#55, the confirm action): a
	// code was sent through the application, no session yet.
	SignInConfirmSent SignInOutcome = "confirm_sent"
	// SignInConfirmRefused is a wrong confirmation code.
	SignInConfirmRefused SignInOutcome = "confirm_refused"
	// SignInEscapeIssued is a lone admin's sign-in whose every credential
	// was right and which the policy refused (#66): an escape code was
	// written to the server's log, no session yet. A refused row is
	// recorded with it.
	SignInEscapeIssued SignInOutcome = "escape_issued"
	// SignInEscapeRefused is a wrong escape code.
	SignInEscapeRefused SignInOutcome = "escape_refused"
	// SignInUnrecorded is a SignInHistory row standing for the failed
	// attempts past a bucket's row budget (signins.go). gate never
	// reports it as an event.
	SignInUnrecorded SignInOutcome = "unrecorded"
)

// SignInMethod is what an attempt presented: a password, a code (TOTP
// or recovery), a passkey assertion as the second step after a
// password, a passkey assertion on its own (#77), a single sign-on
// callback, or a password or passkey alone to resume a session that
// timed out (#71).
type SignInMethod string

const (
	SignInMethodPassword SignInMethod = "password"
	SignInMethodCode     SignInMethod = "code"
	SignInMethodPasskey  SignInMethod = "passkey"
	// SignInMethodPasskeyAlone is a passkey assertion that verified the
	// user, presented with no password before it (#77, ADR-0012): the
	// authenticator's own check -- a PIN or a biometric, neither of which
	// reaches gauntlet -- is the second factor, and the passkey itself
	// the first.
	SignInMethodPasskeyAlone SignInMethod = "passkey_alone"
	SignInMethodSSO          SignInMethod = "sso"
	// SignInMethodResume is the password-only (or, #77, user-verifying
	// passkey-only) resume of a session that timed out through
	// inactivity inside its lifetime ceiling
	// (POST /api/auth/reauthenticate, #71). A SignInSuccess with this
	// method issued a new session ID for the same sign-in, not a new
	// sign-in.
	SignInMethodResume SignInMethod = "resume"
)

// SignInEvent is one sign-in attempt as gate reports it (#45, #53).
// Username is already the account's own username when the attempt
// matched one, or MaskUnknownUsername's form when it did not; the name
// as typed is never carried here.
type SignInEvent struct {
	// UserID is the account the attempt was on, empty when the name
	// matched none.
	UserID   string
	Username string
	Outcome  SignInOutcome
	Method   SignInMethod
	// Client is the address and browser the attempt came from, as the
	// application's ClientIP and the User-Agent header gave them, with
	// the country looked up and the unusual-sign-in signals raised
	// (Client.Unusual, #55).
	Client SessionClient
	// LockedUntil is the end of the lockout this attempt started, or
	// for a SignInLocked refusal the one in force. Zero otherwise.
	LockedUntil time.Time
	// Disabled is set on the failed attempt that disabled the account's
	// sign-in, and on a SignInDisabled refusal.
	Disabled bool
	// Confirmed is set on a SignInSuccess completed through a
	// confirmation code, a passkey, the escape code or an admin's
	// allowance (#55, #65, #66, #81).
	Confirmed bool
}
