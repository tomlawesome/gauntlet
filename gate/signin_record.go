package gate

import (
	"fmt"
	"net/http"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// Every sign-in attempt goes through recordSignIn (#45, #53): the
// password step, the second-factor step by code or passkey, and the SSO
// callback. It writes what the application's audit sink needs and, for
// refusals by the login limiter, a rated Warn line instead.
//
// Recorded:
//
//   - user.login on a completed sign-in, its detail carrying the client
//     address (from=, quoted: Config.ClientIP may read a header the
//     client set) and, for the second-factor and SSO paths, how.
//   - user.login_failed on every failed attempt the limiter admitted:
//     actor and target the account's username when the name matched one,
//     else "unknown"; detail the outcome, the method, the address and,
//     for a name that matched no account, the name as
//     gauntlet.MaskUnknownUsername shows it -- never as typed.
//   - account.locked and account.disabled beside the user.login_failed
//     of the attempt that started a lockout or disabled sign-in. An
//     attempt that did either but succeeded hands it back
//     (gauntlet.LoginLimiter.SignedIn) and writes neither.
//
// A limiter refusal (429) writes no audit record -- a flood of them
// would become a flood of audit writes -- but one Warn line per address
// per minute (warnRated). The right password with a second factor
// still owed writes nothing to the audit: no sign-in has happened yet.
// A "sign in again" refusal of a spent pending login and a backend
// failure record nothing at all, since neither checked a credential.

// unknownAccount is the actor and target of an attempt whose name
// matched no account.
const unknownAccount = "unknown"

// signInClient is the address and browser r came from, as the
// application resolves the address (Config.ClientIP). address, when
// set, is the one the attempt's reservation was keyed on, so the
// record names the same address the limiter counted.
func (g *Gate) signInClient(r *http.Request, address string) gauntlet.SessionClient {
	if address == "" {
		address = g.cfg.ClientIP(r)
	}
	return gauntlet.SessionClient{Address: address, UserAgent: r.UserAgent()}
}

// signInFailed reports whether o is a refused credential or a refused
// attempt, rather than a sign-in or a password step that passed.
func signInFailed(o gauntlet.SignInOutcome) bool {
	return o != gauntlet.SignInSuccess && o != gauntlet.SignInPasswordOK
}

// limiterRefusal reports whether o is the login limiter refusing the
// attempt before any credential was checked.
func limiterRefusal(o gauntlet.SignInOutcome) bool {
	switch o {
	case gauntlet.SignInRateLimited, gauntlet.SignInLocked, gauntlet.SignInDisabled:
		return true
	}
	return false
}

// recordSignIn records one sign-in attempt: ev carries who and how, res
// the limiter's reservation for it (the zero value for SSO, which the
// limiter does not meter). It fills ev's Client, and for a failed
// attempt the lockout or disable it started, appends ev to the sign-in
// history (Deps.SignIns) when there is one, then writes the audit
// record or Warn line (see this file's header).
func (g *Gate) recordSignIn(r *http.Request, ev gauntlet.SignInEvent, res loginReservation, now time.Time) {
	ev.Client = g.signInClient(r, res.address)
	failed := signInFailed(ev.Outcome)
	switch {
	case ev.Outcome == gauntlet.SignInLocked:
		ev.LockedUntil = res.lockedUntil
	case ev.Outcome == gauntlet.SignInDisabled:
		ev.Disabled = true
	case failed:
		if res.lockoutStarted {
			ev.LockedUntil = res.lockedUntil
		}
		ev.Disabled = res.disabledNow
	}
	if g.signInHook != nil {
		g.signInHook(ev, now)
	}
	if g.deps.SignIns != nil {
		g.deps.SignIns.Record(ev, now)
	}

	from := fmt.Sprintf("from=%q", ev.Client.Address)
	name := ev.Username
	if ev.UserID == "" {
		name = unknownAccount
	}
	switch {
	case !failed:
		if ev.Outcome != gauntlet.SignInSuccess {
			return // password_ok: no sign-in yet
		}
		detail := from
		switch ev.Method {
		case gauntlet.SignInMethodCode, gauntlet.SignInMethodPasskey:
			detail = "via second factor; " + from
		case gauntlet.SignInMethodSSO:
			detail = "via sso; " + from
		}
		g.audit(ev.Username, "user.login", ev.Username, detail)
	case limiterRefusal(ev.Outcome):
		g.warnRated("login-refused "+ev.Client.Address, fmt.Sprintf(
			"gate: sign-in refused by the login limiter: outcome=%s method=%s account=%q %s",
			ev.Outcome, ev.Method, ev.Username, from))
	default:
		detail := fmt.Sprintf("outcome=%s method=%s %s", ev.Outcome, ev.Method, from)
		if ev.UserID == "" {
			detail += fmt.Sprintf(" name=%q", ev.Username)
		}
		g.audit(name, "user.login_failed", name, detail)
		if ev.UserID == "" {
			return
		}
		if res.lockoutStarted {
			g.audit(name, "account.locked", name, fmt.Sprintf("until=%s lockouts=%d %s",
				res.lockedUntil.UTC().Format(time.RFC3339), res.lockouts, from))
		}
		if res.disabledNow {
			g.audit(name, "account.disabled", name, fmt.Sprintf("after %d consecutive failures; %s",
				gauntlet.MaxConsecutiveLoginFailures, from))
		}
	}
}

// loginEvent is the event for an attempt on user (nil when the name
// matched no account, typed then being what was typed).
func loginEvent(user *gauntlet.User, typed string, outcome gauntlet.SignInOutcome, method gauntlet.SignInMethod) gauntlet.SignInEvent {
	ev := gauntlet.SignInEvent{Outcome: outcome, Method: method}
	if user != nil {
		ev.UserID, ev.Username = user.ID, user.Username
	} else {
		ev.Username = gauntlet.MaskUnknownUsername(typed)
	}
	return ev
}
