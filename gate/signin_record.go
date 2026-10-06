package gate

import (
	"fmt"
	"net/http"
	"strings"
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
//     client set) and, for the second-factor, passkey-alone (#77) and
//     SSO paths, how. An
//     unusual one (#55) starts with its signals and the action taken:
//     "unusual=new-browser,new-country; action=flag; ".
//   - user.reauthenticated instead of user.login when the sign-in was a
//     resume of a timed-out session with the password alone (#71): the
//     same session continued under a new ID, not a new sign-in.
//   - user.login_failed on every failed attempt the limiter admitted:
//     actor and target the account's username when the name matched one,
//     else "unknown"; detail the outcome, the method, the address and,
//     for a name that matched no account, the name as
//     gauntlet.MaskUnknownUsername shows it -- never as typed.
//   - user.login_refused on a sign-in whose every credential was right
//     and which the unusual-sign-in policy refused (#55): actor and
//     target the username; detail the signals, the reason, the method,
//     whether the application was told, and the address.
//   - address.banned beside the user.login_failed of the attempt that
//     was the AddressBanFailures'th from one address (gauntlet
//     AddressBanned, #70): once per ban. Actor the account tried (or
//     "unknown"), target the address group (an IPv6 /64 as a prefix),
//     detail until=, the count and period, and from=.
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

// proveActionNote is the part of a held sign-in's note
// (completeHeldSignIn) saying a passkey answered the hold rather than a
// confirmation code, so its user.login says "via passkey proof".
const proveActionNote = "action=" + string(UnusualSignInProve) + "; "

// signInClient is the address, browser and country (#54) r came from,
// as the application resolves the address (Config.ClientIP) and the
// country (Config.Country). address, when set, is the one the
// attempt's reservation was keyed on, so the record names the same
// address the limiter counted. This is the one place that client is
// built for a sign-in record and for the session issueSession starts,
// so the two always agree.
func (g *Gate) signInClient(r *http.Request, address string) gauntlet.SessionClient {
	if address == "" {
		address = g.cfg.ClientIP(r)
	}
	client := gauntlet.SessionClient{Address: address, UserAgent: r.UserAgent()}
	if g.cfg.Country != nil {
		if code, ok := g.cfg.Country(address); ok {
			client.Country = code
		}
	}
	return client
}

// signInFailed reports whether o is a refused credential or a refused
// attempt, rather than an outcome that proved every credential so far:
// a sign-in, a password step that passed, or one the unusual-sign-in
// policy refused or sent a confirmation code for (#55).
func signInFailed(o gauntlet.SignInOutcome) bool {
	switch o {
	case gauntlet.SignInSuccess, gauntlet.SignInPasswordOK, gauntlet.SignInRefused, gauntlet.SignInConfirmSent, gauntlet.SignInEscapeIssued:
		return false
	}
	return true
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
	g.recordSignInNote(r, ev, res, "", now)
}

// recordSignInNote is recordSignIn with note -- the unusual-sign-in
// part of a completed sign-in's detail ("unusual=...; action=...; ",
// #55) -- put before the rest of the user.login detail. ev's signals
// (Client.Unusual) are kept; the rest of its client is filled here.
func (g *Gate) recordSignInNote(r *http.Request, ev gauntlet.SignInEvent, res loginReservation, note string, now time.Time) {
	unusual := ev.Client.Unusual
	ev.Client = g.signInClient(r, res.address)
	ev.Client.Unusual = unusual
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
	case ev.Outcome == gauntlet.SignInRefused:
		g.auditRecord(name, "user.login_refused", name, note+from)
	case !failed:
		if ev.Outcome != gauntlet.SignInSuccess {
			return // password_ok, confirm_sent, escape_issued: no sign-in yet
		}
		if ev.Method == gauntlet.SignInMethodResume {
			g.auditRecord(ev.Username, "user.reauthenticated", ev.Username, "session resumed with password; "+from)
			return
		}
		detail := from
		switch {
		case ev.Confirmed && strings.Contains(note, escapeUsedNote):
			detail = "via escape code; " + from
		case ev.Confirmed && strings.Contains(note, proveActionNote):
			detail = "via passkey proof; " + from
		case ev.Confirmed:
			detail = "via confirmation code; " + from
		case ev.Method == gauntlet.SignInMethodCode, ev.Method == gauntlet.SignInMethodPasskey:
			detail = "via second factor; " + from
		case ev.Method == gauntlet.SignInMethodPasskeyAlone:
			detail = "via passkey; " + from
		case ev.Method == gauntlet.SignInMethodSSO:
			detail = "via sso; " + from
		}
		g.auditRecord(ev.Username, "user.login", ev.Username, note+detail)
	case limiterRefusal(ev.Outcome):
		g.warnRated("login-refused "+ev.Client.Address, fmt.Sprintf(
			"gate: sign-in refused by the login limiter: outcome=%s method=%s account=%q %s",
			ev.Outcome, ev.Method, ev.Username, from))
	default:
		detail := fmt.Sprintf("outcome=%s method=%s %s", ev.Outcome, ev.Method, from)
		if ev.UserID == "" {
			detail += fmt.Sprintf(" name=%q", ev.Username)
		}
		g.auditRecord(name, "user.login_failed", name, detail)
		// Counted toward the address ban (#70) whichever name was tried,
		// an unknown one included: that is the point. The SSO callback
		// is not a guess at a credential here, and is not counted.
		if ev.Method != gauntlet.SignInMethodSSO && g.deps.Limiter.RecordAddressFailure(ev.Client.Address, now) {
			g.auditRecord(name, "address.banned", gauntlet.AddressBanGroup(ev.Client.Address), fmt.Sprintf(
				"until=%s after %d failed sign-ins in %s %s",
				now.Add(gauntlet.AddressBanDuration).UTC().Format(time.RFC3339),
				gauntlet.AddressBanFailures, gauntlet.AddressBanDuration, from))
		}
		if ev.UserID == "" {
			return
		}
		if res.lockoutStarted {
			g.auditRecord(name, "account.locked", name, fmt.Sprintf("until=%s lockouts=%d %s",
				res.lockedUntil.UTC().Format(time.RFC3339), res.lockouts, from))
			g.notify(r.Context(), &AccountNotice{
				Kind: NoticeAccountLocked, UserID: ev.UserID, Username: name, At: now,
				Lockout: &LockoutDetail{Until: res.lockedUntil, Lockouts: res.lockouts, Address: ev.Client.Address},
			})
		}
		if res.disabledNow {
			g.auditRecord(name, "account.disabled", name, fmt.Sprintf("after %d consecutive failures; %s",
				gauntlet.MaxConsecutiveLoginFailures, from))
			g.notify(r.Context(), &AccountNotice{
				Kind: NoticeSignInDisabled, UserID: ev.UserID, Username: name, At: now,
				Lockout: &LockoutDetail{Until: res.lockedUntil, Lockouts: res.lockouts, Address: ev.Client.Address},
			})
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
