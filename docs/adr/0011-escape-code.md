# ADR-0011: A log-written escape code lets a lone admin past `block`

**Status:** Accepted (design ratified on #66)
**Date:** 2026-10-05
**Relates to:** #66 (this change), #55 and ADR-0009 (the unusual-sign-in
policy and the confirm step this reuses), #67 and ADR-0010 (a second
admin is the first remedy), #44 and #70 (the unlock code; the disable
that now lifts after 24 hours), #37 and ADR-0003 (the setup code),
ORBIT ADR-0022 (the owner's version of the log-written code), ADR-0002
(compatibility)

## Context

Under `block` (ADR-0009), an admin who signs in from a browser the
account has never used is refused, whatever the reason (policy, a
`Decide` that answered `block` or failed, a confirm notice that could
not be sent). With another admin that is a small cost: they issue a
reset code. For the only admin able to act it is a dead end, which
ADR-0009 shipped as designed and documented, with a log-written escape
code tracked as #66.

The standard answer to "the only person who could fix this is the one
locked out" is an out-of-band break-glass code through the host's own
log, which this module already uses twice: the setup code (ADR-0003) and
the unlock code (#44). Reaching it needs access to the server, not just
its address.

## Decision

Pattern: **out-of-band break-glass code via the host's own log, redeemed
on the held sign-in (as the setup and unlock codes).** The redemption
shape is the confirm step's (#55): a sealed ticket in the refused
browser and a code typed into the same page. No new concept: it is
`confirm` with the code delivered to the log instead of
`Config.DeliverConfirmCode`.

1. **When a code is issued.** At the point a refusal is written, on the
   local password path (`handleLogin`) and the second-factor path
   (`completeLoginFactor`), only when all hold: the verdict is `block`;
   the account is an admin; no other admin can act
   (`Store.OtherAdminCanAct(userID, now)`: no admin other than this one
   whose sign-in is not disabled at `now`, `User.LoginDisabled`); and
   something can announce the code (`Config.OnEscapeCode`, else
   `Config.Log`) -- otherwise it fails closed with no ticket and no
   line. A temporarily locked-out other admin still counts as able: a
   lockout ends within the hour, while a disable lasts up to 24 hours
   (#70) and does not. Another admin who would also be refused cannot be
   known and is not counted; two admins both abroad on new laptops is
   the documented residual, and `Decide` answering `confirm` or `flag`
   for admins stays the application's first remedy.
2. **Never** for a user or viewer (an admin resets them), never on the
   SSO callback (every admin keeps a local password, ADR-0010), and
   never while the account is disabled (the unlock code is for that, and
   a disabled account refuses before any credential).
3. **The code** is `gauntlet.NewOneTimeCode()`, the setup and unlock
   codes' generator exported: 80 bits, `xxxx-xxxx-xxxx-xxxx`, typed
   either case with or without dashes. Only its SHA-256 is kept, inside
   a sealed ticket cookie `gate_escape_login` (path `/api/auth/login`,
   15 minutes, `EscapeCodeLifetime`), under a per-process key of its own.
   Nothing is stored and nothing can read the code back: it exists in
   the log line (a Warn) or in the one call to `Config.OnEscapeCode`.
4. **Binding and single use.** The code is bound to the account and to
   the attempt's browser through the ticket: useless without the cookie,
   and the cookie useless without the code. A ticket is claimed by its
   ID, as confirm's is; the loser of a race gets `step-expired`. A
   restart kills the key, so every outstanding ticket. One ticket per
   refused attempt: a new refusal overwrites the cookie. There is no
   throttle beyond the login limiter, since every refusal already cost
   the password and the second factor.
5. **Entry.** `POST /api/auth/login/escape`, body `{"code": ...}`,
   session-exempt, CSRF header required. It is `handleLoginConfirm` with
   the escape cookie, codec and spent set and the reset-code form of the
   code. It reserves the attempt on the account and the address like
   any login step, so an address ban or a lockout refuses it with `429`
   exactly as it refuses confirm; a wrong code keeps the reservation,
   counts as a failed second factor, records `escape_refused` and
   answers `401 invalid-credentials` ("invalid escape code": one cause,
   no pair). The right code completes the sign-in with the ticket's
   signals: the browser, country and place are remembered (so the
   browser becomes known), the history row is a `success` marked
   confirmed, and the response is `200 {username, role}`.
6. **What the refusal says.** The `403 sign-in-refused` body is
   unchanged, so a stranger learns nothing; it now also sets the ticket
   cookie when a code was issued, and a frontend offers "have a code
   from the server log?" on every refused screen.
7. **Audit and notice.** `user.login_refused`'s note gains
   `escape=issued; `; a history row `escape_issued` is recorded next to
   the `refused` row (new `SignInOutcome` values `escape_issued` and
   `escape_refused`; the history document version is unchanged, since an
   outcome is a string). A completed escape records `user.login` with
   `unusual=...; action=block; escape=used; ` and "via escape code". The
   block notice goes out as today; the completed sign-in sends a
   flag-style `NoticeUnusualSignIn` with `Action: block`, `Reason:
   "escape"` and `SessionRef` set, under the existing hourly quiet. No
   new `NoticeKind`.
8. **Additive API.** `gauntlet.NewOneTimeCode`,
   `Store.OtherAdminCanAct`, `SignInEscapeIssued`, `SignInEscapeRefused`,
   `gate.Config.OnEscapeCode`, `gate.EscapeCodeHandler` and
   `gate.EscapeCodeFunc`, `gate.EscapeCodeLifetime`, and the route
   (`docs/api/auth.yaml`). `Decide` is untouched: the escape reads only
   the final verdict.

## Rejected options

- **A stored code on the account, as the unlock code is.** Rejected: the
  ticket already binds the code to one browser and one attempt, needs no
  document change and dies with the process; a stored code would be
  usable from any browser and would outlive its attempt.
- **A code in the 403 response or a notice.** Rejected: that hands the
  credential to whoever holds the password and second factor, which is
  exactly the thief the `block` was for. Only the host's log is out of
  band.
- **Counting a would-be-refused other admin as unable.** Rejected:
  unknowable at this point, and guessing wrong would issue codes where a
  second admin could have helped.
- **Escape on the SSO callback.** Rejected: every admin keeps a local
  password and second factor (ADR-0010), so the local path is always
  there, and the callback has no place to type a code.

## Consequences

- Someone with log access owns the host and already has the setup and
  unlock codes. Someone without it has the ticket (if they stole the
  password and second factor) but no code, or a code but no ticket;
  either half alone is nothing. A thief holding both credentials can only
  cause Warn lines bound to their own browser.
- With two admins able to act the condition is false, nothing is written
  and `block` is exactly as before.
- Under #70 a disabled other admin stops counting, so the lone-admin
  escape returns for as long as that disable lasts.
- An application that ships no log (`Config.Log` nil) and no
  `Config.OnEscapeCode` offers no escape; the lone admin's remedy there
  is as before.
