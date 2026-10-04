# Error classes

Every error `gate.Routes` and `gate.Protect` answer with is an RFC 9457
Problem Details body (`Content-Type: application/problem+json`,
`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`):

```json
{
  "type": "https://github.com/tomlawesome/gauntlet/blob/main/docs/api/errors.md#invalid-request",
  "title": "Invalid request",
  "status": 400,
  "detail": "invalid request body"
}
```

- **`type`** is a permanent link into this file's anchors, one per
  class below. A frontend branches on it -- never on `detail`'s text,
  which may be reworded at any time, and never on the status code
  alone, since more than one class shares a status.
- **`title`** and **`status`** are fixed per class; `title` is never
  more useful than `type` and exists only because RFC 9457 requires it.
- **`detail`** is free text naming the call site's own reason. Absent
  when a class has nothing more specific to say than its `title` (the
  three `about:blank` cases below, and a handful of plain 404s).
- One class carries extension members beyond the four above --
  `partially-completed`'s `username` (and `totpActive`, no longer sent
  since #58) -- named in that class's own section. No other class has
  any, and none is planned.

**`about:blank`.** A request whose path matches no route, or matches
one only under a different method, answers this generic shape instead:
`type: "about:blank"`, `title` the plain HTTP status text ("Not Found",
"Method Not Allowed"), `status`, no `detail`. It is not one of the
classes below -- deliberately: no frontend needs to branch on which
path or method it mistyped, and `about:blank` is RFC 9457's own name
for exactly this "nothing more to say" case. A `405` still carries the
`Allow` header naming the methods the path does take; only the body
changed.

**This file's anchors are permanent.** Once a class ships, its anchor
is never renamed or removed -- a published `type` URL must keep
resolving to the same meaning for as long as any client might have it
cached or hard-coded. A class that no longer applies is marked
*Deprecated* in its own section, with the release it stopped being
returned in; its anchor stays, and this file never moves to a
different path.

**Security: identical outcomes, identical bodies.** A handful of pairs
of genuinely different causes -- an unknown username versus a wrong
password, say -- answer with exactly the same class *and* the same
`detail` text, on purpose: telling them apart would hand an attacker a
free oracle for which half of a credential pair is wrong. Each pair is
named under the class it shares, below.

## invalid-credentials

- **Status:** 401. **Title:** Invalid credentials.
- A credential presented with the request -- a password, a one-time
  code, a bearer token, a passkey assertion -- was wrong, or has already
  been spent. Carries `WWW-Authenticate: Bearer realm="gate"` (RFC 6750
  §3), as every 401 here does.
- Returned by: `POST /api/auth/register` (wrong or missing setup code),
  `POST /api/auth/login` (wrong username or password), `POST
  /api/auth/login/factor` (wrong authenticator code or recovery code, or
  a refused passkey assertion), `POST /api/auth/unlock` (wrong admin
  username or unlock code), every route that re-checks the caller's own
  password or second factor before acting (`POST /api/auth/password`,
  `POST /api/auth/totp/enrol`, `DELETE /api/auth/totp`, `POST
  /api/auth/recovery-codes`, `POST /api/auth/passkeys/register/begin`,
  `DELETE /api/auth/passkeys/{id}`, `POST
  /api/auth/users/{id}/unlock` on the caller's own account), and `gate.
  Protect` itself for a bearer token that matches no registered kind, is
  revoked or expired, or is not a well-formed `Bearer <token>` credential
  at all.
- `detail` varies by call site, but not within one: see the security
  pairs below.
- **Security pairs sharing this class and body:** an unknown username
  and a wrong password at `login` ("invalid username or password"); a
  wrong authenticator code and a wrong recovery code at `login/factor`
  ("invalid code"); an unknown admin username and a wrong unlock code at
  `unlock` ("invalid username or unlock code -- the current code, if
  any, is in the server's log"); a wrong current setup code and an
  already-rotated one at `register`; a missing bearer token's kind, a
  revoked one, an expired one and a malformed `Authorization` header at
  `Protect` (all "invalid or revoked token"); a refused passkey assertion
  of any kind -- wrong signature, clone warning, a counter that failed
  to save, the credential no longer existing -- at `login/factor`
  (`passkeyNotVerified`, "that passkey couldn't be verified -- use
  another way in"). None of these is ever split into a more specific
  class or a more specific message.

## sign-in-required

- **Status:** 401. **Title:** Sign-in required.
- No valid session cookie. Carries `WWW-Authenticate: Bearer
  realm="gate"`.
- Returned by `gate.Protect` for any session-gated route reached with no
  session, expired session, or one revoked since (a password change, a
  reset, an SSO link); every handler's own "sign in first" check answers
  the same class when reached directly (normally unreachable once
  mounted under `Protect`, which already refuses the request first).
- `detail` is "sign in first" or "unauthorized" depending on which check
  answered; a frontend never reads it.

## step-expired

- **Status:** 401. **Title:** Start again.
- A multi-step process -- the pending login between `login` and
  `login/factor`, a passkey ceremony, or a second-factor enrolment
  waiting to be confirmed -- is invalid, expired, already completed by
  another request, or its target account is gone or has lost the factor
  it needed. Carries `WWW-Authenticate: Bearer realm="gate"`. The cookie
  the step depended on, if it had one, is cleared with the response.
- Returned by `POST /api/auth/login/factor` and `POST
  /api/auth/login/factor/begin` (the pending-login cookie: missing,
  expired, tampered with, already spent by another request, or the
  account was deleted or lost every second factor since the password
  step), and `POST /api/auth/passkeys/register/finish` and the passkey
  branch of `POST /api/auth/login/factor` (the ceremony cookie: missing,
  expired, tampered with, already spent, or sealed for the other
  ceremony), `POST /api/auth/totp/confirm` (the scanned authenticator-app
  secret was set more than ten minutes ago) and `POST
  /api/auth/recovery-codes/confirm` (the first factor was held for more
  than ten minutes without its recovery codes being confirmed, and has
  been deleted) (#58).
- A frontend restarts the flow from its first step -- there is nothing
  left for a retry at this step to complete.

## csrf-required

- **Status:** 403. **Title:** Missing required header.
- `X-Requested-With` is missing, or does not equal the application's
  configured value. Checked on every `POST`, `PATCH` and `DELETE`,
  before any session, role or door check, on every route including the
  session-exempt ones (`register`, `login`, `unlock`, ...).
- `detail` is always "missing required header".

## forbidden

- **Status:** 403. **Title:** Not permitted.
- The session's account holds a role gauntlet does not recognize
  (`account role is not recognized`), or, on an admin-only route, the
  caller is not an admin (`insufficient role`).
- Returned by `gate.Protect` and `gate.RequireRole` (and so every
  admin-only route under `Routes`).

## sign-in-refused

- **Status:** 403. **Title:** Sign-in refused.
- Every credential was right, and the account's sign-in policy refused
  the attempt from this browser or place (#55: the application set an
  unusual sign-in to `block`, or its own check could not be run).
  Retrying from the same browser and place changes nothing; the account
  itself is not locked.
- Returned by `POST /api/auth/login` and `POST /api/auth/login/factor`.
  The SSO callback redirects with `ssoError=refused` instead.
- `detail` is always "this sign-in was refused by the account's sign-in
  policy -- use a browser or place this account has signed in from
  before, or ask an administrator to reset the account". It never says
  which signal was raised, or whether a code would have been sent.
- No `X-Auth-Gate` header: that header marks a session stopped at a
  door, and no session exists here.

## must-change-password

- **Status:** 403. **Title:** Password change required.
- The session is stopped at the forced-password-change door: an
  administrator reset the account, five second-factor steps in a row
  failed, or a sign-in found the password breached. Carries
  `X-Auth-Gate: must-change-password` -- a frontend matches this header,
  never the `detail` text, to route the session straight to the one
  door that gets it out: `POST /api/auth/password`.
- Returned by `gate.Protect` for every route except `POST
  /api/auth/password` while the door holds.

## must-enrol-factor

- **Status:** 403. **Title:** Second factor enrolment required.
- The session's account has a local password and no second factor yet
  -- mandatory for every such account (#49). Carries `X-Auth-Gate:
  must-enrol-factor`; a frontend matches this header, never `detail`, to
  route the session to TOTP enrolment or passkey registration.
- Returned by `gate.Protect` for every route except the TOTP enrol and
  confirm routes, the passkey register begin and finish routes and
  `POST /api/auth/recovery-codes/confirm`, while the door holds. A first
  factor held for its recovery codes to be confirmed (#58) is not yet a
  factor: the door holds until the confirmation.

## invalid-request

- **Status:** 400. **Title:** Invalid request.
- The request body is not one JSON object of the documented fields
  (an unknown field or trailing data is refused, not ignored), a path
  parameter that must be present is empty, or a field's value fails a
  rule gauntlet enforces (password length or breach status, username
  shape, role name, a token's name, kind or device). `detail` names the
  rule, except a handful of generic "invalid request body" sites where
  only the shape, not the content, was wrong.
- Returned across nearly every route that takes a body or a path
  parameter; see the OpenAPI document for which status a given field
  rule answers with on which route.

## not-found

- **Status:** 404. **Title:** Not found.
- No account, token, session or passkey has the id or ref given; or the
  application does not offer this feature at all (`Deps.Passkeys`,
  `Deps.OIDC` or `Deps.SignIns` is nil). `detail` is absent for the
  feature-off cases and named for the rest ("no such user", "no such
  session", "no such token", "no such passkey on this account",
  "sign-in history is not configured").
- Not the same as `about:blank`: this class is for a *route that exists*
  answering "nothing here has that id"; `about:blank` is for a path or
  method the route table never registered at all.

## conflict

- **Status:** 409. **Title:** Conflicting state.
- The request is refused because of the account's or the deployment's
  current state, not because of anything wrong with the request itself:
  an account already in the shape the route would put it in (already
  registered, already linked to SSO, already has an active factor,
  already holds ten passkeys, already has a first factor held for its
  recovery codes to be confirmed, or has nothing held to confirm), an
  account the route refuses to act on
  (the admin account, the caller's own), or a relying party or SSO
  identity that is not ready or not usable. `detail` names which.
- Returned across most routes with a notion of "already done" or "not
  this account". `GET /api/auth/session`'s `passkeys.status` is the
  machine-readable form of "relying party not ready"; this class's
  `detail` only repeats it for a human.

## rate-limited

- **Status:** 429. **Title:** Too many attempts.
- Too many attempts from this client address, or against this account,
  in the current window. `detail` is always "too many attempts, try
  again later".
- Returned by every rate-limited route: login, the second-factor step,
  registration, the admin and lone-admin unlock routes, and every
  password or second-factor re-check.

## setup-required

- **Status:** 503. **Title:** Setup required.
- No account exists yet, so nothing but `GET /api/auth/session` and
  `POST /api/auth/register` is reachable (SSO is not exempt: the first
  account is never an SSO one). `detail` is "setup required".
- Returned by `gate.Protect` itself, before any route-specific handler
  runs.

## not-persisted

- **Status:** 503. **Title:** No persistent storage.
- The deployment has no persistent storage backend configured, so
  creating an account or a token would not survive a restart.
- Returned by `POST /api/auth/register`, `POST /api/auth/users`, `POST
  /api/auth/users/{id}/reset-password` and `POST /api/tokens`.
  `detail` names what an administrator needs to do about it.

## server-error

- **Status:** 500. **Title:** Server error.
- Every other way a request could not be completed: an unexpected
  backend failure, with the real cause logged server-side and never
  echoed in `detail`, which is always a generic line such as "unable to
  complete the request" or "unable to create token".
- Returned wherever a store, session or token operation fails for a
  reason none of the other classes name.

## partially-completed

- **Status:** 500. **Title:** Partly completed.
- A request that changed something but failed before finishing
  everything it meant to. One site:
  - `DELETE /api/auth/users/{id}`: the account was deleted, but its API
    tokens could not be revoked. Extension member **`username`** (the
    deleted account's).
- `detail` says what a person should do next (revoke the tokens by
  hand); there is no automatic retry for the half-finished state.
- No longer returned, since #58, by `POST /api/auth/totp/confirm` (with
  extension member **`totpActive`**, always `true`) or `POST
  /api/auth/passkeys/register/finish`, where a first factor went live
  but its recovery codes could not be saved. The factor and its codes
  are now saved in one write, held until confirmed, so that state
  cannot happen; a failed save there is `server-error`.
