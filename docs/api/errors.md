# Error classes

Every error that `gate.Routes` and `gate.Protect` return comes back as
JSON in the standard RFC 9457 "Problem Details" format, which gives
each error a `type`, a `title`, a `status` and a `detail`. The response
carries `Content-Type: application/problem+json`,
`Cache-Control: no-store` and `X-Content-Type-Options: nosniff`:

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
- **`detail`** is free text giving the route's own reason. It is absent
  when a class has nothing more specific to say than its `title` (the
  two `about:blank` cases below, and a handful of plain 404s).
- One class adds an extra field beyond those four:
  `partially-completed` adds `username` (it also sent `totpActive`
  before #58). That class's own section says more. No other class has
  any, and none is planned.

**`about:blank`.** A request whose path matches no route, or matches
one only under a different method, gets this generic shape instead:
`type: "about:blank"`, `title` the plain HTTP status text ("Not Found",
"Method Not Allowed"), `status`, no `detail`. It is not one of the
classes below, on purpose: no frontend needs to branch on which path or
method it mistyped, and `about:blank` is RFC 9457's own name for
exactly this "nothing more to say" case. A `405` also carries the
`Allow` header listing the methods the path accepts.

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
`detail` text, on purpose: telling them apart would let an attacker
find out which part of a guess was wrong, such as whether a username
exists. Each pair is named under the class it shares, below.

## invalid-credentials

- **Status:** 401. **Title:** Invalid credentials.
- A credential sent with the request -- a password, a one-time code, a
  bearer token, a passkey -- was wrong, or has already been used.
  Carries `WWW-Authenticate: Bearer realm="gate"` (RFC 6750 §3), as
  every 401 here does.
- Returned by:

  | Route | Cause | `detail` |
  |---|---|---|
  | `POST /api/auth/register` | Wrong or missing setup code | "invalid setup code -- the current one is in the server's log" |
  | `POST /api/auth/login` | Wrong username or password | "invalid username or password" |
  | `POST /api/auth/login/factor` | Wrong authenticator code or recovery code | "invalid code" |
  | `POST /api/auth/login/factor` | Passkey refused | "that passkey couldn't be verified -- use another way in" |
  | `POST /api/auth/login/passkey` | Passkey refused, signing in with a passkey alone (#77) | the same passkey text |
  | `POST /api/auth/reauthenticate` | Wrong password, or passkey refused, for the timed-out session's account (#71, #77) | "incorrect password", or the passkey text |
  | `POST /api/auth/login/confirm` | Wrong confirmation code (#55) | "invalid confirmation code" |
  | `POST /api/auth/login/prove` | Passkey refused (#65) | the passkey text |
  | `POST /api/auth/login/escape` | Wrong escape code (#66) | "invalid escape code" |
  | `POST /api/auth/unlock` | Wrong admin username or unlock code | "invalid username or unlock code -- the current code, if any, is in the server's log" |
  | `POST /api/auth/password` | Wrong current password | "current password is incorrect" |
  | `POST /api/auth/totp/enrol`, `DELETE /api/auth/totp`, `POST /api/auth/recovery-codes`, `POST /api/auth/passkeys/register/begin`, `DELETE /api/auth/passkeys/{id}`, `POST /api/auth/oidc/link`, `POST /api/auth/logout-all` (an account with a local password) | Wrong password at the re-check of the caller's own password | "incorrect password" |
  | `POST /api/auth/users/{id}/reset-password`, `POST /api/tokens`, `DELETE /api/auth/users/{id}`, `DELETE /api/auth/users/{id}/totp`, `DELETE /api/auth/users/{id}/passkeys` | Wrong password at the re-check of the calling admin's own password (#72) | "incorrect password" |
  | `POST /api/auth/users` and `PUT /api/auth/users/{id}/role` when they grant the admin role (#67); `POST /api/auth/users/{id}/unlock` on the caller's own account | Wrong password or second-factor code at the caller's re-check | "incorrect password or code" |
  | Any route, at `gate.Protect` | A bearer token that matches no registered kind, is revoked or expired, or an `Authorization` header that is not a well-formed `Bearer <token>` | "invalid or revoked token" |

- `detail` differs between routes, but within one route it never
  says which of the security pairs below was the cause.
- **Security pairs sharing this class and body:**
  - an unknown username and a wrong password at `login`;
  - a wrong authenticator code and a wrong recovery code at
    `login/factor`;
  - an unknown admin username and a wrong unlock code at `unlock`;
  - a wrong current setup code and an already-replaced one at
    `register`;
  - at `Protect`, a token of an unknown type, a revoked token, an
    expired token and a malformed `Authorization` header;
  - every refused passkey, at `login/factor`, `login/passkey`,
    `login/prove` and `reauthenticate`: a wrong signature, a clone
    warning (the passkey's use counter went backwards or did not move,
    which suggests a copied key; a counter that stays at 0 is normal
    and accepted), or a passkey removed from the account
    since the sign-in started. A use counter that could not be saved is
    the server's failure, not the caller's, and answers `server-error`.

  None of these is ever split into a more specific class or a more
  specific message.

## sign-in-required

- **Status:** 401. **Title:** Sign-in required.
- No valid session cookie. Carries `WWW-Authenticate: Bearer
  realm="gate"`.
- Returned by `gate.Protect` for any route that needs a session, reached
  with no session, an expired one, or one ended since by a password
  change, a reset, or linking the account to a single sign-on (SSO)
  login. Every handler's own "sign in first" check answers the same
  class when reached directly (normally unreachable once mounted under
  `Protect`, which already refuses the request first).
- `POST /api/auth/reauthenticate` (#71) answers it, with `detail` "sign
  in again", when there is no session it can resume, whatever the
  reason:
  - no cookie, an unknown session, a session that is still live or was
    ended, or one past its maximum lifetime (at most 24 hours);
  - the account was deleted, has no local password, or must change its
    password before doing anything else.

  The frontend then shows the full sign-in form.
- While a session has timed out through inactivity but is still inside
  its maximum lifetime, every other route that needs a session answers
  the plain `sign-in-required`, and `GET /api/auth/session` carries
  `resumable: true`. That is how a frontend learns the password alone
  will do.
- `detail` is "sign in first", "unauthorized" or "sign in again"
  depending on which check answered; a frontend never reads it.

## step-expired

- **Status:** 401. **Title:** Start again.
- A step of a multi-step process is no longer valid: it expired, was
  tampered with, was already completed by another request, or its
  account is gone or has lost the factor it needed. Carries
  `WWW-Authenticate: Bearer realm="gate"`. The cookie the step depended
  on, if it had one, is cleared with the response.
- A passkey *ceremony* is the two-step exchange where the server sends
  a challenge and the browser answers it with the passkey; the server
  keeps its half in a short-lived cookie.
- Returned by:

  | Route | What is no longer valid |
  |---|---|
  | `POST /api/auth/login/factor`, `POST /api/auth/login/factor/begin` | The pending-login cookie: missing, expired, tampered with, already used by another request, or the account was deleted or lost every second factor since the password step |
  | `POST /api/auth/login/factor` (passkey), `POST /api/auth/passkeys/register/finish` | The ceremony cookie: missing, expired, tampered with, already used, or issued for a different step, such as sign-in instead of registration |
  | `POST /api/auth/login/passkey`, and the passkey branch of `POST /api/auth/reauthenticate` (#77) | The passkey sign-in ceremony cookie: missing, expired or already used |
  | `POST /api/auth/totp/confirm` | The scanned authenticator-app secret was set more than ten minutes ago |
  | `POST /api/auth/recovery-codes/confirm` | The first second factor waited more than ten minutes for its recovery codes to be confirmed, and has been deleted (#58) |
  | `POST /api/auth/login/confirm` | The confirm cookie: missing, expired, tampered with, already used, issued for a passkey instead of a code, or the account was deleted since (#55) |
  | `POST /api/auth/login/prove/begin`, `POST /api/auth/login/prove` | The same, issued for a code instead of a passkey; and, at `prove`, an expired or used passkey ceremony (#65) |
  | `POST /api/auth/login/escape` | The escape cookie, for the same reasons (#66) |

- A frontend restarts the flow from its first step -- there is nothing
  left for a retry at this step to complete.

## csrf-required

- **Status:** 403. **Title:** Missing required header.
- `X-Requested-With` is missing, or does not equal the application's
  configured value. This blocks cross-site request forgery (CSRF),
  where another website makes the user's browser send a request that
  carries their cookie.
- Checked on every method except `GET` and `HEAD` -- so `POST`, `PUT`,
  `PATCH` and `DELETE` -- before any session, role or door check, on
  every route including those that need no session (`register`,
  `login`, `unlock`, ...). A *door* is a hold that keeps a session away
  from everything except one required step, such as changing its
  password; see `must-change-password` and `must-enrol-factor` below.
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
  the attempt from this browser or place (#55): the application chose
  to block unusual sign-ins (one from a new browser, a new country, or
  too far from the last one to have travelled), or its own check could
  not run. Retrying from the same browser and place changes nothing;
  the account itself is not locked.
- Returned by `POST /api/auth/login`, `POST /api/auth/login/factor` and
  `POST /api/auth/login/passkey`. The SSO callback redirects with
  `ssoError=refused` instead. An SSO-only account refused there has no
  administrator remedy in this release (the reset code needs a local
  password): the way back is a browser or place the account has signed
  in from before.
- `detail` is always "this sign-in was refused by the account's sign-in
  policy -- use a browser or place this account has signed in from
  before, or ask an administrator to reset the account". It never says
  which signal was raised, or whether a code would have been sent.
- No `X-Auth-Gate` header: that header marks a session stopped at a
  door, and no session exists here.
- If the refused account is an admin and no other admin could reset it
  (for example, the only admin), there is a way back from the server
  itself (#66, ADR-0011):
  - the response also sets the escape cookie `gate_escape_login`; the
    body is the same either way, so a stranger learns nothing;
  - the server's log holds a one-time code, which
    `POST /api/auth/login/escape` takes from the same browser.

  A frontend can offer "have a code from the server log?" on every
  refused screen. For anyone else, or where nothing could announce a
  code, the cookie is absent and the form simply fails with
  `step-expired`.

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
  `POST /api/auth/recovery-codes/confirm`, while the door holds.
- A new first factor does not count until the user confirms they saved
  its recovery codes (#58). Until then the session stays at this door.

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
- No account, token, session or passkey has the id or ref given; the
  caller asked to remove an authenticator app their account does not
  have; or the application does not offer this feature at all
  (`Deps.Passkeys`, `Deps.OIDC` or `Deps.SignIns` is nil, or, for
  signing in or resuming with a passkey alone, `Config.PasskeySignIn`
  is off). `detail` is
  absent for the feature-off cases and named for the rest ("no such
  user", "no such session", "no such token", "no such passkey on this
  account", "this account has no authenticator app", "sign-in history
  is not configured").
- Not the same as `about:blank`: this class is for a *route that exists*
  answering "nothing here has that id"; `about:blank` is for a path or
  method the route table never registered at all.

## conflict

- **Status:** 409. **Title:** Conflicting state.
- The request is refused because of the account's or the deployment's
  current state, not because of anything wrong with the request itself:
  - the account is already in the shape the route would put it in:
    already registered, already linked to SSO, already has an active
    factor, already holds ten passkeys, already has a first factor
    waiting for its recovery codes to be confirmed, or has nothing
    waiting to confirm;
  - the route refuses to act on this account: the caller's own, or one
    that already holds the role asked for;
  - passkeys are not yet set up for this site's address, or the
    account's single sign-on link cannot be used.

  `detail` names which.
- Returned across most routes with a notion of "already done" or "not
  this account". `GET /api/auth/session`'s `passkeys.status` is the
  machine-readable form of "passkeys not set up for this address"; this
  class's `detail` only repeats it for a person to read.

## last-admin

- **Status:** 409. **Title:** Last admin.
- The request would leave the deployment with no admin account (#67):
  deleting the last admin, or demoting them to `user` or `viewer`. Make
  another account an admin first, then retry. Nothing was changed.
  The same class refuses deleting or demoting the last admin that has a
  local password while other admins remain (#79): they would all depend
  on the identity provider (the single sign-on service the deployment
  uses). Give another admin a local password first.
- Returned by `DELETE /api/auth/users/{id}` (the last admin; deleting
  the caller's own account while other admins exist is `conflict`
  instead) and `PUT /api/auth/users/{id}/role`. Before #67 deleting the
  admin answered `conflict`; a frontend that branched on that should
  branch on this class too.
- `detail` is "this is the last admin account -- make another account
  an admin first", or, for a delete, "the last admin account cannot be
  deleted -- make another account an admin first", or, for the last
  admin with a local password, "this is the last admin that can sign in
  without the identity provider -- give another admin a local password
  first".

## role-managed-by-sso

- **Status:** 409. **Title:** Role managed by single sign-on.
- The request would change to `user` or `viewer` the role of an account
  linked to single sign-on, on a deployment that maps identity-provider
  groups to roles (#76, ADR-0013). The provider's groups decide that role
  at every sign-in and would overwrite the change, so nothing was
  changed: change the group at the identity provider instead.
- Returned by `PUT /api/auth/users/{id}/role` only. Granting `admin` to
  such an account, and demoting an admin, are not refused: the group map
  never touches an admin. An account that already holds the role asked
  for is `conflict` instead.
- `detail` is "this account's role comes from its groups at the identity
  provider; change the group there".

## rate-limited

- **Status:** 429. **Title:** Too many attempts.
- One of:
  - too many attempts from this client address, or against this
    account, in the current window;
  - the address is banned for 24 hours after 100 failed sign-ins
    (#70);
  - for a sign-in that would be held for a confirmation code, too many
    codes were already sent to the account in the window (#84).
- `detail` is always "too many attempts, try again later". A banned
  address gets the same answer as one that hit the normal limit, so a
  client cannot tell the difference.
- Returned by:
  - every sign-in step: `POST /api/auth/login`, `login/factor`,
    `login/confirm` (#55), `login/prove` (#65), `login/escape` (#66),
    `login/passkey/begin` and `login/passkey` (#77), and
    `POST /api/auth/reauthenticate`, which resumes a timed-out session
    (#71);
  - `POST /api/auth/register` (setup-code guesses) and
    `POST /api/auth/unlock` (unlock-code guesses);
  - every re-check of the caller's own password or second factor, on
    the routes listed under `invalid-credentials` above, and
    `POST /api/auth/totp/confirm`.

## setup-required

- **Status:** 503. **Title:** Setup required.
- No account exists yet, so nothing is reachable but
  `GET /api/auth/session`, `POST /api/auth/register` and the
  application's own `/api/healthz`, if it serves one. SSO is not
  exempt: the first account is never an SSO one. `detail` is "setup
  required".
- Returned by `gate.Protect` itself, before any route-specific handler
  runs.

## not-persisted

- **Status:** 503. **Title:** No persistent storage.
- The deployment has no persistent storage backend configured, so the
  change -- a new account, a token, a reset or a role change -- would
  not survive a restart.
- Returned by `POST /api/auth/register`, `POST /api/auth/users`,
  `POST /api/auth/users/{id}/reset-password`,
  `PUT /api/auth/users/{id}/role` and `POST /api/tokens`. `detail`
  names what an administrator needs to do about it.

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
  everything it meant to. One route:
  - `DELETE /api/auth/users/{id}`: the account was deleted, but the API
    tokens it created could not be revoked. Extra field **`username`**
    (the deleted account's).
- `detail` says what a person should do next (revoke the tokens by
  hand); there is no automatic retry for the half-finished state.
- Older versions also returned it from `POST /api/auth/totp/confirm`
  (with the extra field **`totpActive`**, always `true`) and `POST
  /api/auth/passkeys/register/finish`, when the new factor was switched
  on but its recovery codes failed to save. Since #58 the factor and
  its codes are saved together and stay inactive until confirmed, so
  this cannot happen; a failed save there is `server-error`.
