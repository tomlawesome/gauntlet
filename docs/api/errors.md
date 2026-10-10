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
  class below. A frontend should decide what to do by checking `type`
  -- never `detail`'s text, which may be reworded at any time, and
  never the status code alone, since more than one class shares a
  status.
- **`title`** and **`status`** are fixed per class; `title` is never
  more useful than `type` and exists only because RFC 9457 requires it.
- **`detail`** is free text giving the route's own reason. It is absent
  when a class has nothing more specific to say than its `title` (the
  two `about:blank` cases below, and a few plain 404s).
- Two classes add an extra field beyond those four:
  `partially-completed` adds `username`, and `invalid-credentials` adds
  `unknownCredential` on two routes (#92). Each class's own section says
  more. No other class has any, and none is planned.

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

**Security: identical outcomes, identical bodies.** A few pairs of
genuinely different causes -- an unknown username versus a wrong
password, say -- answer with exactly the same class *and* the same
`detail` text, on purpose: telling them apart would let an attacker
find out which part of a guess was wrong, such as whether a username
exists. Each pair is named under the class it shares, below.

**Words used on this page.** Each has this meaning everywhere below.
Short route names such as `login/factor` are under `/api/auth/`.

- **Route that needs a session:** every route except the few that must
  work without one: `GET /api/auth/session`, `register`, `login`,
  `logout`, the other sign-in steps (`login/factor`,
  `login/factor/begin`, `login/passkey/begin`, `login/passkey`,
  `login/confirm`, `login/prove/begin`, `login/prove`, `login/escape`),
  `unlock`, `reauthenticate`, the single sign-on redirects
  `GET /api/auth/oidc/login` and `GET /api/auth/oidc/callback`, the
  application's own `/api/healthz`, and any path the application adds
  with `Gate.Exempt`.
- **Door:** a hold `gate.Protect` puts on a signed-in session until the
  account does one thing: set a new password, add a second factor, or,
  for an admin, register a passkey. While a door holds, every route
  that needs a session answers 403, except the few that do that one
  thing. There are three: `must-change-password`, `must-enrol-passkey`
  and `must-enrol-factor`. Each one's 403 carries an `X-Auth-Gate`
  header naming it.
- **Second factor:** something beside the password that proves the
  person: a TOTP code or a passkey, with recovery codes as the backup.
- **TOTP:** the six-digit codes an authenticator app shows.
- **Re-check:** a signed-in person proving again who they are, on the
  request itself, before a risky action. On most routes it is the
  password alone. A **step-up** is the stricter re-check: the password
  plus a second factor (a TOTP code, a recovery code or a passkey).
- **Passkey ceremony:** the two-step exchange where the server sends a
  challenge and the browser answers it with the passkey; the server
  keeps its half in a short-lived cookie.
- **User handle:** the account ID a passkey carries, a random 128-bit
  value that only the passkey's holder has.
- **Bearer token:** an API token, sent as `Authorization: Bearer
  <token>`.
- **Window:** the time period the login limiter counts attempts in. The
  application sets it, with the number of attempts allowed, when it
  creates the limiter (`gauntlet.NewLoginLimiter(threshold, window)`).
- **Single sign-on (SSO):** signing in through an outside identity
  provider instead of with a local password.

## invalid-credentials

- **Status:** 401. **Title:** Invalid credentials.
- A credential sent with the request -- a password, a one-time code, a
  bearer token or a passkey -- was wrong, or has already been used.
  Carries `WWW-Authenticate: Bearer realm="gate"` (RFC 6750 §3), as
  every 401 here does.
- Returned by:

  | Route | Cause | `detail` |
  |---|---|---|
  | `POST /api/auth/register` | Wrong or missing setup code | "invalid setup code -- the current one is in the server's log" |
  | `POST /api/auth/login` | Wrong username or password | "invalid username or password" |
  | `POST /api/auth/login/factor` | Wrong TOTP code or recovery code | "invalid code" |
  | `POST /api/auth/login/factor` | Passkey refused | "that passkey couldn't be verified -- use another way in" |
  | `POST /api/auth/login/passkey` | Passkey refused, signing in with a passkey alone (#77) | the same passkey text |
  | `POST /api/auth/reauthenticate` | Wrong password, or passkey refused, for the timed-out session's account (#71, #77) | "incorrect password", or the passkey text |
  | `POST /api/auth/login/confirm` | Wrong confirmation code (#55) | "invalid confirmation code" |
  | `POST /api/auth/login/prove` | Passkey refused (#65) | the passkey text |
  | `POST /api/auth/login/escape` | Wrong escape code (#66) | "invalid escape code" |
  | `POST /api/auth/unlock` | Wrong admin username or unlock code | "invalid username or unlock code -- the current code, if any, is in the server's log" |
  | `POST /api/auth/password` | Wrong current password | "current password is incorrect" |
  | `POST /api/auth/totp/enrol`, `DELETE /api/auth/totp`, `POST /api/auth/recovery-codes`, `POST /api/auth/passkeys/register/begin`, `DELETE /api/auth/passkeys/{id}`, `POST /api/auth/oidc/link`, `POST /api/auth/logout-all` (an account with a local password) | Wrong password at the re-check | "incorrect password" |
  | `POST /api/auth/users/{id}/reset-password`, `POST /api/tokens`, `DELETE /api/auth/users/{id}`, `DELETE /api/auth/users/{id}/totp`, `DELETE /api/auth/users/{id}/passkeys`, and `POST /api/auth/users/{id}/allow-sign-in` on another account (#81) | Wrong password at the re-check of the calling admin's own password (#72) | "incorrect password" |
  | `POST /api/auth/users` and `PUT /api/auth/users/{id}/role` when they grant the admin role (#67); `POST /api/auth/users/{id}/unlock` and `POST /api/auth/users/{id}/allow-sign-in` (#81) on the caller's own account | Wrong password, second-factor code or passkey (#82) at the step-up | "incorrect password or code" |
  | Any route, at `gate.Protect` | A bearer token that matches no token type the application registered with `Gate.Handle`, or that was revoked or has expired; or an `Authorization` header that is not the word `Bearer` (in any capitalisation), one space and the token | "invalid or revoked token" |

- `detail` differs between routes, but within one route it never
  says which of the security pairs below was the cause.
- **`unknownCredential`** (#92) is one more field on some refused
  passkeys. It lets the browser forget a passkey that can never work
  here:
  - At `login/passkey`, the browser sends the passkey with its user
    handle. If the handle names an account here, and that account has
    no passkey with this ID in any state (active, registered under an
    earlier web address, or waiting for its recovery codes to be
    confirmed), the error carries the field.
  - Pass the field's value to the browser's
    `PublicKeyCredential.signalUnknownCredential()` (W3C WebAuthn
    Level 3 section 5.1.10.2), so the browser stops offering a passkey
    that can never work here:

    ```json
    "unknownCredential": { "rpId": "home.example", "credentialId": "vI0qOggiE3OT01ZRWBYz5l4MEgU0c7PmAA" }
    ```

    `rpId` is the site's hostname (the relying party ID, or RP ID),
    exactly as `login/passkey/begin` returned it; `credentialId` is the
    passkey's credential ID, base64url with no padding.
  - At `reauthenticate`, a refused `{assertion}` carries the field under
    a narrower rule: only when the user handle is the timed-out
    session's own account and that account has no passkey of that ID in
    any state. Another account's handle, or one naming no account, never
    gets it there.
  - A handle naming no account here never gets it at `login/passkey`
    either. Another application on the same hostname shares the
    browser's passkeys (an RP ID is a hostname, with no port or path),
    and naming one of its passkeys would make the browser hide or delete
    a passkey that still works there.
  - The field tells the caller only that the handle belongs to an
    account here. That is safe because only the passkey's holder has
    the handle.
  - Every other refusal, on these routes or any other, has no such
    field. `detail`, `title` and the status are the same with or
    without it.
- **Security pairs sharing this class and body:**
  - an unknown username and a wrong password at `login`;
  - a wrong TOTP code and a wrong recovery code at `login/factor`;
  - an unknown admin username and a wrong unlock code at `unlock`;
  - a wrong current setup code and an already-replaced one at
    `register`;
  - at `Protect`, a token of an unknown type, a revoked token, an
    expired token and a malformed `Authorization` header;
  - every refused passkey, at `login/factor`, `login/passkey`,
    `login/prove`, `reauthenticate` and the step-up (#82): a wrong
    signature, a clone warning (the passkey's use counter went
    backwards or did not move, which suggests a copied key; a counter
    that stays at 0 is normal and accepted), or a passkey removed from
    the account since the sign-in started. A use counter that could not
    be saved is the server's failure, not the caller's, and answers
    `server-error`. The one difference is at `login/passkey` and
    `reauthenticate`: if the account (at `reauthenticate`, the session's
    own; at `login/passkey`, an account here named by the user handle)
    does not hold that passkey, the error carries `unknownCredential`;
    if it does hold it, no (#92). Only the passkey's holder has the user
    handle and credential ID needed to see this, and all it learns is
    that the passkey was removed.

  None of these is ever split into a more specific class or a more
  specific message.

  One difference remains, and it is not a pair: at `login/passkey`, an
  unknown user handle and a real account without that passkey get the
  same class and message, but only the second carries
  `unknownCredential` (#92). The first is left unnamed because it may
  belong to another application on the same hostname, whose passkey
  must not be hidden.

## sign-in-required

- **Status:** 401. **Title:** Sign-in required.
- No valid session cookie. Carries `WWW-Authenticate: Bearer
  realm="gate"`.
- Returned by `gate.Protect` for any route that needs a session, reached
  with no session, an expired one, or one ended since by a password
  change, a reset, or linking the account to SSO. Each handler also
  checks for a session itself and gives the same class. You only see
  that if you use a handler without `gate.Protect` in front of it.
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
- Returned by:

  | Route | What is no longer valid |
  |---|---|
  | `POST /api/auth/login/factor`, `POST /api/auth/login/factor/begin` | The pending-login cookie: missing, expired, tampered with, already used by another request, or the account was deleted or lost every second factor since the password step |
  | `POST /api/auth/login/factor` (passkey), `POST /api/auth/passkeys/register/finish` | The passkey ceremony cookie: missing, expired, tampered with, already used, or issued for a different step, such as sign-in instead of registration |
  | `POST /api/auth/login/passkey`, and the passkey branch of `POST /api/auth/reauthenticate` (#77) | The passkey sign-in ceremony cookie: missing, expired or already used |
  | `POST /api/auth/totp/confirm` | The scanned authenticator-app secret was set more than ten minutes ago |
  | `POST /api/auth/recovery-codes/confirm` | The first second factor waited more than ten minutes for its recovery codes to be confirmed, and has been deleted (#58) |
  | `POST /api/auth/login/confirm` | The confirm cookie: missing, expired, tampered with, already used, issued for a passkey instead of a code, or the account was deleted since (#55) |
  | `POST /api/auth/login/prove/begin`, `POST /api/auth/login/prove` | The confirm cookie, for the same reasons, except that here the wrong kind is one issued for a code instead of a passkey; and, at `login/prove`, a passkey ceremony that has expired or already been used (#65) |
  | `POST /api/auth/login/escape` | The escape cookie, for the same reasons (#66) |
  | The step-up routes, with a passkey in place of a code (#82): `POST /api/auth/users` and `PUT /api/auth/users/{id}/role` when they grant the admin role; `POST /api/auth/users/{id}/unlock` and `POST /api/auth/users/{id}/allow-sign-in` (#81) on the caller's own account | The step-up ceremony cookie `POST /api/auth/step-up/passkey/begin` set: missing, expired, tampered with or already used. A sign-in's ceremony cookie is never read here |

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
  `login`, `unlock`, ...).
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
  `ssoError=refused` instead. An administrator lets an account in from
  the new browser or place with
  `POST /api/auth/users/{id}/allow-sign-in` (#81), which an SSO-only
  account refused at the callback can use too.
- `detail` is always "this sign-in was refused by the account's sign-in
  policy -- use a browser or place this account has signed in from
  before, or ask an administrator to allow your next sign-in or reset
  the account". It never says which signal was raised, or whether a
  code would have been sent.
- No `X-Auth-Gate` header: that header marks a session stopped at a
  door, and no session exists here.
- If the refused account is an admin and no other admin could reset it
  (for example, the only admin), there is a way back from the server
  itself (#66, ADR-0011):
  - the response also sets the escape cookie `gate_escape_login`; the
    body is the same either way, so a stranger learns nothing;
  - a one-time code goes to the server's log (or to the application's
    `Config.OnEscapeCode` handler, if it set one), and
    `POST /api/auth/login/escape` takes it from the same browser.

  A frontend can offer "have a code from the server log?" on every
  refused screen. For anyone else, or when the server had nowhere to
  send a code (neither `Config.OnEscapeCode` nor `Config.Log` is set),
  the cookie is not set and the form simply fails with `step-expired`.

## must-change-password

- **Status:** 403. **Title:** Password change required.
- The session is stopped at the forced-password-change door: an
  administrator reset the account, five second-factor steps in a row
  failed, or a sign-in found the password breached.
- When the application requires every admin to hold a passkey (#82),
  an admin with no local password -- one that signs in only through
  SSO and was made an admin -- is held here too, with `detail` "this
  admin account has no local password -- set one before going any
  further". A passkey can only be registered on an account with a
  password, so this admin must set one first. They do it straight after
  signing in through SSO again.
- Carries `X-Auth-Gate: must-change-password`. A frontend matches this
  header, never the `detail` text, to send the person straight to the
  one route that gets them out: `POST /api/auth/password`.
- Returned by `gate.Protect` for every route that needs a session,
  except `POST /api/auth/password`, while the door holds.

## must-enrol-factor

- **Status:** 403. **Title:** Second factor enrolment required.
- The session's account has a local password and no second factor yet
  -- mandatory for every such account (#49). Carries `X-Auth-Gate:
  must-enrol-factor`; a frontend matches this header, never `detail`, to
  send the person to set up TOTP or to register a passkey.
- Returned by `gate.Protect` for every route that needs a session,
  except the TOTP enrol and confirm routes, the passkey register begin
  and finish routes and `POST /api/auth/recovery-codes/confirm`, while
  the door holds.
- A new first factor does not count until the user confirms they saved
  its recovery codes (#58). Until then the session stays at this door.
- An admin held for a passkey sees `must-enrol-passkey` instead, even
  with no factor at all (below).

## must-enrol-passkey

- **Status:** 403. **Title:** Passkey registration required.
- The application requires every admin to hold a passkey
  (`gate.Config.AdminPasskey` set to `gate.AdminPasskeyRequired`, #82),
  and this admin has no passkey that works for the site's current web
  address (passkeys are tied to the address they were made for). TOTP
  does not count, and nor does a passkey registered under an earlier
  address. Carries `X-Auth-Gate: must-enrol-passkey`; a frontend
  matches this header, never `detail`, to send the person to passkey
  registration.
- Returned by `gate.Protect` for every route that needs a session,
  except the same ones `must-enrol-factor` admits (passkey register
  begin and finish, TOTP enrol and confirm,
  `POST /api/auth/recovery-codes/confirm`), while the door holds. It
  opens at the next request after a passkey is registered and, for a
  first factor, its recovery codes confirmed.
- Checked after `must-change-password` and before `must-enrol-factor`:
  an admin with no factor at all is told the one thing that opens this
  door. Users and viewers never see it.
- An account made an admin, created as one, or set up as the first
  account is held here from its next request; so is an admin whose
  passkeys another admin cleared. `GET /api/auth/session`'s
  `mustEnrolPasskey` says when it holds.

## invalid-request

- **Status:** 400. **Title:** Invalid request.
- The request body is not one JSON object of the documented fields
  (an unknown field or trailing data is refused, not ignored), a path
  parameter that must be present is empty, or a field's value fails a
  rule gauntlet enforces (password length or breach status, username
  shape, role name, a token's name, kind or device). `detail` names the
  rule, except in a few places where `detail` is just "invalid request
  body" because the request was not valid JSON of the right form.
- `POST /api/auth/login/factor` also answers it when the body holds both
  `code` and `assertion`, or neither (#99). A `null` assertion counts as
  none. Nothing is counted, and the pending login still holds.
- Returned across nearly every route that takes a body or a path
  parameter; see the OpenAPI document for which status a given field
  rule answers with on which route.

## not-found

- **Status:** 404. **Title:** Not found.
- One of:
  - no account, token, session or passkey has the id given (for a
    session, the `ref`);
  - the caller asked to remove an authenticator app their account does
    not have;
  - an admin clearing another account's authenticator app or passkeys
    (`DELETE /api/auth/users/{id}/totp` or `.../passkeys`) found that
    the account was deleted while the request was in flight (#99);
  - the application does not offer this feature at all
    (`Deps.Passkeys`, `Deps.OIDC` or `Deps.SignIns` is nil, or, for
    signing in or resuming with a passkey alone,
    `Config.PasskeySignIn` is off).
- `detail` is absent when the feature is switched off, and gives the
  reason for the others ("no such user", "no such session", "no such
  token", "no such passkey on this account", "this account has no
  authenticator app", "this account was deleted before the request
  finished", "sign-in history is not configured").
- Not the same as `about:blank`: this class is for a *route that exists*
  answering "nothing here has that id"; `about:blank` is for a path or
  method the route table never registered at all.

## conflict

- **Status:** 409. **Title:** Conflicting state.
- The request is refused because of the account's or the deployment's
  current state, not because of anything wrong with the request itself:
  - the account is already in the state the request would create:
    already registered, already linked to SSO, already has an active
    factor, already holds ten passkeys, already has a first factor
    waiting for its recovery codes to be confirmed, or has nothing
    waiting to confirm;
  - the route refuses to act on this account: the caller's own, or one
    that already holds the role asked for;
  - the caller has no local password, so there is no password to
    re-check, at `DELETE /api/auth/totp`,
    `DELETE /api/auth/passkeys/{id}` and
    `POST /api/auth/recovery-codes` (#99). The refusal comes before
    any password is checked, and nothing is counted;
  - an admin removing their own last passkey that works at this
    address, while the application requires admin passkeys (#82):
    "register another passkey first";
  - passkeys are not yet set up for this site's address, or the
    account's SSO link cannot be used.

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
- It also refuses to delete or demote the last admin who has a local
  password, even if other admins exist (#79). Without that admin, every
  remaining admin would depend on the identity provider to get in. Give
  another admin a local password first.
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
  linked to SSO, on a deployment set up to take each person's role from
  their group at the identity provider (#76, ADR-0013). The provider's
  groups decide that role at every sign-in and would overwrite the
  change, so nothing was changed: change the group at the identity
  provider instead.
- Returned by `PUT /api/auth/users/{id}/role` only. Granting `admin` to
  such an account, and demoting an admin, are not refused: the group map
  never touches an admin. An account that already holds the role asked
  for is `conflict` instead.
- `detail` is "this account's role comes from its groups at the identity
  provider; change the group there".

## rate-limited

- **Status:** 429. **Title:** Too many attempts.
- One of:
  - too many attempts from this address, or against this account,
    within the window;
  - the address is banned for 24 hours after 100 failed sign-ins
    (#70);
  - for a sign-in that would be held for a confirmation code, too many
    codes were already sent to the account in the window (#84). A
    resend inside the cooldown (30 seconds after the first code, twice
    as long after each further one in the hour), or past 5 an hour, is
    `429` with nothing sent (#83);
  - at `login/factor/begin` and `login/prove/begin`, the account is
    locked out after repeated failures (unless the browser is one the
    account remembers) or disabled (always). The server refuses
    early, so nobody is asked to touch a passkey for a sign-in that
    could not complete.
- `detail` is always "too many attempts, try again later". A banned
  address gets the same answer as one that hit the normal limit, so a
  client cannot tell the difference.
- Returned by:
  - every sign-in step: `POST /api/auth/login`, `login/factor`,
    `login/factor/begin` (#85), `login/confirm` (#55),
    `login/prove/begin` (#80), `login/prove` (#65), `login/escape`
    (#66), `login/passkey/begin` and `login/passkey` (#77), and
    `POST /api/auth/reauthenticate`, which resumes a timed-out session
    (#71);
  - `POST /api/auth/register` (setup-code guesses) and
    `POST /api/auth/unlock` (unlock-code guesses);
  - every re-check and step-up, on the routes listed under
    `invalid-credentials` above, and `POST /api/auth/totp/confirm`;
  - `POST /api/auth/step-up/passkey/begin` (#82), once the account has
    used up its allowed number of passkey step-ups in the window. These
    are counted separately, and the count is not given back when a
    step-up succeeds.

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
  change -- a new account, a token, a reset, a role change or an
  allowed sign-in -- would not survive a restart.
- Returned by `POST /api/auth/register`, `POST /api/auth/users`,
  `POST /api/auth/users/{id}/reset-password`,
  `PUT /api/auth/users/{id}/role`,
  `POST /api/auth/users/{id}/allow-sign-in` (#81) and
  `POST /api/tokens`. `detail` names what an administrator needs to do
  about it.

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
