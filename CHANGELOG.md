# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

- **An admin can allow an account's next sign-in for ten minutes**
  (#81, ADR-0009 decision 11). `POST /api/auth/users/{id}/allow-sign-in`
  lets a person the unusual-sign-in policy holds or refuses at a new
  browser or place sign in once, normally, and have that browser and
  place remembered -- without a reset code destroying their password,
  and as the first administrator remedy at all for an account that
  signs in only through single sign-on. For another account it takes
  the caller's password, for the caller's own the password and a
  current second factor, as own unlock does. It changes no password,
  second factor, session, lockout or disable. The first completed
  sign-in from any browser spends it; a reset code or sign out
  everywhere clears it. Audited as `user.sign_in_allowed`; the account
  holder is told through the new `NoticeSignInAllowed`
  (`AccountNotice.SignInAllowed`, `SignInAllowedDetail{Until}`). New
  `Store.AllowNextSignIn`, `User.SignInAllowedUntil`,
  `User.SignInAllowed` and `SignInAllowanceLifetime`. Additive.

### Security

- **Confirmation codes and escape codes wait between sends, and five an
  hour at most** (#83). The per-window send limit (#84) let someone
  holding the password ask for a code every minute, window after window.
  Each account and kind of code now also has a resend cooldown, 30
  seconds after the first code and doubling with each further one in
  the last hour (at most 15 minutes), and a cap of five codes in any
  hour, both fixed. Inside the cooldown or past the cap a held sign-in
  is answered `429 rate-limited` with no code, as at the window's limit;
  a refused request is not counted. An admin's unlock
  (`LoginLimiter.UnlockLogin`) or a restart clears both. No API change.

- **Starting a passkey second step spends no sign-in attempts** (#85).
  `login/factor/begin` used to take an attempt on the address's and
  the account's sign-in limits and `login/factor` handed it back in a
  later request, so an abandoned prompt could start a lockout, and a
  completed step whose begin had aged out of the window handed back a
  real wrong guess from that address. Each begin is now counted on a
  limit of the account's own, the limiter's threshold per window (5
  per 5 minutes at the usual settings), never handed back; past it,
  begin is `429 rate-limited`, recorded as `rate_limited`, while codes
  and recovery codes still work. `login/factor` hands back only the
  attempt it took itself. The limit is not the per-address one the login
  page's passkey sign-in spends, so that one filling does not refuse an
  account's second step, and a browser the account remembers has a
  limit of its own beside it, so a stranger holding the password cannot
  keep the owner from their passkey. A banned address is still refused
  at begin unless the browser is known, and so is a locked account
  (recorded as `locked`) or a disabled one (to any browser): begin reads
  the lockout without reserving anything, so no prompt is shown for a
  sign-in that cannot complete. An admin's unlock
  (`LoginLimiter.UnlockLogin`) or a restart clears the count. New
  `LoginLimiter.ReserveFactorBegin` and `ReleaseFactorBegin`. Additive.

- **Only public keys are compiled into an application** (#87). The
  blocklist package embedded the whole `blocklist/keys` folder, so any
  other file left there, such as a private key, would have been built
  into every app. It now embeds `keys/*.pub` only, and the folder has a
  `.gitignore` that lets Git track just `*.pub`, `README.md` and itself.

- **A password reset no longer lets the account past its address's
  limit** (#86, retiring #32's pass). The pass was the last thing on the
  sign-in limits that carried across requests: the pending-login cookie
  let the code step skip the address limit. A reset still ends the
  account's lockout and stops its earlier wrong guesses counting (#24),
  and a browser the account remembers still signs in past a full
  address on its own allowance (#44). What changes: someone reset within
  five minutes of the wrong guesses, signing in from the same address on
  a browser the account does not remember, gets `429 rate-limited` ("too
  many attempts, try again later") until five minutes have passed since
  those guesses, then signs in as normal. A pending-login cookie issued
  before the upgrade that still carries the old flag is accepted, and
  the flag is ignored. `LoginLimiter.AllowAfterReset` now always reports
  false, and `ReleaseAfterReset` and `EndAfterReset` do nothing; all
  three are deprecated and kept until a major version (ADR-0002).

### Changed

- **The accounts document is version 10** (#81), for
  `User.SignInAllowedUntil`. **One-way:** a v0.3.0 build refuses a
  version-10 document at start-up (ADR-0002), so rolling back means
  restoring a copy saved before the upgrade. A version-9 document opens
  as before, with no allowance. No migration code.

- **A sign-in let through by an admin's allowance** (#81) completes as
  an escape-code one does: history row `confirmed`, `user.login` note
  `allowed=used`, and the unusual-sign-in notice's `Reason` is
  `allowed`. `Store.RememberSignIn` now also spends the allowance in its
  one write.

- **The `sign-in-refused` detail** now reads "... or ask an
  administrator to allow your next sign-in or reset the account" (#81).

- CI: a release is cut on `main` only (#88): release:version and
  release:gitlab run in `main` pipelines and refuse a commit that is not
  `main`'s tip; `preview` and `main` pipelines now run every lint and
  test job, as `dev`'s do (docs/releasing.md).

### Fixed

Low-severity findings from the v0.3.0 audit (#80):

- An SSO sign-in that changes the account's role no longer computes a
  password hash (about 100 ms, 64 MiB) it throws away while every other
  request waits on the account store.
- A sign-in with the old password that was already being checked when
  a password change or an admin reset landed is refused, rather than
  given a session the change was meant to end.
- Holding a first second factor (`HoldFirstPasskey`, `HoldFirstTOTP`)
  refuses an account that already has one, or has one on hold, before
  minting the ten recovery codes, rather than hashing all ten and
  throwing them away.
- An admin reset issued while the owner's own password change was still
  being checked is no longer overwritten by it (the code the admin read
  out never worked). The change is refused instead: `POST
  /api/auth/password` answers `409 conflict` and saves nothing, and
  `Store.SetPassword` returns the new `ErrResetDuringChange`. Additive.
- `Store.ClearAllSecondFactors` on an account with nothing to clear
  returns the new `ErrNoSecondFactors` and writes nothing, as
  `ClearPasskeys` answers `ErrNoPasskeys`, instead of saving and
  reporting success. A recovery tool built on it can now say there was
  nothing to remove rather than that everything was.
- A failed SSO callback's warning now ends with `cause="..."`: what the
  token endpoint answered (its status, error code and description, never
  its raw body), why the token did not verify, what the provider
  reported, or why the account could not be saved. A provider that is
  down, a wrong client secret and a failing disk no longer read the
  same.
- `pwlist build` with `--checkpoint`, when the finished run fails a
  sanity bar, now says its checkpoint is kept and that a retry rechecks
  the same result without fetching (delete the checkpoint to fetch
  again), and the retry logs that every chunk was already fetched
  instead of "resuming at chunk" one past the last.
- `SweepTokens` reads the account store once to find tokens whose
  creator is gone, instead of once per token while holding the token
  store's lock, so a slow accounts backend no longer holds every
  bearer-token request for the length of the sweep.
- A token-expiry notice whose notifier answers after the 10-second
  deadline, but answers that it sent it, is recorded as sent when it
  answers. Before, the sweep counted it unsent and a notifier that was
  always slow sent the owner the same notice every day.
- The password list's stored copy (`blocklist.Refresher`) and the
  country file and its `state.json` (`geoip`) keep their owner and group
  when a refresh replaces them, as the account store's file has since
  #79: a refresh run as another user, such as a CLI with sudo, no
  longer leaves files the server cannot read or replace. All three now
  share one writer.
- The Unicode line and paragraph separators (U+2028, U+2029), which a
  few mail and chat clients show as a new line, are now treated like
  control characters wherever those are: dropped from a session's and a
  sign-in record's browser and address and from a masked unknown
  username, and refused in a new username, token name, token device ID
  and an admin's sign-out-everywhere reason. An owner's notice can no
  longer show a made-up extra line.
- `login/prove/begin` counts each begin on the account's passkey-step
  begin budget, as `login/factor/begin` does since #85, so a held
  sign-in's ticket can no longer mint passkey challenges without limit
  for its life; past it, begin is `429 rate-limited`. Like
  `login/factor/begin` it also refuses a locked or disabled account and
  a banned address (`429`, with the same known-browser exceptions)
  before any challenge, so an owner locked out between the password and
  the passkey step is told at once instead of after touching their key.

## [0.3.0] - 2026-10-08

Reading notes for this release:

- "ADR-NNNN" points to an architecture decision record in
  [docs/adr/](docs/adr/), which gives the reasoning; "decision N" is a
  numbered decision inside it.
- A *document* is one stored file (accounts, tokens, sign-in history).
  At this release the accounts document is version 9, the tokens
  document version 3 and the sign-in history version 3. Entries below
  name the version each step reached on the way. **This is one-way:**
  once this release has saved a file, an older gauntlet build refuses
  to open it, so rolling back means restoring a copy of the file saved
  before the upgrade. Older files open in this release as before.

### Added

- **Every admin account must hold a passkey, where the application says
  so** (#82, ADR-0015). An admin account now holds at least one passkey;
  an authenticator app may be held as well, never instead. The
  application chooses with the new, required `gate.Config.AdminPasskey`
  (see Changed below for what that means when upgrading):
  `gate.AdminPasskeyRequired` turns the rule on,
  `gate.AdminPasskeyOptional` waives it for an application reached over
  plain http (anywhere but localhost) or by IP address, or one with no
  passkeys. With it on:
  - An admin with no passkey that works at this address is stopped at a
    new door, `403` class `must-enrol-passkey` with `X-Auth-Gate:
    must-enrol-passkey`, until they register one. It lets through the
    same routes as the second-factor door, and is checked before it.
    An admin with no local password (made an admin from single sign-on)
    is stopped at the `must-change-password` door first, since a passkey
    needs a password; they set one from a fresh single sign-on.
  - `GET /api/auth/session` gains `mustEnrolPasskey` (the door holds)
    and `adminPasskeyRequired` (the rule is on; present while signed
    in), so a frontend can show the requirement before the door holds.
  - Making an account an admin, creating one, handing admin over and
    the first account all succeed, and the new admin is held at the
    door from its next request. The role and create responses and each
    row of `GET /api/auth/users` say so in `heldForPasskey`, and the
    audit detail adds "held for a passkey".
  - An admin cannot delete their own last passkey that works here:
    `409` `conflict`, "register another passkey first", before the
    password is checked. Another admin clearing their passkeys still
    works, as the way back for a lost key; they are held afterwards.
  - Users and viewers keep "any second factor". Nothing is stored: the
    accounts document stays at version 9.
- **A passkey can stand in for the code at an admin step-up** (#82).
  Granting admin, creating an admin and an admin's own unlock take the
  caller's password and either a code or, now, a passkey: `POST
  /api/auth/step-up/passkey/begin` (signed in, no body) answers the
  options for the caller's own passkeys and sets a new five-minute
  ceremony cookie, `gate_passkey_stepup`; the route then takes
  `assertion` (`adminAssertion` on create) in place of `code`
  (`adminCode`). Exactly one of the two, or `400`. Begin is counted on
  a per-account limit of its own, never handed back (`429` past it),
  and takes nothing from the password re-check budget, so an abandoned
  prompt costs no re-check; the passkey itself is checked on that
  budget like a code. A wrong passkey is `401` `invalid-credentials`
  and counts, and a missing or used ceremony is `401` `step-expired`
  and does not. A
  passkey-only admin no longer spends a recovery code on every grant.
  New `LoginLimiter.ReserveStepUpBegin` and `ReleaseStepUpBegin` hold
  that limit in the account map, which no flood of addresses can
  reset. Additive.
- New Go API for #82, additive: the type `gate.AdminPasskeyRule`, its
  constants `gate.AdminPasskeyRequired` and `gate.AdminPasskeyOptional`,
  and the field `gate.Config.AdminPasskey`.
- **Prove an unusual sign-in with a passkey** (#65, ADR-0009 decision 10).
  When a sign-in looks unusual, the person can now be asked to tap a
  passkey instead of typing a code sent to them. An account with no
  passkey that works at this address is held for a code if
  `Config.DeliverConfirmCode` is set, and refused if not. For
  developers: a fifth `UnusualSignInAction`, `prove`
  (`gate.UnusualSignInProve`),
  ranked between `confirm` and `block`, settable per signal in
  `Config.UnusualSignIns` and returnable from `Decide`: the sign-in is held
  until the browser answers a passkey assertion for the same account.
  The 200 is `{"prove": "passkey", "passkeyOrigin": ...}` where `confirm`'s
  is `{"confirm": true}` (the SSO callback redirects with `?prove=1`), and
  the new `POST /api/auth/login/prove/begin` and `POST
  /api/auth/login/prove {assertion}` finish it, through the existing
  non-discoverable ceremony (user verification preferred, not required),
  the login limiter as `login/confirm` does, and the held sign-in's
  confirm ticket, which now has two kinds that are not interchangeable.
  A sign-in that was itself by passkey is already proved and is flagged; an
  account with no passkey usable at this address is held for a code when
  `Config.DeliverConfirmCode` is set, else refused. `UnusualSignInCase`
  gains `CanProve`; a ticket that cannot be made is a block with the new
  reason `prove-failed`. `gate.New` accepts `prove` with nothing else
  wired. Additive; the accounts document is unchanged.

- **Sign in with a passkey alone** (#77, ADR-0012). A passkey can now
  be the whole sign-in: the person taps it and confirms with a PIN or
  fingerprint at the device, and types no username or password. It is
  off by default.

  To turn it on, set `gate.Config.PasskeySignIn` and wire a relying
  party (the passkey checker) that implements the new optional
  `gauntlet.PasskeySignIn`; `passkey.RelyingParty` does. Otherwise both
  new routes answer 404 and `POST /api/auth/login` and `login/factor`
  are exactly as before.

  The new routes are `POST /api/auth/login/passkey/begin` and `POST
  /api/auth/login/passkey`. In WebAuthn terms (the browser standard for
  passkeys) this is a Level 3 discoverable-credential login: the
  passkey itself names the account (its *user handle*), and the device
  must verify the person (*user verification*, a PIN or biometric). That
  makes it a multi-factor sign-in on its own (NIST SP 800-63B-4, AAL2).
  Every account keeps its password; the accounts document stays
  version 9.

  How it fits with the other checks: the sign-in is judged for unusual
  signals like any other (method `passkey_alone` reaches `Decide`; a
  confirmation code is not skipped). Before the signature is checked it
  counts toward the account's lockout and disable, the address limit
  and ban, and the known-browser allowance. After it, an account that
  owes a password change is still limited to changing it. A refused
  assertion keeps its attempt, and a completed sign-in gives both
  back. It does not count toward the run of
  second-factor failures that forces a new password. An account with no
  local password cannot sign in this way. The same passkey resumes a
  timed-out session: `POST /api/auth/reauthenticate` takes `{"assertion":
  ...}` from the same begin route instead of `{"password": ...}`, the user
  handle must be the session's own account. `GET /api/auth/session`
  gains `passkeys.signIn: true` when the routes are on and ready, and now
  sends a `passkeys` block signed out in that case so a login page can
  offer the button. Sessions, the session list (`method`), the sign-in
  history and the audit record carry the method `passkey_alone`. Additive
  Go API: `gauntlet.PasskeySignIn`, `PasskeyAssertion.UserVerified`,
  `SignInMethodPasskeyAlone`, `SessionClient.Method`, `Config.PasskeySignIn`
  and `passkey.RelyingParty`'s `BeginSignIn` and `FinishSignIn`.
- **Roles for SSO accounts from identity-provider groups** (#76,
  ADR-0013). `oidc.Policy.RoleFromGroups` maps a group to `user` or
  `viewer`; `RoleWithoutGroup` (default `viewer`, or `user`) covers an
  account in no mapped group, an absent groups claim included. The role
  is set when the account is first created and again at every single
  sign-on login, in the same write that finds or creates the account.
  The highest role among the mapped groups wins. A downgrade ends the
  account's other sessions. Admin
  is never given by a group (`gate.New` refuses it, and an unknown role,
  at start-up) and an account already an admin is never changed by the
  map. The change is audited as `user.role_changed` with actor `sso` and
  told to `Config.Notices` as `NoticeRoleChanged` with `By` empty and the
  new `RoleChangeDetail.ViaSSO`. On such an account (linked to SSO, a map
  configured, not an admin) `PUT /api/auth/users/{id}/role` to `user` or
  `viewer` is `409` with the new class `role-managed-by-sso`: change the
  group at the provider. Granting or demoting an admin still works. Not
  configured, nothing changes. Additive Go API: `Policy.RoleFromGroups`,
  `Policy.RoleWithoutGroup`, `Policy.Groups`, `Policy.ValidateRoles`,
  `Store.FindOrCreateOIDCUserWithRole` and `OIDCSignIn`; the accounts
  document stays at version 9. Birdcage and mikroview: a frontend that
  branches on the role route's `409` classes should handle the new one.
- **Resume a timed-out session with the password alone** (#71). A
  session that timed out after an hour unused, but is less than 24
  hours old, can now be resumed by typing the password alone, without
  a full two-factor sign-in. The 24-hour limit from the original
  sign-in (the session's *ceiling*) does not move (NIST SP 800-63B-4
  section 2.2.3).
  `POST /api/auth/reauthenticate`, `{"password": "..."}`, presented with
  the timed-out session's cookie, issues a new session ID (ASVS 7.2.4)
  for the same account with the original sign-in time, so the 24-hour
  ceiling does not move, and ends the old ID. It takes the same limiter
  reservation as a password sign-in (lockout, disable, address ban and
  limit, known-browser allowance; a wrong password is a failed sign-in),
  is not judged as an unusual sign-in, and never asks for a second factor.
  Anything not resumable is `401 sign-in-required`, as is an account with
  no local password or one owing a password change. `GET /api/auth/session`
  gains `resumable: true` for a cookie in that state. Sign-in history rows
  and the audit record say so: method `resume`
  (`gauntlet.SignInMethodResume`) and `user.reauthenticated`. Additive Go
  API: `SessionStore.Resumable` and `SessionStore.Resume`. Behaviour
  change: the server now remembers a timed-out session until its 24-hour
  ceiling instead of forgetting it after the hour, so it holds a little
  more in memory. A timed-out session still cannot authenticate a
  request, and `ListForUser` does not list it. Both caps are unchanged;
  a restart still ends every session.
- **API tokens expire, are removed when unused, and start `gnt_`** (#74),
  GitHub's personal-access-token lifecycle. **Your application must
  call `Gate.SweepTokens` once a day.** Gauntlet runs no timer of its
  own, so without the call no unused token is ever removed and nobody
  is warned that a token is about to expire.

  `Token.ExpiresAt` (zero means never); `POST /api/tokens` takes an
  optional `expiresAt`, a future date and time such as
  `2027-01-31T09:00:00Z` (RFC 3339) or `"never"` (a router's ingest
  token, say), a `400` otherwise; the response and list show it, left out for a token that
  never expires. `Authenticate` refuses an expired token exactly as it
  refuses an unknown one. New `TokenStore.CreateWithExpiry`,
  `ErrTokenExpiryInvalid`, `TokenPrefix`, `DefaultTokenLifetime`,
  `TokenUnusedLimit` and `TokenExpiryNoticeWindow`.
  `Gate.SweepTokens(ctx, now)` removes tokens unused for a
  year, or created a year ago and never used (audit
  `token.removed_unused`), and tells the creating account, through
  `Config.Notices`, a week before a token expires, once per token
  (`NoticeTokenExpiring`, `AccountNotice.TokenExpiring`,
  `TokenExpiringDetail`; `Token.ExpiryWarnedAt` remembers it). New values
  start `gnt_`, so secret-scanning tools can recognise a leaked one; the
  project's own scanner (gitleaks) has a rule for them in the new
  `.gitleaks.toml`. Tokens
  issued before keep their bare shape and keep working, and keep no
  expiry. The tokens document is now version 3: once saved, an older
  build cannot open it (see the reading notes above); older documents
  open as before.

- **An escape code for a lone admin refused by `block`** (#66,
  ADR-0011). If the only admin who can sign in is refused for coming
  from a new browser, the server now writes a one-time code to its log
  (or hands it to the new `Config.OnEscapeCode`). The admin reads it
  there and enters it in the same browser within 15 minutes; it works
  once. Your sign-in page needs a box that sends the code to `POST
  /api/auth/login/escape`. That lets the one sign-in through and
  remembers the browser. Under the hood, the refusal sets an encrypted
  ticket cookie, `gate_escape_login`, in the refused browser, and the
  code is checked against it, through the login limiter. The `403 sign-in-refused` body is
  unchanged. Never for users, viewers or the SSO callback; with neither
  `Config.Log` nor `Config.OnEscapeCode` nothing is issued. Additive API:
  `gauntlet.NewOneTimeCode` (the setup and unlock codes' generator),
  `Store.OtherAdminCanAct(userID, now)`, `SignInEscapeIssued` and
  `SignInEscapeRefused`, `gate.EscapeCodeHandler`, `gate.EscapeCodeFunc`
  and `gate.EscapeCodeLifetime`. `user.login_refused` gains
  `escape=issued`, a completed escape records `escape=used` (confirmed),
  and its notice is a `NoticeUnusualSignIn` with `Reason: "escape"`.
- **Several admins, the last one protected** (#67, ADR-0010). A
  deployment may hold any number of admins; the last can be neither
  deleted nor demoted. `Store.CreateUser` accepts `RoleAdmin`; new
  `Store.SetRole(id, role, now)` (any of admin, user and viewer, in either
  direction, returning the account and the role it held), `Store.Admins`,
  `ErrLastAdmin` and `ErrRoleUnchanged`. The last-admin check runs inside
  the same locked write as the change, so two admins removed at once
  cannot leave none. A downgrade, `TransferAdmin`'s demotion included,
  ends the account's sessions (`SessionsEndedAt`); every change writes
  `RoleChangedAt`. `TransferAdmin` refuses with `ErrSeveralAdmins` when
  more than one admin exists. `Admin()` returns the first admin by username;
  `HasLocalAdmin` is true when any admin has a local password; every
  admin keeps its password and second factor when SSO is linked.
- `PUT /api/auth/users/{id}/role` (#75, #67): the one route for every
  role change among admin, user and viewer. `POST /api/auth/users` now
  accepts `role: admin`. Granting admin on either needs the caller's own
  password and a current second factor on the same request (`password`
  and `code` on the role route; `adminPassword` and `adminCode` on
  create), on the re-check budget: missing is `400`, wrong is `401`, `429`
  once the budget is spent. Audited as `user.role_changed` (actor, from,
  to).
- The `last-admin` error class (409): deleting or demoting the last admin.
- `gate.NoticeRoleChanged` and `AccountNotice.RoleChanged`
  (`RoleChangeDetail{From, To}`): `Config.Notices` is told of a role
  change, and of an admin created over HTTP (`From` empty).
- An address ban (#70): `LoginLimiter.RecordAddressFailure` counts failed
  sign-in attempts per source address, and the 100th within a rolling 24
  hours bans the address for 24 hours (`AddressBanFailures`,
  `AddressBanDuration`); `AddressBanned` reads it. IPv4 addresses are
  counted one by one. IPv6 addresses are counted by network, the first
  64 bits (`AddressBanGroup`), so an attacker cannot dodge the ban by
  changing the end of the address. Anything that is not a valid address
  is counted as the text it is. Counts and bans are kept in memory only,
  so a restart forgets them; if memory fills, counts are dropped before
  bans. `gate` refuses a banned
  address with the same `429` as the per-address limit, and a browser the
  account remembers passes the ban, so a reverse proxy that hides visitor
  addresses cannot lock the owner out. The ban starting is one
  `address.banned` audit record. Today's per-address limit is unchanged.
- `LoginDisableDuration` and `User.LoginDisabled`, for the disable that
  lifts itself (see Changed) (#70).

- `persist/persisttest`, a test suite an application runs against its
  own `persist.Backend` from its own tests: `persisttest.Run`. It checks
  that a save reads back as the same bytes and version, that a wrong
  expected version and a second create are refused with
  `persist.ErrConflict`, that a second backend over the same storage
  sees the first's writes, that `VersionReader` (where implemented)
  agrees, and that of two concurrent writers from one version exactly
  one wins. Each check is its own subtest. Gauntlet's memory, file and
  encrypted file backends run it too (#61).
- `SessionStore.RevokeAllForUserCount`: signs a user out everywhere and
  returns how many sessions it ended, counted under the same lock (#58).
- `POST /api/auth/recovery-codes/confirm`: the signed-in user confirms
  they have saved the recovery codes their first second factor was held
  with, which makes the factor and the codes live (see Changed). Open at
  the must-enrol-factor door. `409` when nothing is held, `401`
  `step-expired` when the hold ran out (#58).
- `Store.HoldFirstPasskey`, `Store.HoldFirstTOTP` and
  `Store.ConfirmHeldEnrolment`, with `User.HeldEnrolment`,
  `User.EnrolmentHeld`, `HeldEnrolmentLifetime` and the errors
  `ErrEnrolmentHeld`, `ErrSecondFactorExists`, `ErrNoHeldEnrolment` and
  `ErrHeldEnrolmentExpired`, for applications driving enrolment
  themselves. `Store.SetPendingTOTPSecretAt` records when a pending
  authenticator-app secret was set; `User.TOTPPending` and
  `TOTPPendingLifetime` say whether it can still be confirmed (#58).
- `gate.Config.Country`: an optional lookup from a client address to its
  ISO 3166-1 alpha-2 country code, recorded on a sign-in and the session
  it issues. `SessionClient` and `SignInRow` gain `Country`; the
  sign-in history document is now version 2 for the added field, and an
  older document loads with it blank. The admin sign-in history
  (`GET /api/auth/sign-ins`) and a person's own session list
  (`GET /api/auth/sessions`) both gain an optional `country` field.
  Nothing is recorded with `Config.Country` left nil (#54).
- `geoip`, a new package that downloads the operator's chosen country
  file -- MaxMind GeoLite2-Country or IPinfo Lite, each with the
  operator's own key -- keeps it current in a directory the application
  names, and looks addresses up in it locally. Its `Manager.Country` is
  what an application passes as `gate.Config.Country`. Gauntlet never
  stores the key and keeps it out of every log and error; the
  application credits the provider (docs/geoip.md, ADR-0008). Neither
  `gate` nor the root package imports it (#54).
- Unusual sign-ins (#55, ADR-0009): a completed sign-in -- password or
  SSO, plus any second factor, with no session yet -- is judged against
  what the account remembers (`Store.JudgeSignIn`), and every session
  issue remembers it (`Store.RememberSignIn`), whatever the policy. Three
  signals, each raised only against something already remembered:
  `gauntlet.SignInSignals` (`new-browser`, `new-country`,
  `impossible-travel`), carried on `SessionClient.Unusual`. The account
  remembers up to three countries for 90 days (`User.SeenCountries`) and
  its one latest located sign-in (`User.LastPlace`); both are cleared
  wherever known browsers already are. The accounts document is now
  version 8 for the added fields, and an older build refuses it.
- `gate.Config.UnusualSignIns` (`UnusualSignInPolicy`): what each signal
  does -- `off`, `flag` (default), `confirm` or `block`, with an optional
  override per signal and an optional `Decide` function that can
  overrule the settings' answer once per sign-in, under a fixed 3-second
  `DecideTimeout`. `Decide`, a failed delivery or an invalid answer all
  fail closed to `block`. `gate.New` refuses an unknown action, `confirm`
  with no way to deliver a code, and impossible travel turned on with no
  `Config.Locate` (#55).
- `gate.Config.Locate`, and `geoip.Config.Edition`/`geoip.EditionCity`/
  `(*geoip.Manager).Locate`: an optional point-and-radius lookup from
  MaxMind's larger GeoLite2-City file, so impossible travel can be
  judged; `New` refuses `EditionCity` with IPinfo Lite, which has no
  coordinates. `geoip.Status` gains `Edition` and `Locates` (#55,
  docs/geoip.md).
- `POST /api/auth/login/confirm` and the sealed `gate_confirm_login`
  cookie (15 minutes): under the `confirm` action, a sign-in with every
  credential right is held for an eight-digit code that
  `gate.Config.DeliverConfirmCode` hands the application synchronously;
  typing the code into the same sign-in completes it. Only the code's
  SHA-256 is ever kept (#55).
- The `sign-in-refused` error class (403): under the `block` action,
  every credential was right and the account's sign-in policy refused
  the attempt from this browser or place; returned by `login` and
  `login/factor`, and as `?ssoError=refused` from the SSO callback.
  `SignInOutcome` gains `refused`, `confirm_sent` and `confirm_refused`;
  `SignInEvent` and `SignInRow` gain `Confirmed`. `GET
  /api/auth/sign-ins` and `GET /api/auth/sessions` both gain `unusual`,
  and `sign-ins` also gains `confirmed`; `SignInQuery` gains `Unusual`,
  and `?unusual=true` on `GET /api/auth/sign-ins` answers only rows that
  raised at least one signal. The sign-in history document is now
  version 3 for the added fields, and an older build refuses it (#55).
- `gate.Config.Notices` (`AccountNotifier`): one hook for every account
  event this module raises -- a password reset, a second factor added
  or removed, recovery codes regenerated, an account lockout, a disable,
  every session ended, and an unusual sign-in flagged or blocked -- each
  carrying a `NoticeKind` and the one typed detail pointer that kind
  names (`PasswordResetDetail`, `SecondFactorDetail`, `LockoutDetail`,
  `SessionsEndedDetail`, `UnusualSignInDetail`). Your hook is called
  after the response has been sent, in the background, with a
  10-second limit; if it fails or crashes, gauntlet logs the problem
  and the sign-in is not affected -- the same as the deprecated
  `Config.Notify`. nil means nobody is told (#73).
- `gate.Config.DeliverConfirmCode`: hands an unusual sign-in's
  confirmation code to the application synchronously, before the
  sign-in is answered -- the opposite contract from `Notices`, which may
  be queued. A failure refuses the attempt, since no code reached
  anyone; nil means the confirm action is unavailable (#55, #73).

- **Security fixes reach a merge request the same day** (#79).
  A second, daily pipeline schedule runs the `renovate` job with
  `RENOVATE_SECURITY_ONLY=true`, which merges the new
  `renovate-security.json` over `renovate.json`: every ordinary update
  is off and vulnerability fixes stay on, so a security fix no longer
  waits for Monday's run (docs/releasing.md).
- Additive Go API from the v0.3.0 release audit (#79), each described
  where it changes behaviour below: `SessionStore.CreateContinuing`,
  `SessionStore.EndSessionsForUser`, `Store.ValidateNewAccount`,
  `Store.PasswordMatches`, `ErrLastLocalAdmin`, `ErrNoTOTP`,
  `ErrNoPasskeys`, `TokenStore.RemoveOrphans`,
  `TokenStore.MarkExpiryWarned`, `TokenSweep.Orphaned`,
  `KnownBrowser.Confirmed`, `oidc.AllowIssuerWithPolicy`,
  `oidc.Config.Policy` and `oidc.Client.Issuer`. The accounts document
  stays at version 9.

### Security

- **Confirmation codes and escape codes are limited per account** (#84).
  A sign-in held for a code hands its attempt back to the login
  limiter, so someone holding the password could repeat it without limit
  and flood the owner's mailbox with confirmation codes, or a lone
  admin's server log with escape codes. Each code is now counted per
  account as it is sent, the limiter's threshold per window (5 per 5
  minutes at the usual settings), confirmation and escape codes
  separately, and never handed back, a failed delivery included. Past
  it, a held sign-in is answered `429 rate-limited` with no code, ticket
  or cookie (the SSO callback redirects `ssoError=refused`), recorded as
  `rate_limited`, and a lone admin gets no escape code. A browser the
  account knows is never held, so is unaffected; an admin's unlock
  (`LoginLimiter.UnlockLogin`) or a restart clears the count. New
  `LoginLimiter.ReserveDelivery`. Additive.

- If someone puts an older copy of the accounts or tokens file back
  while the service is running, the service now notices and ignores
  it. It logs one message, keeps what it holds, and stops saving until
  the file is replaced or the service restarts. Before, it silently
  took the old copy, undoing later changes and bringing revoked tokens
  back to life. How: each document now carries a save counter inside
  its encrypted part, and a lower one is refused. The accounts document
  is now version 6 and the tokens document version 2; older ones open
  and are stamped on their next save. A file put back while the service
  is stopped is still accepted on start (docs/design.md §4) (#59).

- **Sign out everywhere keeps the session's 24-hour ceiling** (#79). It
  asked for no credential and issued the new session as a fresh
  sign-in, so anyone holding a live cookie could call it once an hour
  and keep a session for ever. `SessionStore.CreateContinuing` issues
  the new session with the old one's `IssuedAt`, signals and method, as
  `Resume` does, and never past the original ceiling; the cookie lasts
  only to that ceiling. If the caller's session has gone meanwhile,
  nothing is issued.
- `password.KDFParams.Valid` now also refuses memory above 1 GiB, more
  than 64 passes and more than 32 threads, so a damaged or edited lock
  document cannot drive Argon2id into a huge allocation or hold a hash
  slot for minutes (#79). A deliberate future profile raises the
  ceilings.
- The store file keeps its mode, owner and group when it is replaced
  (#79). A server and an application's CLI share the store, and the CLI
  is run with `sudo`: after one root save the server could no longer
  read or replace its own file. A `chown` refused with permission
  denied is ignored; any other failure fails the write. The `.lock` file
  beside the store takes the store's owner when the server creates it.
  Upgrade note: a `.lock` file an earlier release left root-owned
  cannot be repaired by the server; the save error now says so, and
  the fix is to `chown` it to the server's user or delete it while the
  server is stopped.
- A forced password change refuses the password the account already
  has (#79). It asks for no current password, so a caller could lift
  `MustChangePassword` by setting the same one, the very password
  presumed known to someone else. The answer is the same `400` as an
  ordinary change gives; `Store.PasswordMatches` does the comparison.
- Five second-factor failures on an account with no local password end
  its sessions instead of forcing a password change it cannot make
  (#79). The sign-in provider's identity is what is at risk and this
  module cannot change that; the flag is left alone, and `Protect`'s
  must-change door now applies only to an account with a local
  password, so one that already carries the flag is no longer shut out.
- `POST /api/auth/totp/confirm` now records a wrong code as
  `user.login_failed` (`step=recheck`) and logs the "re-check refused"
  line, and does the same for a limiter refusal, as the other in-session
  re-checks do (#79). A run of wrong codes from a stolen session cookie
  against a pending enrolment left no trace.
- `POST /api/auth/oidc/link` asks for the caller's own password,
  `{"password": ...}`, on the same rate-limited re-check as TOTP enrol
  and passkey registration: a wrong or missing one is `401`, a spent
  budget `429`, and no flow cookie is set (#79). A link is permanent and
  strips a non-admin of its password and factors, so a stolen session
  cookie alone could turn into a lasting way in. A frontend that starts
  a link must now send the password.
- `POST /api/auth/logout-all` asks an account with a local password for
  it, `{"password": ...}`, before any session ends (`401`/`429` as on the
  other re-checks), and an SSO-only account's sign out everywhere no
  longer forgets its remembered browsers, countries and last place
  (#79). With only a session cookie, a thief could wipe the account's
  unusual-sign-in baseline and leave their own browser the only one
  remembered, so that under `block` the owner was refused on their own
  devices. An SSO-only account still sends no body; the audit detail
  says the browsers were kept. A frontend must now send the password
  for an account that has one.
- The login limiter keys a username that matches no account on a
  SHA-256 digest of the lowercased name instead of the name itself
  (#79). A body may hold a 64 KiB name and the limiter keeps thousands
  of keys, so a credential-free flood of long made-up names could pin
  hundreds of megabytes. Limiting is unchanged: one name, in any case,
  is one bucket.
- The confirmation code (`ConfirmCode.Client`) and the unusual-sign-in
  and block notices carry the client cleaned and cut as a session's is,
  not the raw `User-Agent` (#79): someone holding the password could put
  line breaks, a made-up line or a huge header into the message the
  service sends the real owner. The rule is exported as
  `gauntlet.SessionClient.Clean`, which `CreateFrom`, `CreateContinuing`
  and `Resume` now use too. Additive.

### Changed

- **Breaking: `gate.New` refuses to start until `Config.AdminPasskey` is
  set** (#82, ADR-0015). There is no default either way, so that each
  application's admin makes a conscious choice and an application never
  runs without the rule, or locks its admins out, by accident. `New`
  refuses an unset or unknown value, and refuses
  `gate.AdminPasskeyRequired` while `Deps.Passkeys` is nil or its
  public URL is unset, an IP address or plain http on any host but
  localhost, naming which; it
  logs the choice at start-up. **Every application must add the line
  before upgrading, or it will not start:** birdcage, which wires no
  passkeys, sets `gate.AdminPasskeyOptional` (until it wires
  `gauntlet/passkey`); mikroview sets `gate.AdminPasskeyRequired` where
  it serves https on a domain name and `gate.AdminPasskeyOptional` when
  reached by IP. With `required`, have every admin register a passkey
  before upgrading: an admin without one is stopped at their first
  request afterwards and registers one there. This also amends
  ADR-0004 decision 4: a relying party that is not ready still boots,
  but only for an application that set `optional`.
- **Every passkey registration now asks for a discoverable credential**
  (#77). The creation options carry `residentKey: "preferred"`
  (and `requireResidentKey: false`), mikroview's included: W3C's
  recommendation, harmless where the authenticator cannot hold one
  (a PIN-less security key still registers, as a second factor), and
  needed before a passkey can sign in alone. Passkeys registered before
  this may not be discoverable; they keep working as a second factor.
- **A token created without an expiry now expires after a year** (#74).
  `TokenStore.Create` and `POST /api/tokens` without `expiresAt` used to
  issue a token that lasted until revoked. Birdcage and mikroview: a
  token made the old way keeps working, but one made from now on stops at
  a year unless its creator passes `expiresAt: "never"` (call
  `CreateWithExpiry` with the zero time from Go), or the application
  rotates it first. Call `Gate.SweepTokens` daily so owners hear a week
  ahead.
- **Breaking: five admin routes now take the calling admin's password**
  (#72, ASVS 7.5.3). `POST /api/auth/users/{id}/reset-password`,
  `POST /api/tokens`, `DELETE /api/auth/users/{id}`,
  `DELETE /api/auth/users/{id}/totp` and
  `DELETE /api/auth/users/{id}/passkeys` need `password` (the caller's
  own) in the JSON request body, which the three `DELETE`s and
  `reset-password` did not read before; a request without a readable
  body is `400`. A missing or wrong password is `401`
  `invalid-credentials`, counted on the same per-account re-check budget
  as the self-service routes (`429` once spent). A caller sending the
  old bodies must add it. `POST /api/auth/users` is unchanged.
- **The accounts document is now version 9** (#67). No field changed:
  a document with several admins is now legal, which a build reading up
  to version 8 refuses at load as "allows exactly one". A version-8
  document opens unchanged, and a version-8 build refuses a version-9
  one. A document with accounts and no admin is still refused.
- Deleting the last admin answers `409` class `last-admin` (the
  `conflict` class it had on `dev` was never released), and the caller's own account
  cannot be deleted while other admins exist (`409` `conflict`).
  `POST /api/auth/users` with `role: admin` is no longer a `400` for
  being an admin; without `adminPassword` and `adminCode` it is a `400`
  naming them.
- `ErrSingleAdmin` is never returned now; it stays exported so
  applications switching on it keep compiling. `ErrCannotDeleteAdmin`
  is still the value `DeleteUser` returns, and also answers
  `errors.Is(err, ErrLastAdmin)`. `ErrInvalidRole`'s text now names admin.
- Login lockouts are capped at one hour, not 24 (#70): 5, 15 and 45
  minutes at 5 attempts per 5 minutes, then an hour each. The escalation
  and the known-browser allowance are unchanged. A stranger who knew the
  username could keep the owner out for a day; the address ban now puts
  the long penalty on the attacker instead.
- The disable after `MaxConsecutiveLoginFailures` (50) failures lifts
  itself 24 hours after `User.LoginDisabledAt`, with no unlock needed
  (#70). Nothing new is stored: a disabled account simply becomes usable
  again 24 hours after the time already on its record.
  The first attempt afterwards clears the account's count of lockouts as
  `UnlockLogin` does, so the next failure does not disable it again at
  once. The admin unlock answer's `wasDisabled` is false for a disable
  that has lapsed. The one-time unlock code follows the same clock since
  the v0.3.0 audit (#79): a lapsed disable issues none.

- `gate.Config.Notify` and `Notifier` are deprecated in favour of
  `Config.Notices`: kept working for a minor release (ADR-0002 decision
  2), and `gate.New` refuses a `Config` setting both. An admin ending
  another account's sessions now goes to `Notices` when it is set, else
  the deprecated `Notify` (#73).
- The known-browser cookie (`gate_known_browser`) now carries up to four
  tokens, one per account, rather than one for whichever account last
  completed a sign-in in that browser: a browser shared by two accounts
  is no longer "new" to the second one on every switch. A one-token
  cookie from before this change still reads as a list of one (#55).
- `Store.ClearKnownBrowsers` also forgets `User.SeenCountries` and
  `User.LastPlace`, and `Store.IssueResetCode` clears all three in its
  own write: sign out everywhere, or an admin reset code, now forgets
  everything the account trusts, not only its known browsers (#55).
- The sign-in history's fold key now also includes the unusual-sign-in
  signals and whether a confirmation code completed the sign-in, so an
  unusual success is never folded into an ordinary one from the same
  address (#55).
- **Breaking for HTTP clients: an account's first second factor is held
  until its recovery codes are confirmed** (#58). The first passkey
  (`register/finish`) or first authenticator app (`totp/confirm`) is
  saved together with its ten recovery codes in one write, on hold; the
  response shows the codes once with `pendingConfirmation: true`
  (`totp/confirm` answers `enabled: false`).

  What changes for your frontend: until the user calls `POST
  /api/auth/recovery-codes/confirm`, the factor signs nothing in and is
  not listed or counted, the codes redeem nothing, and the account stays
  restricted to the second-factor setup routes. No other session ends
  and no audit line is written; the confirmation does all of that.
  Unconfirmed after ten minutes, the factor and codes are deleted. While one is held, starting another
  enrolment is refused with `409`. A scanned but unconfirmed
  authenticator-app secret now expires ten minutes after it was set
  (`401` `step-expired` at `totp/confirm`). A later factor is still added
  live, without codes (`alreadyIssued: true`). This replaces minting the
  codes in a second write after the factor went live, where a failure
  between the two left a live factor with no codes; the
  `partially-completed` answers from those two routes (and
  `totpActive`) are gone, and a failed save there is `server-error`.

  Go API notes: `GenerateRecoveryCodesIfAbsent` is no longer used by `gate` and stays
  for direct callers. The accounts document is now version 7
  (`totpPendingSince`, `heldEnrolment`); older ones open unchanged, and
  a version-6 build refuses a version-7 document.
- **Breaking for HTTP clients.** Every error `gate.Routes` and
  `gate.Protect` return is now an RFC 9457 Problem Details body
  (`application/problem+json`, with `type`, `title`, `status` and
  `detail`) instead of `text/plain` or `{"error": ...}` (#23). Each
  `type` links to its permanent entry in
  [docs/api/errors.md](docs/api/errors.md); `detail` carries the same
  message as before. An unknown path or wrong method under `Routes`
  answers `about:blank`, keeping `Allow` on 405. The one JSON error body
  with an extra field (user deleted, tokens not revoked) keeps
  `username`; its `error` field is now `detail`. The other one that
  existed (TOTP on, recovery codes not saved, with `totpActive`) is
  gone: see the held first second factor (#58) above. `WWW-Authenticate` on 401s is
  unchanged. Switched before mikroview moves onto gauntlet, so it
  migrates once (ADR-0002, owner 2026-10-03).

Behaviour changes and deprecations from the v0.3.0 release audit (#79):

- **An SSO-only admin may set a local password, and one local admin is
  always kept** (#79, ADR-0010). `POST /api/auth/password` lets an
  admin with no local password set a first one with only
  `newPassword`; users and viewers without one still get `409`, and
  the forced second-factor enrolment door then applies. Every step-up
  route now answers `409` to a caller with no local password, telling
  it to set one first, instead of a `401` that could never succeed and
  spent the re-check budget. `SetRole`, `DeleteUser` and `TransferAdmin`
  refuse, inside the write, to remove the last admin who holds a local
  password while other admins remain, with the new `ErrLastLocalAdmin`
  (`409` `last-admin` over HTTP). `GET /api/auth/session` reports
  `mustChangePassword` only for an account with a local password.
- **Google's shared SSO issuer is accepted when the policy pins `hd`**
  (#79, ADR-0014). `oidc.AllowIssuer` refused `accounts.google.com`
  whatever the policy said, so an operator following `Policy`'s own
  documentation got a start-up refusal. `oidc.AllowIssuerWithPolicy`
  accepts it only when `RequiredClaims` names `hd` with a value. Apple
  and Microsoft personal accounts have no tenant claim and stay refused;
  Entra's `common`, `organizations` and `consumers` endpoints stay
  refused too, because go-oidc cannot discover their templated issuer,
  and the error names the single-tenant issuer
  (`https://login.microsoftonline.com/<tenant-guid>/v2.0`) to use
  instead. `oidc.Config.Policy` is checked by `oidc.New` against both
  the configured URL and the issuer the discovery document names, and
  `gate.New` checks `Client.Issuer` against `Deps.OIDCPolicy`. `AllowIssuer` and `Policy.Restricted` are
  deprecated (nothing called `Restricted`).
- `SessionStore.EndSessionsForUser` ends every session as before but
  counts only those still live, so an admin's sign-out of another
  account no longer reports, audits or tells the owner about sessions
  that had timed out and were kept only for a resume.
  `RevokeAllForUserCount` is deprecated in its favour (#79).
- Creating an admin checks the new username and password before the
  step-up, so a typo no longer costs the caller a recovery code
  (#79). `Store.ValidateNewAccount` runs `CreateUser`'s checks without
  writing; `CreateUser` still repeats them inside the write.
- The minimum password length counts characters (code points), not
  UTF-8 bytes, in `CreateUser`, `SetPassword` and `ValidateNewAccount`
  (#79). Seven letters of a non-Latin script no longer pass an "at least
  8 characters" rule.
- `POST /api/auth/login/passkey/begin` reserves its attempt on a limiter
  bucket of its own (`passkey-begin:` plus the address, same limit and
  ban check) instead of the address's login bucket (#79, ADR-0012).
  Page views with passkey autofill filled the address's budget and
  answered every sign-in from it with `429`. The passkey-alone finish
  and the passkey resume release that key.
- `login/factor` with an assertion checks that the relying party is
  ready before it reserves the address's and the account's attempt,
  so a `409` no longer spends attempts toward a `429` and a lockout
  (#79).
- Removing a factor that is not there changes nothing (#79).
  `ClearTOTP` and `ClearPasskeys` return the new `ErrNoTOTP` or
  `ErrNoPasskeys` and write nothing when the account has no such factor
  and none on hold. `DELETE /api/auth/totp` answers `404` `not-found`
  as passkey delete does, before any session ends or anything is
  recorded or sent; the admin clear routes answer `200` with
  `cleared: false` and record and send nothing. Before, a second click
  on "Disable" announced a removal that never happened.
- The token sweep sends an expiry warning first and records it after
  (#79). `TokenStore.Sweep` only lists the tokens to warn about and no
  longer marks them; the new `TokenStore.MarkExpiryWarned` records the
  warning for the ids whose notice was sent, and `Gate.SweepTokens`
  calls it. A failed send is logged and tried again at the next sweep
  (at least once: a duplicate after a crash between the two is
  accepted); `TokenSweep.Warned` counts the tokens marked. A notifier
  failure, timeout or restart used to lose the warning for good.
- `Gate.SweepTokens` removes tokens whose creating account is gone
  (#79). Deleting an account saves the accounts document and then
  revokes its tokens in a second write, and a failure between the two
  left them working for up to a year. `TokenStore.RemoveOrphans`
  deletes, in one write, every attributed token whose creator no
  longer exists, each removal is audited as `token.removed_orphaned`
  by `system`, and `TokenSweep.Orphaned` counts them. Unattributed
  tokens are never touched.
- A lone admin whose sign-in is held for a confirmation code or a
  passkey is offered the escape code, as one who is blocked is (#79,
  ADR-0011): the escape cookie is set beside the hold's ticket, the code
  goes to the log and `escape_issued` is recorded. Before, such an admin
  was held again on every attempt. The held challenge's body is
  unchanged.
- A remembered browser is provisional until its cookie comes back
  (#79). `KnownBrowser.Confirmed` is set when an entry replaces a live
  one the browser carried back. Past `MaxKnownBrowsers` unconfirmed
  entries are evicted first, oldest first, then confirmed ones, and
  the new entry is never the one evicted; before, three cookie-less
  sign-ins pushed the owner's everyday browser out. An unconfirmed
  entry is still known.
- The sign-in-refused text and the SSO-refusal docs now name only
  actions that work (#79). The `403` text, which only an account with a
  local password receives, is unchanged; `docs/api/errors.md` and
  ADR-0009 now say that an SSO-only account refused at the SSO callback
  (`ssoError=refused`) has no administrator remedy in this release, and
  that its way back is a browser or place it has signed in from before.
- The restart unlock code honours the 24-hour self-lift (#79). A
  restart after a disable had lifted itself no longer logs "locked out"
  and prints a live break-glass code for an admin who can sign in, and
  an outstanding code stops working once its disable runs out.
- An empty store file path is refused (#79).
  `NewEncryptedFileBackend` refuses it at construction and the file
  backend's `Load` returns the "no file path configured" error `Save`
  already did; before, it read as a missing file, a fresh install, and
  was refused only once something was saved.
- `geoip` downloads are bounded by a timeout whatever HTTP client made
  them (#79). A caller's `HTTPClient` with no timeout let a provider
  that stopped answering hang the download, and the refresher with it,
  for good.
- The licence check honours `allow-dependencies-licenses` (#79).
  `licence-check.sh` documented per-module exceptions
  (`pkg:golang/<module>@<version>`) but never read the key. It now
  checks that the build has the module at exactly that version (a
  stale entry fails), passes `--ignore` for it and prints the entry
  with its reason; an entry whose module path is the start of another
  module's in the build is refused.

### Fixed

- An account created by its first single sign-on is now audited as
  `user.create` (actor `sso`, the role and the issuer), as an
  admin-created account is (#78).

Low-severity findings from the v0.2.0 audit (#58):

- `GET /api/auth/session` no longer says `mustEnrolSecondFactor` while
  a forced password change still blocks the enrol routes.
- Two first passkey registrations finishing at the same moment no
  longer revoke each other's new session.
- The `ended` count from an admin's sign-out-everywhere can no longer
  be one short when a login lands during it.
- Lowering the sign-in history's `MaxRows` below the rows it holds now
  logs the dropped rows once instead of dropping them silently.
- The sign-in history notices a replaced or `null` file on its next
  read, not only at the next sign-in.
- Registering with a setup code another, lagging process has just spent
  now says the code was already used, not that registration is closed.
- `VerifyPassword` caps the thread count it reads from a stored hash,
  beside its memory, time, salt and key-length caps.
- The file backend's save honours its context deadline while waiting
  for the sidecar lock file, and its doc comment no longer calls
  deleting that `.lock` file harmless.
- A published password list refused for a build time in the future is
  checked again at each refresh and adopted once the clock catches up.
- `pwlist build`'s retry waits now reach the documented 8 s ceiling.

Findings from the v0.3.0 release audit (#79):

- The audit lines are now honest about a passkey: a sign-in held for a
  passkey and completed by one is recorded in `user.login` as "via
  passkey proof" rather than "via confirmation code", and the note is
  written even when the session loses its signals to a failed remember
  write. A session resumed with a passkey is audited by
  `user.reauthenticated` as "session resumed with passkey", not "with
  password" (the history row's method stays `resume`).
- The authenticator-app enrolment URI escapes the product name in both
  the `otpauth://` label and the `issuer` parameter, so "Home Router"
  is no longer shown as "Home+Router" or unscannable, and a colon in
  the name no longer breaks the label's separator.

## [0.2.0] - 2026-10-03

### Added

- `gauntlet.AccountLockoutRecords`, an optional extension of
  `AccountLockouts`: a host application's own lockout store that
  implements it keeps the disabled flag and the count of lockouts
  across a restart, not only the lockout's end. `AccountLockouts` alone
  still works and loses those two on restart, as before (#57).
- Failed sign-ins, lockouts and refused requests are recorded, with the
  client address (#45). Through `gate.Config.Audit`: `user.login_failed`
  for each failed password, code, passkey assertion or refused SSO
  identity the login limiter admitted (detail
  `outcome=... method=... from="..."`; actor and target the account's
  username, or `unknown` with the name masked when it matched no
  account), and `account.locked` (`until=... lockouts=n from=...`) or
  `account.disabled` beside the failure that started a lockout or
  disabled sign-in. A refusal by the limiter (429), a missing CSRF
  header, a malformed `Authorization` header, a role refusal on gate's
  admin routes and the two door 403s are Warn lines on `Config.Log`
  carrying `from=`, at most one per kind and address per minute. The
  name typed for an attempt that matched no account never reaches the
  audit or the log: `gauntlet.MaskUnknownUsername` keeps its first two
  characters and its length (`Hunter2024` is `Hu••••••••`), and names
  that probes try (`root`, `admin`, `postgres` and the like) in full.
  `LoginLimiter.ReserveAccountDecision` (`AccountDecision`) is
  `ReserveAccount` saying why it refused or what the attempt started;
  `SignInOutcome`, `SignInMethod` and `SignInEvent` name an attempt for
  the sign-in history (#53).
- A sign-in history admins can page through (#53,
  [ADR-0006](docs/adr/0006-sign-in-history.md)).
  `gauntlet.OpenSignInHistory(backend, gauntlet.SignInHistoryOptions{})`
  opens a third sealed document, `signins` (wrap its backend in
  `persist.Encrypt` with the label `"signins"`; a plaintext backend is
  refused unless `AllowPlaintextAtRest`, and a nil one keeps it in memory).
  Pass it as the new `gate.Deps.SignIns` and every sign-in attempt
  becomes a row: time, account or masked name, outcome, method, address
  and browser. `GET /api/auth/sign-ins` (admin) lists them newest first,
  filtered by `user`, `address` and `outcome`, paged with `before` and
  `limit`; it answers 404 while `Deps.SignIns` is nil. The newest 10,000
  rows are kept by default (`MaxRows`, at most 50,000). Attempts alike
  within 10 minutes fold into one row with a `count`; failed attempts
  may start at most 100 rows per 10 minutes, the rest counted in one
  `unrecorded` row, so a flood of attempts is a bounded number of rows
  and saves. Saves run in the background, at most every 5 s while a new
  row is unsaved and every minute while only counts changed, and never
  hold up a sign-in; call `Close` at shutdown to save the rest. The
  document starts at version 1.
- Every audit record a request writes now ends with `from="<address>"`
  (#45), not only the sign-in records. A wrong password or code at an
  in-session re-check (password change, authenticator and passkey
  changes, recovery codes, an admin's own unlock) is `user.login_failed`
  with `step=recheck`; a re-check the limiter refuses and a request body
  over 64 KiB each leave a rated Warn line; and a failure through a known
  browser's allowance that disables sign-in writes `account.disabled`
  (`LoginLimiter.ReserveKnownBrowserDecision`, which
  `ReserveKnownBrowser` now wraps).
- `POST /api/auth/users/{id}/logout-all` lets an admin sign another
  account out everywhere (#53): every gauntlet session it holds ends and
  every browser it remembers is forgotten; its password and factors are
  untouched. An optional `reason` (at most 200 characters, no control or
  format characters) goes into the `user.sessions_ended` audit record.
  409 for the caller's own account, 404 for none. gauntlet sends no
  mail: an application that sets the new `gate.Config.Notify` (a
  `gate.Notifier`) is handed a `gate.SessionsEndedNotice` after the
  response, in the background with a 10-second deadline, to mail the
  account's owner; its failure is one log line and never changes the
  admin's answer.
- `persist.Encrypt(backend, key, persist.EncryptOptions{Label: "accounts"})`
  wraps any `persist.Backend` so every document is sealed before the
  backend stores it and opened after it is read: the AES-256-GCM
  envelope `persist.EncryptedFileBackend` has used since #18 (HKDF from
  the application's key of at least 32 bytes, a fresh salt and nonce
  per save, the label authenticated with the document), stored through
  the backend as the JSON text `{"sealed": "<base64>"}` so a `text`
  column or a JSON-validating backend holds it unchanged (#50,
  [ADR-0005](docs/adr/0005-encryption-at-rest-on-every-backend.md)). A
  dump or backup of the database then carries no TOTP secret and no
  passkey public key, and a document altered in the database fails to
  open rather than being read. `EncryptedFileBackend` is now this
  wrapper over the plain file and is otherwise unchanged; files it
  wrote before still open, and still open in mikroview.
  `EncryptOptions.MigratePlaintext` accepts a document the backend
  already holds in the clear and seals it in place on the first load,
  for the one release that introduces the wrapper. The new
  `persist.AtRest` capability (`ProtectedAtRest() bool`) is how a
  backend says a copy of its storage carries no plaintext;
  `persist.Encrypted`, `EncryptedFileBackend` and `Memory` implement it.
- Ways to unlock a sign-in disabled after 50 failures in a row (#44).
  `POST /api/auth/users/{id}/unlock` lets an admin lift another
  account's disable, lockout and count of lockouts; it answers 200
  whether or not anything was locked. On the admin's own account, from
  a session they still hold, it takes a body with their password and a
  current TOTP or recovery code (`UnlockSelfRequest`): 400 without
  them, 401 for a wrong one, each counted on the account's password
  re-check budget (429 once spent); the session alone unlocks nothing.
  It calls the new `LoginLimiter.UnlockLogin`, which also
  clears the limiter's own count of recent guesses; applications with
  their own unlock path should call it rather than `Store.UnlockLogin`.
  When the store opens with the admin disabled and no admin left who
  could unlock it, it announces a one-time unlock code, like the setup
  code: through the new `Options.OnUnlockCode` (`UnlockCodeHandler`,
  `UnlockCodeFunc`), or else as one Warn line on `Options.Log`. A CLI
  that opens the store should pass a hook that does nothing, as it
  does for `OnSetupCode`. `POST /api/auth/unlock` takes the admin's
  username and the code (`Store.CheckUnlockCode`,
  `ErrUnlockCodeInvalid`), and only lifts the disable: the admin then
  signs in with their existing password and second factor. The code
  works once, and stops working if the admin is unlocked any other
  way. The accounts document is unchanged.
- `gauntlet/blocklist`, the common-password list (#52,
  [ADR-0007](docs/adr/0007-common-password-list.md)): the SHA-1 hashes
  of the 10,000 most prevalent passwords in Have I Been Pwned's Pwned
  Passwords. `Embedded()` is the copy built into the release and never
  touches the network; `List.Contains` checks a password against it.
  An application that wants newer lists between releases runs a
  `Refresher` (`NewRefresher`, `RefreshConfig`): it checks the public
  GitHub mirror once a day by default, accepts a list only if its
  checksum and signature verify and it is newer than the one in use,
  and keeps it in a directory the application names. The release
  carries the first signed list, built 2026-10-03; a release refuses
  to tag without a list or with one over 90 days old.
  `Refresher.Contains` lets a refresher stand wherever a list is
  expected. An application's own tests that register accounts with
  common passwords such as `password123` now get
  `ErrPasswordBlocked`, and need other test passwords.
- New passwords are checked before they are set (#43): `Register`,
  `CreateUser` and `SetPassword`, and so gate's register, create-user
  and change-password routes, refuse a password that is on the
  common-password list (`Options.PasswordBlocklist`, by default
  `blocklist.Embedded()`; a `*blocklist.Refresher` works too), in any
  case, with `ErrPasswordBlocked`, and one that is the account's
  username or the product's name, give or take case, punctuation and
  digits around it, with `ErrPasswordContext` (`PasswordMatchesContext`;
  new `Options.ProductName`, and gate adds its `Config.ProductName`
  itself). gate answers both with `400` and a plain reason. The new
  `PasswordList` interface is what the list option takes. Until the
  first signed list ships, the embedded list blocks nothing.
- An optional live breach check (#43): set `Options.BreachCheck` to a
  `blocklist.PwnedChecker` (`NewPwnedChecker`, `PwnedConfig`,
  `DefaultPwnedURL`) and every new password that passed the local
  checks is looked up in Have I Been Pwned's Pwned Passwords by
  k-anonymity -- only the first five hex characters of its SHA-1 are
  sent, with padding requested -- and refused with
  `ErrPasswordBlocked` on a hit. Each check is bounded by
  `BreachCheckTimeout` (5 s), whatever the checker does. When HIBP
  cannot answer, the password is accepted against the embedded list,
  the miss is logged, and the account is marked (new
  `User.BreachCheckPending`); its next sign-in rechecks the password,
  and a hit sets `MustChangePassword` and ends every session on the
  account, while a clean answer clears the mark. SSO accounts are never
  checked. Off by default: gauntlet makes no outbound call the
  application did not ask for. `BreachChecker` is the interface the
  option takes.
- `cmd/pwlist` and three CI jobs, run by a monthly pipeline schedule,
  build that list from HIBP, sign it on a dedicated runner, and publish
  it to the GitLab package registry and the GitHub mirror's releases.
  `scripts/update-blocklist.sh` copies the newest published list into
  a release. Setting this up -- a signing key, a GitHub token, two
  runners and the schedule -- is the owner's, in docs/releasing.md.
- The known-browser allowance (#44): a browser that completes a sign-in
  now gets a `gate_known_browser` cookie (`HttpOnly`, `SameSite=Lax`,
  `Secure` per `SecureCookie`, path `/api/auth`, 45 days), set at every
  session issue and replaced at each one (the path covers every route
  that issues a session, so one browser holds one entry however it
  signed in), and while the account is locked out, or the client's
  address is at its limit, that browser keeps an allowance of its own
  -- the limiter's attempts per window -- so a stranger who knows a username can no longer lock its owner out.
  It is refused once the account is disabled, and every failure through
  it counts toward the 50. The cookie's value is 32 random bytes; the
  account keeps only its SHA-256 (new `User.KnownBrowsers`,
  `KnownBrowser`), at most `MaxKnownBrowsers` (3) per account, the
  oldest evicted, each for `KnownBrowserLifetime` (45 days) from its
  latest sign-in there, checked on the server. Sign out everywhere and
  an admin's reset code forget every browser; a password change, an
  unlock and the forced change after second-factor failures do not.
  New API: `Store.RememberBrowser`, `Store.ClearKnownBrowsers`,
  `Store.KnowsBrowser`, `LoginLimiter.ReserveKnownBrowser` and
  `ReleaseKnownBrowser`. `Store.List` blanks each hash. An application
  with its own sign-in path should call `RememberBrowser` where it
  issues a session; gate does so in `issueSession`.
- `docs/api/auth.yaml` (OpenAPI 3.1) describes every route `gate.Routes`
  serves -- each request body, response body and status -- as the one
  copy a frontend can build against (ADR-0002, #22). `docs/design.md`
  §1.5 now points at it instead of listing the routes by hand.
- CI now checks for breaking changes (#22). A test calls every `gate`
  route and fails if a request, response or status code is not
  described in `docs/api/auth.yaml`, or if a route exists in only one
  of the two. A second job, `lint:apidiff`, fails if an exported Go
  identifier has been removed, renamed or changed since the last
  release tag, unless `VERSION` moves to a new major number (0.x to
  1.0) -- a minor bump such as 0.1 to 0.2 does not count. Additions
  pass. Neither tool enters the library's own dependencies. A field
  renamed in both the handler and `auth.yaml` still has to be caught in
  review.
- `TokenStore.Create` now refuses a token name longer than 64 bytes
  (`MaxTokenNameLen`), or one that contains control characters or
  invisible formatting characters (such as zero-width spaces),
  returning the new `ErrTokenNameInvalid` (#24). Code that passes
  user-typed names should handle this error. An empty name is still
  allowed. Device ids already followed this rule.
- Passkeys (G8, #20, [ADR-0004](docs/adr/0004-passkey-ceremony.md)).
  The new `gauntlet/passkey` package runs the WebAuthn ceremony:
  `passkey.New(passkey.Config{PublicURL, DisplayName})` builds the
  relying party from the application's own public URL, and a missing or
  unusable one (`unset`, `ip`, `insecure`) is a reported status, not a
  startup failure. Wire it into `gate.Deps.Passkeys` to serve
  mikroview's passkey routes from `gate.Routes`: list, register
  begin/finish (begin re-checks the password, as TOTP enrolment does,
  and refuses an account with no local password), rename, delete,
  `POST /api/auth/login/factor/begin`, an
  `assertion` on `POST /api/auth/login/factor`, and the admin
  `DELETE /api/auth/users/{id}/passkeys`. Left nil, every passkey route
  answers 404 and nothing links the WebAuthn library. Each login
  challenge is usable once, and a pending login (the cookie a password
  step sets when a second factor is needed) is spent by the sign-in
  that completes it, whichever factor completes it. A registration
  ceremony is spent by the first finish the library accepts, so one
  begin (one password entry) stores at most one passkey; a finish the
  library refuses (wrong origin, bad signature) can still be corrected
  inside its five minutes. Sealed cookies (the passkey ceremonies, the
  pending login, the SSO flow) open only in the exact base64 spelling
  they were written in. The root package
  gains the seam both sides use (`PasskeyCeremony`, `PasskeyAssertion`,
  `PasskeyStatus`, and `ErrPasskeyCeremonyInvalid`, which marks a dead
  ceremony: expired, tampered with, from the other ceremony or already
  used).
- `Store.AnyPasskeysExist()` reports whether any account holds a
  passkey (#20, owner's answer to question 5), so an application can
  refuse to start when passkeys exist but its relying party is not
  ready. gauntlet itself never refuses; the decision is the
  application's.
- `POST /api/auth/login` lists `passkey` (first) in `secondFactor`, with
  `passkeyOrigin`, when the account holds a usable passkey;
  `GET /api/auth/session` gains `passkeys: {count, status, origin}` when
  the application wires passkeys; `GET /api/auth/users` rows gain
  `passkeyCount`.
- New dependency for the `passkey` package (G8, #20; owner
  approval 2026-09-30): `github.com/go-webauthn/webauthn` v0.18.2
  (BSD-3-Clause), the newest release, with no advisory in OSV or the Go
  vulnerability database as of 2026-10-02. It brings
  `github.com/go-webauthn/x` and eight more modules (CBOR, TPM, JWT,
  msgp, mapstructure, uuid, float16, fwd). Only `gauntlet/passkey`
  imports it, so an application that never imports that package never
  compiles it in. Two of its packages carry other permissive licences,
  `go-webauthn/x/crypto/secp256k1` (ISC) and `go-webauthn/x/revoke`
  (BSD-2-Clause), so the licence policy now allows both (owner decision
  2026-10-02).
- Signed-in users can see and end their own sessions (#48; ASVS 7.5.2).
  `GET /api/auth/sessions` lists every live session on the caller's
  account, newest first: when it signed in, when it was last used, the
  address and browser it signed in from, and which one is this browser.
  It shows at most 100 rows and a `total` of all of them. Each row is
  named by a one-way `ref`, never the session ID, which is the cookie.
  `DELETE /api/auth/sessions/{ref}` ends one; ending this browser's own
  session clears its cookie. It asks for no password, for any account:
  signing out is a safe direction (owner decision 2026-10-02, recorded
  as a deviation from ASVS 7.5.2). It ends the gauntlet session only,
  not the sign-on provider's. Any ref that is not one of the caller's
  live sessions answers 404. There is no admin view of other people's
  sessions. The list lives in memory like the sessions themselves, so a
  restart empties it. In the core package, `Session` gains `Client` and
  `LastUsedAt` and a `Ref()` method, and `SessionStore` gains
  `CreateFrom`, `ListForUser` and `RevokeRef`; a browser's agent and
  address are kept cleaned and capped at `MaxSessionUserAgent` (256)
  and `MaxSessionAddress` (64) bytes. All additions; nothing existing
  changes.

### Changed

- The `user.login` audit record's detail now carries the client address
  (`from="<address>"`, after `via second factor; ` on the code and
  passkey step), where a one-step sign-in's was empty, and a completed
  SSO sign-in now writes `user.login` too (`via sso; from=...`), which
  it never did (#45). An audit consumer matching on the old detail
  needs updating.

- **Breaking.** `OpenStore` now refuses a backend that stores the
  accounts document in the clear -- one that does not implement
  `persist.AtRest`, which is every application database backend
  written so far -- with the new `ErrPlaintextAtRest`, unless
  `Options.AllowPlaintextAtRest` is set (#50,
  [ADR-0005](docs/adr/0005-encryption-at-rest-on-every-backend.md)).
  The document holds every account's TOTP secret, which cannot be
  hashed, so the choice is refuse or warn, and a warning is read once
  while a backup is copied for years. `persist.Memory`, `Encrypt` and
  `EncryptedFileBackend` need no permission; a nil backend stores
  nothing. `OpenTokenStore` is unchanged: the tokens document holds
  only hashes of random values. What each application must do:
  provision a key file of at least 32 random bytes (`persist.MinKeyBytes`;
  mikroview's retention key material already qualifies, birdcage has
  none yet and gains `BIRDCAGE_AUTH_KEY_FILE`), wrap the accounts
  backend -- and, recommended, the tokens backend -- in
  `persist.Encrypt` with a fixed `Label` per store, and for the release
  that first ships the wrapper set `MigratePlaintext: true` where a
  plaintext document already exists (mikroview's Postgres `auth` row);
  the first start seals it in place and the option can then be removed.
  A backend that wraps another (a write-behind queue) must forward
  `ProtectedAtRest`. Take a copy of the plaintext document before
  upgrading: an older gauntlet reads a sealed document as an empty
  store and its first write would overwrite it, while this build
  refuses a sealed document that reaches a store unwrapped. The
  envelope does not change the accounts document's own version (#44
  does, below): it sits below it.
- A second factor (TOTP or a passkey) is now always required for every
  local-password account; `gate` no longer offers a way to turn the
  forced-enrolment door off (#49). `gate.Config.RequireSecondFactor` is
  deprecated and ignored -- it stays only so applications that already
  set it still compile. An application that was relying on the door
  being off (the field's old default) now sees it on unconditionally:
  every local-password account, including ones created before this
  change, is stopped at the door until it enrols a factor, reaching
  only the enrolment routes until then. This closes the gap behind the
  8-character password minimum (`store.go:46`): NIST SP 800-63B-4
  §3.1.1.2 allows 8 characters only behind a mandatory second factor,
  and the minimum stays 8 rather than rising to 15 because the door can
  no longer be left off (#49, `docs/security-by-design.md`).
- **Breaking.** `gate.New` now refuses a `Deps.Sessions` store whose
  idle timeout exceeds the new `MaxSessionIdle` (1 hour), whose
  lifetime ceiling exceeds the new `MaxSessionLifetime` (24 hours), or
  which has no ceiling at all -- NIST SP 800-63B-4's AAL2 session
  limits (§2.2.3, §5.2), adopted by the owner on 2026-10-02 over the
  consumers' previous, longer values (#51). `SessionStore` itself is
  unchanged and still accepts any values; the new
  `(*SessionStore).Limits` method and the two exported constants are
  what `gate.New` checks them against. Mikroview and birdcage both
  pass 24 h idle / 7-day ceiling today and will fail at start-up until
  they change those values to within the new caps.
- The session cookie is hardened (#47; ASVS 3.3.1, 3.3.3, 7.2.4; NIST SP
  800-63B-4 §5.1.1). While `gate.Config.SecureCookie` is true the cookie
  is written and read as `__Host-` plus `CookieName`, which makes a
  browser refuse it unless it is `Secure`, has no `Domain` and is on
  path `/`; under plain HTTP the bare name is kept, since a browser
  drops a `__Host-` cookie that is not `Secure`. Its `Max-Age` is now the
  session store's lifetime ceiling (24 hours at most, #51) instead of a
  fixed 30 days, so the browser forgets it when the session can no
  longer be valid. `gate.New` logs one warning naming `SecureCookie`
  when it is left false, and refuses a `CookieName` that already starts
  with `__Host-` or `__Secure-`. A login -- password, second factor or
  SSO -- from a browser that still holds a live session for the same
  account now ends that session before issuing the new one; another
  account's session in the same browser is left alone. Not breaking for
  mikroview or birdcage: neither reads the session cookie by name
  outside the code `gate` replaces, and neither uses a prefixed name.
  What each app should expect: with TLS on, browsers signed in before
  the upgrade hold the old, unprefixed cookie and are simply asked to
  sign in again (an in-memory session dies with the restart anyway).
- Login lockouts now escalate, and too many failures in a row disable
  an account's sign-in (#44). Each lockout lasts three times the one
  before, from the attempt that starts it: 5, 15, 45, 135, 405 and 1215
  minutes at 5 attempts per 5 minutes, then 24 hours each. The first
  lockout now runs a full window from its last attempt, not until the
  oldest attempt in the window ages out. 50 failures in a row
  (`MaxConsecutiveLoginFailures`), password and second-factor steps
  together, disable the account's local sign-in: the right password is
  then refused exactly as during a lockout, with no end, until
  it is unlocked (see the unlock route and code under Added). Only a
  completed sign-in or a new password resets the count, not a correct
  password alone and not a lockout running out. A password the owner
  sets does not lift a disable; a reset code an admin issues
  (`IssueResetCode`) does. Applications that issue a session
  themselves after `ReserveAccount` should call the new
  `LoginLimiter.SignedIn` in place of `ReleaseAccount` when the sign-in
  completes; `gate` does. Five failed second-factor steps in a row --
  wrong codes or refused passkeys, which only someone with the password
  can make -- now set `MustChangePassword`, so the owner must change the
  password at their next sign-in (`LoginLimiter.SecondFactorFailed`),
  and the same save signs the account out everywhere, so only a fresh
  sign-in with both factors reaches the change-password door. That
  door's message no longer says an administrator reset the account.
  That run is kept in memory and starts again after a restart. Still
  one save as a lockout starts and one as it clears, never one per
  guess.
- The accounts document is now version 5: version 3 (#44) added
  `loginLockoutCount` and `loginDisabledAt`, version 4 (#44)
  `knownBrowsers`, and version 5 (#43) `breachCheckPending`.
  Version-1 to -4 documents open unchanged with the fields they lack
  empty, and are written as version 5 on their next save; no migration
  is needed. No earlier build -- v0.1.0, or a development build that
  wrote version 3 or 4 -- can open an accounts document once this
  version has saved it, so keep a copy before upgrading if a rollback
  is possible.
- A pending login -- the cookie `POST /api/auth/login` sets when a
  second factor is needed -- now completes exactly one sign-in (#20,
  ruling R2). Before, the same cookie could be sent again within its
  five minutes with another valid code, recovery code or passkey
  assertion, and each one opened a session. A repeat now gets 401
  "sign in again" at `login/factor` and `login/factor/begin`; a wrong
  code still leaves the pending login usable. A spent pending login
  (and a spent passkey challenge) is remembered for one lifetime past
  the moment it stops being accepted, so two requests reading the clock
  either side of that moment cannot reopen it. A pending-login cookie
  sealed by an earlier version is refused once, and the user signs in
  again.
- The first admin is created only with a one-time setup code the server
  announces when it starts with no accounts (#37, ADR-0003; owner,
  2026-10-01). An empty store is not only a fresh install -- a deleted
  accounts file, a wrong path or a bad restore all start a server with
  none -- and until now the first visitor took admin. The store makes an
  80-bit code, keeps only its hash in memory, and hands it to the new
  `Options.OnSetupCode` or, when that is nil, writes it as one `Warn`
  line on `Options.Log`; `POST /api/auth/register` now needs it as
  `setupCode` (`401` when wrong, counted against the address by the
  login limiter, `429` at the limit) and checks it before hashing the
  password. It is used up once any account exists and dies with the
  process: a lost code means restart and read the log. SSO can no
  longer create the first account: the two `/api/auth/oidc/*` routes
  answer `503` "setup required" like everything else until the first
  admin exists, and `FindOrCreateOIDCUser` refuses on an empty store
  with the new `ErrSetupRequired`. The first admin is local and links
  SSO afterwards. New: `Store.CheckSetupCode`, `ErrSetupCodeInvalid`,
  `SetupCodeHandler` and its `SetupCodeFunc` adapter;
  `Store.Register` is unchanged and is the host-side primitive gate
  calls after the check. A frontend's first-run screen collects the
  code and hides the SSO button while `setupRequired` is true.
- Both stored documents now carry a top-level `version`, and the tokens
  document is an object, `{"version": 1, "tokens": [...]}`, instead of
  a bare list (#29, ADR-0002 decision 1). Documents written by v0.1.0
  open unchanged, as version 1, and are written in the new shape on
  their next save; v0.1.0 cannot open a tokens document once this
  version has saved it, so keep a copy before upgrading if a rollback
  is possible. A document with a version newer than the running build
  reads is refused at startup with an error naming both versions, is
  not applied (and is logged once) when it appears under a running
  server, and is never saved over by a write -- so a rolled-back build
  cannot load it and silently drop what only the newer build knows,
  such as TOTP secrets or passkeys. There is no migration code yet; it
  is added with the first format change that needs one.
- The accounts document is now version 2: it adds `sessionsEndedAt`
  (#28), and any change to what a stored document carries now raises
  its version (ADR-0002 decision 1). Version-1 documents, from v0.2.0
  or mikroview, open unchanged with the new field empty and are written
  as version 2 on their next save; no migration is needed. v0.2.0
  cannot open an accounts document once this version has saved it, so
  keep a copy before upgrading if a rollback is possible. The tokens
  document stays version 1.
- If the CLI and the running server save at the same moment, both
  changes are now kept (#21). Before, the second save to land wrote its
  whole accounts or tokens document on top of the first, and the first
  change was gone with only a log line to say so. Now the second write
  loads what the first saved, makes its own change again on top of
  that, and saves the result, so both changes survive. This covers both
  the accounts store and the token store, which had no such protection
  before.
- A token revoked with the CLI now stops working on the running server
  at once. Before, it kept working until the server restarted.
  `TokenStore` now re-reads its document before every read, write and
  `Authenticate` when another process has changed it, as `Store`
  already did.
- If an account is deleted, or a token revoked, by another process
  while a login or token use is in progress, that login or token use is
  now refused. Before, it could succeed using the old copy held in
  memory.
- A save conflicts when another process saved the same file after this
  one loaded it. After five conflicts in a row for the same write -- a
  script writing in a loop, not an ordinary CLI command -- the write
  gives up with the new `ErrSaveConflict` and changes nothing; the
  caller can try again. The whole write, retries and reloads included,
  is held to one five-second limit (the limit one save had before),
  since it runs while every login and signed-in request on that store
  waits. The shipped file backends cannot be interrupted mid-call, so
  on a hung mount the limit only stops another retry from starting, not
  a call already in progress.
- When a save is retried, its rules are checked again against the newer
  file: registration still open, only one admin, username not taken,
  recovery codes not already issued. A retry can never break them. A
  write that finds nothing to change -- revoking a token already gone,
  say -- now re-checks that decision against the saved document too, so
  it cannot miss a token another process just issued; such a call can
  now return an error if that re-check fails, where before it always
  returned nil.
- A write that meets an accounts document this store refuses to load
  (two admins, say) now fails instead of saving over it. One that finds
  the document removed from under it -- a file deleted or moved aside
  while the process ran -- fails with the new `ErrDocumentRemoved`
  instead of recreating the file from that one write, which for an
  accounts file could mean a file with no admin that the next start
  refuses. The single-admin rule is checked on every save as well as
  every load, so no write can produce such a file. The first such
  failure after each removal logs one error naming the store and file
  and saying writes are refused until the file is restored or the
  process restarts; reads carry on from memory (#39). To recover,
  put the file back, or restart to start afresh.
- `VerifyAndRecordTOTP` and `RecordPasskeyAssertionIfFresh` now accept a
  code or passkey only if they could save the record that stops it
  being used twice. Before, a correct TOTP code was accepted even when
  that save failed, so the same code could log in a second time. Now
  the call returns `ok == false` and the error, as reset codes and
  recovery codes already did. Callers that allowed a login when `ok`
  was true but an error was also returned should remove that path: that
  combination no longer occurs. The one exception is a passkey that has
  never counted and presents 0 (most platform passkeys): that save
  protects nothing, since the app's single-use challenge is what stops
  a replay, so it is best-effort like `LastLogin` -- if it fails, the
  login is accepted, the last-used time is kept in memory and the
  failure is logged (#36). The app must claim that challenge before
  calling.
- `RecordPasskeyAssertionIfFresh` refuses a passkey whose stored count
  is above zero and that now presents 0, as the WebAuthn spec treats
  it: a possible cloned authenticator (#36). Before, any count of 0 was
  accepted.
- Persistence errors from store writes no longer carry the
  `saving accounts:` / `saving API tokens:` prefix; they name the store
  and backend themselves, and `errors.Is` against the package's errors
  works as before.
- `persist.SaveWithRetry` is deprecated and no longer used by the
  stores; it stays exported for compatibility.
- Smaller fixes from the v0.1.0 audit (#24):
  - `User.HasActiveTOTP` and `HasSecondFactor` now answer correctly on
    the copies `Store.List` returns: `HasActiveTOTP` read false for
    every listed account, and `HasSecondFactor` read false for a
    passkey-only account even though `Get` said true.
  - A password login saves `LastLogin`, and a token use saves its
    last-used time, at most once an hour each, compared against the
    saved value, as `LastLogin` already was -- a token used more often
    than hourly had been saving its last use once and then looking
    idle. The value in memory is always current; a crash can lose up to
    an hour of it.
  - `TokenStore.List`, `ByKind` and the saved document order tokens
    created in the same instant by ID, so the list no longer reshuffles
    on refresh.
  - `OpenStore`'s "no admin" refusal counts empty (null) entries
    separately from real accounts in its message.
  - A generated SSO username always fits the username length limit.
  - Less password hashing under the accounts store's lock: a new SSO
    account, burning a recovery code and `GenerateRecoveryCodesIfAbsent`
    no longer stall other logins while they hash, and
    `GenerateRecoveryCodesIfAbsent` skips the hashing entirely when the
    account already has codes. `BurnRecoveryCode` no longer changes a
    copy another caller is reading.
  - Removing expired sessions no longer pauses every login and session
    check while the whole session store is scanned in one go; each
    login now removes up to 4 expired sessions instead. On a quiet
    server, expired sessions may therefore stay in memory longer, but
    they still never authenticate. Signing out everywhere, and other
    per-user session revokes, no longer walk every session either: the
    store now keeps each user's session IDs alongside the sessions and
    revokes from that list.
  - A login lockout that could not be saved is saved again by a later
    refused attempt on that account (at most every 30 seconds), so a
    backend that recovers inside the lockout ends up holding it and a
    restart no longer lets more guesses through. Clearing a lockout
    whose save failed is retried the same way, every 30 seconds, while
    the stored lockout is still in the future, so a correct password is
    not kept out once storage recovers -- within one process; a restart
    inside that window still waits out the lockout. A stored lockout
    ending more than one window away no longer tries a save on every
    refused guess, only once per 30 seconds.
  - Setting a new password (`SetPassword`) or issuing a reset code
    (`IssueResetCode`) ends any login lockout on the account, so its
    owner can sign in with the new password or the code at once. The
    limiter stops counting guesses made before the change. Linking the
    admin to SSO, whose password keeps working, leaves its lockout in
    place.
  - Internal tidying in `gate`, plus test and documentation fixes. HTTP
    requests and responses are unchanged.
- A failed password change, and a failed SSO login or link, are now
  logged, as the API document already said (#26).

### Fixed

- Fixes from the v0.2.0 release audit (#57):
  - An admin unlock that fails to save now keeps the account disabled in
    this process, so guessing cannot resume while the admin is told the
    unlock failed.
  - A stored accounts, tokens or sign-in history document that is the
    JSON literal `null` is refused as corrupt instead of opening as a
    fresh install, which would have let the next registration overwrite
    every account.
  - An accounts document holding two usernames that differ only in case
    is refused at load, with the reason, instead of silently locking the
    earlier account out.
  - An admin password reset now also drops a disable the login limiter
    decided but had not yet saved, so the owner's first attempt with the
    reset code is admitted and the stale disable is not written back.
  - `POST /api/auth/passkeys/register/finish` validates the body before
    reading the ceremony cookie, as the API document says: a bad body is
    400 and leaves the cookie in place.
  - Every failed SSO login or link callback outcome is logged with its
    `ssoError` code and the client address, not only a refused identity
    and a failed link.
  - The admin sign-out `reason` limit is 200 characters, as the API
    schema says, not 200 bytes.
  - A Pwned Passwords range answer of 200 with an empty body is an error,
    so the password is checked again later instead of being reported
    clean.
  - The stored password list is kept when the clock is behind at start;
    only a freshly downloaded list is checked for a build time in the
    future.
  - The stored password list and its signature are written as one file
    (`top10k.signed`) in a single rename, so a crash mid-write can no
    longer discard the good list; the old two-file layout is still read.
  - `pwlist publish-github` verifies the list's signature before
    uploading (new `--keys` flag, default `blocklist/keys`), and, when
    GitHub reports no digest for an existing file, compares content
    rather than size.
  - `pwlist build` discards a checkpoint saved in the future instead of
    resuming from a stale snapshot.
  - `scripts/update-blocklist.sh` refuses a list older than the embedded
    one unless `--force` is given.
  - CI base images are pinned by digest, as the release job's already
    was, so the jobs that hold the signing key and the GitHub token run
    exactly the image that was reviewed.
  - The API document no longer says SSO can create the first account;
    the first account has always come from the local setup code.
  - Passkey names are quoted in the `account.passkey_added` and
    `account.passkey_removed` audit details (`name="..."`), so a name
    holding a newline or an escape code cannot forge audit lines. Readers
    that parsed the bare `name=` form must expect the quotes.
  - Five second-factor failures in a row force a password change on an
    account whose record carries a lockout and an older-style
    password-change date too; before, the run of failures reset on every
    attempt for such an account.

- `POST /api/tokens` with a name the token store refuses answers 400
  with the reason, instead of 500 "unable to create token" (#25).
- `POST /api/auth/users` answers 503 with the same "no persistent
  storage" message as register when the deployment has no storage set
  up, instead of 500 (#25).
- `DELETE /api/tokens/{id}` answers 500 and logs the error when the
  revoke cannot be saved, instead of 404 "already revoked" while the
  token kept working; 404 is now only for a token that does not exist
  (#26).
- `POST /api/tokens` refuses a name made only of spaces with 400, like
  an empty one (#26).
- `POST /api/auth/login/factor` answers 500 and logs the error,
  without counting the attempt toward the login lockout, when a
  correct authenticator code or recovery code cannot be recorded as
  used; `POST /api/auth/login` does the same for a reset code. Before,
  both answered 401 and counted toward the lockout (#26).
- `POST /api/auth/totp/confirm` answers 409, as the API document
  already said, when no enrolment is pending, instead of 400; and when
  the authenticator is confirmed but recovery codes could not be
  generated, its 500 body is JSON `{"error": ..., "totpActive": true}`
  so a frontend can tell the factor is on (#26).
- `docs/api/auth.yaml` now says a token's kind is whatever the
  application registered (`api` and `ingest` by default), not only
  `api` or `ingest` (#26).
- An account locked out by wrong passwords and then reset -- from the
  command line (`SetPassword`) or with a reset code -- can sign in from
  the address the wrong guesses came from straight away. Before, the
  lockout ended but the per-address limit still answered 429 for up to
  five minutes, which read as the reset having failed (#32). Only that
  account gets past the address limit, only when both the address and
  the account itself reached their limits before the reset, one attempt
  at a time, and only until its sign-in finishes or a guess fails. For
  an account with a second factor the right password spends the pass
  and the code step that follows is let through on the same sign-in, so
  a guess sent in between cannot take it. Other accounts tried
  from that address are still refused, and so is an account that was
  never locked out and only changed its own password. New
  `LoginLimiter.AllowAfterReset`, `ReleaseAfterReset` and
  `EndAfterReset` carry this.
- The token-name and device-id errors say the limit is 64 bytes (fewer
  characters for non-Latin letters), not 64 characters, so a name
  refused for length no longer seems to meet the limit it names (#28).
- `Store.AddPasskey` copies the passkey it is given and the one it
  returns, so a caller reusing either buffer cannot change the stored
  credential (#28).
- A returning SSO sign-in saves `LastLogin` at most hourly, as a
  password login does, instead of rewriting the accounts document on
  every sign-in; `GET /api/auth/users` no longer re-reads each account
  to learn whether it has an authenticator app (#28). Its passkey
  count still takes one store read per account.
- The release job's `release-cli` image is pinned by tag and digest
  instead of `:latest` (#28).
- A request whose `Authorization` header is not a well-formed
  `Bearer <token>` -- another scheme such as `Basic`, a bare `Bearer`,
  a tab for the space -- is refused with 401 and
  `WWW-Authenticate: Bearer realm="gate"`, as an unknown token is.
  Before, the header was ignored and the request went through on its
  session cookie. A request with no `Authorization` header is
  unchanged (#41).
- Linking the admin to SSO no longer ends a login lockout whose save
  had failed (#28). The link used to record itself in
  `PasswordChangedAt`, which the login limiter reads as a password
  change. A new stored field, `User.SessionsEndedAt`, now records when
  an account's sessions were ended -- by a new password, a reset code or
  an SSO link -- and `PasswordChangedAt` moves only when the password
  does. `User.SessionCutoff()` returns the later of the two, and the
  gate refuses a session issued before it. Documents written before this
  field existed, by gauntlet or mikroview, record a link in
  `passwordChangedAt` only, and those sessions stay ended.

## [0.1.0] - 2026-09-30

First release: the shared login library for birdcage and mikroview --
local accounts and roles, sessions, API tokens, TOTP with recovery and
reset codes, passkey storage, OIDC with a self-hosted-only policy, the
HTTP middleware in `gate/`, and the encrypted file backend in `persist/`
(G1-G6 of docs/design.md §5). Audited before release (#16); the GitHub
mirror `github.com/tomlawesome/gauntlet` carries the tag (#17).

### Added

- Repository skeleton: licence, agent and contributor docs, the design
  document and its ADR, and CI (build/vet/test with coverage floors,
  golangci-lint, gitleaks, govulncheck, licence check).
- `persist` package: the `Backend`/`VersionReader` storage interface and
  a `Memory` backend for tests, copied from mikroview's
  `internal/persist`.
- `oidc` package: the OIDC/SSO relying-party layer -- provider discovery,
  Authorization Code + PKCE, ID token verification, the self-hosted-only
  `AllowIssuer`/`IsMultiTenantIssuer` policy and the sealed `FlowState`
  cookie codec -- moved unchanged from mikroview's `internal/oidc`.
  Depends on `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2`
  (owner-approved, AGENTS.md). `internal/testutil` carries the fake OIDC
  provider used by its tests, and by `gate`'s once that package exists.
- Sessions, API tokens and the login limiter, copied from mikroview's
  `internal/auth/{session,token,ratelimit}.go` with names kept.
  `SessionStore` has one constructor, `NewSessionStore(ttl,
  maxLifetime)`, replacing mikroview's two; sessions stay in-memory only
  (docs/design.md §1.7). `TokenStore`'s `TokenOptions.Kinds` replaces
  mikroview's hard-coded `TokenKind.Valid()`: a token whose kind is not
  registered is kept in its document and logged, but never
  authenticates, so a caller-specific kind (mikroview's `droplist-pull`)
  can be registered without a change here. `internal/evict` (`Batch`,
  `Target`, `DownTo`) bounds `LoginLimiter`'s tracked-key map, copied
  from mikroview's `internal/evict`.
- Second-factor data and stdlib flows (issue #5): TOTP enrolment and
  sign-in (`SetPendingTOTPSecret`, `ConfirmTOTP`, `VerifyAndRecordTOTP`,
  `ClearTOTP`, RFC 6238/4226 on stdlib `crypto/hmac`+`crypto/sha1` only);
  recovery codes (`GenerateRecoveryCodes`, `GenerateRecoveryCodesIfAbsent`,
  `BurnRecoveryCode`, Argon2id-hashed, single use); the admin-issued
  password reset code (`IssueResetCode`, Argon2id-hashed, 24-hour,
  single use -- `Store.Authenticate` already redeemed a live one from
  G2 onward); passkey storage methods with no WebAuthn dependency
  (`AddPasskey`, `RenamePasskey`, `DeletePasskey`,
  `RecordPasskeyAssertionIfFresh`, `ClearPasskeys`,
  `ClearAllSecondFactors`, `PasskeyCount`). Every mutating method rolls
  back its in-memory change on a backend write failure.
- Runnable examples (`example_test.go`, `persist/example_test.go`) and a
  README "Using gauntlet" section for apps adopting the module.
- `gate` package (issue #7): `Config`, `Deps`, `New`, `Gate`, `Protect`,
  `Handle`, `Exempt`, `Routes`, `UserFromContext`, `TokenFromContext`,
  `RequireRole` and the `Auditor` interface -- mikroview's
  `internal/api/{auth,tokens,oidc}.go` turned into configuration
  (docs/design.md §1.5). `Routes` serves the full mikroview route table:
  session/register/login/logout/logout-all/password, the two-step
  second-factor login (`POST /api/auth/login/factor`, sealed
  pending-login cookie, TOTP code or a recovery code), TOTP enrol/
  confirm/delete plus the admin clear route, recovery-codes regenerate,
  the admin reset-password route, the OIDC login/callback/link trio
  (404 when `Deps.OIDC` is nil), and the users/tokens admin endpoints.
  `Config.ProductName` is required (used in the TOTP enrolment URI,
  fails closed in `New` if empty); `Config.LoginPath` is where a failed
  OIDC callback redirects with `?ssoError=`. Passkey/WebAuthn routes are
  deferred to G8. Includes mikroview's own fix for a MustChangePassword/
  second-factor door deadlock and its machine-readable auth-gate header
  (gitlab/dev 683704c4), generalized to a non-mikroview-branded name.

- `persist.EncryptedFileBackend` (issue #18): AES-256-GCM with
  HKDF-SHA256, a fresh random salt and nonce per save, and the store's
  path as AAD, moved from mikroview's `internal/persist.EncryptedFileBackend`
  so a hand-edited or tampered accounts file fails to open in both apps.
  `NewEncryptedFileBackend(path, key)` takes raw key bytes (refusing one
  shorter than `MinKeyBytes`, 32, mikroview's own floor) rather than a
  key-file path or mikroview's `*retention.Key` -- reading the key file
  stays the application's job. The on-disk envelope and HKDF info string
  are unchanged from mikroview's, so an existing mikroview-written file
  loads here byte-for-byte; proved with a fixture written by mikroview's
  own code (`persist/testdata/mikroview-encrypted-fixture-v1.bin`,
  generated at mikroview gitlab/dev commit
  bb29f23eb5e9918fdd888a6d34640eb5b228a129). The plain single-file
  mechanics it wraps are an unexported `fileBackend`: gauntlet has no
  unencrypted file mode. Now the documented default for file-backed
  storage (docs/design.md §1.7, docs/security-by-design.md).

### Changed

- `gate` hardening beyond mikroview's own behaviour (issue #15): a
  failed token revocation on user delete now answers 500 with a JSON
  error body naming the account, instead of mikroview's 200 with
  `tokensRevoked=0` -- indistinguishable on the wire from "this user
  held no tokens" -- and the failure is recorded in the audit detail
  too. `decodeJSONBody` rejects a request body carrying an unrecognized
  field or data left over after the JSON value (`DisallowUnknownFields`
  plus a trailing-data check), 400 either way; mikroview accepts both
  silently. `ErrSingleAdmin` and `ErrCannotDeleteAdmin` get their own
  message in `gateErrorMessages` (400/409 respectively) instead of
  falling through to the generic "unable to complete the request" --
  mikroview's matching map has neither entry either. See
  `gate/users_handler.go` and `gate/httpjson.go`'s header comments.
- `oidc.New` now refuses a multi-tenant issuer itself (the same check
  `oidc.AllowIssuer` runs), instead of relying solely on a caller's own
  startup check.
- `NewLoginLimiter` now returns an error (`ErrLimiterConfig`) for a
  threshold under one or a non-positive window, instead of building a
  limiter that refuses every login from the start.

### Security

- `POST /api/auth/totp/enrol` now takes `{"password": ...}` and
  re-checks it on the same per-account bucket as `totp/delete`: a
  session alone -- what a stolen cookie gives an attacker -- could
  previously plant an authenticator secret and take the only copy of
  the recovery codes, locking the real owner out at their next login.
  Mikroview's enrol screen must send the password when it moves onto
  gauntlet (#1202); its delete screen already does.
- `oidc.VerifyIDToken` refuses an ID token with an empty `sub`
  (`ErrNoSubject`): go-oidc does not insist on it, and every user of a
  provider that omitted it would have resolved to the one account keyed
  on `(issuer, "")`.
- `oidc.IsMultiTenantIssuer` recognises a listed public provider written
  with a trailing root dot (`https://accounts.google.com./`), which DNS
  and TLS treat as the same host; before, that spelling passed the
  startup refusal.
- CI: protected refs get their own dependency and build cache
  (`cache:key:prefix: $CI_COMMIT_REF_PROTECTED`), so a merge-request
  pipeline can no longer seed the cache a `dev` pipeline -- which
  carries the protected mirror key in its environment -- builds its
  tools from.
- `LoginLimiter` keeps a real account's counter apart from the capped
  map of addresses and unknown names (#19): keyed by account ID, never
  evicted, so no flood of made-up names can reset it; and a login
  lockout is saved on the account (`User.LoginLockedUntil`) as it begins
  and clears, so a restart does not lift it. New `ReserveAccount`/
  `ReleaseAccount`, `ReserveRecheck`/`ReleaseRecheck`, `SetLog` and the
  `AccountLockouts` interface, which `*Store` implements; `gate` uses
  them. The capped map drops every expired key before evicting a live
  one.
- `OpenStore` refuses an accounts document with more than one admin, or
  with accounts but none of them admin, as it refuses one that will not
  parse; a reload that finds either is ignored and logged.

- `VerifyPassword` now refuses, before hashing, a stored hash whose
  cost settings or lengths are outside what this module writes (with
  4x headroom). A corrupt or tampered hash could previously crash the
  check and leave a hashing slot taken, so enough of them stalled every
  later login, or force an unbounded Argon2id computation.
- `ReserveAccount` now honours a persisted lockout ending more than one
  window past the attempt that would have set it for one window from
  now, rather than wiping it outright -- it previously let a still-valid
  lockout through the moment the login window was shortened across a
  restart.
- The file backend's `Save` now holds an exclusive lock on a sidecar
  `.lock` file for its whole read-compare-write, so a CLI tool and a
  running server saving against the same version can no longer both pass
  the check and both "succeed", with the later one silently discarding
  the earlier write.
