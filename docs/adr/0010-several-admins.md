# ADR-0010: Several admins; the last is protected

**Status:** Accepted (owner decisions 2026-10-04 on #67 and #75);
decision 3 amended by ADR-0013; decisions 2 and 5 amended by ADR-0015
**Date:** 2026-10-05
**Relates to:** #67 (this change), #75 (role change between user and
viewer, folded in), #44 (the unlock code, now the lone operator's
fallback), #55 and ADR-0009 (a blocked admin), #66 (the log-written
escape), #73 (the account-event hook it is told through), ADR-0003
(the first admin), ADR-0002 (compatibility)

## Context

Gauntlet held exactly one admin account, enforced in the store:
`CreateUser` refused `RoleAdmin`, a document with two admins would not
load, and `TransferAdmin` (console only, no HTTP route) moved the role.
The rule came with mikroview's code and was never decided here
(design.md called it "not reopened"). It turns ordinary life -- a
holiday, a lost phone, a new laptop abroad, fifty bad guesses by a
stranger -- into a recovery event that needs host access and a code from
the log. Every system the #67 research surveyed (Entra, Google
Workspace, AWS, Okta, GitLab, Grafana, Home Assistant, Bitwarden, and
others) allows several admins, and those that advise say to keep at
least two: a locked-out admin is fixed by a peer. The ones that guard
the last admin refuse to delete or demote it; none caps the count.

## Decision

The standard pattern is **last-owner protection with step-up
re-authentication for privilege grants** (the "at least one owner" rule
every system above applies; GitHub's sudo mode and ASVS 5.0 7.5.3 for
the step-up).

1. **Several admins; the last one is protected.** Any number of
   accounts may hold `admin`. The last admin can be neither deleted
   (`ErrCannotDeleteAdmin`, which is also `ErrLastAdmin`) nor demoted
   (`ErrLastAdmin`); over HTTP both are 409 with the `last-admin` error
   class. The check runs inside the same locked write as the change
   (`Store.mutate`), so two admins demoting each other at once cannot
   leave none (the check-then-act race `TransferAdmin`'s comment names).
   An admin may demote themselves while another admin remains. Nobody can
   delete the account they are signed in with.
2. **Granting admin needs step-up.** `POST /api/auth/users` with
   `role: admin`, and `PUT /api/auth/users/{id}/role` with
   `role: admin`, take the granting admin's password and a current
   second factor (a TOTP or recovery code) on the same request: the
   `UnlockSelfRequest` / `recheckUnlockSelf` shape, on the account's
   re-check budget (`ReserveRecheck`). A stolen session cookie alone
   cannot make its holder permanent. Every other role change needs
   none.
3. **One route for every role change (#75).** `PUT
   /api/auth/users/{id}/role` moves an account among `admin`, `user` and
   `viewer`, in either direction. Two levels stay: `admin` includes
   `user` includes `viewer`; there are no finer admin roles. An app that
   wants "can manage tokens but not people" composes `RequireRole` over
   its own routes.
4. **A downgrade ends the account's sessions.** The store records
   `SessionsEndedAt` in the same write (OWASP session management: renew
   the session after a privilege change), and the handler drops the
   sessions held in memory. A grant ends nothing. Every change writes
   `User.RoleChangedAt`.
5. **Every admin keeps a local password and second factor on an SSO
   link.** Mikroview #1252's rule, extended from "the admin" to each of
   several. `HasLocalAdmin` is true when any admin has a local password.
6. **Audit and notice.** `user.role_changed` records actor, from and to;
   `user.create` already names the role. `Config.Notices` is told with
   `NoticeRoleChanged` and a `RoleChangeDetail{From, To}` -- a grant, a
   downgrade, and an admin created over HTTP (From empty) alike.
7. **Compatibility (ADR-0002).** `ErrSingleAdmin` stays exported and is
   never returned; `ErrCannotDeleteAdmin` stays the value `DeleteUser`
   returns (a comparable value that also answers `errors.Is(err,
   ErrLastAdmin)`), so `err == ErrCannotDeleteAdmin` keeps working;
   `Admin()` stays and now returns the first admin by username; new
   `Admins()` and `SetRole`; `TransferAdmin` stays for the console while there is one admin and
   refuses with several (`ErrSeveralAdmins`: there is no one account to
   hand over from, and picking one would demote an admin nobody named). The
   accounts document is version 9: no field changed, but a build that
   reads up to version 8 refuses a two-admin document with a message
   about "exactly one", and ADR-0002's rule is that a document an older
   build cannot read correctly gets a new version. A version-8 document
   loads as is.
8. **Loading.** A document with several admins loads. Accounts but no
   admin is still refused at startup: nothing could create one.
9. **Recovery.** With another admin, recovery is that admin, through the
   routes that exist (unlock, reset code, clear factors, sign out
   everywhere). With no other admin able to act, the log codes stay: the
   setup code (empty store), the unlock code (every admin disabled) and
   #66's escape. They are the lone operator's fallback, not the design;
   the documentation says "add a second admin" first.

## Rejected options

- **Keep one admin and build #66 alone.** Rejected: it keeps every
  holiday and lost phone a host-access event, and every surveyed
  system advises the opposite.
- **Console-only role changes, as mikroview does.** Rejected by the
  owner: it makes a second admin unreachable for an operator who never
  opens a shell. The step-up is the control that rule was standing in
  for.
- **Finer admin roles, or a break-glass account type.** Rejected: the
  apps have one or two operators; an Okta-style role set is unused
  attack surface, and a second admin whose sign-in is audited and
  noticed is Entra's emergency account without a new concept.
- **Only the last local-password admin keeps its password on an SSO
  link.** Rejected: one rule with no ordering is simpler and
  `HasLocalAdmin` then means what it says.
- **A separate "promote" and "demote" pair of routes.** Rejected: one
  route taking the target role has one rule for the last-admin check and
  one for the step-up.

## Consequences

- An application can offer admin management over HTTP with no console
  step. Birdcage's and mikroview's own wiring (the CLI's `set-role`,
  mikroview's "exactly one admin" sentences) are for those projects to
  do when they move onto this version.
- The accounts document is version 9; an older build refuses it.
- `Config.Notices` gains `NoticeRoleChanged`; an application that
  switches on `NoticeKind` should handle it or ignore it.
- A deployment with a lone admin still has the log codes, and ADR-0009's
  lone-admin-under-`block` risk is unchanged for it; with two admins
  that risk is a second admin's reset code away.
- The `/api/auth/users` routes still need only the session for
  everything but a grant, as before; ASVS 7.5.3 is met for role grants
  only, not for reset codes, token creation and the other admin routes.
- Every admin keeps a local password (owner decision on #79,
  2026-10-06): an SSO-only account promoted to admin may set one through
  `POST /api/auth/password`; until it does, every step-up route answers
  409 telling it to; and the last admin holding a local password can be
  neither demoted nor deleted (`ErrLastLocalAdmin`, 409 `last-admin`).
- Status note (v0.3.0 audit, 2026-10-08): decision 2's step-up is no longer named
  `recheckUnlockSelf`: it is the shared `recheckStepUp` in `gate`, used
  by user creation, the role route and the admin unlock route, on the
  same re-check budget.
- Status note (v0.3.0 audit, 2026-10-08): decision 3 has one more refusal:
  [ADR-0013](0013-sso-group-roles.md) (#76) answers 409
  `role-managed-by-sso` to a change to `user` or `viewer` on a non-admin
  SSO account when a groups map is configured.
- Status note (#82, 2026-10-08): decision 2's step-up also accepts a
  passkey in place of the code
  ([ADR-0015](0015-every-admin-holds-a-passkey.md) decision 6): the
  password and an assertion from `POST /api/auth/step-up/passkey/begin`,
  on the same re-check budget, so a passkey-only admin no longer spends
  a recovery code per grant. While the application requires admin
  passkeys, a grant to an account with none usable is still made, and
  the account is held at the passkey door until it registers one.
- Status note (#82, 2026-10-08): decision 5's local password is now
  enforced at the door for an admin while the application requires admin
  passkeys (ADR-0015 decision 5): an SSO-only admin is held at the
  `must-change-password` door until it sets one, then at the passkey
  door.
- Status note (v0.4.0 audit, 2026-10-10): the accounts document is version
  10 since #81; version 9 is what #67 introduced (decision 7, and the
  consequence "The accounts document is version 9").
- Status note (v0.4.0 audit, 2026-10-10): `recheckStepUp` also serves the
  caller's own allow-sign-in (#81). ("No longer named" in the note above is
  loose: `recheckUnlockSelf` still exists, as a wrapper around
  `recheckStepUp` for the unlock route.)
- Status note (v0.4.0 audit, 2026-10-10): the consequence that only role
  grants are re-checked is superseded: since #72 reset-password, delete
  user, clearing a user's factors and token creation, and since #81
  allowing another account's next sign-in, re-check the caller's password
  (`recheckAdminPassword`); role grants and admin creation take password
  plus second factor.
