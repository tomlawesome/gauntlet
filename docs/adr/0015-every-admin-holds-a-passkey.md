# ADR-0015: Every admin holds a passkey, where the application says so

**Status:** Accepted (owner rule 2026-10-06; owner answers 2026-10-08 on #82)
**Date:** 2026-10-08
**Relates to:** #82 (this change), #79 (the release-audit decisions it
builds on), ADR-0004 (the passkey ceremony; decisions 3 and 4 amended),
ADR-0010 (several admins; decisions 2 and 5 amended), ADR-0011 (the
escape code, unchanged), ADR-0012 (a passkey signing in on its own),
ADR-0002 (compatibility)

## Context

An admin account can create admins, end anyone's sessions, reset
passwords and mint API tokens. Since #49 every local-password account
must hold a second factor, but any factor will do, and an
authenticator-app code typed into a look-alike page can be passed on to
the real site while it is still valid. A passkey cannot: the browser
binds it to the site's real address (the relying-party ID), so a
phishing page gets nothing it can use.

The owner's rule (2026-10-06): an admin account holds at least one
registered passkey; an authenticator app may be held as well, never
instead. The owner answered the open questions on 2026-10-08, recorded
below.

What the code already had: the root package knows how many passkeys an
account holds (`User.PasskeyCount`, `Store.PasskeyCount`) without
importing WebAuthn, but only `gate` knows which of them are usable --
registered under the relying party's current RP ID
(`usablePasskeyCount`); one from an earlier public URL is stale. `Protect`
already holds every local-password account with no second factor at a
door that still admits the enrolment routes, and re-reads the account on
every request, so a promotion or a removed passkey is seen at the next
request. An SSO-only admin can set its first local password from a fresh
single sign-on (#79). A login ceremony can already run against a known
account (`BeginLogin`/`FinishLogin`, the prove step).

## Decision

Pattern: **phishing-resistant MFA for privileged accounts, enforced at
the door** -- CISA's phishing-resistant MFA guidance (admins first),
NIST SP 800-63B-4 §3.2.5.2, Microsoft Entra's "require phishing-resistant
MFA for administrators" with its register-at-sign-in interrupt, the AWS
root-account MFA prompt and Google Workspace's lock-until-enrolled admin
2-Step Verification -- with **last-credential protection for
self-service removal** (GitHub's sole-owner 2FA, Google's "cannot turn
2SV off") and **break-glass outside the policy** (Entra's
emergency-access accounts).

1. **The door.** While the rule is on, `Protect` holds an admin account
   until it holds a passkey usable under the current RP ID: 403, class
   `must-enrol-passkey`, header `X-Auth-Gate: must-enrol-passkey`. An
   authenticator app alone never opens it. It admits the same routes as
   the any-factor door (passkey register begin and finish, TOTP enrol
   and confirm, the held-enrolment confirm) and is checked before it, so
   an admin with no factor is told the one thing that opens it. The
   whole session is held, as the existing door holds it: `Protect`
   cannot tell which of an application's routes are admin-only, and the
   enforcers above hold the session, not a set of pages.
2. **Promotion grants, then holds.** Granting admin on the role route,
   creating an admin, `TransferAdmin` and the first account all succeed
   as before; the new admin is held at the door from its next request.
   The store does not change. The role and create responses and the
   users list carry `heldForPasskey`, and the audit detail says "held
   for a passkey", so an admin can see who is stuck.
3. **The last usable passkey.** An admin deleting their own last usable
   passkey is refused, 409 `conflict`, "register another passkey
   first", before the password is checked, so the refusal costs no
   re-check. A stale passkey is always deletable. Another admin's
   clear-all and the console `ClearAllSecondFactors` stay open as the
   way back for a lost key, and the account is held at its next request.
   The refusal lives in `gate`, the only place that knows "usable"; the
   door is the invariant, so two concurrent self-deletes that leave
   none are an accepted residual.
4. **The application decides, with no default.**
   `gate.Config.AdminPasskey` is a string-typed `gate.AdminPasskeyRule`
   whose zero value means "not set": `gate.AdminPasskeyRequired` or
   `gate.AdminPasskeyOptional`. `gate.New` refuses an unset or unknown
   value, so the application's admin makes a conscious choice and the
   application never fails silently, either way. With `required` and no
   ready relying party (`Deps.Passkeys` nil, or a status of `unset`,
   `ip` or `insecure`), `New` refuses to start, naming the status and
   the field, rather than lock every admin out or quietly waive the
   rule. The status is fixed by configuration, so the operator sees the
   refusal once, at start-up, not an admin at a door they cannot pass;
   mikroview already refuses to start in the analogous stale-passkey
   case. `New` logs the chosen value. `optional` is for an application
   reached over plain http or by IP address, where browsers make no
   passkeys, or one that wires none.
5. **An SSO-only admin sets a password first.** While the rule is on, an
   admin with no local password is held at the existing
   `must-change-password` door, which admits only `POST
   /api/auth/password`, with the message "set a local password" (it
   sets the first one from a fresh single sign-on, #79). Registering a
   passkey needs a local password (ADR-0004), so the chain is password,
   then passkey, then admin.
6. **Step-up accepts a passkey.** Every route that asks for the
   caller's password and a current second factor (granting admin,
   creating an admin, the admin's own unlock) takes password +
   assertion as the alternative to password + code. `POST
   /api/auth/step-up/passkey/begin` (session-gated, no body) starts a
   login ceremony for the caller's own usable passkeys through
   `Deps.Passkeys` and seals it in its own five-minute cookie,
   `gate_passkey_stepup`, so a sign-in's ceremony cookie is never
   finished here nor this one at a sign-in. Begin takes one re-check
   from the account's budget and keeps it until the assertion passes,
   so a session alone cannot mint challenges without limit. The `passkey/`
   leaf rule holds: `gate` still imports neither `gauntlet/passkey` nor
   the WebAuthn library.

Settled without a question:

- **No grace period.** The door offers registration in the same
  session. Existing admins without a passkey are held at their first
  request after upgrading and register one there.
- **No stored field.** The rule is computed from `Role` and `Passkeys`;
  the accounts document stays at version 9, with no migration.
- **Go API, additive.** `gate.AdminPasskeyRule`, its two constants and
  `gate.Config.AdminPasskey`; nothing in the root package. `gate.New`
  refusing to start until the field is set is a behaviour change under
  ADR-0002, listed in the changelog.
- **Unchanged:** sign-in itself (the door comes after the session), the
  setup, unlock and escape codes (ADR-0003, #44, ADR-0011), recovery
  codes, the held first factor (#58), passkey-alone sign-in (ADR-0012),
  account notices, and users and viewers, who keep "any factor".

## Rejected options

- **Refuse the grant unless the account already holds a passkey.** No
  enforcer surveyed does it; it is impossible for the first account;
  and the root package cannot tell a usable passkey from a stale one.
- **Hold everywhere, refuse nothing.** The person deleting their own
  last key is present and can add the new one first, which is what
  GitHub and Google ask.
- **Refuse every removal.** It blocks the recovery paths for a lost
  key.
- **Hold only the admin routes.** `Protect` cannot know an application's
  admin routes.
- **Enforce it in the store.** The store cannot know the RP ID, and one
  door is the invariant.
- **A switch owned by gauntlet, or any default, on or off.** The
  application knows whether it serves https and whether it wires
  passkeys; a default either way lets an application fail silently, so
  its admin must choose (owner, 2026-10-08).
- **A `*bool` field.** Its zero value does not say "not set" to a
  reader, and a struct literal needs an address-taking helper; a typo
  in a configuration-file mapping would read as false where an enum
  refuses it.
- **Warn and waive when the relying party is not ready.** It silently
  runs admins without the rule.
- **A grace period.** Machinery for what is one click at the door.
- **A new document version.** No field changes.

## Consequences

- Every application must set `Config.AdminPasskey` before upgrading, or
  it will not start. Birdcage, which wires no passkeys, sets `optional`
  until it wires `gauntlet/passkey` (its own issue); mikroview sets
  `required` where it serves https on a domain name and `optional` when
  reached by IP. The changelog and docs/using.md say so, and say to
  register a passkey before upgrading.
- With `required`, a browser that cannot do WebAuthn cannot pass the
  door; the admin uses another. The break-glass codes stay outside the
  door.
- Two concurrent self-deletes can leave an admin with no usable
  passkey; the door holds the account at its next request.
- `GET /api/auth/users` reads each admin account once more while the
  rule is on (the list blanks passkeys, and only the full record tells
  usable from stale); with the rule optional it costs what it did (#42).
- Step-up routes can now answer 401 `step-expired`, for a missing or
  used passkey ceremony.
