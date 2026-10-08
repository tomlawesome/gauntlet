# ADR-0003: The first admin is created with a one-time setup code from the server's log

**Status:** Accepted (owner ruling 2026-10-01 on #37); decision 4 amended by ADR-0013;
decision 6's refusal of `RoleAdmin` superseded by ADR-0010
**Date:** 2026-10-01
**Relates to:** #37 (this change), #26 (v0.2.0 release audit, P54), #39
(no write-back of a deleted accounts file), ADR-0002 (compatibility
promise), ORBIT ADR-0022 (the owner's existing version of this pattern),
mikroview #1252 (the admin keeps a local password)

## Context

Until v0.2.0 the first account created on an empty store became admin,
whether through local registration (`Store.Register`) or SSO
(`FindOrCreateOIDCUser`). An empty store is not only a fresh install: an
accounts file deleted while the server runs, a wrong path in the config
or a botched restore all start a server with no accounts, and the first
visitor then took admin. Certificate-transparency logs publish a new
name within minutes, so "nobody knows the address yet" is not a control.

The owner ruled (2026-10-01): the first admin can only be created with a
one-time setup code the server prints to its log, so nobody without
access to the server can take admin. The owner's ORBIT project already
does this (its ADR-0022: a code made at start-up, kept in process
memory, printed once, inert once the instance is claimed, regenerated on
restart); mikroview and birdcage still have first-visitor-wins and will
close it the same way, in their own repositories.

Constraints: no new dependency; the exported Go API may only grow
(ADR-0002, `scripts/apidiff.sh`); the store must keep working for the
CLI and for tests that hold a `*Store`.

## Decision

1. **The code.** When a persisted store opens with no accounts -- or a
   reload applies a document with none -- it makes a 16-character code
   from the reset-code alphabet (80 bits, shown as `xxxx-xxxx-xxxx-xxxx`,
   typed back with or without dashes, in either case) and keeps only its
   SHA-256 hash, in process memory. Nothing is written to the accounts
   document or anywhere else. The code is announced once: through
   `Options.OnSetupCode` when the application set one, otherwise as one
   `Warn` line on `Options.Log`. Both unset means nobody sees it and no
   account can be created: fail closed, never open.

2. **Check, use, expiry.** `Store.CheckSetupCode(code)` compares in
   constant time. The code is used up by state, not by the check: once
   any account exists it answers `ErrRegistrationClosed`, in this process
   (the single creation funnel retires the hash) and in another (a reload
   that applies accounts retires it). It dies with the process; there is
   no clock expiry. A lost code means restart and read the log again, as
   in ORBIT. A reload that applies an emptied document issues and
   announces a fresh code, so the state after a bad restore is "setup
   required, new code", never "the old code works again".

3. **Local path.** `POST /api/auth/register` takes `{username, password,
   setupCode}`. `gate` reserves the attempt against the client address
   with the login limiter first (`429` at the limit, the same budget as
   login), checks the code (`401` with a plain-text body and a warning in
   the server log naming the address), and only then hashes the password
   -- a guess costs one hash comparison, never Argon2. The right code
   releases the attempt whatever happens after it: the budget guards the
   code, not the operator's typing. Two simultaneous correct attempts end
   with one admin, decided by `Register`'s existing guard.

4. **SSO path.** Closed while no account exists. The two
   `/api/auth/oidc/*` routes leave the bootstrap-exempt set (they answer
   `503` "setup required" like every other route) and
   `FindOrCreateOIDCUser` refuses on an empty store with
   `ErrSetupRequired`, checked both before the hash and inside the write
   against the document being saved. Every SSO-provisioned account is
   `RoleUser`. The first admin is a local account that links SSO
   afterwards; the admin keeps a local password in this model anyway
   (mikroview #1252), so the end state is the one ORBIT's claim cookie
   reaches by a longer route.

5. **Where the check lives.** In the store, so every HTTP caller shares
   one check and one announcement path; `Store.Register` keeps its
   signature and its meaning as the host-side primitive `gate` calls
   after the check. The CLI and tests already have host access, which is
   the access the code exists to prove.

6. **CLI.** No role, as in ORBIT: `CreateUser` still refuses `RoleAdmin`,
   and a CLI's own process cannot see the server's code. A CLI that opens
   the store for one command passes an `OnSetupCode` that does nothing,
   so it does not announce a code of its own.

7. **Exported API, additions only:** `Options.OnSetupCode
   SetupCodeHandler` (an interface, with the `SetupCodeFunc` adapter, so
   `Options` stays comparable -- apidiff counts a func field as a break),
   `Store.CheckSetupCode(code string) error`, `ErrSetupCodeInvalid`,
   `ErrSetupRequired`. `docs/api/auth.yaml` gains
   the `setupCode` field (`SetupCredentials`), the `401` and `429` on
   register, and the narrower bootstrap set.

## Alternatives rejected

- **Carry the code into the OIDC flow** (ORBIT's claim cookie): needs a
  sealed cookie and a new route for a one-time step whose end state the
  local-then-link route already reaches. Can be added later without
  breaking anything.
- **Persist the code's hash in the accounts document** so a CLI could
  print or regenerate it: a document format change and a second copy of
  the secret for no gain over "restart and read the log".
- **Burn the code after N wrong guesses:** at 80 bits the limiter is
  there to notice probing, not to make guessing feasible to stop, and a
  burn hands an attacker a way to force restarts during setup.
- **A clock expiry with automatic re-issue:** a second number to
  explain, and a code that is only ever in the log of a server with no
  accounts gains little from it.

## Consequences

- An operator's first run now reads the server log once. Each app
  documents where that log is.
- A frontend's first-run screen collects the code and hides the SSO
  button while `setupRequired` is true.
- A deployment that meant to be SSO-only still has one local password:
  the admin's, as mikroview #1252 already requires.
- Tests that provision an SSO user start from a store holding the admin
  (`openTestStoreWithAdmin`, `newOIDCTestGate`); `newTestGate` records
  the code its store announced so `registerAdmin` can present it.
- Status note (v0.3.0 audit, 2026-10-08): decision 3's wrong-code `401` now has an
  RFC 9457 `application/problem+json` body (ADR-0002 decision 5), not a
  plain-text one; the warning in the server log is unchanged.
- Status note (v0.3.0 audit, 2026-10-08): decision 6's "`CreateUser` still refuses
  `RoleAdmin`" is superseded: since #67 (ADR-0010) `CreateUser` accepts
  `RoleAdmin`. The rest of decision 6 stands.
