# ADR-0012: A user-verifying passkey can sign in on its own

**Status:** Accepted (design ratified on #77; owner answers of 2026-10-05
recorded below)
**Date:** 2026-10-05
**Relates to:** #77 (this change), #71 (resume a timed-out session),
ADR-0004 (the passkey ceremony; its decision 5 is superseded here),
ADR-0009 (unusual sign-ins) and #55, #70 (the limiter and address ban),
#58 (a first factor is held until its codes are confirmed), #66
(ADR-0011, the escape code), ADR-0002 (compatibility)

## Context

ADR-0004 decided that a passkey is only ever the second step behind a
password: user verification asked for and not required, and "no
discoverable or passwordless login". That fitted a second factor, and
shut out nothing a password-first login could not do. It also made a
passkey that proved the person (a PIN or a biometric at the
authenticator, on top of owning the key) weaker in use than it is: the
sign-in still asked for a typed password first.

NIST SP 800-63B-4 counts a passkey that verified the user as a
multi-factor cryptographic authenticator, enough for AAL2 on its own,
and the W3C's WebAuthn Level 3 gives the standard shape: a client-side
discoverable credential login, where nobody types a username and the
browser offers the passkeys it holds for the site. The owner decided on
2026-10-05 that gauntlet should offer it, that every account keeps its
password, and that every registration asks for a discoverable credential.

## Decision

Pattern: **WebAuthn Level 3 client-side discoverable credential login,
user verification required** (800-63B-4: multi-factor cryptographic
authenticator, AAL2).

1. **Discoverable only; no username-first.** Username-first would add a
   route that says whether a name holds a passkey before any credential
   is shown -- the enumeration ADR-0009 section 9 avoids -- and gains
   nothing: a user-verifying passkey already names its account through
   the user handle, which is the account ID (`[]byte(u.ID)` in
   `passkey/ceremony.go`), so `Store.Get(string(userHandle))` finds it
   with no new index. `BeginSignIn` asks for a discoverable login with
   `userVerification: required` and no allowed list; `FinishSignIn`
   verifies through the library's passkey login, against the named
   account's passkeys under the current RP ID only.
2. **User verification is required, and checked twice.** The ceremony's
   sealed state requires it and `FinishSignIn` reads the flag the
   authenticator signed; gate reads `PasskeyAssertion.UserVerified`
   again before it records anything.
3. **Every account keeps its password** (owner, 2026-10-05). Registration
   is password-gated (ADR-0004 decision 5), recovery is reset-code
   shaped, and a first passkey is not live until its codes are confirmed
   (#58). A passkey replaces the password at sign-in, never in the
   account: no account field changes and the accounts document stays at
   version 9. An account with no local password (single sign-on owns its
   identity) cannot be signed into this way, as it cannot resume a
   session.
4. **Optional seam and a switch.** `gauntlet.PasskeySignIn` is a second
   interface beside `PasskeyCeremony`, which ADR-0004 said would not
   grow; `gauntlet/passkey`'s relying party implements both. Gate offers
   the routes only when `Deps.Passkeys` implements it and
   `Config.PasskeySignIn` is true (default false); otherwise both answer
   404. Mikroview's `POST /api/auth/login`, its `login/factor` branch and
   its cookies are untouched; it opts in when its frontend has the
   button. The session body's `passkeys` block gains `signIn: true` when
   the routes are on and the relying party is ready, and is sent signed
   out for that, so a login page knows to offer it.
5. **Judged, counted, resumable.**
   - Judged as any completed sign-in (ADR-0009 decision 2), before a
     session exists. The method `passkey_alone` reaches `Decide`, so an
     application may relax it. Confirm is **not** skipped by default: the
     signals are about place and browser, and a synced passkey on an
     unlocked stolen phone is the case they exist for.
   - Counted (#70): begin reserves one attempt on the address (a banned
     address or one at its limit is 429). Finish reads the user handle
     from the parsed assertion and calls `reserveLogin` for that account
     before the signature is checked -- the ceremony calls gate's lookup
     first for exactly this -- so the account's lockout and disable, the
     address ban and limit and the known-browser allowance apply as for a
     password. A refused or not-user-verified assertion keeps the
     reservation and is `factor_refused`; a handle that names nothing is
     `no_such_user`; a completed sign-in gives both reservations back and
     resets the account's count. A wrong credential does not count toward
     the account's run of second-factor failures: no password was
     presented, so counting would let anyone holding an account ID force a
     password change on it.
   - Resumable (#71): the same assertion, from the same begin route,
     resumes a timed-out session at `POST /api/auth/reauthenticate`
     (`{assertion}` instead of `{password}`). The user handle must be the
     timed-out session's own account, user verification is required, and
     the attempt is the resume's reservation, method `resume`. A resumed
     session keeps the method of the sign-in it continues.
   - Unchanged: a lone admin's escape (#66) is one more remedy before the
     escape, as a password sign-in is; the must-change-password door still
     holds after a passkey sign-in and the reset code stays valid; a
     passkey held for its codes, or registered under an earlier public
     URL, cannot sign in.
6. **Shapes.** Root: `PasskeySignIn{BeginSignIn, FinishSignIn}`,
   `PasskeyAssertion.UserVerified`, `SignInMethodPasskeyAlone`,
   `SessionClient.Method`. Gate: `Config.PasskeySignIn`; `POST
   /api/auth/login/passkey/begin` and `POST /api/auth/login/passkey`
   (`{assertion}` answers the account or the confirmation challenge; 401
   `invalid-credentials`, 401 `step-expired`, 403 `sign-in-refused`, 404
   when off, 409 while the relying party is not ready, 429), all existing
   error classes. The ceremony cookie is `gate_passkey_signin`, sealed
   under its own key so a second-step login's state cannot finish it,
   five minutes, path `/api/auth` (not `/api/auth/login/passkey`: the one
   begin route also serves the resume route, and a browser sends a cookie
   only to paths under its own). The session, the history row and the audit
   record carry the method `passkey_alone`; notices go through
   `Config.Notices` and need no new kind, since `UnusualSignInDetail.Method`
   already says how.
7. **A resident key is asked for on every registration** (owner,
   2026-10-05), `residentKey: preferred`, mikroview's included. W3C
   recommends it, a platform authenticator's passkey is discoverable
   anyway, and a PIN-less security key that cannot hold one still
   registers, as a second factor. User verification stays preferred and
   attestation `none`.

## Rejected options

- **Username-first, then a passkey.** An enumeration surface for no gain
  (decision 1).
- **Passwordless accounts.** Owner, 2026-10-05: every account keeps a
  password. It would need a new recovery design and a change to the
  accounts document.
- **A per-account toggle.** One more field and one more screen to decide
  something the application already decides with `Config.PasskeySignIn`.
- **Skipping the confirm step for a passkey.** The signals are about
  place and browser, not the credential; a synced passkey on a stolen,
  unlocked phone is what they are for. `Decide` can relax it.
- **A second, cookie-less route for the resume.** The resume reuses the
  begin route and its cookie; a second route would duplicate the ceremony
  for nothing.

## Consequences

- Mikroview is untouched until it opts in: its login screen, cookies and
  responses are as they were, and its next registrations merely ask for a
  discoverable credential.
- The accounts document stays at version 9. `PasskeyCeremony` is
  unchanged; an application that never imports `gauntlet/passkey` still
  links no WebAuthn code (`go list -deps ./gate` shows none).
- A passkey that verified the user is treated as multi-factor
  (docs/security-by-design.md 6.3.3); the biometric itself still never
  reaches gauntlet, only the flag the authenticator signed.
- Passkeys registered before this change may not be discoverable and
  cannot sign in alone; they still work as a second factor.
- An address at its limit cannot begin a passkey sign-in even from a
  browser the account remembers, as the allowance belongs to an account
  the begin step cannot name yet; it applies at the finish.
- Status (v0.3.0 audit, #79): begin no longer reserves on the address's
  login attempts but on its own bucket of the same size
  (`passkey-begin:<address>`), released when the sign-in or resume
  completes. Page loads and cancelled prompts call begin, and were
  spending the budget a wrong guess is limited by; the finish still
  reserves on the address and the account as decision 5 says.
- Status (#92): decision 6's `401` `invalid-credentials` from `POST
  /api/auth/login/passkey` now names a passkey the server does not hold
  in any form (live, stale or held) in an `unknownCredential` member,
  the argument of the browser's `signalUnknownCredential()`, so the
  application can tell the browser to stop offering it. No new class,
  `detail` or Go API; counting is unchanged.

Design ratified on #77, 2026-10-05.
