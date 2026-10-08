# ADR-0004: The passkey ceremony is a leaf package behind a seam in the root

**Status:** Accepted, shipped in v0.2.0 (design on #20; owner decisions of
2026-09-30 and 2026-10-01 recorded below). Decision 5's "no discoverable
or passwordless login" and its unset resident-key preference are
superseded by ADR-0012. Decisions 3 and 4 are amended by ADR-0015 (see
the status notes at the end).
**Date:** 2026-10-02
**Relates to:** #20 (G8, this change), ADR-0001 (mikroview is the
reference), ADR-0002 (additive API, apidiff, OpenAPI contract),
mikroview #1250 (its passkey design) and #1202 (its move onto gauntlet)

## Context

Mikroview's users already hold passkeys, so mikroview cannot move onto
gauntlet (#1202) until gauntlet can run the WebAuthn ceremony: the
browser round trip that creates a passkey (registration) and the one
that proves it at login (assertion). The storage half -- `Passkey`,
`AddPasskey`, `RecordPasskeyAssertionIfFresh`, `ClearPasskeys` and the
rest -- shipped in v0.1.0 with no WebAuthn dependency (design §1.6).
The ceremony half needs `github.com/go-webauthn/webauthn`, which the
owner approved on 2026-09-30 at v0.18.2 (BSD-3-Clause) for the
`passkey/` package, and a public URL, because a passkey is bound to a
domain name (the relying-party id) and an origin, neither of which an
app reached by IP address has.

Three constraints shape the answer. Birdcage does not need passkeys
(design §1.6) and should not carry the library and the eight modules it
brings (CBOR, TPM, JWT and others) into a security product that never
calls them. ADR-0002 freezes every exported identifier at the next tag,
so the surface must be the smallest the done-when needs. And the
done-when is mikroview's own tests passing against gauntlet, so the
HTTP contract must be mikroview's, with only gate-internal names
changed.

Research first (docs/security-by-design.md): v0.18.2 is the newest
release (2026-09-19) and the OSV and Go vulnerability databases hold no
advisory against it as of 2026-10-02; the library's own end-to-end
tests hand-build ceremonies from an ECDSA key, which is the pattern
mikroview's fake authenticator copies and this module reuses.

## Decision

1. **The seam is in the root package.** `gauntlet.PasskeyCeremony` is
   an interface of seven methods (`Status`, `RPID`, `Origin`,
   `BeginRegistration`, `FinishRegistration`, `BeginLogin`,
   `FinishLogin`) whose every value is a root type, a string or raw
   JSON; `gauntlet.PasskeyAssertion` is what a verified login reports,
   in the shape `RecordPasskeyAssertionIfFresh` consumes;
   `gauntlet.PasskeyStatus` names the four availability states; and
   `gauntlet.ErrPasskeyCeremonyInvalid`, which `passkey` wraps whenever
   the sealed ceremony state is unusable (fails the authentication tag,
   is malformed, was sealed for the other ceremony or by another
   process, has expired, or its challenge is spent), lets `gate` tell a
   dead ceremony (start again: 401, cookie cleared) from a refused
   credential (try again: 400 or 401, cookie kept) without importing
   `passkey`. Those four are the seam's root additions. The
   root already carries the WebAuthn-free data shapes and the seams
   other packages implement, and only there can the implementer carry
   a compile-time check that it satisfies the contract.

2. **`gauntlet/passkey` is a leaf.** It imports the root and the
   library, never `gate`, and `gate` never imports it. It exports
   `Config{PublicURL, DisplayName}`, `New`, the opaque `RelyingParty`
   and two sentinel errors (`ErrNotReady`, `ErrNoUsablePasskey`) for
   direct callers and tests -- `gate` never needs them, since it checks
   `Status()` and the usable-passkey count before calling Begin. It owns turning the public URL into a
   relying party or a reason it cannot be one, the two sealing keys
   for ceremony state, the spent-challenge set, the library calls and
   the conversion between `gauntlet.Passkey` and the library's
   credential. It never sees a request or a cookie.

3. **`gate` consumes it through `Deps.Passkeys`.** nil means the
   application has no passkeys: every passkey route answers 404, the
   session body omits `passkeys`, the login response never offers
   `passkey` -- the same shape as `Deps.OIDC == nil`. `gate` owns the
   routes, the two cookies (`gate_passkey_register` on
   `/api/auth/passkeys`, `gate_passkey_assert` on `/api/auth/login`,
   five minutes, sealed values from `passkey`), the limiter
   reservations, sessions, recovery codes and audit, in the files and
   the voice its TOTP routes already have. An app that never imports
   `gauntlet/passkey` never compiles the library in.

4. **The public URL is the application's setting, never the `Host`
   header.** `passkey.New` succeeds whatever the URL says and reports
   `ready`, `unset`, `ip` or `insecure`; while not ready, the
   ceremony-starting routes answer 409 naming the status and the list,
   rename and delete routes keep working so stale passkeys stay
   visible and removable. This is mikroview's "always boots, passkeys
   fail into an explained state" (#1250), kept because its deployments
   reached by IP must keep starting on the day of #1202. Refusing to
   start when accounts already hold passkeys and the relying party is
   not ready stays an application rule: the application, not
   gauntlet, decides it, from `Status()` and the store's
   `AnyPasskeysExist()` (added for this on the owner's answer to #20
   question 5), as mikroview's `passkeyStartupRefusal` does.

5. *Superseded by ADR-0012 (#77) as to a discoverable login with no
   password before it, and the unset resident-key preference: a
   user-verifying passkey may now sign in on its own, behind
   `Config.PasskeySignIn`, and every registration asks for `residentKey:
   preferred`. The rest of this decision stands.* **Policy, written in
   code rather than left to defaults:** user
   presence required; user verification requested but not required
   (a second factor behind a password; requiring it shuts out
   security keys without a PIN); attestation `none`, not verified, no
   metadata service; no discoverable or passwordless login.
   Registration is password-gated at begin, as TOTP enrolment is, and
   refused (409) for an account with no local password (rulings R1 and
   R4 on #20). A login
   challenge is used once (the spent-challenge set). One
   password-proved registration begin stores at most one passkey: the
   ceremony is spent by the first finish the library accepts, keyed by
   the sealed cookie's hash (ruling S1), and a sealed value opens only
   in the one base64 spelling it was written in, so no other spelling
   of a spent cookie gets past that key. A finish the library refuses
   (wrong origin, bad signature, malformed) leaves the ceremony usable
   for a corrected one within its five minutes. A stolen register cookie finished
   inside the owner's own five-minute window is the accepted residual
   -- it needs both of the owner's HttpOnly cookies, yields at most one
   passkey per window, and shows in the owner's list and audit log.
   The pending login a password
   step issues is spent by the sign-in that completes it, so one
   correct password yields one session (ruling R2). A spent challenge
   or pending login is checked against the sealed expiry the
   acceptance check itself reads, on the same wall clock
   (`internal/spent`), and remembered until one lifetime after that
   expiry, so a request that read the clock before the expiry cannot
   find the key already forgotten (ruling S2). Either ceremony expires five
   minutes after begin (sealed `Expires`, checked by the library), and
   a value sealed for one ceremony cannot decode as the other. A sign
   counter that fails to advance refuses the login through the
   library's clone warning and, under the store's lock, through
   `RecordPasskeyAssertionIfFresh`; the stored count is never moved by
   a refused assertion. `login/factor/begin` spends the same login
   limiter reservations as the code step; they are released by a
   completed sign-in, by begin's own server-side failure (500), and by
   a counter that could not be saved -- never by a refused assertion.

6. **Routes and bodies are mikroview's**, except that register/begin
   takes `{password}` (decision 5), which mikroview's does not
   (`GET /api/auth/passkeys`,
   `POST .../register/begin|finish`, `PATCH|DELETE
   /api/auth/passkeys/{id}`, `POST /api/auth/login/factor/begin`, the
   `{assertion}` branch of `POST /api/auth/login/factor`, `DELETE
   /api/auth/users/{id}/passkeys`), described in `docs/api/auth.yaml`
   and driven by the contract tests. The two option bodies and the two
   credential request fields are the W3C's `PublicKeyCredential` JSON,
   produced and consumed by the library and the browser; they are the
   one open schema in the document, so a library bump that adds a W3C
   field cannot fail the contract.

7. **The fake authenticator is shared code**, `internal/passkeytest`,
   importable by `passkey`'s tests, `gate`'s tests and the contract
   module, never by non-test code.

## Alternatives rejected

- **`gate` imports `passkey` and takes a `*passkey.RelyingParty`.**
  Simplest wiring, but every application would link the library and
  its dependency tree, and the owner's concern was exactly that.
- **`passkey` imports `gate` and registers its own handlers.** Needs
  `gate` to export its pending-login cookie, limiter reservations,
  password re-check, audit and cookie writer -- a large surface frozen
  by apidiff for one consumer.
- **A nested Go module for `passkey/`.** Keeps the library out of
  gauntlet's `go.mod` entirely, at the cost of its own tags, apidiff
  run, floors and a second `go get` for mikroview; the owner approved
  the dependency for the one module.
- **Export the library's `*webauthn.WebAuthn` on `RelyingParty`.**
  Would let an app drive its own flows, and would also freeze the
  library's types into gauntlet's API.
- **Refuse to start on a missing or wrong public URL.** Gauntlet fails
  closed on wiring mistakes elsewhere, but here the "mistake" is a
  deployment reached by IP that simply has no passkeys, and the
  frontend already explains the state from the session body.

## Consequences

- Mikroview's move (#1202) wires `Deps.Passkeys = passkey.New(...)`
  and swaps to `gate.Routes()`; its frontend sees the same paths and
  bodies but one, and new cookie names it never reads. The one is
  register/begin: its add-passkey screen asks for the password first,
  as its TOTP enrolment screen already does. That closes a hole
  mikroview has today (a stolen session can plant a passkey).
- Birdcage changes nothing and links nothing new. If it ever offers
  passkeys, `BIRDCAGE_PUBLIC_URL` becomes `passkey.Config.PublicURL`.
- `PasskeyCeremony` cannot gain a method without a major version; a
  later need is met by a second, optional interface.
- No tag carries `passkey/` until the ported mikroview cases pass and
  the fix, function and robustness reviews are done (owner,
  2026-10-01).
- `github.com/go-webauthn/webauthn` joins the modules `govulncheck` and
  the licence gate watch on every pipeline.
- Status note (v0.3.0 audit, 2026-10-08): built and shipped in v0.2.0 (the `passkey`
  package and `gate`'s passkey routes); the **Status** line above was
  never moved from Proposed.
- Status note (v0.3.0 audit, 2026-10-08): decision 2's "two sealing keys" is now three:
  ADR-0012 (#77) added a third, for passkey-alone sign-in, so each
  ceremony's state opens only for its own ceremony.
- Status note (v0.3.0 audit, 2026-10-08): decision 3's "two cookies" is now three:
  ADR-0012 (#77) added `gate_passkey_signin` on `/api/auth`. The two
  named here are unchanged, and all three last five minutes.
- Status note (#82, 2026-10-08): decisions 3 and 4 are amended by
  [ADR-0015](0015-every-admin-holds-a-passkey.md). `Deps.Passkeys` nil
  and a relying party that is not ready (`unset`, `ip`, `insecure`)
  still boot, but only for an application that sets
  `gate.Config.AdminPasskey` to `gate.AdminPasskeyOptional`; with
  `gate.AdminPasskeyRequired`, `gate.New` refuses to start, naming the
  status. Every application now sets the field, so "always boots" is
  the application's explicit choice rather than the default. A fourth
  ceremony cookie, `gate_passkey_stepup` on `/api/auth`, five minutes,
  carries a passkey step-up.
- Status note (#85, 2026-10-08): decision 5's "`login/factor/begin`
  spends the same login limiter reservations as the code step" no
  longer holds. Begin is counted on the account's own begin budget
  (`LoginLimiter.ReserveFactorBegin`; a browser the account remembers
  has one of its own beside it), never handed back except on begin's
  own server-side failure, so `login/factor` releases only the
  reservation it took itself (design.md, "One rule for every budget").
