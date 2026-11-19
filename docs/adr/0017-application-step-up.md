# ADR-0017: Applications step up their own routes with gauntlet's rule

**Status:** Accepted (design ratified on #133, 2026-11-18)
**Date:** 2026-11-18
**Relates to:** #133 (this change), birdcage #166 (the first caller),
#67 and #82 (the step-up and its passkey option), ADR-0015 (every admin
holds a passkey), ADR-0002 (compatibility)

## Context

An application's own admin action -- birdcage minting a CrowdSec
certificate -- needs the same protection as granting the admin role: the
caller's password and a current second factor on the request itself
(ASVS 7.5.3). Gauntlet's one copy of that rule, `recheckStepUp`, was
unexported, so an application could only write a second copy.

Two standard shapes exist for re-authentication before a sensitive
operation: (1) **re-authentication on the request**, where the
credentials travel with the sensitive request and are verified there,
nothing cached (ASVS 7.5.3); (2) a **session-bound recent-auth proof
with a max age** (RFC 9470 step-up, OIDC `auth_time`). Gauntlet's own
routes use shape 1 and have nowhere to store an `auth_time`.

## Decision

1. **Export shape 1; no stored proof, no freshness window.**
   `gate.StepUpProof{Password, Code, Assertion}` (JSON `password`,
   `code`, `assertion`) is embedded in the application route's body, and
   `(*Gate).StepUp(w, r, proof) bool` runs `recheckStepUp` against
   `UserFromContext(r)`. It writes every refusal itself. There is no
   parameter an application can set, so it can neither loosen nor
   tighten the rule. A stored proof would be a second, weaker mechanism
   (a stolen cookie inside the window acts with no credential) that
   gauntlet's own routes would never use.
2. **A method, not middleware.** The proof is in the body the handler
   decodes; the handler validates its own fields first and steps up
   last, so a recovery code is never spent on a request refused
   afterwards.
3. **No new error class.** The requirement is static -- the route's
   contract says the body carries the proof -- so refusals use the
   existing classes: 401 `sign-in-required` (no session user, as on a
   bearer-token or `Exempt` request), 409 `conflict` (no local
   password), 400 `invalid-request` (incomplete proof, nothing counted),
   401 `invalid-credentials` ("incorrect password or code"), 401
   `step-expired` (dead passkey ceremony), 429 `rate-limited`. A new
   `step-up-required` class would either fork the exported helper from
   gauntlet's own routes or change their published 400 contract.
4. **The `gate_passkey_stepup` cookie path becomes `/`**, as the
   session cookie's is. At `/api/auth` an application route never
   received it, so the passkey half -- the one that matters under
   ADR-0015 -- could never pass. The value is sealed, HttpOnly,
   SameSite=Lax, five minutes, single-use and bound to the caller's
   account at finish; the only new exposure is that application handlers
   receive the header, as they already receive the session cookie.
   `gate_passkey_signin` stays at `/api/auth`.
5. **One rule.** `recheckStepUp` now takes a `StepUpProof`; its four
   internal callers (create admin, grant admin, own unlock, own
   allow-sign-in) build one from their bodies with no wire change.
   Password-only re-checks (#72) and `reauthenticate` (#71) stay
   separate: they are different rules by design.

## Consequences

- Additive Go API (one type, one method); patch release 0.4.5.
- An application's step-up route shares the account's re-check budget
  with gauntlet's own, so adding routes adds no guesses.
- Gauntlet audits failed step-ups (`user.login_failed`, `step=recheck`);
  the successful action is the application's to audit.
- The body carries the password: applications must not log request
  bodies or headers on step-up routes.
- A stored-proof window, if ever wanted, is a new issue and a new ADR,
  not a parameter on `StepUp`.
