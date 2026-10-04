# ADR-0002: API standards and the compatibility promise

**Status:** Accepted
**Date:** 2026-09-30
**Amended:** 2026-10-01 -- decision 1, stored-document versions (#29);
decision 5, ASVS moved out of v0.2.0 (#31). 2026-10-02 -- decision 1,
added fields raise the version (#28); decision 1, a third stored
document, the sign-in history (#53, ADR-0006). 2026-10-03 -- decision 5,
the error-format switch moved earlier, to before mikroview's migration
(#23, owner 2026-10-03)
**Relates to:** [ADR-0001](0001-shared-auth-module.md), #22 (CI compatibility
checks), #23 (Problem Details errors), mikroview #1202

## Context

Gauntlet exists so a security fix lands once and both apps pick it up
(ADR-0001). That only works if an app can take a new gauntlet version
without changing its own code. The v0.1.0 audit (#16) asked whether the
module is shaped for that. The answer: the Go surface is small and the
security behaviour lives inside gauntlet, but two things leak to the
apps -- the exported `User`, `Token`, `Session` and `Passkey` structs,
whose fields are also the stored JSON, and the `/api/auth/*` routes and
response bodies their frontends parse. Nothing written down said how
those may change, and nothing checked it.

The owner asked for compliance with proper API standards rather than a
house rule (2026-09-30).

## Decision

1. **Standards, by layer.** The HTTP surface is described by an
   **OpenAPI 3.1** document checked into this repository, the source of
   truth for both frontends. Errors are **RFC 9457 Problem Details**
   (`application/problem+json`). Bearer tokens follow **RFC 6750**, SSO
   follows **OpenID Connect Core** over OAuth 2.0, TOTP follows
   **RFC 6238**. Security requirements are measured against
   **OWASP ASVS**. The Go library follows **semantic versioning** under
   Go's module compatibility rules. Stored documents (accounts, tokens
   and, since #53, the sign-in history, which starts at version 1)
   carry a top-level `version` number; a v0.1.0 document, which has
   none, reads as version 1. A document newer than the running build
   reads is refused -- on open, on reload and by a write -- so an older
   build never loads one and saves it back without the fields it does
   not know. Migrations are written inside gauntlet when the first
   format change needs one; until then there is no migration code.
   Any change to what a document carries raises that document's
   version, a field added as much as a shape changed, so an older build
   refuses it instead of saving it back without the field. An added
   field must read correctly as its zero value from an older document;
   adding one then needs no migration code, only the raised number and
   a round-trip test that the older fixture still opens. Rolling back
   across a raised version means restoring the copy taken before the
   upgrade. The apps never read or write the format themselves.
2. **Additive only from v0.1.0.** Exported identifiers, exported struct
   fields, routes, response fields and stored-document fields are added,
   never renamed or removed, within a major version. Anything to be
   removed is marked deprecated and kept for one minor release first.
3. **Checked by CI, not by reviewers** (#22): contract tests run every
   route through the OpenAPI document; `apidiff` compares the exported
   Go API against the last tag and fails an incompatible change unless
   the major version bumps.
4. **v1.0.0 is tagged only once mikroview and birdcage both run on
   gauntlet.** Until then v0.x means the promise above is kept by
   intent and CI, not yet proven by two consumers.
5. **Timing.** OpenAPI and `apidiff` land in v0.2.0; the frontends
   cannot tell. Measuring the security requirements against ASVS comes
   in a later release, not v0.2.0 (owner, 2026-10-01): the mapping is
   #33, in v0.3.0. The error format switches to RFC 9457 Problem Details
   now, in this release, not timed to mikroview's migration onto gauntlet
   (#23, owner 2026-10-03, superseding this decision's original
   "only when mikroview's frontend moves onto gauntlet"): neither
   mikroview nor birdcage parses gauntlet's error bodies yet, so nothing
   is broken by switching first, and mikroview then migrates onto
   gauntlet's error format once (mikroview #1202) instead of once onto
   the old shape and again onto Problem Details.

## Consequences

- A bump to a new gauntlet tag in either app is expected to be a
  version-number change and a green pipeline, nothing else. The bump
  merge request in each app is the proof; a red one is a gauntlet bug.
- `docs/design.md` §1.5's gate route list is now a pointer to the
  OpenAPI document (`docs/api/auth.yaml`), not a second copy of it.
- Two tool-scope dependencies, `apidiff` (CI only) and the
  `kin-openapi` validator (tests only), were approved by the owner on
  2026-09-30 and shipped with #22; neither enters the library's own
  dependency graph.
- Until #33 lands, nothing checks the security requirements against
  ASVS; decision 1's ASVS line is the target, not yet a measurement.
- Path versioning (`/api/auth/v2/...`) is not adopted: the routes are an
  embedded surface behind each app's own frontend, and the additive rule
  makes a second path prefix unnecessary until a major version.

Written by Fable 5.1, 2026-09-30.
