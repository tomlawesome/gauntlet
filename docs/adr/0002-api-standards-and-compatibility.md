# ADR-0002: API standards and the compatibility promise

**Status:** Accepted
**Date:** 2026-09-30
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
   Go's module compatibility rules. Stored documents carry a version
   number and are migrated inside gauntlet; the apps never read or write
   the format themselves.
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
5. **Timing.** OpenAPI, `apidiff` and ASVS land in v0.2.0; the frontends
   cannot tell. The error format switches to Problem Details only when
   mikroview's frontend moves onto gauntlet (#23, with mikroview #1202),
   because it changes what that frontend parses today.

## Consequences

- A bump to a new gauntlet tag in either app is expected to be a
  version-number change and a green pipeline, nothing else. The bump
  merge request in each app is the proof; a red one is a gauntlet bug.
- `docs/design.md` §1.5's gate route list becomes a pointer to the
  OpenAPI document (`docs/api/auth.yaml`), not a second copy of it.
- Two new tool-scope dependencies (`apidiff`, an OpenAPI validator) need
  the owner's approval per AGENTS.md before #22 starts; neither enters
  the library's own dependency graph.
- Path versioning (`/api/auth/v2/...`) is not adopted: the routes are an
  embedded surface behind each app's own frontend, and the additive rule
  makes a second path prefix unnecessary until a major version.

Written by Fable 5.1, 2026-09-30.
