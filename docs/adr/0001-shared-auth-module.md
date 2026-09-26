# ADR-0001: Gauntlet exists because auth is shared, not copied

**Status:** Accepted
**Date:** 2026-09-26
**Relates to:** birdcage [ADR-0005](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/adr/0005-shared-auth-module.md), mikroview #1202

## Context

Birdcage needed local accounts, sessions, tokens and OIDC. Mikroview
already had all four, tested and running in production. Re-implementing
them by hand in birdcage and keeping the copy in step manually was the
original plan (birdcage ADR-0003); the owner reversed that on reading the
ADR: *"we should really work towards our implementation of authentication
etc being in a reusable module now. It makes little sense to copy
mikroview, only to later try and create a shared Go module."*

Birdcage ADR-0005 records the decision on birdcage's side: one shared
module, its own repository, built and proven in birdcage first, with
mikroview's auth code as the continuous reference it is read against
until mikroview itself moves onto it. This repository is that module.

## Decision

1. **This repository holds the auth model** birdcage ADR-0005 describes:
   local accounts and roles, OIDC with a self-hosted-only policy and
   `(issuer, subject)` identity, opaque server-side sessions, and
   read-only/write-only tokens. The design is
   [docs/design.md](../design.md) (Fable 5.1, 2026-09-26, from birdcage's
   `docs/design/gauntlet.md`).

2. **Storage, logging and eviction are interfaces**, not this module's
   concern -- see `persist.Backend` in [docs/design.md](../design.md)
   §1.2. Gauntlet never owns a database; each application supplies its
   own backend, its own `*slog.Logger`, and (where it needs eviction)
   its own copy of the pure function `evict.DownTo`.

3. **Mikroview's auth code is the reference**, continuously, not a
   one-time source to port from: this module is read against mikroview's
   `internal/auth`, `internal/oidc` and `internal/api/{auth,oidc,
   tokens}.go` at every slice, so it fits without change when mikroview's
   own move (#1202) opens.

## Owner decisions, 2026-09-26

Recorded here because they shaped this repository's shape at creation,
not any one issue:

- **Licence: Apache-2.0.** Mikroview is AGPL-3.0-only and birdcage is
  under the owner's own noncommercial licence; a copyleft or
  noncommercial licence on a library both applications import would put
  conditions on whichever app carries the other licence when a third
  party redistributes it. A permissive licence -- the same family as this
  module's own dependencies (BSD-3-Clause, Apache-2.0) -- keeps both
  applications' terms unchanged.
- **First tag: v0.1.0**, not v1.0.0.
- **Dependencies approved for G2/G5**: `golang.org/x/crypto/argon2`,
  `github.com/coreos/go-oidc/v3`, `golang.org/x/oauth2` (birdcage #8).
  `github.com/go-webauthn/webauthn` is not approved; it waits for the
  `passkey` package (G8).
- **Passkeys**: the data model (the `Passkey` struct, plain fields) ships
  in v1; the WebAuthn ceremony is deferred to G8, after birdcage's first
  login (B4) and before mikroview #1202.
- **Second factor is mandatory in birdcage** from its first release with
  login -- TOTP or a passkey, matching mikroview's own model.
- **Document store, not relational rows**, for an application's own
  persisted accounts/tokens table -- the alternative is a second read
  model that can disagree with the in-memory one.

## Consequences

- A security fix to session, token or OIDC handling lands once, here, and
  each application picks it up by bumping the module version -- birdcage
  ADR-0005's whole point.
- This repository's API is a design call that stays with the top model
  (birdcage ADR-0005); its seams are fixed by what mikroview already
  needs, not invented fresh.
- Mikroview is not changed by this work. Its move onto this module is
  mikroview #1202, opened only when the owner says so.
