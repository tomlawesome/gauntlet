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
   [docs/design.md](../design.md) (2026-09-26, from birdcage's
   `docs/design/gauntlet.md`).

2. **Storage and logging are interfaces**, not this module's concern --
   see `persist.Backend` in [docs/design.md](../design.md) §1.2.
   Gauntlet never owns a database; each application supplies its own
   backend and its own `*slog.Logger`. Eviction is not an interface: the
   pure function `evict.DownTo` is copied into `internal/evict`
   (design.md §1.1), and its one caller here is the login limiter's
   capped map of addresses and unknown usernames. A real account's
   counter is kept apart from that map and never evicted (#19,
   `ratelimit.go`). *(Corrected 2026-09-30, #24: this said eviction was
   an interface each app supplied.)*

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
- Status note (v0.3.0 audit, 2026-10-08): decision 2's "one caller" for
  `evict.DownTo` is out of date: the address-ban counts and bans map
  (`addressban.go`) also call it.
- Status note (v0.3.0 audit, 2026-10-08): the dependency and passkey lines
  above are superseded: `github.com/go-webauthn/webauthn` was approved
  on 2026-09-30 and the `passkey` package shipped in v0.2.0
  ([ADR-0004](0004-passkey-ceremony.md)).
- Status note (v0.4.0 audit, 2026-10-10): the sign-in history's fold index
  (`signins.go`, #90) also calls `evict.DownTo`.
- Status note (v0.4.0 audit, 2026-10-10): decision 1's self-hosted-only
  issuer policy is amended by [ADR-0014](0014-shared-issuers.md):
  `accounts.google.com` is accepted when the policy requires an `hd` value;
  Entra's shared endpoints, Apple and Microsoft personal accounts stay
  refused.
