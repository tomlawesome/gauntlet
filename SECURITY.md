# Security policy

Gauntlet is a shared authentication library (pre-v0.1.0, not yet used by
any application): local accounts with Argon2id password hashing, opaque
server-side sessions, self-hosted-only OIDC, and read-only/write-only
tokens. Compromise of this module compromises every application that
imports it at once -- that is the cost of sharing, and the reason a fix
here matters more than a fix in one app.

## Posture kept from mikroview, the reference implementation

Full detail and the CVE research behind each item is in
[docs/design.md](docs/design.md) section 4 and
[docs/security-by-design.md](docs/security-by-design.md). In short:

- **Sessions**: 128-bit CSPRNG ids, sliding idle timeout capped at a
  fixed ceiling, revoked on a password change, `SameSite=Lax` plus a
  custom-header CSRF check on unsafe methods.
- **OIDC**: Authorization Code + PKCE, constant-time `state`/`nonce`
  checks, an explicit signing-algorithm allowlist, identity keyed on
  `(issuer, subject)` rather than email, and self-hosted issuers only,
  plus Google with the `hd` domain pinned in the policy (ADR-0014) --
  any other public multi-tenant IdP is refused at startup, not left to
  misconfiguration.
- **Tokens**: SHA-256 at rest, kind-checked on every use so a read token
  can never authenticate a write route, a uniform 401 for missing and
  revoked tokens alike, and a login rate limiter in front of password
  hashing to bound it as a denial-of-service lever.
- **Fail-closed**: an unparseable stored document refuses to start rather
  than silently reopening as a fresh install (`persist.Open`); an unknown
  token kind never authenticates; a missing OIDC claim is a refusal, not
  a default-allow.

What each importing application does with this -- which routes it gates,
whether a second factor is mandatory -- is that application's own
`SECURITY.md`, not this one.

## Third-party dependencies

Each new dependency this module takes on is CVE-checked before being
added (see [AGENTS.md](AGENTS.md) for what's currently approved).
`govulncheck` and a licence gate run in CI on every change.

## Reporting a vulnerability

This is a small, personally-maintained project without a formal
disclosure program. If you find a security issue, please open an issue
on [gitlab.tomlawson.io/ai/gauntlet](https://gitlab.tomlawson.io/ai/gauntlet)
describing it -- for anything you'd rather not post publicly first, open
a minimal issue asking for a private contact channel instead of including
details in it.
