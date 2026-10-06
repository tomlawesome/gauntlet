# ADR-0014: A shared SSO issuer is accepted when the policy pins the tenant

**Status:** Accepted (owner decision on #79, 2026-10-06)
**Date:** 2026-10-06
**Relates to:** #79 (v0.3.0 release audit), ADR-0001 (the module carried
mikroview's OIDC package over), ADR-0013 (the same `oidc.Policy`)

## Context

`oidc.AllowIssuer` refused a shared public issuer -- `accounts.google.com`,
Entra's `common`, `organizations` and `consumers` endpoints,
`appleid.apple.com`, `login.live.com` -- whatever policy came with it.
That rule came over unchanged from mikroview's
`docs/decisions/multi-tenant-oidc.md` (`docs/design.md` §1.4), which
judged one claim restriction too easy to get wrong.

The rest of the package promised otherwise. `Policy.RequiredClaims`
documents `{"hd": ["example.com"]}` for a Google Workspace and
`{"tid": ["<tenant-guid>"]}` for an Entra tenant, and
`Policy.Restricted` was exported for a startup check that never called
it. An operator who followed those docs got a refusal at startup.

## Decision

Pattern: **tenant-restricted multi-tenant sign-in** -- the issuer is
shared, so the tenant claim is the access control, as Microsoft's
guidance for multi-tenant apps and Google's `hd` check both describe.

1. `oidc.AllowIssuerWithPolicy(issuer, policy)` accepts a self-hosted
   issuer as before. A shared issuer is accepted only when
   `policy.RequiredClaims` names its tenant claim with at least one
   value: `hd` for Google, `tid` for the Entra shared endpoints. Apple
   and Microsoft personal accounts carry no tenant claim and are always
   refused. The error names the missing claim.
2. It is checked at startup, twice: `oidc.New` checks `Config.Policy`
   against the configured URL and the issuer the discovery document
   names, and `gate.New` checks `Client.Issuer()` against
   `Deps.OIDCPolicy`, the policy enforced at every sign-in.
3. At sign-in, `Policy.Permit` refuses a token whose tenant claim is
   absent or carries another value, as it does for any required claim.
4. `AllowIssuer` stays, deprecated, as `AllowIssuerWithPolicy` with an
   empty policy; `Policy.Restricted` stays, deprecated and unused.

## Rejected options

- **Keep the blanket refusal.** It contradicts `Policy`'s documented
  purpose, and leaves operators on Google Workspace or Entra with no
  supported way in.
- **Accept a shared issuer under any restricting policy** (what
  `Restricted` measured). An email-domain or group rule is not a tenant
  pin: a personal account at a shared provider can hold a verified
  address at the organisation's domain without belonging to its tenant,
  and a groups claim says whatever each tenant at that provider makes it
  say.

## Consequences

- An operator using a shared issuer must pin the tenant in
  `RequiredClaims`, and pass the same policy to `oidc.Config.Policy` and
  `gate.Deps.OIDCPolicy`.
- A missing or misnamed claim is a refusal to start, not a silently open
  door; a token from another tenant is a refused sign-in.
- Pinning a value that itself covers the public -- the Entra tenant id
  shared by all personal Microsoft accounts -- is accepted as written:
  the check confirms a tenant is named, not which one.
