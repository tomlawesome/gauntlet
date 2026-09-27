# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

- Repository skeleton: licence, agent and contributor docs, the design
  document and its ADR, and CI (build/vet/test with coverage floors,
  golangci-lint, gitleaks, govulncheck, licence check).
- `persist` package: the `Backend`/`VersionReader` storage interface and
  a `Memory` backend for tests, copied from mikroview's
  `internal/persist`.
- `oidc` package: the OIDC/SSO relying-party layer -- provider discovery,
  Authorization Code + PKCE, ID token verification, the self-hosted-only
  `AllowIssuer`/`IsMultiTenantIssuer` policy and the sealed `FlowState`
  cookie codec -- moved unchanged from mikroview's `internal/oidc`.
  Depends on `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2`
  (owner-approved, AGENTS.md). `internal/testutil` carries the fake OIDC
  provider used by its tests, and by `gate`'s once that package exists.
- Sessions, API tokens and the login limiter, copied from mikroview's
  `internal/auth/{session,token,ratelimit}.go` with names kept.
  `SessionStore` has one constructor, `NewSessionStore(ttl,
  maxLifetime)`, replacing mikroview's two; sessions stay in-memory only
  (docs/design.md §1.7). `TokenStore`'s `TokenOptions.Kinds` replaces
  mikroview's hard-coded `TokenKind.Valid()`: a token whose kind is not
  registered is kept in its document and logged, but never
  authenticates, so a caller-specific kind (mikroview's `droplist-pull`)
  can be registered without a change here. `internal/evict` (`Batch`,
  `Target`, `DownTo`) bounds `LoginLimiter`'s tracked-key map, copied
  from mikroview's `internal/evict`.
- Second-factor data and stdlib flows (issue #5): TOTP enrolment and
  sign-in (`SetPendingTOTPSecret`, `ConfirmTOTP`, `VerifyAndRecordTOTP`,
  `ClearTOTP`, RFC 6238/4226 on stdlib `crypto/hmac`+`crypto/sha1` only);
  recovery codes (`GenerateRecoveryCodes`, `GenerateRecoveryCodesIfAbsent`,
  `BurnRecoveryCode`, Argon2id-hashed, single use); the admin-issued
  password reset code (`IssueResetCode`, Argon2id-hashed, 24-hour,
  single use -- `Store.Authenticate` already redeemed a live one from
  G2 onward); passkey storage methods with no WebAuthn dependency
  (`AddPasskey`, `RenamePasskey`, `DeletePasskey`,
  `RecordPasskeyAssertionIfFresh`, `ClearPasskeys`,
  `ClearAllSecondFactors`, `PasskeyCount`). Every mutating method rolls
  back its in-memory change on a backend write failure.
- Runnable examples (`example_test.go`, `persist/example_test.go`) and a
  README "Using gauntlet" section for apps adopting the module.
