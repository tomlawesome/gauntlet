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
- `gate` package (issue #7): `Config`, `Deps`, `New`, `Gate`, `Protect`,
  `Handle`, `Exempt`, `Routes`, `UserFromContext`, `TokenFromContext`,
  `RequireRole` and the `Auditor` interface -- mikroview's
  `internal/api/{auth,tokens,oidc}.go` turned into configuration
  (docs/design.md §1.5). `Routes` serves the full mikroview route table:
  session/register/login/logout/logout-all/password, the two-step
  second-factor login (`POST /api/auth/login/factor`, sealed
  pending-login cookie, TOTP code or a recovery code), TOTP enrol/
  confirm/delete plus the admin clear route, recovery-codes regenerate,
  the admin reset-password route, the OIDC login/callback/link trio
  (404 when `Deps.OIDC` is nil), and the users/tokens admin endpoints.
  `Config.ProductName` is required (used in the TOTP enrolment URI,
  fails closed in `New` if empty); `Config.LoginPath` is where a failed
  OIDC callback redirects with `?ssoError=`. Passkey/WebAuthn routes are
  deferred to G8. Includes mikroview's own fix for a MustChangePassword/
  second-factor door deadlock and its machine-readable auth-gate header
  (gitlab/dev 683704c4), generalized to a non-mikroview-branded name.

### Changed

- `gate` hardening beyond mikroview's own behaviour (issue #15): a
  failed token revocation on user delete now answers 500 with a JSON
  error body naming the account, instead of mikroview's 200 with
  `tokensRevoked=0` -- indistinguishable on the wire from "this user
  held no tokens" -- and the failure is recorded in the audit detail
  too. `decodeJSONBody` rejects a request body carrying an unrecognized
  field or data left over after the JSON value (`DisallowUnknownFields`
  plus a trailing-data check), 400 either way; mikroview accepts both
  silently. `ErrSingleAdmin` and `ErrCannotDeleteAdmin` get their own
  message in `gateErrorMessages` (409/400 respectively) instead of
  falling through to the generic "unable to complete the request" --
  mikroview's matching map has neither entry either. See
  `gate/users_handler.go` and `gate/httpjson.go`'s header comments.

### Security

- `VerifyPassword` now refuses, before hashing, a stored hash whose
  cost settings or lengths are outside what this module writes (with
  4x headroom). A corrupt or tampered hash could previously crash the
  check and leave a hashing slot taken, so enough of them stalled every
  later login, or force an unbounded Argon2id computation.
