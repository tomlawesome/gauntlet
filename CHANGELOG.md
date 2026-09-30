# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-09-30

First release: the shared login library for birdcage and mikroview --
local accounts and roles, sessions, API tokens, TOTP with recovery and
reset codes, passkey storage, OIDC with a self-hosted-only policy, the
HTTP middleware in `gate/`, and the encrypted file backend in `persist/`
(G1-G6 of docs/design.md §5). Audited before release (#16); the GitHub
mirror `github.com/tomlawesome/gauntlet` carries the tag (#17).

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

- `persist.EncryptedFileBackend` (issue #18): AES-256-GCM with
  HKDF-SHA256, a fresh random salt and nonce per save, and the store's
  path as AAD, moved from mikroview's `internal/persist.EncryptedFileBackend`
  so a hand-edited or tampered accounts file fails to open in both apps.
  `NewEncryptedFileBackend(path, key)` takes raw key bytes (refusing one
  shorter than `MinKeyBytes`, 32, mikroview's own floor) rather than a
  key-file path or mikroview's `*retention.Key` -- reading the key file
  stays the application's job. The on-disk envelope and HKDF info string
  are unchanged from mikroview's, so an existing mikroview-written file
  loads here byte-for-byte; proved with a fixture written by mikroview's
  own code (`persist/testdata/mikroview-encrypted-fixture-v1.bin`,
  generated at mikroview gitlab/dev commit
  bb29f23eb5e9918fdd888a6d34640eb5b228a129). The plain single-file
  mechanics it wraps are an unexported `fileBackend`: gauntlet has no
  unencrypted file mode. Now the documented default for file-backed
  storage (docs/design.md §1.7, docs/security-by-design.md).

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
  message in `gateErrorMessages` (400/409 respectively) instead of
  falling through to the generic "unable to complete the request" --
  mikroview's matching map has neither entry either. See
  `gate/users_handler.go` and `gate/httpjson.go`'s header comments.
- `oidc.New` now refuses a multi-tenant issuer itself (the same check
  `oidc.AllowIssuer` runs), instead of relying solely on a caller's own
  startup check.
- `NewLoginLimiter` now returns an error (`ErrLimiterConfig`) for a
  threshold under one or a non-positive window, instead of building a
  limiter that refuses every login from the start.

### Security

- `POST /api/auth/totp/enrol` now takes `{"password": ...}` and
  re-checks it on the same per-account bucket as `totp/delete`: a
  session alone -- what a stolen cookie gives an attacker -- could
  previously plant an authenticator secret and take the only copy of
  the recovery codes, locking the real owner out at their next login.
  Mikroview's enrol screen must send the password when it moves onto
  gauntlet (#1202); its delete screen already does.
- `oidc.VerifyIDToken` refuses an ID token with an empty `sub`
  (`ErrNoSubject`): go-oidc does not insist on it, and every user of a
  provider that omitted it would have resolved to the one account keyed
  on `(issuer, "")`.
- `oidc.IsMultiTenantIssuer` recognises a listed public provider written
  with a trailing root dot (`https://accounts.google.com./`), which DNS
  and TLS treat as the same host; before, that spelling passed the
  startup refusal.
- CI: protected refs get their own dependency and build cache
  (`cache:key:prefix: $CI_COMMIT_REF_PROTECTED`), so a merge-request
  pipeline can no longer seed the cache a `dev` pipeline -- which
  carries the protected mirror key in its environment -- builds its
  tools from.
- `LoginLimiter` keeps a real account's counter apart from the capped
  map of addresses and unknown names (#19): keyed by account ID, never
  evicted, so no flood of made-up names can reset it; and a login
  lockout is saved on the account (`User.LoginLockedUntil`) as it begins
  and clears, so a restart does not lift it. New `ReserveAccount`/
  `ReleaseAccount`, `ReserveRecheck`/`ReleaseRecheck`, `SetLog` and the
  `AccountLockouts` interface, which `*Store` implements; `gate` uses
  them. The capped map drops every expired key before evicting a live
  one.
- `OpenStore` refuses an accounts document with more than one admin, or
  with accounts but none of them admin, as it refuses one that will not
  parse; a reload that finds either is ignored and logged.

- `VerifyPassword` now refuses, before hashing, a stored hash whose
  cost settings or lengths are outside what this module writes (with
  4x headroom). A corrupt or tampered hash could previously crash the
  check and leave a hashing slot taken, so enough of them stalled every
  later login, or force an unbounded Argon2id computation.
- `ReserveAccount` now honours a persisted lockout ending more than one
  window past the attempt that would have set it for one window from
  now, rather than wiping it outright -- it previously let a still-valid
  lockout through the moment the login window was shortened across a
  restart.
- The file backend's `Save` now holds an exclusive lock on a sidecar
  `.lock` file for its whole read-compare-write, so a CLI tool and a
  running server saving against the same version can no longer both pass
  the check and both "succeed", with the later one silently discarding
  the earlier write.
