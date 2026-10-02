# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

- `docs/api/auth.yaml` (OpenAPI 3.1) describes every route `gate.Routes`
  serves -- each request body, response body and status -- as the one
  copy a frontend can build against (ADR-0002, #22). `docs/design.md`
  §1.5 now points at it instead of listing the routes by hand.
- CI now checks for breaking changes (#22). A test calls every `gate`
  route and fails if a request, response or status code is not
  described in `docs/api/auth.yaml`, or if a route exists in only one
  of the two. A second job, `lint:apidiff`, fails if an exported Go
  identifier has been removed, renamed or changed since the last
  release tag, unless `VERSION` moves to a new major number (0.x to
  1.0) -- a minor bump such as 0.1 to 0.2 does not count. Additions
  pass. Neither tool enters the library's own dependencies. A field
  renamed in both the handler and `auth.yaml` still has to be caught in
  review.
- `TokenStore.Create` now refuses a token name longer than 64 bytes
  (`MaxTokenNameLen`), or one that contains control characters or
  invisible formatting characters (such as zero-width spaces),
  returning the new `ErrTokenNameInvalid` (#24). Code that passes
  user-typed names should handle this error. An empty name is still
  allowed. Device ids already followed this rule.

### Changed

- The first admin is created only with a one-time setup code the server
  announces when it starts with no accounts (#37, ADR-0003; owner,
  2026-10-01). An empty store is not only a fresh install -- a deleted
  accounts file, a wrong path or a bad restore all start a server with
  none -- and until now the first visitor took admin. The store makes an
  80-bit code, keeps only its hash in memory, and hands it to the new
  `Options.OnSetupCode` or, when that is nil, writes it as one `Warn`
  line on `Options.Log`; `POST /api/auth/register` now needs it as
  `setupCode` (`401` when wrong, counted against the address by the
  login limiter, `429` at the limit) and checks it before hashing the
  password. It is used up once any account exists and dies with the
  process: a lost code means restart and read the log. SSO can no
  longer create the first account: the two `/api/auth/oidc/*` routes
  answer `503` "setup required" like everything else until the first
  admin exists, and `FindOrCreateOIDCUser` refuses on an empty store
  with the new `ErrSetupRequired`. The first admin is local and links
  SSO afterwards. New: `Store.CheckSetupCode`, `ErrSetupCodeInvalid`,
  `SetupCodeHandler` and its `SetupCodeFunc` adapter;
  `Store.Register` is unchanged and is the host-side primitive gate
  calls after the check. A frontend's first-run screen collects the
  code and hides the SSO button while `setupRequired` is true.
- Both stored documents now carry a top-level `version`, and the tokens
  document is an object, `{"version": 1, "tokens": [...]}`, instead of
  a bare list (#29, ADR-0002 decision 1). Documents written by v0.1.0
  open unchanged, as version 1, and are written in the new shape on
  their next save; v0.1.0 cannot open a tokens document once this
  version has saved it, so keep a copy before upgrading if a rollback
  is possible. A document with a version newer than the running build
  reads is refused at startup with an error naming both versions, is
  not applied (and is logged once) when it appears under a running
  server, and is never saved over by a write -- so a rolled-back build
  cannot load it and silently drop what only the newer build knows,
  such as TOTP secrets or passkeys. There is no migration code yet; it
  is added with the first format change that needs one.
- If the CLI and the running server save at the same moment, both
  changes are now kept (#21). Before, the second save to land wrote its
  whole accounts or tokens document on top of the first, and the first
  change was gone with only a log line to say so. Now the second write
  loads what the first saved, makes its own change again on top of
  that, and saves the result, so both changes survive. This covers both
  the accounts store and the token store, which had no such protection
  before.
- A token revoked with the CLI now stops working on the running server
  at once. Before, it kept working until the server restarted.
  `TokenStore` now re-reads its document before every read, write and
  `Authenticate` when another process has changed it, as `Store`
  already did.
- If an account is deleted, or a token revoked, by another process
  while a login or token use is in progress, that login or token use is
  now refused. Before, it could succeed using the old copy held in
  memory.
- A save conflicts when another process saved the same file after this
  one loaded it. After five conflicts in a row for the same write -- a
  script writing in a loop, not an ordinary CLI command -- the write
  gives up with the new `ErrSaveConflict` and changes nothing; the
  caller can try again. The whole write, retries and reloads included,
  is held to one five-second limit (the limit one save had before),
  since it runs while every login and signed-in request on that store
  waits. The shipped file backends cannot be interrupted mid-call, so
  on a hung mount the limit only stops another retry from starting, not
  a call already in progress.
- When a save is retried, its rules are checked again against the newer
  file: registration still open, only one admin, username not taken,
  recovery codes not already issued. A retry can never break them. A
  write that finds nothing to change -- revoking a token already gone,
  say -- now re-checks that decision against the saved document too, so
  it cannot miss a token another process just issued; such a call can
  now return an error if that re-check fails, where before it always
  returned nil.
- A write that meets an accounts document this store refuses to load
  (two admins, say) now fails instead of saving over it. One that finds
  the document removed from under it -- a file deleted or moved aside
  while the process ran -- fails with the new `ErrDocumentRemoved`
  instead of recreating the file from that one write, which for an
  accounts file could mean a file with no admin that the next start
  refuses. The single-admin rule is checked on every save as well as
  every load, so no write can produce such a file. The first such
  failure after each removal logs one error naming the store and file
  and saying writes are refused until the file is restored or the
  process restarts; reads carry on from memory (#39). To recover,
  put the file back, or restart to start afresh.
- `VerifyAndRecordTOTP` and `RecordPasskeyAssertionIfFresh` now accept a
  code or passkey only if they could save the record that stops it
  being used twice. Before, a correct TOTP code was accepted even when
  that save failed, so the same code could log in a second time. Now
  the call returns `ok == false` and the error, as reset codes and
  recovery codes already did. Callers that allowed a login when `ok`
  was true but an error was also returned should remove that path: that
  combination no longer occurs. The one exception is a passkey that has
  never counted and presents 0 (most platform passkeys): that save
  protects nothing, since the app's single-use challenge is what stops
  a replay, so it is best-effort like `LastLogin` -- if it fails, the
  login is accepted, the last-used time is kept in memory and the
  failure is logged (#36). The app must claim that challenge before
  calling.
- `RecordPasskeyAssertionIfFresh` refuses a passkey whose stored count
  is above zero and that now presents 0, as the WebAuthn spec treats
  it: a possible cloned authenticator (#36). Before, any count of 0 was
  accepted.
- Persistence errors from store writes no longer carry the
  `saving accounts:` / `saving API tokens:` prefix; they name the store
  and backend themselves, and `errors.Is` against the package's errors
  works as before.
- `persist.SaveWithRetry` is deprecated and no longer used by the
  stores; it stays exported for compatibility.
- Smaller fixes from the v0.1.0 audit (#24):
  - `User.HasActiveTOTP` and `HasSecondFactor` now answer correctly on
    the copies `Store.List` returns: `HasActiveTOTP` read false for
    every listed account, and `HasSecondFactor` read false for a
    passkey-only account even though `Get` said true.
  - A password login saves `LastLogin`, and a token use saves its
    last-used time, at most once an hour each, compared against the
    saved value, as `LastLogin` already was -- a token used more often
    than hourly had been saving its last use once and then looking
    idle. The value in memory is always current; a crash can lose up to
    an hour of it.
  - `TokenStore.List`, `ByKind` and the saved document order tokens
    created in the same instant by ID, so the list no longer reshuffles
    on refresh.
  - `OpenStore`'s "no admin" refusal counts empty (null) entries
    separately from real accounts in its message.
  - A generated SSO username always fits the username length limit.
  - Less password hashing under the accounts store's lock: a new SSO
    account, burning a recovery code and `GenerateRecoveryCodesIfAbsent`
    no longer stall other logins while they hash, and
    `GenerateRecoveryCodesIfAbsent` skips the hashing entirely when the
    account already has codes. `BurnRecoveryCode` no longer changes a
    copy another caller is reading.
  - Removing expired sessions no longer pauses every login and session
    check while the whole session store is scanned in one go; each
    login now removes up to 4 expired sessions instead. On a quiet
    server, expired sessions may therefore stay in memory longer, but
    they still never authenticate. Signing out everywhere, and other
    per-user session revokes, no longer walk every session either: the
    store now keeps each user's session IDs alongside the sessions and
    revokes from that list.
  - A login lockout that could not be saved is saved again by a later
    refused attempt on that account (at most every 30 seconds), so a
    backend that recovers inside the lockout ends up holding it and a
    restart no longer lets more guesses through. Clearing a lockout
    whose save failed is retried the same way, every 30 seconds, while
    the stored lockout is still in the future, so a correct password is
    not kept out once storage recovers -- within one process; a restart
    inside that window still waits out the lockout. A stored lockout
    ending more than one window away no longer tries a save on every
    refused guess, only once per 30 seconds.
  - Setting a new password (`SetPassword`) or issuing a reset code
    (`IssueResetCode`) ends any login lockout on the account, so its
    owner can sign in with the new password or the code at once. The
    limiter stops counting guesses made before the change. Linking the
    admin to SSO, whose password keeps working, leaves its lockout in
    place.
  - Internal tidying in `gate`, plus test and documentation fixes. HTTP
    requests and responses are unchanged.
- A failed password change, and a failed SSO login or link, are now
  logged, as the API document already said (#26).

### Fixed

- `POST /api/tokens` with a name the token store refuses answers 400
  with the reason, instead of 500 "unable to create token" (#25).
- `POST /api/auth/users` answers 503 with the same "no persistent
  storage" message as register when the deployment has no storage set
  up, instead of 500 (#25).
- `DELETE /api/tokens/{id}` answers 500 and logs the error when the
  revoke cannot be saved, instead of 404 "already revoked" while the
  token kept working; 404 is now only for a token that does not exist
  (#26).
- `POST /api/tokens` refuses a name made only of spaces with 400, like
  an empty one (#26).
- `POST /api/auth/login/factor` answers 500 and logs the error,
  without counting the attempt toward the login lockout, when a
  correct authenticator code or recovery code cannot be recorded as
  used; `POST /api/auth/login` does the same for a reset code. Before,
  both answered 401 and counted toward the lockout (#26).
- `POST /api/auth/totp/confirm` answers 409, as the API document
  already said, when no enrolment is pending, instead of 400; and when
  the authenticator is confirmed but recovery codes could not be
  generated, its 500 body is JSON `{"error": ..., "totpActive": true}`
  so a frontend can tell the factor is on (#26).
- `docs/api/auth.yaml` now says a token's kind is whatever the
  application registered (`api` and `ingest` by default), not only
  `api` or `ingest` (#26).
- An account locked out by wrong passwords and then reset -- from the
  command line (`SetPassword`) or with a reset code -- can sign in from
  the address the wrong guesses came from straight away. Before, the
  lockout ended but the per-address limit still answered 429 for up to
  five minutes, which read as the reset having failed (#32). Only that
  account gets past the address limit, only when both the address and
  the account itself reached their limits before the reset, one attempt
  at a time, and only until its sign-in finishes or a guess fails. For
  an account with a second factor the right password spends the pass
  and the code step that follows is let through on the same sign-in, so
  a guess sent in between cannot take it. Other accounts tried
  from that address are still refused, and so is an account that was
  never locked out and only changed its own password. New
  `LoginLimiter.AllowAfterReset`, `ReleaseAfterReset` and
  `EndAfterReset` carry this.
- The token-name and device-id errors say the limit is 64 bytes (fewer
  characters for non-Latin letters), not 64 characters, so a name
  refused for length no longer seems to meet the limit it names (#28).
- `Store.AddPasskey` copies the passkey it is given and the one it
  returns, so a caller reusing either buffer cannot change the stored
  credential (#28).
- A returning SSO sign-in saves `LastLogin` at most hourly, as a
  password login does, instead of rewriting the accounts document on
  every sign-in; `GET /api/auth/users` no longer re-reads each account
  after listing them (#28).
- The release job's `release-cli` image is pinned by tag and digest
  instead of `:latest` (#28).

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
