# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

- `persist.Encrypt(backend, key, persist.EncryptOptions{Label: "accounts"})`
  wraps any `persist.Backend` so every document is sealed before the
  backend stores it and opened after it is read: the AES-256-GCM
  envelope `persist.EncryptedFileBackend` has used since #18 (HKDF from
  the application's key of at least 32 bytes, a fresh salt and nonce
  per save, the label authenticated with the document), stored through
  the backend as the JSON text `{"sealed": "<base64>"}` so a `text`
  column or a JSON-validating backend holds it unchanged (#50,
  [ADR-0005](docs/adr/0005-encryption-at-rest-on-every-backend.md)). A
  dump or backup of the database then carries no TOTP secret and no
  passkey public key, and a document altered in the database fails to
  open rather than being read. `EncryptedFileBackend` is now this
  wrapper over the plain file and is otherwise unchanged; files it
  wrote before still open, and still open in mikroview.
  `EncryptOptions.MigratePlaintext` accepts a document the backend
  already holds in the clear and seals it in place on the first load,
  for the one release that introduces the wrapper. The new
  `persist.AtRest` capability (`ProtectedAtRest() bool`) is how a
  backend says a copy of its storage carries no plaintext;
  `persist.Encrypted`, `EncryptedFileBackend` and `Memory` implement it.
- Ways to unlock a sign-in disabled after 50 failures in a row (#44).
  `POST /api/auth/users/{id}/unlock` lets an admin lift another
  account's disable, lockout and count of lockouts; it answers 200
  whether or not anything was locked. On the admin's own account, from
  a session they still hold, it takes a body with their password and a
  current TOTP or recovery code (`UnlockSelfRequest`): 400 without
  them, 401 for a wrong one, each counted on the account's password
  re-check budget (429 once spent); the session alone unlocks nothing.
  It calls the new `LoginLimiter.UnlockLogin`, which also
  clears the limiter's own count of recent guesses; applications with
  their own unlock path should call it rather than `Store.UnlockLogin`.
  When the store opens with the admin disabled and no admin left who
  could unlock it, it announces a one-time unlock code, like the setup
  code: through the new `Options.OnUnlockCode` (`UnlockCodeHandler`,
  `UnlockCodeFunc`), or else as one Warn line on `Options.Log`. A CLI
  that opens the store should pass a hook that does nothing, as it
  does for `OnSetupCode`. `POST /api/auth/unlock` takes the admin's
  username and the code (`Store.CheckUnlockCode`,
  `ErrUnlockCodeInvalid`), and only lifts the disable: the admin then
  signs in with their existing password and second factor. The code
  works once, and stops working if the admin is unlocked any other
  way. The accounts document is unchanged.
- The known-browser allowance (#44): a browser that completes a sign-in
  now gets a `gate_known_browser` cookie (`HttpOnly`, `SameSite=Lax`,
  `Secure` per `SecureCookie`, path `/api/auth/login`, 45 days), set at
  every session issue and replaced at each one, and while the account
  is locked out, or the client's address is at its limit, that browser
  keeps an allowance of its own -- the limiter's attempts per window --
  so a stranger who knows a username can no longer lock its owner out.
  It is refused once the account is disabled, and every failure through
  it counts toward the 50. The cookie's value is 32 random bytes; the
  account keeps only its SHA-256 (new `User.KnownBrowsers`,
  `KnownBrowser`), at most `MaxKnownBrowsers` (3) per account, the
  oldest evicted, each for `KnownBrowserLifetime` (45 days) from its
  latest sign-in there, checked on the server. Sign out everywhere and
  an admin's reset code forget every browser; a password change, an
  unlock and the forced change after second-factor failures do not.
  New API: `Store.RememberBrowser`, `Store.ClearKnownBrowsers`,
  `Store.KnowsBrowser`, `LoginLimiter.ReserveKnownBrowser` and
  `ReleaseKnownBrowser`. `Store.List` blanks each hash. An application
  with its own sign-in path should call `RememberBrowser` where it
  issues a session; gate does so in `issueSession`.
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
- Passkeys (G8, #20, [ADR-0004](docs/adr/0004-passkey-ceremony.md)).
  The new `gauntlet/passkey` package runs the WebAuthn ceremony:
  `passkey.New(passkey.Config{PublicURL, DisplayName})` builds the
  relying party from the application's own public URL, and a missing or
  unusable one (`unset`, `ip`, `insecure`) is a reported status, not a
  startup failure. Wire it into `gate.Deps.Passkeys` to serve
  mikroview's passkey routes from `gate.Routes`: list, register
  begin/finish (begin re-checks the password, as TOTP enrolment does,
  and refuses an account with no local password), rename, delete,
  `POST /api/auth/login/factor/begin`, an
  `assertion` on `POST /api/auth/login/factor`, and the admin
  `DELETE /api/auth/users/{id}/passkeys`. Left nil, every passkey route
  answers 404 and nothing links the WebAuthn library. Each login
  challenge is usable once, and a pending login (the cookie a password
  step sets when a second factor is needed) is spent by the sign-in
  that completes it, whichever factor completes it. A registration
  ceremony is spent by the first finish the library accepts, so one
  begin (one password entry) stores at most one passkey; a finish the
  library refuses (wrong origin, bad signature) can still be corrected
  inside its five minutes. Sealed cookies (the passkey ceremonies, the
  pending login, the SSO flow) open only in the exact base64 spelling
  they were written in. The root package
  gains the seam both sides use (`PasskeyCeremony`, `PasskeyAssertion`,
  `PasskeyStatus`, and `ErrPasskeyCeremonyInvalid`, which marks a dead
  ceremony: expired, tampered with, from the other ceremony or already
  used).
- `Store.AnyPasskeysExist()` reports whether any account holds a
  passkey (#20, owner's answer to question 5), so an application can
  refuse to start when passkeys exist but its relying party is not
  ready. gauntlet itself never refuses; the decision is the
  application's.
- `POST /api/auth/login` lists `passkey` (first) in `secondFactor`, with
  `passkeyOrigin`, when the account holds a usable passkey;
  `GET /api/auth/session` gains `passkeys: {count, status, origin}` when
  the application wires passkeys; `GET /api/auth/users` rows gain
  `passkeyCount`.
- New dependency for the `passkey` package (G8, #20; owner
  approval 2026-09-30): `github.com/go-webauthn/webauthn` v0.18.2
  (BSD-3-Clause), the newest release, with no advisory in OSV or the Go
  vulnerability database as of 2026-10-02. It brings
  `github.com/go-webauthn/x` and eight more modules (CBOR, TPM, JWT,
  msgp, mapstructure, uuid, float16, fwd). Only `gauntlet/passkey`
  imports it, so an application that never imports that package never
  compiles it in. Two of its packages carry other permissive licences,
  `go-webauthn/x/crypto/secp256k1` (ISC) and `go-webauthn/x/revoke`
  (BSD-2-Clause), so the licence policy now allows both (owner decision
  2026-10-02).
- Signed-in users can see and end their own sessions (#48; ASVS 7.5.2).
  `GET /api/auth/sessions` lists every live session on the caller's
  account, newest first: when it signed in, when it was last used, the
  address and browser it signed in from, and which one is this browser.
  It shows at most 100 rows and a `total` of all of them. Each row is
  named by a one-way `ref`, never the session ID, which is the cookie.
  `DELETE /api/auth/sessions/{ref}` ends one; ending this browser's own
  session clears its cookie. It asks for no password, for any account:
  signing out is a safe direction (owner decision 2026-10-02, recorded
  as a deviation from ASVS 7.5.2). It ends the gauntlet session only,
  not the sign-on provider's. Any ref that is not one of the caller's
  live sessions answers 404. There is no admin view of other people's
  sessions. The list lives in memory like the sessions themselves, so a
  restart empties it. In the core package, `Session` gains `Client` and
  `LastUsedAt` and a `Ref()` method, and `SessionStore` gains
  `CreateFrom`, `ListForUser` and `RevokeRef`; a browser's agent and
  address are kept cleaned and capped at `MaxSessionUserAgent` (256)
  and `MaxSessionAddress` (64) bytes. All additions; nothing existing
  changes.

### Changed

- **Breaking.** `OpenStore` now refuses a backend that stores the
  accounts document in the clear -- one that does not implement
  `persist.AtRest`, which is every application database backend
  written so far -- with the new `ErrPlaintextAtRest`, unless
  `Options.AllowPlaintextAtRest` is set (#50,
  [ADR-0005](docs/adr/0005-encryption-at-rest-on-every-backend.md)).
  The document holds every account's TOTP secret, which cannot be
  hashed, so the choice is refuse or warn, and a warning is read once
  while a backup is copied for years. `persist.Memory`, `Encrypt` and
  `EncryptedFileBackend` need no permission; a nil backend stores
  nothing. `OpenTokenStore` is unchanged: the tokens document holds
  only hashes of random values. What each application must do:
  provision a key file of at least 32 random bytes (`persist.MinKeyBytes`;
  mikroview's retention key material already qualifies, birdcage has
  none yet and gains `BIRDCAGE_AUTH_KEY_FILE`), wrap the accounts
  backend -- and, recommended, the tokens backend -- in
  `persist.Encrypt` with a fixed `Label` per store, and for the release
  that first ships the wrapper set `MigratePlaintext: true` where a
  plaintext document already exists (mikroview's Postgres `auth` row);
  the first start seals it in place and the option can then be removed.
  A backend that wraps another (a write-behind queue) must forward
  `ProtectedAtRest`. Take a copy of the plaintext document before
  upgrading: an older gauntlet reads a sealed document as an empty
  store and its first write would overwrite it, while this build
  refuses a sealed document that reaches a store unwrapped. The
  envelope does not change the accounts document's own version (#44
  does, below): it sits below it.
- A second factor (TOTP or a passkey) is now always required for every
  local-password account; `gate` no longer offers a way to turn the
  forced-enrolment door off (#49). `gate.Config.RequireSecondFactor` is
  deprecated and ignored -- it stays only so applications that already
  set it still compile. An application that was relying on the door
  being off (the field's old default) now sees it on unconditionally:
  every local-password account, including ones created before this
  change, is stopped at the door until it enrols a factor, reaching
  only the enrolment routes until then. This closes the gap behind the
  8-character password minimum (`store.go:39`): NIST SP 800-63B-4
  §3.1.1.2 allows 8 characters only behind a mandatory second factor,
  and the minimum stays 8 rather than rising to 15 because the door can
  no longer be left off (#49, `docs/security-by-design.md`).
- **Breaking.** `gate.New` now refuses a `Deps.Sessions` store whose
  idle timeout exceeds the new `MaxSessionIdle` (1 hour), whose
  lifetime ceiling exceeds the new `MaxSessionLifetime` (24 hours), or
  which has no ceiling at all -- NIST SP 800-63B-4's AAL2 session
  limits (§2.2.3, §5.2), adopted by the owner on 2026-10-02 over the
  consumers' previous, longer values (#51). `SessionStore` itself is
  unchanged and still accepts any values; the new
  `(*SessionStore).Limits` method and the two exported constants are
  what `gate.New` checks them against. Mikroview and birdcage both
  pass 24 h idle / 7-day ceiling today and will fail at start-up until
  they change those values to within the new caps.
- The session cookie is hardened (#47; ASVS 3.3.1, 3.3.3, 7.2.4; NIST SP
  800-63B-4 §5.1.1). While `gate.Config.SecureCookie` is true the cookie
  is written and read as `__Host-` plus `CookieName`, which makes a
  browser refuse it unless it is `Secure`, has no `Domain` and is on
  path `/`; under plain HTTP the bare name is kept, since a browser
  drops a `__Host-` cookie that is not `Secure`. Its `Max-Age` is now the
  session store's lifetime ceiling (24 hours at most, #51) instead of a
  fixed 30 days, so the browser forgets it when the session can no
  longer be valid. `gate.New` logs one warning naming `SecureCookie`
  when it is left false, and refuses a `CookieName` that already starts
  with `__Host-` or `__Secure-`. A login -- password, second factor or
  SSO -- from a browser that still holds a live session for the same
  account now ends that session before issuing the new one; another
  account's session in the same browser is left alone. Not breaking for
  mikroview or birdcage: neither reads the session cookie by name
  outside the code `gate` replaces, and neither uses a prefixed name.
  What each app should expect: with TLS on, browsers signed in before
  the upgrade hold the old, unprefixed cookie and are simply asked to
  sign in again (an in-memory session dies with the restart anyway).
- Login lockouts now escalate, and too many failures in a row disable
  an account's sign-in (#44). Each lockout lasts three times the one
  before, from the attempt that starts it: 5, 15, 45, 135, 405 and 1215
  minutes at 5 attempts per 5 minutes, then 24 hours each. The first
  lockout now runs a full window from its last attempt, not until the
  oldest attempt in the window ages out. 50 failures in a row
  (`MaxConsecutiveLoginFailures`), password and second-factor steps
  together, disable the account's local sign-in: the right password is
  then refused exactly as during a lockout, with no end, until
  it is unlocked (see the unlock route and code under Added). Only a
  completed sign-in or a new password resets the count, not a correct
  password alone and not a lockout running out. A password the owner
  sets does not lift a disable; a reset code an admin issues
  (`IssueResetCode`) does. Applications that issue a session
  themselves after `ReserveAccount` should call the new
  `LoginLimiter.SignedIn` in place of `ReleaseAccount` when the sign-in
  completes; `gate` does. Five failed second-factor steps in a row --
  wrong codes or refused passkeys, which only someone with the password
  can make -- now set `MustChangePassword`, so the owner must change the
  password at their next sign-in (`LoginLimiter.SecondFactorFailed`),
  and the same save signs the account out everywhere, so only a fresh
  sign-in with both factors reaches the change-password door. That
  door's message no longer says an administrator reset the account.
  That run is kept in memory and starts again after a restart. Still
  one save as a lockout starts and one as it clears, never one per
  guess.
- The accounts document is now version 4 (#44): version 3 added
  `loginLockoutCount` and `loginDisabledAt`, and version 4
  `knownBrowsers`. Version-1, -2 and -3 documents open unchanged with
  the fields they lack empty, and are written as version 4 on their
  next save; no migration is needed. No earlier build -- v0.1.0, or a
  development build that wrote version 3 -- can open an accounts
  document once this version has saved it, so keep a copy before
  upgrading if a rollback is possible.
- A pending login -- the cookie `POST /api/auth/login` sets when a
  second factor is needed -- now completes exactly one sign-in (#20,
  ruling R2). Before, the same cookie could be sent again within its
  five minutes with another valid code, recovery code or passkey
  assertion, and each one opened a session. A repeat now gets 401
  "sign in again" at `login/factor` and `login/factor/begin`; a wrong
  code still leaves the pending login usable. A spent pending login
  (and a spent passkey challenge) is remembered for one lifetime past
  the moment it stops being accepted, so two requests reading the clock
  either side of that moment cannot reopen it. A pending-login cookie
  sealed by an earlier version is refused once, and the user signs in
  again.
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
- The accounts document is now version 2: it adds `sessionsEndedAt`
  (#28), and any change to what a stored document carries now raises
  its version (ADR-0002 decision 1). Version-1 documents, from v0.2.0
  or mikroview, open unchanged with the new field empty and are written
  as version 2 on their next save; no migration is needed. v0.2.0
  cannot open an accounts document once this version has saved it, so
  keep a copy before upgrading if a rollback is possible. The tokens
  document stays version 1.
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
  to learn whether it has an authenticator app (#28). Its passkey
  count still takes one store read per account.
- The release job's `release-cli` image is pinned by tag and digest
  instead of `:latest` (#28).
- A request whose `Authorization` header is not a well-formed
  `Bearer <token>` -- another scheme such as `Basic`, a bare `Bearer`,
  a tab for the space -- is refused with 401 and
  `WWW-Authenticate: Bearer realm="gate"`, as an unknown token is.
  Before, the header was ignored and the request went through on its
  session cookie. A request with no `Authorization` header is
  unchanged (#41).
- Linking the admin to SSO no longer ends a login lockout whose save
  had failed (#28). The link used to record itself in
  `PasswordChangedAt`, which the login limiter reads as a password
  change. A new stored field, `User.SessionsEndedAt`, now records when
  an account's sessions were ended -- by a new password, a reset code or
  an SSO link -- and `PasswordChangedAt` moves only when the password
  does. `User.SessionCutoff()` returns the later of the two, and the
  gate refuses a session issued before it. Documents written before this
  field existed, by gauntlet or mikroview, record a link in
  `passwordChangedAt` only, and those sessions stay ended.

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
