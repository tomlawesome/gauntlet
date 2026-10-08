# Design: `gauntlet`, the shared authentication module

**Status:** describes gauntlet as built, up to v0.3.0 (v0.1.0 shipped
2026-09-30, v0.2.0 2026-10-03). Originally proposed 2026-09-26 as the
API and layout that birdcage's
[ADR-0005](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/adr/0005-shared-auth-module.md)
left to this design. **Issue:** #8 (build `gauntlet` and use it).
**Later consumer:** mikroview #1202. Sections 5 (build plan) and 6
(owner decisions) are history: kept as the record, and complete.

The original design was read against mikroview at its `dev` of the time
(`internal/auth`, `internal/oidc`, `internal/api/{auth,oidc,tokens,
webauthn,server,clientip}.go`, `internal/persist`, `internal/logging`,
`internal/evict`, `SECURITY.md`, `docs/decisions/multi-tenant-oidc.md`).
Where this document says "mikroview does X", that is where it was seen.
Mikroview and birdcage are separate repositories, so their file names,
line numbers and "today" behaviour are as read then, not re-checked
here.

## Summary

- One module, seven public packages. The four the design started with:
  `gauntlet` (accounts, sessions, tokens, hashing, rate limiting --
  mikroview's `internal/auth` with its names kept), `gauntlet/oidc`
  (mikroview's `internal/oidc`, unchanged), `gauntlet/persist` (the
  storage interface, plus the encryption wrapper and file backend both
  apps share) and `gauntlet/gate` (the HTTP middleware and handlers
  mikroview keeps in `internal/api`). Added since: `gauntlet/passkey`
  (the WebAuthn ceremony, G8), `gauntlet/blocklist` (the common-password
  list, #52) and `gauntlet/geoip` (the sign-in country, #54), plus
  `persist/persisttest`, a test suite an app runs against its own
  backend (#61).
- Three seams, as [ADR-0005](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/adr/0005-shared-auth-module.md) fixed them: storage is `persist.Backend`,
  copied method-for-method from mikroview so its existing backends
  satisfy it with no adapter; logging is `*slog.Logger`, which is what
  mikroview's `logging.New` already returns; eviction is a pure function
  and goes in as `gauntlet/internal/evict`, not an interface.
- Gauntlet saves accounts, tokens and the sign-in history each as one
  JSON document -- one file, or one database row -- rewritten in full on
  every save (a whole-document store). The documents hold mikroview's
  `User` and `Token` JSON, byte for byte, in the shape mikroview already
  stores, so its existing data loads unchanged.
- Each document has a top-level `version` (#29, ADR-0002 decision 1).
  Mikroview's documents load as version 1 unchanged. Gauntlet writes
  accounts as version 9 (#28, #44, #43, #59, #58, #55, #67), tokens as
  version 3 (#59, #74) and the sign-in history as version 3 (#53, #54,
  #55); `docversion.go` lists what each version added. A document newer
  than the running build is refused.
- Because every save rewrites every field, gauntlet's `User` must carry
  *every* field mikroview stores -- including TOTP, recovery codes,
  reset codes and passkeys -- or mikroview's move would silently drop
  them. So the data model for second factors was in v1 from the start,
  before the ceremonies were decided.
- Birdcage implements `persist.Backend` as one small table in its own
  database, wires `gate.Protect` in place of `requireAuth`, routes
  read-only API tokens to the existing `dashboardRoutes` mux, and keeps
  its agent tokens and client certificates exactly as they are.

## 1. Package layout and public API

```
github.com/tomlawesome/gauntlet
├── go.mod                      module github.com/tomlawesome/gauntlet; go 1.27
├── LICENSE                     (owner decision, see §6)
├── README.md  SECURITY.md  AGENTS.md  CHANGELOG.md  CONTRIBUTING.md
├── doc.go                      package gauntlet
├── user.go  password.go  session.go  token.go  ratelimit.go  username.go
├── totp.go  recoverycodes.go  resetcode.go  passkeys.go   (storage + stdlib logic)
├── id.go
├── lockout.go  addressban.go  knownbrowser.go  unusual.go  signins.go
│   mutate.go  docversion.go  ...   (later issues; one file per concern)
├── persist/                    Backend, Snapshot, ErrConflict, VersionReader, AtRest,
│                               Open, SaveWithRetry (deprecated), LoadDocument, Memory (tests),
│                               Encrypt, Encrypted, EncryptOptions (#50, ADR-0005),
│                               EncryptedFileBackend, MinKeyBytes (issue #18)
│   └── persisttest/            Run -- the suite an app runs against its own Backend (#61)
├── oidc/                       Config, Client, Identity, Policy, FlowState, StateCodec,
│                               AllowIssuer, IsMultiTenantIssuer
├── gate/                       Config, Deps, Gate, Protect, Routes, RequireRole,
│                               UserFromContext, TokenFromContext
│   └── contracttest/           tests that the handlers match docs/api/auth.yaml
│                               (its own go.mod, so the OpenAPI library stays out of gauntlet's)
├── passkey/                    Config, New, RelyingParty, ErrNotReady, ErrNoUsablePasskey
│                               (G8, ADR-0004; the one importer of go-webauthn)
├── blocklist/                  List, Parse, Embedded, Refresher, RefreshConfig, NewRefresher,
│                               DefaultURL, PwnedChecker (#52, #43, ADR-0007; the common-password list)
├── geoip/                      Config, New, Manager, Source, Status (#54, ADR-0008; the
│                               sign-in country, and the one importer of maxminddb)
├── cmd/pwlist/                 builds, signs, verifies and publishes that list (CI only)
├── internal/listsig/           the list's Ed25519 signature format
├── internal/evict/             Batch, Target, DownTo (copied from mikroview)
├── internal/hashcost/          Use, Cheap -- cheap Argon2id hashes for this
│                               module's own tests
├── internal/spent/             Set, New, Claim, Spent -- one-time-key tracking
│                               shared by gate and passkey
├── internal/testutil/          fake OIDC provider (mikroview's fake_provider_test.go)
├── internal/passkeytest/       fake WebAuthn authenticator (mikroview's webauthnfake_test.go)
├── docs/                       this file, using.md, the ADRs, api/auth.yaml and the rest
├── scripts/                    CI and release checks (API diff, licences, list age, coverage)
├── supply-chain/               the licence policy and coverage floors those checks read
└── testdata/                   old document fixtures (sign-in history versions 1-3)
```

`passkey/` (the WebAuthn ceremony, `github.com/go-webauthn/webauthn`) was
added in G8 (#20, [ADR-0004](adr/0004-passkey-ceremony.md)).
It is a leaf: `gate` reaches it only through the `gauntlet.PasskeyCeremony`
interface in the root, so an application that never imports it -- birdcage
-- never compiles the library in.

### 1.1 Why these boundaries

- **One core package, not several.** Mikroview's `internal/auth` is one
  package because `Store.Authenticate` reads `ResetCodeHash`,
  `LinkOIDCIdentity` clears TOTP and passkeys, and `DeleteUser` burns
  tokens. Splitting it would mean exporting internals for the sake of
  tidiness. Mikroview's move is then an import rewrite
  (`auth "github.com/tomlawesome/gauntlet"`) rather than a refactor.
- **`persist` holds the interface, plus one shared backend.** Mikroview's
  `FileBackend`, `PostgresBackend` and the write-behind wrapper serve
  six other stores there and stay in mikroview; Go's structural typing
  means they already satisfy gauntlet's interface (same four methods,
  same `VersionReader` extension) without moving. `EncryptedFileBackend`
  is the one exception (issue #18): both apps need the same
  authenticated-encryption file backend, so it moved into
  `gauntlet/persist` rather than staying duplicated, and gauntlet takes
  key bytes directly rather than a key file path -- reading the key
  file stays each application's job (§1.7). Since #50
  ([ADR-0005](adr/0005-encryption-at-rest-on-every-backend.md)) that
  backend is `persist.Encrypt` over the plain file, and the same wrapper
  goes over any application backend -- mikroview's Postgres blob,
  birdcage's table -- so the accounts document is ciphertext wherever
  it is stored, and `OpenStore` refuses a backend that would hold it in
  the clear unless the application says it accepts that
  (`Options.AllowPlaintextAtRest`). The one thing that does not
  carry across a package boundary is the sentinel `ErrConflict`, so
  mikroview's `internal/persist` will assign `var ErrConflict =
  gpersist.ErrConflict` when it moves -- one line, no data change.
  Gauntlet also ships a `Memory` backend for its own tests and for
  apps' tests.
- **`gate` is in the module.** [ADR-0005](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/adr/0005-shared-auth-module.md)'s survey counted the handlers
  and middleware as auth code, and they are where most of the pitfalls
  live (§4). Leaving them out would make birdcage rewrite 2,000 lines
  and put mikroview back on a fork. `gate` is mikroview's
  `internal/api/{auth,oidc,tokens}.go` with the mikroview-specific parts
  turned into configuration (cookie name, CSRF header value, route sets
  per token kind, audit sink, client-IP function). CSRF is another
  website tricking a signed-in browser into sending a request; a header
  that only the app's own frontend sends defeats it.
- **Eviction is not an interface.** `evict.DownTo` is a generic function
  with no state; the only caller inside the module is `LoginLimiter`. An
  interface over a pure function would be ceremony. It is copied into
  `internal/evict` so the module owns one implementation; mikroview keeps
  its own copy for its other maps until it chooses to import this one.

### 1.2 The seams each app implements

```go
package persist

type Snapshot struct { Payload []byte; Version int64; Exists bool }

type Backend interface {
    Load(ctx context.Context) (Snapshot, error)
    Save(ctx context.Context, payload []byte, expect int64) (int64, error) // ErrConflict on mismatch; expect==0 means create
    Close() error
    Describe() string // credential-free, for logs
}

type VersionReader interface { // optional; lets a live server notice a CLI's write cheaply
    Version(ctx context.Context) (version int64, exists bool, err error)
}

var ErrConflict = errors.New("persist: store was modified by someone else")

func Open(ctx context.Context, b Backend, name string, decode func([]byte) error) (version int64, existed bool, err error)
func SaveWithRetry(ctx context.Context, b Backend, payload []byte, current int64) (version int64, conflicted bool, err error) // deprecated
func LoadDocument(ctx context.Context, b Backend) ([]byte, int64, error)
func NewMemory() *Memory // in-memory Backend for tests
```

Identical to mikroview's `internal/persist/{persist,document,open}.go`.
`Open`'s fail-closed contract (a document that exists but cannot be
parsed is a startup error, never "empty") is kept: it is what stops a
corrupt accounts file re-opening registration to the next visitor.

`SaveWithRetry` is deprecated (`persist/document.go`). If two processes
saved at the same moment, it let the later save replace the earlier
one, which could silently lose the earlier change. Nothing in this
module calls it any more. Store and TokenStore now replay instead
(`mutate.go`): when a save finds another process wrote first, the store
reloads that process's document and re-applies its own change on top.
It tries up to five times before returning `ErrSaveConflict`.
`SaveWithRetry` stays, unchanged, for a caller that already depends on
it.

Logging: every constructor takes `*slog.Logger` in its options; nil
means discard. Mikroview passes `logging.New("auth")`; birdcage passes
its `internal/logging` logger. No interface is needed because both apps
already speak `slog`.

Audit: `gate` records account and token events through

```go
type Auditor interface { Record(actor, action, target, detail string) }
```

which is the signature of mikroview's `audit.Store.Record` minus its
return value. Birdcage adapts it to `audit_log` in a dozen lines.

### 1.3 Core package `gauntlet`

Types and signatures are mikroview's, listed here so the fit can be
checked line by line. Anything marked *new* is a change from mikroview,
with its reason.

```go
type Role string
const ( RoleAdmin Role = "admin"; RoleUser Role = "user"; RoleViewer Role = "viewer" )
func (r Role) AtLeast(min Role) bool // admin ⊇ user ⊇ viewer; unknown role ranks below viewer

type User struct { // JSON tags exactly as mikroview internal/auth/store.go:81
    ID, Username, PasswordHash string; Role Role
    CreatedAt, LastLogin, PasswordChangedAt, RoleChangedAt time.Time
    SessionsEndedAt, LoginLockedUntil time.Time // new (#28, #19): gauntlet's own, zero in mikroview's documents
    LoginLockoutCount int; LoginDisabledAt time.Time // new (#44): gauntlet's own, zero in older documents
    KnownBrowsers []KnownBrowser // new (#44): accounts version 4; none in older documents
    SeenCountries []SeenCountry; LastPlace *LastPlace // new (#55): accounts version 8; what unusual sign-ins are judged against, none/nil in older documents
    OIDCIssuer, OIDCSubject string; HasLocalPassword bool
    ResetCodeHash string; ResetCodeExpiresAt time.Time; MustChangePassword bool
    TOTPSecret string; TOTPConfirmedAt time.Time; TOTPLastCounter uint64
    RecoveryCodes []RecoveryCode; Passkeys []Passkey
    ResetCodeSpentHash string                    // new: a spent reset code, kept until the forced change so it cannot become the new password
    BreachCheckPending bool                      // new (#43): accounts version 5; the breach check could not answer, recheck at next sign-in
    TOTPPendingSince time.Time                   // new (#58): when a scanned, unconfirmed TOTP secret was set
    HeldEnrolment *HeldEnrolment                 // new (#58): a first second factor on hold until its recovery codes are confirmed
}
func (u *User) LocalPassword() bool
func (u *User) SessionCutoff() time.Time // new (#28): later of SessionsEndedAt and PasswordChangedAt
func (u *User) HasActiveTOTP() bool
func (u *User) HasSecondFactor() bool

type Options struct { Log *slog.Logger; OnSetupCode SetupCodeHandler      // new; OnSetupCode #37
    AllowPlaintextAtRest bool; OnUnlockCode UnlockCodeHandler                // #50; #44
    PasswordBlocklist PasswordList; ProductName string; BreachCheck BreachChecker } // #43
type PasswordList interface { Contains(password string) bool }             // *blocklist.List, *blocklist.Refresher
type BreachChecker interface { Breached(ctx context.Context, password string) (bool, error) } // *blocklist.PwnedChecker
func PasswordMatchesContext(password string, words ...string) bool        // #43
const BreachCheckTimeout = 5 * time.Second                                 // #43
type SetupCodeHandler interface { SetupCode(code string) }; type SetupCodeFunc func(code string) // adapter, as http.HandlerFunc
func OpenStore(b persist.Backend, opts Options) (*Store, error)            // = OpenWithBackend
func (s *Store) Persisted() bool
func (s *Store) Count() int
func (s *Store) Register(username, password string, now time.Time) (*User, error)          // first account only, becomes admin; host-side -- gate checks the setup code first
func (s *Store) CheckSetupCode(code string) error                                           // new (#37, ADR-0003): the one-time code an empty store announced
func (s *Store) CheckUnlockCode(username, code string) (*User, error)                       // new (#44): the one-time code a store with its lone admin disabled announced
func NewOneTimeCode() (display, canonical string)                                          // new (#66): the setup and unlock codes' generator, exported for gate's escape code
func (s *Store) OtherAdminCanAct(userID string, now time.Time) bool                        // new (#66): some other admin is not LoginDisabled(now); a lockout does not count against it
func (s *Store) CreateUser(username, password string, role Role, now time.Time) (*User, error) // role may be RoleAdmin since #67; gate step-ups the caller first
func (s *Store) DeleteUser(id string) (*User, error)                                       // refuses the last admin: ErrCannotDeleteAdmin, also ErrLastAdmin
func (s *Store) SetRole(id string, role Role, now time.Time) (*User, Role, error)          // new (#67, #75): the user and the role it held; refuses demoting the last admin inside the write (ErrLastAdmin); a downgrade ends the account's sessions; ErrRoleUnchanged when nothing would change
func (s *Store) TransferAdmin(toUsername string, now time.Time) (from, to *User, err error) // console handover from the one admin; ErrSeveralAdmins with more
func (s *Store) Admin() *User                                                              // an admin: the first by username (#67)
func (s *Store) Admins() []User                                                            // new (#67): every admin, by username, credentials blanked
func (s *Store) HasLocalAdmin() bool                                                       // any admin has a local password
func (s *Store) Authenticate(username, password string, now time.Time) (*User, error)     // also redeems a live reset code; rechecks a BreachCheckPending account (#43)
func (s *Store) Get(id string) (*User, bool)
func (s *Store) ByUsername(username string) (*User, bool)
func (s *Store) ByOIDCIdentity(issuer, subject string) (*User, bool)
func (s *Store) FindOrCreateOIDCUser(issuer, subject, usernameHint string, now time.Time) (*User, bool, error)
func (s *Store) FindOrCreateOIDCUserWithRole(issuer, subject, usernameHint string, role Role, now time.Time) (OIDCSignIn, error) // new (#76, ADR-0013): role "" leaves it alone; user|viewer creates or moves the account in the sign-in write, never an admin
func (s *Store) LinkOIDCIdentity(userID, issuer, subject string, now time.Time) error
func (s *Store) SetPassword(username, newPassword string, now time.Time) error
func (s *Store) UnlockLogin(accountID string) error // #44: lifts a disable, clears the count and the lockout (no limiter: a CLI)
type KnownBrowser struct { Hash string; IssuedAt time.Time } // new (#44): SHA-256 of a browser's token, never the token
const MaxKnownBrowsers = 3; const KnownBrowserLifetime = 45 * 24 * time.Hour // #44 (owner, 2026-10-02)
func (s *Store) RememberBrowser(accountID, replacing string, now time.Time) (string, error) // #44: new token, old one's entry dropped, oldest evicted past 3
func (s *Store) ClearKnownBrowsers(accountID string) error                                 // #44: sign out everywhere; IssueResetCode does it in its own write
func (s *Store) KnowsBrowser(accountID, token string, now time.Time) bool                  // #44: hash on the record, under 45 days old
// Unusual sign-ins (#55): judged against the memory above, never looked up again after the fact.
type SeenCountry struct { Code string; LastAt time.Time }       // gate.Config.Country's answer, and when it was last seen
const MaxSeenCountries = 3; const SeenCountryLifetime = 90 * 24 * time.Hour
type Location struct { Latitude, Longitude float64; RadiusKm int } // a city-level lookup's point and accuracy radius (geoip.EditionCity)
type LastPlace struct { Country string; Location; At time.Time }   // the account's one latest located sign-in; a point, not a trail
const ImpossibleTravelSpeedKmh = 800.0                             // about airliner speed (Okta's figure): a sign-in that implies travelling faster than this from LastPlace, after both accuracy radii, is impossible travel
type SignInSignals uint8 // bit set, not a slice, so SessionClient stays comparable
const ( SignalNewBrowser SignInSignals = 1 << iota; SignalNewCountry; SignalImpossibleTravel ) // fixed order: new-browser, new-country, impossible-travel
func (s SignInSignals) Has(f SignInSignals) bool; func (s SignInSignals) Names() []string; func (s SignInSignals) String() string
func ParseSignInSignal(name string) (SignInSignals, bool)
type SignInJudgement struct { Signals SignInSignals; PreviousCountry string } // PreviousCountry is LastPlace.Country when SignalImpossibleTravel is set
func (s *Store) JudgeSignIn(accountID string, tokens []string, country string, loc *Location, now time.Time) SignInJudgement // read-only; tokens are the known-browser tokens the browser carries
func (s *Store) RememberSignIn(accountID, replacing, country string, loc *Location, now time.Time) (string, error) // one write: rotates the browser token (as RememberBrowser) and remembers the country and last place; RememberBrowser is RememberSignIn with country and loc left blank
func (s *Store) List() []User                                              // secrets blanked
// TOTP, recovery codes, reset codes: SetPendingTOTPSecret, ConfirmTOTP, VerifyAndRecordTOTP,
// ClearTOTP, GenerateRecoveryCodes(IfAbsent), BurnRecoveryCode, IssueResetCode -- as in mikroview.
// Passkeys: AddPasskey, RenamePasskey, DeletePasskey, RecordPasskeyAssertionIfFresh, ClearPasskeys,
// ClearAllSecondFactors, PasskeyCount, AnyPasskeysExist -- storage methods only; no WebAuthn import.
// The ceremony seam (G8, ADR-0004), implemented by gauntlet/passkey and driven by gate:
type PasskeyStatus string // PasskeyStatusReady "ready", PasskeyStatusUnset "unset", PasskeyStatusIP "ip", PasskeyStatusInsecure "insecure"
type PasskeyCeremony interface {
    Status() PasskeyStatus; RPID() string; Origin() string           // RPID and Origin are "" unless ready
    BeginRegistration(u *User) (options json.RawMessage, sealed string, err error)
    FinishRegistration(u *User, sealed string, credential json.RawMessage) (Passkey, error) // Name, CreatedAt left to the caller
    BeginLogin(u *User) (options json.RawMessage, sealed string, err error)
    FinishLogin(u *User, sealed string, assertion json.RawMessage) (PasskeyAssertion, error)
}
type PasskeyAssertion struct { CredentialID []byte; SignCount uint32; CloneWarning bool } // what RecordPasskeyAssertionIfFresh consumes
var ErrPasskeyCeremonyInvalid error // wrapped by passkey's Finish methods for a dead ceremony: unreadable, other ceremony, expired, already used

func HashPassword(password string) (string, error)   // argon2id, m=64MiB t=3 p=4, 16-byte salt, 32-byte key
func VerifyPassword(password, encoded string) bool   // constant-time; parameters read from the encoded string
type KDFParams struct{ Memory, Time uint32; Threads uint8 }
func DefaultKDFParams() KDFParams
func (p KDFParams) Valid() bool      // zero fields refused, never derived cheaply
func NewKDFSalt() ([]byte, error)
func DeriveKey(passphrase string, salt []byte, p KDFParams) []byte  // kept: mikroview's retention key uses it

type Session struct { ID, UserID string; IssuedAt, ExpiresAt, LastUsedAt time.Time; Client SessionClient }
type SessionClient struct { Address, UserAgent, Country string; Unusual SignInSignals } // new (#48): recorded at sign-in, memory only; Country (#54) is the lookup's answer, not the client's own word; Unusual (#55) is gate's judgement, not the client's word either
const ( MaxSessionUserAgent = 256; MaxSessionAddress = 64 )          // bytes kept, after control/format chars are dropped
func (s Session) Ref() string                                       // new (#48): first 32 hex of SHA-256(ID); shown instead of the ID
func NewSessionStore(ttl, maxLifetime time.Duration) *SessionStore  // new: one constructor; mikroview's two collapse
func (s *SessionStore) Create(userID string, now time.Time) Session // CreateFrom with an empty client
func (s *SessionStore) CreateFrom(userID string, client SessionClient, now time.Time) Session // new (#48)
func (s *SessionStore) Validate(id string, now time.Time) (Session, bool) // sliding ttl, capped at IssuedAt+maxLifetime; moves LastUsedAt; refuses but keeps a session idle past its ttl inside the ceiling (#71)
func (s *SessionStore) Resumable(id string, now time.Time) (Session, bool) // new (#71): the timed-out session id names, if still inside the ceiling; authenticates nothing
func (s *SessionStore) Resume(id string, client SessionClient, now time.Time) (Session, bool) // new (#71): ends that session and starts one with a new ID, same account and IssuedAt, in one step
func (s *SessionStore) ListForUser(userID string, now time.Time) []Session // new (#48): live only, newest first; evicts what is past the ceiling, skips a resumable one
func (s *SessionStore) RevokeRef(userID, ref string) (Session, bool)       // new (#48): searches userID's sessions only
func (s *SessionStore) Revoke(id string)
func (s *SessionStore) RevokeAllForUser(userID string)

type TokenKind string
const ( TokenKindAPI TokenKind = "api"; TokenKindIngest TokenKind = "ingest" )
type Token struct { ID, Name string; Kind TokenKind; Device, HashedValue string
                    CreatedAt, LastUsedAt, ExpiresAt, ExpiryWarnedAt time.Time; CreatedBy, CreatedByUsername string } // JSON as mikroview token.go; ExpiresAt and ExpiryWarnedAt new (#74), zero = never / not warned; tokens document version 3, an older build refuses it
const ( TokenPrefix = "gnt_"; DefaultTokenLifetime = 365*24*time.Hour; TokenUnusedLimit = 365*24*time.Hour; TokenExpiryNoticeWindow = 7*24*time.Hour ) // #74
type TokenOptions struct { Log *slog.Logger; Kinds []TokenKind }          // new: Kinds, default {api, ingest}
func OpenTokenStore(b persist.Backend, opts TokenOptions) (*TokenStore, error)
func (s *TokenStore) Persisted() bool
func (s *TokenStore) Create(name string, kind TokenKind, device string, creator *User, now time.Time) (raw string, tok *Token, err error) // expires after DefaultTokenLifetime; raw starts gnt_ (#74)
func (s *TokenStore) CreateWithExpiry(name string, kind TokenKind, device string, creator *User, now, expiresAt time.Time) (raw string, tok *Token, err error) // zero expiresAt = never; not after now is ErrTokenExpiryInvalid
func (s *TokenStore) Authenticate(raw string, want TokenKind, now time.Time) (*Token, bool) // SHA-256 lookup; kind must match; an expired token is refused like an unknown one
func (s *TokenStore) Sweep(now time.Time) (TokenSweepResult, error) // #74: removes tokens unused for a year, marks tokens expiring within a week as warned
func (s *TokenStore) Revoke(id string) error
func (s *TokenStore) RevokeAllCreatedBy(userID string) (int, error)
func (s *TokenStore) List() []Token
func (s *TokenStore) ByKind(kind TokenKind) []*Token

func NewLoginLimiter(threshold int, window time.Duration) (*LoginLimiter, error) // ErrLimiterConfig on threshold < 1 or window <= 0
func (l *LoginLimiter) SetLog(log *slog.Logger)                    // eviction pressure, unsaved lockouts
func (l *LoginLimiter) Reserve(key string, now time.Time) bool     // addresses, unknown names: capped map
func (l *LoginLimiter) Release(key string, now time.Time)
func (l *LoginLimiter) RecordFailure(key string, now time.Time)
func (l *LoginLimiter) Allow(key string, now time.Time) bool       // read only; prefer Reserve before a slow check
func (l *LoginLimiter) ReserveAccount(lockouts AccountLockouts, accountID string, now time.Time) bool // #19; ReserveAccountDecision's Allowed
func (l *LoginLimiter) ReserveAccountDecision(lockouts AccountLockouts, accountID string, now time.Time) AccountDecision // new (#45): why it refused or what it started
type AccountDecision struct { Allowed, Locked, Disabled bool; LockedUntil time.Time; LockoutStarted, DisabledNow bool; Lockouts int }
func (l *LoginLimiter) ReleaseAccount(lockouts AccountLockouts, accountID string, now time.Time)
func (l *LoginLimiter) SignedIn(lockouts AccountLockouts, accountID string, now time.Time)           // #44: completed sign-in resets the count
func (l *LoginLimiter) SecondFactorFailed(lockouts AccountLockouts, accountID string, now time.Time) // #44: 5 in a row set MustChangePassword, end every session
func (l *LoginLimiter) UnlockLogin(lockouts AccountLockouts, accountID string) error                // #44: Store.UnlockLogin plus this limiter's own count
func (l *LoginLimiter) ReserveKnownBrowser(lockouts AccountLockouts, accountID string, now time.Time) bool // #44: a known browser's own budget once the ordinary path refuses
func (l *LoginLimiter) ReserveKnownBrowserDecision(lockouts AccountLockouts, accountID string, now time.Time) AccountDecision // new (#45): Disabled, DisabledNow, Lockouts
func (l *LoginLimiter) ReleaseKnownBrowser(lockouts AccountLockouts, accountID string, now time.Time)
const MaxConsecutiveLoginFailures = 50                                                             // #44: disables local sign-in
const LoginDisableDuration = 24 * time.Hour                                                        // new (#70): the disable lifts itself this long after User.LoginDisabledAt
func (u *User) LoginDisabled(now time.Time) bool                                                   // new (#70): LoginDisabledAt set and not yet lapsed
const AddressBanFailures = 100; const AddressBanDuration = 24 * time.Hour                          // new (#70): failed sign-ins from one address in a rolling day ban it for a day
func (l *LoginLimiter) AddressBanned(address string, now time.Time) (until time.Time, banned bool) // new (#70): memory only; IPv6 per /64
func (l *LoginLimiter) RecordAddressFailure(address string, now time.Time) (banStarted bool)       // new (#70): true once per ban
func AddressBanGroup(address string) string                                                       // new (#70): the key an address is counted under
func (l *LoginLimiter) AllowAfterReset(addressKey string, lockouts AccountLockouts, accountID string, now time.Time) bool // #32
func (l *LoginLimiter) ReleaseAfterReset(addressKey, accountID string)
func (l *LoginLimiter) EndAfterReset(addressKey, accountID string)
func (l *LoginLimiter) ReserveRecheck(accountID string, now time.Time) bool
func (l *LoginLimiter) ReleaseRecheck(accountID string, now time.Time)
func (l *LoginLimiter) ReserveDelivery(channel, accountID string, now time.Time) bool // new (#84): a code sent, per account and channel; counted, never handed back
type AccountLockouts interface {                                    // *Store implements it
    LoginLockedUntil(accountID string) time.Time
    SetLoginLockedUntil(accountID string, until time.Time) error
}
type AccountLockoutRecords interface {                              // new: a host store keeps the disable and count too
    AccountLockouts
    LoginLockoutRecord(accountID string) LoginLockoutRecord
    SetLoginLockoutRecord(accountID string, rec LoginLockoutRecord) error // all three fields in one write
}
type LoginLockoutRecord struct { LockedUntil time.Time; Lockouts int; DisabledAt time.Time }

type SignInOutcome string // new (#45, #53): success, password_ok, no_such_user, wrong_password, factor_refused, locked, disabled, rate_limited, sso_refused, unrecorded
// escape_issued, escape_refused // new (#66, ADR-0011): a lone admin's refused or held sign-in was given an escape code in the server log (no session yet; the refused or confirm_sent row is recorded too) / a wrong escape code; escape_issued is never budgeted, escape_refused is budgeted as any failure
// refused, confirm_sent, confirm_refused // new (#55): every credential was right; refused is a block, confirm_sent means a code is out (or, under prove, a passkey is owed, #65) and no session yet, confirm_refused is a wrong code (or a refused passkey assertion). refused and confirm_sent cost the full credential, like success, and are never budgeted (signins.go); confirm_refused is budgeted as any failure
type SignInMethod string  // password, code, passkey, sso; passkey_alone (#77: a passkey sign-in with no password) and resume (#71: a timed-out session resumed)
type SignInEvent struct { UserID, Username string; Outcome SignInOutcome; Method SignInMethod; Client SessionClient; LockedUntil time.Time; Disabled bool
    Confirmed bool } // new (#55): the sign-in completed through gate's confirmation-code step
func MaskUnknownUsername(typed string) string // new (#53): first two runes + one • per further rune; probe names (root, admin, ...) kept

// The sign-in history (#53, ADR-0006): a third sealed document, "signins".
func OpenSignInHistory(b persist.Backend, opts SignInHistoryOptions) (*SignInHistory, error) // nil b = memory only
type SignInHistoryOptions struct { Log *slog.Logger; MaxRows int; AllowPlaintextAtRest bool }
const DefaultMaxSignInRows = 10_000 // MaxRows 0; MaxSignInRows = 50_000 is the most allowed
const DefaultSignInListLimit, MaxSignInListLimit = 50, 200
type SignInRow struct { Seq uint64; At, Until time.Time; Count int; UserID, Username string; Outcome SignInOutcome; Method SignInMethod; Client SessionClient; LockedUntil time.Time; Disabled, Confirmed bool } // Client.Unusual and Confirmed new (#55); signins document version 3, an older build refuses it, an older row reads as none and false
type SignInQuery struct { UserID, Address string; Outcome SignInOutcome; Before uint64; Limit int; Unusual bool } // Unusual new (#55): only rows that raised at least one signal
func (h *SignInHistory) Record(ev SignInEvent, now time.Time)        // never waits for a save
func (h *SignInHistory) List(q SignInQuery) (rows []SignInRow, more bool) // newest first
func (h *SignInHistory) Summary() (total int, since time.Time)
func (h *SignInHistory) Flush(ctx context.Context) error           // save now
func (h *SignInHistory) Close() error                              // flush once, stop the writer
func (h *SignInHistory) Persisted() bool
func (h *SignInHistory) Describe() string

func ValidateUsername(username string) error       // 1–64 runes, no control/format chars
func ValidateLocalUsername(username string) error  // additionally: no "@"

// Second-factor and code helpers, for apps that render enrolment or check a code themselves.
func GenerateTOTPSecret() ([]byte, error)
func EncodeTOTPSecret(secret []byte) string
func DecodeTOTPSecret(s string) ([]byte, error)
func TOTPEnrollmentURI(productName, username string, secret []byte) string
func GenerateTOTPCode(secret []byte, counter uint64) string
func VerifyTOTP(encodedSecret, code string, now time.Time, lastUsedCounter uint64) (matchedCounter uint64, ok bool)
func FormatRecoveryCode(code string) string; func NormaliseRecoveryCode(typed string) string
func FormatResetCode(code string) string;    func NormaliseResetCode(typed string) string

const MaxDeviceIDLen = 64; const MaxTokenNameLen = 64
const ResetCodeTTL = 24 * time.Hour

// Sentinel errors, compared with errors.Is: ErrInvalidCredentials, ErrNotPersisted,
// ErrTokenNotPersisted, ErrUserNotFound, ErrUsernameTaken/Invalid/Length/IsEmail,
// ErrPasswordTooShort, ErrPasswordBlocked, ErrPasswordContext (#43), ErrInvalidRole, ErrRegistrationClosed, ErrSetupCodeInvalid,
// ErrSetupRequired (SSO cannot create the first account), ErrNoAdmin, ErrSingleAdmin
// (kept, never returned since #67), ErrLastAdmin and ErrRoleUnchanged (#67),
// ErrCannotDeleteAdmin, ErrTransferToSelf, ErrOIDCAlreadyLinked, ErrOIDCIdentityTaken,
// ErrNoLocalPassword, ErrNoPendingTOTP, ErrTOTPAlreadyActive, ErrPasskeyDuplicate,
// ErrPasskeyLimitReached, ErrPasskeyNotFound, ErrTokenNotFound, ErrTokenKindInvalid,
// ErrTokenNameInvalid, ErrTokenDeviceInvalid/Required/NotAllowed, ErrLimiterConfig,
// ErrSaveConflict (a write kept losing a race with another save; nothing
// was written, so the caller can just try again), ErrDocumentRemoved (the
// backend's file is gone since this process loaded it; restore the file,
// or restart the process to start afresh), ErrPlaintextAtRest (#50: the
// backend would hold the accounts in the clear), ErrSeveralAdmins
// (TransferAdmin with more than one admin), ErrLastLocalAdmin (#79: the
// last admin that can sign in without the identity provider),
// ErrUnlockCodeInvalid (#44), ErrTokenExpiryInvalid (#74), ErrNoTOTP and
// ErrNoPasskeys (nothing to remove, nothing written),
// ErrSecondFactorExists, ErrEnrolmentHeld, ErrNoHeldEnrolment and
// ErrHeldEnrolmentExpired (#58: the held first factor), and
// ErrPasskeyCeremonyInvalid (above).
```

Reasons for the *new* items:

- `Options`/`TokenOptions` carry the logger instead of a package-level
  `persistLog`, because a module cannot call an app's `logging.New`.
- `Options.OnSetupCode` and `CheckSetupCode` are the first-admin setup
  code (#37, [ADR-0003](adr/0003-first-admin-setup-code.md), owner
  2026-10-01): an empty persisted store makes a one-time 80-bit code,
  keeps only its hash in memory, and announces it once -- through the
  hook, or as one `Warn` line on `Log` -- so that creating the first
  admin needs the server's log, not just its address. It is inert once
  any account exists and dies with the process; a reload that applies
  an emptied document issues a new one. `Register` stays the host-side
  primitive; `gate` checks the code before calling it, rate-limited per
  address like login. SSO never creates the first account
  (`ErrSetupRequired`): the first admin is local and links SSO
  afterwards, the end state #1252 requires anyway.
- `TokenOptions.Kinds` replaces the hard-coded `TokenKind.Valid()`.
  Mikroview has a third kind, `droplist-pull`, that is its own business;
  its tokens document already contains such rows, and they must keep
  authenticating after the move. Mikroview declares
  `const TokenKindDroplistPull gauntlet.TokenKind = "droplist-pull"` and
  passes it in `Kinds`. Birdcage passes the default.
- `Device` keeps its Go name and JSON tag (mikroview's data has it). Its
  meaning is "the one principal an ingest token is bound to": a router in
  mikroview, nothing yet in birdcage (§2.3).

**Sign-in limits at a glance** (#19, #44, #70, #84). What an operator
sees, with the limiter set to 5 attempts per 5 minutes (the application
chooses both numbers in `NewLoginLimiter`, and the rows that say "5 in
5 minutes" and the lockout lengths follow them; the 50, the second
factor's 5, the 100 and the 24 hours are fixed):

| What happens | Limit | Result |
|---|---|---|
| Wrong password or code for one account | 5 in 5 minutes | locked for 5 minutes, then 15, then 45, then 1 hour each time |
| Failures in a row on one account | 50 (`MaxConsecutiveLoginFailures`), about 8 hours of lockouts | local sign-in disabled for 24 hours (`LoginDisableDuration`), or until an admin unlocks it |
| Failed second-factor steps in a row | 5 | the password must be changed, and every session on the account ends |
| Failed attempts from one address (a right one does not count) | 5 in 5 minutes | `429 rate-limited` until the window passes |
| Failed sign-ins from one address | 100 in 24 hours (`AddressBanFailures`) | the address is banned for 24 hours (`AddressBanDuration`) |
| Codes sent for one account | 5 in 5 minutes, for each kind (confirmation, escape) | `429 rate-limited`, nothing sent |
| Passkey step-ups started by one account (#82) | 5 in 5 minutes, counted and never refunded | `429 rate-limited`, no challenge; the re-check budget is untouched |
| Sign-ins from a browser the account remembers, while it is locked out | 5 in 5 minutes | allowed, so a stranger cannot lock the owner out |

A *door* is a check in `Protect` that blocks every route but a few until
the account has done something: set a new password (the
must-change-password door), added a second factor, or, for an admin
where the application requires it, registered a passkey (#82). The
change-password door asks for no current password, which is why several
rules below end every session before sending an account to it.

**How the limiter differs from mikroview's** (#19, owner 2026-09-27).
Mikroview keeps every counter in one map of 4096 caller-chosen keys,
evicted oldest-first, so a flood of made-up names or addresses can
evict the counter guarding a real account. Here:

- A real account's counters are keyed by its ID, in a map that is never
  evicted. It is bounded by the account count; entries leave only by
  expiring.
- Only addresses and unknown names share the capped map. It drops every
  expired key before evicting a live one, and logs, once per window,
  when it has to.
- A login lockout is written to the account (`User.LoginLockedUntil`),
  so it survives a restart. It is saved only as it begins and as it
  clears: one save as a lockout starts, one as the first attempt after
  it clears it, never one per wrong guess.

**Lockouts** escalate (#44, owner 2026-10-02) and are capped (#70, owner
2026-10-05):

- Each lasts three times the one before, from the attempt that starts
  it: 5, 15 and 45 minutes at 5 attempts per 5 minutes, then one hour
  each (never less than one window).
- The cap was 24 hours. Usernames here are the operator's name or
  `admin`, so a stranger could keep the owner out for a day, and
  mainstream defaults lock for minutes. The long penalty falls on the
  attacking address instead (the address ban, below).
- Their count, `User.LoginLockoutCount`, is written in the same save
  that starts one.

**The 50-failure disable.** `MaxConsecutiveLoginFailures` (50) failures
in a row disable the account's local sign-in (`User.LoginDisabledAt`),
in that same save. Each lockout's attempts count, plus those in the
window, password and second-factor steps alike.

- A disabled account is refused with exactly the locked response, until
  `Store.UnlockLogin` or until `LoginDisableDuration` (24 hours) after
  the disable began, whichever is first.
- Nothing is stored for the disable to lift: it is `LoginDisabledAt`
  against the clock (`User.LoginDisabled(now)`). The first attempt after
  it lapses clears the record as `UnlockLogin` does, in the write that
  records that attempt. That includes the count of lockouts, or the
  next failure would reach fifty again and disable the account at once.
  The accounts document version is unchanged.
- The count resets only on a completed sign-in (`SignedIn`, called
  wherever gate issues a session) or a new password (`SetPassword`,
  `IssueResetCode`). It does not reset on a correct password alone, nor
  as a lockout runs out.
- A new password the owner sets does not lift a disable. A reset code
  does, since issuing one is an admin action (owner, 2026-10-02).

**Second-factor failures.** Five failed second-factor steps in a row
since the last completed sign-in mean the password is known to someone
else. So `SecondFactorFailed` sets `MustChangePassword` and ends every
session on the account (`SessionsEndedAt`), in one save. The
change-password door asks for no current password, so only a fresh
sign-in with both factors may reach it. That run is kept in memory only.

**A host's own store** need implement only `AccountLockouts`, the
lockout's end. The limiter then keeps the disable and the count of
lockouts in its memory, so a restart re-enables a disabled account and
starts the lockouts short again. A store that also implements
`AccountLockoutRecords` keeps all three on its own record, written
together in one save, and they survive a restart as on the `*Store`.

**Unlocking** (#44):

- An admin lifts another account's disable, lockout and count with
  `POST /api/auth/users/{id}/unlock`, through `LoginLimiter.UnlockLogin`.
  That also drops the limiter's own count of the window's guesses, and
  any lockout decision it has yet to save. `Store.UnlockLogin` alone is
  for a process with no limiter.
- An admin whose own sign-in is disabled, but who still holds a session,
  may unlock it on the same route only by entering their password and a
  current second factor (a TOTP or recovery code) again. Each is checked
  on the account's password re-check budget (`ReserveRecheck`); the
  session alone is not enough (owner, 2026-10-02).
- When the store opens with the admin disabled and no admin left who
  could unlock it, it makes a one-time unlock code and announces it
  (`Options.OnUnlockCode`, else one Warn line on `Options.Log`). It has
  the setup code's shape: 80 bits, only its SHA-256 kept, in memory,
  never in the document, gone with the process. It is retired whenever
  a write or load shows that account no longer disabled, so it is single
  use and dies with any other unlock.
- `POST /api/auth/unlock` takes the username and code
  (`CheckUnlockCode`), rate limited on the client address like
  registration, with one identical refusal for every wrong input. It
  only lifts the disable: no session is issued, and the admin signs in
  as normal with their existing password and second factor. It is not a
  password reset, account reset or admin transfer (owner, 2026-10-02).
- The unlock code follows `User.LoginDisabled`, as every other check
  does. A disable that has lapsed (#70) issues no code, even while the
  record still holds it, and an outstanding code stops working once its
  disable lapses.

**After a reset** (#24, #32):

- A new password or reset code ends the lockout, and guesses from before
  it stop counting (#24). Linking the admin to SSO, which ends its
  sessions but keeps its password, does not.
- The reset account also gets past the per-address limit (#32; owner,
  2026-10-01: a reset needs the server's command line or an
  admin-issued code, so this gives an attacker nothing). Only that
  account gets the pass, and only when the address and the account both
  reached their limits before the reset. (The reset ended a lockout, so
  an account that only changed its own password gets nothing.) It is one
  attempt at a time, and only until its sign-in issues a session or a
  password is wrong (`AllowAfterReset`, `ReleaseAfterReset`,
  `EndAfterReset`).
- For an account with a second factor, the right password spends the
  pass, and the pending login carries the code step past the address
  limit, so a guess sent in between cannot take it. The account's own
  limit still applies. Other names tried from that address stay
  refused.
- Re-checking a signed-in caller's own password has its own per-account
  budget, memory only.

**One rule for every budget** (#84, owner 2026-10-08). A reservation on
the login buckets (address, unknown name, account) lives and dies inside
one request. Anything that must be bounded across requests gets a
bucket of its own that is counted, never refunded: challenge minting
(`passkey-begin:` per address, `passkey-stepup-begin:` per account for
the passkey step-up, #82) and code delivery.

- A sign-in held for a confirmation code proved every credential, so its
  attempt goes back to the login buckets in that request (a correct
  credential is no failure, SP 800-63B-4 §3.2.2). What is bounded
  instead is the send.
- `ReserveDelivery` counts each code as it goes out: confirmation codes
  and escape codes on channels of their own, the limiter's threshold per
  window per account and channel, in the account map, memory only. It
  keeps the count whether or not the delivery reported an error.
- Past it, a held sign-in is answered `429 rate-limited` with no code,
  ticket or cookie, and a lone admin's refusal or hold carries no escape
  code.
- A completed sign-in leaves the count alone, so the owner signing in on
  a known browser -- never held, so never sending -- cannot refill a
  stranger's budget. `LoginLimiter.UnlockLogin` empties it, and a
  restart clears it.
- Rate limiting out-of-band code delivery is the standard control (SP
  800-63B-4 §3.1.3.2, ASVS 5.0 6.6.3, OWASP MFA cheat sheet).

**The address ban** (#70, owner 2026-10-05; `addressban.go`) bans the
address a guesser connects from, as the tool fail2ban does. It sits
beside the capped account lockout (OWASP Authentication Cheat Sheet;
Auth0 brute-force protection).

- The per-address limit stays as it was: a short brake with the
  account's threshold and window.
- Separately, each failed sign-in attempt is counted per address: a
  wrong password or code, in any name, an unknown one included, but not
  an SSO refusal. The 100th (`AddressBanFailures`) within a rolling 24
  hours bans the address for 24 hours (`AddressBanDuration`): flat, not
  escalating, not extended by further failures. Only deliberate guessing
  reaches 100; 100 is NIST SP 800-63B-4 §3.2.2's figure, applied per
  address where NIST counts per account.
- IPv4 addresses count by the whole address. IPv6 addresses count per
  /64: all addresses sharing the same first half, normally one home or
  office network, count as one (`AddressBanGroup`). Gauntlet normalises
  the string `ClientIP` returned; one that does not parse counts as
  itself. An empty address is never counted: nothing was resolved, so it
  would otherwise be one address.
- A banned address gets the address limit's own `429` (`rate-limited`,
  recorded as `rate_limited` and a rated Warn line, no audit record),
  checked before anything is reserved. The ban starting is one
  `address.banned` audit record, once per ban.
- The count is each failure's time, kept for 24 hours and at most 99 per
  address: the simplest structure that gives an exact rolling window. It
  is dropped when the ban starts.
- Counts and bans are memory only. A restart clears them, which costs the
  guesser nothing they could cause; the account lockout, saved on the
  account, is the backstop for an attack spread over many addresses.
- They live in a map of their own capped at 4096 addresses
  (`maxAddressBanKeys`), with the attempts map's rules: expired entries
  first, then the least recently active in a batch, logged once per
  window. But counts go before bans, so a flood of addresses never lifts
  a ban; a ban is shed only when bans alone fill the map, the oldest
  first.
- Known browsers pass the ban (below).

**The known-browser allowance** (#44) keeps a stranger from locking the
owner out.

- A browser that completes a sign-in on an account is remembered on its
  record (`RememberBrowser`). It gets a 32-byte random token, base64url,
  and the record keeps only the token's SHA-256 and when it was issued.
  Remembered browsers are still recognised after the application is
  restarted or upgraded (the hash needs no per-process key), and each
  one can be forgotten on its own.
- Each completed sign-in rotates the token, dropping the browser's old
  entry in the same write. An account remembers at most three browsers,
  each for 45 days from its latest sign-in there, checked on the server
  from `IssuedAt` (owner, 2026-10-02). Past three, the oldest is
  evicted: those that have never brought their token back
  (`KnownBrowser.Confirmed` false) before those that have, and never the
  one just added.
- Once the ordinary path refuses an attempt -- the account locked out,
  or the address at its limit -- and the browser's token matches the
  named account (`KnowsBrowser`), the attempt goes ahead on
  `ReserveKnownBrowser`: the limiter's threshold per window, per
  account, no escalation, refused outright while the account is
  disabled. Its bucket is created only after a match, so there is at
  most one per account.
- Each failure through it counts toward the 50. The attempt that fills
  the budget closes it for one window and adds one lockout's worth to
  `LoginLockoutCount` (which also lengthens the next ordinary lockout),
  so the fiftieth disables as an ordinary failure would. A success hands
  the count back (`ReleaseKnownBrowser`, `SignedIn`).
- Forgetting: sign out everywhere on an account with a local password,
  which asks for it again (`ClearKnownBrowsers`; the calling browser is
  then remembered again), and an admin's reset code forget every
  browser. An SSO-only account's sign out everywhere has no password to
  ask for, and keeps them. A signed-in password change, an SSO link, an
  unlock and the forced change after second-factor failures do not
  forget them -- that is when the owner needs the allowance.
- Nothing is keyed on the client's address. A request carrying a token
  the named account remembers is also not refused by the address ban
  (#70). So a reverse proxy that hides visitor addresses, where one
  attacker's ban would be everyone's, cannot lock the owner out; the
  request then meets the ordinary path and its allowance as above. A
  token for another account, or a request naming no account, gets no
  such pass.
- A stolen token gains its holder the allowance during a lockout, ending
  at the disable, and never a session. SSO never reaches the limiter, so
  the token is harmless there; it is issued all the same.

**Internals: when a lockout save fails** (#24, #28):

- A lockout whose save fails is saved again by a refused attempt while
  it is in force, at most every 30 seconds (#24).
- A clear whose save fails -- the owner signed in and ended a lockout
  the record still holds -- is retried the same way, but that retry
  lives only in memory. A restart before it succeeds reloads the
  record's lockout, and the owner waits it out or resets the password
  (#28).
- An escalated lockout or a disable whose save fails is enforced from
  memory and retried the same way.

Not exported: `newID` (16 random bytes, hex) stays private; apps that
want the same shape for their own ids already have one.

**Common passwords** (#43, #52, [ADR-0007](adr/0007-common-password-list.md)).
`gauntlet/blocklist` holds the SHA-1 hashes of the 10,000 most
prevalent Pwned Passwords. `blocklist.Embedded()` is the copy compiled
into the release and makes no network request. It is a full signed
list (`blocklist/embedded/top10k.txt` and its `.sig`, built 2026-10-03),
and a release refuses to tag with a list built more than 90 days
earlier (`scripts/blocklist-age-check.sh`).
An application that wants newer lists between releases runs a
`blocklist.Refresher`, which fetches the published list from the
public GitHub mirror's `pwned-top10k-current` release, adopts it only
if its checksum, Ed25519 signature (keys in `blocklist/keys/`) and
format check out and it is newer than the list in use, and keeps it in
a directory the app names. `cmd/pwlist` builds the list from the
range API of Have I Been Pwned (HIBP), the public database of leaked
passwords, in a monthly scheduled pipeline.

**New-password checks** (#43, `passwordcheck.go`). `Register`,
`CreateUser` and `SetPassword` -- the only places a local password is
set -- run the same checks, cheapest first, before the Argon2id hash:
the 8-character minimum; the account's username and
`Options.ProductName`, whole-password, ignoring case, punctuation and
digits around them (`PasswordMatchesContext`; gate adds its own
`Config.ProductName` on its routes) -> `ErrPasswordContext`; the
common-password list, as typed and in lower case
(`Options.PasswordBlocklist`, default `blocklist.Embedded()`) ->
`ErrPasswordBlocked`; and, only when the application sets
`Options.BreachCheck`, a live query to HIBP (`blocklist.PwnedChecker`)
-> `ErrPasswordBlocked`. Only the first five characters of the
password's SHA-1 fingerprint are sent, so the service never learns the
password; gauntlet compares the rest locally. (The request asks HIBP to
pad its answer, so the answer's size gives nothing away; the padding
entries, of count 0, are ignored.) The live check is bounded by
`BreachCheckTimeout` (5 s) even if the checker ignores its context.
When it cannot answer, the password is accepted against the local
list, the miss is logged, and `User.BreachCheckPending` is set (accounts
document version 5). `Authenticate`, after the password verifies,
rechecks a marked account: a hit sets `MustChangePassword` and
`SessionsEndedAt` in one write, as `requirePasswordChange` does, since
the change-password door then asks for no current password; a clean
answer clears the mark; no answer leaves it. A new password, a reset
code and an SSO link that removes the local password all settle the
mark. SSO-provisioned accounts never reach any of this (owner,
2026-10-02, on #43).

### 1.4 `gauntlet/oidc`

Mikroview's `internal/oidc` moves unchanged: `Config`, `New`, `Client.
AuthCodeURL/Exchange/VerifyIDToken`, `VerifyNonce`, `Identity`,
`Policy.Permit/Restricted`, `AllowIssuer`, `IsMultiTenantIssuer`,
`FlowState`, `NewFlowState`, `StateCodec.Encode/Decode`. It is already a
leaf package with plain-field config and no mikroview imports. The
self-hosted-only policy (`multiTenantIssuers`) moves with it, as
`docs/decisions/multi-tenant-oidc.md` decided and [ADR-0003](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/adr/0003-mikroview-sidecar.md) adopted it for birdcage;
[ADR-0014](adr/0014-shared-issuers.md) since accepts one shared issuer,
Google, when the policy pins the `hd` domain; Entra's shared endpoints
stay refused.

**Roles from groups (#76, [ADR-0013](adr/0013-sso-group-roles.md)).**
`Policy` gains `RoleFromGroups` (group -> `user` | `viewer`, matched like
`AllowedGroups`) and `RoleWithoutGroup` (`""` means `viewer`), and the
methods `Groups(id)` (the claim's values, as `Permit` reads them) and
`ValidateRoles(valid)`. `gate.New` refuses a value of `admin` or any
unknown role: an identity provider never mints an admin, and an account
already holding `admin` is never changed by the map. With a map set,
every SSO sign-in applies the highest role among the identity's mapped
groups, or the fallback for none (including an absent groups claim), in
the same store write that finds or creates the account. A downgrade ends
the account's other sessions; the change is audited as
`user.role_changed` with actor `sso` and told to `Config.Notices` as
`NoticeRoleChanged` with `RoleChangeDetail.ViaSSO`. No stored field is
added, so the accounts document stays at version 9. On such an account
the role route refuses `user`/`viewer` changes (409
`role-managed-by-sso`); the map narrows roles, not access, so
`Restricted` is unchanged and who may sign in stays with
`AllowedGroups`.

### 1.5 `gauntlet/gate`

```go
package gate

type Config struct {
    CookieName          string        // required; "mikroview_session" / "birdcage_session"
    SecureCookie        bool
    CSRFHeaderValue     string        // required; sent as X-Requested-With by the app's own frontend
    RequireSecondFactor bool          // deprecated, ignored: see §1.6
    ProductName         string        // required: names the deployment in TOTP enrolment URIs and passkey display names
    LoginPath           string        // the frontend route the SSO callback's ?ssoError= redirect points at; "" = a bare ?ssoError=
    Log                 *slog.Logger
    Audit               Auditor       // nil = no audit
    Notices             AccountNotifier // told about every account event (#73); nil = nobody told
    Notify              Notifier      // deprecated: Notices narrowed to one event (#53); New refuses both set
    DeliverConfirmCode  func(ctx context.Context, c ConfirmCode) error // synchronous; nil = the confirm action is unavailable (#55, #73)
    OnEscapeCode        EscapeCodeHandler // #66: takes a lone admin's escape code (refused or held sign-in); nil = a Warn line on Log; both nil = none issued
    ClientIP            func(*http.Request) string // required; limiter key and from= in every audit record (#45); app owns trusted-proxy policy
    Country             func(address string) (code string, ok bool) // #54: (*geoip.Manager).Country; nil = no country recorded
    Locate              func(address string) (gauntlet.Location, bool) // #55: (*geoip.Manager).Locate; nil = impossible travel never raised, and New refuses ImpossibleTravel turned on
    PasskeySignIn       bool          // #77: offer sign-in with a passkey alone (§1.6); off = those routes answer 404
    AdminPasskey        AdminPasskeyRule // #82, required, no default: AdminPasskeyRequired (every admin holds a passkey; needs a ready relying party) or AdminPasskeyOptional (§1.6)
    UnusualSignIns      UnusualSignInPolicy // what a new browser, new country or impossible travel does (#55)
    Now                 func() time.Time
}

type Deps struct {
    Users      *gauntlet.Store
    Sessions   *gauntlet.SessionStore
    Tokens     *gauntlet.TokenStore
    Limiter    *gauntlet.LoginLimiter
    OIDC       *oidc.Client      // nil = SSO off; login/callback answer 404
    OIDCState  *oidc.StateCodec
    OIDCPolicy oidc.Policy
    Passkeys   gauntlet.PasskeyCeremony // nil = no passkeys in this app: passkey routes answer 404 (G8, ADR-0004)
    SignIns    *gauntlet.SignInHistory  // new (#53): nil = no history; GET /api/auth/sign-ins answers 404, audit unchanged
}

func New(cfg Config, deps Deps) (*Gate, error)

// Protect is mikroview's requireAuth. Bearer tokens are tried first, in the
// order kinds were registered with Handle; a match is dispatched to that
// kind's handler and never to next. Otherwise: CSRF header on unsafe
// methods, exempt paths, session cookie, SessionCutoff check,
// MustChangePassword door (and, under the admin passkey rule, an admin
// with no local password), admin passkey door (#82), second-factor door,
// then next.
func (g *Gate) Protect(next http.Handler) http.Handler
func (g *Gate) Handle(kind gauntlet.TokenKind, h http.Handler) // e.g. TokenKindAPI -> the app's read-only mux
func (g *Gate) Exempt(paths ...string)                          // beyond the built-in /api/auth/* set

// Routes serves /api/auth/* and /api/tokens[/{id}] with mikroview's paths,
// request and response bodies. Mount it under the same Protect.
func (g *Gate) Routes() http.Handler
func (g *Gate) SweepTokens(ctx context.Context, now time.Time) (TokenSweep, error) // #74: call daily; TokenSweep{Removed, Warned int}

func UserFromContext(r *http.Request) *gauntlet.User
func TokenFromContext(r *http.Request) *gauntlet.Token
func RequireRole(min gauntlet.Role, next http.Handler) http.Handler // 403 below min

// Unusual sign-ins (#55): Config.UnusualSignIns says what each signal
// does; Decide, if set, can overrule the settings' answer once per
// judged sign-in, fixed-timeout, fail-closed to block.
type UnusualSignInAction string
const ( UnusualSignInOff UnusualSignInAction = "off"; UnusualSignInFlag UnusualSignInAction = "flag"
        UnusualSignInConfirm UnusualSignInAction = "confirm"
        UnusualSignInProve UnusualSignInAction = "prove" // #65: held for a passkey assertion; ranks between confirm and block
        UnusualSignInBlock UnusualSignInAction = "block" ) // zero value/"" means flag
type UnusualSignInPolicy struct {
    Action UnusualSignInAction // base for every signal; "" means flag
    NewBrowser, NewCountry, ImpossibleTravel UnusualSignInAction // per-signal override; "" means Action
    // Decide is asked once per unusual sign-in, after every credential
    // and before any session, with the settings' answer in c.Default;
    // its answer replaces that. Runs under ctx, bounded by
    // DecideTimeout; may do local I/O within that. A panic, an error, a
    // timeout, an answer that is not flag, confirm, prove or block, or
    // confirm with no DeliverConfirmCode refuses the sign-in (block),
    // reasoned decide-failed, decide-timeout or decide-invalid.
    Decide func(ctx context.Context, c UnusualSignInCase) (UnusualSignInAction, error)
}
type UnusualSignInCase struct {
    UserID, Username string; Role gauntlet.Role
    Signals          gauntlet.SignInSignals
    Country          string // what Config.Country answered; "" if unknown
    PreviousCountry  string // the account's last place's country when impossible-travel is raised; "" otherwise
    Method           gauntlet.SignInMethod
    Client           gauntlet.SessionClient // resolved address and agent, never the headers
    Default          UnusualSignInAction    // what the settings decided
    CanProve         bool // #65: the account has a passkey usable here and this sign-in was not itself a passkey one, so prove would hold it for a passkey
}
const DecideTimeout = 3 * time.Second // fixed, not configurable: Decide should be a local lookup

// #73: the application mails the owner; gauntlet sends nothing. One
// notice per account event, told apart by Kind, with the one typed
// detail its Kind names.
type AccountNotifier interface { AccountEvent(ctx context.Context, n AccountNotice) error }
type AccountNotice struct {
    Kind             NoticeKind
    UserID, Username string
    Role             gauntlet.Role // zero for a lockout or disable: no account record is loaded for either
    At               time.Time
    By               string // the admin's username when an admin caused it; "" for the account's own holder
    PasswordReset *PasswordResetDetail // password-reset
    SecondFactor  *SecondFactorDetail  // second-factor-added, second-factor-removed
    Lockout       *LockoutDetail       // account-locked, sign-in-disabled
    SessionsEnded *SessionsEndedDetail // sessions-ended
    UnusualSignIn *UnusualSignInDetail // unusual-sign-in (flag, block -- confirm sends only the code, below)
    RoleChanged   *RoleChangeDetail    // role-changed (#67): From (empty for a created admin), To
    TokenExpiring *TokenExpiringDetail // token-expiring (#74): TokenID, Name, Kind, ExpiresAt; raised by SweepTokens, so By is empty
}
const MaxSessionEndReason = 200 // characters

// UnusualSignInDetail (#55) never carries coordinates; the application
// chooses wording, address and channel and treats Client.UserAgent as
// text, never markup. At most one flag or block notice per account per
// hour (unusualNoticeInterval); a held one is notify=quiet in the audit.
type UnusualSignInDetail struct {
    Action     UnusualSignInAction // flag, confirm or block
    Signals    gauntlet.SignInSignals
    Method     gauntlet.SignInMethod
    Client     gauntlet.SessionClient // address, agent (text) and country
    SessionRef string // flag: the ref the session list shows, so a message can say "end this session"
    Reason     string // block: policy, decide-failed, decide-timeout, decide-invalid, notify-failed or prove-failed
}

// deprecated (#53, kept a minor release, ADR-0002 decision 2): Notices
// narrowed to one event. New refuses a Config with both set.
type Notifier interface { SessionsEnded(ctx context.Context, n SessionsEndedNotice) error }
type SessionsEndedNotice struct { UserID, Username, EndedBy, Reason string; Ended int; At time.Time }

// #55, #73: a confirmation code is handed to the application
// synchronously -- the opposite contract from AccountNotifier, which may
// be queued -- and a failure refuses the sign-in.
DeliverConfirmCode func(ctx context.Context, c ConfirmCode) error
type ConfirmCode struct {
    UserID, Username string; Role gauntlet.Role
    Code string; ExpiresAt time.Time
    Signals gauntlet.SignInSignals; Method gauntlet.SignInMethod
    Client gauntlet.SessionClient; At time.Time
}
```

**Sign-in records (#45).** Every sign-in attempt -- the password step,
the code or passkey step, the SSO callback -- goes through one helper,
`recordSignIn` (`gate/signin_record.go`), which writes through `Auditor`:
`user.login` on a completed sign-in, detail `from="<address>"` (quoted:
`ClientIP` may read a client-set header), prefixed `via second factor; `
or `via sso; `; `user.login_failed` for each failed attempt the limiter
admitted, actor and target the account's username or `unknown`, detail
`outcome=<outcome> method=<method> from="..."` plus `name="Hu••••"`
(`MaskUnknownUsername`) when no account matched -- the typed name never
reaches the audit or the log; and `account.locked` (`until=... lockouts=n
from=...`) or `account.disabled` beside the failure whose limiter
decision started a lockout or the disable, and `address.banned`
(actor the account tried or `unknown`, target the address group, detail
`until=... after 100 failed sign-ins in 24h0m0s from=...`) beside the
failure that was the 100th from an address (#70), once per ban. An
attempt that starts a lockout or disable but succeeds hands it back and
writes neither. A limiter refusal (429)
is no audit record but a rated Warn line, as are a missing CSRF header,
a malformed `Authorization` header, a role refusal on `Routes`' admin
routes and the two door 403s: at most one line per kind and address per
minute, the next counting what was left out, 4,096 sources tracked
before the rest share one line (`gate/warnrate.go`). A right password
with a factor still owed, a "sign in again" refusal and a backend
failure write nothing.

Every other audit record a request writes ends with `; from="<address>"`
(`gate.audit` takes the request, so none can leave it out). A wrong
password or code at an in-session re-check (`recheckPassword`,
`recheckSecondFactor`) is `user.login_failed` with `step=recheck`; a
re-check the limiter refuses and a request body over 64 KiB each leave a
rated Warn line. A failure through a known browser's allowance that disables
sign-in writes `account.disabled`, read from
`ReserveKnownBrowserDecision`.

**Sign-in history (#53).** `recordSignIn` also appends each event to
`Deps.SignIns` when set, and `GET /api/auth/sign-ins` (admin) pages
through it newest first, filtered by `user`, `address` and `outcome`,
`before` a row's `seq`, `limit` 1-200 (default 50); 404 while
`Deps.SignIns` is nil. Re-checks are not rows: the caller already holds
a session. Bounds and write cadence are in §4 and ADR-0006.

**Resuming a timed-out session (#71).** A session idle past the idle
timeout (`MaxSessionIdle`, 1 h) but inside its lifetime ceiling
(`MaxSessionLifetime`, 24 h from the sign-in) is "timed out, resumable":
`SessionStore.Validate` refuses it, so it authenticates nothing, but the
store keeps it until the ceiling (the sweep, logout, `RevokeAllForUser`
and the password-change cutoff drop it like any other). `POST
/api/auth/reauthenticate`, `{"password": "..."}`, presented with that
session's cookie, resumes it: the standard pattern is NIST SP 800-63B-4
section 2.2.3 (after an inactivity timeout and before the overall
timeout the verifier MAY accept a password in conjunction with the
session secret), with the session ID regenerated (ASVS 7.2.4). The
route is session-exempt like login and needs the CSRF header. It takes
the same limiter reservation as a password sign-in (`reserveLogin`: the
account lockout and disable, the address limit and ban, the known-browser
allowance), a wrong password counting as a failed sign-in. On success
`SessionStore.Resume` ends the old session and starts one with a new ID,
the same account and the original `IssuedAt`, so the 24-hour ceiling does
not move (the cookie's Max-Age is cut to what is left of it); the
response is login's `{username, role}`. It never asks for a second
factor, is not judged as an unusual sign-in (#55: the session it
continues was, and its signals carry over), does not remember the
browser, and does not reset the account's failure count the way a
completed sign-in does -- a password alone proves less than the sign-in
it continues. Anything not resumable -- no cookie, an unknown, live,
ended or past-ceiling session, an account deleted, with no local password
(an SSO-only account) or owing a password change -- is the one `401
sign-in-required`. `GET /api/auth/session` reports `resumable: true` for a
cookie in that state, which is how a frontend knows to ask for the
password rather than show the full form; every other gated route still
answers `sign-in-required`. History row method `resume`; audit
`user.reauthenticated`. A passkey with user verification resumes a
session in place of the password (#77, ADR-0012).
Sessions are in memory, so a restart still ends them, resumable or not.
The server now keeps a timed-out session until its ceiling (at most 24
hours after sign-in) instead of dropping it one idle timeout after last
use, so it holds more sessions in memory at once. A timed-out session
still authenticates nothing until it is resumed.

**Admin sign-out (#53).** `POST /api/auth/users/{id}/logout-all` ends
every gauntlet session the account holds and forgets its remembered
browsers -- all or nothing, no per-session admin route and no admin list
of another account's sessions (owner, 2026-10-02). 409 for the caller's
own account, 404 for none, 400 for a reason over 200 characters or holding a
control or format character. Audited as `user.sessions_ended`. Once the
response is written, `Config.Notices` (or the deprecated `Config.Notify`)
is called in its own goroutine with a 10-second deadline and `recover()`;
an error or panic is one log line, and the response's `notified` means
asked, not delivered.

**Several admins and role changes (#67, #75, ADR-0010).**
`POST /api/auth/users` accepts `role: admin`, and `PUT
/api/auth/users/{id}/role` moves an account among `admin`, `user` and
`viewer`. Granting `admin` on either needs the caller's own password
and a current second factor on the same request (`recheckStepUp`, the
`UnlockSelfRequest` shape; `password` and `code` on the role route,
`adminPassword` and `adminCode` on create, whose `password` is the new
account's), on the account's `ReserveRecheck` budget: either missing
400, either wrong 401, 429 once the budget is spent. Any other change
needs none. Since #82 a passkey stands in for the code: `POST
/api/auth/step-up/passkey/begin` (session-gated, no body) starts a login
ceremony for the caller's own usable passkeys through
`Deps.Passkeys.BeginLogin` and sets `gate_passkey_stepup`. It takes
nothing from the re-check budget: each begin is counted on its own
per-account bucket (`passkey-stepup-begin:`), never refunded, 429 when
full, so an abandoned prompt costs no re-check (the budget rule above).
The route then takes `password` and `assertion` (`adminAssertion` on
create) in place of the code -- exactly one of the two, else 400 -- and
`recheckPasskey` reserves a re-check in that request, finishes the
ceremony for the caller, refuses a clone warning, records the counter
and hands the reservation back. A wrong assertion is 401 and keeps it; a
missing or dead ceremony checks nothing, hands it back and is 401
`step-expired`. So a passkey-only admin no longer
spends a recovery code per grant. While every admin must hold a passkey
(§1.6), a grant to an account with none usable here still succeeds, and
the account is held at the passkey door from its next request: the role
and create responses and the users list carry `heldForPasskey`, and the
audit detail says "held for a passkey". The last admin can be neither demoted nor deleted (409,
class `last-admin`); an admin may demote themselves while another
remains, and cannot delete their own account. A downgrade ends the
account's sessions (the store writes `SessionsEndedAt`; the handler
drops the in-memory ones). Audited as `user.role_changed` with actor,
from and to; `Config.Notices` gets `NoticeRoleChanged`
(`RoleChangeDetail{From, To}`), also for an admin created over HTTP.
On an SSO account whose role the identity provider's groups decide
(#76, §1.4), a change to `user` or `viewer` is refused, 409 class
`role-managed-by-sso`, before any step-up; granting or demoting an admin
is not.

**The admin's password on the other admin routes (#72, ASVS 7.5.3).**
`POST /api/auth/users/{id}/reset-password`, `POST /api/tokens`,
`DELETE /api/auth/users/{id}`, `DELETE /api/auth/users/{id}/totp` and
`DELETE /api/auth/users/{id}/passkeys` each take the calling admin's own
`password` in the request body, checked by `recheckAdminPassword`
(`recheckPassword` on the account's `ReserveRecheck` budget, no second
factor): a missing or wrong one is `401` `invalid-credentials`,
audited as a failed re-check and counted, `429` once the budget is
spent. A stolen session cookie then no longer takes over an account,
mints a token that outlives the session, or strips a second factor. A
request that is refused for what it asks (the caller's own account, an
unreadable body) is refused before the password is checked; nothing is
read or changed until it passes. Only an admin with a session reaches
`POST /api/tokens` -- a bearer token never gets past `Protect` to these
routes -- so every caller of it is asked. The body of each `DELETE` is
JSON, as on `DELETE /api/auth/totp`.

**Unusual sign-ins (#55).** Four paths judge a completed sign-in
(`gauntlet.Store.JudgeSignIn`) against what the account remembers
(`SeenCountries`, `LastPlace`, known browsers): the one-step password
path, the second-factor step, the SSO callback's sign-in branch and the
passkey-alone sign-in (#77). Every other session issue never judges but
still remembers (`gauntlet.Store.RememberSignIn`), so turning a signal
on later starts from a baseline.

`Config.UnusualSignIns` resolves the signals raised to one action; the
strictest of the kept signals wins.

| Action | What the person sees | What the application must wire |
|---|---|---|
| `off` | nothing: the signal is ignored | nothing |
| `flag` | signed in as usual; the session, the sign-in history and the audit record are marked unusual | nothing (a notice through `Config.Notices` if set) |
| `confirm` | asked for an eight-digit code the application delivers | `Config.DeliverConfirmCode` |
| `prove` (#65, ADR-0009 decision 10) | asked to use a passkey for the same account | nothing |
| `block` | refused: 403 `sign-in-refused` (`docs/api/errors.md`) | nothing |

- **`Decide`**, if set, can overrule that answer once, fixed at
  `DecideTimeout` (3 s). It fails closed to `block` on a panic, an
  error, a timeout, an answer that is not `flag`, `confirm`, `prove` or
  `block` (`off` included: `Decide` cannot switch a judged sign-in off),
  or `confirm` with no `Config.DeliverConfirmCode`.
- **`confirm`** holds the sign-in behind a code that
  `Config.DeliverConfirmCode` hands the application synchronously. The
  person types it into the same sign-in at `POST
  /api/auth/login/confirm` (ticket cookie `gate_confirm_login`, §1.5's
  cookie table). The code is eight decimal digits, shown once, kept only
  as its SHA-256.
- **`prove`** holds it for a passkey assertion for the same account
  instead. It uses the same ticket cookie, marked `Prove` with no code,
  and answers `{"prove": "passkey", "passkeyOrigin": ...}` (the SSO
  callback redirects with `?prove=1`). `POST
  /api/auth/login/prove/begin` and `POST /api/auth/login/prove
  {assertion}` run the existing non-discoverable ceremony
  (`BeginLogin`/`FinishLogin`, user verification preferred, not
  required) and the login limiter, as confirm does. It resolves per
  sign-in: a passkey sign-in is already proved, so `flag`; an account
  with no passkey usable here is held for a code (`confirm`) when
  `Config.DeliverConfirmCode` is set, else refused (`block`).
  `UnusualSignInCase.CanProve` tells `Decide` which.
- **`block`** refuses the one attempt, never the account, and writes
  nothing to the account's memory.
- **The lone admin's escape code** (#66, ADR-0011). A refused or held
  admin whom no other admin can act for (`Store.OtherAdminCanAct`) also
  gets an escape code -- written to the server's log, or handed to
  `Config.OnEscapeCode`, never answered -- and a ticket cookie
  `gate_escape_login`. Typing the code into the refused browser at `POST
  /api/auth/login/escape` lets that one sign-in through, exactly as
  `confirm` does, through the same login limiter. Never for a user or
  viewer, never on the SSO callback; with neither `Config.Log` nor
  `Config.OnEscapeCode`, nothing is issued.
- **Start-up checks.** `gate.New` refuses an unknown action, `confirm`
  with no `Config.DeliverConfirmCode`, and `ImpossibleTravel` turned on
  with no `Config.Locate` (`prove` needs nothing wired).
- **Notices and sends.** A `flag` or `block` notice through
  `Config.Notices` is rate-limited to once an account per hour. A
  `confirm` code and an escape code are not held back by that, since
  each is the code the person is waiting for, but each is counted on the
  account's send budget (`ReserveDelivery`, #84, §1.3). Past it, the
  sign-in is answered `429 rate-limited` (the SSO callback redirects
  `ssoError=refused`) with no code, recorded as `rate_limited`, with no
  notice and no escape code.

**Account notices (#73, folding in #53 and #55).** `Config.Notices`
(`AccountNotifier`) is the one hook for every account event this module
raises: a password reset, a second factor added or removed, recovery
codes regenerated, a lockout, a disable, an admin ending every session,
an unusual sign-in flagged or blocked. Each call carries one
`AccountNotice` with a `NoticeKind` and the one typed detail pointer that
kind names; the async contract (own goroutine, 10 s, `recover()`, errors
logged only, after the response) is the one `Config.Notify` always had.
A confirmation code is different on purpose: `Config.DeliverConfirmCode`
is called synchronously, before the sign-in is answered, and a failure
there refuses the attempt, since no code reached anyone to use.

The HTTP contract `Routes` serves -- every route, request, response,
status code and error body, carried over from mikroview's
`internal/api/server.go` route table -- is
[`docs/api/auth.yaml`](api/auth.yaml) (OpenAPI 3.1, ADR-0002), not a
list here. The contract tests in `gate/contracttest` fail when a
handler and that document disagree. The passkey routes (G8, #20) are
mikroview's own paths and bodies; [ADR-0004](adr/0004-passkey-ceremony.md)
has the seam, the cookies and the policy.

What stays fixed inside `gate`, because it is security behaviour, not
taste:

- `X-Requested-With` is the CSRF header name.
- Every cookie gate sets is `HttpOnly` and `SameSite=Lax`, and `Secure`
  while `SecureCookie` is on. `gate.New` warns once when `SecureCookie`
  is off.
- The session cookie's name is prefixed `__Host-` while `SecureCookie`
  is on: a browser then refuses the cookie unless it is `Secure`, has no
  `Domain` and is on path `/`. Under plain HTTP it keeps the bare name,
  since a browser would drop a `__Host-` cookie there.
- A login ends the session the same browser already held for that
  account, since the new cookie replaces it (#47).
- While `Count()==0` the server is in a 503 "setup required" state with
  only healthz, session and register reachable. The OIDC pair is not:
  SSO cannot create the first account (#37).
- Unknown and revoked tokens get identical 401 bodies.
- The login limiter is keyed on both the client IP and the account (its
  ID when the name matches one, the name otherwise; §1.3), and reserves
  then releases, so a correct password does not count as a failure.
- The machine-readable 403 header that tells a frontend which door
  refused it is `X-Auth-Gate`, the same for every app (a door, §1.3, is
  the must-change-password, admin passkey (#82) or second-factor check
  in `Protect`; the values are `must-change-password`,
  `must-enrol-passkey` and `must-enrol-factor`).
  Mikroview's `X-Mikroview-Auth-Gate` is renamed, and its frontend
  follows when it moves onto the module (owner, 2026-09-27, on #7).

The cookies:

| Cookie | Path | Lifetime | What it is for |
|---|---|---|---|
| session (`Config.CookieName`) | `/` | the session store's lifetime ceiling, so the browser forgets it once the session can no longer be valid | the signed-in session |
| `gate_known_browser` (#44) | `/api/auth` | 45 days, matching the server's own check (§1.3) | the known-browser allowance |
| `gate_pending_login` | `/api/auth/login` | 5 minutes | a right password waiting for its second factor; spent by the sign-in that completes it |
| `gate_confirm_login` (#55, #65) | `/api/auth/login` | 15 minutes (`ConfirmCodeLifetime`) | an unusual sign-in held for a code (`confirm`) or a passkey (`prove`) |
| `gate_escape_login` (#66) | `/api/auth/login` | 15 minutes (`EscapeCodeLifetime`) | a lone admin's refused or held sign-in waiting for its escape code |
| `gate_oidc_flow` | `/api/auth/oidc` | 5 minutes | the SSO round trip's state, nonce and PKCE verifier |
| `gate_passkey_register` | `/api/auth/passkeys` | 5 minutes | a passkey registration, begin to finish |
| `gate_passkey_assert` | `/api/auth/login` | 5 minutes | a passkey as the second factor, or a passkey proving an unusual sign-in (`login/prove`), begin to finish |
| `gate_passkey_signin` (#77) | `/api/auth` | 5 minutes | a passkey sign-in on its own, or a passkey resuming a timed-out session |
| `gate_passkey_stepup` (#82) | `/api/auth` | 5 minutes | a signed-in caller's passkey standing in for a code at a step-up (granting admin, creating an admin, the admin's own unlock), begin to finish |

Notes on the table:

- **Known browser.** It is set at every session issue (`issueSession`).
  Its path covers every route that issues a session, so each issue sees
  the browser's old tokens and replaces its own entry rather than adding
  a second against the cap of three. It has no `__Host-` prefix, which
  needs path `/`. It is read for the allowance only once the limiter has
  refused an attempt. Since #55 it carries up to four tokens, one per
  account, joined by a character base64url never produces, so a browser
  shared by two accounts is not "new" to whichever one is switched to. A
  one-token cookie from before that change reads as a list of one.
- **Confirm and escape.** `/api/auth/login` is a prefix of
  `/api/auth/login/confirm`, `/api/auth/login/prove` and
  `/api/auth/login/escape`. The SSO callback can still set the confirm
  cookie, since a response may set a cookie for any path. Each is sealed
  under its own per-process key, so a restart fails a waiting
  confirmation cleanly.
- **Passkey ceremonies.** `passkey` seals the three under three
  independent keys, and opens each only in the spelling it was written
  in. A login challenge is usable once; one registration begin stores
  at most one passkey; a finish the library refuses leaves that
  registration usable within its five minutes.

Hard-coded strings that are mikroview's today and must not leak into
birdcage: the product name in TOTP enrolment URIs and passkey display
names, the `?ssoError=` redirect target. `Config` gains `ProductName`
(required: `gate.New` refuses an empty one) and `LoginPath` for them. Mikroview's 30-day cookie constant is gone:
the cookie's lifetime is the session ceiling (#47).

### 1.6 Second factors and passkeys -- always required, since #49; a passkey for admins, since #82

Mikroview's model (v0.6.1, `CHANGELOG.md` #1249/#1250/#1253) is: every
local-password account must hold a second factor, TOTP or a passkey;
ten shared recovery codes; SSO accounts have none. `requireAuth` enforces
it. The data for all of this lives on `User`.

- **Data model: in v1, unavoidably.** See Summary: a whole-document store
  cannot round-trip fields it does not know.
- **TOTP, recovery codes, reset codes: in v1.** Stdlib only (HMAC-SHA1,
  base32, crypto/rand), already inseparable from `Authenticate`, and
  ~800 lines that exist and are tested. Leaving them out would mean
  building a `gate` that cannot run mikroview's login flow.
- **Passkeys: data in v0.1.0, ceremony in G8.** The `Passkey` struct is
  plain fields (`[]byte`, `uint32`, `[]string`, a flags struct mirrored
  from `webauthn.CredentialFlags`), so storing them costs no dependency.
  The ceremony (`gauntlet/passkey`: the relying party built from the
  app's public URL, sealed ceremony cookies -- two in G8, a third for
  the passkey-alone sign-in since #77, a fourth for the passkey step-up
  since #82 -- and the spent-challenge set) brings
  `github.com/go-webauthn/webauthn` v0.18.2 (owner, 2026-09-30) and is
  reached from `gate` only through `gauntlet.PasskeyCeremony`
  ([ADR-0004](adr/0004-passkey-ceremony.md); ADR-0012 adds the optional
  `gauntlet.PasskeySignIn` beside it). Registration is
  password-gated at begin, as TOTP enrolment is. Birdcage does not wire it
  and does not link it. A missing or unusable public URL is a reported
  status (`unset`, `ip`, `insecure`), not a startup refusal: the
  ceremony routes answer 409 and the session body says why; mikroview's
  deployments reached by IP keep starting -- as long as the application
  sets `Config.AdminPasskey` to `AdminPasskeyOptional` there (#82, below).
- **A passkey that verified the user can sign in on its own (#77,
  [ADR-0012](adr/0012-passkey-alone-sign-in.md)), behind
  `Config.PasskeySignIn` (off by default).** The person picks their
  passkey and confirms with a PIN or fingerprint. They type no username,
  because the passkey itself stores which account it belongs to. (For
  developers: a WebAuthn Level 3 discoverable-credential login, the
  account named by the user handle, which is the account ID.) User
  verification, the PIN or fingerprint, is required (800-63B-4: a
  multi-factor cryptographic authenticator, AAL2). `POST /api/auth/login/passkey/begin` and `POST
  /api/auth/login/passkey`, through a second optional interface,
  `gauntlet.PasskeySignIn`, that `gauntlet/passkey`'s relying party
  implements beside `PasskeyCeremony`; `go list -deps ./gate` still shows
  no WebAuthn code. Every account keeps its password -- a passkey replaces
  it at sign-in, never in the account, so the accounts document stays at
  version 9 -- and every registration asks for a discoverable credential
  (`residentKey: preferred`). The sign-in is judged like any other
  (method `passkey_alone` reaches `Decide`; confirm is not skipped), is
  counted for the account's lockout and the address limit and ban before
  the signature is checked, and meets the must-change-password door after
  it. The same passkey resumes a timed-out session (§1.5, #71). Mikroview
  opts in when its login screen has the button.
- **The door is always shut: `RequireSecondFactor` is deprecated and
  ignored (#49).** `gate` no longer offers a way to turn the
  forced-enrolment door off -- every local-password account, mikroview's
  and birdcage's alike, must hold a second factor before it can reach
  anything but the enrolment routes. This closes the gap ASVS 5.0 6.2.1
  and NIST SP 800-63B-4 §3.1.1.2 flagged against the 8-character minimum
  (`store.go:46`, docs/security-by-design.md): with the door
  configurable and off by default, an application that forgot to turn
  it on got 8-character single-factor passwords. Cost: the TOTP enrol
  screen is in birdcage's v1 UI slice (§5); it cannot be deferred the
  way "recommend on" would have allowed.
- **Every admin holds a passkey, where the application says so (#82,
  [ADR-0015](adr/0015-every-admin-holds-a-passkey.md)).** Owner rule
  (2026-10-06): an admin account holds at least one passkey; an
  authenticator app may be held as well, never instead.
  `Config.AdminPasskey` is required and has no default: `New` refuses
  an unset or unknown value, so the application's admin chooses, and
  refuses `AdminPasskeyRequired` while `Deps.Passkeys` is nil or its
  status is not `ready`, naming the status, rather than lock every
  admin out or silently waive the rule; it logs the choice at start-up.
  `AdminPasskeyOptional` is for an application reached over plain
  http (anywhere but localhost) or by IP address, or one with no
  passkeys (birdcage today). With
  the rule on, `Protect` holds an admin with no passkey usable under
  the current RP ID at a new door, 403 `must-enrol-passkey`, which
  admits the same enrolment routes as the any-factor door and is
  checked before it; an admin with no local password is held at the
  must-change-password door first, because registering a passkey needs
  one (password, then passkey, then admin). The session body carries
  `mustEnrolPasskey` and `adminPasskeyRequired`. Promotion grants and
  then holds; there is no grace period, because the door offers
  registration in the same session. An admin's own last usable
  passkey cannot be deleted (409 "register another passkey first",
  before the password re-check); another admin's clear-all and the
  console `ClearAllSecondFactors` stay open as recovery, and the account
  is held afterwards. Nothing is stored: the rule is computed from
  `Role` and `Passkeys`, so the accounts document stays at version 9.
  Users and viewers keep "any factor".
- **The first factor is held until its recovery codes are confirmed
  (#58, owner 2026-10-04).** An account's first second factor -- its
  first passkey (`register/finish`) or its first authenticator app
  (`totp/confirm`) -- is saved with ten new recovery codes in one write,
  on hold (`User.HeldEnrolment`; `Store.HoldFirstPasskey`,
  `Store.HoldFirstTOTP`), and the codes are shown once. Neither is live:
  a held passkey is not listed, counted or offered at sign-in, a held
  app verifies no code, held codes redeem nothing, `HasSecondFactor`
  stays false and the door stays shut. `POST
  /api/auth/recovery-codes/confirm` ("I've saved these";
  `Store.ConfirmHeldEnrolment`) makes both live in one more write; only
  then are the account's other sessions ended, this one renewed and
  `account.passkey_added` or `account.totp_enabled` audited. Unconfirmed
  after ten minutes (`HeldEnrolmentLifetime`), both are deleted --
  lazily, by the next enrolment write on the account, and refused at
  confirmation -- and a scanned but unconfirmed TOTP secret also
  expires ten minutes after it was set (`TOTPPendingLifetime`). One
  enrolment at a time: while one is held, starting another is refused
  (409). A later factor is added live at once without codes: an account
  keeps one set across all its factors. This replaces "the factor goes
  live, then the codes are minted in a second write", where a crash or
  failed save between the two left a live factor with no codes
  (answered `partially-completed`).

### 1.7 Deliberately not in the module

- Persisted sessions. Mikroview's are in-memory by design (re-login after
  restart, no signing keys); persisting them would change behaviour for
  existing users, which [ADR-0005](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/adr/0005-shared-auth-module.md) forbids.
- A SQL backend. Mikroview keeps its own (`internal/persist.PostgresBackend`);
  birdcage writes its own if it ever needs one. `persist.Memory` is for
  tests.
- Reading the key file itself. `persist.Encrypt` and
  `persist.EncryptedFileBackend` (#18, #50) take raw key bytes; finding,
  mounting and reading that file -- and deciding a store has no key and
  therefore no persistence -- stays each application's own job.
- The recovery-key store (`recovery.go`, mikroview's CLI gate) and the
  `-recover-admin-account` tooling. They are mikroview's operational
  surface; birdcage gets a `birdcage user` CLI over the same `Store`
  (§2.5) and mikroview keeps what it has.
- Trusted-proxy client-IP logic. It is deployment policy; the app passes
  `Config.ClientIP`.
- The sign-in country's provider key and its credit (#54, ADR-0008).
  `geoip.Config` takes the MaxMind or IPinfo key as plain strings;
  keeping it (a secret file, the app's own sealed settings) is the
  application's job, like the encryption key. So is showing the credit
  both providers ask for ([docs/geoip.md](geoip.md)): gauntlet has no
  page to put it on.

## 2. Birdcage wiring

### 2.1 Routes and credentials

| Surface | Today | With gauntlet |
|---|---|---|
| Frontend static files | open | open (the login page is in the SPA) |
| `GET /api/*` dashboard (`dashboardRouteSpecs`) | open | session with role ≥ viewer, **or** API token (`TokenKindAPI`) via `g.Handle(TokenKindAPI, dashboardRoutes(h))` -- the mux already built for exactly this |
| `GET /api/stream` | open | session only; `EventSource` cannot send a bearer header and a token holder can poll |
| `POST /api/heartbeat` | open | session-gated by default, which no canary can satisfy -- recommend retiring it (§6); `POST /ingest/heartbeat` on the ingest listener has replaced it |
| `/api/auth/*`, `/api/tokens*` | -- | `g.Routes()`; user/token admin behind `RequireRole(RoleAdmin)` inside `gate` |
| #134 per-canary settings write | CLI only | `PUT /api/canaries/{id}/settings` (or as #134 specifies) under `Protect` + `RequireRole(RoleUser)`; API tokens never reach it because they are dispatched to the read-only mux |
| `/ingest/*` (own listener, mTLS + `agent_tokens`) | unchanged | unchanged -- [ADR-0011](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/adr/0011-certificate-kind-authorisation.md)/[ADR-0012](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/adr/0012-scanner-enrolment-proof.md) authenticate agents, not people |
| `/enrol/*` | unchanged | unchanged |

`TestDashboardRoutesReadOnlyExceptHeartbeat` keeps its job: the read-only
mux is what API tokens are dispatched to, so a mutating route must be
registered on a *different* mux (`writeRoutes`) that only sessions
reach. That is the structural guarantee mikroview's `readOnlyRoutes`
gives and birdcage's `api.go` comment already promises.

Roles, as a recommendation: viewer reads; user edits per-canary settings
and other operational toggles; admin manages accounts, tokens and
approvals. A deployment may hold several admins and the last one is
protected (#67, ADR-0010): it can be neither deleted nor demoted, an
admin may be granted over HTTP only with the granting admin's password
and a current second factor re-entered on the same request, and every
admin keeps a local password when SSO is linked. `TransferAdmin` stays
for an app's console while there is one admin; with several it refuses
(`ErrSeveralAdmins`) and the console uses `SetRole`. Three roles, each
including the ones below it: `admin`, then `user`, then `viewer`. There
are no finer admin roles; an app combines `RequireRole` checks over its
own routes.

### 2.2 `requireAuth` replacement

`internal/api/api.go`: `requireAuth` becomes `g.Protect`; `dashboardRoutes`
is also passed to `g.Handle(gauntlet.TokenKindAPI, …)`; `g.Routes()` is
registered on the outer mux under `/api/auth/` and `/api/tokens`.
`NewHandlerWithHub` takes the `*gate.Gate` from `cmd/birdcage`. Tests
build a `Gate` over `persist.NewMemory()` with one registered admin.

### 2.3 Storage: `internal/store/authblob.go`

One table, both dialects, migration `0025_auth_store`:

```sql
CREATE TABLE auth_store (
  name       TEXT PRIMARY KEY,   -- 'accounts' | 'tokens' | 'signins'
  payload    TEXT NOT NULL,      -- the JSON document, byte-exact
  version    BIGINT NOT NULL,    -- compare-and-swap token
  updated_at TEXT NOT NULL
);
```

`store.NewAuthBackend(database *db.DB, name string) persist.Backend`
implements `Load`, `Save` (`UPDATE … WHERE name=? AND version=?`, rows
affected 0 → `ErrConflict`; `expect==0` → `INSERT`, primary-key conflict
→ `ErrConflict`), `Version` (so a running server notices a CLI write
without pulling the document), `Close` (no-op; the pool is `db.DB`'s)
and `Describe` (`"birdcage db store 'accounts'"`). Uses `db.DB`'s
`?`-rebinding `Exec/QueryRow`, so one implementation serves SQLite and
Postgres like every other birdcage store.

The backend `OpenStore` is given is that table wrapped in
`persist.Encrypt(store.NewAuthBackend(database, "accounts"), key,
persist.EncryptOptions{Label: "accounts"})` -- the same for `"tokens"`
-- with `key` the bytes of `BIRDCAGE_AUTH_KEY_FILE` (§2.4), so the
`payload` column only ever holds `{"sealed": "<base64>"}` (#50,
[ADR-0005](adr/0005-encryption-at-rest-on-every-backend.md)). The column
stays `TEXT`: the envelope is JSON text. `OpenStore` refuses the
unwrapped table (`gauntlet.ErrPlaintextAtRest`). Birdcage has no
plaintext accounts document to migrate, so it never needs
`MigratePlaintext`.

The sign-in history (#53, [ADR-0006](adr/0006-sign-in-history.md)) is a
third row of the same table: birdcage adds the name `signins`, opened
through `persist.Encrypt(store.NewAuthBackend(database, "signins"), key,
persist.EncryptOptions{Label: "signins"})` and
`gauntlet.OpenSignInHistory`, passed as `gate.Deps.SignIns`
and closed at shutdown. That is birdcage's change to make, reported
there; nothing here changes birdcage.

Why a document table rather than `users`/`tokens` rows: gauntlet's
`Store` is an in-memory index that persists whole documents -- that is
the shape [ADR-0005](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/adr/0005-shared-auth-module.md) fixed by choosing mikroview's seams, and mikroview's
own Postgres backend (`store_blob`) is the same table under another
name. A relational model would need a second read model that can
disagree with the first. The cost is that accounts are not queryable by
SQL; with a handful of operators that is fine, and audit goes to
`audit_log` through `gate.Auditor`.

Birdcage's `agent_tokens` and `client_certs` are untouched. Gauntlet's
`TokenKindIngest` is not registered by birdcage in v1: agents already
have a stronger credential (token + client certificate, [ADR-0012](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/adr/0012-scanner-enrolment-proof.md)), and
a second ingest credential would be a second door.

### 2.4 Configuration (`cmd/birdcage/main.go`)

```
BIRDCAGE_AUTH_SECURE_COOKIE   default: true when the dashboard listener has TLS, else false with a startup warning
BIRDCAGE_SESSION_TTL          default 1h    (gauntlet.MaxSessionIdle; mikroview's old 24h default is refused by gate.New)
BIRDCAGE_SESSION_MAX_LIFETIME default 24h   (gauntlet.MaxSessionLifetime; mikroview's old 168h default is refused by gate.New)
BIRDCAGE_OIDC_ISSUER_URL, _CLIENT_ID, _CLIENT_SECRET_FILE, _SCOPES
BIRDCAGE_OIDC_ALLOWED_GROUPS, _ALLOWED_EMAILS, _ALLOWED_EMAIL_DOMAINS
BIRDCAGE_AUTH_KEY_FILE        a file of at least 32 random bytes (persist.MinKeyBytes), made once (for example `head -c 32 /dev/urandom`) and mounted like the OIDC secret; the accounts and tokens documents are sealed under it (§2.3, ADR-0005). Required once auth is configured: OpenStore refuses an unsealed table. Keep a separate copy: if the file is lost or changed, the sealed documents cannot be opened, the store refuses to start, and nobody can sign in
BIRDCAGE_PUBLIC_URL           redirect URL base (never the Host header); would be passkey.Config.PublicURL if birdcage ever wired passkeys (§1.6: it does not)
```

`gate.New` fails closed on a `Deps.Sessions` built with an idle timeout
above `gauntlet.MaxSessionIdle` or a lifetime ceiling above
`gauntlet.MaxSessionLifetime`, or with no ceiling at all -- NIST SP
800-63B-4 AAL2's own limits, adopted by the owner 2026-10-02
(gauntlet#51, `docs/security-by-design.md`'s Sessions table). An app
passing more than that is refused at start-up, not just logged.

Unusual sign-ins (#55): birdcage leaves `Config.UnusualSignIns` at its
zero value (`flag` on every signal) for now. It already mails its one
administrator, so once that mail path is wired to carry a confirmation
code, `Decide` can answer `confirm` for the admin account alone -- the
mitigation for the lone-admin-under-`block` risk in §4's pitfalls
table -- and `flag` for everyone else.

Startup: `oidc.AllowIssuerWithPolicy` refuses a multi-tenant issuer
whose policy does not pin the tenant ([ADR-0014](adr/0014-shared-issuers.md))
before listening, as mikroview's `main.go:1723` does -- `oidc.New` and
`gate.New` refuse it as well, so this call is belt-and-braces, not the
only check. Login
limiter: 5 per 5
minutes per IP and per username (mikroview's constants). Client IP:
`RemoteAddr` host until birdcage has a trusted-proxy setting (§5, slice
B5).

### 2.5 CLI

`birdcage user {create,list,reset-password,transfer-admin}` over the same
`Store` and backend, run on the host against the live database. This is
what the `VersionReader` in §2.3 is for: mikroview's `reloadIfStale`
lets a running server pick up the CLI's write on the next authenticated
request, so a locked-out admin does not need a restart.

### 2.6 Frontend

Svelte screens copied from mikroview's, in this order: login (password,
then TOTP/recovery code), first-run register (which also asks for the
setup code from the server log and shows no SSO button, #37), forced
change-password,
forced second-factor enrolment (QR + confirm, recovery codes shown once
and confirmed as saved, #58),
users admin, tokens admin, SSO button and `?ssoError=` handling. `api.ts`
gains the `X-Requested-With: birdcage` header on every request and a 401
→ login redirect.

### 2.7 SECURITY.md

Rewritten route-by-route from the table in §2.1, as [ADR-0003](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/adr/0003-mikroview-sidecar.md) requires.

## 3. Mikroview wiring, later (#1202)

Not done in this work; recorded so the API above is checked against it.

- `internal/auth` → `import auth "github.com/tomlawesome/gauntlet"`. The
  document shapes (`{"users": [...]}` for accounts, a bare token list
  for tokens; store names `auth` and `tokens` in `store_blob`, or
  `users.json`/`tokens.json` files) are what gauntlet still reads as
  version 1, so a copy of real data loads without migration -- the
  acceptance test [ADR-0005](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/adr/0005-shared-auth-module.md) assigns
  to #1202. Gauntlet's first save writes the accounts document as
  `"version": 9` (#28 onwards) and wraps the tokens list as
  `{"version": 3, "tokens": [...]}` (#29, #59, #74); mikroview's own code cannot
  read that tokens document, so rolling back past the move needs the
  copy taken before it.
- `persist.Backend`: mikroview's file, Postgres and write-behind
  backends satisfy gauntlet's interface as they stand. One line:
  `ErrConflict = gpersist.ErrConflict`. Its own
  `internal/persist.EncryptedFileBackend` already moved to
  `gauntlet/persist` (issue #18); mikroview's stores can switch to the
  gauntlet one directly, passing `retention.Key`'s raw material rather
  than the `*retention.Key` type. Its Postgres mode wraps
  `PostgresBackend` for the `auth` row in `persist.Encrypt` under the
  same material, with `Label: "auth"` and `MigratePlaintext: true` for
  the release that introduces it (the row holds plaintext JSON today;
  the first open seals it in place), since `OpenStore` now refuses an
  unsealed backend (#50, ADR-0005). `store_blob.payload` stays `text`:
  the envelope is JSON text.
- Constructor renames: `OpenWithBackend(b)` → `OpenStore(b, Options{Log:
  logging.New("auth")})`; `OpenTokenStoreWithBackend(b)` →
  `OpenTokenStore(b, TokenOptions{Kinds: […, TokenKindDroplistPull]})`;
  `NewSessionStoreWithMaxLifetime(ttl, max)` → `NewSessionStore(ttl,
  max)`. Call sites: `main.go:839, 970, 1930-1937` and the CLI tools.
- Session check: mikroview's one `IssuedAt.Before(PasswordChangedAt)`
  check (`internal/api/auth.go:202`, its `sessionUser`) becomes
  `IssuedAt.Before(user.SessionCutoff())` (#28). Its documents record an
  SSO link in `passwordChangedAt` and carry no `sessionsEndedAt`;
  `SessionCutoff` reads both, so a session issued before such a link
  stays dead after the move.
- `internal/oidc` → `gauntlet/oidc`, no other change (`main.go:1733`).
- Handlers: two steps. First mikroview keeps `internal/api/{auth,oidc,
  tokens}.go` over gauntlet's stores -- everything they call is in §1.3
  by the same name, so the frontend sees identical JSON. Second, with
  `gauntlet/passkey` in place (G8), mikroview swaps to `gate.Routes()`
  and deletes its copies, wiring `Deps.Passkeys = passkey.New(
  passkey.Config{PublicURL: cfg.PublicURL, DisplayName: "MikroView"})`
  in place of its own `NewRelyingParty`; its add-passkey screen asks
  for the password first (register/begin re-checks it, #20 R1).
  `Server` fields `Auth,
  Sessions, LoginLimiter, SecureCookie, Tokens, OIDC, OIDCState,
  OIDCPolicy, RelyingParty` (`server.go:354-458`) map one-to-one onto
  `gate.Deps`/`gate.Config`. Its startup refusal when accounts hold
  passkeys but the relying party is not ready stays its own decision,
  made from `Status()` and `Store.AnyPasskeysExist()` in place of its
  own copy of that method (#20, question 5).
- `DeriveKey`/`KDFParams` stay exported so mikroview's retention
  encryption keeps importing them from the same place its passwords
  come from.
- Unusual sign-ins (#55): mikroview keeps no address per account
  either, so it is the same choice as birdcage's -- `flag` by default,
  `confirm` for the admin account through `Decide` once a mail path
  exists to carry the code.

Checked and fits without a data change: `User` (all 19 fields), `Token`
(9 fields, `droplist-pull` via `Kinds`), `Session` semantics
(`IssuedAt` vs `PasswordChangedAt`, sliding ttl with ceiling), the
(issuer, subject) index, `LinkOIDCIdentity`'s admin-keeps-password
rule (#1252) -- but not `FindOrCreateOIDCUser`'s first-user-is-admin
rule, which #37 closes (mikroview's own copy closes the same way),
`Authenticate`'s reset-code path (#1251), the username rules (#1252's
no-`@` for new local accounts only).

## 4. Security

Per [`docs/security-by-design.md`](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/security-by-design.md): what can go wrong, what mikroview
already does about it, and what the module must keep. Advisories were
checked against the Go vulnerability database (`vuln.go.dev`, index
fetched 2026-09-26) and the GitHub Advisory Database.

**Threat model.** A birdcage session or admin account edits canary
settings and (later) firewall state; an API token reads every alert and
the map of the operator's network; an OIDC misconfiguration hands admin
to a stranger. Compromise of the module compromises both products at
once, which is the price of sharing and the reason fixes land once.

### Sessions

| Pitfall | Mikroview today | Module keeps |
|---|---|---|
| Session fixation / predictable ids | 128-bit `crypto/rand` id, new id per login, never reused | same; `newID` panics rather than degrades if the CSPRNG fails |
| Sessions that never expire | sliding 24h idle + 7-day ceiling from `IssuedAt` (#294) | both, enforced in `Validate`, not by readers of `ExpiresAt`; `gate.New` refuses an idle timeout above 1h or a ceiling above 24h (#51). Changed (#71): a session idle past 1h but inside the ceiling can be resumed with the password alone, under a new ID and the same ceiling (`POST /api/auth/reauthenticate`) |
| Session survives a password reset from another process | `IssuedAt < PasswordChangedAt` → revoke, checked per request | kept in `gate.Protect` as `IssuedAt < SessionCutoff()`; the CLI in §2.5 depends on it. Changed (#28): a password change, a reset code and an SSO link record the end in `SessionsEndedAt`, and only the first two move `PasswordChangedAt`, which the login limiter reads as a password change |
| CSRF | `SameSite=Lax` + `X-Requested-With` on unsafe methods; bearer requests bypass CSRF because cookies are not involved | kept; header value per app |
| Cookie over plain HTTP | `Secure` on by default, off only with TLS off | kept; birdcage derives the default from its listener. `gate.New` logs one warning when `SecureCookie` is off, and prefixes the cookie name `__Host-` when it is on (#47) |
| Logout that does not revoke | server-side delete; logout-all revokes every session of the user | kept; new (#53): an admin's `POST /api/auth/users/{id}/logout-all` revokes every session of another account and forgets its remembered browsers |
| Sessions their owner cannot see | none: logout-all only | new (#48): `GET /api/auth/sessions` lists the caller's own live sessions (address and agent from sign-in, capped at 100 rows with a `total`) by a one-way `ref`, never the ID; `DELETE /api/auth/sessions/{ref}` ends one, with no password (owner, 2026-10-02: signing out is a safe direction), and 404 for any ref not the caller's. Own sessions only: no admin view of anyone else's |

### OIDC

| Pitfall | Mikroview today | Module keeps |
|---|---|---|
| Code interception / replay | Authorization Code + PKCE S256, `state` and `nonce` compared constant-time, verifier held in an AES-256-GCM cookie the browser cannot read or forge | all of it; the flow-state key is per process |
| Algorithm confusion (`alg:none`, HS256 with the public key) | explicit allowlist RS256/ES256/PS256 on the verifier | kept explicit rather than relying on go-oidc's default |
| Account takeover by email match | identity is (issuer, subject); email and `preferred_username` are display hints only | kept; the index is a struct key |
| Public IdP hands admin to the first visitor | multi-tenant issuers refused at startup; first OIDC user becomes admin only when the store is empty | multi-tenant issuers refused, except Google with the `hd` domain pinned in the policy ([ADR-0014](adr/0014-shared-issuers.md)); since #37 SSO never creates the first account -- the first admin is local, created with the setup code from the server's log (ADR-0003) |
| Redirect URL from `Host` | built from `publicBaseUrl` only | birdcage: `BIRDCAGE_PUBLIC_URL` |
| Slow or hung IdP blocks login or startup | 10 s HTTP timeout on discovery, JWKS and exchange | kept |
| Group/claim policy failing open | every missing or unreadable claim is a refusal; policy re-checked on every login | kept |
| `golang.org/x/oauth2` CVE-2025-22868 (GO-2025-3488): memory exhaustion parsing a malformed token in `oauth2/jws`, fixed 0.27.0 | mikroview is on 0.37.0; the `jws` package is not on the auth-code path | pin ≥ 0.27.0 in `go.mod`; `govulncheck` in CI |
| `github.com/coreos/go-oidc/v3` | no entry in either database as of today | dependency review on every bump |

### Tokens

| Pitfall | Mikroview today | Module keeps |
|---|---|---|
| A read token used to write | dispatch to a mux that has no write routes, decided by token kind, never by handler checks | `gate.Handle(kind, mux)`; the app can only register whole muxes |
| Token kind confusion | `Authenticate(raw, want)` refuses any other kind | kept; unknown kinds in the document are logged and never authenticate |
| Plaintext at rest | SHA-256 of a 128-bit random value; raw shown once | kept, and documented why SHA-256 not Argon2id here |
| A token valid for years, and a leaked one no scanner recognises | no expiry, a bare hex value | new (#74), GitHub's personal-access-token lifecycle: `Token.ExpiresAt`, a year by default, `never` only by asking (a router's ingest token would stop reporting on its expiry day); `Authenticate` refuses an expired token as it refuses an unknown one; `Gate.SweepTokens` removes tokens unused for a year (`token.removed_unused`) and sends `NoticeTokenExpiring` once per token, seven days ahead; new values start `gnt_` and `.gitleaks.toml` has a rule for them, while the old bare shape still authenticates. Tokens that exist already keep no expiry |
| Username or token enumeration | one 401 body for missing, wrong and revoked; `ErrInvalidCredentials` for unknown user and wrong password alike; dummy Argon2id hash so timing matches | kept |
| Argon2id as a DoS lever | 64 MiB per hash, at most 4 concurrent (`maxConcurrentHashes`), login limiter in front | kept |
| Unseen failures | only successes audited | new (#45): every failed sign-in, and every wrong password or code at an in-session re-check, is `user.login_failed`; a lockout or disable starting, through a known browser too, is `account.locked` or `account.disabled`, and an address ban starting is `address.banned` (#70); every audit record a request writes carries the client address; refused requests and oversize bodies are rated Warn lines (§1.5) |
| Brute force: account lockouts | 5 failures per 5 min per IP and per username, bounded key map with batch eviction | changed (#19, #44, #70): each lockout lasts three times the last, 5 min up to 1 h. An existing account's counter is keyed by its ID and never evicted; its lockout is saved on the account, so a restart does not lift it (one save as it starts, one as it clears, not one per guess). Addresses and unknown names keep the capped map, expired keys dropped first |
| Brute force: long runs on one account | as above | new (#44): 50 failures in a row disable sign-in until an unlock or 24 hours, whichever is first |
| Brute force: one address guessing many names | as above | new (#70): 100 failed sign-ins from one address (IPv6 per /64, one network) in a day ban it for 24 hours, in memory; known browsers pass the ban. Birdcage's `ClientIP` is `RemoteAddr` until a trusted-proxy setting exists, so behind a proxy every visitor shares one address bucket -- the account bucket still holds |
| `golang.org/x/crypto` advisories | all 30 entries are in `ssh`, `ssh/agent` or `openpgp`; none touches `argon2` | import only `argon2`; birdcage already carries this module at 0.57.0 |

The application must call `Gate.SweepTokens` once a day: the library
has no timer of its own, so without that call unused tokens are never
removed and no expiry notice is sent.

### Second factors (data in v1; ceremonies per §1.6)

TOTP replay is guarded by `TOTPLastCounter`; recovery codes are
Argon2id-hashed and single-use; the reset code is Argon2id-hashed,
24-hour, single-use, and replaces the password outright. A passkey
sign-count that fails to advance refuses the login (the library's clone
warning, then `RecordPasskeyAssertionIfFresh` under the store's lock)
and never moves the stored count; each login challenge is used once,
a registration replay is refused as a duplicate credential, and every
ceremony expires five minutes after begin; attestation is `none`. As a
second factor, user verification (a PIN or fingerprint on the
authenticator) is requested, not required (ADR-0004 decision 5); a
passkey sign-in on its own requires it (#77, ADR-0012, which supersedes
decision 5 for that case).
`github.com/go-webauthn/webauthn` v0.18.2 is the newest release and has
no entry in the OSV or Go vulnerability databases (re-checked
2026-10-02 for G8); `govulncheck` in CI watches it from here on.

### Sign-in history (#53, ADR-0006)

| Pitfall | Module does |
|---|---|
| A flood of failed attempts becomes a flood of writes | attempts change memory only; one writer saves the whole document at most every 5 s while a new row is unsaved and every 60 s while only counts changed; `Flush`/`Close` at shutdown. A crash loses at most that much; the audit sink has every attempt |
| A flood of attempts fills the history | alike attempts within 10 minutes fold into one row (`count`, `until`); failures may start at most 100 rows per 10-minute bucket, the rest counted in one `unrecorded` row; a success or a passed password step is never budgeted. 100,000 made-up names in 10 minutes are 101 rows |
| The history grows without end | the newest `MaxRows` kept, 10,000 by default (owner, 2026-10-02), at most 50,000, oldest dropped; `total` and `since` show how full and how far back. ~340 B a row typically, ~645 B worst: 6.5 MB of JSON, 8.6 MB sealed in a text column, at the default |
| A save holds up sign-ins | rows are copied under the lock; encode, seal and save run outside it (about 60 ms for a full worst-case history), one at a time |
| A password typed into the username box is kept | a name matching no account is masked before it is stored, audited or logged (`MaskUnknownUsername`); probe names in full |
| Addresses and browsers readable in a backup | sealed under its own `persist.Encrypt` label, `signins`; a plaintext backend is refused unless allowed |
| Two writers, or a removed document | a conflicting save reloads and re-appends its unsaved rows renumbered; a removed document keeps memory and is logged once until a save succeeds |

### Common-password list (#52, ADR-0007)

| Pitfall | Module does |
|---|---|
| A tampered list served to applications | Ed25519 signature over the exact bytes, keys compiled in from `blocklist/keys/`; no key, no list adopted; SHA-256 checked too |
| A replayed or rolled-back older list | adopted only if built later than the list in use, and never older than the embedded copy |
| A list dated far ahead to block every later one | refused if built more than 24 hours in the future |
| A hostile or broken server exhausting memory | 256 B checksum, 1 MiB list and 4 KiB signature caps; per-request timeouts |
| The stored copy altered on disk | verified again on every start; written 0600 by rename |
| The signing key leaking | a file on one protected, project-locked runner that talks to nobody, never a CI variable; publishing credentials sit on a different runner |
| A sample or partial build published | `# sample:` header refused by `Parse`, `sign` and every refresher; a full build must see 500 M hashes with a 10,000th count of at least 1,000 |
| An outbound call the application did not ask for | `Embedded()` never touches the network; refreshing is opt-in |

### Country of origin (#54, ADR-0008)

| Pitfall | Module does |
|---|---|
| A provider key in a log, an error or a status page | keys are never stored; IPinfo's token rides in the URL, so every message has the URL's query removed (`cleanErr`) and any key text replaced (`redact`); a provider's error body is never read; `Status` carries no key; `New`'s validation errors never repeat the value |
| A download pointed at the operator's own network | the default client refuses to connect to a private, loopback, link-local, unspecified or reserved address, checked on the address actually dialled, redirects included; https redirects only; no proxy; fixed provider URLs |
| A bad file replacing a good one | written to a temporary file, opened and probed with a documentation-address lookup before it is renamed into place and swapped in; 128 MiB cap, one `.mmdb` per MaxMind archive with no unsafe paths; any failure keeps the file in use |
| A stale file answering quietly | still used, since a country rarely moves, but past 45 days every check logs a warning and `Status().Stale` is true |
| A provider outage, or a refused key | a failed check retries in an hour, a refused key (401/403) in a day; the kept file is loaded at start, so lookups survive a restart offline; with no file, `Country` says "not known", never an error |
| An address sent to a third party | lookups are in a local file; only public unicast addresses are looked up |

### Unusual sign-ins (#55, ADR-0009)

| Pitfall | Module does |
|---|---|
| A flag that fires on every account right after the upgrade | each signal is raised only against something the account already remembers (the baseline rule); an account with nothing remembered of a kind remembers this sign-in instead and raises nothing, so the first sign-in after the upgrade is always quiet |
| A flood of notices | at most one `flag` or `block` notice per account per hour (`unusualNoticeInterval`), in memory; a `confirm` notice is never held back, since it carries the code the person is waiting for |
| A notifier or `Decide` that hangs the sign-in | `Decide` and the `confirm` notice run under `DecideTimeout` (3 s, fixed); a function that ignores its context is abandoned at the deadline and its answer goes nowhere; the `flag`/`block` notice runs after the response, with its own 10 s bound, so it never holds a sign-in up at all |
| A `Decide` bug that quietly weakens the policy | every failure -- panic, error, timeout, or an answer that is not `flag`/`confirm`/`prove`/`block` (`off` included), or `confirm` with no `Config.DeliverConfirmCode` -- fails closed to `block`, logged once and audited with the reason, rather than silently falling back to the settings' own (looser) answer |
| An attacker learning the account's places | `UnusualSignInCase` and `UnusualSignInDetail` carry a country, never coordinates; a stranger who proves the full credential learns only that a policy exists, which the 200/403 already told them |
| An unusual success folded away in the sign-in history | the fold key includes the signals and whether a confirmation code completed it, so an unusual success never folds into an ordinary one from the same address |
| A confirmation code in a log, an error or a record | only its SHA-256 is kept, inside the sealed ticket cookie; the digits themselves are never logged, audited or written to the history |
| A blocking action chosen with nothing wired to deliver a code | `gate.New` refuses `confirm` on any field with no `Config.DeliverConfirmCode`, and `ImpossibleTravel` turned on with no `Config.Locate`, as a missing-dependency error at startup, not a runtime surprise |
| A browser shared by two accounts refused on every switch | the known-browser cookie carries up to four tokens, one per account (#55 change to #44), so switching accounts in one browser is not "new" to the second account |
| A VPN or carrier toggle refused on every hop | impossible travel is a risk signal, not proof; the docs (geoip.md, this file's pitfalls) recommend `flag` or `confirm` for it, never `block`, since a toggle across a few hundred kilometres within an hour is an honest false positive |
| Memory lost on a restart | `SeenCountries` and `LastPlace` are on the sealed account record, not in process memory, so they survive a restart; only the per-process confirm-ticket key and the hourly notice rate do not, which costs at most one stale ticket or one extra notice |
| The lone admin refused from a new laptop under `block` | an escape exists (#66, ADR-0011): when no other admin can act, the refusal writes a one-time code to the server's log (or `Config.OnEscapeCode`) and sets a ticket in the refused browser; typing the code at `POST /api/auth/login/escape` lets that one sign-in through. It needs host access (the log), not the address. First remedy is still a second admin (#67), who can issue the reset code, and `Decide` answering `confirm` or `flag` for admins (§2.4); with two admins able to act no code is written, and two admins both abroad on new laptops stays a residual. Since the v0.3.0 audit (#79) the code is also issued when the admin's sign-in is held for a code or a passkey (`confirm`, `prove`), so a lost passkey or an undelivered code has the same way out |
| A password holder flooding the owner's mailbox or the server's log with codes | each confirmation code and escape code is counted per account as it is sent (`ReserveDelivery`, #84): five per five-minute window each at the consumers' defaults, never handed back, a failed delivery included; past it the held sign-in gets `429 rate-limited` and nothing is sent |
| A log-written escape code that an attacker reads | someone who can read the log already owns the host and holds the setup and unlock codes; without the log, a thief holding the password and second factor has the ticket but no code, and the code without that browser's ticket is nothing. Eighty bits behind the login limiter, one outstanding per refused attempt, single use, gone at expiry or restart |

### Fail-closed list

Unparseable accounts document → refuse to start. Unknown role → denied
everything. Unknown token kind → never authenticates. Missing claim →
refused. Backend write failure → in-memory change rolled back and the
error returned (every mutating `Store` method in mikroview does this;
the module's tests assert it per method). Accounts or tokens file
removed while the server runs → never recreated from memory, since
moving it aside is how an operator resets; every write fails with
`ErrDocumentRemoved`, reads carry on from memory, and the log shows one
error per removal (`<store> store (<path>) has been removed since this
process loaded it; writes are refused until it is restored or the
process restarts`). The operator restores the file, or restarts to
start afresh (#39).

To reset the accounts, the operator moves the file aside:

1. Stop the service first, so a running copy cannot hold the old
   accounts in memory and write them back.
2. Move the accounts file aside: rename it, or move it elsewhere. Do
   the same with the tokens file to drop every token too. Keep the
   moved files: they are the only way back.
3. Start the service. It finds no accounts, so everyone is signed out
   and first-admin setup is open again: it announces a new setup code
   (in its log, or through the application's `OnSetupCode` hook), and
   whoever has that code creates the first admin.

**Restoring a store file.** Always stop the service before restoring or
replacing one.

- As a safeguard, a running service refuses an older copy (#59,
  v0.3.0). Each document carries a save counter inside the seal; a
  running store refuses to adopt a document with a lower counter than
  it has already loaded or written. It leaves the file on disk alone,
  keeps what it holds, logs once why, and refuses writes until the file
  is replaced or the process restarts -- the same way a document from a
  newer build is refused. Before #59 such a copy was adopted at the
  next request, undoing later changes and reviving revoked tokens, with
  nothing logged.
- But a service that is stopped and restarted accepts an older copy
  without warning: the counter is not remembered once the process
  exits. So restore only a copy you mean to go back to.

## 5. Build plan (history, complete for gauntlet)

History, kept as the record. The gauntlet slices (G1-G8) are done:
G7 tagged v0.1.0 on 2026-09-30, and G8 shipped `passkey/`. The birdcage
slices (B1-B7) are birdcage's work and are tracked there.

Issue-sized slices in order. G = gauntlet repository, B = birdcage.
Each ends with a one-line done-when. G1-G6 are the module; B1 can start
once G4 is tagged.

- **G1 Repository and skeleton.** `go.mod`, licence, `AGENTS.md`,
  `SECURITY.md`, CI (`go test -race`, `go vet`, `govulncheck`), `persist`
  package with `Memory`. *Done when:* CI is green on an empty module with
  `persist` tests passing.
- **G2 Core accounts and passwords.** `User`, `Role`, `Store`
  (everything in §1.3 except tokens and second factors), `HashPassword`/
  `VerifyPassword`, `username.go`, `id.go`; mikroview's tests ported.
  *Done when:* a `users.json`-shaped fixture, built field-for-field from
  mikroview's `User` type (mikroview has no such fixture file), loads,
  saves and reloads byte-identical (`roundtrip_test.go`), and every
  ported test passes.
- **G3 Sessions, tokens, limiter.** `SessionStore`, `TokenStore` with
  `Kinds`, `LoginLimiter`, `internal/evict`. *Done when:* a tokens
  fixture built field-for-field from mikroview's `Token` type, with
  `droplist-pull` rows, round-trips and only registered kinds
  authenticate (`tokendocument_test.go`).
- **G4 Second-factor data and stdlib flows.** TOTP, recovery codes,
  reset codes, passkey storage methods (no WebAuthn). *Done when:* the
  full mikroview `User` document round-trips and `Authenticate` redeems
  a reset code exactly once.
- **G5 `oidc`.** Package moved with its fake provider. *Done when:* the
  ported tests pass and a multi-tenant issuer is refused (Google excepted
  with `hd` pinned, [ADR-0014](adr/0014-shared-issuers.md)).
- **G6 `gate`.** Middleware and handlers with `Config`/`Deps`; the
  built-in exempt and bootstrap sets; audit hook. *Done when:* an
  httptest server over `persist.Memory` passes the ported
  `internal/api/auth_test.go` cases for register, login, TOTP door,
  change-password door, token dispatch, OIDC callback (fake provider) and
  CSRF.
- **G7 Tag v0.1.0** (owner, 2026-09-26: the first release is v0.1.0, not v1.0.0). *Done when:* `CHANGELOG.md` lists G1-G6 and
  birdcage can `go get` the tag through the GitHub mirror (#17; owner,
  2026-09-29).
- **B1 Storage backend and migration.** `0025_auth_store`,
  `store.NewAuthBackend`, `VersionReader`. *Done when:* gauntlet's
  backend suite, `persist/persisttest` (#61), passes on SQLite and
  Postgres -- no hand port of mikroview's `persist/contract_test.go`.
  From birdcage's own test, with a fresh table per call:

  ```go
  persisttest.Run(t, func(t testing.TB) func() persist.Backend {
  	table := newEmptyAuthTable(t)
  	return func() persist.Backend { return store.NewAuthBackend(table.db, table.name) }
  })
  ```
- **B2 Wire the gate.** `requireAuth` → `gate.Protect`; API tokens to
  `dashboardRoutes`; `g.Routes()`; env config; startup issuer check;
  `mailConfigured`-style plumbing for `Gate`. *Done when:* every
  `GET /api/*` answers 401 without a session and 200 with one, and an API
  token reaches `GET /api/alerts` but not `/api/auth/users`.
- **B3 CLI `birdcage user`.** *Done when:* `reset-password` against a
  live server is honoured on the next request without restart --
  including from an address the lockout's guesses filled (#32).
- **B4 Frontend: login, register, change-password, TOTP enrolment,
  recovery codes.** *Done when:* a fresh install can be set up and signed
  into from the browser with a second factor, screenshots in the MR.
- **B5 Frontend: users and tokens admin; SSO button; trusted-proxy
  setting for `ClientIP`.** *Done when:* an admin can create a viewer and
  an API token from the UI and a login via a local Authentik succeeds.
- **B6 SECURITY.md rewrite and retire `POST /api/heartbeat`.** *Done
  when:* every route in §2.1 is documented with its credential and the
  read-only test is renamed `TestDashboardRoutesReadOnly`.
- **B7 First write feature: #134** on `writeRoutes` behind
  `RequireRole(RoleUser)`. *Done when:* a viewer gets 403, a user 200, an
  API token 404 (it never reaches that mux).
- **G8 `passkey` package** (before mikroview #1202; owner, 2026-10-01:
  it starts before B4, since birdcage does not need it and mikroview
  cannot ship without it). *Done when:* mikroview's `webauthn_test.go`
  and `passkey_test.go` cases pass against it, and no tag carries
  `passkey/` until they do.

## 6. What the owner had to do (history, decided)

History, kept as the record: every item below was decided on the dates
given. The repository exists, the licence is Apache-2.0, and all four
dependencies are in `go.mod` (`go-webauthn` v0.18.2 since G8).

**Owner decisions, 2026-09-26 (Q17-Q24):** licence **Apache-2.0**; first tag **v0.1.0**; the
three G2/G5 dependencies below **approved** (`go-webauthn` still waits for
G8); passkeys: data in v1, ceremony in G8; second factor **mandatory** in
birdcage; roles as recommended; document store as recommended; the owner
creates the repository. Retiring `POST /api/heartbeat` is now #135, which
removes it before login rather than in B6.

- **Create the repository** `github.com/tomlawesome/gauntlet` (GitLab
  primary under `ai/`, GitHub mirror, as birdcage), default branch `dev`,
  with the layout in §1. Recommendation: same protection rules and CI
  hosts as birdcage; no releases from GitHub.
  **Owner decision, 2026-09-29:** the mirror is created at v0.1.0 (#17),
  not v0.2.0 as decided 2026-09-27, so birdcage fetches the tag by its
  module path.
- **Licence.** A real decision: mikroview is AGPL-3.0-only and birdcage
  is under the Birdcage Noncommercial Licence 1.0. A copyleft or
  noncommercial licence on the library would put conditions on whichever
  app has the other licence when a third party redistributes it; as sole
  copyright holder the owner is not bound by that, but recipients are.
  Recommendation: a permissive licence for gauntlet (Apache-2.0 or
  BSD-3-Clause, the licences of its own dependencies), so both apps keep
  their terms unchanged and outside review of an auth library is not
  discouraged.
- **Approve dependencies** (none are approved by this document):
  - `golang.org/x/crypto/argon2` -- Go team, BSD-3-Clause. Birdcage
    already lists `golang.org/x/crypto` v0.57.0 in `go.mod`; this is a new
    *package* from an already-present module. Needed in G2.
  - `github.com/coreos/go-oidc/v3` -- CoreOS/Red Hat, Apache-2.0, v3.21.0
    in mikroview. Needed in G5.
  - `golang.org/x/oauth2` -- Go team, BSD-3-Clause, v0.37.0 in mikroview;
    carries CVE-2025-22868 in a package not on our path, fixed since
    0.27.0. Needed in G5.
  - `github.com/go-webauthn/webauthn` (+ indirect `go-webauthn/x`) --
    BSD-3-Clause, v0.18.2 in mikroview. Needed only in G8; approval can
    wait for that issue.
- **Passkeys timing** (§1.6). Recommendation: data in v1, ceremony in
  G8 after birdcage's first login ships.
- **Second factor mandatory in birdcage** (§1.6). Recommendation: yes,
  from the first release with login.
- **Roles for birdcage's write paths** (§2.1). Recommendation: viewer
  reads, user edits canary settings, admin manages people and tokens.
- **Retire `POST /api/heartbeat`** on the dashboard listener (§2.1).
  Recommendation: yes, in B6; the ingest listener has carried heartbeats
  since #32.
- **Document store, not rows, for birdcage's accounts** (§2.3).
  Recommendation: the document table; the alternative is a second read
  model.
