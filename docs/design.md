# Design: `gauntlet`, the shared authentication module

**Status:** Proposed design for [ADR-0005](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/adr/0005-shared-auth-module.md); the API and layout are the call
that ADR reserved. **Date:** 2026-09-26. **Issue:** #8 (build `gauntlet`
and use it). **Later consumer:** mikroview #1202.

Everything below was read against mikroview at its current `dev`
(`internal/auth`, `internal/oidc`, `internal/api/{auth,oidc,tokens,
webauthn,server,clientip}.go`, `internal/persist`, `internal/logging`,
`internal/evict`, `SECURITY.md`, `docs/decisions/multi-tenant-oidc.md`).
Where this document says "mikroview does X", that is where it was seen.

## Summary

- One module, four packages: `gauntlet` (accounts, sessions, tokens,
  hashing, rate limiting -- mikroview's `internal/auth` with its names
  kept), `gauntlet/oidc` (mikroview's `internal/oidc`, unchanged),
  `gauntlet/persist` (the storage *interface* only) and `gauntlet/gate`
  (the HTTP middleware and handlers mikroview keeps in `internal/api`).
- Three seams, as [ADR-0005](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/adr/0005-shared-auth-module.md) fixed them: storage is `persist.Backend`,
  copied method-for-method from mikroview so its existing backends
  satisfy it with no adapter; logging is `*slog.Logger`, which is what
  mikroview's `logging.New` already returns; eviction is a pure function
  and goes in as `gauntlet/internal/evict`, not an interface.
- The persisted documents are mikroview's, byte for byte: the same
  `User` and `Token` JSON, the same whole-document shape. Because a
  whole-document store rewrites every field on every save, gauntlet's
  `User` must carry *every* field mikroview stores today -- including
  TOTP, recovery codes, reset codes and passkeys -- or mikroview's move
  would silently drop them. So the data model for second factors is in
  v1 whatever the owner decides about the ceremonies.
- Birdcage implements `persist.Backend` as one small table in its own
  database, wires `gate.Protect` in place of `requireAuth`, routes
  read-only API tokens to the existing `dashboardRoutes` mux, and keeps
  its agent tokens and client certificates exactly as they are.

## 1. Package layout and public API

```
github.com/tomlawesome/gauntlet
├── go.mod                      module github.com/tomlawesome/gauntlet; go 1.27
├── LICENSE                     (owner decision, see §6)
├── README.md  SECURITY.md  AGENTS.md  CHANGELOG.md
├── doc.go                      package gauntlet
├── user.go  password.go  session.go  token.go  ratelimit.go  username.go
├── totp.go  recoverycodes.go  resetcode.go  passkeys.go   (storage + stdlib logic)
├── id.go
├── persist/                    Backend, Snapshot, ErrConflict, VersionReader,
│                               Open, SaveWithRetry, LoadDocument, Memory (tests),
│                               EncryptedFileBackend, MinKeyBytes (issue #18)
├── oidc/                       Config, Client, Identity, Policy, FlowState, StateCodec,
│                               AllowIssuer, IsMultiTenantIssuer
├── gate/                       Config, Deps, Gate, Protect, Routes, RequireRole,
│                               UserFromContext, TokenFromContext
├── internal/evict/             Batch, Target, DownTo (copied from mikroview)
└── internal/testutil/          fake OIDC provider (mikroview's fake_provider_test.go)
```

`passkey/` (the WebAuthn ceremony, `github.com/go-webauthn/webauthn`) is
a fifth package that is *not* in v0.1.0 -- §1.6.

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
  file stays each application's job (§1.7). The one thing that does not
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
  per token kind, audit sink, client-IP function).
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
func SaveWithRetry(ctx context.Context, b Backend, payload []byte, current int64) (version int64, conflicted bool, err error)
func LoadDocument(ctx context.Context, b Backend) ([]byte, int64, error)
func NewMemory() *Memory // in-memory Backend for tests
```

Identical to mikroview's `internal/persist/{persist,document,open}.go`.
`Open`'s fail-closed contract (a document that exists but cannot be
parsed is a startup error, never "empty") is kept: it is what stops a
corrupt accounts file re-opening registration to the next visitor.

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
    OIDCIssuer, OIDCSubject string; HasLocalPassword bool
    ResetCodeHash string; ResetCodeExpiresAt time.Time; MustChangePassword bool
    TOTPSecret string; TOTPConfirmedAt time.Time; TOTPLastCounter uint64
    RecoveryCodes []RecoveryCode; Passkeys []Passkey
}
func (u *User) LocalPassword() bool
func (u *User) HasActiveTOTP() bool
func (u *User) HasSecondFactor() bool

type Options struct { Log *slog.Logger }                                   // new
func OpenStore(b persist.Backend, opts Options) (*Store, error)            // = OpenWithBackend
func (s *Store) Persisted() bool
func (s *Store) Count() int
func (s *Store) Register(username, password string, now time.Time) (*User, error)          // first account only, becomes admin
func (s *Store) CreateUser(username, password string, role Role, now time.Time) (*User, error)
func (s *Store) DeleteUser(id string) (*User, error)
func (s *Store) TransferAdmin(toUsername string, now time.Time) (from, to *User, err error)
func (s *Store) Admin() *User
func (s *Store) HasLocalAdmin() bool
func (s *Store) Authenticate(username, password string, now time.Time) (*User, error)     // also redeems a live reset code
func (s *Store) Get(id string) (*User, bool)
func (s *Store) ByUsername(username string) (*User, bool)
func (s *Store) ByOIDCIdentity(issuer, subject string) (*User, bool)
func (s *Store) FindOrCreateOIDCUser(issuer, subject, usernameHint string, now time.Time) (*User, bool, error)
func (s *Store) LinkOIDCIdentity(userID, issuer, subject string, now time.Time) error
func (s *Store) SetPassword(username, newPassword string, now time.Time) error
func (s *Store) List() []User                                              // secrets blanked
// TOTP, recovery codes, reset codes: SetPendingTOTPSecret, ConfirmTOTP, VerifyAndRecordTOTP,
// ClearTOTP, GenerateRecoveryCodes(IfAbsent), BurnRecoveryCode, IssueResetCode -- as in mikroview.
// Passkeys: AddPasskey, RenamePasskey, DeletePasskey, RecordPasskeyAssertionIfFresh, ClearPasskeys,
// ClearAllSecondFactors, PasskeyCount -- storage methods only; no WebAuthn import.

func HashPassword(password string) (string, error)   // argon2id, m=64MiB t=3 p=4, 16-byte salt, 32-byte key
func VerifyPassword(password, encoded string) bool   // constant-time; parameters read from the encoded string
type KDFParams struct{ Memory, Time uint32; Threads uint8 }
func DefaultKDFParams() KDFParams
func DeriveKey(passphrase string, salt []byte, p KDFParams) []byte  // kept: mikroview's retention key uses it

type Session struct { ID, UserID string; IssuedAt, ExpiresAt time.Time }
func NewSessionStore(ttl, maxLifetime time.Duration) *SessionStore  // new: one constructor; mikroview's two collapse
func (s *SessionStore) Create(userID string, now time.Time) Session
func (s *SessionStore) Validate(id string, now time.Time) (Session, bool) // sliding ttl, capped at IssuedAt+maxLifetime
func (s *SessionStore) Revoke(id string)
func (s *SessionStore) RevokeAllForUser(userID string)

type TokenKind string
const ( TokenKindAPI TokenKind = "api"; TokenKindIngest TokenKind = "ingest" )
type Token struct { ID, Name string; Kind TokenKind; Device, HashedValue string
                    CreatedAt, LastUsedAt time.Time; CreatedBy, CreatedByUsername string } // JSON as mikroview token.go
type TokenOptions struct { Log *slog.Logger; Kinds []TokenKind }          // new: Kinds, default {api, ingest}
func OpenTokenStore(b persist.Backend, opts TokenOptions) (*TokenStore, error)
func (s *TokenStore) Create(name string, kind TokenKind, device string, creator *User, now time.Time) (raw string, tok *Token, err error)
func (s *TokenStore) Authenticate(raw string, want TokenKind, now time.Time) (*Token, bool) // SHA-256 lookup; kind must match
func (s *TokenStore) Revoke(id string) error
func (s *TokenStore) RevokeAllCreatedBy(userID string) (int, error)
func (s *TokenStore) List() []Token
func (s *TokenStore) ByKind(kind TokenKind) []*Token

func NewLoginLimiter(threshold int, window time.Duration) (*LoginLimiter, error) // ErrLimiterConfig on threshold < 1 or window <= 0
func (l *LoginLimiter) SetLog(log *slog.Logger)                    // eviction pressure, unsaved lockouts
func (l *LoginLimiter) Reserve(key string, now time.Time) bool     // addresses, unknown names: capped map
func (l *LoginLimiter) Release(key string, now time.Time)
func (l *LoginLimiter) RecordFailure(key string, now time.Time)
func (l *LoginLimiter) ReserveAccount(lockouts AccountLockouts, accountID string, now time.Time) bool // #19
func (l *LoginLimiter) ReleaseAccount(lockouts AccountLockouts, accountID string, now time.Time)
func (l *LoginLimiter) ReserveRecheck(accountID string, now time.Time) bool
func (l *LoginLimiter) ReleaseRecheck(accountID string, now time.Time)
type AccountLockouts interface {                                    // *Store implements it
    LoginLockedUntil(accountID string) time.Time
    SetLoginLockedUntil(accountID string, until time.Time) error
}

func ValidateUsername(username string) error       // 1–64 runes, no control/format chars
func ValidateLocalUsername(username string) error  // additionally: no "@"
```

Reasons for the three *new* items:

- `Options`/`TokenOptions` carry the logger instead of a package-level
  `persistLog`, because a module cannot call an app's `logging.New`.
- `TokenOptions.Kinds` replaces the hard-coded `TokenKind.Valid()`.
  Mikroview has a third kind, `droplist-pull`, that is its own business;
  its tokens document already contains such rows, and they must keep
  authenticating after the move. Mikroview declares
  `const TokenKindDroplistPull gauntlet.TokenKind = "droplist-pull"` and
  passes it in `Kinds`. Birdcage passes the default.
- `Device` keeps its Go name and JSON tag (mikroview's data has it). Its
  meaning is "the one principal an ingest token is bound to": a router in
  mikroview, nothing yet in birdcage (§2.3).

The limiter differs from mikroview's (#19, owner 2026-09-27). Mikroview
keeps every counter in one map of 4096 caller-chosen keys, evicted
oldest-first, so a flood of made-up names or addresses can evict the
counter guarding a real account. Here a real account's counters are
keyed by its ID in a map that is never evicted (bounded by the account
count, entries leave only by expiring), and only addresses and unknown
names share the capped map, which drops every expired key before
evicting a live one and logs, once per window, when it has to. A login
lockout is written to the account (`User.LoginLockedUntil`) so it
survives a restart, but only as it begins and as it clears: one save per
lockout episode, not one per wrong guess. Re-checking a signed-in
caller's own password has its own per-account budget, memory only.

Not exported: `newID` (16 random bytes, hex) stays private; apps that
want the same shape for their own ids already have one.

### 1.4 `gauntlet/oidc`

Mikroview's `internal/oidc` moves unchanged: `Config`, `New`, `Client.
AuthCodeURL/Exchange/VerifyIDToken`, `VerifyNonce`, `Identity`,
`Policy.Permit/Restricted`, `AllowIssuer`, `IsMultiTenantIssuer`,
`FlowState`, `NewFlowState`, `StateCodec.Encode/Decode`. It is already a
leaf package with plain-field config and no mikroview imports. The
self-hosted-only policy (`multiTenantIssuers`) moves with it and is not
made configurable: `docs/decisions/multi-tenant-oidc.md` decided that
deliberately, and [ADR-0003](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/adr/0003-mikroview-sidecar.md) adopted it for birdcage.

### 1.5 `gauntlet/gate`

```go
package gate

type Config struct {
    CookieName          string        // "mikroview_session" / "birdcage_session"
    SecureCookie        bool
    CSRFHeaderValue     string        // sent as X-Requested-With by the app's own frontend
    RequireSecondFactor bool          // mikroview: true (#1253). Birdcage: §1.6
    Log                 *slog.Logger
    Audit               Auditor       // nil = no audit
    ClientIP            func(*http.Request) string // limiter key; app owns trusted-proxy policy
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
}

func New(cfg Config, deps Deps) (*Gate, error)

// Protect is mikroview's requireAuth. Bearer tokens are tried first, in the
// order kinds were registered with Handle; a match is dispatched to that
// kind's handler and never to next. Otherwise: CSRF header on unsafe
// methods, exempt paths, session cookie, PasswordChangedAt check,
// MustChangePassword door, second-factor door, then next.
func (g *Gate) Protect(next http.Handler) http.Handler
func (g *Gate) Handle(kind gauntlet.TokenKind, h http.Handler) // e.g. TokenKindAPI -> the app's read-only mux
func (g *Gate) Exempt(paths ...string)                          // beyond the built-in /api/auth/* set

// Routes serves /api/auth/* and /api/tokens[/{id}] with mikroview's paths,
// request and response bodies. Mount it under the same Protect.
func (g *Gate) Routes() http.Handler

func UserFromContext(r *http.Request) *gauntlet.User
func TokenFromContext(r *http.Request) *gauntlet.Token
func RequireRole(min gauntlet.Role, next http.Handler) http.Handler // 403 below min
```

Routes carried over (mikroview `internal/api/server.go` route table):
`GET /api/auth/session`; `POST /api/auth/{register,login,login/factor,
logout,logout-all,password}`; `GET|POST /api/auth/users`,
`DELETE /api/auth/users/{id}`, `POST /api/auth/users/{id}/reset-password`,
`DELETE /api/auth/users/{id}/totp`; `POST /api/auth/totp/{enrol,confirm}`,
`DELETE /api/auth/totp`; `POST /api/auth/recovery-codes`;
`GET /api/auth/oidc/{login,callback}`,
`POST /api/auth/oidc/link`; `GET|POST /api/tokens`,
`DELETE /api/tokens/{id}`. Passkey routes join when `passkey/` lands.

What stays fixed inside `gate` because it is security behaviour, not
taste: `X-Requested-With` as the CSRF header name; cookie `HttpOnly`,
`SameSite=Lax`, path `/`, browser `Max-Age` 30 days; the OIDC flow cookie
scoped to `/api/auth/oidc` with a 5-minute life; the 503 "setup required"
state while `Count()==0` with only healthz, session, register and the
OIDC pair reachable; identical 401 bodies for unknown and revoked tokens;
login limiter keyed on both client IP and the account (its ID when the
name matches one, the name otherwise; §1.3) with reserve-then-release so
a correct password does not count as a failure.
The machine-readable 403 header that tells a frontend which door
refused it is `X-Auth-Gate`, the same for every app -- mikroview's
`X-Mikroview-Auth-Gate` is renamed, and its frontend follows when it
moves onto the module (owner, 2026-09-27, on #7).

Hard-coded strings that are mikroview's today and must not leak into
birdcage: the product name in TOTP enrolment URIs and passkey display
names, the `?ssoError=` redirect target, the 30-day cookie constant's
name. `Config` gains `ProductName` and `LoginPath` for the first two.

### 1.6 Second factors and passkeys -- recommendation, not a decision

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
- **Passkeys: the ceremony is not in v0.1.0.** The `Passkey` struct is
  plain fields (`[]byte`, `uint32`, `[]string`, a flags struct mirrored
  from `webauthn.CredentialFlags`), so storing them costs no dependency.
  The ceremony (`RelyingParty`, two sealed cookies, the spent-challenge
  map, `internal/api/{webauthn,passkey}.go`) brings
  `github.com/go-webauthn/webauthn` and needs a public URL to derive the
  RP id. Birdcage does not need it to gate #134. Recommend `gauntlet/
  passkey` as the first post-v1 slice, and before mikroview's #1202,
  which cannot ship without it (its users have passkeys).
- **`RequireSecondFactor` for birdcage: recommend on.** Birdcage changes
  firewall state and holds credentials, so [ADR-0003](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/adr/0003-mikroview-sidecar.md)'s "the case for
  gating it is stronger than mikroview's" applies to the second factor
  too. Cost: the TOTP enrol screen is in birdcage's v1 UI slice (§5).
  If the owner prefers a smaller first cut, off is a one-field change
  and the door can be closed later without touching data.

### 1.7 Deliberately not in the module

- Persisted sessions. Mikroview's are in-memory by design (re-login after
  restart, no signing keys); persisting them would change behaviour for
  existing users, which [ADR-0005](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/adr/0005-shared-auth-module.md) forbids.
- A SQL backend. Mikroview keeps its own (`internal/persist.PostgresBackend`);
  birdcage writes its own if it ever needs one. `persist.Memory` is for
  tests.
- Reading the key file itself. `persist.EncryptedFileBackend` (issue #18,
  see below) takes raw key bytes; finding, mounting and reading that
  file -- and deciding a store has no key and therefore no persistence
  -- stays each application's own job.
- The recovery-key store (`recovery.go`, mikroview's CLI gate) and the
  `-recover-admin-account` tooling. They are mikroview's operational
  surface; birdcage gets a `birdcage user` CLI over the same `Store`
  (§2.5) and mikroview keeps what it has.
- Trusted-proxy client-IP logic. It is deployment policy; the app passes
  `Config.ClientIP`.

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
approvals. Mikroview's single-admin rule and `TransferAdmin` come with
the module and are not reopened here.

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
  name       TEXT PRIMARY KEY,   -- 'accounts' | 'tokens'
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
BIRDCAGE_SESSION_TTL          default 24h   (mikroview default)
BIRDCAGE_SESSION_MAX_LIFETIME default 168h  (mikroview default)
BIRDCAGE_OIDC_ISSUER_URL, _CLIENT_ID, _CLIENT_SECRET_FILE, _SCOPES
BIRDCAGE_OIDC_ALLOWED_GROUPS, _ALLOWED_EMAILS, _ALLOWED_EMAIL_DOMAINS
BIRDCAGE_PUBLIC_URL           redirect URL base (never the Host header) and, later, the passkey RP id
```

Startup: `oidc.AllowIssuer` refuses a multi-tenant issuer before
listening, as mikroview's `main.go:1723` does -- `oidc.New` refuses it
as well, so this call is belt-and-braces, not the only check. Login
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
then TOTP/recovery code), first-run register, forced change-password,
forced second-factor enrolment (QR + confirm, recovery codes shown once),
users admin, tokens admin, SSO button and `?ssoError=` handling. `api.ts`
gains the `X-Requested-With: birdcage` header on every request and a 401
→ login redirect.

### 2.7 SECURITY.md

Rewritten route-by-route from the table in §2.1, as [ADR-0003](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/adr/0003-mikroview-sidecar.md) requires.

## 3. Mikroview wiring, later (#1202)

Not done in this work; recorded so the API above is checked against it.

- `internal/auth` → `import auth "github.com/tomlawesome/gauntlet"`. The
  document shapes (`storeFile{Users}` for accounts, `[]*Token` for
  tokens; store names `auth` and `tokens` in `store_blob`, or
  `users.json`/`tokens.json` files) are unchanged, so a copy of real
  data loads without migration -- the acceptance test [ADR-0005](https://gitlab.tomlawson.io/ai/birdcage/-/blob/dev/docs/adr/0005-shared-auth-module.md) assigns
  to #1202.
- `persist.Backend`: mikroview's file, Postgres and write-behind
  backends satisfy gauntlet's interface as they stand. One line:
  `ErrConflict = gpersist.ErrConflict`. Its own
  `internal/persist.EncryptedFileBackend` already moved to
  `gauntlet/persist` (issue #18); mikroview's stores can switch to the
  gauntlet one directly, passing `retention.Key`'s raw material rather
  than the `*retention.Key` type.
- Constructor renames: `OpenWithBackend(b)` → `OpenStore(b, Options{Log:
  logging.New("auth")})`; `OpenTokenStoreWithBackend(b)` →
  `OpenTokenStore(b, TokenOptions{Kinds: […, TokenKindDroplistPull]})`;
  `NewSessionStoreWithMaxLifetime(ttl, max)` → `NewSessionStore(ttl,
  max)`. Call sites: `main.go:839, 970, 1930-1937` and the CLI tools.
- `internal/oidc` → `gauntlet/oidc`, no other change (`main.go:1733`).
- Handlers: two steps. First mikroview keeps `internal/api/{auth,oidc,
  tokens}.go` over gauntlet's stores -- everything they call is in §1.3
  by the same name, so the frontend sees identical JSON. Second, once
  `gauntlet/passkey` exists, mikroview swaps to `gate.Routes()` and
  deletes its copies. `Server` fields `Auth, Sessions, LoginLimiter,
  SecureCookie, Tokens, OIDC, OIDCState, OIDCPolicy, RelyingParty`
  (`server.go:354-458`) map one-to-one onto `gate.Deps`/`gate.Config`.
- `DeriveKey`/`KDFParams` stay exported so mikroview's retention
  encryption keeps importing them from the same place its passwords
  come from.

Checked and fits without a data change: `User` (all 19 fields), `Token`
(9 fields, `droplist-pull` via `Kinds`), `Session` semantics
(`IssuedAt` vs `PasswordChangedAt`, sliding ttl with ceiling), the
(issuer, subject) index, `FindOrCreateOIDCUser`'s first-user-is-admin
rule, `LinkOIDCIdentity`'s admin-keeps-password rule (#1252),
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
| Sessions that never expire | sliding 24h idle + 7-day ceiling from `IssuedAt` (#294) | both, enforced in `Validate`, not by readers of `ExpiresAt` |
| Session survives a password reset from another process | `IssuedAt < PasswordChangedAt` → revoke, checked per request | kept in `gate.Protect`; the CLI in §2.5 depends on it |
| CSRF | `SameSite=Lax` + `X-Requested-With` on unsafe methods; bearer requests bypass CSRF because cookies are not involved | kept; header value per app |
| Cookie over plain HTTP | `Secure` on by default, off only with TLS off | kept; birdcage derives the default from its listener |
| Logout that does not revoke | server-side delete; logout-all revokes every session of the user | kept |

### OIDC

| Pitfall | Mikroview today | Module keeps |
|---|---|---|
| Code interception / replay | Authorization Code + PKCE S256, `state` and `nonce` compared constant-time, verifier held in an AES-256-GCM cookie the browser cannot read or forge | all of it; the flow-state key is per process |
| Algorithm confusion (`alg:none`, HS256 with the public key) | explicit allowlist RS256/ES256/PS256 on the verifier | kept explicit rather than relying on go-oidc's default |
| Account takeover by email match | identity is (issuer, subject); email and `preferred_username` are display hints only | kept; the index is a struct key |
| Public IdP hands admin to the first visitor | multi-tenant issuers refused at startup; first OIDC user becomes admin only when the store is empty | kept, not configurable |
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
| Username or token enumeration | one 401 body for missing, wrong and revoked; `ErrInvalidCredentials` for unknown user and wrong password alike; dummy Argon2id hash so timing matches | kept |
| Argon2id as a DoS lever | 64 MiB per hash, at most 4 concurrent (`maxConcurrentHashes`), login limiter in front | kept |
| Brute force | 5 failures per 5 min per IP and per username, bounded key map with batch eviction | changed (#19): an existing account's counter is keyed by its ID, never evicted, and its lockout is saved on the account so a restart does not lift it (one save per lockout, not per guess); addresses and unknown names keep the capped map, expired keys dropped first. Birdcage's `ClientIP` is `RemoteAddr` until a trusted-proxy setting exists, so behind a proxy the IP bucket collapses to one -- the account bucket still holds |
| `golang.org/x/crypto` advisories | all 30 entries are in `ssh`, `ssh/agent` or `openpgp`; none touches `argon2` | import only `argon2`; birdcage already carries this module at 0.57.0 |

### Second factors (data in v1; ceremonies per §1.6)

TOTP replay is guarded by `TOTPLastCounter`; recovery codes are
Argon2id-hashed and single-use; the reset code is Argon2id-hashed,
24-hour, single-use, and replaces the password outright. Passkey
sign-count regression is recorded to flag clones. `github.com/go-webauthn/
webauthn` has no entry in either advisory database today; that is
re-checked when the `passkey` slice is filed.

### Fail-closed list

Unparseable accounts document → refuse to start. Unknown role → denied
everything. Unknown token kind → never authenticates. Missing claim →
refused. Backend write failure → in-memory change rolled back and the
error returned (every mutating `Store` method in mikroview does this;
the module's tests assert it per method).

## 5. Build plan

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
  *Done when:* a copy of a mikroview `users.json` fixture loads, saves
  and reloads byte-identical, and every ported test passes.
- **G3 Sessions, tokens, limiter.** `SessionStore`, `TokenStore` with
  `Kinds`, `LoginLimiter`, `internal/evict`. *Done when:* a mikroview
  tokens fixture containing `droplist-pull` rows round-trips and only
  registered kinds authenticate.
- **G4 Second-factor data and stdlib flows.** TOTP, recovery codes,
  reset codes, passkey storage methods (no WebAuthn). *Done when:* the
  full mikroview `User` document round-trips and `Authenticate` redeems
  a reset code exactly once.
- **G5 `oidc`.** Package moved with its fake provider. *Done when:* the
  ported tests pass and `AllowIssuer` refuses the multi-tenant list.
- **G6 `gate`.** Middleware and handlers with `Config`/`Deps`; the
  built-in exempt and bootstrap sets; audit hook. *Done when:* an
  httptest server over `persist.Memory` passes the ported
  `internal/api/auth_test.go` cases for register, login, TOTP door,
  change-password door, token dispatch, OIDC callback (fake provider) and
  CSRF.
- **G7 Tag v0.1.0** (owner, 2026-09-26: the first release is v0.1.0, not v1.0.0). *Done when:* `CHANGELOG.md` lists G1-G6 and
  birdcage can `go get` the tag.
- **B1 Storage backend and migration.** `0025_auth_store`,
  `store.NewAuthBackend`, `VersionReader`. *Done when:* the persist
  contract test (ported from mikroview `persist/contract_test.go`)
  passes on SQLite and Postgres.
- **B2 Wire the gate.** `requireAuth` → `gate.Protect`; API tokens to
  `dashboardRoutes`; `g.Routes()`; env config; startup issuer check;
  `mailConfigured`-style plumbing for `Gate`. *Done when:* every
  `GET /api/*` answers 401 without a session and 200 with one, and an API
  token reaches `GET /api/alerts` but not `/api/auth/users`.
- **B3 CLI `birdcage user`.** *Done when:* `reset-password` against a
  live server is honoured on the next request without restart.
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
- **G8 `passkey` package** (after B4, before mikroview #1202). *Done
  when:* mikroview's `webauthn_test.go` cases pass against it.

## 6. What the owner has to do

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

Written by Fable 5.1, 2026-09-26. Owner decisions recorded by Opus 5.5, 2026-09-26.
