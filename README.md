# gauntlet

A shared Go authentication library for the applications that embed it:
local accounts and roles, sessions, API tokens, single sign-on through
OIDC (OpenID Connect), the second factor every account must have -- an
authenticator app (TOTP) or a passkey, with recovery codes -- and the
HTTP layer that checks all of that in front of an application's own
routes. One implementation, so a security fix lands once.

**Status: pre-1.0, so the API may change between minor versions.**
[CHANGELOG.md](CHANGELOG.md) says what each release added and what
changed shape. Nothing has a stability guarantee until v1.0.

## What ships

- Local accounts with three roles (admin, user, viewer), Argon2id
  password hashing, and a one-time setup code that guards creating the
  first admin.
- Sessions that end after at most an hour unused or a day old, and API
  tokens that expire.
- Single sign-on through OIDC, with the account's role taken from the
  provider's groups when the application asks for that.
- Second factors: an authenticator app (TOTP) and passkeys, with
  recovery codes. A passkey can also be the whole sign-in.
- Lockout after repeated failures, and a chosen response to an unusual
  sign-in: a new browser, a new country, or an impossible distance from
  the last one.
- A sign-in history an admin can page through, with the country each
  sign-in came from.
- A built-in list of common passwords, rebuilt by CI, and an optional
  live check against Have I Been Pwned.
- The HTTP layer, `gauntlet/gate`: a `net/http` middleware and the
  `/api/auth/*` and `/api/tokens` routes.

## What stays with the application

gauntlet does not talk to a database or a browser directly. Three
things are the application's:

- **Storage.** gauntlet keeps each store's data in memory as one
  *document* (a single JSON blob, written out whole after every change)
  through a `persist.Backend` the application implements over its own
  storage: a file, a database row. `persist.Encrypt` *seals* (encrypts)
  the document before the backend sees it; `OpenStore` refuses a backend
  that would store it in the clear. Two backends ship:
  `persist.NewEncryptedFileBackend` for a single file, and
  `persist.NewMemory()` for tests.
- **Logging.** Every store's options take a `*slog.Logger`; nil
  discards.
- **The clock.** Every method that needs "now" takes a `time.Time`, so
  the application decides and tests can hold time still.

## A minimal sketch

```go
key := readKeyFile() // at least persist.MinKeyBytes (32) bytes; keeping it is the app's job
accounts, err := persist.Encrypt(myBackend, key, persist.EncryptOptions{Label: "accounts"})
store, err := gauntlet.OpenStore(accounts, gauntlet.Options{Log: logger, ProductName: "myapp"})
// An empty store announces a one-time setup code: it logs it, or hands
// it to Options.OnSetupCode. Whoever creates the first account must
// type it in; the HTTP layer checks it before Register.
err = store.CheckSetupCode(typedCode)
admin, err := store.Register("alice", password, time.Now()) // the first account is always the admin
```

Everything after that -- the HTTP layer, password checks, telling an
account's owner what happened, the sign-in history and country -- is
in [docs/using.md](docs/using.md).

## Where to read more

- [docs/using.md](docs/using.md): wiring gauntlet into an application,
  step by step.
- [docs/design.md](docs/design.md): the design, package by package.
- [docs/adr/](docs/adr/): one architecture decision record (ADR) per
  decision, from why the module exists
  ([ADR-0001](docs/adr/0001-shared-auth-module.md)) to accepting
  Google's shared SSO issuer (ADR-0014).
- [docs/api/auth.yaml](docs/api/auth.yaml): every route, as an OpenAPI
  contract.
- [docs/api/errors.md](docs/api/errors.md): every error body.
- [SECURITY.md](SECURITY.md): the threat model and how to report a
  vulnerability.
- `go doc github.com/tomlawesome/gauntlet`: runnable, checked examples
  for each entry point.

## Licence

Apache-2.0. See [LICENSE](LICENSE).

The common-password list in `gauntlet/blocklist` is built from
[Have I Been Pwned](https://haveibeenpwned.com)'s Pwned Passwords. HIBP
puts no licence terms on that data, so no credit is owed; gauntlet
gives one anyway, here and in the header of every copy of the list, and
an application that embeds gauntlet does not have to repeat it.

The `geoip` package downloads MaxMind's or IPinfo's data at run time and
ships none. Both providers require the application that shows their
data to credit them, and gauntlet has no page of its own to do it on;
[docs/geoip.md](docs/geoip.md) quotes what each asks for.
