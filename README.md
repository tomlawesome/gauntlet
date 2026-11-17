# gauntlet

A shared Go authentication library for the applications that embed it:
local accounts and roles, sessions, API tokens, single sign-on through
OIDC (OpenID Connect), the second factor every account with a password
must hold -- an authenticator app (TOTP) or a passkey, with recovery
codes -- and the
HTTP layer that checks all of that in front of an application's own
routes. One implementation, so a security fix lands once.

**Status: pre-1.0.** From v0.1.0 nothing exported -- Go identifiers,
routes, response fields and stored fields -- is removed or renamed
within a major version ([ADR-0002](docs/adr/0002-api-standards-and-compatibility.md);
CI checks the Go identifiers with a tool called apidiff). A release can
still add a required setting. [CHANGELOG.md](CHANGELOG.md) flags that as
breaking (v0.3.0's `Config.AdminPasskey` was one) and says what each
release added.

## What ships

- Local accounts with three roles (admin, user, viewer), Argon2id
  password hashing, and a one-time setup code that guards creating the
  first admin.
- Sessions that end after at most an hour unused or a day old, and API
  tokens that expire.
- Single sign-on through OIDC, with the account's role taken from the
  provider's groups when the application asks for that.
- Second factors: an authenticator app (TOTP) and passkeys, with
  recovery codes. A passkey (a sign-in key stored on your phone or
  computer, unlocked by fingerprint or PIN) can also be used to sign in
  without typing the password (the account still keeps its password).
- Lockout after repeated failures, and a chosen response to an unusual
  sign-in: a new browser, a new country, or a place too far from the last
  sign-in to have travelled to in the time between.
- A sign-in history an admin can page through, with the country each
  sign-in came from.
- A built-in list of common passwords, rebuilt automatically on a schedule, and an optional
  live check against Have I Been Pwned.
- The HTTP layer, `gauntlet/gate`: a `net/http` middleware and the
  `/api/auth/*` and `/api/tokens` routes.

## What stays with the application

gauntlet leaves three things to the application:

- **Storage.** gauntlet keeps each store's data (accounts, tokens,
  sign-in history) in memory and saves it whole, as one block of JSON
  text. The accounts and token stores save after every change; the
  sign-in history saves in the background within a minute. It saves through a `persist.Backend` the
  application writes over its own storage: a file, a database row.
  `persist.Encrypt` encrypts the data before the backend sees it;
  `OpenStore` (accounts) and `OpenSignInHistory` refuse a backend that
  would save their data unencrypted. Two
  backends ship:
  `persist.NewEncryptedFileBackend` for a single file, and
  `persist.NewMemory()` for tests.
- **Logging.** Every store's options take a `*slog.Logger`; nil
  discards.
- **The clock.** Most store methods that need the current time take it as
  an argument (a `time.Time`), and gate reads it from `Config.Now`, so the
  application supplies it and tests can use a fixed time.

## A minimal sketch

```go
key := readKeyFile() // at least persist.MinKeyBytes (32) bytes; keeping it is the app's job
accounts, err := persist.Encrypt(myBackend, key, persist.EncryptOptions{Label: "accounts"})
store, err := gauntlet.OpenStore(accounts, gauntlet.Options{Log: logger, ProductName: "myapp"})
// An empty store announces a one-time setup code: it logs it, or hands
// it to Options.OnSetupCode. Whoever creates the first account must
// type it in. In a web app the gate package checks it for you; here
// you call CheckSetupCode yourself, before Register.
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
  ([ADR-0001](docs/adr/0001-shared-auth-module.md)) to requiring a
  passkey on every admin account (ADR-0015).
- [docs/api/auth.yaml](docs/api/auth.yaml): every route, written as an
  OpenAPI file (a standard machine-readable description of web routes).
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

The `geoip` package downloads country data from MaxMind or IPinfo (two
IP-location services) while the application runs, and includes none in
the library. Both providers require the application that shows their
data to credit them, and gauntlet has no page of its own to do it on;
[docs/geoip.md](docs/geoip.md) quotes what each asks for.
