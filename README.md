# gauntlet

A shared Go authentication library: local accounts, sessions, tokens,
OIDC and the HTTP middleware that gates them -- factored out of
[mikroview](https://github.com/tomlawesome/mikroview) so it and
[birdcage](https://gitlab.tomlawson.io/ai/birdcage) share one
implementation instead of two copies that drift apart.

**Status: pre-v0.1.0, not for use yet.** The API is still being built out
issue by issue against the design in [docs/design.md](docs/design.md);
nothing here has a stability guarantee until it tags.

See [docs/adr/0001-shared-auth-module.md](docs/adr/0001-shared-auth-module.md)
for why this module exists, and [SECURITY.md](SECURITY.md) for its threat
model.

## Using gauntlet

gauntlet holds accounts, sessions, tokens and password/OIDC identity. It
does not talk to a database or a browser directly -- three things stay
with the application that imports it:

- **Storage.** gauntlet keeps its whole dataset in memory and asks to
  have it written down after every change, through a `persist.Backend`
  the app implements over its own storage (a file, a database table).
  `persist.NewMemory()` is a ready-made backend for tests; nothing else
  ships one.
- **Logging.** Every store's `Options`/`TokenOptions` takes a
  `*slog.Logger` (nil discards). gauntlet can't call an app's own
  logging constructor, so the app passes its logger in.
- **The clock.** Every method that needs "now" takes it as an explicit
  `time.Time` parameter rather than calling `time.Now()` itself, so the
  app decides -- and tests can hold time still.

A minimal sketch:

```go
store, err := gauntlet.OpenStore(myBackend, gauntlet.Options{Log: logger})
// An empty store logs a one-time setup code (or hands it to
// Options.OnSetupCode); the first-run screen sends it with the
// first account's credentials, and gate checks it before Register.
err = store.CheckSetupCode(typedCode)
admin, err := store.Register("alice", password, time.Now()) // first account -> admin
user, err := store.Authenticate("alice", password, time.Now())
```

Runnable, checked examples for the entry points above, plus
`NewSessionStore`, `OpenTokenStore` and `NewLoginLimiter`, are in
[example_test.go](example_test.go) and
[persist/example_test.go](persist/example_test.go) -- read them with
`go doc github.com/tomlawesome/gauntlet` or on
[pkg.go.dev](https://pkg.go.dev/github.com/tomlawesome/gauntlet) once
this module is published there.

The HTTP layer that wires these into a `net/http` middleware is
`gauntlet/gate`: `New` builds it, `Protect` is the middleware, and
`Routes` serves mikroview's `/api/auth/*` and `/api/tokens` routes. See
`go doc github.com/tomlawesome/gauntlet/gate` and
[docs/design.md](docs/design.md) §1.5.

## Licence

Apache-2.0. See [LICENSE](LICENSE).

The common-password list in `gauntlet/blocklist` is built from
[Have I Been Pwned](https://haveibeenpwned.com)'s Pwned Passwords. HIBP
places no licence terms on that data; the attribution is ours to give.
