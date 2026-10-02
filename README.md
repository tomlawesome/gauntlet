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

Every new local password is checked before it is set (#43): not the
username or the product's name (`Options.ProductName`), not on the
common-password list (`Options.PasswordBlocklist`, by default the one
built into the release, `blocklist.Embedded()`), and -- only if the app
opts in, since it is an outbound call -- not in Have I Been Pwned's
breach corpus:

```go
hibp, err := blocklist.NewPwnedChecker(blocklist.PwnedConfig{}) // only a 5-character hash prefix leaves the process
store, err := gauntlet.OpenStore(myBackend, gauntlet.Options{
	Log: logger, ProductName: "birdcage", BreachCheck: hibp,
})
```

If HIBP cannot be reached the password is accepted against the built-in
list and checked again at the account's next sign-in; a hit then forces
a password change. See [docs/design.md](docs/design.md) §1.3.

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

gate records every sign-in attempt, failed ones included, through
`Config.Audit`, with the client address `Config.ClientIP` resolves, and
logs refused requests to `Config.Log` (see design.md §1.5). An admin can
sign another account out everywhere (`POST
/api/auth/users/{id}/logout-all`). gauntlet sends no mail itself; to tell
the account's owner, set `Config.Notify`:

```go
type mailNotifier struct{ mail *myapp.Mailer; users *myapp.Directory }

func (m mailNotifier) SessionsEnded(ctx context.Context, n gate.SessionsEndedNotice) error {
	to, ok := m.users.EmailFor(n.Username) // the app maps the account to an address
	if !ok {
		return nil // nobody to tell
	}
	return m.mail.Send(ctx, to, "You were signed out",
		fmt.Sprintf("An administrator (%s) signed you out of %d sessions. Reason: %s", n.EndedBy, n.Ended, n.Reason))
}

g, err := gate.New(gate.Config{ /* ... */ Notify: mailNotifier{mail, users}}, deps)
```

It is called after the admin's response, in its own goroutine, with a
context that ends after 10 seconds; an error or panic is logged and
never changes the admin's answer. `Reason` may be empty: the message
should still say an administrator signed them out.

## Licence

Apache-2.0. See [LICENSE](LICENSE).

The common-password list in `gauntlet/blocklist` is built from
[Have I Been Pwned](https://haveibeenpwned.com)'s Pwned Passwords. HIBP
places no licence terms on that data; the attribution is ours to give.
