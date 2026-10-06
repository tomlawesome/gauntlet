# gauntlet

A shared Go authentication library. It holds local accounts and roles,
sessions, API tokens, single sign-on through OIDC (OpenID Connect), the
second factor every account must have -- an authenticator app (TOTP) or
a passkey, with recovery codes -- and the HTTP layer that checks all of
that in front of an application's own routes. It was factored out of
[mikroview](https://github.com/tomlawesome/mikroview) so it and
[birdcage](https://gitlab.tomlawson.io/ai/birdcage) share one
implementation instead of two copies that drift apart.

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

[docs/design.md](docs/design.md) is the design, package by package.
[docs/adr/](docs/adr/) holds one architecture decision record (ADR) per
decision, from why the module exists
([ADR-0001](docs/adr/0001-shared-auth-module.md)) to roles from SSO
groups (ADR-0013). [SECURITY.md](SECURITY.md) is the threat model and
how to report a vulnerability.

## Using gauntlet

gauntlet does not talk to a database or a browser directly. Three
things stay with the application that imports it:

- **Storage.** gauntlet keeps each store's data in memory as one
  *document* -- a single JSON blob, written out whole after every
  change -- through a `persist.Backend` the application implements over
  its own storage (a file, a database row). Wrap that backend in
  `persist.Encrypt` so the document is *sealed* (encrypted) before the
  backend ever sees it: `OpenStore` refuses a backend that would store
  it in the clear, because the document holds every account's TOTP
  secret. Two backends ship ready-made: `persist.NewEncryptedFileBackend`
  for a single file, already sealed, and `persist.NewMemory()` for
  tests.
- **Logging.** Every store's `Options`/`TokenOptions` takes a
  `*slog.Logger` (nil discards). gauntlet can't call an app's own
  logging constructor, so the app passes its logger in.
- **The clock.** Every method that needs "now" takes it as an explicit
  `time.Time` parameter rather than calling `time.Now()` itself, so the
  app decides -- and tests can hold time still.

A minimal sketch:

```go
key := readKeyFile() // at least persist.MinKeyBytes (32) bytes; keeping it is the app's job
accounts, err := persist.Encrypt(myBackend, key, persist.EncryptOptions{Label: "accounts"})
store, err := gauntlet.OpenStore(accounts, gauntlet.Options{Log: logger, ProductName: "birdcage"})
// An empty store announces a one-time setup code: it logs it, or hands
// it to Options.OnSetupCode. Whoever creates the first account must
// type it in; gate checks it before Register.
err = store.CheckSetupCode(typedCode)
admin, err := store.Register("alice", password, time.Now()) // the first account is always the admin
user, err := store.Authenticate("alice", password, time.Now())
```

Every new local password is checked before it is set, and refused if it
is:

- too short, or the username or the product's name
  (`Options.ProductName`) with case, digits or punctuation around it
- on the common-password list (`Options.PasswordBlocklist`, by default
  the one built into the release, `blocklist.Embedded()`)
- in Have I Been Pwned (HIBP)'s breach corpus, when the app opts in --
  since it is an outbound call:

```go
hibp, err := blocklist.NewPwnedChecker(blocklist.PwnedConfig{}) // only a 5-character hash prefix leaves the process
store, err := gauntlet.OpenStore(accounts, gauntlet.Options{
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

## The HTTP layer

`gauntlet/gate` (the gate package) is the HTTP layer. `gate.New` builds
it from a `Config` and the stores above (`Deps`); `Protect` is the
`net/http` middleware that checks the session cookie, or an API token,
before a request reaches the application; `Routes` serves the
`/api/auth/*` and `/api/tokens` routes mikroview's frontend already
speaks. Mount `Routes` behind `Protect`. Single sign-on and passkeys are
optional: leave `Deps.OIDC` or `Deps.Passkeys` nil and their routes
answer 404. See `go doc github.com/tomlawesome/gauntlet/gate`,
[docs/api/auth.yaml](docs/api/auth.yaml) (every route) and
[docs/api/errors.md](docs/api/errors.md) (every error body).

gate records every sign-in attempt, failed ones included. Each one goes
to `Config.Audit` as one record: who acted, what happened
(`user.login_failed`, `account.locked` and so on), which account it
concerned, and a detail line that includes the client address.
`Config.ClientIP` is the function that works that address out from the
request, because only the application knows which proxies to trust. A
request gate refuses -- rate-limited, missing its CSRF header, lacking
the role -- is one warning line on `Config.Log`.

gauntlet sends no mail itself. To tell an account's owner that
something happened to their account -- a password reset, a second
factor added or removed, a lockout, an admin signing them out
everywhere (`POST /api/auth/users/{id}/logout-all`), an unusual
sign-in, a role change, an API token about to expire -- set
`Config.Notices`. It is called with one `AccountNotice` per event: the
event's `Kind`, the account, and a detail for that kind:

```go
type mailNotifier struct{ mail *myapp.Mailer; users *myapp.Directory }

func (m mailNotifier) AccountEvent(ctx context.Context, n gate.AccountNotice) error {
	to, ok := m.users.EmailFor(n.Username) // the app maps the account to an address
	if !ok {
		return nil // nobody to tell
	}
	switch n.Kind {
	case gate.NoticeSessionsEnded:
		return m.mail.Send(ctx, to, "You were signed out",
			fmt.Sprintf("An administrator (%s) signed you out of %d sessions. Reason: %s", n.By, n.SessionsEnded.Ended, n.SessionsEnded.Reason))
	}
	return nil // the other kinds: see gate.NoticeKind
}

g, err := gate.New(gate.Config{ /* ... */ Notices: mailNotifier{mail, users}}, deps)
```

It is called after the response that caused it, in its own goroutine,
with a context that ends after 10 seconds. An error or panic is logged
and never changes that response. `Reason` may be empty: the message
should still say an administrator signed them out. The older
`Config.Notify`, which heard about sign-outs only, still works but is
deprecated; `New` refuses a `Config` with both set.

To give admins a sign-in history (`GET /api/auth/sign-ins`), open a
third document beside the accounts and tokens ones. Each document is
sealed under its own `Label`, so one copied from another store is
refused rather than read. Close the history at shutdown so its last
rows are saved:

```go
sealed, err := persist.Encrypt(myBackendFor("signins"), key, persist.EncryptOptions{Label: "signins"})
signIns, err := gauntlet.OpenSignInHistory(sealed, gauntlet.SignInHistoryOptions{Log: logger}) // MaxRows 0: the newest 10,000
defer signIns.Close()
g, err := gate.New(cfg, gate.Deps{ /* ... */ SignIns: signIns})
```

Leave `Deps.SignIns` nil and the route answers 404; the audit records
are written either way. See
[docs/adr/0006-sign-in-history.md](docs/adr/0006-sign-in-history.md).

To record which country each sign-in came from, run a `geoip.Manager`
on the operator's chosen provider and key, and pass its `Country`.
Lookups happen in a file kept on the server; no address is sent
anywhere. The application credits the provider (see Licence, below)
and leaves `Dir` out of backups ([docs/geoip.md](docs/geoip.md)):

```go
countries, err := geoip.New(geoip.Config{Source: geoip.SourceIPinfo, IPinfo: geoip.IPinfoKey{Token: token}, Dir: dataDir + "/geoip", Log: logger})
go countries.Run(ctx) // checks daily; Close it once Run has returned
g, err := gate.New(gate.Config{ /* ... */ Country: countries.Country}, deps)
```

## Licence

Apache-2.0. See [LICENSE](LICENSE).

The common-password list in `gauntlet/blocklist` is built from
[Have I Been Pwned](https://haveibeenpwned.com)'s Pwned Passwords. HIBP
puts no licence terms on that data, so no credit is owed; gauntlet
gives one anyway, here and in the header of every copy of the list, and
an application that imports gauntlet does not have to repeat it.

The `geoip` package downloads MaxMind's or IPinfo's data at run time and
ships none. Both providers require the application that shows their
data to credit them, and gauntlet has no page of its own to do it on;
[docs/geoip.md](docs/geoip.md) quotes what each asks for.
