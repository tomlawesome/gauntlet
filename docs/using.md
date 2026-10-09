# Using gauntlet in an application

This page is for the developer wiring gauntlet into an application. It
walks the steps in the order an application takes them: open the
stores, build the HTTP layer, then turn on the optional parts. Each
snippet compiles against the current API.

[README.md](../README.md) has what ships and the three things that
stay with the application (storage, logging, the clock).
[design.md](design.md) has the reasoning behind each piece.

## Open the stores

The HTTP layer needs four stores. Each one is opened by the
application, which keeps the key and the backends.

```go
key := readKeyFile() // at least persist.MinKeyBytes (32) bytes

accounts, err := persist.Encrypt(myBackendFor("accounts"), key, persist.EncryptOptions{Label: "accounts"})
store, err := gauntlet.OpenStore(accounts, gauntlet.Options{Log: logger, ProductName: "myapp"})

tokenDoc, err := persist.Encrypt(myBackendFor("tokens"), key, persist.EncryptOptions{Label: "tokens"})
tokens, err := gauntlet.OpenTokenStore(tokenDoc, gauntlet.TokenOptions{Log: logger})

sessions := gauntlet.NewSessionStore(gauntlet.MaxSessionIdle, gauntlet.MaxSessionLifetime)
limiter, err := gauntlet.NewLoginLimiter(5, time.Minute) // failed sign-ins per address before a 429
```

- **Accounts** (`OpenStore`) and **tokens** (`OpenTokenStore`) are each
  one *document*: a single JSON blob, written out whole after every
  change, through a `persist.Backend` the application implements over
  its own storage. Wrap the backend in `persist.Encrypt` so the document
  is *sealed* (encrypted) before the backend sees it. `OpenStore`
  refuses a backend that would store the document in the clear, because
  it holds every account's TOTP secret; `Options.AllowPlaintextAtRest`
  is the only way past that, and it is a decision, not a default.
- The `Label` is not secret. It is bound into the ciphertext so a
  document copied from one store into another fails to open there
  instead of being read as something else. Use the same label every
  time the same store is opened.
- Two backends ship ready-made: `persist.NewEncryptedFileBackend(path,
  key)`, one sealed file, and `persist.NewMemory()` for tests.
- **Sessions** live in memory only (`NewSessionStore`): a restart signs
  everyone out. The two arguments are the idle timeout and the ceiling;
  `gate.New` refuses a store set longer than `gauntlet.MaxSessionIdle`
  (one hour) and `gauntlet.MaxSessionLifetime` (a day).
- **The login limiter** (`NewLoginLimiter`) allows that many attempts
  per window for each client address, and for each account, before it
  refuses further ones. It also fronts the setup code, so a guess costs
  the server nothing but a comparison.

An empty accounts store announces a one-time setup code: it logs it, or
hands it to `Options.OnSetupCode`. Whoever creates the first account
must type it in; the HTTP layer checks it before `Register`, and the
first account is always the admin.

### Password checks

Every new local password is checked before it is set, and refused if it
is:

- too short, or the username or the product's name
  (`Options.ProductName`) with case, digits or punctuation around it
- on the common-password list (`Options.PasswordBlocklist`; by default
  the one built into the release, `blocklist.Embedded()`)
- in Have I Been Pwned (HIBP)'s breach corpus, when the application opts
  in -- it is an outbound call, so gauntlet never makes it unasked:

```go
hibp, err := blocklist.NewPwnedChecker(blocklist.PwnedConfig{}) // only a 5-character hash prefix leaves the process
store, err := gauntlet.OpenStore(accounts, gauntlet.Options{
	Log: logger, ProductName: "myapp", BreachCheck: hibp,
})
```

If HIBP cannot be reached the password is accepted against the built-in
list and checked again at the account's next sign-in; a hit then forces
a password change. See [design.md](design.md) §1.3 and
[ADR-0007](adr/0007-common-password-list.md) for how the list is kept
fresh.

## Build the HTTP layer

`gauntlet/gate` (the gate package) is the HTTP layer. `gate.New` builds
it from a `Config` and the stores above (`Deps`):

```go
g, err := gate.New(gate.Config{
	CookieName:      "myapp_session",
	SecureCookie:    tlsOn, // the app knows whether TLS terminates in front of it
	CSRFHeaderValue: "myapp",
	ProductName:     "myapp",
	ClientIP:        func(r *http.Request) string { return r.RemoteAddr },
	AdminPasskey:    gate.AdminPasskeyOptional, // or gate.AdminPasskeyRequired; there is no default
	Log:             logger,
}, gate.Deps{Users: store, Sessions: sessions, Tokens: tokens, Limiter: limiter})

mux := http.NewServeMux()
mux.Handle("/api/auth/", g.Routes())
mux.Handle("/api/tokens", g.Routes())
mux.Handle("/api/tokens/", g.Routes())
mux.Handle("/", myApp)
handler := g.Protect(mux) // serve this
```

- `Protect` is the `net/http` middleware. It checks the CSRF header on
  every unsafe request, then the session cookie, before a request
  reaches the application. Mount `Routes` behind the same `Protect` that
  guards the rest of the application: `Routes` does not call it itself.
- `Routes` serves the `/api/auth/*` and `/api/tokens` routes.
  [api/auth.yaml](api/auth.yaml) describes every one and
  [api/errors.md](api/errors.md) every error body.
- `CSRFHeaderValue` is required: the frontend sends it as
  `X-Requested-With` on every unsafe request, and an empty value would
  let a missing header pass.
- `ProductName` is required: it names the deployment in the URI an
  authenticator app scans, and no password may be it.
- `ClientIP` is required: it works the client address out from the
  request, because only the application knows which proxies to trust.
  The login limiter and every audit record use it.
- `SecureCookie` false logs one warning at start-up and sends the
  session cookie over plain HTTP; set it true wherever TLS terminates.
- `AdminPasskey` is required, and has no default: say whether every
  admin account must hold a passkey (see "Every admin holds a passkey"
  below). `New` refuses to start while it is unset.
- `New` fails closed: a missing store or CSRF value is an error, not a
  gate that panics on its first request.
- API tokens reach the application only through handlers registered
  with `g.Handle(kind, handler)`; a bearer token of an unregistered kind
  is refused. `g.Exempt(paths...)` adds paths reachable without a
  session.

### Audit and logs

- gate records every sign-in attempt, failed ones included. Each one
  goes to `Config.Audit` as one record: who acted, what happened
  (`user.login_failed`, `account.locked` and so on), which account it
  concerned, and a detail line that includes the client address. nil
  means no audit.
- A request gate refuses -- rate-limited, missing its CSRF header,
  lacking the role -- is one warning line on `Config.Log`. nil discards
  it.

### Single sign-on and passkeys

Both are optional, and both answer 404 on their routes until wired:

- **OIDC.** Set `Deps.OIDC` (an `oidc.Client`, from `oidc.New`) and
  `Deps.OIDCState`; `New` refuses one without the other. `Deps.OIDCPolicy`
  can map the provider's groups to roles
  ([ADR-0013](adr/0013-sso-group-roles.md)).
- **Passkeys.** Set `Deps.Passkeys` to a `passkey.RelyingParty`, built
  by `passkey.New` from the application's public URL
  ([ADR-0004](adr/0004-passkey-ceremony.md)). `Config.PasskeySignIn`
  then also offers signing in with a passkey alone
  ([ADR-0012](adr/0012-passkey-alone-sign-in.md)). An application that
  never imports `gauntlet/passkey` never links the WebAuthn library.

### Tell the browser to forget a removed passkey

With passkey sign-in on, a browser keeps offering a passkey its owner
has removed, and every try is refused. When the passkey's account is
one of this application's and holds no passkey of that ID, the `401` from `POST /api/auth/login/passkey`
carries `unknownCredential` (#92, [errors.md](api/errors.md#invalid-credentials)).
So does a refused passkey at `POST /api/auth/reauthenticate`, when it
names the timed-out session's own account and that account no longer
holds it, so the resume prompt can drop it too.
Pass that object unchanged to
`PublicKeyCredential.signalUnknownCredential()`, and the browser or
password manager drops the passkey from its list.

- Check the call exists first, with
  `if (PublicKeyCredential.signalUnknownCredential)`: as of 2026-10,
  Chrome and Edge 132 and later have it, Safari has announced it, and
  Firefox does not.
- Where it is missing, show the refusal as usual and suggest removing
  the passkey by hand in the browser's or password manager's settings,
  then signing in another way.
- The browser's deletion cannot be undone, so gauntlet never names a
  passkey it still holds, even one that cannot sign in here today.

Passkeys are scoped to the hostname, not the port or path. Two
applications on one hostname, on two ports or two paths, or anything on
`localhost`, each see the other's passkeys in the browser's chooser.
Gauntlet names only a passkey presented with one of its own account IDs,
so a sibling application's passkey is refused but never named. Never
copy one application's user store into another on the same hostname:
the IDs would then match, and each would name the other's passkeys. One
hostname per application is simplest.

### Every admin holds a passkey

`Config.AdminPasskey` says whether every admin account must hold a
passkey ([ADR-0015](adr/0015-every-admin-holds-a-passkey.md), #82).
There is no default: you choose, so the rule is never on or off by
accident.

- `gate.AdminPasskeyRequired`: an admin who holds no passkey that works
  at this site's address is stopped at a door (`403`, `X-Auth-Gate:
  must-enrol-passkey`) until they register one, which the door still
  lets them do. An authenticator app alone does not open it. Use this
  wherever the application is served over https on a domain name and
  sets `Deps.Passkeys`. `New` refuses to start with it while
  `Deps.Passkeys` is nil, or its public URL is unset, an IP address or
  plain http on any host but `localhost` -- browsers cannot make a
  passkey for any of those, so the door could never open. Plain http on
  `localhost` is accepted, as browsers accept it, for development.
- `gate.AdminPasskeyOptional`: admins may hold any second factor, as
  every other account may. Use this for an application reached over
  plain http (anywhere but `localhost`) or by IP address, or one that
  wires no passkeys.

`New` logs the choice at start-up ("gate: admin passkey rule:
required"). Users and viewers are never affected.

**Upgrading to this version.** Add the line to your `gate.Config`
before you upgrade; without it the application will not start. If
you choose `AdminPasskeyRequired`, have each admin register a passkey
before upgrading: an admin without one is stopped at their next
request after the upgrade and has to register one there. A browser
that cannot make a passkey cannot get past the door; use another. The
setup, unlock and escape codes in the server's log still work as
before.

## Recovery codes

Each account with a second factor holds ten single-use recovery codes.
The first set is shown when the first factor is set up, and goes live
only when the person confirms they have saved it
(`POST /api/auth/recovery-codes/confirm`).

A person can ask for a new set at any time
(`POST /api/auth/recovery-codes`, behind their password). Regenerating
replaces the old set at once, as GitHub, Google, Microsoft, 1Password
and Dropbox do:

- The new codes are in the reply and nowhere else. Show them on that
  page, and give the person a way to save them.
- The old set stops working the moment that reply is produced.
- A person who missed the new codes (a dropped connection, a closed
  page) regenerates again. There is no way to show the same codes twice.
- Tell the person "your previous recovery codes no longer work", on the
  page that shows the new ones and, if you send mail, in the message for
  `gate.NoticeRecoveryCodesRegenerated` (see the next section).

## Tell the account's owner

gauntlet sends no mail itself. To tell an account's owner that
something happened to their account -- a password reset, a second
factor added or removed, a lockout, an admin signing them out
everywhere (`POST /api/auth/users/{id}/logout-all`), an unusual
sign-in, an admin allowing their next sign-in from a new browser or
place (`POST /api/auth/users/{id}/allow-sign-in`), a role change, an
API token about to expire -- set
`Config.Notices`. It is called with one `AccountNotice` per event: the
event's `Kind`, the account, and a detail for that kind.

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

- It is called after the response that caused it, in its own goroutine,
  with a context that ends after 10 seconds.
- An error or panic is logged and never changes that response.
- `Reason` may be empty: the message should still say an administrator
  signed them out.
- The older `Config.Notify`, which heard about sign-outs only, still
  works but is deprecated; `New` refuses a `Config` with both set.

## Keep a sign-in history

To give admins a sign-in history (`GET /api/auth/sign-ins`), open a
third document beside the accounts and tokens ones, sealed under its
own label, and close it at shutdown so its last rows are saved:

```go
signInDoc, err := persist.Encrypt(myBackendFor("signins"), key, persist.EncryptOptions{Label: "signins"})
signIns, err := gauntlet.OpenSignInHistory(signInDoc, gauntlet.SignInHistoryOptions{Log: logger}) // MaxRows 0: the newest 10,000
defer signIns.Close()
g, err := gate.New(cfg, gate.Deps{ /* ... */ SignIns: signIns})
```

- Leave `Deps.SignIns` nil and the route answers 404; the audit records
  are written either way.
- Rows are saved a few seconds after they arrive, not one by one, so
  `Close` matters: it stops the writer and saves once more.
- [ADR-0006](adr/0006-sign-in-history.md) has what each row holds.

## Record the sign-in country

To record which country each sign-in came from, run a `geoip.Manager`
on the operator's chosen provider and key, and pass its `Country`:

```go
countries, err := geoip.New(geoip.Config{Source: geoip.SourceIPinfo, IPinfo: geoip.IPinfoKey{Token: token}, Dir: dataDir + "/geoip", Log: logger})
go countries.Run(ctx) // checks daily; Close it once Run has returned
g, err := gate.New(gate.Config{ /* ... */ Country: countries.Country}, deps)
```

- Lookups happen in a file kept on the server; no address is sent
  anywhere. The only request out is the daily check for a new file.
- The application credits the provider wherever it shows the country:
  both providers require it, and gauntlet has no page of its own.
- Leave `Dir` out of backups: it is the provider's public data,
  downloaded again on demand.
- [geoip.md](geoip.md) has the provider accounts, the credit wording
  each asks for, and the city file that impossible-travel detection
  needs.

## Runnable examples

Checked examples for `OpenStore`, `NewSessionStore`, `OpenTokenStore`,
`NewLoginLimiter`, `persist.NewMemory` and `persist.Encrypt` are in
[example_test.go](../example_test.go) and
[persist/example_test.go](../persist/example_test.go). Read them with
`go doc github.com/tomlawesome/gauntlet` or on
[pkg.go.dev](https://pkg.go.dev/github.com/tomlawesome/gauntlet) once
this module is published there.
