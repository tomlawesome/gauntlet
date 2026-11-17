# Security policy

Gauntlet is a shared Go authentication library, pre-1.0. Every
application that imports it trusts it with sign-in, so a flaw here is a
flaw in all of them at once. That is the cost of sharing, and the
reason a fix here matters more than a fix in one app.

## Security posture

The full detail, and the research into known flaws behind each item,
is in [docs/design.md](docs/design.md) section 4 and
[docs/security-by-design.md](docs/security-by-design.md). In short:

- **Passwords**: stored only as Argon2id hashes (a hash is the result
  of a deliberately slow one-way scramble, so a stolen hash is hard to
  crack). Every new
  password is checked against a built-in list of common passwords, and
  optionally against Have I Been Pwned.
- **Second factor, always**: every account with a local password must
  hold a second factor -- an authenticator app (TOTP) or a passkey, with
  recovery codes. Until it has one, it can reach only the routes that
  set one up. The application cannot turn this off: the old
  `Config.RequireSecondFactor` setting is ignored. Single sign-on
  accounts have no second factor here; the identity provider handles
  that.
- **Sessions**: the session ID is a long random value (128 bits) that
  nobody can guess, and the server keeps its own record of it. A session
  ends after at most an hour unused and never lasts more than 24 hours
  from sign-in. A password change ends every session. The cookie is
  marked `SameSite=Lax`, so browsers do not send it with requests
  started by other websites, except when someone clicks a link to your
  app (a plain page load, a GET request). As a second guard, every
  request other than a GET or HEAD must also carry a header
  (`X-Requested-With`) that another website cannot add. Never make an application change data in
  response to a GET. Together these block cross-site request forgery (a
  hostile page making your browser act for you).
- **Single sign-on (OIDC, OpenID Connect)**:
  - The sign-in is protected against someone stealing the sign-in code
    and using it themselves (this protection is called PKCE). Its
    one-time values are checked in a way that takes the same time
    whether they are right or wrong, so response speed gives nothing
    away.
  - Only a fixed list of approved signature methods is accepted for the
    provider's identity tokens.
  - An account is matched by the provider and its own user ID, never
    by email address.
  - A self-hosted sign-in provider or a single Entra tenant (one
    organisation's Microsoft directory) is accepted. Google is
    accepted only when the policy pins your Google domain (the `hd`
    claim, [ADR-0014](docs/adr/0014-shared-issuers.md)). Apple,
    Microsoft personal accounts and Entra's shared endpoints (`common`,
    `organizations`, `consumers`), where anyone can make an account, are
    always refused when the app starts. Any other public provider is not
    recognised as shared, so nothing stops it at start-up: the policy
    must restrict who may sign in.
- **API tokens**: stored only as a SHA-256 hash. A token is accepted
  only by the handler registered for its kind, so a read-only (API)
  token never reaches the ingest handler, and the other way round. A
  missing, revoked or expired token all get the same 401 answer. Tokens
  expire after a year unless created otherwise.
- **Guessing and flooding**: a limit on how fast password checks are
  accepted, so nobody can overload the server by forcing it to check
  many passwords. Repeated failures lock the account briefly, then
  switch it off for 24 hours. A network (IP) address with too many
  failures is blocked for 24 hours.
- **Unusual sign-ins**: a sign-in from a new browser, a new country, or
  a place too far from the last sign-in to have travelled to in the time
  between can be allowed but marked on the session, the sign-in history and the
  audit record, asked for an extra
  code or passkey, or blocked -- the application chooses. A lone
  admin refused this way can get back in with a one-time code written
  to the server's log.
- **Stored data**: the accounts store and the sign-in history refuse
  to save to a place that would keep them unencrypted, unless the
  application sets `AllowPlaintextAtRest`. `persist.Encrypt` encrypts a
  store before the application's storage sees it.
- **When something goes wrong, refuse**: a stored file that cannot be read stops the start-up
  rather than quietly starting again as a fresh install
  (`persist.Open`). An unknown token kind never authenticates. A
  missing OIDC claim is a refusal, not an allow.

What each importing application does with this -- for example which
routes it protects -- belongs in that application's own `SECURITY.md`.

## Third-party dependencies

Before a new library is added, it is checked for publicly known
security flaws (CVEs, the public numbered list of known flaws).
[AGENTS.md](AGENTS.md), the maintainer's internal notes file, lists the approved ones under "Approved third-party modules".
Two automatic checks run on every change:

- `govulncheck`, which flags known flaws in the libraries in use;
- a licence check, which refuses a library whose licence is not on the
  allowed list.

## Reporting a vulnerability

This is a small project kept by one person, with no formal disclosure
programme.

**Do not post the details of a vulnerability in public.** Report it
privately through GitHub instead:

- Open [github.com/tomlawesome/gauntlet/security/advisories/new](https://github.com/tomlawesome/gauntlet/security/advisories/new)
  (or the repository's **Security** tab, then **Report a vulnerability**).
- You need a GitHub account. Only you and the maintainer can see the
  report.
- Say what is affected, how to reproduce it, and which version you used.
