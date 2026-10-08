# Security policy

Gauntlet is a shared Go authentication library, pre-1.0. Every
application that imports it trusts it with sign-in, so a flaw here is a
flaw in all of them at once. That is the cost of sharing, and the
reason a fix here matters more than a fix in one app.

## Security posture

The full detail, and the research into known flaws behind each item,
is in [docs/design.md](docs/design.md) section 4 and
[docs/security-by-design.md](docs/security-by-design.md). In short:

- **Passwords**: stored only as Argon2id hashes (a deliberately slow
  one-way scramble, so a stolen hash is hard to crack). Every new
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
  nobody can guess, and the server looks it up. A session ends after at
  most an hour unused and never lasts more than 24 hours from sign-in.
  A password change ends every session. The cookie is `SameSite=Lax`:
  browsers leave it off requests another site makes, except when a link
  there opens a page here (a plain GET). So every request other than a
  GET or HEAD must also carry a header a hostile web page cannot add,
  and an application must not change anything on a GET. Together these
  block cross-site request forgery (a hostile page making your browser
  act for you).
- **Single sign-on (OIDC, OpenID Connect)**:
  - The sign-in is protected against a stolen or replayed code (PKCE),
    and its one-time values are compared in constant time, so timing
    leaks nothing.
  - Only the signing algorithms on an explicit list are accepted.
  - An account is matched by the provider and its own user ID, never
    by email address.
  - Only your own self-hosted provider is accepted, plus Google when
    the policy pins your Google domain (`hd`,
    [ADR-0014](docs/adr/0014-shared-issuers.md)). Any other public
    provider, where anyone can make an account, is refused at start-up
    rather than left to configuration.
- **API tokens**: stored only as a SHA-256 hash. A read-only token can
  never be used on a write route, and the other way round. A missing,
  revoked or expired token all get the same 401 answer. Tokens expire
  after a year unless created otherwise.
- **Guessing and flooding**: a rate limiter sits in front of password
  checks, so nobody can wear the server out by making it hash
  passwords. Repeated failures lock the account for a while, then
  disable it for 24 hours. An address with too many failures is banned
  for 24 hours.
- **Unusual sign-ins**: a sign-in from a new browser, a new country, or
  an impossible distance from the last one can be flagged, held for a
  code or a passkey, or refused -- the application chooses. A lone
  admin refused this way can get back in with a one-time code written
  to the server's log.
- **Stored data**: the accounts store and the sign-in history refuse
  storage that would keep them unencrypted, unless the application
  explicitly sets `AllowPlaintextAtRest`. `persist.Encrypt` encrypts a
  store before the application's storage sees it.
- **Fail closed**: a stored file that cannot be read stops the start-up
  rather than quietly starting again as a fresh install
  (`persist.Open`). An unknown token kind never authenticates. A
  missing OIDC claim is a refusal, not an allow.

What each importing application does with this -- for example which
routes it protects -- belongs in that application's own `SECURITY.md`.

## Third-party dependencies

Before a new library is added, it is checked for publicly known
security flaws (CVEs). [AGENTS.md](AGENTS.md), the project's working
notes, lists the approved ones under "Approved third-party modules".
Two automatic checks run on every change:

- `govulncheck`, which flags known flaws in the libraries in use;
- a licence check, which refuses a library whose licence is not on the
  allowed list.

## Reporting a vulnerability

This is a small project kept by one person, with no formal disclosure
programme.

**Do not post the details of a vulnerability in public.** Open an
issue on [gitlab.tomlawson.io/ai/gauntlet](https://gitlab.tomlawson.io/ai/gauntlet)
that says only that you have a security report, and ask for a private
way to send it. For a minor issue you would be happy to see public, you
may describe it in the issue. You need an account on that GitLab server
to open an issue.
