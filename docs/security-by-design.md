# Security by design

Gauntlet's copy of the policy shared with mikroview and birdcage,
shortened to what applies to a library with no network listener, no
lures and no infrastructure of its own.

Every new feature is **researched before it is designed** -- not designed
and then reviewed. A security review at the end can only find flaws in
the architecture already chosen; research done first changes which
architecture gets chosen.

## What "researched" means here

Four things, all required, before an implementation plan is written.

1. **Research first, plan second.** The output of research is expected to
   change the design; if it never does, the research wasn't real.
2. **Search CVEs explicitly**, for every dependency and pattern the
   feature touches -- against the Go vulnerability database
   (`vuln.go.dev`) and the GitHub Advisory Database, reading the
   authoritative record rather than secondary coverage of it.
3. **Compare against known secure and insecure architectures.** Find who
   has built this before and what went wrong for them.
4. **Treat industry norms as direction, not proof.** A norm carries real
   weight but is a starting point to verify, not a conclusion to accept.

Because this module's compromise compromises every application that
imports it at once, the bar is higher, not lower, than a single
application's own feature: a mistake here ships everywhere gauntlet is
used.

## Minimum bar for a feature issue

Before implementation starts, the issue records:

- the **threat model** -- what an attacker gains if this component is
  compromised, stated concretely
- **CVEs and prior incidents** found, with links to the authoritative
  records
- **what the research changed** about the design, or an explicit note
  that it confirmed it
- **fail-closed behaviour** for every error path
- **what is deliberately not being done**, and why

Anything contested or uncertain is written down as contested, not
silently resolved in one direction.

## Verification standard

A finding is not acted on until it is reproduced -- research, including
research from an automated agent, is a lead, not a conclusion. Where a
fix is made, a test proves the flaw existed first.

## Trust boundary: the accounts store (issue #18)

The accounts store this module persists (via `persist.EncryptedFileBackend`
or otherwise) is a **trusted** input, not hostile data: it is refused
outright on tamper (a wrong key, a flipped byte, a document moved to
another store's path) rather than sanitised or partially accepted, because
there is no safe partial reading of a corrupted or forged auth store.

Gauntlet decides how a document is authenticated once opened; the
*application* decides which `persist.Backend` to use and, for
`EncryptedFileBackend`, where its key file lives and how it is mounted.
Gauntlet never reads a key file itself.

The supported way to change accounts outside the UI is the application's
own CLI (mikroview's `-recover-admin-account` and equivalents), never
hand-editing the store file: an edited file is exactly what the AAD and
AEAD tag are there to catch, so hand-editing turns "administrative
recovery" into "the store no longer opens".

Whoever holds the host the store lives on, and the key that opens it, is
the operator. Encryption defends the data at rest against a copied
backup or a lost drive; it does not defend it against that operator, who
by construction can already read what the running process can read.

## Standards conformance: TOTP and bearer tokens (#35)

Pinned by `TestGenerateTOTPCodeRFC6238Vectors` and
`TestVerifyTOTPWindowInSeconds` (`totp_test.go`) and the `TestRFC6750*`
tests (`gate/rfc6750_test.go`). Where gauntlet differs from the RFC on
purpose, it is listed here; each one fails closed.

**TOTP, RFC 6238.** Conforms on what it implements: HMAC-SHA1, the
30-second step from the Unix epoch, RFC 4226 truncation (checked
against Appendix B's SHA-1 vectors), and a code accepted at most once
(§5.2). Deliberate differences:

- **SHA-1 only.** §1.2 allows SHA-256 and SHA-512; gauntlet does not
  offer them. Authenticator apps do not all honour the algorithm
  parameter, and one that silently uses SHA-1 anyway produces codes
  that never match, locking the account's owner out. SHA-1 is not weak
  here: TOTP uses it inside HMAC, where collisions do not matter.
- **6 digits, not 8.** RFC 6238 allows either; 6 is what every
  consumer app shows. The enrolment URI (`TOTPEnrollmentURI`) sends no
  `algorithm`, `digits` or `period`, so apps use their defaults: SHA1, 6
  and 30, the same as `totp.go`.
- **One step either side.** §5.2 recommends allowing at most one step
  back, for network delay. Gauntlet also accepts one step ahead, for a
  phone whose clock runs fast. Two steps either side are refused.

**Bearer tokens, RFC 6750.** Gauntlet reads a token only from the
`Authorization` header, matches the `Bearer` scheme name in any case
(RFC 7235 §2.1), refuses any other `Authorization` header rather than
ignoring it, and answers every 401 with
`WWW-Authenticate: Bearer realm="gate"`. Deliberate differences:

- **No token in the query string or form body.** §2.2 and §2.3 allow
  both. A URL ends up in logs, browser history and `Referer` headers,
  and §2.3 itself advises against it, so gauntlet ignores both: the
  request is judged as if it carried no token.
- **Exactly one space after `Bearer`.** §2.1 allows one or more. A
  second space is read as part of the token, which then matches
  nothing: 401.
- **No `error` attribute on the challenge.** §3 says a refused token
  SHOULD get `error="invalid_token"`. Every 401, whether for a cookie
  or a token, carries the same fixed challenge, and
  `docs/api/auth.yaml` fixes that value. Adding the attribute changes
  the API contract, so it goes through ADR-0002.
- **No 400 `invalid_request`.** §3.1 answers a malformed request 400.
  Gauntlet answers 401 with the same challenge instead, for an
  `Authorization` header in any other form (another scheme, a bare
  `Bearer`, a tab for the space) as for a token that matches nothing,
  so a refused credential always looks the same and the API contract
  needs no second error shape (#41; a 400 was considered and not
  chosen). It does not check that a token is `b64token` syntax either:
  a malformed token is just one that matches nothing. A request with
  no `Authorization` header at all is judged by its session cookie.
- **No 403 `insufficient_scope`.** A token reaches only the handler its
  kind was registered with (`Gate.Handle`), so a route outside that
  handler is never offered to it. The handler answers, typically 404.
