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

## Standards conformance: OWASP ASVS (#33)

**Edition.** ASVS 5.0.0, released 30 May 2025
(<https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release>; requirement
text at <https://github.com/OWASP/ASVS/tree/v5.0.0_release/5.0/en>). ASVS
is OWASP's checklist of what an application must do to be called
secure, numbered chapter.section.requirement (for example 6.2.1) and
graded into three levels.

**Level: L2.** ASVS says L1 is the minimum and "most applications should
be striving to achieve" L2; L3 is for applications that "demonstrate
the highest levels of security" and leans on hardware tokens, HSMs,
log shipping and per-response CSP. Gauntlet guards two self-hosted,
single-operator dashboards that change firewall and router state, and
a compromise of the library compromises both at once, so L1 is too
little. L3's extra requirements are mostly deployment and
infrastructure (hardware security modules, separate log systems,
memory encryption) that a library cannot provide and a single operator
would not run. L2 is therefore the target; L3 requirements are listed
only where gauntlet happens to meet them. Both consumers run with
`RequireSecondFactor` on, which is what L2's 6.3.3 asks for.

**Scope.** A library with HTTP routes but no server, no frontend and no
deployment. In scope: V6 authentication, V7 sessions, V8
authorization (the role and token-kind hooks), V9 the sealed values
it mints, V10 the OIDC client, V11 cryptography, V16 logging and
errors, and the parts of V1, V2, V3, V4, V13, V14 and V15 that touch
its routes and data. Out of scope, the application's own concerns:
browser headers and CSP (V3.4), file handling (V5), TLS (V12),
deployment configuration (V13 except secrets), WebRTC (V17), the
frontend (password masking and paste, logout links, client storage),
and authorization over the application's own resources.

**How to read the tables.** *Met* names the code or test that satisfies
the requirement. *App* means the requirement is real but belongs to the
importing application, and says what gauntlet gives it. *N/A* means
the requirement describes something gauntlet does not have. *Deviation*
is a deliberate difference, recorded here. *Gap* names the issue that
tracks the fix. L3 rows are included only where met or where the gap
is cheap. Where a row also appears in the NIST SP 800-63B review below,
it says so instead of repeating the reasoning.

### V6 Authentication

| Req | Level | Status | Evidence |
|---|---|---|---|
| 6.1.1 brute-force controls documented | 1 | Met | `docs/design.md` §1.3 (limiter) and §4 Tokens table; lockout survives restart (`ratelimit.go`, `User.LoginLockedUntil`) |
| 6.1.2, 6.2.11 context-specific word list | 2 | Gap | #43 (password blocklist). See 800-63B §3.1.1.2 |
| 6.1.3, 6.3.4 all pathways documented, strength consistent | 2 | Met, with one deviation | Pathways: password then TOTP/passkey/recovery code; reset code then the same second factor (`gate/login_handler.go:129-172`); SSO; bearer token; setup code. All in `docs/api/auth.yaml`. Deviation: an SSO sign-in creates a session with no local second factor (`gate/oidc_handler.go:292`); see 6.8.4 |
| 6.2.1 passwords at least 8 characters (15 recommended) | 1 | Met, conditional | `store.go:39` `minPasswordLength = 8`. 8 is enough only behind a mandatory second factor; see 800-63B §3.1.1.2 and #49 (password minimum) |
| 6.2.2 users can change their password | 1 | Met | `POST /api/auth/password`, `gate/password_handler.go` |
| 6.2.3 change requires current and new password | 1 | Met | `gate/password_handler.go:45` (`recheckPassword`, rate limited by `ReserveRecheck`, :98). Skipped only under `MustChangePassword`, where the reset code just proved the account |
| 6.2.4 checked against the top 3000 passwords | 1 | Gap | #43 (password blocklist) |
| 6.2.5 no composition rules | 1 | Met | Length is the only rule (`store.go:962`, `:1532`) |
| 6.2.6, 6.2.7 masking, paste, password managers | 1 | App | Frontend; gauntlet imposes nothing that blocks them |
| 6.2.8 verified exactly as received | 1 | Met | `password.go:92`, `:159`: raw bytes to Argon2id, no trimming or case change. See 800-63B §3.1.1.2 on NFC |
| 6.2.9 at least 64 characters permitted | 2 | Met | No maximum; the 64 KiB body limit (`gate/httpjson.go:37`) is the only bound |
| 6.2.10 no periodic rotation | 2 | Met | No expiry exists; `MustChangePassword` is set only by an admin reset |
| 6.2.12 breached-password check | 2 | Gap | #43 (password blocklist) |
| 6.3.1 controls implemented as documented | 1 | Met | `account_limiter_test.go`, `gate/reset_address_limit_test.go`, `stall_test.go` |
| 6.3.2 no default accounts | 1 | Met | Empty store, first admin needs the setup code (`setupcode.go`, ADR-0003) |
| 6.3.3 MFA or equivalent | 2 | Met | `gate.Config.RequireSecondFactor` closes the door at `gate/protect.go:366`; both consumers set it. L3's hardware factor is available (passkeys with user presence, ADR-0004 decision 5) but not mandatory |
| 6.3.5 notify suspicious attempts | 3 | Not targeted | No notification channel; see 800-63B §4.6 |
| 6.3.6 email not an authentication factor | 3 | Met | Gauntlet sends nothing and stores no addresses |
| 6.3.7 notify after credential changes | 3 | Not targeted | Audit record only (`account.password_changed` etc.); see 800-63B §4.6 |
| 6.3.8 no user enumeration | 3 | Met | One body for unknown name, wrong password and dead reset code (`gate/login_handler.go:140-146`); dummy hash for timing (`password.go:80`, `TestAuthenticateUnknownUserStillRunsTheHash` in `store_test.go`) |
| 6.4.1 initial secrets random, short-lived, single use, not the long-term password | 1 | Met | Reset code: 80 bits, 24 h, spent by the login that redeems it, `MustChangePassword` forces replacement (`resetcode.go`, `store.go:1454`). Setup code: 80 bits, dies when an account exists or the process ends (`setupcode.go`) |
| 6.4.2 no hints or secret questions | 1 | Met | None exist |
| 6.4.3 reset does not bypass MFA | 2 | Met | A reset-code login still reaches the second-factor step: `HasSecondFactor` is checked after `Authenticate` whatever credential passed (`gate/login_handler.go:172`); `Protect` keeps the door shut (`gate/protect.go:366`) |
| 6.4.4 lost factor needs proof at enrolment level | 2 | Met, by process | Recovery codes are the self-service path; otherwise an admin, in person, clears the factor (`DELETE /api/auth/users/{id}/totp`, `.../passkeys`) or issues a reset code. The admin is the identity check, as at enrolment |
| 6.4.5 renewal reminders | 3 | N/A | Nothing expires except a reset code, which an admin reissues |
| 6.4.6 admin starts a reset without choosing the password | 3 | Met | `IssueResetCode` mints a random code the user must replace on first use; the admin never sets a password |
| 6.5.1 lookup secrets and TOTP usable once | 2 | Met | `TOTPLastCounter` advanced under the lock (`totp.go:394-434`); `BurnRecoveryCode` (`recoverycodes.go:260`); `TestVerifyTOTPRefusesReplay` (`totp_test.go`), `replay_test.go` |
| 6.5.2 lookup secrets under 112 bits hashed with a password hash and a 32-bit salt | 2 | Met | Recovery codes (50 bits) and reset codes (80 bits) are Argon2id with a 128-bit salt (`recoverycodes.go:122`, `resetcode.go:155`). See 800-63B §3.1.2.2 |
| 6.5.3 CSPRNG for secrets and seeds | 2 | Met | `crypto/rand` throughout: `totp.go:91`, `recoverycodes.go:57`, `resetcode.go:94`, `id.go:14` |
| 6.5.4 lookup secrets at least 20 bits | 2 | Met | 50, 80 and 80 bits |
| 6.5.5 TOTP lifetime at most 30 s | 2 | Deviation | A code is accepted for its own step and one either side, so up to 90 s, never twice. Reasoned in the RFC 6238 section above and 800-63B §3.1.4.2 |
| 6.5.6 any factor revocable | 3 | Met | `ClearTOTP`, `DeletePasskey`, `ClearAllSecondFactors`, admin routes |
| 6.5.7 biometrics only as a second factor | 3 | N/A | A passkey's local biometric never reaches gauntlet; the passkey is treated as possession only |
| 6.5.8 TOTP checked against server time | 3 | Met | `VerifyTOTP(now)` takes the server clock; `gate.Config.Now` is the application's, never the client's |
| 6.6.x out-of-band (SMS, push) | 2–3 | N/A | None offered |
| 6.7.1 verification keys protected from modification | 3 | Met | Passkey public keys live in the trusted accounts store (trust boundary section above) |
| 6.7.2 challenge at least 64 bits, unique | 3 | Met | 32-byte library challenge, spent once (`passkey/challenges.go`, ADR-0004 decision 5) |
| 6.8.1 identity namespaced by IdP | 2 | Met | `(issuer, subject)` is the key (`user.go:104`, `store.go` `ByOIDCIdentity`) |
| 6.8.2 assertion signatures always validated | 2 | Met | ID token verified by go-oidc with the RS256/ES256/PS256 allowlist (`oidc/oidc.go:183`); no unsigned path |
| 6.8.3 SAML replay | 2 | N/A | No SAML |
| 6.8.4 strength expected from the IdP verified, or fallback documented | 2 | Deviation, documented here | Gauntlet does not read `acr`, `amr` or `auth_time`. Fallback assumption: an SSO sign-in is as strong as the self-hosted IdP's own policy, which the same operator controls; gauntlet adds no local second factor to it and a linked account loses its local factors (`LinkOIDCIdentity`). Public multi-tenant issuers are refused (`oidc/policy.go:183`) so that policy is always the operator's |

### V7 Session management

| Req | Level | Status | Evidence |
|---|---|---|---|
| 7.1.1 timeouts documented with justification against NIST | 2 | Met by 800-63B §5.2 below | Idle and absolute lifetimes are `NewSessionStore(ttl, maxLifetime)` arguments; `gate.New` caps them at `gauntlet.MaxSessionIdle`/`MaxSessionLifetime`, AAL2's own figures, recorded there |
| 7.1.2 concurrent sessions documented | 2 | Met, here | Unlimited sessions per account; each is independent; `logout-all` ends them together; a credential change ends them all through `SessionCutoff` |
| 7.1.3, 7.6.1 federated sessions documented | 2 | Met, here | An SSO session is gauntlet's own, with gauntlet's timeouts; IdP logout does not reach it and gauntlet never calls the IdP again until the next login. No back-channel logout |
| 7.2.1 verified on the backend | 1 | Met | `SessionStore.Validate` under the server's lock (`session.go:201`) |
| 7.2.2 dynamic reference tokens | 1 | Met | Opaque id per login (`session.go:108`) |
| 7.2.3 CSPRNG, 128 bits | 1 | Met | `id.go:14`: 16 bytes from `crypto/rand` |
| 7.2.4 new token on every authentication, old one ended | 1 | Met, one gap | New session per login and after `logout-all` (`gate/logout_handler.go:32`); the pending-login cookie is never a session. Gap: a login made from a browser that still holds a live session leaves that old session alive until it idles out; part of #47 (session cookie hardening) |
| 7.3.1, 7.3.2 inactivity and absolute timeouts | 2 | Met | Both enforced in `Validate` (`session.go:208-217`); `gate.New` refuses a store with no ceiling or above `MaxSessionIdle`/`MaxSessionLifetime` (#51) |
| 7.4.1 terminated session unusable | 1 | Met | Server-side delete (`Revoke`, `RevokeAllForUser`); `SessionCutoff` catches sessions from another process (`gate/protect.go:163`) |
| 7.4.2 sessions ended when an account is disabled or deleted | 1 | Met | A deleted user no longer resolves, so every session dies on its next request; `DeleteUser` also revokes the tokens it created |
| 7.4.3 option to end other sessions after a factor change | 2 | Met | A password change and a reset end every session (`SessionsEndedAt`, `store.go:1556`, `resetcode.go:185`); TOTP and passkey changes do not, and `POST /api/auth/logout-all` is the option |
| 7.4.4 logout visible on every page | 2 | App | Frontend |
| 7.4.5 admins can end a user's sessions | 2 | Met, bluntly | An admin reset code ends them (and the password); deleting the account ends them. No softer admin route |
| 7.5.1 full re-authentication before changing authentication settings | 2 | Met | `recheckPassword` guards password change, TOTP enrol and delete, passkey register and delete, recovery-code regeneration (`gate/password_handler.go:45,67`, `gate/totp_handler.go:253`, `gate/passkey_handler.go:182,431`, `gate/recoverycodes_handler.go:44`) |
| 7.5.2 users can view and end their sessions | 2 | Gap, deferred | End-all exists; there is no list. Sessions carry no device or address, so a list would be a count. #48 (session list); accepted for v0.x |
| 7.5.3 step-up before highly sensitive operations | 3 | Not targeted | Admin routes (create user, create token, reset) rely on the session alone |
| 7.6.2 session needs the user's action | 2 | Met | The OIDC flow starts from the user's redirect and a sealed flow cookie; the callback cannot create a session without it (`gate/oidc_handler.go:229-249`) |

### V8 Authorization

| Req | Level | Status | Evidence |
|---|---|---|---|
| 8.1.1 function-level rules documented | 1 | Met | `docs/design.md` §2.1 (roles) and `docs/api/auth.yaml` (which routes need `admin`); token kinds reach only the handler registered for them (`Gate.Handle`) |
| 8.1.2 field-level rules documented | 2 | Met | `Store.List` and `blankCredentials` define what leaves the store (`user.go:193`); the API document closes every response body |
| 8.1.3, 8.1.4, 8.2.4 contextual or adaptive decisions | 3 | N/A | None made; the client address feeds only the login limiter |
| 8.2.1 function-level enforcement | 1 | Met | `RequireRole` (`gate/routes.go:50-59`), unknown role denied everything (`user.go:51`, `gate/protect.go:338`) |
| 8.2.2 object-level enforcement | 1 | Met | Passkey rename and delete take the caller's own account id; user and token routes are admin only; `logout-all` acts on the cookie's account, never a body field |
| 8.2.3 field-level enforcement | 2 | Met | Secrets blanked before any copy leaves the store; hashes never serialised to HTTP |
| 8.3.1 enforced on the server | 1 | Met | All in `gate`; nothing trusts the frontend |
| 8.3.2 changes apply immediately | 3 | Met | Role read from the store on every request (`gate/protect.go:321-341`) |
| 8.3.3 originating subject's permissions | 3 | Met | No service-to-service hop; the token or session on the request decides |
| 8.4.1 multi-tenant | 2 | N/A | Single tenant by design (`docs/decisions/multi-tenant-oidc.md`, carried in `oidc/policy.go`) |
| 8.4.2 layered admin access | 3 | Not targeted | Role plus mandatory second factor; no device posture |

### V9 Self-contained tokens

Gauntlet mints four sealed values the browser carries back: the OIDC
flow state, the pending login, and the passkey register and assert
ceremonies. A sealed value is encrypted and integrity-protected
(AES-256-GCM) so the browser can hold it but not read or forge it.

| Req | Level | Status | Evidence |
|---|---|---|---|
| 9.1.1 integrity checked before use | 1 | Met | GCM tag; any failure is a refusal (`oidc/state.go:94-127`, `gate/pendinglogin.go`, `passkey/seal.go:47-90`) |
| 9.1.2 algorithm allowlist, no `none` | 1 | Met | One fixed cipher per codec; no header, no negotiation |
| 9.1.3 keys from trusted configuration | 1 | Met | A random per-process key per codec; nothing in the value names a key |
| 9.2.1 validity window checked | 1 | Met | Expiry inside the sealed payload: 5 min for all four (`pendingLoginCookieMaxAge`, `passkey/challenges.go:15`, OIDC flow cookie) |
| 9.2.2 right type for the purpose | 2 | Met | Separate codecs and keys for register and assert (`passkey/seal.go:61`), for the pending login and for the flow state; one cannot open as another |
| 9.2.3, 9.2.4 audience | 2 | Met | Per-process keys make the audience this process; ID tokens' `aud` is checked against the client id by go-oidc |

### V10 OAuth and OIDC (client side only)

| Req | Level | Status | Evidence |
|---|---|---|---|
| 10.1.2 values accepted only from the flow this agent started | 2 | Met | `state`, `nonce` and the PKCE verifier are 256-bit random and sealed into the flow cookie (`oidc/state.go:70`); constant-time `state` compare (`gate/oidc_handler.go:229`) |
| 10.2.1 CSRF on the code flow | 2 | Met | PKCE S256 (`oidc/oidc.go:200`) and `state` |
| 10.2.2 mix-up defence | 2 | N/A | One issuer per deployment; go-oidc checks the ID token's `iss` against it |
| 10.2.3 minimal scopes | 3 | App | `oidc.Config.Scopes` is the application's |
| 10.5.1 nonce | 2 | Met | `oidc.VerifyNonce` (`gate/oidc_handler.go:249`) |
| 10.5.2 identify by `sub` | 2 | Met | `(issuer, subject)`; email is display only |
| 10.5.3 issuer in metadata must match | 2 | Met | go-oidc discovery refuses a mismatched issuer; `AllowIssuer` refuses multi-tenant ones before that |
| 10.5.4 `aud` equals client id | 2 | Met | go-oidc verifier config |
| 10.5.5 back-channel logout | 2 | N/A | Not implemented |
| 10.3, 10.4, 10.6, 10.7 resource and authorization server | — | N/A | Gauntlet is a client; its own bearer tokens are not OAuth |

### V11 Cryptography

**Inventory (11.1.2).** Every cryptographic use, so a future change (or a
post-quantum migration) starts from a list rather than a search:

| Use | Algorithm and parameters | Where |
|---|---|---|
| Passwords, recovery codes, reset codes at rest | Argon2id, 64 MiB, 3 passes, 4 lanes, 16-byte salt, 32-byte output; parameters written into each hash and read back on verify, bounded at 4× on read | `password.go:28-48`, `:125-161` |
| Bearer tokens at rest | SHA-256 of a 128-bit random value (fast hash is enough for a random secret) | `token.go:44` |
| Setup code | SHA-256, memory only, constant-time compare | `setupcode.go:73,140` |
| TOTP | HMAC-SHA1 over a 160-bit secret, 30 s step, 6 digits (RFC 6238; SHA-1 inside HMAC is approved by SP 800-131A) | `totp.go:47-65`, `:206` |
| Sealed cookies (OIDC flow, pending login, passkey ceremonies) | AES-256-GCM, 32-byte key from `crypto/rand` per process and per codec, 96-bit random nonce per value, strict base64url | `oidc/state.go`, `gate/pendinglogin.go`, `passkey/seal.go` |
| Encrypted accounts and tokens files | AES-256-GCM; key = HKDF-SHA256(app key ≥ 32 bytes, 16-byte random salt per save); 96-bit random nonce; AAD = the store's logical path; envelope has magic and version bytes | `persist/encrypted_file.go:22,59-78,153-161` |
| Random values | `crypto/rand`: session and account ids 128 bits, token values 128 bits, TOTP secrets 160 bits, reset and setup codes 80 bits, recovery codes 50 bits, OIDC `state`/`nonce` 256 bits, WebAuthn challenge 256 bits | `id.go`, `totp.go`, `resetcode.go`, `recoverycodes.go`, `oidc/state.go`, go-webauthn |
| Signature verification | ID tokens RS256/ES256/PS256 (go-oidc); WebAuthn assertions, library default COSE algorithms (go-webauthn v0.18.2) | `oidc/oidc.go:183`, `passkey/ceremony.go` |

**Key lifecycle (11.1.1).** Per-process keys are made at start and die
with the process; a restart ends in-flight ceremonies and pending
logins, which is accepted. The encrypted-file key is the application's
(trust boundary section above): gauntlet never reads it, and rotating
it means loading with the old key and saving with the new, which an
application can do with two backends. The TOTP secret is the one
long-lived symmetric key gauntlet stores; it is only as protected as
the backend (13.3.1 below).

| Req | Level | Status | Evidence |
|---|---|---|---|
| 11.1.1, 11.1.2 key policy and inventory | 2 | Met | Above |
| 11.1.3, 11.1.4 discovery tooling, PQC plan | 3 | Not targeted | Inventory above is the plan's starting point |
| 11.2.1 validated implementations | 2 | Met | Go standard library, `golang.org/x/crypto/argon2`, go-oidc, go-webauthn; all CVE-checked (`docs/design.md` §4) |
| 11.2.2 crypto agility | 2 | Met | Argon2id parameters self-describing; envelope version byte; sealed values die with the process. TOTP's SHA-1 is fixed on purpose (RFC 6238 section) |
| 11.2.3 at least 128-bit security | 2 | Met | Table above; nothing below 128 bits except hashed single-use codes, which 6.5.4 covers |
| 11.2.4 constant-time comparisons | 3 | Met | `subtle.ConstantTimeCompare` for password, TOTP, setup code, OIDC state; every recovery code checked even after a match (`recoverycodes.go:277`) |
| 11.2.5 fail securely | 3 | Met | A GCM failure is a refusal with one generic message; no padding oracle exists |
| 11.3.1–11.3.5 ciphers, modes, AEAD, nonces | 1–3 | Met | AES-GCM only; random 96-bit nonces (fine for the few saves a file sees; the per-save HKDF salt makes each save a fresh key anyway) |
| 11.4.1 approved hashes | 1 | Met | SHA-256, HMAC-SHA1 (approved for HMAC), no MD5 |
| 11.4.2 password hashing with current parameters | 2 | Met | RFC 9106 §4 second profile |
| 11.4.3 hash lengths | 2 | Met | 256-bit outputs where collision resistance matters |
| 11.4.4 KDF with stretching | 2 | Met | `DeriveKey` is the same Argon2id profile |
| 11.5.1 CSPRNG, 128 bits for non-guessable values | 2 | Met | Table above |
| 11.5.2 CSPRNG under load | 3 | Met | `crypto/rand`; `newID` panics rather than degrades |
| 11.6.x, 11.7.x public-key generation, memory encryption | 2–3 | N/A | Gauntlet generates no key pairs; in-use encryption is infrastructure |

### V16 Security logging and error handling

**Logging inventory (16.1.1).** Two channels, both the application's to
store, keep and protect:

- `*slog.Logger` (`Options.Log`, `TokenOptions.Log`, `gate.Config.Log`):
  backend failures (`logError`), refused saves, limiter eviction
  pressure (`ratelimit.go:251`), a lockout whose save failed
  (`ratelimit.go:512`), a refused setup code (`gate/register_handler.go:56`),
  an SSO policy denial (`gate/oidc_handler.go:154,268`), the setup code
  itself once (`setupcode.go:109`). Lines name the account; they never
  carry a password, code, token, cookie or secret.
- `gate.Auditor.Record(actor, action, target, detail)`: `user.login`,
  `user.register`, `account.password_changed`, `account.totp_enabled`,
  `account.totp_disabled`, `user.totp_cleared`, `account.passkey_added`,
  `account.passkey_removed`, `account.passkey_clone_suspected`,
  `user.passkeys_cleared`, `account.link_sso`, `account.sessions_ended`,
  `account.recovery_codes_regenerated`, `user.create`, `user.delete`,
  `user.password_reset`, `token.create`, `token.revoke`. Timestamps and
  storage are the application's sink.

| Req | Level | Status | Evidence |
|---|---|---|---|
| 16.1.1 inventory | 2 | Met | Above |
| 16.2.1 who, what, when, where | 2 | Gap, partial | Who and what are in every record; when is the sink's; where (client address) is in none. Part of #45 (log failed sign-ins) |
| 16.2.2 UTC timestamps | 2 | App | The sink's clock |
| 16.2.3, 16.2.4 only documented sinks, parseable | 2 | Met | Only the two channels above; `slog` is structured |
| 16.2.5 no secrets in logs | 2 | Met | Inventory above; raw token shown once in the create response only |
| 16.3.1 all authentication attempts logged, success and failure | 2 | Gap | Successes are audited (`user.login`); a refused password, code, assertion or setup code is counted by the limiter but not logged. #45 (log failed sign-ins) |
| 16.3.2 failed authorization logged | 2 | Gap | 403s (CSRF, role, doors) are silent. #45 (log failed sign-ins) |
| 16.3.3 attempts to bypass controls logged | 2 | Gap | Lockouts, malformed `Authorization`, oversize bodies: silent. #45 (log failed sign-ins) |
| 16.3.4 unexpected errors logged | 2 | Met | `logError` on every backend or sealing failure |
| 16.4.1 log injection | 2 | Met | Usernames refuse control and format characters (`username.go:74-82`); token names likewise (`token.go`); `slog` quotes |
| 16.4.2, 16.4.3 log protection and shipping | 2 | App | The sink |
| 16.5.1 generic error messages | 2 | Met | `gateErrorMessages` (`gate/httpjson.go:80-106`); anything unmapped is logged and answered with a fixed text |
| 16.5.2 external failure handled | 2 | Met | 10 s IdP timeouts; `ErrDocumentRemoved` keeps reads working (`docs/design.md` §4 fail-closed list) |
| 16.5.3 fail closed | 2 | Met | Fail-closed list; a save that fails refuses the login that depended on it (`totp.go:380-393`) |
| 16.5.4 last-resort handler | 3 | App | `net/http` recovers a handler panic per connection; the application owns the server |

### Input handling at the routes (V1, V2, V4, V14, V15)

| Req | Level | Status | Evidence |
|---|---|---|---|
| 1.2.3 JSON output encoded | 1 | Met | `encoding/json` only (`gate/httpjson.go:62`) |
| 1.2.4 database injection | 1 | N/A | Document store; the application's backend sees opaque bytes |
| 1.5.2 safe deserialisation | 2 | Met | Typed structs, `DisallowUnknownFields`, trailing data refused, 64 KiB cap (`gate/httpjson.go:37-56`) |
| 2.1.1 validation rules documented | 1 | Met | `docs/api/auth.yaml` request schemas; `TestContractRequestBodiesMatchHandlers` |
| 2.2.1, 2.2.2 server-side positive validation | 1 | Met | `ValidateUsername`, `ValidateLocalUsername` (`username.go`), token name and device rules (`token.go`), TOTP code shape (`totp.go:253-260`), code normalisation (`resetcode.go:67`) |
| 2.3.1 steps in order, none skipped | 1 | Met | Password → pending login → factor → session; ceremonies sealed and spent once (ADR-0004 decision 5) |
| 2.4.1 anti-automation | 2 | Met | Limiter on login, factor, setup code and re-checks; Argon2id semaphore (`password.go:66`) |
| 4.1.1 `Content-Type` with charset | 1 | Gap | `application/json` without `charset` and no `nosniff`; #46 (no-store/nosniff headers) |
| 4.1.3 proxy headers not user-overridable | 2 | App | `gate.Config.ClientIP` is the application's trusted-proxy policy (`docs/design.md` §1.7) |
| 13.3.1 secrets management | 2 | Deviation | TOTP seeds and passkey public keys are plaintext inside the document; `persist.EncryptedFileBackend` is the documented default, a SQL backend stores them as the database protects them. #50 (TOTP seeds and passkey keys at rest); see 800-63B §3.1.4.2 |
| 14.2.1 no secrets in URLs | 1 | Met | Bearer token read from the header only (RFC 6750 section above); the OIDC code is consumed once from the callback query, as the protocol requires |
| 14.3.2 `Cache-Control: no-store` | 2 | Gap | Not set; #46 (no-store/nosniff headers) |
| 15.1.2 dependency inventory | 2 | Met | `go.sum`, `supply-chain/licence-policy.yml`, `govulncheck` in CI |
| 15.2.2 resource-heavy functions bounded | 2 | Met | At most 4 concurrent Argon2id (`password.go:66`), limiter before hashing, 64 KiB bodies |
| 15.3.1 only the needed fields returned | 1 | Met | `blankCredentials`; closed response schemas |
| 15.3.3 mass assignment | 2 | Met | Each handler decodes a named request struct |
| 15.3.4 client IP from a trusted field | 2 | App | `ClientIP` |
| 15.4.1–15.4.3 safe concurrency | 3 | Met | Store and session mutexes, copy-then-save (`mutate.go`), `-race` in CI, check-and-spend under one lock for TOTP, recovery codes and ceremonies |
| 3.3.1 cookie `Secure` | 1 | Met, conditional | `gate.Config.SecureCookie`; the application must set it where TLS terminates. Default false with no warning: #47 (session cookie hardening) |
| 3.3.2 `SameSite` fits the purpose | 2 | Met | `Lax` on every cookie (`gate/cookie.go:22-31`) |
| 3.3.3 `__Host-` prefix | 2 | Gap | #47 (session cookie hardening); see 800-63B §5.1.1 |
| 3.3.4 `HttpOnly` | 2 | Met | Every cookie |
| 3.3.5 cookie under 4096 bytes | 3 | Met | Session id 32 characters; sealed values a few hundred bytes |
| 3.5.1 CSRF | 1 | Met | `X-Requested-With` on unsafe methods plus `SameSite=Lax` (`gate/protect.go:118-123`, `:313`); bearer requests skip it because no cookie is involved |
| 3.5.3 state-changing routes use unsafe methods | 1 | Met | Every mutation is POST, PATCH or DELETE (`docs/api/auth.yaml`); the OIDC callback is GET but creates nothing without the sealed flow cookie |

### Summary

At L2 gauntlet meets every requirement except: password blocklists
(6.1.2, 6.2.4, 6.2.11, 6.2.12), logging of refused attempts and
decisions (16.2.1, 16.3.1–16.3.3), response headers (4.1.1, 14.3.2),
the session cookie's prefix and lifetime (3.3.3, 7.2.4, 7.3.2), and a
session list (7.5.2). Each has an issue; the password blocklist and
the lockout shape (from the 800-63B review) need the owner. Three
deviations are recorded rather than fixed: the TOTP acceptance window,
the SSO sign-in's reliance on the IdP's policy, and secrets at rest on
backends other than the encrypted file.

Written by Fable 5.1, 2026-10-02.

## Standards conformance: NIST SP 800-63B (#34)

**Revision.** SP 800-63B-4, *Digital Identity Guidelines: Authentication
and Authenticator Management*, final, published August 2025
(<https://doi.org/10.6028/NIST.SP.800-63b-4>; read at
<https://pages.nist.gov/800-63-4/sp800-63b.html>). It supersedes
revision 3. Section numbers below are revision 4's.

**What gauntlet is in NIST's words.** For local accounts gauntlet is the
*verifier* (it checks the credential) and the *CSP* (it issues and
binds authenticators: the password, the TOTP secret, recovery codes,
passkeys, reset codes). For SSO it is the *relying party* of a
self-hosted IdP. The *subscriber* is the operator or one of a handful of
colleagues; the apps are the service.

**Assurance level.** NIST grades an authentication event AAL1 to AAL3.
With `gate.Config.RequireSecondFactor` on, as both consumers run, a
local sign-in is a password plus a single-factor OTP (TOTP), a look-up
secret (recovery code) or a single-factor cryptographic authenticator
(passkey): **AAL2** (§2.2.1). With it off, **AAL1**. AAL3 is not claimed:
it needs a non-exportable hardware key on every sign-in and FIPS 140
validated modules, and NIST itself rules synced passkeys out of AAL3
(Appendix B). An SSO sign-in is whatever the IdP's policy makes it;
gauntlet adds nothing to it (see the ASVS section, 6.8.4).

**Out of scope.** The federal-only material: FIPS 140 validation
(§2.1.2 and after), records retention, privacy controls and SORN/PIA
(§2.4), redress (§2.4.4), biometrics (§3.2.3), out-of-band and PSTN
authenticators (§3.1.3), identity proofing (§4.2.2), session monitoring
(§5.3), and attestation (§3.2.4; gauntlet asks for none, which
Appendix B says "SHOULD NOT block" public use).

**How to read the tables.** *Conforms* names the code. *Deviation* is a
deliberate difference, documented here as the issue asks. *Gap* names
the fix issue in the standards-gaps list. Where the ASVS section above
already holds the evidence, the row points at it.

### Passwords (§3.1.1)

| Requirement | Status | Evidence |
|---|---|---|
| Chosen by the subscriber or assigned randomly (§3.1.1.1) | Conforms | User-chosen; the only assigned secret is the reset code, which must be replaced on first use |
| 15 characters minimum as a single factor; 8 minimum when only part of MFA (§3.1.1.2) | Conforms, conditionally; gap | `minPasswordLength = 8` (`store.go:39`). Allowed only because both consumers mandate a second factor. Nothing stops an application running `RequireSecondFactor = false` with 8-character passwords: #49 (password minimum); design call |
| Permit at least 64 characters; accept printing ASCII, space and Unicode; count code points (SHOULD) | Conforms | No maximum, no character rules; length counted in characters (`store.go:962`, `:1532`) |
| No other composition rules (SHALL NOT) | Conforms | None |
| No periodic change; force a change on compromise | Conforms | No expiry; an admin reset sets `MustChangePassword` and kills the old password at once (`resetcode.go:180-183`) |
| No hints, no knowledge-based questions | Conforms | None exist |
| Verify the whole password, no truncation | Conforms | `password.go:92`, `:159` |
| NFC normalisation before hashing (SHOULD) | Deviation | Not applied: ASVS 6.2.8 asks for the bytes exactly as received, and both consumers' operators type on their own devices. A password typed on a device that composes accented characters differently will not match; documented, not fixed |
| Blocklist of common, expected and compromised passwords, whole-password match, reason given on refusal (SHALL) | Gap | None. #43 (password blocklist); owner decision on the list |
| Guidance on choosing a strong password (SHALL) | Application | Frontend copy; gauntlet returns a plain "too short" |
| Rate limiting on the account (SHALL, §3.2.2) | Conforms, with the #44 (consecutive-failure cap) gap | Below |
| Password managers and paste allowed | Conforms | Nothing server-side interferes |
| Salted and hashed with a password hashing scheme, cost as high as practical, parameters stored with each hash, salt at least 32 bits | Conforms | Argon2id, RFC 9106 §4 second profile, 128-bit salt, parameters in the hash string (`password.go:28-48`, `:94`). ASVS 11.4.2 |
| Extra keyed hash with a verifier-only secret (SHOULD) | Deviation | No pepper. The encrypted file backend is the at-rest layer instead (trust boundary section above); a pepper would be one more key for the application to mount |

### Look-up secrets: recovery codes (§3.1.2, §4.2.1.1)

Gauntlet's recovery codes replace the *second* factor only; the
password is still required (`gate/login_handler.go:254`). NIST calls
that a look-up secret used as an authenticator (§3.1.2), not account
recovery (§4.2), which is the path that bypasses authentication. §3.1.2
is the stricter fit for how they are used, and the one applied here;
§4.2.1.1's 64-bit minimum and reissue-on-use rules are for codes that
stand alone, which these never do.

| Requirement | Status | Evidence |
|---|---|---|
| Generated by an approved RBG, at least six decimal digits | Conforms | 10 characters over a 32-letter alphabet from `crypto/rand`: 50 bits (`recoverycodes.go:30-36`, `:57`) |
| Delivered over a session authenticated at AAL2 | Conforms | Minted at TOTP confirmation or passkey registration, both password-gated inside a session (`gate/totp_handler.go:207`, `gate/passkey_handler.go`) |
| Used successfully only once | Conforms | `BurnRecoveryCode` marks `UsedAt` under the lock, by hash not position (`recoverycodes.go:300-321`) |
| Stored hashed; under 112 bits means a password hashing scheme with a 32-bit salt | Conforms | Argon2id with a 128-bit salt (`recoverycodes.go:122`). ASVS 6.5.2 |
| Rate limited on the account (§3.2.2) | Conforms | Shares the login account budget (`gate/login_handler.go:226-231`) |
| Replacement code on request; replacement notifies the subscriber (§4.2.1.1) | Conforms, and a deviation | `POST /api/auth/recovery-codes` regenerates the set behind the password; notification is the §4.6 deviation below |

### Single-factor OTP: TOTP (§3.1.4)

| Requirement | Status | Evidence |
|---|---|---|
| Key at least 112 bits of strength; approved hash | Conforms | 160-bit secret, HMAC-SHA1 (`totp.go:48-51`); SHA-1 inside HMAC is approved by SP 800-131A. Reasoned in the RFC 6238 section above |
| Time nonce changes at least every two minutes | Conforms | 30 s step |
| Keys protected by access controls limited to the components that need them (§3.1.4.2) | Deviation | The secret is plaintext in the accounts document; `persist.EncryptedFileBackend` is the documented default, and a SQL backend relies on the database's own controls. #50 (TOTP seeds and passkey keys at rest); ASVS 13.3.1 |
| Approved key establishment at binding | Conforms | The secret reaches the authenticator app in the enrolment URI over the application's TLS, once, and is confirmed before activation (`ConfirmTOTP`) |
| Collected over an authenticated protected channel | Application | TLS is the application's |
| Accepted only once while valid (replay resistance, §3.2.7) | Conforms | `TOTPLastCounter`, advanced under the same lock as the check (`totp.go:394-434`); the enrolment code cannot also sign in (`totp.go:344`) |
| Defined lifetime from clock drift plus entry delay | Conforms, and the ASVS 6.5.5 deviation | One step either side of now, never two (`totp.go:64`, `TestVerifyTOTPRejectsTwoStepsAway`): the drift allowance NIST describes, and the 90 s ASVS counts against |
| Rate limiting SHALL for outputs under 64 bits (§3.2.2) | Conforms, with the #44 (consecutive-failure cap) gap | 6 digits; shares the account budget |
| Warn on a duplicate OTP (MAY) | Not done | A replay is refused silently; #45 (log failed sign-ins) would at least record it |

### Cryptographic authenticators: passkeys (§3.1.6, §3.1.7, §3.2.5, Appendix B)

| Requirement | Status | Evidence |
|---|---|---|
| Challenge nonce at least 64 bits, statistically unique | Conforms | 32-byte library challenge, spent once (`passkey/challenges.go`, ADR-0004 decision 5) |
| Public keys protected against modification | Conforms | Trusted accounts store (trust boundary section); AEAD-tagged on the encrypted backend |
| Key and algorithm at least 112 bits; approved verification | Conforms | go-webauthn v0.18.2's default algorithm set (ES256, RS256 and the rest of its COSE list), left as the library ships it; a browser-made passkey is P-256 |
| Phishing resistance by verifier name binding (§3.2.5.2); at least one phishing-resistant option offered at AAL2 (SHALL) | Conforms where wired | WebAuthn binds the credential to the relying-party id, taken from the application's public URL never the `Host` header (ADR-0004 decision 4). An application that leaves `Deps.Passkeys` nil offers none; that is its own call (birdcage today) |
| Authentication intent (§3.2.8) | Conforms | User presence always required (`passkey/relyingparty.go:72`); TOTP and recovery codes are typed by hand |
| UV preferred and inspected; treat an unverified passkey as single-factor (App. B) | Conforms | `VerificationPreferred` (`passkey/relyingparty.go:105`); flags stored (`passkey/ceremony.go:47-48`). A passkey is only ever the second factor after a password, so it is counted as possession whatever UV says |
| Backup-eligible and backup-state flags available to policy (MAY) | Conforms | Stored on `Passkey.Flags`; no policy reads them, which Appendix B says is right for public-facing use |
| Sign counter checked | Conforms | Library clone warning and `RecordPasskeyAssertionIfFresh` under the store lock; audited as `account.passkey_clone_suspected` |
| Non-exportable keys | Not claimed | AAL3 only; synced passkeys accepted (Appendix B permits them at AAL2) |

### Rate limiting (§3.2.2)

| Requirement | Status | Evidence |
|---|---|---|
| Limit failed attempts on a subscriber account (SHALL) | Conforms | Per-account counter keyed by account id, never evicted; lockout written to `User.LoginLockedUntil` so a restart does not lift it (`ratelimit.go:399-402`, `docs/design.md` §1.3). Address counter alongside |
| No more than 100 consecutive failures per authenticator, then disable it until rebound (SHALL) | Gap, design call | A lockout lasts one window and then the count starts again; nothing accumulates across windows and no authenticator is ever disabled. At the consumers' 5 per 5 minutes that is 1,440 guesses a day against a six-digit code, forever. #44 (consecutive-failure cap); owner question: escalate or disable |
| Disregard earlier failures after a success (SHOULD) | Conforms | `Release`/`ReleaseAccount` on success (`gate/login_handler.go:152`, `:276`) |
| Increasing delays, bot challenges, risk signals (MAY) | Not done | #44 (consecutive-failure cap) is the first of these |
| Password and second factor both throttled when both are tried | Conforms | One budget for the password step and the code step (`gate/login_handler.go:226-231`); the signed-in password re-check has its own (`ReserveRecheck`) |

### Binding, recovery and invalidation (§4)

| Requirement | Status | Evidence |
|---|---|---|
| Record of every bound authenticator with event times (§4.1) | Conforms, one gap | `TOTPConfirmedAt`, `Passkey.CreatedAt` and `LastUsedAt`, `PasswordChangedAt`. Recovery codes carry no issue time (`GenerateRecoveryCodes` ignores `now`); the audit record `account.recovery_codes_regenerated` holds it. Source address of a binding is not recorded (SHOULD): #45 (log failed sign-ins) adds the address to audit detail |
| Binding an additional authenticator needs authentication at the account's current AAL (§4.1.2.1) | Conforms | TOTP enrol and passkey registration need the session and the password again (`gate/totp_handler.go:67`, `gate/passkey_handler.go:182`); a first factor is enrolled behind the AAL1 session the forced-enrolment door allows, which §4.1.2.1 permits when the account "currently has only AAL1" |
| Notify the subscriber, independently of the binding transaction (§4.1.2.1, §4.2.3, §4.6) | Deviation | Gauntlet stores no contact addresses and sends nothing; the owner's standing rule forbids its agents from sending mail at all. Every binding, recovery and invalidation is an audit record instead, which the single operator reads. Documented, not fixed |
| Encourage two means of authentication (SHOULD) | Conforms | Recovery codes are minted with the first second factor; TOTP and passkeys coexist |
| Account recovery: an application-specific method is allowed if risk-assessed and documented (§4.2.1) | Conforms, documented here | The method is an admin-issued reset code read out in person or on a trusted call (`resetcode.go` header). It replaces the password only; the second factor is still demanded (`gate/login_handler.go:172`), which is §4.2.2.2's "one recovery code plus one bound single-factor authenticator". An admin clearing the second factor as well is the "interaction with a CSP agent" case. Risk: whoever holds admin can take any account; that is already true of the host |
| Issued code validity 24 h, throttled, at least six digits (§4.2.1.2) | Conforms | `ResetCodeTTL` 24 h, 80 bits, single use, Argon2id-hashed, counted by the login limiter |
| Suspend or invalidate a compromised authenticator promptly (§4.3, §4.5); backup authenticator for reporting loss | Conforms | Self-service `ClearTOTP`, `DeletePasskey`, recovery codes; admin clear routes; `DeleteUser` revokes the account's tokens |
| Expiry handling (§4.4) | Conforms | Only reset codes expire; an expired one is refused like a wrong password, and the admin issues another |

### Sessions (§5, §2.2.3)

| Requirement | Status | Evidence |
|---|---|---|
| Session secret issued at authentication, at least 64 bits from an approved RBG, erased at logout, bound to one authentication event | Conforms | 128-bit id per login (`id.go`, `session.go:108`); `Revoke` on logout, `RevokeAllForUser` on sign-out-everywhere; a new id after every sign-in |
| Not persistent across restarts (SHOULD) | Conforms | In memory only (`docs/design.md` §1.7); the browser cookie outlives the process but the id it carries does not |
| Cookies: Secure (SHALL), minimal path, HttpOnly, SameSite Lax or Strict, opaque value | Conforms | `gate/cookie.go:22-31`; the ceremony cookies are scoped to their routes |
| Cookie `__Host-` prefix (SHOULD); expire at or soon after the session (SHOULD) | Gap | No prefix; `Max-Age` is 30 days against a 7-day ceiling. #47 (session cookie hardening); ASVS 3.3.3 |
| `Secure` SHALL | Gap, partial | `gate.Config.SecureCookie` defaults to false and `gate.New` says nothing; the same issue, #47 (session cookie hardening) |
| CSRF: POST/PUT content carries a session identifier the RP verifies (SHALL) | Deviation | Gauntlet uses a custom header on every unsafe method plus `SameSite=Lax` (`gate/protect.go:118-123`), the defence OWASP's cheat sheet lists as equivalent; a per-request token would mean a second cookie or body field for both frontends |
| Timeouts: AAL2 overall SHOULD be at most 24 h, inactivity at most 1 h; both SHALL be enforced and documented (§2.2.3, §5.2) | Conforms | Enforced in `SessionStore.Validate` (`session.go:208-217`) and capped by `gate.New`, which refuses a `Deps.Sessions` store configured above `gauntlet.MaxSessionIdle` (1 h) or `gauntlet.MaxSessionLifetime` (24 h), or with no ceiling at all (`gate/config.go`). Owner decision, 2026-10-02 (gauntlet#51): adopt AAL2's own figures rather than keep mikroview's and birdcage's previous 24 h idle / 7-day ceiling (`docs/design.md` §2.4); both apps must lower their configured values or fail to start. |
| Activity resets the inactivity timeout; reauthentication resets both | Conforms | Sliding `ExpiresAt` capped at the ceiling; a fresh login is a fresh session |
| A session is never stronger than the event that created it | Conforms | One session type; the second-factor door refuses a session whose account has no factor when one is required (`gate/protect.go:366`) |
| No fallback to an insecure transport | Application | TLS termination |
| Federation: the RP is authoritative on reauthentication (§5.2) | Conforms | Gauntlet's own timeouts apply to an SSO session; the IdP's session is never consulted after the callback |

### Summary of findings

Conforms on everything above except: the password blocklist (#43, owner
decision on the list); the consecutive-failure cap (#44, design call on
escalate-versus-disable); the password minimum tied to a mandatory second
factor (#49, design call); cookie prefix, lifetime and `Secure` default
(#47); refused attempts and binding sources not logged (#45). Documented
deviations: no NFC normalisation, no pepper, TOTP secrets as protected as
the backend, no out-of-band notifications, the custom-header CSRF defence,
the consumers' session lifetimes (proposed; awaiting the owner's decision),
and the TOTP acceptance window. Each gap is one issue in the standards-gaps
list, shared with the ASVS section where both standards ask for it.

Written by Fable 5.1, 2026-10-02.
