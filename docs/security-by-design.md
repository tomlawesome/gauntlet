# Security by design

Gauntlet's copy of the security policy shared with mikroview and
birdcage, shortened to what applies to a library. Gauntlet serves HTTP
routes but does not run a server, has no decoy systems to attract
attackers, and has no hosting of its own.

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
- **fail-closed behaviour**: what happens on every error path. It must
  refuse the request, never let it through
- **what is deliberately not being done**, and why

Anything contested or uncertain is written down as contested, not
silently resolved in one direction.

## Verification standard

A finding is not acted on until it is reproduced -- research, including
research from an automated agent, is a lead, not a conclusion. Where a
fix is made, a test proves the flaw existed first.

## Trust boundary: the accounts store (issue #18)

The accounts store this module persists (via `persist.Encrypt`,
`persist.EncryptedFileBackend` or otherwise) is **trusted**: gauntlet
assumes the file is genuine, not hostile data. If the tamper check fails
(a wrong key, a changed byte, or a document copied from another store's
path), gauntlet refuses the whole file. It never cleans up a damaged file
or uses part of it, because there is no safe partial reading of a
corrupted or forged auth store.

Gauntlet decides how a document is authenticated once opened; the
*application* decides which `persist.Backend` to use and, for
`persist.Encrypt` and `EncryptedFileBackend`, where its key file lives
and how it is mounted. Gauntlet never reads a key file itself. Since #50
([ADR-0005](adr/0005-encryption-at-rest-on-every-backend.md)) the accounts
store refuses to open over a backend that would hold the document in the
clear, unless the application sets `Options.AllowPlaintextAtRest`.
TOTP (the six-digit code an authenticator app shows) needs each app's
secret stored in a form gauntlet can read back, so it cannot be hashed
the way a password is; encrypting the whole document is the only way a
database dump or backup carries none of those secrets.

Do not edit the accounts file by hand. The supported way to change
accounts outside the UI is the application's own command-line tool
(mikroview's `-recover-admin-account` and equivalents). The file is
encrypted with a built-in tamper check, so any change breaks it:
gauntlet then refuses to open the file, and nobody can sign in.

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
30-second step from the Unix epoch, the RFC 4226 method for turning the
hash into a six-digit code (checked against the RFC's published SHA-1 test
values in Appendix B), and a code accepted at most once (§5.2). Deliberate differences:

- **SHA-1 only.** §1.2 allows SHA-256 and SHA-512; gauntlet does not
  offer them. Authenticator apps do not all honour the algorithm
  parameter, and one that silently uses SHA-1 anyway produces codes
  that never match, locking the account's owner out. SHA-1 is weak
  when used on its own to fingerprint data, because two inputs can be
  made to match; TOTP uses it inside HMAC, a keyed construction where
  that weakness cannot be exploited.
- **6 digits, not 8.** RFC 6238 allows either; 6 is what every
  consumer app shows. The setup link (the text inside the QR code,
  `TOTPEnrollmentURI`) leaves out `algorithm`, `digits` and `period`, so
  each app uses its defaults: SHA-1, 6 digits and 30 seconds, the same as
  `totp.go`.
- **One step either side.** §5.2 recommends allowing at most one step
  back, for network delay. Gauntlet also accepts one step ahead, for a
  phone whose clock runs fast. Two steps either side are refused.

**Bearer tokens, RFC 6750.** A bearer token is a secret string sent in
the `Authorization` header; whoever holds it can use it. Gauntlet reads a
token only from that header, accepts the word `Bearer` in any
capitalisation (RFC 7235 §2.1), refuses any other `Authorization` header rather than
ignoring it, and answers every 401 with
`WWW-Authenticate: Bearer realm="gate"`. Deliberate differences:

- **No token in the query string or form body.** §2.2 and §2.3 allow
  both. A URL ends up in logs, browser history and `Referer` headers,
  and §2.3 itself advises against it, so gauntlet ignores both: the
  request is judged as if it carried no token.
- **Exactly one space after `Bearer`.** §2.1 allows one or more. A
  second space is read as part of the token, which then matches
  nothing: 401.
- **No `error` detail in the 401's `WWW-Authenticate` header.** §3 says a
  refused token SHOULD get `error="invalid_token"`. Every 401, whether
  for a cookie or a token, carries the same fixed challenge, and
  `docs/api/auth.yaml` fixes that value. Adding the detail changes the
  API contract, so it goes through ADR-0002.
- **No 400 `invalid_request`.** §3.1 answers a malformed request 400.
  Gauntlet answers 401 with the same challenge instead, for an
  `Authorization` header in any other form (another scheme, a bare
  `Bearer`, a tab for the space) as for a token that matches nothing,
  so a refused credential always looks the same and the API contract
  needs no second error shape (#41; a 400 was considered and not
  chosen). It does not check that a token uses only the characters RFC
  6750 allows (`b64token` syntax) either: a malformed token simply
  matches nothing. A request with
  no `Authorization` header at all is judged by its session cookie.
- **No 403 `insufficient_scope`.** A token works only on the routes of
  the handler its kind was registered for (`Gate.Handle`). Anywhere else
  the request is never given to that token at all; that handler usually
  answers 404.

## Standards conformance: OWASP ASVS (#33)

**Edition.** ASVS 5.0.0, released 30 May 2025
(<https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release>; requirement
text at <https://github.com/OWASP/ASVS/tree/v5.0.0_release/5.0/en>). ASVS
is OWASP's checklist of what an application must do to be called
secure, numbered chapter.section.requirement (for example 6.2.1) and
graded into three levels.

**Level: L2.** ASVS says L1 is the minimum and "most applications should
be striving to achieve" L2; L3 is for applications that "demonstrate
the highest levels of security" and leans on hardware tokens, hardware
security modules (HSMs), copying logs to a separate system and a Content
Security Policy (CSP) set per response. Gauntlet guards two self-hosted,
single-operator dashboards that change firewall and router state, and
a compromise of the library compromises both at once, so L1 is too
little. L3's extra requirements are mostly deployment and
infrastructure (hardware security modules, separate log systems,
memory encryption) that a library cannot provide and a single operator
would not run. L2 is therefore the target; L3 requirements are listed
only where gauntlet happens to meet them. A second factor is mandatory
for every local-password account (#49), which is what L2's 6.3.3 asks
for.

**Terms.** Used from here on without repeating:

- **Single sign-on (SSO)**: signing in through a separate sign-in server
  instead of a local password. That server is the **identity provider
  (IdP)**, and **OpenID Connect (OIDC)** is the protocol gauntlet uses to
  talk to it.
- **Multi-factor authentication (MFA)**: a sign-in that needs two
  different kinds of proof. A **one-time password (OTP)** is a code that
  works once or for a short time; TOTP is the time-based kind.
- **Have I Been Pwned (HIBP)**: a public service that knows which
  passwords have appeared in data breaches.
- **Cross-site request forgery (CSRF)**: another website making your
  browser send a request to this one.
- **Door**: a hold that keeps a signed-in session away from everything
  but one required step, such as setting a new password or adding a
  second factor.
- **Sealed value**: a small piece of data the server encrypts and
  protects against tampering, so the browser can carry it back but cannot
  read or change it.

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
| 6.1.1 brute-force controls documented | 1 | Met | Repeated wrong tries lock the account, for longer each time; 50 in a row switch its sign-in off for 24 hours; 100 failures from one address ban that address for 24 hours. Detail and evidence in *Brute-force controls* below this table |
| 6.1.2, 6.2.11 context-specific word list | 2 | Met | The list is the account's username and the product's name (`Options.ProductName`; gate adds `Config.ProductName` on its routes), refused when the whole password is just one of them, ignoring case and any punctuation or digits added around it (`PasswordMatchesContext`, `passwordcheck.go`), refused with `ErrPasswordContext` (#43). See 800-63B §3.1.1.2 |
| 6.1.3, 6.3.4 all pathways documented, strength consistent | 2 | Met, with one deviation | Pathways: password then TOTP/passkey/recovery code; reset code then the same second factor (`gate/login_handler.go:274-307`); a user-verifying passkey on its own, off unless `Config.PasskeySignIn` (#77, ADR-0012, `gate/login_passkey_handler.go`); SSO; bearer token; setup code. All in `docs/api/auth.yaml`. Deviation: an SSO sign-in creates a session with no local second factor (`gate/oidc_handler.go:423`); see 6.8.4 |
| 6.2.1 passwords at least 8 characters (15 recommended) | 1 | Met | `store.go:48` `minPasswordLength = 8`, counted in characters, not bytes (`passwordTooShort`, `store.go:55-57`), conforming because a second factor is mandatory for every local-password account (#49); see 800-63B §3.1.1.2 |
| 6.2.2 users can change their password | 1 | Met | `POST /api/auth/password`, `gate/password_handler.go` |
| 6.2.3 change requires current and new password | 1 | Met | `gate/password_handler.go:77` (`recheckPassword`, rate limited by `ReserveRecheck`, `:154`). Not asked when the account is flagged `MustChangePassword`, because the person has just proved who they are with a reset code or (since #44) by signing in with both factors. In both cases every earlier session is ended in the same write that sets the flag |
| 6.2.4 checked against the top 3000 passwords | 1 | Met | Every new password is checked, as typed and in lower case, against `Options.PasswordBlocklist` (`passwordcheck.go:112`), by default `blocklist.Embedded()`: the 10,000 most common Pwned Passwords, signed and built into the module (`blocklist/embedded/top10k.txt`, #43, #52, ADR-0007). A match is refused with `ErrPasswordBlocked`. A release refuses to tag if the list is missing, unsigned or more than 90 days old (`scripts/blocklist-age-check.sh`) |
| 6.2.5 no composition rules | 1 | Met | Length is the only rule (`store.go:55-57`) |
| 6.2.6, 6.2.7 masking, paste, password managers | 1 | App | Frontend; gauntlet imposes nothing that blocks them |
| 6.2.8 verified exactly as received | 1 | Met | `password.go:94`, `:161`: the password is hashed exactly as typed (raw bytes to Argon2id), with no trimming or case change. See 800-63B §3.1.1.2 and the NFC row below |
| 6.2.9 at least 64 characters permitted | 2 | Met | No maximum; the 64 KiB body limit (`gate/httpjson.go:37`) is the only bound |
| 6.2.10 no periodic rotation | 2 | Met | No expiry exists; `MustChangePassword` is set only on evidence of compromise: an admin reset, five failed second-factor steps in a row (`LoginLimiter.SecondFactorFailed`, #44), or a sign-in recheck that finds the password in a breach (#43) |
| 6.2.12 breached-password check | 2 | Met, opt-in | `Options.BreachCheck` with `blocklist.PwnedChecker`: the HIBP password-range service: gauntlet sends only the first 5 characters of the password's SHA-1 hash, so the service never learns the password (`Add-Padding` hides the size of the reply). The check is bounded by `BreachCheckTimeout` (5 s), refused with `ErrPasswordBlocked`. An outbound call, so the application turns it on. When HIBP cannot answer, the password is accepted against the embedded list, the miss logged, and the account marked (`User.BreachCheckPending`); the next sign-in rechecks, and a hit sets `MustChangePassword` and ends every session (owner, 2026-10-02, #43). SSO accounts have no local password and are never checked |
| 6.3.1 controls implemented as documented | 1 | Met | `account_limiter_test.go`, `lockout_escalation_test.go`, `lockout_escalation_api_test.go`, `gate/lockout_escalation_test.go`, `gate/reset_address_limit_test.go`, `knownbrowser_test.go`, `gate/knownbrowser_test.go`, `stall_test.go` |
| 6.3.2 no default accounts | 1 | Met | Empty store, first admin needs the setup code (`setupcode.go`, ADR-0003) |
| 6.3.3 MFA or equivalent | 2 | Met | The forced-enrolment door in `gate/protect.go` (`Protect`) is always shut (#49): every local-password account must hold a second factor. L3's hardware factor is available (passkeys with user presence, ADR-0004 decision 5) but not mandatory for every account. For admins it is mandatory wherever the application offers passkeys (#82, ADR-0015). With `gate.Config.AdminPasskey` set to `AdminPasskeyRequired`, an admin is held at the `must-enrol-passkey` door until it holds a passkey usable at this address, so phishing-resistant MFA guards every privileged account. `gate.New` refuses that setting without a ready relying party (the app's own passkey settings). An app reached over plain http (anywhere but localhost) or by IP must say `AdminPasskeyOptional`. A passkey that checks the person (PIN or fingerprint) and signs in on its own (#77, ADR-0012) counts as two proofs, at AAL2 (NIST's middle assurance level, which needs two different kinds of proof): the device, which you have, and the PIN or fingerprint at the device. User verification is required for it, read from what the authenticator signed |
| 6.3.5 notify suspicious attempts | 3 | Met | `gate.Config.Notices` (`AccountNotifier`, #73) is told of an unusual sign-in flagged or blocked -- a new browser, a new country or impossible travel (#55) -- an account lockout and a disable; gauntlet sends nothing itself, so the notice reaches the account's owner only once the application wires it to mail or message them; see 800-63B §4.6 |
| 6.3.6 email not an authentication factor | 3 | Met | Gauntlet sends nothing and stores no addresses |
| 6.3.7 notify after credential changes | 3 | Met | `gate.Config.Notices` is told of a password reset and a second factor added or removed, beside the audit record (`account.password_changed` etc.); see 800-63B §4.6 |
| 6.3.8 no user enumeration | 3 | Met | One body for unknown name, wrong password and dead reset code (`gate/login_handler.go:247-259`); a fake password check runs for unknown names, so the response time does not reveal that the name does not exist (`password.go:82`, `TestAuthenticateUnknownUserStillRunsTheHash` in `store_test.go`) |
| 6.4.1 initial secrets random, short-lived, single use, not the long-term password | 1 | Met | Reset code: 80 bits, 24 h, spent by the login that redeems it, `MustChangePassword` forces replacement (`resetcode.go:229`, `store.go:1982-1984`). Setup code: 80 bits, dies when an account exists or the process ends (`setupcode.go`) |
| 6.4.2 no hints or secret questions | 1 | Met | None exist |
| 6.4.3 reset does not bypass MFA | 2 | Met | A reset-code login still reaches the second-factor step: `HasSecondFactor` is checked after `Authenticate` whatever credential passed (`gate/login_handler.go:284`); `Protect` keeps the door shut (`gate/protect.go:496`) |
| 6.4.4 lost factor needs proof at enrolment level | 2 | Met, by process | Recovery codes are the self-service path; otherwise an admin, in person, clears the factor (`DELETE /api/auth/users/{id}/totp`, `.../passkeys`) or issues a reset code. The admin is the identity check, as at enrolment |
| 6.4.5 renewal reminders | 3 | N/A | Nothing expires except a reset code, which an admin reissues |
| 6.4.6 admin starts a reset without choosing the password | 3 | Met | `IssueResetCode` mints a random code the user must replace on first use; the admin never sets a password |
| 6.5.1 lookup secrets and TOTP usable once | 2 | Met | `TOTPLastCounter` advanced under the lock (`totp.go:487-491`); `BurnRecoveryCode` (`recoverycodes.go:251`); `TestVerifyTOTPRefusesReplay` (`totp_test.go`), `replay_test.go` |
| 6.5.2 lookup secrets (recovery codes) under 112 bits stored with a slow password hash and a random salt of at least 32 bits (an extra value mixed in so equal codes hash differently) | 2 | Met | Recovery codes (50 bits) and reset codes (80 bits) are Argon2id with a 128-bit salt (`enrolhold.go:166`, `resetcode.go:198`). See 800-63B §3.1.2.2 |
| 6.5.3 secrets and seeds come from a cryptographically secure random number generator (Go's `crypto/rand`) | 2 | Met | `crypto/rand` throughout: `totp.go:95-97`, `resetcode.go:117-129` (reset and recovery codes), `id.go:13-15` |
| 6.5.4 lookup secrets at least 20 bits | 2 | Met | 50, 80 and 80 bits |
| 6.5.5 TOTP lifetime at most 30 s | 2 | Deviation | A code is accepted for its own step and one either side, so up to 90 s, never twice. Reasoned in the RFC 6238 section above and 800-63B §3.1.4.2 |
| 6.5.6 any factor revocable | 3 | Met | `ClearTOTP`, `DeletePasskey`, `ClearAllSecondFactors`, admin routes |
| 6.5.7 biometrics only as a second factor | 3 | Met | A passkey's local biometric never reaches gauntlet, only the user-verified flag the authenticator signs. A passkey signing in alone (#77, ADR-0012) requires that flag, so any biometric is used together with possession of the key and never by itself; as a second step behind a password the passkey is still treated as possession only |
| 6.5.8 TOTP checked against server time | 3 | Met | `VerifyTOTP(now)` takes the server clock; `gate.Config.Now` is the application's, never the client's |
| 6.6.x out-of-band (SMS, push) | 2–3 | N/A | None offered as a sign-in factor |
| 6.6.3 out-of-band codes rate limited | 2 | Met | Each confirmation code (`Config.DeliverConfirmCode`, for an unusual sign-in) and each escape code (for the lone admin) counts against that account's limit for the time period (the limiter's threshold per window), separately for each way of sending it (`LoginLimiter.ReserveDelivery`, #84). The count is not given back if the code goes unused. Whatever the window says, there is also a wait before the next send, which starts at 30 seconds and doubles with each send (30 s, 1, 2, 4 minutes), and at most 5 sends in any hour (#83); both are fixed. Past any of these limits, the sign-in that is waiting for a code gets `429 rate-limited` and nothing is sent. Guesses at either code are on the login limiter (`gate/confirmlogin.go`, `gate/escapelogin.go`). See 800-63B-4 §3.1.3.2 |
| 6.7.1 verification keys protected from modification | 3 | Met | Passkey public keys live in the trusted accounts store (trust boundary section above) |
| 6.7.2 challenge at least 64 bits, unique | 3 | Met | 32-byte library challenge, spent once (`passkey/challenges.go`, ADR-0004 decision 5) |
| 6.8.1 an account is identified by its identity provider and subject together | 2 | Met | `(issuer, subject)` is the key, so the same subject at two different sign-in servers is two different accounts (`user.go:81-82`, `store.go` `ByOIDCIdentity`) |
| 6.8.2 assertion signatures always validated | 2 | Met | ID token verified by go-oidc with the RS256/ES256/PS256 allowlist (`oidc/oidc.go:211`); no unsigned path |
| 6.8.3 SAML replay | 2 | N/A | No SAML |
| 6.8.4 strength expected from the IdP verified, or fallback documented | 2 | Deviation, documented here | Gauntlet ignores the fields in the IdP's ID token that say how strongly, and how recently, the person signed in (`acr`, `amr` and `auth_time`). Fallback assumption: an SSO sign-in is as strong as the self-hosted IdP's own policy, which the same operator controls; gauntlet adds no local second factor to it. Linking an account to SSO removes its local password and second factors, except on an admin, which keeps both (`LinkOIDCIdentity`, `store.go:1825`). Sign-in servers shared by many unrelated organisations (multi-tenant issuers) are refused. The one exception is Google, and only when the policy names the single Google Workspace domain (`hd`) it will accept (ADR-0014, `oidc/policy.go` `AllowIssuerWithPolicy`). So the sign-in server is always the operator's own or their organisation's |

**Brute-force controls (6.1.1).** Documented in `docs/design.md` §1.3
(the limiter) and the "Brute force" row of §4's Tokens table.

- **Lockout.** The limiter's threshold of wrong tries within its window
  (both set by the application; five in five minutes is typical) locks
  the account. Each lockout lasts three times as long as the one before.
  The first lasts one window (the time period the limiter counts wrong
  tries in); the length is capped at an hour. With a five-minute window:
  5, 15, 45, then 60 minutes (#70). The lockout and the count of lockouts are saved on the
  account (`User.LoginLockedUntil`, `User.LoginLockoutCount`), so a
  restart does not lift them (`ratelimit.go`, `lockout.go`).
- **Disable.** 50 failed attempts in a row switch the account's sign-in
  off for 24 hours, or until it is unlocked (`User.LoginDisabledAt`,
  `LoginDisableDuration`, #44, #70).
- **Address ban.** 100 failed sign-ins from one address within 24 hours
  ban that address for 24 hours; for IPv6, all addresses in the same /64
  block (the block one home network normally gets) count as one address. The ban
  is held in memory only, and a known browser passes it
  (`addressban.go`, #70).
- **Known browser.** A browser that has completed a sign-in keeps a
  small allowance of its own during a lockout, so a stranger cannot
  cheaply lock the owner out; its failures still count toward the 50
  (`knownbrowser.go`, `LoginLimiter.ReserveKnownBrowser`, #44). Since
  #55 its cookie carries one token per account, up to four, so a
  browser shared by two accounts keeps each account's own allowance.

### V7 Session management

| Req | Level | Status | Evidence |
|---|---|---|---|
| 7.1.1 timeouts documented with justification against NIST | 2 | Met by 800-63B §5.2 below | Idle and absolute lifetimes are `NewSessionStore(ttl, maxLifetime)` arguments; `gate.New` caps them at `gauntlet.MaxSessionIdle`/`MaxSessionLifetime`, AAL2's own figures, recorded there |
| 7.1.2 concurrent sessions documented | 2 | Met, here | Unlimited sessions per account; each is independent; `logout-all` ends them together; a credential change ends them all through `SessionCutoff`. The owner sees them in `GET /api/auth/sessions`, which shows at most 100 rows and a `total` of all of them (#48) |
| 7.1.3, 7.6.1 federated sessions documented | 2 | Met, here | An SSO session is gauntlet's own, with gauntlet's timeouts. Signing out at the sign-in server does not end the gauntlet session, and gauntlet does not ask the server again until the next sign-in. Back-channel logout (where the server tells the app to end a session) is not supported |
| 7.2.1 verified on the backend | 1 | Met | `SessionStore.Validate` under the server's lock (`session.go:416-418`) |
| 7.2.2 dynamic reference tokens | 1 | Met | The session ID is a random value that means nothing by itself, made per login; the server looks the session up by it (`session.go:246`) |
| 7.2.3 CSPRNG, 128 bits | 1 | Met | `id.go:13-15`: 16 bytes from `crypto/rand` |
| 7.2.4 new token on every authentication, old one ended | 1 | Met | Every sign-in gets a new session ID, and `logout-all` makes a new session (`gate/logout_handler.go:96`). When a timed-out session is resumed with just the password (#71), the old ID is ended and a new one issued in one step (`SessionStore.Resume`). A login half-way through (the pending-login cookie) is never a session. A sign-in (password, second factor or SSO) from a browser still holding the same account's live session ends that session before the new one is issued (`gate/cookie.go` `revokeReplacedSession`, #47) |
| 7.3.1, 7.3.2 inactivity and absolute timeouts | 2 | Met | Both enforced in `Validate` (`session.go:416-437`); a session timed out inside its ceiling authenticates nothing and is held only to be resumed (#71); `gate.New` refuses a store with no ceiling or above `MaxSessionIdle`/`MaxSessionLifetime` (#51) |
| 7.4.1 terminated session unusable | 1 | Met | Server-side delete (`Revoke`, `RevokeAllForUser`); `SessionCutoff` catches sessions from another process (`gate/protect.go:226`) |
| 7.4.2 sessions ended when an account is disabled or deleted | 1 | Met | A deleted user no longer resolves, so every session dies on its next request. Deleting through `DELETE /api/auth/users/{id}` also ends the account's sessions and revokes the API tokens it created (`gate/users_handler.go:262-263`). `Store.DeleteUser` on its own does neither, so an application calling it directly does that itself; `Gate.SweepTokens` removes any token whose creator no longer exists (`token.removed_orphaned`) |
| 7.4.3 option to end other sessions after a factor change | 2 | Met | These end every session: a password change and a reset (`SessionsEndedAt`, `store.go:2118`, `resetcode.go:231`); turning on a second factor, that is confirming the recovery codes for a first factor, or adding an authenticator app to an account that already holds a passkey (`gate/recoverycodes_handler.go:154`, `gate/totp_handler.go:254`); and removing the last second factor (`gate/totp_handler.go:334`, `gate/passkey_handler.go:560`). These do not: adding a further passkey, removing one of several, regenerating recovery codes. For those, `POST /api/auth/logout-all` is the option |
| 7.4.4 logout visible on every page | 2 | App | Frontend |
| 7.4.5 admins can end a user's sessions | 2 | Met | `POST /api/auth/users/{id}/logout-all` ends every session the account holds and forgets its remembered browsers, leaving its password and factors (`gate/users_logoutall_handler.go`, #53); audited as `user.sessions_ended`, and `gate.Config.Notices` lets the application tell the owner (the older `Config.Notify` still works but is deprecated). A reset code or deleting the account also ends them |
| 7.5.1 full re-authentication before changing authentication settings | 2 | Met | `recheckPassword` guards password change, TOTP enrol and delete, passkey register and delete, recovery-code regeneration (`gate/password_handler.go:77`, `gate/totp_handler.go:72,309`, `gate/passkey_handler.go:190,544`, `gate/recoverycodes_handler.go:63`) |
| 7.5.2 users can view and end their sessions | 2 | Met, with a deviation | `GET /api/auth/sessions` lists the caller's own live sessions with the address and browser each signed in from; `DELETE /api/auth/sessions/{ref}` ends one, `logout-all` ends all (`gate/sessions_handler.go`, #48). Deviation: ending a session asks for no re-authentication, for any account, SSO-only included. Owner decision, 2026-10-02: signing out is the safe direction. Someone holding a stolen session can already end all sessions of an SSO-only account with `logout-all`, because that account has no password to ask for. (An account with a local password does give its password there, #79.) Asking for one here would add nothing. Ends gauntlet's session only, not the IdP's |
| 7.5.3 step-up before highly sensitive operations | 3 | Met | Making an account an admin (`POST /api/auth/users` with `role: admin`, `PUT /api/auth/users/{id}/role`) needs the granting admin to type their password and a current second-factor code again in the same request. These re-entries share a limit on wrong tries, like the password re-check (`recheckStepUp`, #67, ADR-0010). The other admin routes that take over, expose or strip an account -- reset code, create token, delete user, clear a user's authenticator app or passkeys -- need the calling admin's password again, under the same limit (`recheckAdminPassword`, #72) |
| 7.6.2 session needs the user's action | 2 | Met | The OIDC flow starts from the user's redirect and a sealed flow cookie; the callback cannot create a session without it (`gate/oidc_handler.go:301-305`) |

### V8 Authorization

| Req | Level | Status | Evidence |
|---|---|---|---|
| 8.1.1 function-level rules documented | 1 | Met | `docs/design.md` §2.1 (roles) and `docs/api/auth.yaml` (which routes need `admin`); token kinds reach only the handler registered for them (`Gate.Handle`) |
| 8.1.2 field-level rules documented | 2 | Met | `Store.List` and `blankCredentials` define what leaves the store (`user.go:263`); `docs/api/auth.yaml` lists every field a response may contain and allows no others (the one exception is WebAuthn's own passkey JSON) |
| 8.1.3, 8.1.4, 8.2.4 contextual or adaptive decisions | 3 | N/A | None made on access to a route: once a session exists, its role alone decides. Context is used only at sign-in, before any session exists: the client address feeds the login limiter and the address ban; a known-browser token (#44) gives that browser a small allowance during a lockout; the address and browser feed the unusual-sign-in checks (#55, `gate/unusual.go`), which can hold or refuse a sign-in (6.3.5, 800-63B §3.2.2). None of them grants or widens access |
| 8.2.1 function-level enforcement | 1 | Met | `RequireRole` (`gate/protect.go:553`), on every admin route (`gate/routes.go:66-80`); unknown role denied everything (`user.go:27-37`, `gate/protect.go:428`) |
| 8.2.2 object-level enforcement | 1 | Met | Passkey rename and delete take the caller's own account id; user and token routes are admin only; `logout-all` acts on the cookie's account, never a body field |
| 8.2.3 field-level enforcement | 2 | Met | Secrets blanked before any copy leaves the store; hashes never serialised to HTTP |
| 8.3.1 enforced on the server | 1 | Met | All in `gate`; nothing trusts the frontend |
| 8.3.2 changes apply immediately | 3 | Met | Role read from the store on every request (`gate/protect.go:213-231`) |
| 8.3.3 originating subject's permissions | 3 | Met | No service-to-service hop; the token or session on the request decides |
| 8.4.1 multi-tenant | 2 | N/A | Single tenant by design: the one shared SSO issuer accepted, Google, needs the `hd` domain pinned (ADR-0014, `oidc/policy.go` `AllowIssuerWithPolicy`) |
| 8.4.2 layered admin access | 3 | Not targeted | Access depends on the role plus a mandatory second factor; gauntlet does not check the health or setup of the device (device posture) |

### V9 Self-contained tokens

Gauntlet mints seven sealed values the browser carries back: the OIDC
flow state, the pending login, the confirm ticket (an unusual sign-in
held for a code or a passkey, #55, #65), the escape ticket (#66), and
the three passkey exchanges (registering, asserting, signing in), each a
two-step challenge-and-answer between server and browser. Each sealed
value is encrypted and integrity-protected (AES-256-GCM) so the browser
can hold it but not read or forge it.

| Req | Level | Status | Evidence |
|---|---|---|---|
| 9.1.1 integrity checked before use | 1 | Met | GCM tag; any failure is a refusal (`internal/seal/seal.go:99-120`, the one codec `oidc/state.go`, `gate/pendinglogin.go` and `passkey/seal.go` share); the confirm and escape tickets use the pending login's codec type (`gate/confirmlogin.go:66`, `gate/escapelogin.go:96`) |
| 9.1.2 algorithm allowlist, no `none` | 1 | Met | One fixed cipher per codec; no header, no negotiation |
| 9.1.3 keys from trusted configuration | 1 | Met | A random per-process key per codec; nothing in the value names a key |
| 9.2.1 validity window checked | 1 | Met | Expiry inside the sealed payload: 5 min for the flow state, the pending login and the three passkey ceremonies (`oidcFlowCookieMaxAge`, `pendingLoginCookieMaxAge`, `passkey/challenges.go:15`); 15 min for the confirm and escape tickets, since a person may wait for a code (`ConfirmCodeLifetime`, `EscapeCodeLifetime`) |
| 9.2.2 right type for the purpose | 2 | Met | A separate codec and key for each: the three passkey ceremonies (`passkey/seal.go:47-51`), the pending login, the confirm ticket, the escape ticket and the flow state; one cannot open as another |
| 9.2.3, 9.2.4 audience (who a value is meant for) | 2 | Met | A sealed value can only be opened by the process that made it, because each process has its own keys; ID tokens' `aud` is checked against the client id by go-oidc |

### V10 OAuth and OIDC (client side only)

| Req | Level | Status | Evidence |
|---|---|---|---|
| 10.1.2 values accepted only from the flow this agent started | 2 | Met | `state`, `nonce` and the PKCE code verifier (PKCE: Proof Key for Code Exchange, which stops a stolen sign-in code being used by someone else) are random 256-bit values kept in the encrypted flow cookie (`oidc/state.go:69-71`); constant-time `state` compare (`gate/oidc_handler.go:319`) |
| 10.2.1 CSRF on the code flow | 2 | Met | PKCE S256 (`oidc/oidc.go:234`, `:236`) and `state` |
| 10.2.2 mix-up defence (mix-up: tricking the app into using the wrong sign-in server) | 2 | N/A | One issuer per deployment; go-oidc checks the ID token's `iss` against it |
| 10.2.3 minimal scopes | 3 | App | `oidc.Config.Scopes` is the application's |
| 10.5.1 nonce | 2 | Met | `oidc.VerifyNonce` (`gate/oidc_handler.go:339`) |
| 10.5.2 identify by `sub` | 2 | Met | `(issuer, subject)`; email is display only |
| 10.5.3 issuer in metadata must match | 2 | Met | go-oidc discovery refuses a mismatched issuer; `AllowIssuerWithPolicy` refuses multi-tenant ones whose policy does not pin the tenant before that (ADR-0014) |
| 10.5.4 `aud` equals client id | 2 | Met | go-oidc verifier config |
| 10.5.5 back-channel logout | 2 | N/A | Not implemented |
| 10.3, 10.4, 10.6, 10.7 resource and authorization server | — | N/A | Gauntlet is a client; its own bearer tokens are not OAuth |

### V11 Cryptography

**Inventory (11.1.2).** Every cryptographic use, so a future change (or a
post-quantum migration) starts from a list rather than a search:

| Use | Algorithm and parameters | Where |
|---|---|---|
| Passwords, recovery codes, reset codes at rest | Argon2id, 64 MiB, 3 passes, 4 lanes, 16-byte salt, 32-byte output; the settings are stored inside each hash and read back when checking; on read they may not exceed 4 times the current settings, so a forged hash cannot force a huge memory or time cost | `password.go:28-50`, `:127-161` |
| Bearer tokens at rest | SHA-256 of a 128-bit random value (fast hash is enough for a random secret); expire after a year unless the admin chooses a time or `never`, are removed after a year unused, and start `gnt_` so a leak is recognisable (#74) | `token.go:164-169`, `:638-640` |
| Setup code | SHA-256, memory only, constant-time compare | `setupcode.go:73,90` |
| Escape code (#66) | 80 bits (the setup code's generator), only its SHA-256 kept, inside a sealed ticket cookie bound to the refused browser; constant-time compare; single use; 15 minutes; dies with the process | `escapecode.go`, `gate/escapelogin.go` |
| TOTP | HMAC-SHA1 over a 160-bit secret, 30 s step, 6 digits (RFC 6238; SHA-1 inside HMAC is approved by SP 800-131A) | `totp.go:47-64`, `:215-219` |
| Sealed cookies (OIDC flow, pending login, confirm and escape tickets, passkey ceremonies) | AES-256-GCM, 32-byte key from `crypto/rand` per process and per codec, 96-bit random nonce per value, strict base64url | `oidc/state.go`, `gate/pendinglogin.go`, `gate/confirmlogin.go`, `gate/escapelogin.go`, `passkey/seal.go` |
| Sealed accounts and tokens documents, on every backend (#50) | Encrypted with AES-256-GCM. A fresh key is derived for every save from the application's key (at least 32 bytes) and a random 16-byte salt (HKDF-SHA256), so no two saves share a key; 96-bit random nonce. The document is tied to its store's name (passed as AAD, the "additional authenticated data" that must match when it is opened: `EncryptOptions.Label`, or the file's path for `EncryptedFileBackend`), so a copy put in another store will not open. The sealed document starts with a fixed marker and a version number, and is carried as `{"sealed": "<base64>"}` through a database backend | `persist/seal.go`, `persist/encrypted.go` |
| Random values | `crypto/rand`: session and account ids 128 bits, token values 128 bits, TOTP secrets 160 bits, reset, setup, unlock and escape codes 80 bits, recovery codes 50 bits, OIDC `state`/`nonce` 256 bits, WebAuthn challenge 256 bits | `id.go`, `totp.go`, `resetcode.go`, `setupcode.go`, `unlockcode.go`, `escapecode.go`, `recoverycodes.go`, `oidc/state.go`, go-webauthn |
| Signature verification | ID tokens RS256/ES256/PS256 (go-oidc); WebAuthn assertions, library default COSE algorithms (go-webauthn v0.18.2) | `oidc/oidc.go:211`, `passkey/ceremony.go` |

**Key lifecycle (11.1.1).** Per-process keys are made at start and die
with the process; a restart ends in-flight ceremonies and pending
logins, which is accepted. The document key is the application's
(trust boundary section above): gauntlet never reads it. The TOTP
secret is the one long-lived symmetric key gauntlet stores; it is
sealed under the document key on every backend, and `OpenStore`
refuses a backend that would hold it in the clear (13.3.1 below, #50).

**Changing the document key.** Take care: a document sealed under a key
the application no longer has cannot be opened. Every account, TOTP
secret and token in it is lost, and nobody can sign in. So:

1. Stop the application, so nothing writes while the key changes.
2. Keep the old key file. Make the new key: at least 32 bytes from a
   secure random source.
3. For each store sealed under that key (accounts, tokens, and the
   sign-in history if the application keeps one), read the document
   with the old key and write it back with the new one, calling `Save`
   with the version number that `Load` returned, so it fails if something
   else changed the document in between. Gauntlet ships no tool for
   this; it is a few lines of Go in the application. How depends on
   the backend:
   - **The file backend** (`persist.NewEncryptedFileBackend`): `Load`
     through `NewEncryptedFileBackend(path, oldKey)`, then `Save`
     through `NewEncryptedFileBackend(path, newKey)`. The file is tied
     to its path, so give both the same path, written exactly as the
     application gives it. Do not use `persist.Encrypt` here: it binds the
     document to a `Label`, not the file's path, so the file backend would
     refuse it.
   - **Your own backend** (`persist.Encrypt`): `Load` through
     `persist.Encrypt(backend, oldKey, opts)`, then `Save` through
     `persist.Encrypt(backend, newKey, opts)`, with the same backend and
     the same `Label`.
4. Start the application with the new key and check that someone can
   sign in. Only then delete the old key: until that check passes, it
   is the only way back.

| Req | Level | Status | Evidence |
|---|---|---|---|
| 11.1.1, 11.1.2 key policy and inventory | 2 | Met | Above |
| 11.1.3, 11.1.4 discovery tooling, PQC plan | 3 | Not targeted | Inventory above is the plan's starting point |
| 11.2.1 validated implementations | 2 | Met | Go standard library, `golang.org/x/crypto/argon2`, go-oidc, go-webauthn; all CVE-checked (`docs/design.md` §4) |
| 11.2.2 ability to change algorithms later (crypto agility) | 2 | Met | Password-hash settings are stored in each hash, the encrypted file carries a version byte, and short-lived sealed values vanish with the process. TOTP's SHA-1 is fixed on purpose (RFC 6238 section) |
| 11.2.3 at least 128-bit security | 2 | Met | Table above; nothing below 128 bits except hashed single-use codes, which 6.5.4 covers |
| 11.2.4 constant-time comparisons | 3 | Met | `subtle.ConstantTimeCompare` for password, TOTP, setup code, OIDC state; every unused recovery code checked even after a match (`recoverycodes.go:266-273`) |
| 11.2.5 fail securely | 3 | Met | A decryption failure (AES-GCM) is a refusal with one generic message, so an attacker learns nothing from which way it failed; there is no padding to probe (no padding oracle) |
| 11.3.1–11.3.5 ciphers, modes, AEAD, nonces | 1–3 | Met | AES-GCM only; a random 96-bit one-time value (a "nonce") for each encryption. That is safe here because a file is saved only a few times, and each save also uses a fresh key (the per-save HKDF salt) |
| 11.4.1 approved hashes | 1 | Met | SHA-256, HMAC-SHA1 (approved for HMAC), no MD5 |
| 11.4.2 password hashing with current parameters | 2 | Met | RFC 9106 §4's second recommended Argon2id setting (the lower-memory one) |
| 11.4.3 hash lengths | 2 | Met | 256-bit outputs where collision resistance matters |
| 11.4.4 KDF with stretching | 2 | Met | `DeriveKey` is the same Argon2id profile |
| 11.5.1 CSPRNG, 128 bits for non-guessable values | 2 | Met | Table above |
| 11.5.2 CSPRNG under load | 3 | Met | `crypto/rand`; `newID` panics rather than degrades |
| 11.6.x, 11.7.x public-key generation, memory encryption | 2–3 | N/A | Gauntlet makes no public/private key pairs; encrypting data while a program is running (in memory) is up to the host or hardware |

### V16 Security logging and error handling

**Logging inventory (16.1.1).** Two channels, both the application's to
store, keep and protect:

- `*slog.Logger` (`Options.Log`, `TokenOptions.Log`, `gate.Config.Log`)
  takes these lines:
  - backend failures (`logError`) and refused saves
  - the limiter running short of memory and dropping old entries
    (`ratelimit.go:440`)
  - a lockout whose save failed (`ratelimit.go:1255-1256`)
  - a refused setup code (`gate/register_handler.go:57`), a refused unlock
    code (`gate/unlock_handler.go:56`) and an SSO policy denial
    (`gate/oidc_handler.go:358`)
  - the setup code, the lone admin's unlock code and escape code, each
    when issued (`setupcode.go:125`, `unlockcode.go:171`,
    `gate/escapelogin.go:188`)
  - an account notifier (`Config.Notices`) that failed or panicked
    (`gate/notify.go`)
  - rated Warn lines (Warn lines limited to one per kind and address per
    minute, `gate/warnrate.go`) for a sign-in the login limiter refused,
    a re-check it refused, a request body over 64 KiB, a missing CSRF
    header, a malformed `Authorization` header, a role refusal on gate's
    admin routes and the three 403s that keep a session at a required step
    (the three doors), each with `from=` the client address (#45)

  Lines name the account (a name that matched none masked by
  `MaskUnknownUsername`). Apart from the setup code, unlock code and
  escape code (written to the log on purpose, for whoever has access to
  the host), log lines never contain a password, code, token, cookie or
  secret.
- `gate.Auditor.Record(actor, action, target, detail)`: one record per
  event below. A record a request writes ends with `from=` the client
  address (#45); the two token sweeps have actor `system` and no
  address. Timestamps and storage are up to the application, wherever it
  sends its logs.

  | Group | Action | Recorded when |
  |---|---|---|
  | Sign-in | `user.login` | A sign-in completed (#45, `gate/signin_record.go`). One that an admin's allowance let through (#81) carries the note `allowed=used; ` and says `via admin allowance; ` |
  | Sign-in | `user.login_failed` | A wrong password, code or passkey the limiter let through; or a wrong password or code at an in-session re-check (`step=recheck`) |
  | Sign-in | `user.login_refused` | The account's sign-in policy refused a sign-in whose credentials were right (#55) |
  | Sign-in | `user.reauthenticated` | A timed-out session was resumed with the password or a passkey (#71, #77) |
  | Sign-in | `account.locked` | Too many wrong tries: a lockout started |
  | Sign-in | `account.disabled` | 50 failures in a row switched the account's sign-in off |
  | Sign-in | `address.banned` | 100 failed sign-ins from one address banned it for 24 hours (#70) |
  | Sign-in | `user.unlock` | An admin lifted an account's lockout or disable (`gate/users_handler.go:462`) |
  | Sign-in | `user.sign_in_allowed` | An admin allowed an account's next sign-in from any browser or place (#81) |
  | Sign-in | `account.unlock_code_used` | The lone admin lifted their own disable with the unlock code from the server's log (`gate/unlock_handler.go:67`) |
  | Second factor | `account.totp_enabled`, `account.totp_disabled` | The account's owner added or removed an authenticator app |
  | Second factor | `account.passkey_added`, `account.passkey_removed` | The owner added or removed a passkey |
  | Second factor | `account.passkey_clone_suspected` | A passkey's use counter went backwards or did not move, which suggests a copied key; the sign-in was refused. A counter that is 0 both stored and presented is normal (most phone and laptop passkeys never count) and is accepted with no entry |
  | Second factor | `user.totp_cleared`, `user.passkeys_cleared` | An admin removed another account's authenticator app or passkeys |
  | Second factor | `account.recovery_codes_regenerated` | The owner asked for a new set of recovery codes |
  | Accounts and roles | `user.register` | The first admin was created with the setup code |
  | Accounts and roles | `user.create` | An admin created an account, or a first SSO sign-in did (actor `sso`) |
  | Accounts and roles | `user.delete` | An admin deleted an account |
  | Accounts and roles | `user.role_changed` | An admin changed a role, or the identity provider's group map moved an account at sign-in (actor `sso`, #76) |
  | Accounts and roles | `account.password_changed` | The owner changed their password |
  | Accounts and roles | `user.password_reset` | An admin issued a reset code |
  | Accounts and roles | `account.link_sso` | The owner linked the account to SSO |
  | Accounts and roles | `account.sessions_ended` | The owner signed out everywhere, or ended one session |
  | Accounts and roles | `user.sessions_ended` | An admin signed another account out everywhere (#53) |
  | Tokens | `token.create`, `token.revoke` | An admin created or revoked an API token |
  | Tokens | `token.removed_unused` | `Gate.SweepTokens` removed a token unused for a year (#74) |
  | Tokens | `token.removed_orphaned` | `Gate.SweepTokens` removed a token whose creating account no longer exists |

- The sign-in history (#53, ADR-0006), a third sealed document the
  application stores (`gate.Deps.SignIns`): one row per sign-in
  attempt, with repeated alike attempts merged into a single row with a
  count -- time, account or masked name,
  outcome, method, address, browser -- the newest 10,000 by default,
  read by admins through `GET /api/auth/sign-ins`. Never a password,
  code or a name as typed.

| Req | Level | Status | Evidence |
|---|---|---|---|
| 16.1.1 inventory | 2 | Met | Above |
| 16.2.1 who, what, when, where | 2 | Met | Who and what are in every record; when is the sink's; where (`from=` the client address, quoted) is in every audit record a request writes (`gate.audit` takes the request) and every refused-request Warn line (#45); the sign-in history keeps the address and browser of each attempt (#53) |
| 16.2.2 UTC timestamps | 2 | App | The sink's clock |
| 16.2.3, 16.2.4 only documented sinks, parseable | 2 | Met | Only the two channels above; `slog` is structured |
| 16.2.5 no secrets in logs | 2 | Met | Inventory above; raw token shown once in the create response only |
| 16.3.1 all authentication attempts logged, success and failure | 2 | Met | Every sign-in attempt is recorded (`gate/signin_record.go`). A successful password, second-factor or SSO sign-in is `user.login`. A wrong password, code, passkey assertion or SSO identity that the limiter let through is `user.login_failed`. One the limiter refused gets a rated Warn line. When the application keeps a sign-in history, each attempt is also a row there (#53). The same applies when a signed-in person is asked to type their password again (an in-session re-check): a wrong password or code is `user.login_failed` with `step=recheck`, and a refused re-check gets a rated Warn line. A refused setup or unlock code is logged (#45) |
| 16.3.2 failed authorization logged | 2 | Met | A rated Warn line with the address for a missing CSRF header, an unrecognised role, any of the three doors, and a role refusal on every admin route `Routes` serves (`gate/protect.go` `warnRefused`, `adminOnly`). An application's own `RequireRole` wrapping has no `Gate` to log through and writes nothing (#45) |
| 16.3.3 attempts to bypass controls logged | 2 | Met | A lockout starting is `account.locked`, a disable `account.disabled` (on the ordinary path and through a known browser's allowance), an address ban starting `address.banned` (#70), every attempt refused during either a rated Warn line, and a malformed `Authorization` header and a request body over 64 KiB each a rated Warn line (#45) |
| 16.3.4 unexpected errors logged | 2 | Met | `logError` on every backend or sealing failure |
| 16.4.1 log injection | 2 | Met | Usernames refuse control and format characters (`username.go:90`); token names likewise (`token.go:670`); `slog` quotes |
| 16.4.2, 16.4.3 log protection and shipping | 2 | App | The sink |
| 16.5.1 generic error messages | 2 | Met | `gateErrorMessages` (`gate/httpjson.go:115-154`, used by `writeAuthError` at `:163-170`); anything unmapped is logged and answered with a fixed text |
| 16.5.2 external failure handled | 2 | Met | 10 s IdP timeouts; `ErrDocumentRemoved` keeps reads working (`docs/design.md` §4 fail-closed list) |
| 16.5.3 fail closed | 2 | Met | Fail-closed list; a save that fails refuses the login that depended on it (`gate/login_handler.go:420-443`) |
| 16.5.4 last-resort handler | 3 | App | `net/http` recovers a handler panic per connection; the application owns the server |

### Input handling at the routes (V1, V2, V4, V14, V15)

| Req | Level | Status | Evidence |
|---|---|---|---|
| 1.2.3 JSON output encoded | 1 | Met | `encoding/json` only (`gate/httpjson.go:102`, `:255`) |
| 1.2.4 database injection | 1 | N/A | Document store; the application's backend sees opaque bytes |
| 1.5.2 safe deserialisation | 2 | Met | Typed structs, `DisallowUnknownFields`, trailing data refused, 64 KiB cap (`gate/httpjson.go:37-66`) |
| 2.1.1 validation rules documented | 1 | Met | `docs/api/auth.yaml` request schemas; `TestContractRequestBodiesMatchHandlers` |
| 2.2.1, 2.2.2 server-side positive validation | 1 | Met | `ValidateUsername`, `ValidateLocalUsername` (`username.go`), token name and device rules (`token.go`), TOTP code shape (`totp.go:261-269`), code normalisation (`resetcode.go:72`) |
| 2.3.1 steps in order, none skipped | 1 | Met | Password → pending login → factor → session; ceremonies sealed and spent once (ADR-0004 decision 5) |
| 2.4.1 anti-automation | 2 | Met | Limiter on login, factor, setup code and re-checks; a cap on how many Argon2id password hashes run at once (`password.go:68-70`) |
| 4.1.1 `Content-Type` with charset | 1 | Met | `application/json; charset=utf-8` on every successful JSON response (`writeJSON`, `gate/httpjson.go:97`, #46). Error bodies are `application/problem+json` with no charset parameter, because RFC 9457 defines none; JSON is always UTF-8 (RFC 8259), so the character set is still fixed (`gate/httpjson.go:242`) |
| 4.1.3 proxy headers not user-overridable | 2 | App | `gate.Config.ClientIP` is the application's trusted-proxy policy (`docs/design.md` §1.7) |
| 13.3.1 secrets management | 2 | Met | The accounts document -- TOTP seeds and passkey public keys inside it -- is sealed by `persist.Encrypt` before any backend stores it, and `OpenStore` refuses a backend that stores plaintext unless the application sets `AllowPlaintextAtRest` (#50, ADR-0005); the key is the application's secret, never the document's. See 800-63B §3.1.4.2 |
| 14.2.1 no secrets in URLs | 1 | Met | Bearer token read from the header only (RFC 6750 section above); the OIDC code is consumed once from the callback query, as the protocol requires |
| 14.3.2 `Cache-Control: no-store` | 2 | Met | Set on every JSON response, error bodies included (`writeJSON`, `gate/httpjson.go:84`; `writeProblem`, `:242`; #46) |
| 15.1.2 dependency inventory | 2 | Met | `go.sum`, `supply-chain/licence-policy.yml`, `govulncheck` in CI |
| 15.2.2 resource-heavy functions bounded | 2 | Met | At most 4 concurrent Argon2id (`password.go:68-70`), limiter before hashing, 64 KiB bodies |
| Request floods (no ASVS row) | -- | App | Gauntlet limits every route that checks a guessable secret (above) and nothing else: session IDs and bearer tokens are 128 random bits (`id.go`), out of reach of guessing at any rate. A general per-address request limit across all routes belongs in the application's reverse proxy, which sees every request before the application does (owner, 2026-10-02) |
| 15.3.1 only the needed fields returned | 1 | Met | `blankCredentials`; closed response schemas |
| 15.3.3 mass assignment | 2 | Met | Each handler decodes a named request struct |
| 15.3.4 client IP from a trusted field | 2 | App | `ClientIP` |
| 15.4.1–15.4.3 safe concurrency | 3 | Met | Store and session mutexes; each change is made on a copy of the data and then saved (`mutate.go`); `-race` in CI (Go's data-race detector); two requests cannot both use the same one-time code, because checking and marking it used happen as one locked step (TOTP, recovery codes and ceremonies) |
| 3.3.1 cookie `Secure` | 1 | Met, conditional | `gate.Config.SecureCookie`; the application must set it where TLS terminates, and `gate.New` logs one warning naming the setting when it is left false (#47) |
| 3.3.2 `SameSite` fits the purpose | 2 | Met | `Lax` on every cookie (`gate/cookie.go` `writeCookie`) |
| 3.3.3 `__Host-` prefix | 2 | Met, conditional | The session cookie is `__Host-` + `CookieName` while `SecureCookie` is true (`gate/cookie.go` `sessionCookieName`, #47); under plain HTTP a browser would drop a `__Host-` cookie, so the bare name is used there. The ceremony cookies and the known-browser cookie (`gate_known_browser`, path `/api/auth`, #44) are scoped to their routes, which the prefix forbids |
| 3.3.4 `HttpOnly` | 2 | Met | Every cookie |
| 3.3.5 cookie under 4096 bytes | 3 | Met | Session id 32 characters; known-browser token 43; sealed values a few hundred bytes |
| 3.5.1 CSRF | 1 | Met | `X-Requested-With` on every method but `GET` and `HEAD`, plus `SameSite=Lax` (`gate/protect.go:171-186`, called at `:403`); bearer requests skip it because no cookie is involved (the bearer branch returns first, `:380-390`) |
| 3.5.3 routes that change data use POST, PUT, PATCH or DELETE, never GET (the "unsafe" methods) | 1 | Met | Every mutation is POST, PUT, PATCH or DELETE (`docs/api/auth.yaml`); the OIDC callback is GET but creates nothing without the sealed flow cookie |

### Summary

At L2 gauntlet meets every requirement. The common-password list
(6.2.4) ships with the module since #52. The breached-password check
(6.2.12) is met where the application turns on the live HIBP check. The lockout shape from the 800-63B review is
settled (#44). Three deviations are recorded rather than fixed: the TOTP
acceptance window, the SSO sign-in's reliance on the IdP's policy, and
ending one session without re-authentication (7.5.2, owner 2026-10-02).
Secrets at rest were a fourth until #50 sealed the document on every
backend.

## Standards conformance: NIST SP 800-63B (#34)

**Revision.** SP 800-63B-4, *Digital Identity Guidelines: Authentication
and Authenticator Management*, final, published August 2025
(<https://doi.org/10.6028/NIST.SP.800-63b-4>; read at
<https://pages.nist.gov/800-63-4/sp800-63b.html>). It supersedes
revision 3. Section numbers below are revision 4's.

**What gauntlet is in NIST's words.** For local accounts gauntlet checks
credentials (NIST's *verifier*) and also issues them and attaches them
to accounts (NIST's *credential service provider*): the password, the
TOTP secret, recovery codes, passkeys and reset codes. For SSO it is the
*relying party* (the app that trusts the single sign-on server) of a
self-hosted IdP. The *subscriber* (the person who signs in) is the
operator or one of a handful of colleagues; the apps are the service.

**Assurance level.** NIST grades an authentication event AAL1 to AAL3
(authenticator assurance level).
A second factor is mandatory for every local-password account (#49), so
a local sign-in is always a password plus a single-factor OTP (TOTP), a
look-up secret (recovery code) or a single-factor cryptographic
authenticator (passkey): **AAL2** (§2.2.1). AAL3 is not claimed:
it needs a non-exportable hardware key on every sign-in and FIPS 140
validated modules, and NIST itself rules synced passkeys out of AAL3
(Appendix B). An SSO sign-in is whatever the IdP's policy makes it;
gauntlet adds nothing to it (see the ASVS section, 6.8.4).

**Out of scope.** The federal-only material: FIPS 140 validation (the US
government's certification of cryptographic modules, §2.1.2 and after),
records retention, US federal-agency privacy paperwork (SORN and PIA
privacy notices, §2.4) and a way to dispute decisions (redress, §2.4.4),
biometrics (§3.2.3), codes sent by phone network (PSTN) or other channels
(out-of-band authenticators, §3.1.3), identity proofing (§4.2.2), session
monitoring (§5.3), and attestation (proof of which make of device a
passkey comes from, §3.2.4; gauntlet asks for none, which Appendix B says
"SHOULD NOT block" public use).

**How to read the tables.** *Conforms* names the code. *Deviation* is a
deliberate difference, documented here as the issue asks. *Gap* names the
issue that tracks the fix. Where the ASVS section above already holds the
evidence, the row points at it. NIST's capital words mean: SHALL =
required, SHOULD = recommended, MAY = optional.

### Passwords (§3.1.1)

| Requirement | Status | Evidence |
|---|---|---|
| Chosen by the subscriber or assigned randomly (§3.1.1.1) | Conforms | User-chosen; the only assigned secret is the reset code, which must be replaced on first use |
| 15 characters minimum as a single factor; 8 minimum when only part of MFA (multi-factor authentication, §3.1.1.2) | Conforms | `minPasswordLength = 8` (`store.go:48`), conforming unconditionally because a second factor is mandatory for every local-password account and cannot be turned off (#49) |
| Permit at least 64 characters; accept ordinary typed characters, spaces and any Unicode character; count each character as one, so an accented letter or emoji is one (SHOULD) | Conforms | No maximum, no character rules; length counted in characters, each code point one (`passwordTooShort`, `store.go:55-57`) |
| No other composition rules (SHALL NOT) | Conforms | None |
| No periodic change; force a change on compromise | Conforms | No expiry; an admin reset sets `MustChangePassword` and kills the old password at once (`resetcode.go:223-229`); five failed second-factor steps in a row, which only someone with the password can make, set it too and sign the account out everywhere (`LoginLimiter.SecondFactorFailed`, #44); so does a sign-in whose breach recheck finds the password in HIBP (`Store.Authenticate`, #43) |
| No hints, no knowledge-based questions | Conforms | None exist |
| Verify the whole password, no truncation | Conforms | `password.go:94`, `:161` |
| NFC normalisation before hashing (SHOULD) | Deviation | Not applied: passwords are not converted to one standard form of accented letters (NFC normalisation) before hashing. ASVS 6.2.8 asks for the bytes exactly as received, and the operators of the applications that use gauntlet type on their own devices. A password with an accented letter, typed on a device that builds that letter differently, will not match; documented, not fixed |
| Blocklist of common, expected and compromised passwords, whole-password match, reason given on refusal (SHALL) | Conforms | Context words (username, product name), the built-in list of the 10,000 most common breached passwords (signed, shipped with the module since #52, ADR-0007), and the opt-in live HIBP check (#43), each whole-password, each refusal a plain reason (`ErrPasswordContext`, `ErrPasswordBlocked`, mapped to `400` by gate). See ASVS 6.2.4 |
| Guidance on choosing a strong password (SHALL) | Application | Frontend copy; gauntlet returns a plain reason for each refusal: too short, common or breached, too close to the username or product name |
| Rate limiting on the account (SHALL, §3.2.2) | Conforms | Below |
| Password managers and paste allowed | Conforms | Nothing server-side interferes |
| Salted and hashed with a password hashing scheme, cost as high as practical, parameters stored with each hash, salt at least 32 bits | Conforms | Argon2id, RFC 9106 §4's second recommended setting, 128-bit salt, parameters in the hash string (`password.go:28-50`, `:94-99`). ASVS 11.4.2 |
| Extra keyed hash with a verifier-only secret (SHOULD) | Deviation | Not done. A pepper is a second secret mixed into every password hash and kept apart from the stored data. Gauntlet instead encrypts the whole accounts document (`persist.Encrypt`, on every backend since #50; trust boundary section above), and a pepper would be one more key for the application to store |

### Look-up secrets: recovery codes (§3.1.2, §4.2.1.1)

Gauntlet's recovery codes replace the *second* factor only; they do not
replace the password, which is still required
(`gate/login_handler.go:295`). So NIST treats them as a second-factor
method (a look-up secret used as an authenticator, §3.1.2), not as
account recovery (§4.2), which is the path that bypasses authentication.
§3.1.2 is the stricter rule, and the one applied here;
§4.2.1.1's 64-bit minimum and reissue-on-use rules are for codes that
stand alone, which these never do.

| Requirement | Status | Evidence |
|---|---|---|
| Made by an approved random bit generator (RBG; Go's `crypto/rand`), at least six decimal digits | Conforms | 10 characters over a 32-letter alphabet from `crypto/rand`: 50 bits (`recoverycodes.go:30-39`, `:58-60`, `resetcode.go:117-129`) |
| Delivered over a session authenticated at AAL2 | Conforms | Minted at TOTP confirmation or passkey registration, inside a session, after the enrolment's first step re-checked the password (`gate/totp_handler.go:218`, `gate/passkey_handler.go:363`) |
| Used successfully only once | Conforms | `BurnRecoveryCode` marks `UsedAt` under the lock, by hash not position (`recoverycodes.go:290-310`) |
| Stored hashed; under 112 bits means a password hashing scheme with a 32-bit salt | Conforms | Argon2id with a 128-bit salt (`enrolhold.go:166`). ASVS 6.5.2 |
| Rate limited on the account (§3.2.2) | Conforms | Shares the login account budget (`gate/login_handler.go:412`) |
| Replacement code on request; replacement notifies the subscriber (§4.2.1.1) | Conforms, and a deviation | `POST /api/auth/recovery-codes` regenerates the set behind the password; telling the account's owner is covered in the "Tell the account's owner" row below (§4.6) |

### Single-factor OTP: TOTP (§3.1.4)

| Requirement | Status | Evidence |
|---|---|---|
| Key at least 112 bits of strength; approved hash | Conforms | 160-bit secret, HMAC-SHA1 (`totp.go:48-51`); SHA-1 inside HMAC is approved by SP 800-131A. Reasoned in the RFC 6238 section above |
| Time nonce changes at least every two minutes | Conforms | 30 s step |
| Keys protected by access controls limited to the components that need them (§3.1.4.2) | Conforms | The secret is sealed inside the accounts document before any backend stores it (`persist.Encrypt`), so only a process holding the application's key reads it; `OpenStore` refuses a backend that would hold it in the clear unless the application accepts that (#50, ADR-0005). ASVS 13.3.1 |
| Approved key establishment at binding | Conforms | The secret reaches the authenticator app in the enrolment URI over the application's TLS, once, and is confirmed before activation (`ConfirmTOTP`) |
| Collected over an authenticated protected channel | Application | TLS is the application's |
| Accepted only once while valid (replay resistance, §3.2.7) | Conforms | `TOTPLastCounter`, advanced under the same lock as the check (`totp.go:487-491`); the enrolment code cannot also sign in, since its counter is stored as used (`totp.go:431`, `enrolhold.go:315`) |
| Defined lifetime from clock drift plus entry delay | Conforms, and the ASVS 6.5.5 deviation | One step either side of now, never two (`totp.go:64`, `TestVerifyTOTPRejectsTwoStepsAway`): the drift allowance NIST describes, and the 90 s ASVS counts against |
| Failed tries limited when a code is short enough to be guessed (under 64 bits; SHALL, §3.2.2) | Conforms | 6 digits; shares the account budget, so at most 50 consecutive guesses before sign-in is disabled (#44) |
| Warn on a duplicate OTP (MAY) | Not done | A replay is refused without telling the subscriber; it is recorded as `user.login_failed` (`factor_refused`) with the address, and as a row of the sign-in history (#45, #53) |

### Cryptographic authenticators: passkeys (§3.1.6, §3.1.7, §3.2.5, Appendix B)

| Requirement | Status | Evidence |
|---|---|---|
| Challenge nonce at least 64 bits, statistically unique | Conforms | 32-byte library challenge, spent once (`passkey/challenges.go`, ADR-0004 decision 5) |
| Public keys protected against modification | Conforms | Trusted accounts store (trust boundary section); AEAD-tagged on every backend opened through `persist.Encrypt` (#50) |
| Key and algorithm at least 112 bits; approved verification | Conforms | The signature algorithms go-webauthn v0.18.2 accepts by default (ES256, RS256 and others from the standard WebAuthn list), left as the library ships them; a browser-made passkey uses P-256 |
| Phishing resistance by verifier name binding (§3.2.5.2); at least one phishing-resistant option offered at AAL2 (SHALL) | Conforms where wired | A passkey works only on the website address it was made for (WebAuthn binds the credential to the relying-party id, taken from the application's public URL, never the `Host` header; ADR-0004 decision 4), so a look-alike site cannot use it. NIST requires that such an option be offered. An application that leaves `Deps.Passkeys` nil offers none; that is its own call. Gauntlet goes further for admins: where the application requires it (`gate.Config.AdminPasskey`, #82, ADR-0015), every admin must hold a passkey, beyond the SHALL's "offered". Admins come first, as CISA's phishing-resistant MFA guidance asks; the step-up before granting admin accepts the passkey too |
| Authentication intent (§3.2.8) | Conforms | The person must act on the sign-in (touch the key or approve on the device): user presence is always required (`passkey/relyingparty.go:79-80`). TOTP and recovery codes are typed by hand |
| User verification (UV: the PIN or fingerprint check on the passkey's device) preferred and inspected; treat an unverified passkey as single-factor (App. B) | Conforms | UV is asked for, and the flags the device signs are stored (`passkey/relyingparty.go:113`, `passkey/ceremony.go`). Behind a password: UV is preferred, not required, and the passkey counts as possession only, whatever UV says. On its own (#77, ADR-0012): UV is required -- in the sealed ceremony, in `FinishSignIn`'s read of the signed flag and again in gate (`PasskeyAssertion.UserVerified`) -- so an unverified passkey never signs in alone |
| Backup-eligible and backup-state flags available to policy (MAY) | Conforms | Flags saying whether a passkey can be, and is, backed up (synced) to other devices are stored on `Passkey.Flags`; no rule reads them, which Appendix B says is right for public-facing use |
| Sign counter checked | Conforms | Library clone warning and `RecordPasskeyAssertionIfFresh` under the store lock; audited as `account.passkey_clone_suspected` |
| Non-exportable keys | Not claimed | AAL3 only; synced passkeys accepted (Appendix B permits them at AAL2) |

### Rate limiting (§3.2.2)

| Requirement | Status | Evidence |
|---|---|---|
| Limit failed attempts on a subscriber account (SHALL) | Conforms | Per-account counter keyed by account id, never evicted; lockout and the count of lockouts written to `User.LoginLockedUntil` and `User.LoginLockoutCount` so a restart does not lift them (`LoginLimiter.ReserveAccount`, `docs/design.md` §1.3). Address counter alongside, and an address ban after 100 failures from one address (#70) |
| No more than 100 consecutive failures per authenticator, then disable it until rebound (SHALL) | Conforms, lower and wider | NIST allows at most 100 wrong tries in a row per authenticator, after which it must be blocked. Gauntlet is stricter: 50 wrong tries in a row (`MaxConsecutiveLoginFailures`), counting password and second-factor steps together, switch off the whole account's local sign-in (`User.LoginDisabledAt`), not one authenticator (owner, 2026-10-02). Lockouts before that escalate, capped at an hour, so the fiftieth arrives after about 8 hours. Only a completed sign-in or a new password resets the count (#44). The disable ends in one of four ways, listed after this table |
| Disregard earlier failures after a success (SHOULD) | Conforms | After a completed sign-in the wrong-try count and the lockout history are cleared (`LoginLimiter.SignedIn`; `gate/login_handler.go`, `completeLogin`). A correct password on its own gives back only that one attempt (`ReleaseAccount`), because the second factor is still to come |
| Increasing delays (MAY) | Conforms | Each lockout three times the last, from one limiter window up to an hour: 5, 15, 45, 60 minutes with a five-minute window (#44, #70) |
| Risk signals (MAY): a known browser | Conforms | A browser that has completed a sign-in on the account keeps the limiter's attempts per window during a lockout; it is refused once the account is disabled, and its failures count toward that (`knownbrowser.go`, #44). It holds a 32-byte token whose SHA-256 is on the account: at most 3 per account, each kept 45 days from its latest sign-in, one token per account in the cookie since #55 |
| Risk signals (MAY): an unusual sign-in | Conforms | Judged after a sign-in's credentials pass, before any session: a new browser, a new country, or a distance from the last sign-in too far to have travelled, each raised only against something the account already remembers (`gauntlet.Store.JudgeSignIn`, #55). `gate.Config.UnusualSignIns` sets what each does; the four settings are listed after this table. An optional `Decide` function can overrule the settings per sign-in (ADR-0009). A lone admin who is blocked gets a one-time escape code in the server log, to be used in the refused browser (ADR-0011, #66); only someone with access to the server can read it, so access to the host, not the address, lets that one attempt through |
| Risk signals (MAY): the client address | Conforms | At the limiter it feeds the per-address limit and, since #70, the address ban, which a known browser passes. It also feeds the new-country and impossible-travel signals above (`gate.Config.Country`, `gate.Config.Locate`) |
| Bot challenges (MAY) | Not done | None |
| Password and second factor both throttled when both are tried | Conforms | One budget for the password step and the code step (`gate/login_handler.go:231`, `:412`); the signed-in password re-check has its own (`ReserveRecheck`) |

The disable ends at the first of these:

- 24 hours after it began (#70, owner 2026-10-05).
- An admin unlocks it (`POST /api/auth/users/{id}/unlock`,
  `Store.UnlockLogin`). For an admin's own account, the admin must type
  their password and a current second factor again.
- An admin issues a reset code.
- No other admin can do it, so the lone admin types the one-time unlock
  code written to the server's log at startup. This lifts only the
  disable (`unlockcode.go`, `POST /api/auth/unlock`).

The four `gate.Config.UnusualSignIns` settings:

- `flag`: marks the session and the sign-in history.
- `confirm`: holds the sign-in for a code sent to the person.
- `prove`: holds it for a passkey on the same account, which a look-alike
  page cannot capture. For an account with no passkey usable here it
  falls back to `confirm`, else `block` (#65).
- `block`: refuses it.

### Binding, recovery and invalidation (§4)

| Requirement | Status | Evidence |
|---|---|---|
| Record of every bound authenticator with event times (§4.1) | Conforms | `TOTPConfirmedAt`, `Passkey.CreatedAt` and `LastUsedAt`, `PasswordChangedAt`. Recovery codes carry no issue time (`GenerateRecoveryCodes` ignores `now`); the audit record `account.recovery_codes_regenerated` holds it. Every binding's audit record carries the source address (`from=`, SHOULD; #45) |
| Binding an additional authenticator needs authentication at the account's current AAL (§4.1.2.1) | Conforms | TOTP enrol and passkey registration need the session and the password again (`gate/totp_handler.go:72`, `gate/passkey_handler.go:190`); a first factor is enrolled behind the AAL1 session the forced-enrolment door allows, which §4.1.2.1 permits when the account "currently has only AAL1" |
| Tell the account's owner (NIST's "subscriber") about changes, separately from the change itself (§4.1.2.1, §4.2.3, §4.6) | Conforms | Gauntlet stores no contact addresses and sends no email or messages itself; the application does, through two hooks, described after this table. Each event is also an audit record, which the operator reads regardless |
| Encourage two means of authentication (SHOULD) | Conforms | Recovery codes are minted with the first second factor; TOTP and passkeys coexist |
| Account recovery: an application-specific method is allowed if risk-assessed and documented (§4.2.1) | Conforms, documented here | The method is an admin-issued reset code read out in person or on a trusted call (`resetcode.go` header). It replaces the password only; the second factor is still demanded (`gate/login_handler.go:284`), which is §4.2.2.2's "one recovery code plus one bound single-factor authenticator". An admin clearing the second factor as well is NIST's "interaction with a CSP agent" case, where a support person at the credential service provider is involved. Risk: whoever holds admin can take any account; that is already true of the host |
| Issued code validity 24 h, throttled, at least six digits (§4.2.1.2) | Conforms | `ResetCodeTTL` 24 h, 80 bits, single use, Argon2id-hashed, counted by the login limiter |
| Suspend or invalidate a compromised authenticator promptly (§4.3, §4.5); backup authenticator for reporting loss | Conforms | Self-service `ClearTOTP`, `DeletePasskey`, recovery codes; admin clear routes; `DELETE /api/auth/users/{id}` revokes the API tokens the account created (`Store.DeleteUser` alone does not; ASVS 7.4.2) |
| Expiry handling (§4.4) | Conforms | Only reset codes expire; an expired one is refused like a wrong password, and the admin issues another |

The two hooks that let the application tell an account's owner:

- `gate.Config.Notices` (`AccountNotifier`, #73; it replaces
  `Config.Notify` of #53, now deprecated) is told of:
  - a password reset
  - a second factor added or removed
  - recovery codes regenerated
  - a lockout
  - a disable
  - an admin ending all of an account's sessions
  - an unusual sign-in flagged or blocked (#55)
  - a role change (#67, #76)
  - an API token that expires within a week (#74, from
    `Gate.SweepTokens`)
  - an admin allowing an account's next sign-in (#81)
- `gate.Config.DeliverConfirmCode` (#55, #73) hands over an unusual
  sign-in's confirmation code at once, because that code is the
  credential the person is waiting to type, not an after-the-fact
  message.

### Sessions (§5, §2.2.3)

| Requirement | Status | Evidence |
|---|---|---|
| Session secret issued at authentication, at least 64 bits from an approved RBG, erased at logout, bound to one authentication event | Conforms | 128-bit id per login (`id.go`, `session.go:246`); `Revoke` on logout, `RevokeAllForUser` on sign-out-everywhere; a new id after every sign-in |
| Not persistent across restarts (SHOULD) | Conforms | In memory only (`docs/design.md` §1.7); the browser cookie outlives the process but the id it carries does not |
| Cookies: Secure (SHALL), minimal path, HttpOnly, SameSite Lax or Strict, opaque value | Conforms | `gate/cookie.go:65-75`; the ceremony cookies are scoped to their routes |
| Cookie `__Host-` prefix (SHOULD); expire at or soon after the session (SHOULD) | Conforms | `__Host-` + `CookieName` while `SecureCookie` is true; `Max-Age` is the session store's lifetime ceiling, so the browser drops the cookie when the session can no longer be valid (`gate/cookie.go`, #47); ASVS 3.3.3 |
| `Secure` SHALL | Conforms, conditional | `gate.Config.SecureCookie` is the application's to set where TLS terminates; `gate.New` logs one warning when it is left false (#47) |
| CSRF (cross-site request forgery): POST/PUT content carries a session identifier the app (the relying party) verifies (SHALL) | Deviation | Gauntlet uses a custom header on every unsafe method plus `SameSite=Lax` (`gate/protect.go:171-186`), the defence OWASP's cheat sheet lists as equivalent; a per-request token would mean a second cookie or body field for both frontends |
| Timeouts: AAL2 overall SHOULD be at most 24 h, inactivity at most 1 h; both SHALL be enforced and documented (§2.2.3, §5.2) | Conforms | Enforced in `SessionStore.Validate` (`session.go:416-437`) and capped by `gate.New`, which refuses a `Deps.Sessions` store configured above `gauntlet.MaxSessionIdle` (1 h) or `gauntlet.MaxSessionLifetime` (24 h), or with no ceiling at all (`gate/config.go:307-319`). Owner decision, 2026-10-02 (gauntlet#51): adopt AAL2's own figures rather than keep mikroview's and birdcage's previous 24 h idle / 7-day ceiling (`docs/design.md` §2.4); both apps must lower their configured values or fail to start. |
| Activity resets the inactivity timeout; reauthentication resets both | Conforms | Sliding `ExpiresAt` capped at the ceiling; a fresh login is a fresh session |
| After an idle timeout but before the overall time limit, NIST lets the app accept just the password together with the old session (MAY, §2.2.3) | Adopted (#71, owner 2026-10-05) | `POST /api/auth/reauthenticate` needs the timed-out session's cookie and the password, through the same limiter reservation as a password sign-in. It issues a new session ID, keeps the original sign-in time (so the 24 h overall limit does not move) and ends the old ID. A wrong password is a failed sign-in. Gauntlet had already adopted both limits; only the way back in was stricter, which pushed operators toward long-lived API tokens in browser tabs |
| A session is never stronger than the event that created it | Conforms | One session type; the second-factor door refuses a session whose local-password account has no factor (`gate/protect.go:496`, always shut since #49) |
| No fallback to an insecure transport | Application | TLS termination |
| Federation: the RP is authoritative on reauthentication (§5.2) | Conforms | Gauntlet's own timeouts apply to an SSO session; the IdP's session is never consulted after the callback |

### Summary of findings

Conforms on everything above. Four deviations are documented: no NFC
normalisation, no pepper, the custom-header CSRF defence, and the TOTP
acceptance window. The common-password list ships with the module
(#52). Gauntlet sends nothing itself (§4.1.2.1, §4.2.3, §4.6). It gives
the application two hooks to tell the owner: `Config.Notices` for every
account change, recovery and invalidation event, including an unusual
sign-in flagged or blocked (#55), and `Config.DeliverConfirmCode` for the
confirmation code, which is itself a credential (#73).
