# ADR-0016: A read-only "still signed in" check for long-lived responses

**Status:** Proposed (owner-adopted specification on #104, 2026-10-10)
**Date:** 2026-10-10
**Relates to:** #104 (this change), #71 (timed-out sessions resume with
the password; `Resumable`), #51 (the AAL2 session caps), #74 (token
expiry and `LastUsedAt`), ADR-0002 (compatibility), mikroview #375
(the websocket re-check this generalises)

## Context

An application that holds one response open for a long time -- birdcage's
`GET /api/stream` (server-sent events), mikroview's `GET /api/ws` (a
websocket) -- is authenticated once, by `Protect`, at the request that
opens it. Sign-out, "sign out everywhere", a password reset or an account
deletion then end the session in the store, and the open stream never
hears. Mikroview fixed this on its own code (#375) by re-running
`sessionUser` at every keepalive tick; birdcage replays the request
through `gate.Protect` every 30 seconds.

Both re-checks go through `SessionStore.Validate`, which is the only
session check the module offers, and `Validate` is also the thing that
slides idle expiry and moves `LastUsedAt`. So a tab left open on a stream
never idles out: it stays signed in up to `MaxSessionLifetime` (a day)
instead of `MaxSessionIdle` (an hour). NIST SP 800-63B §7.2 measures the
idle timeout from the subscriber's inactivity; traffic the application
generates for itself is not activity. `TokenStore.Authenticate` has the
same side effect on a bearer token: it moves `LastUsedAt` and, once an
hour, writes the tokens document.

`Protect` also enforces more than "is the session live": a session issued
before the account's `SessionCutoff`, an unrecognised role, and three
doors (forced password change, the admin passkey rule, forced second-
factor enrolment). A re-check that only asked the session store would
keep a stream open for an account `Protect` had started refusing.

## Decision

Pattern: **one policy decision, two enforcement points** (the decision/
enforcement split of NIST SP 800-162 and XACML: `Protect` and the new
call enforce the same decision function, so a refusal cannot exist in one
and not the other), with **re-validation on the keepalive tick**
(mikroview #375) and **a read-only check beside the touching one** --
the `Peek` of a queue or buffer: look, change nothing.

1. **`SessionStore.Peek`** (root package):

   ```go
   // Peek reports whether id is a live session, as Validate does,
   // without changing anything: the expiry does not slide, LastUsedAt
   // does not move, and nothing is evicted. It applies every rule
   // Validate applies -- unknown, past the lifetime ceiling, idle past
   // its expiry (whether or not still resumable), revoked -- and
   // returns the session as stored. It is the check for traffic the
   // application generates for itself: a stream re-checking the cookie
   // that opened it must not keep the session awake (NIST SP 800-63B
   // §7.2, #104).
   func (s *SessionStore) Peek(id string, now time.Time) (Session, bool)
   ```

   `Peek(id, now)` is true exactly when `Validate(id, now)` would be true
   at the same instant, and the two agree on every refusal. It takes the
   store's mutex for the map read and releases it; it never writes. A
   session past its ceiling is left for `Validate`, `Resumable` or the
   sweep to drop.

2. **`TokenStore.Peek`** (root package):

   ```go
   // Peek reports whether raw is a live token of kind want, as
   // Authenticate does -- same hash lookup, same kind rule, same
   // expiry rule, same reload of a stale document first -- without
   // recording a use: LastUsedAt does not move and the tokens document
   // is not written. The token returned is a copy, as Authenticate's is.
   func (s *TokenStore) Peek(raw string, want TokenKind, now time.Time) (*Token, bool)
   ```

   Reloading a stale document is a read of the backend, not a write, and
   is what lets a revoke made through the CLI end a stream in the
   running server. An unpersisted store holds no tokens and refuses
   everything, as `Authenticate` does.

3. **`(*Gate).StillSignedIn`** (gate package):

   ```go
   // StillSignedIn answers, for a request Protect admitted earlier and
   // whose response is still open, whether Protect would admit it again
   // now: nil while it would, otherwise the refusal Protect would write.
   // It reads the same cookie or Authorization header, applies the same
   // rules in the same order -- the undecided state, the bearer kinds
   // registered with Handle, the CSRF header, Exempt paths, the session,
   // the account, its role, and the three doors, each against the
   // request's own path -- and differs in one way: it touches nothing.
   // The session's expiry does not slide, no LastUsedAt moves, no
   // document is written, nothing is revoked and no log line is left.
   // A stream that calls it on a timer therefore idles out when the
   // person does, not while the tab is open (#104).
   //
   // The clock is Config.Now. r is the request as the handler received
   // it; it is read, never changed, so one request may be checked from
   // the handler's goroutine while other requests are served. A request
   // on an Exempt path is admitted whatever its cookie says, as Protect
   // admits it: a route that must be re-checked must not be exempt.
   func (g *Gate) StillSignedIn(r *http.Request) error
   ```

   ```go
   // Refusal is StillSignedIn's answer when Protect would no longer
   // admit the request. Status and Class are what Protect's response
   // would carry (docs/api/errors.md), so an application can end the
   // stream with the same reason -- a websocket close reason, a last
   // server-sent event -- that the next ordinary request will get.
   type Refusal struct {
       Status int    // 401, 403 or 503
       Class  string // "sign-in-required", "invalid-credentials", "csrf-required", "forbidden", "must-change-password", "must-enrol-passkey", "must-enrol-factor", "setup-required"
   }
   func (e *Refusal) Error() string // "gate: no longer admitted: 403 must-enrol-factor"
   ```

   An error rather than a bool, because the apps can use the reason (a
   close frame's text, the frontend's choice between "reconnect" and
   "go to the door") and because returning Protect's own refusal value
   is what makes the parity checkable: the two cannot drift, since there
   is only one place that decides. `nil` is the whole of "carry on";
   nothing else is returned, because the stream already holds its
   principal from `UserFromContext`/`TokenFromContext`.

4. **One decision function.** `Protect`'s body is split into a
   decision, `decide(r, now, touch bool) (verdict, *refusal)`, and the
   writing of its result. `Protect` calls it with `touch` true and
   writes the response (and the rated Warn line, and the
   `WWW-Authenticate` or `X-Auth-Gate` header) from the returned
   refusal; `StillSignedIn` calls it with `touch` false and returns the
   refusal's status and class. With `touch` false the session path uses
   `SessionStore.Peek` instead of `Validate`, the bearer path uses
   `TokenStore.Peek` instead of `Authenticate`, and the proactive
   `Revoke` of a session issued before `SessionCutoff` is skipped (the
   session is refused all the same; the next real request revokes it).
   Nothing else differs between the two modes, by construction.

5. **The refusal list.** Each line is a refusal `Protect` has today, in
   the order it checks them; `StillSignedIn` returns the same.

   | Condition | Protect answers | `Refusal{Status, Class}` |
   |---|---|---|
   | No account exists yet and the path is not bootstrap-exempt | 503 | `503 setup-required` |
   | Bearer token matches no registered kind: revoked, expired, unknown, wrong kind, no `Handle` for its kind | 401 | `401 invalid-credentials` |
   | `Authorization` header present but not `Bearer <token>` | 401 | `401 invalid-credentials` |
   | Unsafe method without the CSRF header | 403 | `403 csrf-required` |
   | No cookie; session unknown, revoked, idle past `MaxSessionIdle` (resumable or not), past `MaxSessionLifetime`; account deleted; session issued before `SessionCutoff` | 401 | `401 sign-in-required` |
   | Role not one of admin, user, viewer | 403 | `403 forbidden` |
   | `MustChangePassword` on a local-password account, path is not `/api/auth/password` | 403 + `X-Auth-Gate` | `403 must-change-password` |
   | Admin with no local password while `AdminPasskeyRequired`, path is not `/api/auth/password` | 403 + `X-Auth-Gate` | `403 must-change-password` |
   | Admin held at the passkey door, path not an enrolment route | 403 + `X-Auth-Gate` | `403 must-enrol-passkey` |
   | Local-password account with no second factor, path not an enrolment route | 403 + `X-Auth-Gate` | `403 must-enrol-factor` |

   A bearer token whose creating account is gone is not a separate line:
   deleting an account revokes its tokens in the same request
   (`RevokeAllCreatedBy`, users_handler.go), so the token is simply
   gone; one orphaned outside the server (a deleted document entry, a
   CLI delete) is refused once the daily `SweepTokens` removes it, for
   `Protect` and `StillSignedIn` alike. That is today's rule
   (gate/tokens_expiry_test.go pins it) and this change keeps it.

Settled without a question:

- **Go API, additive.** Two methods on existing root types, one method
  and one type in `gate`. No route, no response field, no document
  change; `apidiff` passes, the OpenAPI document and errors.md are
  unchanged. `Validate` and `Authenticate` keep their meaning: real
  requests still slide the session, as they should.
- **No logging from `StillSignedIn`.** A sign-out would otherwise leave
  one rated Warn line per open tab; the next ordinary request from that
  tab logs through `Protect` as before.
- **The call is the application's to make.** `gate` runs no timer and
  knows nothing about the stream; the application calls `StillSignedIn`
  from its own keepalive tick (mikroview's ping, birdcage's 30-second
  replay) and ends the response on a refusal. docs/using.md gains a
  "Long-lived responses" section with that loop.
- **`GET /api/auth/session` is unchanged.** A page load is the person's
  own activity; it may keep sliding the session.

## Rejected options

- **A bool.** Cheaper to read, but the apps lose the reason, and parity
  with `Protect` would rest on a test rather than on the code's shape.
- **A separate rule list in `StillSignedIn`.** The next door added to
  `Protect` would be missing here until someone remembered; the shared
  decision function makes that impossible.
- **Push revocation into open streams** (the store notifies the hub).
  Mikroview rejected it for #375: a second, push-driven copy of every
  invalidation rule, and it still misses idle expiry and the doors.
- **A `Validate` option to not slide** (`ValidateOptions`, a `touch`
  argument). Changes a shipped signature or adds a second way to call
  the same method; two names for two behaviours read better.
- **Skipping the CSRF and exemption steps in `StillSignedIn`.** Would
  make it a different decision from `Protect`'s; the steps cost nothing
  on a request that already passed them.
- **Refusing a token whose owner is gone at request time.** A behaviour
  change to `Protect` under ADR-0002 (and an existing test), and the
  delete route already revokes those tokens; the sweep covers the rest.

## Consequences

- A stream re-checked every 30 seconds now ends about an hour after the
  person's last real request, instead of after a day; the frontend's
  existing reconnect lands on 401 and the sign-in page, or on
  `Resumable: true` for the password-only resume (#71), since an idle
  `Peek` leaves the session resumable.
- `Protect`'s body is restructured but its responses, headers and log
  lines are unchanged; the existing gate test suite is the proof, and
  the contract tests still pass over the same routes.
- Mikroview's `ws.go` can replace its `sessionUser` tick with
  `StillSignedIn` when it moves onto gauntlet (mikroview #1202);
  birdcage replaces its `Protect` replay (its own issue, to be filed by
  birdcage).
- `Peek` leaves a dead session in the map until `Validate`, `Resumable`
  or the sweep reaches it; the sweep already bounds that (#24).

## Build notes

For the agent writing the tests from this document alone, and the agent
implementing it afterwards. The order is the global one: tests first,
run and recorded failing, then the code.

### Test cases

Root package (`session_test.go`, `token_test.go`; clock is a plain
`time.Time` advanced by hand; `NewSessionStore(idle, ceiling)`):

- `Peek` on a fresh session is true and returns `ExpiresAt`,
  `LastUsedAt`, `IssuedAt` exactly as `Create` set them.
- `Peek` every few seconds for longer than `idle` (for example
  `idle=10s`, checked every 2s for 30s) is true until `now` passes
  `IssuedAt+idle` and false from then on; afterwards `Validate` is also
  false and, with a ceiling, `Resumable` is still true.
- A session `Peek`ed many times has the same `ExpiresAt` and
  `LastUsedAt` as before (read back with another `Peek`, or
  `ListForUser`). A `Validate` after those peeks slides it as usual.
- `Peek` is false for an unknown id, a revoked id, a session past the
  ceiling (even if used a moment ago), and a session idle past `idle`
  in a store with no ceiling.
- `Peek` and `Validate` agree: for each state above, the two booleans
  match at the same `now`.
- `TokenStore.Peek`: true for a live token of its kind; false for the
  wrong kind, an expired token, a revoked token, an unknown value, an
  empty value, an unregistered kind, and on an unpersisted store.
- `TokenStore.Peek` leaves `LastUsedAt` as it was (read with `List`),
  and makes no save: a `persist.Memory` backend wrapped to count `Save`
  calls records none. `Authenticate` afterwards still records a use.
- `TokenStore.Peek` sees a revoke made through a second store opened on
  the same backend (the stale-document reload).

Gate package (in-package tests; `newTestGate`, `registerAdmin`,
`newBrowser` and `openStoreWithUsers` in the existing test files are the
fixtures; `Config.Now` is the clock; a handler that calls
`g.StillSignedIn(r)` and writes the result is the "stream"):

- Signed in, re-checked every 5s with the clock advancing, no other
  request: nil until `MaxSessionIdle` has passed since sign-in, then
  `*Refusal{401, "sign-in-required"}`; `GET /api/auth/session` then
  reports `resumable: true`.
- Signed in, one real request through `Protect` every 10 minutes while
  the stream re-checks every 5s: nil for the whole hour, then nil until
  `MaxSessionLifetime`, then `401 sign-in-required`.
- A check never extends: after N checks the session's expiry, read
  through `GET /api/auth/sessions` (`lastUsedAt`), is unchanged.
- Each row of the refusal table, driven as a real condition, returns
  that `Status` and `Class`, and the same request through `Protect`
  answers the same status and class body at that moment:
  logout; `Sessions.Revoke`; "sign out everywhere"; account deleted;
  password changed in another browser (the cutoff); unrecognised role
  (`openStoreWithUsers`); `MustChangePassword` set; admin with no local
  password under `AdminPasskeyRequired`; admin without a usable passkey
  under the rule; local account with no second factor; the stream path
  being an enrolment route or `/api/auth/password` is admitted at the
  matching door; bearer token revoked, expired, of an unregistered kind,
  malformed header; no cookie at all; a POST stream without the CSRF
  header; all accounts gone (via the store directly, if reachable);
  an `Exempt` path with a dead cookie is nil.
- Bearer: a live token on its kind's handler is nil, and `List` shows
  `LastUsedAt` unchanged by the checks.
- `Refusal.Error()` names the status and class; `errors.As` recovers
  `*Refusal` from the returned error.
- Race: one request checked from several goroutines while `Protect`
  serves others, under `-race`.
- No log line: a refusal from `StillSignedIn` leaves nothing in
  `Config.Log`.

### Implementation

- `session.go`: `Peek` beside `Validate`; share `gone`/`expired`.
- `token.go`: split `Authenticate` into the lookup (`lookupLocked(hash,
  want, now)`) and the use-recording tail; `Peek` is the lookup alone.
- `gate/protect.go`: extract `decide(r, now, touch)` returning
  `(verdict{user, token, kind}, *refusal{status, class, detail, door,
  warnKind, warnMsg})`; `Protect` becomes decide-then-write-or-dispatch;
  `sessionUser` gains the `touch` flag (its two other callers,
  `handleSession` and `cookie.go`, keep `true`). Add `StillSignedIn`
  and `Refusal` in a new `gate/stillsignedin.go`.
- `docs/using.md`: "Long-lived responses" under "Build the HTTP layer",
  with the tick loop, the `errors.As` on `*gate.Refusal`, and the
  sentence that the check never keeps a session awake.
  `docs/design.md` §1.5's Go-surface list gains the three lines.
  `CHANGELOG.md` Unreleased: Added.
- Coverage floors, `apidiff`, `gofmt`, `golangci-lint` as AGENTS.md
  lists; no new dependency.
