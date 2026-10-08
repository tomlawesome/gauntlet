# ADR-0006: Sign-in history: a third sealed document, bounded and folded

**Status:** Accepted (owner decisions 2026-10-02 on #53)
**Date:** 2026-10-02
**Relates to:** #53 (this change), #45 (the sign-in audit records it
builds on), ADR-0002 (stored-document versions), ADR-0005 (sealing
every backend), ADR-0001 (`persist.Backend` is the application's)

## Context

Admins asked to see sign-in activity across accounts: when, which
account or name, how it ended, from which address and browser (#53).
#45 already writes every attempt to the application's audit sink, but
that sink is the application's own and gate cannot read it back to
show a page. The owner first asked for the history to be kept
permanently, then settled on the newest 10,000 rows by default, which
an application may raise.

What makes this harder than a list in memory: anyone can make sign-in
attempts, as fast as the login limiter lets them, from as many
addresses as they hold. A design that wrote one stored row per attempt
would let a stranger turn a password spray into a stream of writes and
a document that grows without end. And the name an attempt typed is
often a password typed into the wrong box.

Measured with `persist.Encrypt` over realistic rows: a row is about
340 bytes of JSON typically and 645 at worst (64-byte address, 256-byte
browser string, 64-character name).

| rows | JSON typical / worst | in a text column (base64) | encode + seal + save | load + decode |
|---|---|---|---|---|
| 10,000 | 3.4 / 6.5 MB | 4.5 / 8.6 MB | ~50 / ~95 ms | 60 / 90 ms |
| 20,000 | 6.8 / 12.9 MB | 9.1 / 17.2 MB | ~125 / ~200 ms | 110 / 175 ms |
| 100,000 | 34 / 65 MB | 45 / 86 MB | ~540 ms / ~1 s | 530 ms / 1.1 s |

`BenchmarkSignInHistorySave` (`signins_test.go`) measures one save of a
full, worst-case history at the default cap at about 60 ms on the
development host, in line with the table.

## Decision

1. **A third sealed document, never the accounts document.** The
   history is its own document, `signins`, beside `accounts` and
   `tokens`: its own `persist.Backend`, its own `persist.Encrypt` label
   `"signins"`, version 1 (`signInsDocumentVersion`):
   `{"version":1,"nextSeq":n,"rows":[...]}`. The application supplies
   the backend and the key as it does for the other two; birdcage adds
   the name `signins` to its `auth_store` table. `OpenSignInHistory`
   opens it under the accounts store's rules: an unreadable document,
   a sealed one reaching it unwrapped, and one newer than the build are
   refused, and so is a plaintext backend unless the application sets
   `AllowPlaintextAtRest`, since every row carries an address and a
   browser. A nil backend keeps it in memory, for tests and
   development.
2. **Bounded by a row cap.** The newest `MaxRows` rows are kept,
   oldest dropped first: 10,000 by default (`DefaultMaxSignInRows`),
   at most 50,000 (`MaxSignInRows`). Each save writes the whole
   document, so the cap is also what bounds one save. `Summary` reports
   how many rows are held and when the oldest began, so an admin sees
   how far back the history goes.
3. **Folded and budgeted, so a flood is a bounded number of rows.** In
   `Record`, in this order: an attempt with the same outcome, method,
   account (or masked name) and address as a row that began within 10
   minutes folds into it -- `count` up, `until` moved, nothing else; a
   failed attempt may start at most 100 new rows per 10-minute bucket,
   the rest folding into that bucket's one `unrecorded` row, which
   carries only a count and times; then the cap. A success, or a
   password step that passed, is never budgeted: only someone holding
   the credential can make one. An attempt that started a lockout or
   disabled sign-in is neither folded nor budgeted, because the lockout
   is what its row shows and the limiter bounds how often one starts.
   100,000 made-up names from many addresses in ten minutes are 101
   rows.
4. **Writes decoupled from attempts, and outside the lock.** `Record`
   changes memory and nudges one writer goroutine, started by
   `OpenSignInHistory` and stopped by `Close`. The writer saves no
   sooner than 5 s after its last save while a new row is unsaved, and
   no sooner than 60 s while only counts changed: a flood is at most
   one save per 5 s while the row budget is spent and one a minute
   after. The rows are copied under the lock; the encode, the seal and
   the write happen without it, one save at a time, so a save never
   holds up a sign-in. `Flush` saves at once; `Close` flushes once. A
   crash loses at most the last 5 s of rows or 60 s of counts; the
   audit sink (#45) has every attempt regardless.
5. **One writer per document.** A running server owns its history, as
   it owns its sessions; there is no reload of another process's
   writes. If two writers do meet, the save that finds the document
   changed reloads it through the shared replay loop (`mutate.go`) and
   re-appends the rows it added since its last save, renumbered; count
   bumps it made to rows already saved are lost in that one case. A
   removed document keeps the history in memory and is logged once
   until a save succeeds.
6. **The typed name is never stored.** A name that matched no account
   is masked before it is stored, audited or logged
   (`MaskUnknownUsername`): its first two characters and one `•` per
   further character, except a fixed list of probe names (root, admin,
   postgres and the like) kept in full (owner, 2026-10-02). A name that
   matched an account is stored as the account's username.
7. **Read by admins through gate.** `gate.Deps.SignIns` receives every
   attempt `recordSignIn` sees; `GET /api/auth/sign-ins`, admin only,
   pages through it newest first, filtered by account, address and
   outcome. With no history configured the route answers 404.

## Rejected: add-only storage

An add-only or segmented store -- append each row, rotate segments --
would make a save cost one row rather than the whole document, and so
allow a far larger history. It needs a new backend interface every
application implements (the file, birdcage's `auth_store`,
mikroview's `store_blob`), segment rotation, crash consistency across
segments, sealing per segment, and amendments to ADR-0002 and
ADR-0005: roughly 1,500 to 2,500 lines, with the risk in the least
testable part. With the save outside the lock, the cap no longer
affects sign-ins, and under a sustained spray the row budget alone
holds the history to about 14,400 rows a day, so 10,000 rows cover
about 17 hours of the worst case and months on a quiet site. Raising
the default later is a one-line compatible change; lowering it drops
rows (owner, 2026-10-02).

## Consequences

- Applications that want the history open a third backend with its
  own label and pass it as `gate.Deps.SignIns`; one that does not keeps
  working, with the route answering 404 and the audit unchanged.
- A history over 10,000 rows is a few megabytes in the application's
  storage, rewritten at most every 5 s during a flood; at 50,000 rows a
  worst-case save is about half a second, outside the lock.
- An older build cannot open a `signins` document of a later version
  (ADR-0002); version 1 is this release's.
- In-session re-checks are audited (#45) but are not rows: the caller
  already holds a session, and the history is of sign-ins.
- Status note (v0.3.0 audit, 2026-10-08): the `signins` document is version 3, not 1
  (decision 1 and the consequence above): ADR-0008 added the country
  (version 2) and ADR-0009 the unusual-sign-in signals and the
  confirmed flag (version 3).
- Status note (v0.3.0 audit, 2026-10-08): decision 3's fold key also includes the
  unusual-sign-in signals and the confirmed flag (ADR-0009), and the
  failed-attempt budget also exempts a refused sign-in, a confirmation
  code sent and an escape code issued, not only a success or a passed
  password step.
- Status note (v0.3.0 audit, 2026-10-08): decision 7's `GET /api/auth/sign-ins` also
  takes `unusual=true` (rows that raised a signal, ADR-0009), `before`
  and `limit`.
