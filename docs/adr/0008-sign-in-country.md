# ADR-0008: Sign-in country: recorded at sign-in from a local file the operator's chosen provider supplies

**Status:** Accepted (owner decisions 2026-10-04 on #54)
**Date:** 2026-10-04
**Relates to:** #54 (this change), #53 and ADR-0006 (the sign-in
history it adds to), #48 (a person's own session list), #55 (unusual
sign-ins, which builds on the stored country), ADR-0002 (stored-document
versions, additive API), mikroview #1352 (the code `geoip` is ported
from)

## Context

#54 adds the country a sign-in came from to the admin sign-in history
(#53) and to a person's own session list (#48). An address alone means
little to most people; a country is easier to recognise as not theirs. #55, which will flag unusual
sign-ins, needs the same country, as it was when the sign-in happened.

Mikroview already shows countries. Its `internal/geoip` downloads a
country file from one of three providers, keeps it on disk and looks up
addresses locally, so no address leaves the operator's server.

Two things differ for a library. Gauntlet has no web page of its own on
which to credit a data provider, and it has no settings store in which
to keep a provider's key. Both providers that need a key ask the
application to credit them; DB-IP, mikroview's keyless default, asks for
a credit on the page that shows its data, which only the application can
place.

## Decision

1. **Looked up once, when the sign-in is recorded.** Every sign-in
   history row and every session gains `country`: an ISO 3166-1
   alpha-2 code such as `GB`, or nothing. Nothing means "not known",
   never an error: a private address, no file loaded yet, or no entry
   in the file. The code is stored on the row and the session, not
   looked up again when shown, so a row never changes meaning when the
   file changes and #55 sees the country the address had at the time. A
   row recorded with no file loaded stays blank; there is no backfill.
   The flag or the name shown for a code is the application's job.
2. **A leaf package behind one optional function.** The new package
   `geoip` is the only importer of
   `github.com/oschwald/maxminddb-golang/v2` (v2.6.0). Gate sees one
   optional field, `gate.Config.Country func(address string) (code
   string, ok bool)`, and the application passes
   `(*geoip.Manager).Country`. Nil means no country is ever recorded.
   Neither `gate` nor the root package names `geoip`, and CI checks
   that neither links the reader. `SessionClient` and `SignInRow` gain
   `Country`, and the sign-in history document goes from version 1 to
   2 for the added field (ADR-0002 decision 1): an older build refuses
   a version 2 document, and a version 1 document loads with blank
   countries.
3. **One source, chosen by the operator, keys kept by the
   application.** The operator chooses MaxMind GeoLite2-Country
   (account ID and licence key) or IPinfo Lite (token). There is no
   default and no fallback from one to the other. The keys arrive in
   `geoip.Config` as plain strings; where they are kept is the
   application's job, as the encryption key is (design §1.7). Gauntlet
   does not store, seal or show them, and no error, log line or
   `Status` field carries one. IPinfo's token travels in the download
   URL, so the URL's query is removed from every message made from a
   request. `New` refuses an unknown source, an empty key, a key with
   whitespace or non-ASCII characters, a key over 256 characters, and a
   MaxMind account ID with a colon (it would break basic auth).
4. **Downloaded, checked, kept and refreshed like the common-password
   list.** The last good file is kept in `Config.Dir` as
   `<source>.mmdb` (0600) with a small `state.json`, and `New` loads it
   before any network request, so lookups work from the first sign-in
   after a restart. `Run` checks at start and then daily, give or take
   a tenth, with a conditional request where the provider answers one.
   A download replaces the file in use only after it opens as a
   database and a lookup of a documentation address succeeds in it. A
   failed check keeps the file in use and retries in an hour; a key the
   provider refuses (401 or 403) is retried in a day. A file older
   than 45 days is still used, with a warning on every check. The
   default client gives a download two minutes and 128 MiB, follows
   https redirects only, and will not connect to a private, loopback,
   link-local, unspecified or reserved address, redirects included.
   The file is the provider's public data, so applications leave it out
   of backups.
5. **Only public addresses are looked up, and only a country is
   read.** An address is parsed, an IPv4-mapped address is read as its
   IPv4 host, and a private, loopback, link-local, unspecified or
   reserved address is not looked up. Records are read by path, trying
   IPinfo's flat `country_code` and then MaxMind's `country.iso_code`,
   so either layout works from either provider. Only an upper-case
   two-letter code is ever returned. IPinfo's network-owner fields are
   not read.

## Rejected options

- **Looking the country up when the history is shown.** It would need
  no stored field, but a row would change meaning whenever the file
  changed, a row from before a file was loaded would gain a country it
  never had, and #55 needs the country at the time of the sign-in.
- **A precedence list with a keyless default**, as mikroview has
  (IPinfo, then MaxMind, then DB-IP with no key). DB-IP's licence asks
  for a credit on the page that shows its data; a library cannot place
  it, and an answer quietly taken from an uncredited source would break
  the licence (owner, 2026-10-04: DB-IP excluded). With DB-IP gone, a
  precedence between the two keyed sources adds switching and two sets
  of credits for no gain.
- **Gauntlet storing or sealing the keys**, as mikroview's settings do.
  It would need a key store, a way to enter keys and a sealing key in a
  library that has none of these; the application already keeps
  secrets of its own, the encryption key among them.
- **A path to a `.mmdb` the operator mounts themselves.** Mikroview
  had this and retired it in #1352 in favour of fetching the file
  itself. It would leave each operator to find a file, accept its
  licence and keep it current by hand, and a file nobody refreshes
  goes stale without anyone being told.

## Consequences

- An application that wants countries imports `geoip`, takes the
  operator's choice of source and key, runs a `Manager`, passes its
  `Country` to `gate.Config.Country`, and credits the provider where it
  shows the data ([docs/geoip.md](../geoip.md)). One that does not is
  unchanged and records no country.
- The admin sign-in history and the session list gain an optional
  `country` field (docs/api/auth.yaml); the change is additive.
- An older build cannot open a version 2 sign-in history document.
- The process makes one conditional request a day to the chosen
  provider, and holds that provider's country file on disk and in
  memory (a few to tens of megabytes).
- A sign-in recorded while no file is loaded, or while the provider is
  unreachable on a first start, has no country, and keeps none.
