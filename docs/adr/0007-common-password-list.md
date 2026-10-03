# ADR-0007: The common-password list is built in CI, signed, and refreshed at run time

**Status:** Accepted (the design on #52 and the owner's decisions of
2026-10-02); built without the owner's infrastructure, which is still
to come (see Consequences)
**Date:** 2026-10-02
**Relates to:** #52 (this change), #43 (the password blocklist that
uses it), ADR-0002 (additive API), the central exception "Built-in
common-password hashes in gauntlet" (owner, 2026-10-02)

## Context

#43 refuses common and breached passwords. The owner chose two checks:
the live Have I Been Pwned (HIBP) range API, opt-in per application,
and a built-in list of the SHA-1 hashes of the 10,000 most prevalent
Pwned Passwords, as the fallback when HIBP is unreachable. Shipping a
fixed list needed an exception to the rule against vendoring lookup
datasets; the exception was granted on the condition that the list is
kept fresh, which is this ADR. HIBP places no licence terms on the
Pwned Passwords API; attribution is voluntary.

Finding the 10,000 most prevalent hashes means reading the whole
corpus: 1,048,576 range requests and 20-40 GB per run. The list itself
is about 410 KB.

## Decision

1. **`cmd/pwlist` builds it, standard library only.** `build` walks
   every prefix in order, 256 chunks of 4,096 with 32 requests in
   flight, gzip on, an identifying User-Agent and no padding. Each
   request gets five attempts with jittered backoff (250 ms to 8 s,
   honouring `Retry-After`) on 429, 5xx and network errors; any other
   status or a malformed line ends the run. A 10,000-entry min-heap
   ordered by (count desc, hash asc) keeps the top; it is checkpointed
   after each chunk, and a checkpoint older than 24 hours is ignored.
   Nothing is written unless the run saw at least 500 million hashes
   and the 10,000th was seen at least 1,000 times. The output is
   deterministic: a `# key: value` header (format, source, built,
   count, min-count, total-hashes, attribution) and the hashes sorted,
   without counts.

2. **Three CI jobs on three runners, only for the monthly `blocklist`
   pipeline schedule.** `blocklist:build` (the shared `light` lane,
   4 h) talks to HIBP and holds nothing; `blocklist:sign` (the
   `gauntlet-signing` runner, 5 min) holds the key and talks to nobody;
   `blocklist:publish` (the `gauntlet-publish` runner, 10 min) holds the
   GitLab job token and the GitHub token, and verifies the signature
   against the committed keys before uploading. Monthly (owner,
   2026-10-02), because the 10,000th entry of a billion-hash corpus
   moves only when HIBP ingests a large breach and the live check
   covers the time in between. A pipeline variable,
   `BLOCKLIST_SAMPLE=true`, runs the build alone over 2,048 prefixes
   from any branch and publishes nothing; its output is marked as a
   sample, which nothing will sign or accept.

3. **Published to GitLab first, then to the public GitHub mirror,
   which is where applications fetch it** (owner, 2026-10-02: the
   GitLab project is private). The GitLab generic package registry
   gets package `pwned-top10k` twice per run, version `<YYYY.MM.DD>`
   and `current`. Then `pwlist publish-github` copies the same three
   files to two releases on `tomlawesome/gauntlet`:
   `pwned-top10k-<YYYY.MM.DD>`, never rewritten, and
   `pwned-top10k-current`, whose files are replaced; neither is marked
   the repository's latest release. `blocklist.DefaultURL` is
   `pwned-top10k-current`'s `top10k.txt`; `.sha256` and `.sig` sit
   beside it. The GitHub token can write this repository's releases
   and nothing else, and lives as a file mounted read-only on the
   `gauntlet-publish` runner, never a CI variable; the job is told only
   its path. It runs on its own runner rather than the shared lane so
   no other project's job can read it, and not on the signing runner
   so no one runner holds both the key and a way to publish.

4. **Signed with Ed25519 from `crypto/ed25519`**, not the cosign key
   birdcage's releases use: data and code keys stay separate, and
   verification needs no third-party code. The private key is a
   PKCS#8 PEM file on the signing runner's host under
   `/etc/gauntlet-signing/`, mounted read-only, never a CI variable
   (this GitLab has no environment-scoped variables, so a protected
   variable reaches every protected job). The `.sig` file holds one
   line per key, `<key-id> <base64 signature>`, where key-id is the
   first 16 hex characters of the SHA-256 of the public key; `sign`
   signs with every key it finds. Public keys are
   `blocklist/keys/*.pub`, compiled in. A verifier accepts when at least
   one line is from a trusted key and every trusted line verifies; a
   signature from no trusted key is refused, and with no key committed
   everything is refused. Rotation: commit the new `.pub`, release,
   sign with both keys, and retire the old key a release later.

5. **`package blocklist` makes no network request unless asked.**
   `Embedded()` is the copy compiled into the release. A `Refresher`,
   opt-in, checks the published `.sha256` first (256 bytes at most,
   10 s) and stops if it is unchanged; otherwise it fetches the list
   (1 MiB at most) and signature (4 KiB at most) and adopts the list
   only if the checksum matches, the signature verifies, the format is
   v1 with exactly 10,000 strictly ascending hashes, it is built no
   more than 24 hours ahead, and it is newer than the list in use. It
   checks at start and then daily by default (an hour at least). The
   adopted copy is kept in the application's directory, 0600, written
   atomically, and verified again on the next start. Any failure logs
   one Warn and keeps the current list. #43 wires it in as
   `Options.PasswordBlocklist`, defaulting to `Embedded()`.

6. **The embedded copy is the published files, unchanged.**
   `scripts/update-blocklist.sh` fetches them, verifies them as an
   application would, and copies them into `blocklist/embedded/`, as a
   release step. A test verifies the committed copy against the
   committed keys on every pipeline, and `release:version` refuses to
   tag when the copy is more than 90 days old.

## Alternatives rejected

- **A third-party plaintext list** (SecLists, Django's, the NCSC's):
  unclear origin or licence, and plaintext passwords in the repository.
  The research and the owner's choice are on #43.
- **Weekly runs**: a million requests and tens of gigabytes a week on a
  shared lane for a list that rarely changes. The owner chose monthly.
- **Applications reading the GitLab registry**: it would mean opening
  the private project's package registry to anyone. The owner chose the
  public mirror's releases instead.
- **Signing with cosign or a CI variable**: cosign means third-party
  verification code in every application; a variable means the key
  reaches every protected job.
- **Fetching on every password check**, or having gauntlet refresh on
  its own: an auth library must not make outbound calls an application
  did not ask for.

## Consequences

- **Until the first signed run there is no real list.**
  `blocklist/embedded/` holds a placeholder and `Embedded()` returns an
  empty list that blocks nothing; `blocklist/keys/` is empty, so every
  list is refused; and `release:version` refuses to tag. The first real
  list arrives with the first signed run. The owner's steps are in
  docs/releasing.md, "The common-password list": generate the key and
  commit its public half, create the GitHub token, mount both on the
  runner host, register the `gauntlet-signing` and `gauntlet-publish`
  runners, and create the schedule.
- The GitHub token expires; when it does, the GitHub copy stops
  updating and applications keep the last list they adopted.
- The public key set is part of each release, so a key rotation takes
  two releases, and an application on an old release refreshes only
  while the old key still signs.
- `blocklist` is new exported API under ADR-0002: `List`, `Parse`,
  `Embedded`, `Refresher`, `RefreshConfig`, `NewRefresher`,
  `DefaultURL`, `DefaultRefreshInterval`, `MinRefreshInterval`. The
  signature format is internal (`internal/listsig`).
- Each scheduled run downloads 20-40 GB from HIBP on the `light` lane.

Written from the design on #52, 2026-10-02.
