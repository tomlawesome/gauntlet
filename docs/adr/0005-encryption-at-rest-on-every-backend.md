# ADR-0005: The accounts document is sealed before any backend stores it

**Status:** Accepted (owner assigned design and build 2026-10-02 on #50)
**Date:** 2026-10-02
**Relates to:** #50 (this change), #18 (the encrypted file backend),
#33/#34 (the ASVS and SP 800-63B reviews that found it), ADR-0001
(`persist.Backend` is the application's), ADR-0002 (compatibility
promise), mikroview #1202

## Context

The accounts document holds every account's TOTP secret in the clear.
It has to: verifying a 30-second code means recomputing HMAC-SHA1 over
the secret, not comparing a hash (`user.go`, `TOTPSecret`). It also
holds each passkey's public key and the Argon2id password hashes. Until
now only `persist.EncryptedFileBackend` (#18) sealed the document; the
backends the applications actually run on -- mikroview's Postgres
`store_blob`, birdcage's planned `auth_store` table -- stored it as
plaintext JSON, so a database dump or a backup carried every operator's
TOTP seed. SP 800-63B-4 §3.1.4.2 says OTP keys SHALL be protected by
access controls limiting them to the components that need them; ASVS
5.0 13.3.1 (L2) wants secrets in a secrets store, not in application
data. Both were recorded as deviations.

Constraints: a backend stays the application's own code (ADR-0001:
"the module never owns a database"); reading the key file stays the
application's job (`docs/design.md` §1.7); no new dependency; the
exported Go API may only grow (ADR-0002); mikroview's existing
encrypted files must keep opening byte-for-byte; mikroview's
`store_blob.payload` is a Postgres `text` column, and birdcage's design
says `TEXT` too.

## Decision

1. **Whole document, below the store.** `persist.Encrypt(backend, key,
   opts)` wraps any `persist.Backend` so every `Save` seals the payload
   and every `Load` opens it: the same AES-256-GCM envelope
   `EncryptedFileBackend` has used since #18 (HKDF-SHA256 from the
   application's key with a fresh 16-byte salt and 96-bit nonce per
   save), now in `persist/seal.go` as the one place that turns key
   material into ciphertext. `EncryptedFileBackend` is that wrapper
   over the plain file backend. Sealing the whole document rather than
   the secret fields alone gives integrity as well as confidentiality:
   a document altered in the database -- a swapped password hash, a
   removed second factor -- fails to open instead of being read, which
   is what the trust-boundary section of `docs/security-by-design.md`
   already promised for the file. The `Store` and the document format
   are untouched; the accounts document stays version 3.
2. **A text envelope for everything but the file.** Through `Encrypt`
   the inner backend stores `{"sealed": "<base64>"}`: valid JSON, plain
   ASCII, so a `text` column and a backend that validates JSON both
   hold it unchanged. The file backend keeps writing mikroview's binary
   envelope so its existing files round-trip; both forms open
   everywhere.
3. **One application key, one label per store.** The key is the
   application's, as for the file: at least 32 bytes, read from
   wherever the application mounts it, never by gauntlet. The same key
   serves every store; `EncryptOptions.Label` ("accounts", "tokens") is
   authenticated with every document, so a document copied from one
   store's row into another's fails to open. The label is not a secret
   and must not change between releases, which is why it is explicit
   rather than taken from `Backend.Describe`. Rotation is open with the
   old key, save with the new -- two wrappers over one inner backend.
4. **The accounts store refuses a plaintext backend.** `OpenStore`
   returns `ErrPlaintextAtRest` for a backend that does not say,
   through the new `persist.AtRest` capability, that a copy of its
   storage carries no plaintext. `Encrypted`, `EncryptedFileBackend`
   and `Memory` (which has no storage) say so; a backend that wraps
   another forwards the answer. An application that accepts the
   exposure sets `Options.AllowPlaintextAtRest`, which names what it
   accepts. Refusing rather than warning follows #49 and #51: a warning
   is read once at start-up, and a backup is copied for years. The
   tokens store has no such check; its document holds only SHA-256
   hashes of random values.
5. **Plaintext is accepted only when asked, and sealed at once.** By
   default a plaintext document under `Encrypt` is refused like a
   tampered one, or anyone who can write the backend could replace the
   ciphertext with a document of their own. With
   `EncryptOptions.MigratePlaintext` the first `Load` seals the document
   in place under the version it was read at, so the upgrade is done
   once the application has started (or a CLI command has run) once,
   and the option can be removed. A document that is already sealed is
   not affected by the option; a collision with another process doing
   the same upgrade loads what that process wrote.

## Consequences

- **Breaking for both applications** (CHANGELOG, Unreleased): every
  `OpenStore` over a database backend must now wrap it in
  `persist.Encrypt` or set `AllowPlaintextAtRest`. Mikroview's accounts
  file already opens through the encrypted backend; its Postgres mode
  and birdcage's table need the wrapper, a 32-byte key file, and
  `MigratePlaintext` for one release. Birdcage has no key file today
  and gains one (`docs/design.md` §2.3, §2.4).
- The ASVS 13.3.1 and SP 800-63B §3.1.4.2 rows move from deviation to
  met, with the application's choice of backend as the remaining
  condition; "TOTP secrets as protected as the backend" leaves both
  summaries.
- Rolling back past this release on a database backend means restoring
  the plaintext copy taken before the upgrade first: an older gauntlet
  reads `{"sealed": ...}` as an accounts document with no users -- an
  empty store, setup code and all -- and its first write would put a
  plaintext document of no accounts over the ciphertext. Nothing in an
  older build can be taught otherwise. This build refuses that same
  envelope when it reaches a store unwrapped (`errSealedDocument`), so
  an application that drops the wrapper by mistake fails at start-up
  instead of emptying its accounts.
- The deprecated `SaveWithRetry` and `LoadDocument` are unaffected:
  they see whatever the wrapped backend returns, plaintext.
- Not done here: a per-field pepper for password hashes (the sealed
  document is the at-rest layer instead), and reading key files inside
  gauntlet (§1.7 stands).
- Status note (v0.3.0 audit, 2026-10-08): this change shipped in v0.2.0, so "CHANGELOG,
  Unreleased" above means the `[0.2.0]` section.
- Status note (v0.3.0 audit, 2026-10-08): the accounts document is no longer version 3
  (decision 1): later changes raised it, and it is version 9 now. The
  sealing is unchanged.
