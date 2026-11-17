package persist

import (
	"context"
	"errors"
	"fmt"
)

// AtRest is an optional Backend capability: saying whether a copy of
// the backend's storage -- a database dump, a backup, a lost drive --
// carries the document in the clear. Encrypted answers true, since
// everything it hands its inner backend is ciphertext; Memory answers
// true because it has no storage for a copy to be taken of. A backend
// that does not implement it is taken to store plaintext, which is the
// fail-closed reading: gauntlet's accounts store refuses such a backend
// at open unless the application says it accepts that
// (gauntlet.Options.AllowPlaintextAtRest, #50), because the accounts
// document holds the TOTP secrets, which cannot be hashed. A backend
// that wraps another (a write-behind queue, say) should forward its
// inner backend's answer.
type AtRest interface {
	ProtectedAtRest() bool
}

// EncryptOptions configures Encrypt.
type EncryptOptions struct {
	// Label names the store the ciphertext belongs to -- "accounts",
	// "tokens" -- and is authenticated with every document (the AEAD's
	// additional data), so a document copied from one store into
	// another fails to open there instead of silently decrypting as
	// something else. It must be the same string every time the same
	// store is opened; it is not the key, and not secret. Required: an
	// empty label is refused rather than defaulted from
	// Backend.Describe, which is written for logs and may change
	// wording between releases.
	Label string
	// MigratePlaintext accepts a document the inner backend holds in
	// the clear -- one written before the store was wrapped -- and
	// seals it in place the first time it is loaded, so the upgrade is
	// complete once the application has started (or a CLI command has
	// run) once. Off, which is the default, a plaintext document is
	// refused exactly as a tampered one is: anyone who can write the
	// backend could otherwise replace the ciphertext with a document of
	// their own and have it accepted, which is the integrity the
	// envelope's tag exists to refuse. Set it for the release that
	// introduces the wrapper and remove it afterwards; a document that
	// is already sealed is not affected by it either way.
	MigratePlaintext bool
}

// Encrypted is a Backend that seals every document under a key before
// handing it to the Backend it wraps, and opens it after: AES-256-GCM,
// with the key derived from the caller's material via HKDF-SHA256, a
// fresh random salt and nonce on every save, and the store's Label as
// additional authenticated data (see seal.go for the envelope). The
// inner backend -- an application's database table, mikroview's
// Postgres blob, a file -- only ever sees ciphertext, so a dump or a
// backup of it carries no TOTP secret and no passkey public key, and
// a document altered there fails to open rather than being read as if
// it were valid (#50; EncryptedFileBackend had this for files alone
// since #18, and is now this type over the plain file backend).
//
// The document the inner backend stores is a small JSON object,
// {"sealed": "<base64>"} (textEnvelope), so a backend that keeps the
// document in a text column or validates it as JSON is unaffected by
// the wrapping; the file backend alone keeps mikroview's binary form.
// Versions and conflicts are the inner backend's: the wrapper changes
// the bytes, not the compare-and-swap around them.
//
// The key stays the application's (docs/design.md §1.7): reading a key
// file, mounting it, and rotating it -- open with the old key, save
// with the new, which two Encrypted over one inner backend can do --
// are the application's job. One key serves every store it has; the
// Label keeps the stores' documents apart.
type Encrypted struct {
	inner Backend
	key   []byte
	aad   []byte
	// binary selects mikroview's raw envelope over the text one on
	// Save; only EncryptedFileBackend sets it, so a file it writes is
	// byte-for-byte what mikroview's own code writes. Load accepts both
	// forms regardless.
	binary  bool
	migrate bool
}

// Encrypt wraps inner so every read decrypts and every write encrypts
// under key. It refuses a key shorter than MinKeyBytes rather than
// derive a weaker cipher key from it, refuses an empty Label (see
// EncryptOptions), and copies key so the caller may reuse or clear its
// own slice afterwards.
func Encrypt(inner Backend, key []byte, opts EncryptOptions) (*Encrypted, error) {
	if inner == nil {
		return nil, errors.New("persist: Encrypt needs a backend to wrap")
	}
	if opts.Label == "" {
		return nil, errors.New("persist: Encrypt needs a label naming the store (EncryptOptions.Label)")
	}
	return newEncrypted(inner, key, []byte(opts.Label), false, opts.MigratePlaintext)
}

func newEncrypted(inner Backend, key, aad []byte, binary, migrate bool) (*Encrypted, error) {
	if len(key) < MinKeyBytes {
		return nil, fmt.Errorf("persist: key material is %d bytes, want at least %d", len(key), MinKeyBytes)
	}
	dup := make([]byte, len(key))
	copy(dup, key)
	return &Encrypted{inner: inner, key: dup, aad: aad, binary: binary, migrate: migrate}, nil
}

// Describe is the inner backend's: it says where the document lives,
// which the wrapping does not change, and it never includes the key.
func (b *Encrypted) Describe() string { return b.inner.Describe() }

func (b *Encrypted) Close() error { return b.inner.Close() }

// ProtectedAtRest implements AtRest: everything the inner backend
// stores is ciphertext.
func (b *Encrypted) ProtectedAtRest() bool { return true }

// Load reads the inner backend's document and decrypts it. A document
// that fails to decrypt -- the wrong key, a document altered or written
// by something else, or one copied in from a store with a different
// Label -- is a real error, not a missing-document case: treating it as
// absent would silently reopen a first-run setup on top of a store that
// actually holds data. Callers funnelling through Open get the
// fail-closed *StartupError that produces.
//
// A plaintext document is refused the same way unless
// EncryptOptions.MigratePlaintext is set, in which case it is sealed
// and saved back before being returned, so the returned Version is the
// sealed document's. If another process saves in between -- the same
// upgrade from a CLI command, say -- what it wrote is loaded instead,
// once; a second collision is reported as the conflict it is rather
// than retried without end.
func (b *Encrypted) Load(ctx context.Context) (Snapshot, error) {
	return b.load(ctx, true)
}

func (b *Encrypted) load(ctx context.Context, retryConflict bool) (Snapshot, error) {
	snap, err := b.inner.Load(ctx)
	if err != nil || !snap.Exists {
		return snap, err
	}
	plain, err := openSealed(b.key, b.aad, snap.Payload)
	if err == nil {
		snap.Payload = plain
		return snap, nil
	}
	if !b.migrate || !errors.Is(err, errNotSealed) {
		return Snapshot{}, fmt.Errorf("persist: %s: %w", b.inner.Describe(), err)
	}

	// Plaintext, and the caller asked for it to be upgraded: seal it
	// in place under the version it was read at, so a write that
	// landed between the read and this save is not overwritten.
	sealed, err := b.seal(snap.Payload)
	if err != nil {
		return Snapshot{}, err
	}
	version, err := b.inner.Save(ctx, sealed, snap.Version)
	if errors.Is(err, ErrConflict) && retryConflict {
		return b.load(ctx, false)
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("persist: %s: sealing the plaintext document in place: %w", b.inner.Describe(), err)
	}
	snap.Version = version
	return snap, nil
}

// Save encrypts payload and writes it through the inner backend, which
// still performs the version check against whatever ciphertext it
// currently holds.
func (b *Encrypted) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	sealed, err := b.seal(payload)
	if err != nil {
		return 0, err
	}
	return b.inner.Save(ctx, sealed, expect)
}

func (b *Encrypted) seal(payload []byte) ([]byte, error) {
	var sealed []byte
	var err error
	if b.binary {
		sealed, err = sealDocument(b.key, b.aad, payload)
	} else {
		sealed, err = sealText(b.key, b.aad, payload)
	}
	if err != nil {
		return nil, fmt.Errorf("persist: encrypting %s: %w", b.inner.Describe(), err)
	}
	return sealed, nil
}

// Version implements VersionReader without decrypting anything: the
// inner backend's own Version when it has one, otherwise its Load with
// the payload dropped. The version is the inner backend's token for
// whatever bytes it holds, ciphertext or not, so unlike Load this never
// fails on a document sealed under a different key -- which is what
// lets a running server notice that a document it cannot open has
// changed, and say so, rather than stall.
func (b *Encrypted) Version(ctx context.Context) (version int64, exists bool, err error) {
	if vr, ok := b.inner.(VersionReader); ok {
		return vr.Version(ctx)
	}
	snap, err := b.inner.Load(ctx)
	if err != nil {
		return 0, false, err
	}
	return snap.Version, snap.Exists, nil
}
