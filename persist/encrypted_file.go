package persist

import "context"

// EncryptedFileBackend is Encrypted over the plain single-file backend:
// every document a file-backed store writes is ciphertext under the key
// the caller provides, with the file's path as the label the envelope
// is bound to. A hand-edited or tampered file, or one opened under the
// wrong key, fails Load outright rather than being read as if it were
// valid -- see Encrypted.Load.
//
// This is gauntlet's only file backend (docs/security-by-design.md):
// there is no unencrypted mode to fall back to, and the plain
// single-file mechanics live in the unexported fileBackend this type
// wraps. It writes mikroview's binary envelope, not the text one
// Encrypt writes (see seal.go), so a file mikroview's own
// internal/persist.EncryptedFileBackend wrote opens here byte-for-byte
// and vice versa (#18). It never migrates a plaintext file: gauntlet
// has never written one.
//
// Ported from mikroview's internal/persist.EncryptedFileBackend (#853
// there, #18 here), which wraps the same key type's Seal/Open
// (internal/retention). This type takes the raw key bytes directly
// instead: reading a key file, or deciding a store has no key and
// therefore no persistence, stays the calling application's job
// (docs/design.md §1.7). Since #50 it is a thin shape over Encrypted,
// kept as its own type so existing callers and apidiff see no change.
type EncryptedFileBackend struct {
	enc *Encrypted
}

// NewEncryptedFileBackend wraps the file at path so every read decrypts
// and every write encrypts under key. It refuses an empty path, and a
// key shorter than MinKeyBytes rather than derive a weaker cipher key
// from it, and copies key so the caller may reuse or clear its own slice
// afterwards.
func NewEncryptedFileBackend(path string, key []byte) (*EncryptedFileBackend, error) {
	return newEncryptedFileBackendForPath(path, path, key)
}

// newEncryptedFileBackendForPath is NewEncryptedFileBackend with the
// bytes-on-disk location and the AAD-binding location told apart. Every
// ordinary caller reads a document from exactly where it lives and uses
// NewEncryptedFileBackend; this exists for persist/testdata's
// cross-app fixture (TestEncryptedFileBackendOpensMikroviewFixture),
// which reads ciphertext from wherever this checkout put it while the
// AAD it must match is the logical path mikroview's own code sealed it
// under.
func newEncryptedFileBackendForPath(realPath, logicalPath string, key []byte) (*EncryptedFileBackend, error) {
	// Refused here rather than left for the first Save, so a store with
	// no path configured fails at startup instead of after setup.
	if realPath == "" {
		return nil, errNoPath
	}
	enc, err := newEncrypted(newFileBackend(realPath), key, []byte(logicalPath), true, false)
	if err != nil {
		return nil, err
	}
	return &EncryptedFileBackend{enc: enc}, nil
}

func (b *EncryptedFileBackend) Describe() string { return b.enc.Describe() }

func (b *EncryptedFileBackend) Close() error { return b.enc.Close() }

// ProtectedAtRest implements AtRest: the file holds ciphertext only.
func (b *EncryptedFileBackend) ProtectedAtRest() bool { return true }

// Load reads the file and decrypts it -- see Encrypted.Load for what a
// failure means and why it is never treated as a missing document.
func (b *EncryptedFileBackend) Load(ctx context.Context) (Snapshot, error) {
	return b.enc.Load(ctx)
}

// Save encrypts payload and writes it through the wrapped file backend,
// which still performs the version check against whatever ciphertext is
// currently on disk.
func (b *EncryptedFileBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	return b.enc.Save(ctx, payload, expect)
}

// Version implements VersionReader by reading the raw (still
// encrypted) file's version without decrypting it -- see
// Encrypted.Version.
func (b *EncryptedFileBackend) Version(ctx context.Context) (version int64, exists bool, err error) {
	return b.enc.Version(ctx)
}
