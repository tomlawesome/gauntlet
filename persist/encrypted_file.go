package persist

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// MinKeyBytes is the shortest key mikroview's own key-file rule accepts
// (internal/retention.MinKeyBytes) and the floor NewEncryptedFileBackend
// enforces here (issue #18): thirty-two bytes because that is the size
// of the AES-256 key every document is ultimately sealed with, so
// nothing weaker than the documented cipher strength can stand in for
// it. Where the key bytes come from -- a file the operator mounts, or
// anything else -- is the calling application's job, not this
// package's; gauntlet only ever sees the raw material.
const MinKeyBytes = 32

// sealMagic, sealVersion, saltBytes and sealHeaderBytes, plus the HKDF
// info string sealInfo below, are not this package's own design: they
// are mikroview's on-disk envelope (internal/retention/seal.go,
// internal/retention/key.go), copied unchanged so a document mikroview
// already wrote loads here byte-for-byte and vice versa (issue #18's
// whole point). Changing any of them would silently stop reading
// mikroview's existing accounts files. The AES-GCM nonce (12 bytes) and
// tag (16 bytes) that follow the header are not repeated as constants
// here: they come straight from the cipher (aead.NonceSize(),
// aead.Overhead()), the same way mikroview's own code reads them.
const (
	sealMagic       = "MVS1"
	sealVersion     = 1
	saltBytes       = 16
	sealHeaderBytes = len(sealMagic) + 1 + saltBytes

	// sealInfo is the HKDF domain-separation string mikroview's
	// internal/retention used for its file-backed stores
	// (StateStoreKeyInfo, "the state store" meaning any one-document-
	// per-file store, accounts included) -- not a gauntlet-specific
	// name, kept exactly so the derived key matches.
	sealInfo = "mikroview/state-store/v1/"
)

// EncryptedFileBackend wraps a single-file Backend so every document a
// file-backed store writes is ciphertext under the key the caller
// provides: AES-256-GCM, with the key derived from that material via
// HKDF-SHA256, a fresh random salt and nonce on every save, and the
// store's path as additional authenticated data (AAD). A hand-edited or
// tampered file, or one opened under the wrong key, fails Load outright
// rather than being read as if it were valid -- see Load.
//
// This is gauntlet's only file backend (docs/security-by-design.md):
// there is no unencrypted mode to fall back to, and the plain
// single-file mechanics live in the unexported fileBackend this type
// wraps.
//
// Ported from mikroview's internal/persist.EncryptedFileBackend (#853
// there, #18 here), which wraps the same key type's Seal/Open
// (internal/retention). This type takes the raw key bytes directly
// instead: reading a key file, or deciding a store has no key and
// therefore no persistence, stays the calling application's job
// (docs/design.md §1.7).
type EncryptedFileBackend struct {
	inner *fileBackend
	key   []byte
	// aad binds every envelope to the store it belongs to (its logical
	// path), so a document copied from one store's file to another's
	// fails to open there instead of silently decrypting as something
	// else.
	aad []byte
}

// NewEncryptedFileBackend wraps the file at path so every read decrypts
// and every write encrypts under key. It refuses a key shorter than
// MinKeyBytes rather than derive a weaker cipher key from it, and copies
// key so the caller may reuse or clear its own slice afterwards.
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
	if len(key) < MinKeyBytes {
		return nil, fmt.Errorf("persist: key material is %d bytes, want at least %d", len(key), MinKeyBytes)
	}
	dup := make([]byte, len(key))
	copy(dup, key)
	return &EncryptedFileBackend{inner: newFileBackend(realPath), key: dup, aad: []byte(logicalPath)}, nil
}

func (b *EncryptedFileBackend) Describe() string { return b.inner.Describe() }

func (b *EncryptedFileBackend) Close() error { return b.inner.Close() }

// Load reads the file and decrypts it. A document that fails to decrypt
// -- the wrong key, a file altered or written by something else, or one
// copied in from a different logical path -- is a real error, not a
// missing-document case: treating it as absent would silently reopen a
// first-run setup on top of a store that actually holds data. Callers
// funnelling through persist.Open get the fail-closed *StartupError that
// produces.
func (b *EncryptedFileBackend) Load(ctx context.Context) (Snapshot, error) {
	snap, err := b.inner.Load(ctx)
	if err != nil || !snap.Exists {
		return snap, err
	}
	plain, err := openSealed(b.key, b.aad, snap.Payload)
	if err != nil {
		return Snapshot{}, fmt.Errorf("persist: %s: %w", b.inner.path, err)
	}
	snap.Payload = plain
	return snap, nil
}

// Save encrypts payload and writes it through the wrapped file backend,
// which still performs the version check against whatever ciphertext is
// currently on disk.
func (b *EncryptedFileBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	sealed, err := sealDocument(b.key, b.aad, payload)
	if err != nil {
		return 0, fmt.Errorf("persist: encrypting %s: %w", b.inner.path, err)
	}
	return b.inner.Save(ctx, sealed, expect)
}

// Version implements persist.VersionReader by reading the raw (still
// encrypted) file's version without decrypting it -- the version is a
// hash of whatever bytes are on disk, encrypted or not, so this never
// fails on a document sealed under a different key the way Load does.
func (b *EncryptedFileBackend) Version(ctx context.Context) (version int64, exists bool, err error) {
	snap, err := b.inner.Load(ctx)
	if err != nil {
		return 0, false, err
	}
	return snap.Version, snap.Exists, nil
}

// aeadFor builds the AES-256-GCM cipher for one call: a key derived from
// material and salt under sealInfo, wrapped in GCM. One function for
// both sealDocument and openSealed, so there is exactly one place that
// turns derived key material into a cipher.AEAD.
func aeadFor(material, salt []byte) (cipher.AEAD, error) {
	derived, err := hkdf.Key(sha256.New, material, salt, sealInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("persist: deriving key: %w", err)
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, fmt.Errorf("persist: cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("persist: gcm: %w", err)
	}
	return aead, nil
}

// sealDocument encrypts plaintext into a self-contained envelope: a
// fresh random salt and nonce are generated on every call, so nothing
// needs to be kept between calls and two seals of the same bytes never
// produce the same ciphertext.
//
// Envelope shape (mikroview's, unchanged -- see the sealMagic group's
// comment): magic (4 bytes) + version (1 byte) + salt (16 bytes) + nonce
// (12 bytes) + ciphertext-with-GCM-tag.
func sealDocument(material, aad, plaintext []byte) ([]byte, error) {
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("persist: generating salt: %w", err)
	}
	aead, err := aeadFor(material, salt)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("persist: generating nonce: %w", err)
	}

	dst := make([]byte, 0, sealHeaderBytes+len(nonce)+len(plaintext)+aead.Overhead())
	dst = append(dst, sealMagic...)
	dst = append(dst, sealVersion)
	dst = append(dst, salt...)
	dst = append(dst, nonce...)
	return aead.Seal(dst, nonce, plaintext, aad), nil
}

// openSealed reverses sealDocument. A failure to open -- wrong key,
// wrong aad, or a document that has been altered or was never sealed at
// all -- is reported as a single class of error: none of those are
// worth distinguishing to an operator, who can only respond to all of
// them the same way.
func openSealed(material, aad, envelope []byte) ([]byte, error) {
	if len(envelope) < sealHeaderBytes {
		return nil, errors.New("persist: not a sealed document (too short)")
	}
	if string(envelope[:len(sealMagic)]) != sealMagic {
		return nil, errors.New("persist: not a sealed document")
	}
	if envelope[len(sealMagic)] != sealVersion {
		return nil, fmt.Errorf("persist: unsupported sealed-document version %d", envelope[len(sealMagic)])
	}
	salt := envelope[len(sealMagic)+1 : sealHeaderBytes]
	rest := envelope[sealHeaderBytes:]

	aead, err := aeadFor(material, salt)
	if err != nil {
		return nil, err
	}
	if len(rest) < aead.NonceSize() {
		return nil, errors.New("persist: not a sealed document (truncated)")
	}
	nonce := rest[:aead.NonceSize()]
	ciphertext := rest[aead.NonceSize():]

	plain, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		// The path is part of what is authenticated (see aad), so a file
		// that was moved -- or is mounted at a different path than it was
		// written at -- fails exactly like a wrong key, and a backup taken
		// at the old path fails the same way. Said here, because the
		// startup advice that follows ("restore from a backup") cannot
		// help with that case.
		return nil, fmt.Errorf("persist: did not decrypt -- wrong key, the document has been altered, or the file was moved from the path it was written at: %w", err)
	}
	return plain, nil
}
