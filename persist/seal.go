package persist

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

// The sealing primitives every encrypting backend in this package is
// built on: Encrypted (encrypted.go) and, through it,
// EncryptedFileBackend (encrypted_file.go). They started life inside
// encrypted_file.go (issue #18) and moved here unchanged when #50 put
// the same envelope in front of every backend, so there is exactly one
// place that turns key material into ciphertext and back.

// MinKeyBytes is the shortest key mikroview's own key-file rule accepts
// (internal/retention.MinKeyBytes) and the floor Encrypt and
// NewEncryptedFileBackend enforce here (issue #18): thirty-two bytes
// because that is the size of the AES-256 key every document is
// ultimately sealed with, so nothing weaker than the documented cipher
// strength can stand in for it. Where the key bytes come from -- a file
// the operator mounts, or anything else -- is the calling application's
// job, not this package's; gauntlet only ever sees the raw material.
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

// textEnvelope is the sealed envelope in the form Encrypted stores
// through an arbitrary backend (#50): a JSON object whose one member is
// the binary envelope sealDocument makes, in standard base64. A backend
// that keeps "the JSON document" in a text column -- mikroview's
// store_blob and birdcage's planned auth_store are both `payload text`
// -- cannot hold the binary form (Postgres refuses bytes that are not
// UTF-8 in a text column), and a backend that validates JSON would
// refuse it too. The member name is the one thing that tells a sealed
// document from a plaintext accounts or tokens document, whose
// top-level members are "version" and "users" or "tokens" -- see
// decodeEnvelope. The file backend keeps writing the binary form
// (EncryptedFileBackend), mikroview's format for its existing files;
// both forms open everywhere.
type textEnvelope struct {
	Sealed []byte `json:"sealed"`
}

// errNotSealed is the open-side error for bytes that are neither form of
// envelope -- a plaintext document, or something else entirely. Encrypted
// matches it to tell "this is the plaintext an upgrade should seal" from
// "this is ciphertext that failed to open", which are different answers
// (see Encrypted.Load).
var errNotSealed = errors.New("persist: not a sealed document")

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

// sealText is sealDocument in the textEnvelope form.
func sealText(material, aad, plaintext []byte) ([]byte, error) {
	sealed, err := sealDocument(material, aad, plaintext)
	if err != nil {
		return nil, err
	}
	// encoding/json writes a []byte member as standard base64 itself;
	// a marshal of this shape cannot fail.
	return json.Marshal(textEnvelope{Sealed: sealed})
}

// decodeEnvelope recognises either envelope form and returns the binary
// envelope inside it. Bytes that are neither -- a plaintext document,
// or anything else -- are errNotSealed; a text envelope whose base64
// does not decode is reported as its own error, since it is a sealed
// document that has been damaged rather than one that was never
// sealed.
//
// The text form is recognised by shape, not by a byte prefix, because a
// text column may legitimately hand back the JSON with different
// whitespace than it was given: it must be a JSON object with the one
// member textEnvelope has. A plaintext accounts or tokens document is a
// JSON object too, but without that member, so it is reported as
// errNotSealed, never mistaken for ciphertext.
func decodeEnvelope(payload []byte) ([]byte, error) {
	if bytes.HasPrefix(payload, []byte(sealMagic)) {
		return payload, nil
	}
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errNotSealed
	}
	var head struct {
		Sealed json.RawMessage `json:"sealed"`
	}
	if err := json.Unmarshal(trimmed, &head); err != nil || head.Sealed == nil {
		return nil, errNotSealed
	}
	var env textEnvelope
	if err := json.Unmarshal(trimmed, &env); err != nil {
		return nil, fmt.Errorf("persist: sealed document is damaged: %w", err)
	}
	return env.Sealed, nil
}

// openSealed reverses sealDocument. A failure to open -- wrong key,
// wrong aad, or a document that has been altered or was never sealed at
// all -- is reported as a single class of error: none of those are
// worth distinguishing to an operator, who can only respond to all of
// them the same way. The one exception is bytes that are not an
// envelope at all, reported as errNotSealed so Encrypted can tell a
// plaintext document from damaged ciphertext (see decodeEnvelope).
func openSealed(material, aad, payload []byte) ([]byte, error) {
	envelope, err := decodeEnvelope(payload)
	if err != nil {
		return nil, err
	}
	// From here on the bytes claimed to be an envelope (the magic
	// prefix, or the text form's member), so what fails is damaged
	// ciphertext, never a plaintext document: none of these is
	// errNotSealed.
	if len(envelope) < sealHeaderBytes {
		return nil, errors.New("persist: sealed document is truncated (too short)")
	}
	if string(envelope[:len(sealMagic)]) != sealMagic {
		return nil, errors.New("persist: sealed document is damaged (no magic)")
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
		// The label (a file's path) is part of what is authenticated
		// (see aad), so a document that was moved -- a file mounted at
		// a different path than it was written at, or a document copied
		// into another store's row -- fails exactly like a wrong key,
		// and a backup taken at the old path fails the same way. Said
		// here, because the startup advice that follows ("restore from
		// a backup") cannot help with that case.
		return nil, fmt.Errorf("persist: did not decrypt -- wrong key, the document has been altered, or it was moved from the store it was written for: %w", err)
	}
	return plain, nil
}
