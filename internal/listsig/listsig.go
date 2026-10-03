// Package listsig is the signature format for the common-password list
// (#52, ADR-0007): Ed25519 keys in PEM files, and a detached signature
// file holding one line per signing key.
//
// It is internal so the format is shared by the two places that need it
// -- cmd/pwlist, which signs on the CI signing runner, and package
// blocklist, which verifies inside every application -- without
// freezing it in the module's exported API (ADR-0002).
//
// The signature file (`top10k.txt.sig`) is plain text, one line per key:
//
//	<key-id> <base64 Ed25519 signature over the file's exact bytes>
//
// where key-id is the first 16 hex characters of the SHA-256 of the raw
// 32-byte public key. Several lines are how a key rotation works: for one
// release the list is signed by the old and the new key, so an
// application that only knows the old key still finds a line it can
// check, and one that knows only the new key does too.
package listsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// MaxSignatureFile bounds a signature file. One line is 16 + 1 + 88 + 1
// = 106 bytes, so this is room for over thirty keys -- far more than a
// rotation ever has in flight -- and small enough that a hostile server
// cannot make a verifier buffer much.
const MaxSignatureFile = 4096

// keyIDLen is how many hex characters of the public key's SHA-256 name
// it. 64 bits is not a security boundary -- the signature is checked
// against the full key -- only a way to pick the right key without
// trying each; two trusted keys sharing a prefix are refused outright.
const keyIDLen = 16

var (
	// ErrNoKeys means verification had no trusted public key at all.
	// With no key nothing can be checked, so everything is refused:
	// that is the state of package blocklist until the owner commits
	// the first public key.
	ErrNoKeys = errors.New("listsig: no trusted public keys; every signature is refused")
	// ErrUnknownKey means no line of the signature file names a trusted
	// key: it was signed, but not by anyone this verifier trusts.
	ErrUnknownKey = errors.New("listsig: signed only by keys this build does not trust")
	// ErrBadSignature means a line names a trusted key but its
	// signature does not match the data.
	ErrBadSignature = errors.New("listsig: signature does not match the data")
	// ErrMalformed means the signature file is not in the format above.
	ErrMalformed = errors.New("listsig: malformed signature file")
)

// KeyID names a public key: the first 16 hex characters of the SHA-256
// of its raw 32 bytes.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:keyIDLen]
}

// MarshalPublicKey encodes pub as a PEM "PUBLIC KEY" block (PKIX), the
// form committed under blocklist/keys/*.pub.
func MarshalPublicKey(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("listsig: encode public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParsePublicKey decodes a PEM "PUBLIC KEY" block holding an Ed25519
// key. Anything after the block other than whitespace is refused, so a
// file that holds two keys is an error rather than silently its first.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("listsig: not a PEM PUBLIC KEY block")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("listsig: trailing data after the PUBLIC KEY block")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("listsig: parse public key: %w", err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("listsig: public key is %T, not Ed25519", key)
	}
	return pub, nil
}

// MarshalPrivateKey encodes priv as a PEM "PRIVATE KEY" block (PKCS#8),
// the form the signing runner holds under /etc/gauntlet-signing/.
func MarshalPrivateKey(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("listsig: encode private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePrivateKey decodes a PEM "PRIVATE KEY" block holding an Ed25519
// key. The error never quotes the file's contents.
func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("listsig: not a PEM PRIVATE KEY block")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("listsig: trailing data after the PRIVATE KEY block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("listsig: parse private key: not PKCS#8")
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("listsig: private key is %T, not Ed25519", key)
	}
	return priv, nil
}

// Sign signs data with every key and returns the signature file, lines
// sorted by key id so the same keys always give the same file. Two keys
// with the same id are refused: their lines would be indistinguishable
// to a verifier.
func Sign(data []byte, keys []ed25519.PrivateKey) ([]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New("listsig: no signing keys")
	}
	lines := make([]string, 0, len(keys))
	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		id := KeyID(k.Public().(ed25519.PublicKey))
		if seen[id] {
			return nil, fmt.Errorf("listsig: two signing keys share key id %s", id)
		}
		seen[id] = true
		lines = append(lines, id+" "+base64.StdEncoding.EncodeToString(ed25519.Sign(k, data)))
	}
	slices.Sort(lines)
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

// Keyring is a set of trusted public keys, indexed by key id.
type Keyring map[string]ed25519.PublicKey

// NewKeyring indexes keys by id, refusing two keys that share one.
func NewKeyring(keys ...ed25519.PublicKey) (Keyring, error) {
	ring := make(Keyring, len(keys))
	for _, k := range keys {
		if len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("listsig: public key is %d bytes, not %d", len(k), ed25519.PublicKeySize)
		}
		id := KeyID(k)
		if _, dup := ring[id]; dup {
			return nil, fmt.Errorf("listsig: two trusted keys share key id %s", id)
		}
		ring[id] = k
	}
	return ring, nil
}

// Verify checks sig, a signature file, against data.
//
// It accepts only when at least one line names a key in ring and every
// line that names a key in ring verifies. A line naming a key the ring
// does not hold is skipped -- that is the other half of a rotation --
// but a file in which no line is trusted is refused (ErrUnknownKey), as
// is any malformed line, a repeated key id, or a file over
// MaxSignatureFile. An empty ring refuses everything (ErrNoKeys).
//
// Every line from a trusted key must verify, not just one: a file
// carrying one good and one bad signature from keys this build trusts
// was not produced by the signing job, which signs with every key it
// holds, so something altered it.
func Verify(data, sig []byte, ring Keyring) error {
	if len(ring) == 0 {
		return ErrNoKeys
	}
	if len(sig) > MaxSignatureFile {
		return fmt.Errorf("%w: %d bytes, over the %d-byte limit", ErrMalformed, len(sig), MaxSignatureFile)
	}
	if len(sig) == 0 || sig[len(sig)-1] != '\n' {
		return fmt.Errorf("%w: empty, or the last line is not terminated", ErrMalformed)
	}
	trusted := 0
	seen := make(map[string]bool)
	for i, line := range strings.Split(strings.TrimSuffix(string(sig), "\n"), "\n") {
		id, b64, ok := strings.Cut(line, " ")
		if !ok || !isLowerHex(id, keyIDLen) {
			return fmt.Errorf("%w: line %d is not `<key-id> <signature>`", ErrMalformed, i+1)
		}
		// The decoder skips '\r' and '\n' inside its input, so a CRLF
		// file would decode cleanly; re-encoding and comparing leaves
		// exactly one spelling of each signature.
		raw, err := base64.StdEncoding.Strict().DecodeString(b64)
		if err != nil || len(raw) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(raw) != b64 {
			return fmt.Errorf("%w: line %d does not hold a %d-byte base64 signature", ErrMalformed, i+1, ed25519.SignatureSize)
		}
		if seen[id] {
			return fmt.Errorf("%w: key id %s appears twice", ErrMalformed, id)
		}
		seen[id] = true
		pub, ok := ring[id]
		if !ok {
			continue
		}
		if !ed25519.Verify(pub, data, raw) {
			return fmt.Errorf("%w (key %s)", ErrBadSignature, id)
		}
		trusted++
	}
	if trusted == 0 {
		return ErrUnknownKey
	}
	return nil
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
