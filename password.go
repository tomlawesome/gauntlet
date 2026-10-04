// Copied from mikroview's internal/auth/password.go, unchanged except
// for the error message prefix ("gauntlet:" in place of "auth:"). The
// design (docs/design.md §1.3) requires identical Argon2id parameters
// so existing mikroview hashes verify unchanged.

package gauntlet

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/tomlawesome/gauntlet/internal/hashcost"
)

// Argon2id parameters for a small self-hosted service -- RFC 9106 §4's
// memory-constrained profile (64 MiB memory, 3 passes, 4 threads, t=3),
// not its high-memory profile (t=1, but only ever recommended paired
// with several GiB of memory, impractical here). Encoded into every
// hash string, so changing these later doesn't invalidate existing
// hashes -- only new ones use the new parameters (VerifyPassword reads
// memory/time/threads back out of the hash string itself, never from
// these constants).
const (
	argon2Memory  uint32 = 64 * 1024 // KiB
	argon2Time    uint32 = 3
	argon2Threads uint8  = 4
	argon2KeyLen  uint32 = 32
	argon2SaltLen        = 16
)

// Upper bounds VerifyPassword accepts from a stored hash (issue #12).
// A stored hash is data, not necessarily one HashPassword wrote -- a
// corrupt document, or anyone with write access to the backend, can put
// any cost into it -- so its declared cost is checked before any memory
// is allocated. Four times today's cost leaves room to raise the
// constants above without locking out existing hashes; raising them
// past these bounds means raising the bounds in the same change.
const (
	maxVerifyMemory  = 4 * argon2Memory // KiB
	maxVerifyTime    = 4 * argon2Time
	maxVerifyThreads = 4 * argon2Threads
	maxVerifyKeyLen  = 64
	maxVerifySaltLen = 64
)

// maxConcurrentHashes bounds how many Argon2id computations may run at
// once, process-wide.
//
// Each hash allocates argon2Memory (64 MiB) for its duration, so without
// a bound the memory ceiling is set by however many requests arrive
// simultaneously -- registration and login are typically unauthenticated
// and rate-limit-free at the point the hash runs. A handful of
// concurrent attempts can otherwise reserve hundreds of MiB, enough to
// OOM a memory-limited container.
//
// Placed here, around the cost itself, rather than in any one caller:
// every caller (login, register, admin create-user, a CLI recovery path)
// is bounded automatically and a future caller cannot forget it. Waiting
// is deliberate rather than rejecting -- a queued request holds a
// goroutine, not 64 MiB, so the queue is cheap while the memory ceiling
// stays fixed.
const maxConcurrentHashes = 4

var hashSlots = make(chan struct{}, maxConcurrentHashes)

func acquireHashSlot() func() {
	hashSlots <- struct{}{}
	return func() { <-hashSlots }
}

// dummyHash is verified against when a username doesn't exist, so a
// failed login takes the same amount of time either way -- otherwise
// "valid username, wrong password" (does the Argon2id work) and "no
// such username" (returns immediately) would be distinguishable by
// response time, leaking which usernames exist.
var dummyHash = mustHashPassword("not-a-real-password-used-only-for-timing")

// HashPassword returns a self-describing Argon2id hash string
// ("argon2id$v=<version>$m=<memory>,t=<time>,p=<threads>$<salt>$<hash>",
// all base64) for password, with a fresh random salt.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	memory, iterations, threads := newHashCost()
	release := acquireHashSlot()
	hash := argon2.IDKey([]byte(password), salt, iterations, memory, threads, argon2KeyLen)
	release()
	return fmt.Sprintf("argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, iterations, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// newHashCost is the cost HashPassword gives a new hash: the constants
// above, except in this module's own tests, which switch to a cheap one
// (internal/hashcost) that no production binary can.
func newHashCost() (memory, iterations uint32, threads uint8) {
	if hashcost.Cheap() {
		return hashcost.Memory, hashcost.Time, hashcost.Threads
	}
	return argon2Memory, argon2Time, argon2Threads
}

func mustHashPassword(password string) string {
	h, err := HashPassword(password)
	if err != nil {
		panic("gauntlet: failed to compute dummy hash: " + err.Error())
	}
	return h
}

// VerifyPassword reports whether password matches encodedHash (as
// produced by HashPassword), comparing in constant time. A malformed
// encodedHash is treated as a non-match, never an error -- there's
// nothing a caller can usefully do differently. So is one whose declared
// cost or lengths are outside the maxVerify* bounds above: it is refused
// before any hashing is done.
func VerifyPassword(password, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 5 || parts[0] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[1], "v=%d", &version); err != nil {
		return false
	}
	var memory, iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false
	}
	if version != argon2.Version ||
		iterations < 1 || iterations > maxVerifyTime ||
		threads < 1 || threads > maxVerifyThreads ||
		memory < 8*uint32(threads) || memory > maxVerifyMemory {
		return false
	}
	if len(parts[3]) > base64.RawStdEncoding.EncodedLen(maxVerifySaltLen) ||
		len(parts[4]) > base64.RawStdEncoding.EncodedLen(maxVerifyKeyLen) {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(salt) == 0 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(want) == 0 {
		return false
	}
	release := acquireHashSlot()
	defer release() // a panic inside argon2 must not keep the slot
	got := argon2.IDKey([]byte(password), salt, iterations, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// KDFParams are the Argon2id cost parameters one derivation was run
// with. Recorded alongside whatever they protected, for the same reason
// HashPassword encodes them into its hash string: raising the cost later
// must not make everything derived under the old cost unopenable.
type KDFParams struct {
	Memory  uint32 `json:"memory"` // KiB
	Time    uint32 `json:"time"`
	Threads uint8  `json:"threads"`
}

// DefaultKDFParams is the profile a new derivation uses -- the same
// RFC 9106 §4 memory-constrained profile HashPassword's constants
// describe, so there is one Argon2id cost in this codebase rather than a
// second one that drifts.
func DefaultKDFParams() KDFParams {
	return KDFParams{Memory: argon2Memory, Time: argon2Time, Threads: argon2Threads}
}

// Valid reports whether p is usable. Zero values would silently produce
// a derivation far weaker than the documented one, so a lock document
// that arrives with them is refused rather than opened cheaply.
func (p KDFParams) Valid() bool {
	return p.Memory >= 8*1024 && p.Time >= 1 && p.Threads >= 1
}

// DeriveKey turns a passphrase into 32 bytes of key material under p.
//
// Exported for an application's own use of the same KDF profile (e.g.
// mikroview's router-backup vault passphrase) -- sharing this one keeps
// the cost profile in a single place, and -- because every derivation
// here takes a slot from the same process-wide semaphore -- a burst of
// unlock attempts cannot reserve more memory than a burst of logins
// already could.
func DeriveKey(passphrase string, salt []byte, p KDFParams) []byte {
	release := acquireHashSlot()
	defer release()
	return argon2.IDKey([]byte(passphrase), salt, p.Time, p.Memory, p.Threads, argon2KeyLen)
}

// NewKDFSalt returns a fresh random salt of the size this package's
// derivations use.
func NewKDFSalt() ([]byte, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}
