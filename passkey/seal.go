package passkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/tomlawesome/gauntlet"
)

// sessionCodec seals the library's ceremony state (webauthn.SessionData:
// the challenge, the RP ID and origin, the user, the allowed
// credentials, the expiry) into a string the browser carries back
// unchanged from Begin to Finish. It must not be readable or alterable
// by whoever holds it, so it is AES-256-GCM, stdlib only, under a key
// made once from crypto/rand and held only in memory: a tampered value
// fails the authentication tag rather than decoding into a different
// ceremony, and a value sealed by an earlier process does not open at
// all. The same construction as gate's pending-login cookie and oidc's
// flow state, as a separate type for the same reason mikroview gives:
// widening one codec to carry an unrelated payload would leave neither
// shape visible from its own file.
//
// Expiry is not the codec's concern: SessionData carries its own
// Expires, set by Begin and checked by Finish (and again by the
// library).
type sessionCodec struct {
	aead cipher.AEAD
}

func newSessionCodec() *sessionCodec {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// A CSPRNG that cannot produce bytes is not something either
		// ceremony can degrade from: every one depends on a codec.
		panic("passkey: crypto/rand unavailable: " + err.Error())
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("passkey: constructing the ceremony cipher: " + err.Error())
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic("passkey: constructing the ceremony AEAD: " + err.Error())
	}
	return &sessionCodec{aead: aead}
}

// registerCodec and assertCodec each seal one ceremony's state, under
// two independently generated keys rather than one shared codec: a value
// sealed for one ceremony cannot decode as the other, so a
// registration's state can never be replayed to finish a login (or the
// other way round). That is a property of the ciphertext, not a rule a
// caller has to remember.
var (
	registerCodec = newSessionCodec()
	assertCodec   = newSessionCodec()
)

// errUnreadable is every way decode refuses: which one is not worth
// telling apart, even in the log.
var errUnreadable = fmt.Errorf("passkey: sealed state unreadable: %w", gauntlet.ErrPasskeyCeremonyInvalid)

// encode seals sd.
func (c *sessionCodec) encode(sd webauthn.SessionData) (string, error) {
	plaintext, err := json.Marshal(sd)
	if err != nil {
		return "", fmt.Errorf("passkey: encoding ceremony state: %w", err)
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("passkey: generating the ceremony seal nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(c.aead.Seal(nonce, nonce, plaintext, nil)), nil
}

// decode reverses encode, refusing (gauntlet.ErrPasskeyCeremonyInvalid)
// anything malformed, spelled other than encode spelled it, tampered
// with, or sealed under another codec's key.
func (c *sessionCodec) decode(sealed string) (webauthn.SessionData, error) {
	// Strict: only the spelling encode wrote opens. A lenient decoder
	// ignores the unused bits in the last character, so one sealed value
	// would open under several cookie strings -- and gate keys a spent
	// registration on the cookie string (registrationKey).
	raw, err := base64.RawURLEncoding.Strict().DecodeString(sealed)
	if err != nil {
		return webauthn.SessionData{}, errUnreadable
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return webauthn.SessionData{}, errUnreadable
	}
	plaintext, err := c.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return webauthn.SessionData{}, errUnreadable
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(plaintext, &sd); err != nil {
		return webauthn.SessionData{}, errUnreadable
	}
	return sd, nil
}
