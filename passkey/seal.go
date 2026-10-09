package passkey

import (
	"crypto/cipher"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/tomlawesome/gauntlet"
	// Named apart from this package's own seal function (ceremony.go).
	sealing "github.com/tomlawesome/gauntlet/internal/seal"
)

// sessionCodec seals the library's ceremony state (webauthn.SessionData:
// the challenge, the RP ID and origin, the user, the allowed
// credentials, the expiry) into a string the browser carries back
// unchanged from Begin to Finish. It must not be readable or alterable
// by whoever holds it, so it is internal/seal's AES-256-GCM under a key
// made once from crypto/rand and held only in memory: a tampered value
// fails the authentication tag rather than decoding into a different
// ceremony, and a value sealed by an earlier process does not open at
// all. gate's pending-login cookie and oidc's flow state share that
// mechanism, so a fix to it lands once (#90), but each keeps its own
// typed wrapper and key, for the reason mikroview gives: widening one
// codec to carry an unrelated payload would leave neither shape visible
// from its own file.
//
// Expiry is not the codec's concern: SessionData carries its own
// Expires, set by Begin and checked by Finish (and again by the
// library).
type sessionCodec struct {
	codec *sealing.Codec
	// aead is codec's own cipher, kept so this package's tests can seal
	// an authentic value that is not session JSON.
	aead cipher.AEAD
}

func newSessionCodec() *sessionCodec {
	// A CSPRNG that cannot produce bytes is not something either
	// ceremony can degrade from: every one depends on a codec.
	c := sealing.MustNew("passkey: ceremony codec")
	return &sessionCodec{codec: c, aead: c.AEAD()}
}

// registerCodec, assertCodec and signInCodec each seal one ceremony's
// state, under three independently generated keys rather than one shared
// codec: a value sealed for one ceremony cannot decode as another, so a
// registration's state can never be replayed to finish a login, nor a
// second-step login's to sign in with a passkey alone (the one ceremony
// that needs no password before it, #77). That is a property of the
// ciphertext, not a rule a caller has to remember.
var (
	registerCodec = newSessionCodec()
	assertCodec   = newSessionCodec()
	signInCodec   = newSessionCodec()
)

// errUnreadable is every way decode refuses: which one is not worth
// telling apart, even in the log.
var errUnreadable = fmt.Errorf("passkey: sealed state unreadable: %w", gauntlet.ErrPasskeyCeremonyInvalid)

// encode seals sd.
func (c *sessionCodec) encode(sd webauthn.SessionData) (string, error) {
	sealed, err := c.codec.Seal(sd)
	if err != nil {
		return "", fmt.Errorf("passkey: sealing ceremony state: %w", err)
	}
	return sealed, nil
}

// decode reverses encode, refusing (gauntlet.ErrPasskeyCeremonyInvalid)
// anything malformed, spelled other than encode spelled it, tampered
// with, or sealed under another codec's key. Strict spelling matters
// here: a lenient decoder ignores the unused bits in the last
// character, so one sealed value would open under several cookie
// strings -- and gate keys a spent registration on the cookie string
// (registrationKey).
func (c *sessionCodec) decode(sealed string) (webauthn.SessionData, error) {
	var sd webauthn.SessionData
	if !c.codec.Open(sealed, &sd) {
		return webauthn.SessionData{}, errUnreadable
	}
	return sd, nil
}
