// Package seal turns a small value into an opaque string a browser
// carries and hands back unchanged, and opens it again: oidc's login
// flow state, gate's sign-in tickets and passkey's ceremony state all
// use it. Each of those keeps its own typed wrapper and its own Codec,
// so what each one seals stays visible from its own file and a value
// sealed for one cannot be opened by another; this package holds only
// the mechanics they share, so a fix to them lands once (#90).
//
// AES-256-GCM, stdlib crypto/aes and crypto/cipher only. GCM is
// authenticated encryption, so a sealed value is both private (an
// oidc PKCE verifier cannot be read out of the cookie) and
// tamper-evident (any change fails the authentication tag rather than
// decoding into a different account or ceremony). A plain HMAC-signed
// cookie would give the second without the first.
//
// The key is made once from crypto/rand when a Codec is built and held
// only in memory, the same process-lifetime contract gauntlet's
// SessionStore has: a restart fails any flow in progress cleanly,
// because nothing the old process sealed opens under the new key. No
// key ever reaches a file or a configuration setting.
//
// The value is JSON, sealed behind a fresh random nonce and written as
// unpadded base64url, so it fits a cookie or a JSON field as it is.
// Open reads that spelling strictly: a lenient decoder ignores the
// unused bits in the last character, so one sealed value would open
// under several strings, and gate keys a spent passkey registration on
// the string itself. The strict reading had to be fixed in three
// copies before this package existed (#20).
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// encoding is the one spelling Seal writes and Open accepts.
var encoding = base64.RawURLEncoding.Strict()

// Codec seals and opens values under one in-memory key. It is safe for
// concurrent use.
type Codec struct {
	aead cipher.AEAD
}

// New builds a Codec with a fresh AES-256-GCM key from crypto/rand.
func New() (*Codec, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("seal: generating the key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("seal: constructing the cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("seal: constructing the AEAD: %w", err)
	}
	return &Codec{aead: aead}, nil
}

// MustNew is New for a codec built at package load, where there is no
// caller to return an error to. A CSPRNG that cannot produce bytes is
// not something to degrade from gracefully: every flow that seals
// state depends on its codec existing. what names the codec in the
// panic.
func MustNew(what string) *Codec {
	c, err := New()
	if err != nil {
		panic(what + ": " + err.Error())
	}
	return c
}

// AEAD returns the codec's cipher, for a test that must seal bytes Seal
// would never write (an authentic value that is not JSON, say).
func (c *Codec) AEAD() cipher.AEAD { return c.aead }

// Seal encodes v as JSON and seals it behind a fresh random nonce,
// written as unpadded base64url.
func (c *Codec) Seal(v any) (string, error) {
	plaintext, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("seal: encoding: %w", err)
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("seal: generating the nonce: %w", err)
	}
	return encoding.EncodeToString(c.aead.Seal(nonce, nonce, plaintext, nil)), nil
}

// Open reverses Seal into v, reporting whether value opened: spelled
// exactly as Seal spelled it, sealed under this codec's key, unaltered,
// and JSON that fits v. Which of those failed is deliberately not said:
// a caller has no use for it, and neither has anyone probing with
// forged values.
func (c *Codec) Open(value string, v any) bool {
	sealed, err := encoding.DecodeString(value)
	if err != nil {
		return false
	}
	ns := c.aead.NonceSize()
	if len(sealed) < ns {
		return false
	}
	plaintext, err := c.aead.Open(nil, sealed[:ns], sealed[ns:], nil)
	if err != nil {
		return false
	}
	return json.Unmarshal(plaintext, v) == nil
}
