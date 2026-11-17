// Package browsertoken is the known-browser token's shape (#44), written
// once (#90 item 8): what gauntlet's store issues and what gate accepts
// back from a cookie are the same rule, so a change to one cannot leave
// the other behind. The token itself, how it is stored and what it
// grants are gauntlet's knownbrowser.go; this package holds only its
// size, how a new one is made and which strings count as one.
//
// It is internal rather than a public function of gauntlet (owner,
// 2026-10-09, 20a): gauntlet's API check makes anything exported
// permanent, and no application has a use for it.
package browsertoken

import (
	"crypto/rand"
	"encoding/base64"
)

// Bytes is a token's size before encoding: 256 bits, twice the 128 a
// session ID has (gauntlet's newID), so it cannot be guessed.
const Bytes = 32

// encoding is the one spelling New writes and WellFormed accepts:
// base64url, so it fits a cookie as it is, without padding.
var encoding = base64.RawURLEncoding.Strict()

// New returns a fresh token: Bytes random bytes, unpadded base64url.
func New() string {
	b := make([]byte, Bytes)
	if _, err := rand.Read(b); err != nil {
		// As gauntlet's newID: no CSPRNG, no token can be made safely.
		panic("browsertoken: crypto/rand unavailable: " + err.Error())
	}
	return encoding.EncodeToString(b)
}

// WellFormed reports whether s is spelled exactly as New spells a
// token, so anything else -- a forged, truncated or re-spelled cookie --
// is refused before it is hashed or compared.
//
// Only the canonical spelling counts, as internal/seal requires of a
// sealed value: a token is stored as the SHA-256 of the string, so two
// spellings of the same bytes would be two different tokens to the
// store, and one of them could never have been issued. Go's decoder is
// not exact on its own: without Strict it ignores the unused bits in
// the last character, and even with Strict it skips line breaks. So
// the decoded bytes are spelled again and compared, which states the
// rule itself rather than listing what the decoder happens to skip.
func WellFormed(s string) bool {
	if len(s) != encoding.EncodedLen(Bytes) {
		return false
	}
	b, err := encoding.DecodeString(s)
	return err == nil && len(b) == Bytes && encoding.EncodeToString(b) == s
}
