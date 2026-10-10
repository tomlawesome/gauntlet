// Package plaintext decides what counts as plain text in a string a
// person or a client chose -- a username, a passkey name, a sign-out
// reason, the client details a session or sign-in record carries -- and
// cleans what does not.
//
// A control (Cc) or format (Cf) character, or the Unicode line or
// paragraph separator (Zl, Zp), is not text a person reads but an
// instruction to whatever shows it: an ANSI escape is run by an
// operator's terminal, a newline forges a whole extra line in the audit
// trail, a bidi override (U+202E and friends) makes a name render as
// something other than what it is, and some mail and chat clients start
// a new line at U+2028 or U+2029 as at a newline (#80). The defects
// behind CVE-2025-55754 (Tomcat, ANSI escapes reaching console output)
// and CVE-2025-48432 (Django, crafted input reaching logs unescaped)
// are this one.
//
// Two jobs follow, and a surface usually wants both: refuse such text
// when it is given (Valid), and take it out when it is shown (Clean),
// for text stored before the rule or edited into a file by hand. Input
// validation does not replace output encoding, or the other way round.
// A name a person chooses is held to a stricter rule (ValidWithin): it
// also refuses U+FFFD and counts its length in characters (#90).
//
// This is not the full RFC 8266 profile: its extra steps (space folding,
// NFKC) tidy a name but add no security, and would need a new
// dependency. Letters of any script, accents and emoji are all plain
// text. The package is internal so the rule is shared by the root
// package and gate without becoming API.
package plaintext

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Unprintable reports whether r is a character that is refused or
// dropped in text a person or a client chose: a control (Cc) or format
// (Cf) character, or the line or paragraph separator (Zl, Zp).
func Unprintable(r rune) bool {
	return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}

// Valid reports whether s is valid UTF-8 holding no unprintable
// character. The empty string is valid.
func Valid(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if Unprintable(r) {
			return false
		}
	}
	return true
}

// Clean returns s without its invalid UTF-8 and unprintable characters,
// the rest in order. Spaces are kept as they are: trimming is the
// caller's decision.
func Clean(s string) string {
	if Valid(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	// Ranging over a string yields utf8.RuneError for each invalid byte,
	// the same value a real U+FFFD gives; only the width tells them
	// apart, so invalid bytes are dropped and a genuine U+FFFD is kept.
	for i, r := range s {
		if r == utf8.RuneError {
			if _, size := utf8.DecodeRuneInString(s[i:]); size == 1 {
				continue
			}
		}
		if !Unprintable(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ValidWithin is the rule for a name a person chooses -- a username, a
// token name, a device ID, a passkey name, a sign-out reason (#90): s
// is Valid, holds no U+FFFD, and is at most maxChars characters long,
// each code point counting as one whatever its width in bytes. The
// empty string passes.
//
// U+FFFD is refused because a browser only sends it when the text it
// was given was broken (and JSON decoding turns invalid UTF-8 into it),
// so a name holding one is not what the person typed. Characters, not
// bytes, because a documented maxLength counts characters (JSON Schema
// validation section 6.3.1, NIST SP 800-63B-4 section 3.1.1.2), and a
// byte limit would give non-Latin names fewer letters.
func ValidWithin(s string, maxChars int) bool {
	if !utf8.ValidString(s) {
		return false
	}
	n := 0
	for _, r := range s {
		n++
		if n > maxChars || r == utf8.RuneError || Unprintable(r) {
			return false
		}
	}
	return true
}
