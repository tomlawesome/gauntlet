package gauntlet

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"time"
)

// The known-browser allowance (#44). Escalating lockouts and the
// disable at MaxConsecutiveLoginFailures stop a guesser, but they stop
// the account's owner with them: anyone who knows a username can lock
// its owner out by guessing wrong five times. So a browser that has
// completed a sign-in on an account is remembered on that account's
// record, and keeps a small allowance of its own while the account is
// locked out (LoginLimiter.ReserveKnownBrowser). A stranger's browser
// has never completed a sign-in there and gets nothing.
//
// The browser carries a random token for each account it has completed
// a sign-in on -- 32 bytes each, base64url, naming nothing, up to four in
// one cookie (gate's knownbrowser.go) -- and an account's record carries
// only its own token's SHA-256, the way an API token is kept (token.go):
// the document holds no value that works as the cookie, and checking
// one needs no key. That is also why it is not sealed with gate's
// pending-login codec: that key is per process, so a long-lived cookie
// sealed with it would die at every deploy. Nothing is keyed on the
// client's address; shared addresses make that useless.
//
// Each completed sign-in rotates the token (RememberBrowser): the
// browser's old one leaves the record in the same write that adds its
// new one, so a browser holds at most one entry on an account, and the
// entry is renewed for another KnownBrowserLifetime.
//
// What a stolen token gains is the allowance and nothing more: the
// limiter's threshold of guesses per window during a lockout, each one
// counted toward the disable. It never stands in for a password, a
// second factor or a session.

// MaxKnownBrowsers is how many browsers one account remembers at a
// time (owner, 2026-10-02). Remembering one more evicts the one
// remembered longest ago among those never confirmed
// (KnownBrowser.Confirmed), and only when none is left a confirmed one,
// so an account's record never grows past it however many browsers sign
// in.
const MaxKnownBrowsers = 3

// KnownBrowserLifetime is how long a remembered browser keeps the
// allowance after the sign-in that remembered it: 45 days (owner,
// 2026-10-02), renewed at each completed sign-in from that browser.
// Checked against KnownBrowser.IssuedAt on the server
// (Store.KnowsBrowser); a cookie's Max-Age only tells the browser when
// to forget it.
const KnownBrowserLifetime = 45 * 24 * time.Hour

// knownBrowserTokenBytes is the token's size before encoding: 256 bits,
// twice the 128 a session ID has (newID), so it cannot be guessed.
const knownBrowserTokenBytes = 32

// KnownBrowser is one browser an account remembers (User.KnownBrowsers).
type KnownBrowser struct {
	// Hash is the hex SHA-256 of the token the browser carries, never
	// the token itself. Store.List blanks it.
	Hash string `json:"hash"`
	// IssuedAt is when the token was issued: the browser's latest
	// completed sign-in on the account. It ages out KnownBrowserLifetime
	// later, and the oldest goes first, within its class (Confirmed),
	// when the account remembers more than MaxKnownBrowsers.
	IssuedAt time.Time `json:"issuedAt"`
	// Confirmed is true once the browser has brought its token back: the
	// entry replaced one it carried (RememberSignIn). A browser that
	// signs in once and never returns stays unconfirmed, and unconfirmed
	// entries are evicted first, so a run of cookie-less sign-ins cannot
	// push out the browsers the owner uses every day. An unconfirmed
	// entry is still known (KnowsBrowser): coming back is what confirms
	// it. No document version bump: version 9 is new in the release that
	// adds this field, and an older entry reads as unconfirmed.
	Confirmed bool `json:"confirmed,omitempty"`
}

// live reports whether b still grants the allowance at now: issued no
// longer than KnownBrowserLifetime ago, and not after now. An IssuedAt
// ahead of now is a clock that has stepped back since, or another
// process's clock running ahead; it is refused until now reaches it,
// failing closed as the limiter's own reading of a future password
// change does.
func (b KnownBrowser) live(now time.Time) bool {
	return !b.IssuedAt.After(now) && now.Sub(b.IssuedAt) < KnownBrowserLifetime
}

// knownBrowserHash is the form a token is stored and compared in.
func knownBrowserHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// wellFormedKnownBrowserToken reports whether token has the shape
// RememberBrowser issues, so anything else -- a forged or truncated
// cookie -- is refused before it is hashed or compared.
func wellFormedKnownBrowserToken(token string) bool {
	if len(token) != base64.RawURLEncoding.EncodedLen(knownBrowserTokenBytes) {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(b) == knownBrowserTokenBytes
}

// newKnownBrowserToken returns a fresh token, base64url without padding.
func newKnownBrowserToken() string {
	b := make([]byte, knownBrowserTokenBytes)
	if _, err := rand.Read(b); err != nil {
		// As newID: no CSPRNG, nothing in this package can be made safely.
		panic("gauntlet: crypto/rand unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// RememberBrowser remembers a browser that has just completed a sign-in
// on accountID, and returns the token to hand it: a new one every call.
// replacing is the token the browser already carried, if any ("" for
// none); its entry leaves accountID's record in the same write, so a
// browser renews its own entry instead of piling up new ones. In that
// write too, entries past KnownBrowserLifetime are dropped, and if the
// account would then remember more than MaxKnownBrowsers the ones
// issued longest ago go, unconfirmed ones (KnownBrowser.Confirmed)
// before confirmed ones; the new entry always stays.
//
// One write per call. A failed write is the caller's to log: the
// sign-in it follows has already succeeded and should not fail over
// this, and the browser keeps whatever token it had. Refused with
// ErrUserNotFound for an account that does not exist.
func (s *Store) RememberBrowser(accountID, replacing string, now time.Time) (string, error) {
	return s.RememberSignIn(accountID, replacing, "", nil, now)
}

// ClearKnownBrowsers forgets every browser accountID remembers, so none
// of them keeps an allowance any longer, and with them the countries it
// signs in from and its last place (#55), and an administrator's
// allowance of its next sign-in (#81): sign out everywhere forgets
// what the account trusts, so the next sign-in sets a fresh baseline. Called by sign out everywhere
// -- whose own browser is then remembered again as its new session is
// issued -- and done by IssueResetCode in its own write.
//
// Deliberately not by the other writes that end sessions -- a signed-in
// password change, an SSO link, UnlockLogin, or the forced change after
// a run of second-factor failures: those are when the owner most needs
// the allowance, and a guesser's browser never completed a sign-in to
// be remembered.
//
// Refused with ErrUserNotFound for an account that does not exist; an
// account remembering none of these costs no write.
func (s *Store) ClearKnownBrowsers(accountID string) error {
	s.reloadIfStale()
	return s.mutate(func(st *storeState) error {
		u, ok := st.byID[accountID]
		if !ok {
			return ErrUserNotFound
		}
		if len(u.KnownBrowsers) == 0 && len(u.SeenCountries) == 0 && u.LastPlace == nil && u.SignInAllowedUntil.IsZero() {
			return errNoChange
		}
		u.KnownBrowsers, u.SeenCountries, u.LastPlace = nil, nil, nil
		u.SignInAllowedUntil = time.Time{}
		return nil
	})
}

// KnowsBrowser reports whether token is one RememberBrowser issued for
// accountID that is still live at now: its hash is on the account's
// record, issued less than KnownBrowserLifetime ago. A malformed token,
// an unknown account or a token remembered by another account is false.
// Compared in constant time against every entry, as the setup and
// unlock codes are, so how far a forged token matched is not timed.
func (s *Store) KnowsBrowser(accountID, token string, now time.Time) bool {
	if !wellFormedKnownBrowserToken(token) {
		return false
	}
	want := []byte(knownBrowserHash(token))

	s.reloadIfStale()
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[accountID]
	if !ok {
		return false
	}
	found := false
	for _, b := range u.KnownBrowsers {
		if subtle.ConstantTimeCompare([]byte(b.Hash), want) == 1 && b.live(now) {
			found = true
		}
	}
	return found
}
