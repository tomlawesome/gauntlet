package passkey

import (
	"sync"
	"time"
)

// ceremonyLifetime is how long a ceremony may take from Begin to
// Finish: Begin seals Expires this far ahead, and Finish (and the
// library) refuse it after that. Five minutes, mikroview's number: long
// enough to unlock a phone or touch a security key, short enough that
// an abandoned ceremony does not leave a live one-shot ticket in a
// browser. gate's ceremony cookies carry the same Max-Age.
const ceremonyLifetime = 5 * time.Minute

// spentChallenges remembers the challenge of every login ceremony that
// finished, until it would have expired anyway. The ceremony state rides
// in a sealed value the browser holds, so without this the server keeps
// nothing saying a ceremony was used, and an authenticator that always
// reports a sign count of zero (most platform passkeys) gives the
// counter nothing to catch a replay with: the same assertion could open
// a second session.
type spentChallenges struct {
	mu   sync.Mutex
	seen map[string]time.Time // challenge -> when it can be forgotten
}

// claim reports whether challenge is being used for the first time, and
// marks it used. Expired entries are dropped on the way, so the map only
// ever holds the ceremonies of the last few minutes.
func (c *spentChallenges) claim(challenge string, expires, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = make(map[string]time.Time)
	}
	for k, until := range c.seen {
		if !now.Before(until) {
			delete(c.seen, k)
		}
	}
	if _, used := c.seen[challenge]; used {
		return false
	}
	if expires.Before(now.Add(ceremonyLifetime)) {
		expires = now.Add(ceremonyLifetime)
	}
	c.seen[challenge] = expires
	return true
}

// spent is claimed by FinishLogin only, as in mikroview. A login is
// final inside FinishLogin -- the signature is the proof -- so that is
// where its challenge is spent. A registration is final only at
// Store.AddPasskey, outside this package, so FinishRegistration claims
// nothing: a claim there would fire before the store said yes, and
// AddPasskey's duplicate check already refuses a credential registered
// twice.
var spent = &spentChallenges{}
