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
// marks it used until expires -- the sealed ceremony's own Expires.
// Expired entries are dropped on the way, so the map only ever holds the
// ceremonies of the last few minutes.
//
// The entry must live exactly as long as open would still accept the
// ceremony, and open compares the sealed Expires, which has been through
// JSON and so carries only a wall-clock reading, against time.Now. The
// entry's expiry is therefore that same wall-clock instant, stripped of
// any monotonic reading (Round(0)), so dropping it is decided on the same
// clock. An expiry computed as now.Add(...) would carry time.Now's
// monotonic reading, and if the wall clock stepped back the entry could
// be dropped while the ceremony still looked unexpired -- reopening
// replay for an authenticator whose count stays at 0.
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
	c.seen[challenge] = expires.Round(0)
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
