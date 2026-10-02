// Package spent remembers one-time keys -- a passkey login challenge, a
// pending login's ID -- until the thing they unlock could no longer be
// accepted anyway, so each can be used once. gauntlet/passkey and gate
// share this one implementation (rulings R2 on #20, in the second and
// third addenda to the G8 design note).
//
// The contract, in plain words:
//
//   - A key is forgotten on the caller's own expiry: the forget time the
//     caller passes to Claim is the sealed expiry its acceptance check
//     reads (a login ceremony's Expires; a pending login's IssuedAt plus
//     its maximum age). Both have been through JSON and carry only a
//     wall-clock reading, and Claim and Spent strip the monotonic
//     reading from now as well, so every comparison here is wall clock
//     against wall clock -- the same clock the acceptance check uses. A
//     key is therefore never forgotten while what it guards would still
//     be accepted, whatever the clock does in between.
//   - Forgetting happens late, never early. Keys are queued in claim
//     order and dropped only from the head, stopping at the first one
//     whose forget time has not passed, so a key behind a longer-lived
//     one stays (and stays refused) until that one goes. Each key is
//     queued once and dropped once, so a claim costs constant time on
//     average however large the set.
//   - The set is bounded by the successful uses of one lifetime: a key
//     outlives its own forget time by at most one lifetime, plus the size
//     of any backward clock step taken between issue and claim. Every
//     key costs a correct password or a signed assertion, both
//     rate-limited, so there is no hard cap.
package spent

import (
	"sync"
	"time"
)

type entry struct {
	key      string
	forgetAt time.Time
}

// Set is a set of spent keys. The zero value is not ready; use New.
type Set struct {
	mu    sync.Mutex
	seen  map[string]time.Time // key -> its forget time
	queue []entry              // claim order; queue[head:] is live
	head  int
}

// New returns an empty Set.
func New() *Set {
	return &Set{seen: make(map[string]time.Time)}
}

// Claim reports whether key is being used for the first time and, if so,
// records it until forgetAt. A key already held is refused whatever now
// says. A forgetAt already past is still recorded; it goes at the next
// prune that reaches it. Callers claim only after their acceptance check
// has passed on that same forgetAt, so a past one arises only at the
// boundary, where the acceptance check already refuses.
func (s *Set) Claim(key string, forgetAt, now time.Time) bool {
	now, forgetAt = now.Round(0), forgetAt.Round(0)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	if _, held := s.seen[key]; held {
		return false
	}
	s.seen[key] = forgetAt
	s.queue = append(s.queue, entry{key: key, forgetAt: forgetAt})
	return true
}

// Spent reports whether key is held, after pruning the same way Claim
// does. It records nothing.
func (s *Set) Spent(key string, now time.Time) bool {
	now = now.Round(0)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	_, held := s.seen[key]
	return held
}

// pruneLocked drops keys from the head of the queue while their forget
// time has passed, stopping at the first that has not. Once the dropped
// prefix is more than half the queue, the live part is copied to a fresh
// slice so the backing array does not hold onto it.
func (s *Set) pruneLocked(now time.Time) {
	for s.head < len(s.queue) && !now.Before(s.queue[s.head].forgetAt) {
		delete(s.seen, s.queue[s.head].key)
		s.queue[s.head] = entry{}
		s.head++
	}
	if s.head > 0 && s.head > len(s.queue)/2 {
		s.queue = append([]entry(nil), s.queue[s.head:]...)
		s.head = 0
	}
}
