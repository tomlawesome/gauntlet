// Copied from mikroview's internal/auth/session.go, with names kept
// (docs/adr/0001-shared-auth-module.md decision 3). One change from
// mikroview, from docs/design.md §1.3:
//
//   - NewSessionStore(ttl, maxLifetime) replaces mikroview's two
//     constructors, NewSessionStore(ttl) (no ceiling) and
//     NewSessionStoreWithMaxLifetime(ttl, maxLifetime). A caller that
//     wants no ceiling passes 0, exactly as mikroview's own
//     NewSessionStoreWithMaxLifetime(ttl, 0) already means "no ceiling"
//     -- one entry point rather than two ways to ask for the same
//     thing.
package gauntlet

import (
	"sync"
	"time"
)

// Session is deliberately an opaque random ID (see newID), not a JWT --
// easy to revoke (delete it server-side) and needs no signing-key
// management. Sessions are in-memory only, unlike accounts themselves:
// losing them on restart just means re-login, not the lockout/silent-
// reopen risk losing an account would carry (docs/design.md §1.7).
type Session struct {
	ID     string
	UserID string
	// IssuedAt is set once at Create and never changed by Validate's
	// sliding-expiration renewal -- it answers "when did this specific
	// login happen," used to invalidate a session issued before a
	// password reset (see User.PasswordChangedAt), which ExpiresAt alone
	// can't express.
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// SessionStore holds active sessions, mutex-protected like every other
// piece of mikroview's runtime state.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]Session
	// byUser holds each user's session IDs, kept in step with sessions,
	// so RevokeAllForUser touches only that user's entries. Signing out
	// everywhere is open to any signed-in user; walking the whole map
	// under the lock for it would let a loop of those calls stall every
	// other request.
	byUser map[string]map[string]struct{}
	ttl    time.Duration
	// maxLifetime caps how long a session can live from IssuedAt,
	// regardless of how often it is used.
	//
	// Without it the sliding renewal below has no ceiling at all: a
	// session used even once per ttl never expires, so a browser left
	// signed in on a shared machine, or a cookie taken months ago, stays
	// valid indefinitely (#294 item 3). ttl answers "has this been
	// abandoned"; this answers "how old is too old", and the two are
	// different questions.
	//
	// Zero disables the ceiling, which is what the CLI tooling and most
	// tests want -- they construct a store to exercise one behaviour and
	// have no interest in wall-clock ageing.
	maxLifetime time.Duration
	// order holds every session ID in the order the sweep reaches them:
	// Create appends, and each Create checks the first few (see
	// sweepBatch), dropping a dead one and moving a live one to the back.
	// Validate evicts an expired session only when that exact ID is
	// presented again, so a login whose cookie is never used again -- a
	// script that signs in per poll, a browser that never comes back --
	// would otherwise stay in the map for the life of the process.
	//
	// The sweep used to walk the whole map in one Create whenever its
	// size doubled, holding the lock throughout: cheap on average, but
	// with a large map that one call stalled every Validate and Create
	// behind it (#24). Checking a fixed few per Create spreads the same
	// walk evenly instead. A revoked or already-evicted ID is simply
	// dropped when the sweep reaches it, so Revoke and RevokeAllForUser
	// need not touch order at all.
	order idQueue
	// sweepVisits counts the entries the sweep has checked, so tests can
	// see how much work one call did without timing it.
	sweepVisits int
	// revokeVisits counts the sessions RevokeAllForUser has checked, for
	// the same reason.
	revokeVisits int
}

// sweepBatch is how many entries of order each Create checks. It must
// be above 1: every Create adds an entry, so checking only one would
// never catch up. With 4, a dead session is dropped within a quarter as
// many Creates as the store holds, so under steady logins the map holds
// about a third more than its live sessions.
const sweepBatch = 4

// NewSessionStore builds a store with sliding expiry ttl, capped at
// maxLifetime from each session's IssuedAt however often it is used. A
// zero or negative maxLifetime means no ceiling -- see maxLifetime's
// doc comment.
func NewSessionStore(ttl, maxLifetime time.Duration) *SessionStore {
	if maxLifetime < 0 {
		maxLifetime = 0
	}
	return &SessionStore{sessions: make(map[string]Session), byUser: make(map[string]map[string]struct{}), ttl: ttl, maxLifetime: maxLifetime}
}

// Create starts a new session for userID.
func (s *SessionStore) Create(userID string, now time.Time) Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := Session{ID: newID(), UserID: userID, IssuedAt: now, ExpiresAt: now.Add(s.ttl)}
	s.sessions[sess.ID] = sess
	if s.byUser[userID] == nil {
		s.byUser[userID] = make(map[string]struct{})
	}
	s.byUser[userID][sess.ID] = struct{}{}
	s.order.push(sess.ID)
	s.sweepLocked(now)
	return sess
}

// sweepLocked checks the next sweepBatch entries of order: an ID no
// longer in the map, or a session Validate would refuse at now, is
// dropped; a live one goes to the back of order.
func (s *SessionStore) sweepLocked(now time.Time) {
	for range sweepBatch {
		id, ok := s.order.pop()
		if !ok {
			return
		}
		s.sweepVisits++
		sess, ok := s.sessions[id]
		if !ok {
			continue
		}
		if s.expired(sess, now) {
			s.removeLocked(sess)
			continue
		}
		s.order.push(id)
	}
}

// idQueue is a first-in, first-out queue of session IDs kept in
// fixed-size blocks. A plain slice used as a queue would copy every ID
// it holds each time it outgrew its array -- the same whole-store pause
// under the lock the incremental sweep exists to avoid, only smaller.
// Here growing allocates one block, and the list of blocks it extends
// holds one pointer per idBlock IDs.
type idQueue struct {
	blocks [][]string // blocks[0][head:] is the front; only the last is part-filled
	head   int
	n      int
}

const idBlock = 1024

func (q *idQueue) push(id string) {
	if len(q.blocks) == 0 || len(q.blocks[len(q.blocks)-1]) == idBlock {
		q.blocks = append(q.blocks, make([]string, 0, idBlock))
	}
	last := len(q.blocks) - 1
	q.blocks[last] = append(q.blocks[last], id)
	q.n++
}

func (q *idQueue) pop() (string, bool) {
	if q.n == 0 {
		return "", false
	}
	id := q.blocks[0][q.head]
	q.blocks[0][q.head] = ""
	q.head++
	q.n--
	if q.head == idBlock {
		q.blocks[0] = nil
		q.blocks = q.blocks[1:]
		q.head = 0
	}
	return id, true
}

// expired reports whether Validate would refuse sess at now.
func (s *SessionStore) expired(sess Session, now time.Time) bool {
	if now.After(sess.ExpiresAt) {
		return true
	}
	deadline, capped := s.deadline(sess)
	return capped && now.After(deadline)
}

// Validate reports whether id is a live session, extending its expiry
// on success (sliding expiration -- stays alive while actively used,
// rather than forcing a re-login mid-session at a fixed wall-clock
// time). An expired session is evicted on the read that finds it,
// rather than needing a separate sweep.
//
// The renewal is bounded by maxLifetime: a session is refused once it is
// older than that from IssuedAt, however recently it was used, and the
// renewed expiry never reaches past that point either. Without the
// second half the ceiling would be checked but not enforced -- a session
// could sit with an ExpiresAt beyond its own deadline and be accepted by
// any code reading ExpiresAt rather than calling this.
func (s *SessionStore) Validate(id string, now time.Time) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return Session{}, false
	}
	if now.After(sess.ExpiresAt) {
		s.removeLocked(sess)
		return Session{}, false
	}
	if deadline, capped := s.deadline(sess); capped {
		if now.After(deadline) {
			s.removeLocked(sess)
			return Session{}, false
		}
		sess.ExpiresAt = earliest(now.Add(s.ttl), deadline)
	} else {
		sess.ExpiresAt = now.Add(s.ttl)
	}
	s.sessions[id] = sess
	return sess, true
}

// deadline is the absolute moment sess stops being usable, and whether
// there is one at all.
func (s *SessionStore) deadline(sess Session) (time.Time, bool) {
	if s.maxLifetime <= 0 {
		return time.Time{}, false
	}
	return sess.IssuedAt.Add(s.maxLifetime), true
}

func earliest(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// Revoke ends one session (logout).
func (s *SessionStore) Revoke(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[id]; ok {
		s.removeLocked(sess)
	}
}

// removeLocked drops sess from both sessions and byUser.
func (s *SessionStore) removeLocked(sess Session) {
	delete(s.sessions, sess.ID)
	ids := s.byUser[sess.UserID]
	delete(ids, sess.ID)
	if len(ids) == 0 {
		delete(s.byUser, sess.UserID)
	}
}

// RevokeAllForUser ends every session belonging to userID -- used when
// a password is reset (via the CLI recovery tool), so a stolen session
// doesn't survive a deliberate credential reset.
func (s *SessionStore) RevokeAllForUser(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.byUser[userID] {
		s.revokeVisits++
		delete(s.sessions, id)
	}
	delete(s.byUser, userID)
}
