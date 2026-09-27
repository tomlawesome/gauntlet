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
	ttl      time.Duration
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
	// nextSweep is the map size at which Create next drops every
	// expired entry. Validate evicts an expired session only when that
	// exact ID is presented again, so a login whose cookie is never
	// used again -- a script that signs in per poll, a browser that
	// never comes back -- would otherwise stay in the map for the life
	// of the process. Sweeping at a size that doubles each time keeps
	// the cost amortised at O(1) per Create.
	nextSweep int
}

// minSessionSweep is the smallest map size at which Create sweeps.
const minSessionSweep = 1024

// NewSessionStore builds a store with sliding expiry ttl, capped at
// maxLifetime from each session's IssuedAt however often it is used. A
// zero or negative maxLifetime means no ceiling -- see maxLifetime's
// doc comment.
func NewSessionStore(ttl, maxLifetime time.Duration) *SessionStore {
	if maxLifetime < 0 {
		maxLifetime = 0
	}
	return &SessionStore{sessions: make(map[string]Session), ttl: ttl, maxLifetime: maxLifetime, nextSweep: minSessionSweep}
}

// Create starts a new session for userID.
func (s *SessionStore) Create(userID string, now time.Time) Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := Session{ID: newID(), UserID: userID, IssuedAt: now, ExpiresAt: now.Add(s.ttl)}
	s.sessions[sess.ID] = sess
	if len(s.sessions) >= s.nextSweep {
		s.sweepExpiredLocked(now)
		s.nextSweep = max(2*len(s.sessions), minSessionSweep)
	}
	return sess
}

// sweepExpiredLocked drops every session Validate would refuse at now.
func (s *SessionStore) sweepExpiredLocked(now time.Time) {
	for id, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, id)
			continue
		}
		if deadline, capped := s.deadline(sess); capped && now.After(deadline) {
			delete(s.sessions, id)
		}
	}
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
		delete(s.sessions, id)
		return Session{}, false
	}
	if deadline, capped := s.deadline(sess); capped {
		if now.After(deadline) {
			delete(s.sessions, id)
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
	delete(s.sessions, id)
}

// RevokeAllForUser ends every session belonging to userID -- used when
// a password is reset (via the CLI recovery tool), so a stolen session
// doesn't survive a deliberate credential reset.
func (s *SessionStore) RevokeAllForUser(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.UserID == userID {
			delete(s.sessions, id)
		}
	}
}
