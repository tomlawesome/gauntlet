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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tomlawesome/gauntlet/internal/plaintext"
)

// MaxSessionIdle is the longest a session may go unused before gate.New
// refuses to start: NIST SP 800-63B-4 AAL2 caps inactivity at one hour
// (§2.2.3, §5.2). The owner adopted this over the consumers' previous
// 24-hour idle value on 2026-10-02 (gauntlet#51) -- see
// docs/security-by-design.md's Sessions table.
//
// This is a cap gate.New enforces on Deps.Sessions, not a limit
// SessionStore itself imposes -- a caller using SessionStore directly
// (the CLI tooling, this package's own tests) is unaffected.
const MaxSessionIdle = time.Hour

// MaxSessionLifetime is the longest a session may live from IssuedAt,
// however often it is used, before gate.New refuses to start: NIST SP
// 800-63B-4 AAL2 caps the overall session at 24 hours (§2.2.3, §5.2).
// The owner adopted this over the consumers' previous 7-day ceiling on
// 2026-10-02 (gauntlet#51).
//
// As with MaxSessionIdle, this is a cap gate.New enforces, not one
// SessionStore itself imposes.
const MaxSessionLifetime = 24 * time.Hour

// MaxSessionUserAgent and MaxSessionAddress bound what CreateFrom keeps
// of a SessionClient, in bytes, after it has dropped the characters
// cleanClientText refuses. The User-Agent header is the client's to
// choose and has no length limit of its own short of the server's
// header cap, and every session holds its copy in memory until the
// session ends -- at most MaxSessionLifetime when gate is in front --
// so the cap is what bounds that memory, not the header. 256 bytes holds
// every real browser's agent string whole; 64 holds an IPv6 address with
// a zone (gauntlet#48).
const (
	MaxSessionUserAgent = 256
	MaxSessionAddress   = 64
)

// SessionClient is what a session records about the browser that signed
// in, so its owner can tell one session from another in a list of their
// own sessions (ASVS 7.5.2, gauntlet#48). It is captured once, when the
// session is created, and never updated: a session is one sign-in, and
// the address it signed in from is the fact the list shows. It lives in
// memory with the session and is never written to the accounts
// document.
//
// Address and UserAgent are as the client presented them, not verified:
// Address is whatever the application's own client-address policy
// resolved (gate.Config.ClientIP, which may read a proxy header), and
// UserAgent is the header the browser chose to send. They help a person
// recognise their own devices; they prove nothing about who holds a
// session.
//
// Country is an ISO 3166-1 alpha-2 code looked up from Address when the
// attempt was made (#54), or empty when it is not known: no lookup was
// configured, the address was private, or the lookup had nothing for it.
// Unlike Address and UserAgent it is not the client's own word -- it
// comes from gate.Config.Country, not a header -- so CreateFrom passes
// it through unchanged rather than cleaning or cutting it.
//
// Unusual is the unusual-sign-in signals the sign-in raised (#55), none
// for an ordinary one: gate's judgement, not the client's word, so it
// too passes through CreateFrom unchanged.
//
// Method is how the sign-in was made (#77): gate's own record, passed
// through CreateFrom unchanged, and empty for a session made without
// one. A resumed session keeps the method of the sign-in it continues.
type SessionClient struct {
	Address   string
	UserAgent string
	Country   string
	Unusual   SignInSignals
	Method    SignInMethod
}

// Clean is c with Address and UserAgent cleaned and cut the way every
// session and sign-in record keeps them: control and Unicode formatting
// characters, the line and paragraph separators (unprintable) and
// invalid UTF-8 dropped, then UserAgent cut to
// MaxSessionUserAgent bytes and Address to MaxSessionAddress, never
// mid-character. Both are the client's own word, so neither may carry a
// terminal escape, a bidirectional override, a line break or a megabyte
// of padding into a page, a log or a message that later shows them.
// Country is kept only as exactly two ASCII letters, upper-cased (an
// ISO 3166-1 alpha-2 code); anything else a lookup returned becomes "",
// no country. Unusual and Method are gate's own and pass through
// unchanged. It is one rule: CreateFrom, CreateContinuing and Resume
// clean through it, and gate cleans through it the client it hands to a
// notice or a confirmation code.
func (c SessionClient) Clean() SessionClient {
	c.Address = cleanClientText(c.Address, MaxSessionAddress)
	c.UserAgent = cleanClientText(c.UserAgent, MaxSessionUserAgent)
	c.Country = cleanCountry(c.Country)
	return c
}

// cleanCountry returns s upper-cased when it is exactly two ASCII
// letters, else "".
func cleanCountry(s string) string {
	if len(s) != 2 {
		return ""
	}
	b := []byte(s)
	for i, ch := range b {
		switch {
		case 'a' <= ch && ch <= 'z':
			b[i] = ch - 'a' + 'A'
		case 'A' <= ch && ch <= 'Z':
		default:
			return ""
		}
	}
	return string(b)
}

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
	// password reset or an SSO link (see User.SessionCutoff), which
	// ExpiresAt alone can't express.
	IssuedAt  time.Time
	ExpiresAt time.Time
	// LastUsedAt is the last time Validate accepted this session (IssuedAt
	// until then) -- what a session list shows so a person can spot a
	// session they are not using.
	LastUsedAt time.Time
	// Client is the browser this session signed in from, as CreateFrom
	// recorded it; empty when created through Create.
	Client SessionClient
}

// Ref is a one-way reference to this session: the first 32 hex
// characters (128 bits) of SHA-256 over its ID. A session list shows
// this and never the ID, because the ID is the session cookie itself --
// a page that rendered it would hand a copy of every one of the
// person's sessions to anything that can read the page. The ref names a
// session well enough to end it (SessionStore.RevokeRef, which only
// ever acts within one account), and cannot be turned back into a
// cookie. Derived on each call rather than stored, so it costs no
// memory and cannot drift from the ID.
func (s Session) Ref() string {
	sum := sha256.Sum256([]byte(s.ID))
	return hex.EncodeToString(sum[:16])
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

// Limits returns the store's configured idle timeout and lifetime
// ceiling (0 meaning no ceiling, as NewSessionStore and maxLifetime's
// doc comment describe) -- what gate.New reads to refuse a
// Deps.Sessions store configured outside MaxSessionIdle/
// MaxSessionLifetime, without exposing the fields themselves.
func (s *SessionStore) Limits() (idle, ceiling time.Duration) {
	return s.ttl, s.maxLifetime
}

// Create starts a new session for userID, recording no client -- the
// CLI tooling and tests that have no request to read one from. It is
// CreateFrom with an empty SessionClient.
func (s *SessionStore) Create(userID string, now time.Time) Session {
	return s.CreateFrom(userID, SessionClient{}, now)
}

// CreateFrom starts a new session for userID, recording client so the
// account's owner can recognise it later (ListForUser). The client is
// cleaned and cut before it is kept (SessionClient.Clean).
func (s *SessionStore) CreateFrom(userID string, client SessionClient, now time.Time) Session {
	client = client.Clean()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := Session{ID: newID(), UserID: userID, IssuedAt: now, ExpiresAt: now.Add(s.ttl), LastUsedAt: now, Client: client}
	s.sessions[sess.ID] = sess
	if s.byUser[userID] == nil {
		s.byUser[userID] = make(map[string]struct{})
	}
	s.byUser[userID][sess.ID] = struct{}{}
	s.order.push(sess.ID)
	s.sweepLocked(now)
	return sess
}

// CreateContinuing starts a new session for from.UserID that continues
// from rather than starting a new sign-in: a new ID, but from's IssuedAt,
// so the lifetime ceiling does not move, and from's unusual-sign-in
// signals and method, since the sign-in they describe was judged once
// already. Its client is client, cleaned as CreateFrom does. Its expiry
// is now plus the idle timeout, never past the ceiling.
//
// It is the one way a route that rotates a session without a whole
// sign-in -- sign out everywhere, which asks at most for the password
// again -- keeps the sign-in's lifetime ceiling. Issuing through CreateFrom there would start the ceiling
// again from now, so anyone holding a live cookie could call the route
// once an idle period and keep a session for ever. It does not check or
// end from; the caller has already done whatever it needs to.
func (s *SessionStore) CreateContinuing(from Session, client SessionClient, now time.Time) Session {
	client = client.Clean()
	client.Unusual, client.Method = from.Client.Unusual, from.Client.Method
	s.mu.Lock()
	defer s.mu.Unlock()
	expires := now.Add(s.ttl)
	if deadline, capped := s.deadline(from); capped {
		expires = earliest(expires, deadline)
	}
	sess := Session{ID: newID(), UserID: from.UserID, IssuedAt: from.IssuedAt, ExpiresAt: expires, LastUsedAt: now, Client: client}
	s.sessions[sess.ID] = sess
	if s.byUser[sess.UserID] == nil {
		s.byUser[sess.UserID] = make(map[string]struct{})
	}
	s.byUser[sess.UserID][sess.ID] = struct{}{}
	s.order.push(sess.ID)
	s.sweepLocked(now)
	return sess
}

// cleanClientText is Clean's rule for one SessionClient field:
// plaintext.Clean drops what is not plain text rather than refusing it
// -- a session is never refused for what a browser sent -- and what is
// left is cut to at most maxBytes on a character boundary. Client text
// keeps a byte cap (#90): it is not a name a person chose.
func cleanClientText(s string, maxBytes int) string {
	s = plaintext.Clean(s)
	if len(s) <= maxBytes {
		return s
	}
	cut := 0
	for i := range s {
		if i > maxBytes {
			break
		}
		cut = i
	}
	return s[:cut]
}

// sweepLocked checks the next sweepBatch entries of order: an ID no
// longer in the map, or a session that can never be used again at now
// (gone), is dropped; a live one, or a timed-out one that can still be
// resumed, goes to the back of order.
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
		if s.gone(sess, now) {
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

// expired reports whether Validate would refuse sess at now: idle past
// its expiry, or past the lifetime ceiling.
func (s *SessionStore) expired(sess Session, now time.Time) bool {
	if now.After(sess.ExpiresAt) {
		return true
	}
	deadline, capped := s.deadline(sess)
	return capped && now.After(deadline)
}

// gone reports whether sess can never be used again at now, so the store
// may drop it: past the lifetime ceiling, or idle past its expiry in a
// store with no ceiling. An idle-expired session inside a ceiling is
// not gone but resumable (see Resumable), held until the ceiling.
func (s *SessionStore) gone(sess Session, now time.Time) bool {
	if deadline, capped := s.deadline(sess); capped {
		return now.After(deadline)
	}
	return now.After(sess.ExpiresAt)
}

// resumable reports whether sess has timed out through inactivity while
// still inside its lifetime ceiling.
func (s *SessionStore) resumable(sess Session, now time.Time) bool {
	return now.After(sess.ExpiresAt) && !s.gone(sess, now)
}

// Validate reports whether id is a live session, extending its expiry
// on success (sliding expiration -- stays alive while actively used,
// rather than forcing a re-login mid-session at a fixed wall-clock
// time). A session that can never be used again is evicted on the read
// that finds it, rather than needing a separate sweep.
//
// The renewal is bounded by maxLifetime: a session is refused once it is
// older than that from IssuedAt, however recently it was used, and the
// renewed expiry never reaches past that point either. Without the
// second half the ceiling would be checked but not enforced -- a session
// could sit with an ExpiresAt beyond its own deadline and be accepted by
// any code reading ExpiresAt rather than calling this.
//
// A session idle past its expiry but inside the ceiling is refused but
// kept: it is "timed out, resumable" (Resumable, Resume), and nothing
// here ever lets it authenticate a request. Refusing it does not extend
// it either.
func (s *SessionStore) Validate(id string, now time.Time) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return Session{}, false
	}
	if s.gone(sess, now) {
		s.removeLocked(sess)
		return Session{}, false
	}
	if now.After(sess.ExpiresAt) {
		return Session{}, false // timed out, resumable
	}
	if deadline, capped := s.deadline(sess); capped {
		sess.ExpiresAt = earliest(now.Add(s.ttl), deadline)
	} else {
		sess.ExpiresAt = now.Add(s.ttl)
	}
	sess.LastUsedAt = now
	s.sessions[id] = sess
	return sess, true
}

// Resumable returns the session id names when it has timed out through
// inactivity (MaxSessionIdle's job in gate) but is still inside its
// lifetime ceiling, so its owner may resume it with a password
// (NIST SP 800-63B-4 section 2.2.3, gauntlet#71). It reports false for
// a live session, an unknown ID, and one past the ceiling -- which it
// also evicts. A store with no ceiling has no resumable sessions.
//
// It changes nothing else, and the session it returns authenticates
// nothing: Validate still refuses it. Whether the caller may resume it
// -- the password, the account's state -- is the caller's to check,
// then Resume.
func (s *SessionStore) Resumable(id string, now time.Time) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return Session{}, false
	}
	if s.gone(sess, now) {
		s.removeLocked(sess)
		return Session{}, false
	}
	if !s.resumable(sess, now) {
		return Session{}, false
	}
	return sess, true
}

// Resume ends the timed-out session id names and starts a new one for
// the same account in one step, under the lock, so two requests resuming
// one session cannot both succeed: the second finds it gone and gets
// false. The new session has a new ID (ASVS 7.2.4), the old session's
// IssuedAt -- the lifetime ceiling does not move -- and its unusual-
// sign-in signals and method, since it continues a sign-in already judged; its
// client is client, cleaned as CreateFrom does. Its expiry is now plus
// the idle timeout, never past the ceiling.
//
// It reports false, changing nothing, unless id is Resumable at now.
func (s *SessionStore) Resume(id string, client SessionClient, now time.Time) (Session, bool) {
	client = client.Clean()
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.sessions[id]
	if !ok || !s.resumable(old, now) {
		return Session{}, false
	}
	s.removeLocked(old)
	client.Unusual, client.Method = old.Client.Unusual, old.Client.Method
	deadline, _ := s.deadline(old) // resumable implies a ceiling
	sess := Session{ID: newID(), UserID: old.UserID, IssuedAt: old.IssuedAt, ExpiresAt: earliest(now.Add(s.ttl), deadline), LastUsedAt: now, Client: client}
	s.sessions[sess.ID] = sess
	if s.byUser[sess.UserID] == nil {
		s.byUser[sess.UserID] = make(map[string]struct{})
	}
	s.byUser[sess.UserID][sess.ID] = struct{}{}
	s.order.push(sess.ID)
	s.sweepLocked(now)
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

// ListForUser returns userID's live sessions, newest IssuedAt first --
// what a person sees when they list their own sessions (ASVS 7.5.2,
// gauntlet#48). A session that can never be used again is evicted here
// rather than listed, the same as Validate evicts one it finds gone,
// and a timed-out one that can still be resumed (Resumable) is neither
// listed nor evicted, so the list never shows a session that could not
// be used.
//
// It walks only userID's own entries (byUser), never the whole store,
// for the reason RevokeAllForUser does. It knows nothing of the account
// itself: a session issued before User.SessionCutoff is still returned,
// and dropping it is the caller's job, as it is for Validate.
func (s *SessionStore) ListForUser(userID string, now time.Time) []Session {
	s.mu.Lock()
	var out []Session
	for id := range s.byUser[userID] {
		sess := s.sessions[id]
		if s.gone(sess, now) {
			s.removeLocked(sess)
			continue
		}
		if s.expired(sess, now) {
			continue // timed out, resumable: kept, but not a live session
		}
		out = append(out, sess)
	}
	s.mu.Unlock()
	// Sorted outside the lock: the order is for the reader, and no other
	// request needs to wait on it.
	slices.SortFunc(out, func(a, b Session) int {
		if c := b.IssuedAt.Compare(a.IssuedAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// RevokeRef ends the one session of userID's whose Ref is ref, and
// returns it. It reports false, ending nothing, when no session of
// userID's has that ref -- including when another account's session
// does: the search never leaves userID's own entries, so a ref can only
// ever end a session belonging to the account that asked. Whether the
// session was still live does not matter; ending an expired one only
// evicts it early. The comparison is constant-time per entry, so how
// long a refusal takes says nothing about how near a guess came.
func (s *SessionStore) RevokeRef(userID, ref string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.byUser[userID] {
		sess := s.sessions[id]
		if subtle.ConstantTimeCompare([]byte(sess.Ref()), []byte(ref)) == 1 {
			s.removeLocked(sess)
			return sess, true
		}
	}
	return Session{}, false
}

// RevokeAllForUser ends every session belonging to userID -- used when
// a password is reset (via the CLI recovery tool), so a stolen session
// doesn't survive a deliberate credential reset.
func (s *SessionStore) RevokeAllForUser(userID string) {
	s.RevokeAllForUserCount(userID)
}

// RevokeAllForUserCount is RevokeAllForUser, also reporting how many
// sessions it ended -- counted under the same lock the revoke runs
// under, so a session a login issues between a separate count and the
// revoke is never missed: it either lands before the lock is taken,
// and is counted and ended here, or after this returns, and is simply
// a new session this sign-out never claimed to touch. A caller that
// counted first and revoked after (gauntlet#58 R5, the admin sign-out's
// "ended" response) could report one short when a login raced it.
//
// The count includes sessions that had already timed out but were kept
// as resumable, which no session list shows.
//
// Deprecated: use EndSessionsForUser, which counts only the sessions
// that were still live, so the number agrees with the account's own
// list of sessions.
func (s *SessionStore) RevokeAllForUserCount(userID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.byUser[userID])
	for id := range s.byUser[userID] {
		s.revokeVisits++
		delete(s.sessions, id)
	}
	delete(s.byUser, userID)
	return n
}

// EndSessionsForUser ends every session belonging to userID, as
// RevokeAllForUser does, and reports how many of them were live at now:
// the number a person would have seen in their own list of sessions
// (ListForUser) just before. Sessions that had timed out but could
// still be resumed, or that were past their ceiling and not yet swept,
// are ended too but not counted -- reporting them as sessions ended
// would claim more than the list ever showed. Counted and ended under
// one lock, for the reason RevokeAllForUserCount gives.
func (s *SessionStore) EndSessionsForUser(userID string, now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id := range s.byUser[userID] {
		s.revokeVisits++
		if sess, ok := s.sessions[id]; ok && !s.expired(sess, now) {
			n++
		}
		delete(s.sessions, id)
	}
	delete(s.byUser, userID)
	return n
}
