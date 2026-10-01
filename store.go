// Copied from mikroview's internal/auth/store.go, with names kept
// (docs/adr/0001-shared-auth-module.md decision 3). Two changes from
// mikroview, both from docs/design.md §1.3:
//
//   - Options carries the *slog.Logger instead of a package-level
//     persistLog, because a module cannot call an application's own
//     logging constructor. nil means discard.
//   - OpenStore(b, opts) replaces mikroview's Open(path)/OpenWithBackend(b):
//     gauntlet ships no file backend (persist.Backend is the seam; see
//     persist/persist.go), so there is only the one entry point.
package gauntlet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// minPasswordLength is enforced at every path that sets a user-chosen
// password (createLocked, SetPassword) -- self-registration, admin-
// created accounts, and any CLI recovery tooling an application builds
// all funnel through one of those two, so there's exactly one place
// this needs to live.
const minPasswordLength = 8

var (
	// ErrNotPersisted is returned by Register/CreateUser when no backend
	// is configured -- refusing rather than silently creating a user
	// that would vanish on restart.
	ErrNotPersisted = errors.New("gauntlet: no backend is configured, refusing to create a user that would not survive a restart")
	// ErrUsernameTaken is returned by Register/CreateUser for an
	// already-registered username (case-insensitive).
	ErrUsernameTaken = errors.New("gauntlet: username already exists")
	// ErrRegistrationClosed is returned by Register once at least one
	// user already exists -- self-registration is a one-time, first-
	// account-only path (see Store.Count()); every user after that is
	// created by an existing admin via CreateUser.
	ErrRegistrationClosed = errors.New("gauntlet: registration is closed, an account already exists")
	// ErrInvalidCredentials is returned by Authenticate for either an
	// unknown username or a wrong password -- deliberately not
	// distinguished, so a caller can't be tricked into leaking which
	// usernames exist via the error alone (VerifyPassword's constant-
	// time dummy-hash comparison handles the timing side of the same
	// concern).
	ErrInvalidCredentials = errors.New("gauntlet: invalid username or password")
	// ErrUserNotFound is returned by SetPassword/Get for an unknown user
	// ID/username.
	ErrUserNotFound = errors.New("gauntlet: no such user")
	// ErrSingleAdmin is returned by CreateUser for a RoleAdmin request.
	// This package holds exactly one admin; handover is TransferAdmin,
	// not creating a second one.
	ErrSingleAdmin = errors.New("gauntlet: this deployment has a single admin account -- transfer the role instead of creating another admin")
	// ErrInvalidRole is returned by CreateUser for any role other than
	// RoleUser or RoleViewer. RoleAdmin is refused separately, as
	// ErrSingleAdmin above.
	ErrInvalidRole = errors.New(`gauntlet: role must be "user" or "viewer"`)
	// ErrCannotDeleteAdmin is returned by DeleteUser for the admin
	// account. Transfer the role first if the intent is to remove the
	// person currently holding it.
	ErrCannotDeleteAdmin = errors.New("gauntlet: the admin account cannot be deleted -- transfer the admin role first")
	// ErrTransferToSelf is returned by TransferAdmin when the target is
	// already the admin.
	ErrTransferToSelf = errors.New("gauntlet: that account is already the admin")
	// ErrNoAdmin is returned by TransferAdmin when no account holds the
	// role -- nothing to transfer.
	ErrNoAdmin = errors.New("gauntlet: this deployment has no admin account")

	// errMultipleAdmins is the decode error for an accounts document
	// holding more than one admin. No write in this package produces
	// one (see CreateUser and TransferAdmin), so it can only come from a
	// hand edit or a foreign writer, and it is refused the way an
	// unparseable document is.
	errMultipleAdmins = errors.New("more than one account holds the admin role; this package allows exactly one")
	// errNoAdmin is the decode error for an accounts document that holds
	// accounts but none of them is the admin. See checkAdmins.
	errNoAdmin = errors.New("accounts document holds accounts but no admin")
	// ErrOIDCAlreadyLinked is returned by LinkOIDCIdentity when the
	// account is already connected to a different (issuer, subject).
	ErrOIDCAlreadyLinked = errors.New("gauntlet: account is already connected to an SSO identity")
	// ErrOIDCIdentityTaken is returned by LinkOIDCIdentity when the
	// (issuer, subject) pair is already linked to a *different* user --
	// an OIDC identity can back at most one local account.
	ErrOIDCIdentityTaken = errors.New("gauntlet: this SSO identity is already linked to a different account")
	// ErrPasswordTooShort is returned by createLocked/SetPassword for a
	// password under minPasswordLength. Deliberately not checked inside
	// HashPassword itself: that function also hashes two non-user-chosen
	// values (dummyHash's fixed timing-comparison string, and
	// FindOrCreateOIDCUser's random unmatchable-hash input for SSO-only
	// accounts), neither of which should be subject to a password policy
	// at all.
	ErrPasswordTooShort = fmt.Errorf("gauntlet: password must be at least %d characters", minPasswordLength)
)

// oidcKey is (issuer, subject) as a map key -- a struct rather than a
// delimited string concatenation, so there's no theoretical risk of one
// issuer/subject pair's serialized form colliding with a different
// pair's.
type oidcKey struct {
	issuer  string
	subject string
}

// storeFile is the on-disk shape: an object wrapping the user list.
type storeFile struct {
	Users []*User `json:"users"`
}

// checkAdmins refuses a document with more than one admin, and refuses
// one that holds accounts but none of them admin. An empty document (no
// users at all) is fine -- that's a deployment before Register. But once
// accounts exist, losing the admin is a one-way door: Register is closed
// as soon as Count()>0, CreateUser refuses RoleAdmin, and TransferAdmin
// needs a current admin to transfer from, so nothing in this package
// could ever create a new one. Loading such a document anyway would mean
// a server that answers 403 on every admin route forever, with a backup
// the only way back -- refusing it at startup says so up front instead.
//
// A `null` entry (see applyLoaded) is not an account and is not counted
// as one in the message, but a document made only of them is still
// refused: something wrote a non-empty list there, and reading it as a
// fresh install would reopen registration on the strength of it.
func (f storeFile) checkAdmins() error {
	admins, accounts := 0, 0
	for _, u := range f.Users {
		if u == nil {
			continue
		}
		accounts++
		if u.Role == RoleAdmin {
			admins++
		}
	}
	if admins > 1 {
		return fmt.Errorf("%w (found %d)", errMultipleAdmins, admins)
	}
	if admins == 0 && len(f.Users) > 0 {
		if nulls := len(f.Users) - accounts; nulls > 0 {
			return fmt.Errorf("%w (found %d accounts and %d null entries)", errNoAdmin, accounts, nulls)
		}
		return fmt.Errorf("%w (found %d)", errNoAdmin, accounts)
	}
	return nil
}

// Options configures OpenStore.
type Options struct {
	// Log receives errors: a bookkeeping change (a LastLogin bump) that
	// could not be saved and exists only in memory -- see
	// mutateBestEffortLocked -- and a document another process wrote
	// that this store refuses to apply -- see reloadIfStale. nil
	// discards both.
	Log *slog.Logger
}

// Store persists user accounts through a persist.Backend -- an
// application's file, database table, or persist.Memory for tests.
// Persistence is not optional: a nil backend leaves Store usable (so an
// application still boots fine with auth unconfigured) but
// Register/CreateUser refuse to add a user in that state -- see
// ErrNotPersisted.
type Store struct {
	mu      sync.RWMutex
	backend persist.Backend
	log     *slog.Logger
	// storeState is the accounts document as this process holds it,
	// guarded by mu. Embedded so the fields read as s.byID; a write
	// changes a copy and swaps it in whole -- see mutate.
	storeState
	// version is the backend's token for the document as of the last
	// load, so a running server can pick up a change made by a separate
	// process -- namely a CLI recovery tool, which opens its own
	// independent Store against the same backend. Without this, a
	// password reset would silently have no effect on an already-running
	// server until it restarts, defeating the point of a recovery tool
	// that shouldn't require one.
	//
	// It is also what makes a write conditional: see mutate.
	version int64

	// reloadInFlight is non-nil while one caller is checking the backend
	// for staleness, and is closed when that check finishes. It is
	// deliberately not guarded by mu: a caller waiting on it must not
	// hold a lock the reload itself needs to take. See reloadIfStale.
	reloadMu       sync.Mutex
	reloadInFlight chan struct{}

	// refusedVersion is the last document version reloadIfStale refused
	// to apply (see checkAdmins), so a refused document is logged once
	// rather than on every request until someone fixes it, and so
	// registrationOpenGuard can keep registration closed while it holds.
	// Only reloadIfStale writes it, and only one of those runs at a time,
	// but registrationOpenGuard now reads it too, so both sides go
	// through mu like byID/byName/version above.
	refusedVersion    int64
	hasRefusedVersion bool
}

// storeState is the in-memory index over the accounts document: the
// accounts and the lookups the store answers from. It is what a write
// changes, as a whole -- see Store.mutate -- and what OpenStore and
// reloadIfStale replace on a load.
type storeState struct {
	byID      map[string]*User
	byName    map[string]string  // lowercased username -> ID
	oidcIndex map[oidcKey]string // (issuer, subject) -> ID, see ByOIDCIdentity
	// lastLoginSaved is each account's LastLogin as of the last load or
	// save, by ID -- what Authenticate measures staleness against (see
	// lastLoginGranularity), since the in-memory value may be ahead of
	// it.
	lastLoginSaved map[string]time.Time
}

// indexUsers builds the state for a decoded document. Shared by
// OpenStore, reloadIfStale and the conflict replay in mutate, so the
// three can't diverge on what loading means.
func indexUsers(file storeFile) storeState {
	st := storeState{
		byID:           make(map[string]*User, len(file.Users)),
		byName:         make(map[string]string, len(file.Users)),
		oidcIndex:      make(map[oidcKey]string, len(file.Users)),
		lastLoginSaved: make(map[string]time.Time, len(file.Users)),
	}
	for _, u := range file.Users {
		// A JSON array containing `null` unmarshals successfully into a
		// nil *User -- valid JSON, so the decode error check doesn't
		// catch it.
		if u == nil {
			continue
		}
		st.byID[u.ID] = u
		st.byName[strings.ToLower(u.Username)] = u.ID
		st.lastLoginSaved[u.ID] = u.LastLogin
		if u.OIDCIssuer != "" || u.OIDCSubject != "" {
			st.oidcIndex[oidcKey{issuer: u.OIDCIssuer, subject: u.OIDCSubject}] = u.ID
		}
	}
	return st
}

// clone deep-copies the state: every account, and every slice inside
// one, so a change to the copy can be thrown away without having
// touched the original.
func (st *storeState) clone() *storeState {
	cp := &storeState{
		byID:           make(map[string]*User, len(st.byID)),
		byName:         make(map[string]string, len(st.byName)),
		oidcIndex:      make(map[oidcKey]string, len(st.oidcIndex)),
		lastLoginSaved: make(map[string]time.Time, len(st.lastLoginSaved)),
	}
	for id, u := range st.byID {
		cp.byID[id] = u.clone()
	}
	maps.Copy(cp.byName, st.byName)
	maps.Copy(cp.oidcIndex, st.oidcIndex)
	maps.Copy(cp.lastLoginSaved, st.lastLoginSaved)
	return cp
}

// users is the accounts in document order: by username, so the saved
// bytes do not depend on map iteration.
func (st *storeState) users() []*User {
	list := make([]*User, 0, len(st.byID))
	for _, u := range st.byID {
		list = append(list, u)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Username < list[j].Username })
	return list
}

// recordSaved notes each account's LastLogin as the value just saved.
func (st *storeState) recordSaved() {
	if st.lastLoginSaved == nil {
		st.lastLoginSaved = make(map[string]time.Time, len(st.byID))
	}
	clear(st.lastLoginSaved)
	for id, u := range st.byID {
		st.lastLoginSaved[id] = u.LastLogin
	}
}

// encodeAccounts is the state as the document is saved.
func encodeAccounts(st *storeState) ([]byte, error) {
	return json.MarshalIndent(storeFile{Users: st.users()}, "", "  ")
}

// decodeAccounts is the document as it is opened: parsed and checked
// (checkAdmins) before it becomes a state.
func decodeAccounts(data []byte) (*storeState, error) {
	var file storeFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	if err := file.checkAdmins(); err != nil {
		return nil, err
	}
	st := indexUsers(file)
	return &st, nil
}

// accounts is the replay loop's view of this store -- see mutate.go.
func (s *Store) accounts() document[storeState] {
	return document[storeState]{
		backend: s.backend,
		what:    "accounts",
		clone:   (*storeState).clone,
		encode:  encodeAccounts,
		decode:  decodeAccounts,
		// The single-admin rule, checked on the way out as well as on
		// the way in: an op that broke it would otherwise save a
		// document the next OpenStore refuses.
		check: func(st *storeState) error {
			return storeFile{Users: st.users()}.checkAdmins()
		},
	}
}

// mutate applies op to the accounts and saves the result, taking the
// write lock for the whole of it. op runs against a copy of the state;
// if the save is refused because another process wrote first, the
// fresh document is loaded and op runs again against that, up to
// maxSaveAttempts times (see mutate.go). On success the copy replaces
// the state; on any error -- op's own, or a save that could not be
// made -- nothing changes and nothing was written.
//
// op must read only the state it is given, and set the method's results
// through captured variables that its last run overwrites.
func (s *Store) mutate(op func(*storeState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mutateLocked(op)
}

// mutateLocked is mutate for a caller that already holds mu.
//
// Two outcomes install a state: the saved one, and the fresh document
// op refused on a replay (see document.replay) -- the account op was to
// change is gone from what another process wrote, and this store takes
// that document rather than keep answering from memory that still has
// the account. The caller then re-reads the state and finds what the op
// found.
func (s *Store) mutateLocked(op func(*storeState) error) error {
	next, version, err := s.accounts().replay(&s.storeState, s.version, op)
	if next != nil {
		next.recordSaved()
		s.storeState = *next
		s.version = version
		// The document out there is now one this process holds: an
		// earlier refusal no longer describes it (same as applyLoaded).
		s.refusedVersion, s.hasRefusedVersion = 0, false
	}
	if errors.Is(err, errNoChange) {
		return nil
	}
	return err
}

// mutateBestEffortLocked is mutateLocked for a write not worth failing
// the caller over -- a LastLogin bump. A change that cannot be saved is
// logged and kept in memory, where every read sees it, so a transient
// backend problem degrades to "will not survive a restart" rather than
// failing an otherwise successful login. An error from op itself is
// dropped: it means the change did not apply, and there is nothing to
// keep.
func (s *Store) mutateBestEffortLocked(op func(*storeState) error) {
	err := s.mutateLocked(op)
	if err == nil {
		return
	}
	// op is replayable: running it on the live state applies the change
	// this process could not save. If op is what failed, it fails here
	// the same way and changes nothing -- including when it refused a
	// freshly loaded document, since mutateLocked installed that
	// document, so the live state is the one op refused.
	if opErr := op(&s.storeState); opErr != nil {
		return
	}
	if s.log != nil {
		s.log.Error(fmt.Sprintf("%v -- this change exists only in memory and will be lost on restart", err))
	}
}

// reloadTimeout bounds one staleness check against the backend. Long
// enough that an ordinary slow query is not mistaken for an outage,
// short enough that a stalled backend does not hold a request goroutine
// and a pool connection indefinitely. Exceeding it is not fatal -- the
// store keeps serving what it already has in memory.
//
// A var, not a const, only so tests can shorten it. Nothing outside
// tests assigns to it.
var reloadTimeout = 5 * time.Second

// saveTimeout is the write-side counterpart: it bounds one write as a
// whole -- every save the replay loop makes for it and every reload
// between them (mutate.go, Store and TokenStore alike) -- which runs
// while the store's write lock is held. Without it a backend that stops
// answering mid-save would hold that lock, and with it every login and
// every signed-in request, until the process was restarted; and one
// that merely answers slowly and conflicts every time would hold it for
// five saves and four reloads. A write that overruns fails like any
// other save failure: nothing is changed and the caller gets the error.
//
// That protection only reaches a backend that honours ctx. The shipped
// file backends (persist/file.go's Save, and EncryptedFileBackend on top
// of it) call plain os.ReadFile/CreateTemp/Write/Sync/Rename, and wait on
// the lock file before any of them -- none of which take a context or
// can be interrupted by one -- so on a hung mount the deadline never
// fires. reloadTimeout has the same limit on the read side.
//
// A var, not a const, only so tests can shorten it.
var saveTimeout = 5 * time.Second

// OpenStore returns a Store persisting through b. A nil b gives a usable
// but unpersisted store -- see Store's doc comment.
//
// A backend that exists but cannot be read, or holds a document that
// cannot be parsed, is a hard error: OpenStore returns (nil, err) rather
// than a store whose live backend would overwrite that document on the
// first write. That distinction is load-bearing: treating an unreadable
// accounts store as an absent one turns a corrupted file into a fresh
// install, silently reopening registration to whoever loads the page
// next. See persist.Open.
func OpenStore(b persist.Backend, opts Options) (*Store, error) {
	s := &Store{
		backend:    b,
		log:        opts.Log,
		storeState: indexUsers(storeFile{}),
	}

	version, existed, err := persist.Open(context.Background(), b, "the accounts store", func(data []byte) error {
		var file storeFile
		if err := json.Unmarshal(data, &file); err != nil {
			return err
		}
		if err := file.checkAdmins(); err != nil {
			return err
		}
		// version isn't in scope yet here -- persist.Open hasn't
		// returned it to this statement's left-hand side. applyLoaded
		// is called with a placeholder and corrected below once
		// persist.Open's real version is available.
		s.applyLoaded(file, 0)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if existed {
		s.version = version
	}
	return s, nil
}

// applyLoaded replaces the in-memory index from a decoded document.
// Shared by OpenStore and reloadIfStale so the two can't diverge on what
// loading means.
func (s *Store) applyLoaded(file storeFile, version int64) {
	s.storeState = indexUsers(file)
	s.version = version
	// A refusal only holds while the refused document is still the one
	// on disk: this document was just accepted, so any earlier refusal
	// no longer describes what's out there.
	s.refusedVersion, s.hasRefusedVersion = 0, false
}

// reloadIfStale re-reads the document if the backend has moved on since
// this Store last loaded it.
//
// This is what lets a running server pick up a change made by a separate
// process -- a CLI recovery command opening its own Store against the
// same backend. Without it, a password reset would silently have no
// effect on a live server until restart.
//
// Every failure here is deliberately silent and non-fatal: it keeps
// serving whatever is already in memory. A transient backend problem
// must not take authentication down on a server that is running fine.
//
// Three things bound what a sick backend can cost, because this runs on
// every authenticated request and on every login and registration
// attempt, including unauthenticated ones:
//
//   - The read has a deadline (reloadTimeout), so a backend that stops
//     answering cannot block a caller forever.
//   - Only one check is ever in flight. Concurrent callers join the
//     running one instead of opening their own, so a stall costs one
//     pooled connection rather than one per request.
//   - The staleness question is asked with Version when the backend can
//     answer it cheaply. Backends without that capability fall back to
//     Load exactly as before.
func (s *Store) reloadIfStale() {
	if s.backend == nil {
		return
	}

	// Join a check already in flight rather than starting a second one.
	s.reloadMu.Lock()
	if inFlight := s.reloadInFlight; inFlight != nil {
		s.reloadMu.Unlock()
		<-inFlight
		return
	}
	done := make(chan struct{})
	s.reloadInFlight = done
	s.reloadMu.Unlock()
	defer func() {
		s.reloadMu.Lock()
		s.reloadInFlight = nil
		s.reloadMu.Unlock()
		close(done)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), reloadTimeout)
	defer cancel()

	if vr, ok := s.backend.(persist.VersionReader); ok {
		version, exists, err := vr.Version(ctx)
		if err != nil || !exists {
			return
		}
		s.mu.RLock()
		stale := version != s.version
		refused := s.hasRefusedVersion && version == s.refusedVersion
		s.mu.RUnlock()
		if !stale || refused {
			return
		}
	}

	// Captured before the unlocked read below, and compared against
	// again once the write lock is held: the only safe way to detect a
	// concurrent in-process write (mutate) that landed while this call
	// was reading without the lock. A version that moved at all between
	// here and the write-lock check below means some other caller's
	// write is now the authoritative state, and applying a snapshot read
	// before it would silently revert that write.
	s.mu.RLock()
	beforeLoad := s.version
	s.mu.RUnlock()

	snap, err := s.backend.Load(ctx)
	if err != nil || !snap.Exists {
		return
	}
	s.mu.RLock()
	alreadyRefused := s.hasRefusedVersion && snap.Version == s.refusedVersion
	s.mu.RUnlock()
	if snap.Version == beforeLoad || alreadyRefused {
		return
	}

	var file storeFile
	if err := json.Unmarshal(snap.Payload, &file); err != nil {
		return
	}
	// Unlike a transient read failure, this is a document someone wrote:
	// keep serving what is in memory, and say why once. Every write
	// fails while it stands -- mutate meets the same refusal when its
	// save conflicts and reloads, rather than writing over it -- and a
	// store that opened on an empty backend also keeps registration
	// closed (registrationOpenGuard) instead of treating Count() == 0 as
	// a fresh install.
	if err := file.checkAdmins(); err != nil {
		s.mu.Lock()
		s.refusedVersion, s.hasRefusedVersion = snap.Version, true
		s.mu.Unlock()
		if s.log != nil {
			s.log.Error(fmt.Sprintf("accounts store (%s) was changed by another process and is not being applied: %v", s.backend.Describe(), err))
		}
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.version != beforeLoad {
		return
	}
	s.applyLoaded(file, snap.Version)
}

// Persisted reports whether a backend is configured.
func (s *Store) Persisted() bool {
	return s.backend != nil
}

// Count returns the number of user accounts. 0 is what gates both
// whether auth is active at all, and whether Register is still open.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

// Register creates the very first account, always as RoleAdmin,
// regardless of what a future caller might pass -- there is no role
// parameter because there's no meaningful choice: the first person to
// register is the super-admin by definition. Fails with
// ErrRegistrationClosed once any account exists.
//
// The "is registration still open" test is passed down as a guard and
// evaluated inside createLocked's critical section rather than checked
// here, because checking it here would be a TOCTOU: Count() takes and
// releases the lock on its own, so two concurrent Register calls could
// both observe an empty store and both go on to insert. That window is
// not theoretical or narrow -- HashPassword below runs before the lock
// is taken and deliberately costs ~100ms (Argon2id), holding it open for
// the entire hash. Left unguarded, N concurrent registrations during the
// first-run window all succeed and every one of them gets RoleAdmin.
func (s *Store) Register(username, password string, now time.Time) (*User, error) {
	if !s.Persisted() {
		return nil, ErrNotPersisted
	}
	// Reload first so a decision made by another process is visible
	// before we take the lock -- the guard below re-reads the same
	// fields under it, so this is an optimization for the cross-process
	// case, not the correctness boundary.
	s.reloadIfStale()

	// Cheap rejection BEFORE hashing. HashPassword is Argon2id at 64
	// MiB, and registration is typically unauthenticated and
	// rate-limit-free -- so without this, a small POST that is going to
	// be refused anyway still costs 64 MiB and ~66ms, and a handful of
	// concurrent ones OOM-kill the container.
	//
	// This is a fast path, NOT the correctness boundary: it reads the
	// guard's fields without holding the write lock, so it can race.
	// registrationOpenGuard runs again inside createLocked's write,
	// against the document being saved, and that remains what actually
	// guarantees exactly one account can be self-registered.
	if err := func() error {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return registrationOpenGuard(s, &s.storeState)
	}(); err != nil {
		return nil, err
	}

	return s.createLocked(username, password, RoleAdmin, now, registrationOpenGuard)
}

// registrationOpenGuard is Register's precondition: no account may
// exist yet. createLocked runs it inside the write's op, against st --
// the document being saved, which on a replay is the one another
// process just wrote -- and that is what makes "exactly one account can
// ever be self-registered" hold, across processes as well as within
// one.
//
// hasRefusedVersion also closes it: a document with accounts exists on
// disk even though this process refused to apply it (see reloadIfStale),
// so a store that opened on an empty backend must not read its own
// empty Count() as a fresh install and create a second admin on top of
// the one the operator already has.
func registrationOpenGuard(s *Store, st *storeState) error {
	if len(st.byID) > 0 || s.hasRefusedVersion {
		return ErrRegistrationClosed
	}
	return nil
}

// CreateUser adds an additional account with the given role -- for use
// by an already-authenticated admin (the caller enforces who may call
// this; Store itself has no notion of "who is calling"), or by CLI
// recovery tooling. No guard: unlike Register, this is deliberately
// callable at any time.
//
// role must be RoleUser or RoleViewer. Anything else is refused:
// RoleAdmin specifically as ErrSingleAdmin, any other value as
// ErrInvalidRole -- neither is silently coerced to a lesser role, since
// that would create an account under the name the caller chose with a
// privilege they did not ask for.
func (s *Store) CreateUser(username, password string, role Role, now time.Time) (*User, error) {
	if !s.Persisted() {
		return nil, ErrNotPersisted
	}
	// This package holds exactly one admin at a time. Refused here
	// rather than only at a caller's own API layer so every caller
	// inherits the invariant instead of each remembering it.
	if role == RoleAdmin {
		return nil, ErrSingleAdmin
	}
	if role != RoleUser && role != RoleViewer {
		return nil, ErrInvalidRole
	}
	// Same as Register: picking up another process's writes first
	// avoids most save conflicts, though correctness no longer depends
	// on it -- see mutate.
	s.reloadIfStale()
	return s.createLocked(username, password, role, now, nil)
}

// DeleteUser removes an account by ID and returns it, so the caller can
// clean up what belonged to it (sessions, API tokens).
//
// It refuses to delete the admin. This package holds exactly one admin,
// and a deployment with none has no way to add accounts, manage tokens,
// or reach any admin-gated screen. Enforced here rather than only at a
// caller's own API layer so every caller inherits it.
func (s *Store) DeleteUser(id string) (*User, error) {
	if !s.Persisted() {
		return nil, ErrNotPersisted
	}
	s.reloadIfStale()

	// A deletion that only exists in memory must not be reported as
	// done: the caller would revoke the account's sessions and tokens
	// and tell its operator the account is gone, and a restart before
	// the next good write would bring it straight back -- with none of
	// those revocations remembered. mutate installs the change only
	// once it is saved, and may run this op again against a freshly
	// loaded document if another process wrote first, so the op decides
	// from the state it is given and sets its result last.
	var deleted User
	err := s.mutate(func(st *storeState) error {
		u, ok := st.byID[id]
		if !ok {
			return ErrUserNotFound
		}
		if u.Role == RoleAdmin {
			return ErrCannotDeleteAdmin
		}
		delete(st.byID, id)
		delete(st.byName, strings.ToLower(u.Username))
		if u.OIDCIssuer != "" {
			delete(st.oidcIndex, oidcKey{issuer: u.OIDCIssuer, subject: u.OIDCSubject})
		}
		deleted = *u
		return nil
	})
	if err != nil {
		return nil, err
	}

	deleted.PasswordHash = ""
	return &deleted, nil
}

// TransferAdmin moves the admin role to toUsername, atomically.
//
// This is the only way to change who administers a deployment. There is
// deliberately no separate promote or demote: either alone would leave
// the deployment with two admins or none, and the rest of the system
// assumes neither can happen.
//
// The whole operation runs under one write lock with the invariant
// re-checked inside it; doing it as two calls, or checking the current
// admin beforehand, is the check-then-act race behind the Appsmith
// duplicate-admin and open-webui zero-admin bugs.
func (s *Store) TransferAdmin(toUsername string, now time.Time) (from, to *User, err error) {
	// Like every other write here: picking up another process's writes
	// first avoids most save conflicts -- see mutate.
	s.reloadIfStale()

	// Who the admin is, and whether the target exists and is someone
	// else, are decided inside the op against the document being saved:
	// on a replay that is the one another process just wrote, which may
	// already have moved the role. An admin transfer that only exists in
	// memory is a deployment that silently regains its old admin -- or
	// loses the only one -- on the next restart, so mutate installs it
	// only once it is saved.
	var fromCopy, toCopy User
	err = s.mutate(func(st *storeState) error {
		var current *User
		for _, u := range st.byID {
			if u.Role == RoleAdmin {
				current = u
				break
			}
		}
		if current == nil {
			return ErrNoAdmin
		}
		targetID, ok := st.byName[strings.ToLower(toUsername)]
		if !ok {
			return ErrUserNotFound
		}
		target := st.byID[targetID]
		if target.ID == current.ID {
			return ErrTransferToSelf
		}
		current.Role = RoleUser
		current.RoleChangedAt = now
		target.Role = RoleAdmin
		target.RoleChangedAt = now
		fromCopy, toCopy = *current, *target
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return &fromCopy, &toCopy, nil
}

// Admin returns the single admin account, or nil if there isn't one yet.
func (s *Store) Admin() *User {
	s.reloadIfStale()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.byID {
		if u.Role == RoleAdmin {
			cp := *u
			return &cp
		}
	}
	return nil
}

// HasLocalAdmin reports whether the deployment still has a way in that
// does not depend on an identity provider: an admin account that can
// sign in with a local password.
//
// This package holds exactly one admin at a time (see CreateUser), so
// "at least one admin has a local password" and "the admin has a local
// password" are the same question -- but the name says the rule rather
// than the current cardinality, so a future second admin would only
// change this method's body.
//
// It reuses User.LocalPassword() rather than re-deriving "has a
// password" from the stored hash: an unmatchable hash is deliberately
// indistinguishable from a real one (see FindOrCreateOIDCUser), so
// HasLocalPassword is the only honest source.
func (s *Store) HasLocalAdmin() bool {
	admin := s.Admin()
	return admin != nil && admin.LocalPassword()
}

// createLocked inserts a new account. guard, when non-nil, is evaluated
// inside the write, against the state being saved (see mutate), and
// aborts the insert if it returns an error -- that's the hook callers
// use to make a precondition ("registration is still open") atomic with
// the insert itself rather than checking it beforehand and racing.
//
// HashPassword deliberately runs before the lock is acquired: Argon2id
// is ~100ms by design, and holding the store's write lock for that long
// would serialize every reader behind each in-flight registration -- an
// easy self-inflicted DoS. The cost of hashing before the guard runs is
// one wasted hash on the losing side of a race, which is the right
// trade.
func (s *Store) createLocked(username, password string, role Role, now time.Time, guard func(*Store, *storeState) error) (*User, error) {
	// Validated here rather than in Register/CreateUser separately: this
	// is the single funnel every locally-created account passes through,
	// so nothing can be added later that skips it.
	if err := ValidateLocalUsername(username); err != nil {
		return nil, err
	}
	if len(password) < minPasswordLength {
		return nil, ErrPasswordTooShort
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	// An account that only exists in memory must not be reported as
	// created: Register/CreateUser's callers hand the operator a session
	// or a success response for it, and a restart before the next good
	// write would erase the account under them. mutate installs it only
	// once it is saved.
	//
	// The guard and the username check run inside the op, against the
	// document being saved: on a replay that is the one another process
	// just wrote, which may already hold an admin or this username.
	id := newID()
	key := strings.ToLower(username)
	var created User
	err = s.mutate(func(st *storeState) error {
		if guard != nil {
			if err := guard(s, st); err != nil {
				return err
			}
		}
		if _, exists := st.byName[key]; exists {
			return ErrUsernameTaken
		}
		u := &User{
			ID:           id,
			Username:     username,
			PasswordHash: hash,
			Role:         role,
			CreatedAt:    now,
			// A real password the user chose, so it may later be reset.
			HasLocalPassword: true,
		}
		st.byID[u.ID] = u
		st.byName[key] = u.ID
		created = *u
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &created, nil
}

// ByOIDCIdentity looks up the user linked to the given (issuer,
// subject) pair, if any.
func (s *Store) ByOIDCIdentity(issuer, subject string) (*User, bool) {
	s.reloadIfStale()
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[s.oidcIndex[oidcKey{issuer: issuer, subject: subject}]]
	if !ok {
		return nil, false
	}
	cp := *u
	return &cp, true
}

// FindOrCreateOIDCUser looks up the user for (issuer, subject), or
// just-in-time provisions one if this identity has never signed in
// before -- the reported bool is true exactly when a new account was
// created. Unlike Register, this is never gated by Count() > 0:
// Register's one-time-only rule exists to close the *self-service local
// registration form* after the first account, but has no bearing on
// admin-driven creation (CreateUser) or, here, an identity provider
// vouching for someone -- every never-before-seen (issuer, subject) pair
// is provisioned regardless of how many accounts already exist.
//
// usernameHint (typically the ID token's preferred_username or email
// claim) is used as the new account's Username only if it's non-empty
// and not already taken by a *different* user -- it is a display
// convenience only, never part of the identity key, and this method
// never attaches a login to an existing account merely because it
// shares that hint: an IdP-side email/username reassignment must never
// silently inherit a pre-existing account. On any collision (or an
// empty hint) a deterministic synthetic username is used instead,
// derived from (issuer, subject) so a retried provisioning attempt lands
// on the same account rather than racing itself.
//
// The very first user -- local or OIDC, whichever happens first --
// becomes RoleAdmin, the same rule Register already applies; every later
// account (from either path) is RoleUser, decided under this method's
// own write lock rather than a separate Count() pre-check, so this
// doesn't add a second copy of the narrow TOCTOU window Register's own
// pre-lock Count() check already has.
func (s *Store) FindOrCreateOIDCUser(issuer, subject, usernameHint string, now time.Time) (user *User, created bool, err error) {
	if !s.Persisted() {
		return nil, false, ErrNotPersisted
	}
	s.reloadIfStale()

	key := oidcKey{issuer: issuer, subject: subject}

	// The unmatchable hash is ~100ms of Argon2id, so it is made before
	// the write lock, as createLocked and LinkOIDCIdentity make theirs --
	// but only when this identity looks new. Most calls are a returning
	// sign-in that would throw it away, and a wasted hash on every SSO
	// login is a different cost from LinkOIDCIdentity's one on a rare
	// operation.
	s.mu.RLock()
	_, known := s.byID[s.oidcIndex[key]]
	s.mu.RUnlock()
	var unmatchable string
	if !known {
		if unmatchable, err = unmatchablePasswordHash(); err != nil {
			return nil, false, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if id, ok := s.oidcIndex[key]; ok {
		if _, ok := s.byID[id]; ok {
			// LastLogin only -- a missed update here costs nothing
			// worth failing an otherwise-successful SSO login over, so
			// this is a best-effort write (same reasoning as
			// Authenticate's ordinary-login path below).
			s.mutateBestEffortLocked(func(st *storeState) error {
				u, ok := st.byID[id]
				if !ok {
					return ErrUserNotFound
				}
				u.LastLogin = now
				return nil
			})
			if u, ok := s.byID[id]; ok {
				cp := *u
				return &cp, false, nil
			}
		}
	}

	if unmatchable == "" {
		// The identity's account was deleted between the read above
		// and this lock -- rare enough that hashing under the lock here
		// is cheaper than making every sign-in pay for the hash.
		if unmatchable, err = unmatchablePasswordHash(); err != nil {
			return nil, false, err
		}
	}

	// A JIT-provisioned account that only exists in memory must not be
	// reported as created: the caller is about to sign this person in as
	// though the account durably exists, and a restart before the next
	// good write would erase it while sessions referencing its ID are
	// still live. mutate installs it only once it is saved.
	//
	// Everything the op decides -- whether the identity already has an
	// account, whether this is the first account and so the admin, and
	// which username is free -- is read from the document being saved:
	// on a replay that is the one another process just wrote, which may
	// have provisioned this identity, registered the admin, or taken the
	// hinted name since this process looked.
	id := newID()
	var result User
	err = s.mutateLocked(func(st *storeState) error {
		if existingID, ok := st.oidcIndex[key]; ok {
			if u, ok := st.byID[existingID]; ok {
				// Another process provisioned this identity first:
				// sign in to that account rather than make a second.
				u.LastLogin = now
				result, created = *u, false
				return nil
			}
		}

		role := RoleUser
		if len(st.byID) == 0 {
			role = RoleAdmin
		}
		u := &User{
			ID:           id,
			Username:     st.uniqueUsername(usernameHint, issuer, subject),
			PasswordHash: unmatchable,
			Role:         role,
			CreatedAt:    now,
			LastLogin:    now,
			OIDCIssuer:   issuer,
			OIDCSubject:  subject,
			// Explicitly false: the hash above is random and unmatchable,
			// so there is no password here to reset. Recorded rather than
			// inferred, because the hash itself is indistinguishable from
			// a real one.
			HasLocalPassword: false,
		}
		st.byID[u.ID] = u
		st.byName[strings.ToLower(u.Username)] = u.ID
		st.oidcIndex[key] = u.ID
		result, created = *u, true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return &result, created, nil
}

// uniqueUsername picks hint if it's non-empty and not already taken in
// st, otherwise a deterministic synthetic username derived from
// (issuer, subject) -- see FindOrCreateOIDCUser's doc comment. It reads
// the state it is called on, so a replayed write checks the document it
// is about to save.
func (st *storeState) uniqueUsername(hint, issuer, subject string) string {
	// The hint is whatever the identity provider put in
	// preferred_username or email -- text this package does not
	// control. An unusable one is dropped, not rejected, so the person
	// still gets a stable account under the generated name below.
	hint = sanitiseUsernameHint(hint)
	if hint != "" {
		if _, taken := st.byName[strings.ToLower(hint)]; !taken {
			return hint
		}
	}
	sum := sha256.Sum256([]byte(issuer + "\x00" + subject))
	full := hex.EncodeToString(sum[:])
	// Grows the slice of the hash used until a free username is found --
	// deterministic and idempotent for the same (issuer, subject) across
	// retries, since it always starts from the same hash. A collision at
	// the shortest length is exceptionally unlikely on its own; growing
	// further makes it vanishingly so without ever depending on
	// randomness for reproducibility.
	//
	// Nothing validates the name after this returns, so every candidate
	// has to fit maxUsernameLength itself: "oidc-" plus all 64 hex digits
	// would not, so the slice stops at 56. Both forms are ASCII, so bytes
	// and runes count the same.
	const prefix = "oidc-"
	for n := 8; n <= len(full) && len(prefix)+n <= maxUsernameLength; n += 8 {
		candidate := prefix + full[:n]
		if _, taken := st.byName[strings.ToLower(candidate)]; !taken {
			return candidate
		}
	}
	return prefix + newID() // practically unreachable; 37 characters
}

// unmatchablePasswordHash produces a real, freshly generated Argon2id
// hash of a random value -- the credential given to an account that has
// no local password.
//
// Not "": a local-login attempt against such an account has to take the
// same time as a genuine wrong-password attempt. VerifyPassword's
// malformed-hash guard returns false *before* running Argon2id for an
// empty or malformed hash, so storing "" would let an attacker tell
// "this username is SSO-only" from response time alone -- and knowing
// which accounts can't be attacked locally tells them which ones can.
//
// Shared by FindOrCreateOIDCUser (provisioned SSO-only from the start)
// and LinkOIDCIdentity (converted to SSO-only), so the two can't drift.
func unmatchablePasswordHash() (string, error) {
	return HashPassword(newID())
}

// LinkOIDCIdentity attaches (issuer, subject) to an existing account,
// converting it to SSO-only in the same operation -- unless the account
// is the admin, which keeps its password and its second factor.
//
// **For every role but admin, linking is destructive and one-way.** The
// account's local password is replaced with a fresh unmatchable hash and
// HasLocalPassword is set to false, exactly as if the account had been
// OIDC-provisioned from the start. There is deliberately no state where
// a local password and a linked identity both work: keeping the old
// password alive would preserve the weaker local-password attack
// surface on an account that has supposedly moved past it, which
// defeats the point of linking.
//
// The same call also clears every local second factor -- TOTPSecret,
// TOTPConfirmedAt, TOTPLastCounter, RecoveryCodes and Passkeys, for the
// non-admin case -- unconditionally, not the factor-remaining check a
// caller removing one factor at a time would make: linking removes both
// local credentials at once, so there is nothing left standing for
// either to guard.
//
// **The admin keeps its local password and its local second factor,
// permanently** (mikroview #1252: "the admin must always be able to sign
// in, even with the identity provider down"). This package assumes at
// most one admin and never authenticates to the provider on its own
// behalf, so a provider that cannot answer means nobody gets in at all --
// the one account that can end that outage is worth the attack surface
// the paragraph above refuses everybody else.
//
// A role change afterwards does not re-run this: an admin demoted to
// user keeps the password and factor it had, and TransferAdmin's own
// rules decide what the new admin holds. Linking is the event this
// method describes, not a standing property of the role.
//
// Idempotent for the same user. Fails with ErrOIDCIdentityTaken if that
// identity is already linked to a *different* account -- which is what
// stops someone attaching their own IdP identity to a colleague's
// account, and, on the admin account, stops it being quietly taken over.
func (s *Store) LinkOIDCIdentity(userID, issuer, subject string, now time.Time) error {
	if !s.Persisted() {
		return ErrNotPersisted
	}
	// Generated before the lock: HashPassword is ~100ms by design, and
	// holding the write lock across it would serialize every reader --
	// the same reasoning createLocked documents. Which means it is
	// generated for an admin's link too and then not used; the role is
	// not knowable until the lock is held, and one wasted hash on a rare
	// operation is cheaper than holding the lock across one.
	unmatchable, err := unmatchablePasswordHash()
	if err != nil {
		return err
	}

	s.reloadIfStale()

	// A link that only exists in memory must not be reported as done:
	// for everyone but the admin this also destroys the local password,
	// so the caller would tell its operator SSO is now the only way in
	// when a restart could revert to a password nobody remembers is
	// still live -- or, worse, leave the account's SSO index entry
	// pointing nowhere durable. mutate installs it only once it is
	// saved, and the "identity already taken" and "already linked"
	// checks run against the document being saved.
	key := oidcKey{issuer: issuer, subject: subject}
	return s.mutate(func(st *storeState) error {
		u, ok := st.byID[userID]
		if !ok {
			return ErrUserNotFound
		}
		if existingID, ok := st.oidcIndex[key]; ok && existingID != userID {
			return ErrOIDCIdentityTaken
		}
		// Already connected to something else. Idempotent for the same
		// identity (above and below), refused for a different one: the
		// old (issuer, subject) would stay in the index and go on
		// signing in as this account, so "re-link" would quietly mean
		// "two ways in".
		if u.OIDCSubject != "" && (u.OIDCIssuer != issuer || u.OIDCSubject != subject) {
			return ErrOIDCAlreadyLinked
		}

		u.OIDCIssuer = issuer
		u.OIDCSubject = subject
		if u.Role != RoleAdmin {
			u.PasswordHash = unmatchable
			u.HasLocalPassword = false
			// See the doc comment above: every non-admin loses both
			// local credentials on linking, not just the password.
			u.TOTPSecret = ""
			u.TOTPConfirmedAt = time.Time{}
			u.TOTPLastCounter = 0
			u.RecoveryCodes = nil
			u.Passkeys = nil
			// An outstanding admin reset dies with the password it was
			// a stand-in for: Authenticate treats a live code as the
			// password, so left here it would keep a local way in open
			// for up to 24 hours after the account became SSO-only, and
			// the forced-change flag would then door an account with
			// nothing to change.
			u.ResetCodeHash = ""
			u.ResetCodeExpiresAt = time.Time{}
			u.MustChangePassword = false
		}
		// Invalidates every session issued before this point, including
		// in another process -- the account's credentials just changed
		// fundamentally, so anything holding a session from before that
		// should have to come back through the IdP. True for the admin
		// too, whose password survives: a second way into the account
		// was just attached, and a session issued before that should be
		// re-made through one of them.
		u.PasswordChangedAt = now
		st.oidcIndex[key] = userID
		return nil
	})
}

// lastLoginGranularity is how stale an account's saved LastLogin may
// become before a login is worth a whole-document save -- the rule
// lastUsedGranularity (token.go) applies to a token's LastUsedAt, for
// the same reason: an hour is far finer than the question the field
// answers ("is this account still in use?"), and without it every
// login rewrites every account.
const lastLoginGranularity = time.Hour

// Authenticate verifies username/password and, on success, records
// LastLogin and returns a copy of the user. Always runs a password
// comparison (against dummyHash if the username doesn't exist) so a
// failed login takes the same time either way. The CPU-heavy Argon2id
// comparison deliberately happens with the lock released -- only the
// map/field reads and writes around it are synchronized.
//
// While an admin-issued reset code is live the code is what this
// verifies, in place of the password -- that is what lets somebody
// locked out type it into the password box and get in. Only one
// Argon2id comparison ever runs, whichever credential is in play, so a
// pending reset is not something an attacker can spot from how long a
// failed attempt took. Nothing is lost by not also trying the password:
// issuing a code replaces the stored password hash with an unmatchable
// one, so the old password is already dead.
//
// A code is spent on the login that uses it (single use): losing the
// session before completing the forced change does not lock the account
// out, since another code can be issued -- a code left live until the
// password is actually set is replayable for its full life by anyone who
// saw it, and whoever finishes first takes the account.
//
// MustChangePassword is *not* cleared here -- only setting a new
// password does that -- so the session this login goes on to create is
// still the restricted one.
func (s *Store) Authenticate(username, password string, now time.Time) (*User, error) {
	s.reloadIfStale()

	s.mu.RLock()
	id, known := s.byName[strings.ToLower(username)]
	hash := dummyHash
	viaResetCode := false
	if known {
		u := s.byID[id]
		if u.resetCodeLive(now) {
			hash, viaResetCode = u.ResetCodeHash, true
		} else {
			hash = u.PasswordHash
		}
	}
	s.mu.RUnlock()

	secret := password
	if viaResetCode {
		secret = NormaliseResetCode(password)
	}
	valid := VerifyPassword(secret, hash)
	if !known || !valid {
		return nil, ErrInvalidCredentials
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-fetch by id rather than trusting a pointer captured above -- a
	// concurrent reloadIfStale (triggered by another in-flight request)
	// could have swapped s.byID/s.byName for entirely new maps in the
	// window since the RUnlock, which would otherwise leave this write
	// landing on an orphaned copy nothing else references.
	u, ok := s.byID[id]
	if !ok {
		return nil, ErrInvalidCredentials
	}
	if viaResetCode {
		// Spending the code is the write that matters here: a spend
		// that only lands in memory is undone by a restart, and the
		// code is live again for whoever saw it. Refuse the login
		// rather than honour a spend nothing recorded. A missed
		// LastLogin on an ordinary password login costs nothing, so
		// that path keeps the best-effort write below.
		//
		// Whether the code is still live is decided inside the op,
		// against the document being saved, rather than trusted from
		// the read above: a second reset in the window between them
		// issues a new code and must kill this one, a spend that landed
		// first must not be honoured twice, and on a replay either may
		// have come from another process.
		var spent User
		err := s.mutateLocked(func(st *storeState) error {
			u, ok := st.byID[id]
			if !ok || !u.resetCodeLive(now) || u.ResetCodeHash != hash {
				return ErrInvalidCredentials
			}
			u.ResetCodeHash = ""
			u.ResetCodeExpiresAt = time.Time{}
			u.LastLogin = now
			spent = *u
			return nil
		})
		if err != nil {
			return nil, err
		}
		return &spent, nil
	}
	// Saved only once the saved value is more than lastLoginGranularity
	// old; otherwise held in memory, where Get and List see it, until
	// the next save of any kind carries it. Compared against the saved
	// value rather than u.LastLogin, which every login moves: against
	// that, logins less than an hour apart would never save again.
	if now.Sub(s.lastLoginSaved[id]) < lastLoginGranularity {
		u.LastLogin = now
		cp := *u
		return &cp, nil
	}
	s.mutateBestEffortLocked(func(st *storeState) error {
		u, ok := st.byID[id]
		if !ok {
			return ErrInvalidCredentials
		}
		u.LastLogin = now
		return nil
	})
	if u, ok = s.byID[id]; !ok {
		return nil, ErrInvalidCredentials
	}
	cp := *u
	return &cp, nil
}

// Get returns a copy of the user with the given ID -- used to resolve a
// session's UserID back to a user on every authenticated request.
func (s *Store) Get(id string) (*User, bool) {
	s.reloadIfStale()
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[id]
	if !ok {
		return nil, false
	}
	cp := *u
	return &cp, true
}

// ByUsername looks up a user by username (case-insensitive) -- used by
// CLI recovery tooling to confirm an account exists before prompting for
// a new password.
func (s *Store) ByUsername(username string) (*User, bool) {
	s.reloadIfStale()
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[s.byName[strings.ToLower(username)]]
	if !ok {
		return nil, false
	}
	cp := *u
	return &cp, true
}

// SetPassword replaces username's password hash -- a CLI recovery path
// needs no current password since container/host access is the trust
// anchor for that tool. Also records PasswordChangedAt, which is what
// actually invalidates any session issued before this reset (see
// User.PasswordChangedAt) -- a CLI tool runs in a different process from
// the live server, so it has no way to reach into that server's
// in-memory SessionStore directly.
func (s *Store) SetPassword(username, newPassword string, now time.Time) error {
	if len(newPassword) < minPasswordLength {
		return ErrPasswordTooShort
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	// After the hash, before the write, like every other write here:
	// picking up another process's writes first avoids most save
	// conflicts -- see mutate.
	s.reloadIfStale()

	// A password change that only exists in memory must not be reported
	// as done: the caller would tell its operator the old credential is
	// dead, and a restart before the next good write would prove that
	// wrong. mutate installs it only once it is saved.
	return s.mutate(func(st *storeState) error {
		u, ok := st.byID[st.byName[strings.ToLower(username)]]
		if !ok {
			return ErrUserNotFound
		}
		u.PasswordHash = hash
		u.PasswordChangedAt = now
		// An account that has a password has a local password, by
		// definition. Stated explicitly rather than left to be derived
		// from OIDCIssuer, so a linked account (OIDC *and* a local
		// password) isn't misread as SSO-only by recovery tooling.
		u.HasLocalPassword = true
		// Setting a password ends any outstanding admin reset: the
		// account now has a credential only its owner knows, so the
		// code stops working and the forced-change gate lifts. Done
		// here, inside the store, so every path that sets a password
		// clears it rather than each caller having to remember.
		u.ResetCodeHash = ""
		u.ResetCodeExpiresAt = time.Time{}
		u.MustChangePassword = false
		return nil
	})
}

// List returns every account, sorted by username, with every credential
// and credential-adjacent field blanked.
func (s *Store) List() []User {
	s.reloadIfStale()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0, len(s.byID))
	for _, u := range s.byID {
		cp := *u
		cp.PasswordHash = ""
		// The reset-code hash is a credential verifier too, and this
		// list is the one that leaves the package on its way to an
		// admin-facing API. Blanked for the same reason the password
		// hash is, so neither can be serialized by accident.
		cp.ResetCodeHash = ""
		// TOTPSecret is worse than a verifier hash if it leaked -- it's
		// the actual shared secret, good for minting valid codes
		// indefinitely, not just checking one. RecoveryCodes are hashes
		// only, same category as ResetCodeHash above. Neither belongs
		// in an admin-facing account list. HasActiveTOTP still answers
		// truly on the copy (see User.totpSecretBlanked), so a caller
		// showing who has an authenticator app needs no extra Get.
		cp.totpSecretBlanked = u.TOTPSecret != ""
		cp.TOTPSecret = ""
		cp.RecoveryCodes = nil
		// Passkeys carries each credential's PublicKey -- not a secret
		// the way a private key would be, but still credential material
		// an admin-facing account list has no business serializing,
		// same stance as the three fields above. Blanked wholesale
		// rather than per-field: a caller that needs a count must call
		// a dedicated accessor instead of reading
		// len(this copy's Passkeys), which always reads zero now.
		cp.Passkeys = nil
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}
