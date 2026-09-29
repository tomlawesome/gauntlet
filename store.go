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

// checkAdmins refuses a document with more than one admin. None is fine:
// that is a deployment before Register, or one whose admin was never
// created.
func (f storeFile) checkAdmins() error {
	admins := 0
	for _, u := range f.Users {
		if u != nil && u.Role == RoleAdmin {
			admins++
		}
	}
	if admins > 1 {
		return fmt.Errorf("%w (found %d)", errMultipleAdmins, admins)
	}
	return nil
}

// Options configures OpenStore.
type Options struct {
	// Log receives warnings (a concurrent write from another process was
	// overwritten -- see tryPersistLocked) and errors (a change could not
	// be persisted and exists only in memory -- see persistLocked). nil
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
	mu        sync.RWMutex
	backend   persist.Backend
	log       *slog.Logger
	byID      map[string]*User
	byName    map[string]string  // lowercased username -> ID
	oidcIndex map[oidcKey]string // (issuer, subject) -> ID, see ByOIDCIdentity
	// version is the backend's token for the document as of the last
	// load, so a running server can pick up a change made by a separate
	// process -- namely a CLI recovery tool, which opens its own
	// independent Store against the same backend. Without this, a
	// password reset would silently have no effect on an already-running
	// server until it restarts, defeating the point of a recovery tool
	// that shouldn't require one.
	//
	// It is also what makes a write conditional: see persistLocked.
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

// reloadTimeout bounds one staleness check against the backend. Long
// enough that an ordinary slow query is not mistaken for an outage,
// short enough that a stalled backend does not hold a request goroutine
// and a pool connection indefinitely. Exceeding it is not fatal -- the
// store keeps serving what it already has in memory.
//
// A var, not a const, only so tests can shorten it. Nothing outside
// tests assigns to it.
var reloadTimeout = 5 * time.Second

// saveTimeout is the write-side counterpart: it bounds one save in
// tryPersistLocked (Store and TokenStore alike), which runs while the
// store's write lock is held. Without it a backend that stops answering
// mid-save would hold that lock, and with it every login and every
// signed-in request, until the process was restarted. A save that
// overruns fails like any other save failure: the caller rolls its
// change back and reports the error.
//
// That protection only reaches a backend that honours ctx. The shipped
// file backends (persist/file.go's Save, and EncryptedFileBackend on top
// of it) call plain os.ReadFile/CreateTemp/Write/Sync/Rename, none of
// which take a context or can be interrupted by one -- so on a hung
// mount the deadline never fires. reloadTimeout has the same limit on
// the read side.
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
		backend:   b,
		log:       opts.Log,
		byID:      make(map[string]*User),
		byName:    make(map[string]string),
		oidcIndex: make(map[oidcKey]string),
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
	s.byID = make(map[string]*User, len(file.Users))
	s.byName = make(map[string]string, len(file.Users))
	s.oidcIndex = make(map[oidcKey]string, len(file.Users))
	for _, u := range file.Users {
		// A JSON array containing `null` unmarshals successfully into a
		// nil *User -- valid JSON, so the error check above doesn't
		// catch it.
		if u == nil {
			continue
		}
		s.byID[u.ID] = u
		s.byName[strings.ToLower(u.Username)] = u.ID
		if u.OIDCIssuer != "" || u.OIDCSubject != "" {
			s.oidcIndex[oidcKey{issuer: u.OIDCIssuer, subject: u.OIDCSubject}] = u.ID
		}
	}
	s.version = version
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
	// concurrent in-process write (persistLocked/tryPersistLocked) that
	// landed while this call was reading without the lock. A version
	// that moved at all between here and the write-lock check below
	// means some other caller's write is now the authoritative state,
	// and applying a snapshot read before it would silently revert that
	// write.
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
	// keep serving what is in memory, and say why once. A server with its
	// own live accounts saves over this on its next write; one that opened
	// on an empty backend has none to save, so registrationOpenGuard keeps
	// registration closed instead of treating Count() == 0 as a fresh
	// install.
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
	// registrationOpenGuard re-checks under the lock inside createLocked,
	// and that remains what actually guarantees exactly one account can
	// be self-registered.
	if err := func() error {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return registrationOpenGuard(s)
	}(); err != nil {
		return nil, err
	}

	return s.createLocked(username, password, RoleAdmin, now, registrationOpenGuard)
}

// registrationOpenGuard is Register's under-the-lock precondition: no
// account may exist yet. Re-read from the live store with the write
// lock held (see createLocked), which is what makes "exactly one
// account can ever be self-registered" actually hold under concurrency.
//
// hasRefusedVersion also closes it: a document with accounts exists on
// disk even though this process refused to apply it (see reloadIfStale),
// so a store that opened on an empty backend must not read its own
// empty Count() as a fresh install and create a second admin on top of
// the one the operator already has.
func registrationOpenGuard(s *Store) error {
	if len(s.byID) > 0 || s.hasRefusedVersion {
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
	// Same as Register: a whole-document save is built from what this
	// process holds, so pick up another process's writes first or the
	// save writes over them.
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

	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.byID[id]
	if !ok {
		return nil, ErrUserNotFound
	}
	if u.Role == RoleAdmin {
		return nil, ErrCannotDeleteAdmin
	}

	delete(s.byID, id)
	delete(s.byName, strings.ToLower(u.Username))
	oidcKeyDeleted := oidcKey{issuer: u.OIDCIssuer, subject: u.OIDCSubject}
	if u.OIDCIssuer != "" {
		delete(s.oidcIndex, oidcKeyDeleted)
	}
	if err := s.tryPersistLocked(); err != nil {
		// A deletion that only exists in memory must not be reported as
		// done: the caller would revoke the account's sessions and
		// tokens and tell its operator the account is gone, and a
		// restart before the next good write would bring it straight
		// back -- with none of those revocations remembered.
		s.byID[id] = u
		s.byName[strings.ToLower(u.Username)] = u.ID
		if u.OIDCIssuer != "" {
			s.oidcIndex[oidcKeyDeleted] = u.ID
		}
		return nil, fmt.Errorf("saving accounts: %w", err)
	}

	cp := *u
	cp.PasswordHash = ""
	return &cp, nil
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
	// Like every other write here: the save below is a whole-document
	// rewrite of what this process holds.
	s.reloadIfStale()

	s.mu.Lock()
	defer s.mu.Unlock()

	var current *User
	for _, u := range s.byID {
		if u.Role == RoleAdmin {
			current = u
			break
		}
	}
	if current == nil {
		return nil, nil, ErrNoAdmin
	}

	targetID, ok := s.byName[strings.ToLower(toUsername)]
	if !ok {
		return nil, nil, ErrUserNotFound
	}
	target := s.byID[targetID]
	if target.ID == current.ID {
		return nil, nil, ErrTransferToSelf
	}

	prevCurrentRole, prevCurrentRoleChangedAt := current.Role, current.RoleChangedAt
	prevTargetRole, prevTargetRoleChangedAt := target.Role, target.RoleChangedAt

	current.Role = RoleUser
	current.RoleChangedAt = now
	target.Role = RoleAdmin
	target.RoleChangedAt = now
	if err := s.tryPersistLocked(); err != nil {
		// Put both roles back rather than leave this call's caller
		// believing the transfer happened: an admin transfer that only
		// exists in memory is a deployment that silently regains its old
		// admin -- or loses the only one -- on the next restart.
		current.Role, current.RoleChangedAt = prevCurrentRole, prevCurrentRoleChangedAt
		target.Role, target.RoleChangedAt = prevTargetRole, prevTargetRoleChangedAt
		return nil, nil, fmt.Errorf("saving accounts: %w", err)
	}

	fromCopy, toCopy := *current, *target
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
// with the write lock already held and aborts the insert if it returns
// an error -- that's the hook callers use to make a precondition
// ("registration is still open") atomic with the insert itself rather
// than checking it beforehand and racing.
//
// HashPassword deliberately runs before the lock is acquired: Argon2id
// is ~100ms by design, and holding the store's write lock for that long
// would serialize every reader behind each in-flight registration -- an
// easy self-inflicted DoS. The cost of hashing before the guard runs is
// one wasted hash on the losing side of a race, which is the right
// trade.
func (s *Store) createLocked(username, password string, role Role, now time.Time, guard func(*Store) error) (*User, error) {
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

	s.mu.Lock()
	defer s.mu.Unlock()

	if guard != nil {
		if err := guard(s); err != nil {
			return nil, err
		}
	}

	key := strings.ToLower(username)
	if _, exists := s.byName[key]; exists {
		return nil, ErrUsernameTaken
	}

	u := &User{
		ID:           newID(),
		Username:     username,
		PasswordHash: hash,
		Role:         role,
		CreatedAt:    now,
		// A real password the user chose, so it may later be reset.
		HasLocalPassword: true,
	}
	s.byID[u.ID] = u
	s.byName[key] = u.ID
	if err := s.tryPersistLocked(); err != nil {
		// An account that only exists in memory must not be reported as
		// created: Register/CreateUser's callers hand the operator a
		// session or a success response for it, and a restart before
		// the next good write would erase the account under them.
		delete(s.byID, u.ID)
		delete(s.byName, key)
		return nil, fmt.Errorf("saving accounts: %w", err)
	}

	cp := *u
	return &cp, nil
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

	s.mu.Lock()
	defer s.mu.Unlock()

	key := oidcKey{issuer: issuer, subject: subject}
	if id, ok := s.oidcIndex[key]; ok {
		if u, ok := s.byID[id]; ok {
			// LastLogin only -- a missed update here costs nothing
			// worth failing an otherwise-successful SSO login over, so
			// this keeps the log-and-carry-on write (same reasoning as
			// Authenticate's ordinary-login path below).
			u.LastLogin = now
			s.persistLocked()
			cp := *u
			return &cp, false, nil
		}
	}

	unmatchable, err := unmatchablePasswordHash()
	if err != nil {
		return nil, false, err
	}

	role := RoleUser
	if len(s.byID) == 0 {
		role = RoleAdmin
	}

	u := &User{
		ID:           newID(),
		Username:     s.uniqueUsernameLocked(usernameHint, issuer, subject),
		PasswordHash: unmatchable,
		Role:         role,
		CreatedAt:    now,
		LastLogin:    now,
		OIDCIssuer:   issuer,
		OIDCSubject:  subject,
		// Explicitly false: the hash above is random and unmatchable, so
		// there is no password here to reset. Recorded rather than
		// inferred, because the hash itself is indistinguishable from a
		// real one.
		HasLocalPassword: false,
	}
	s.byID[u.ID] = u
	s.byName[strings.ToLower(u.Username)] = u.ID
	s.oidcIndex[key] = u.ID
	if err := s.tryPersistLocked(); err != nil {
		// A JIT-provisioned account that only exists in memory must not
		// be reported as created: the caller is about to sign this
		// person in as though the account durably exists, and a restart
		// before the next good write would erase it while sessions
		// referencing its ID are still live.
		delete(s.byID, u.ID)
		delete(s.byName, strings.ToLower(u.Username))
		delete(s.oidcIndex, key)
		return nil, false, fmt.Errorf("saving accounts: %w", err)
	}

	cp := *u
	return &cp, true, nil
}

// uniqueUsernameLocked picks hint if it's non-empty and not already
// taken, otherwise a deterministic synthetic username derived from
// (issuer, subject) -- see FindOrCreateOIDCUser's doc comment. Callers
// must hold s.mu.
func (s *Store) uniqueUsernameLocked(hint, issuer, subject string) string {
	// The hint is whatever the identity provider put in
	// preferred_username or email -- text this package does not
	// control. An unusable one is dropped, not rejected, so the person
	// still gets a stable account under the generated name below.
	hint = sanitiseUsernameHint(hint)
	if hint != "" {
		if _, taken := s.byName[strings.ToLower(hint)]; !taken {
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
	for n := 8; n <= len(full); n += 8 {
		candidate := "oidc-" + full[:n]
		if _, taken := s.byName[strings.ToLower(candidate)]; !taken {
			return candidate
		}
	}
	return "oidc-" + newID() // practically unreachable
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

	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.byID[userID]
	if !ok {
		return ErrUserNotFound
	}

	key := oidcKey{issuer: issuer, subject: subject}
	if existingID, ok := s.oidcIndex[key]; ok && existingID != userID {
		return ErrOIDCIdentityTaken
	}
	// Already connected to something else. Idempotent for the same
	// identity (above and below), refused for a different one: the old
	// (issuer, subject) would stay in the index and go on signing in as
	// this account, so "re-link" would quietly mean "two ways in".
	if u.OIDCSubject != "" && (u.OIDCIssuer != issuer || u.OIDCSubject != subject) {
		return ErrOIDCAlreadyLinked
	}

	prevIssuer, prevSubject := u.OIDCIssuer, u.OIDCSubject
	prevHash, prevHasLocalPassword := u.PasswordHash, u.HasLocalPassword
	prevPasswordChangedAt := u.PasswordChangedAt
	prevTOTPSecret := u.TOTPSecret
	prevTOTPConfirmedAt := u.TOTPConfirmedAt
	prevTOTPLastCounter := u.TOTPLastCounter
	prevRecoveryCodes := u.RecoveryCodes
	prevPasskeys := u.Passkeys
	prevResetHash, prevResetExpiresAt := u.ResetCodeHash, u.ResetCodeExpiresAt
	prevMustChange := u.MustChangePassword
	_, hadIndexEntry := s.oidcIndex[key]

	u.OIDCIssuer = issuer
	u.OIDCSubject = subject
	if u.Role != RoleAdmin {
		u.PasswordHash = unmatchable
		u.HasLocalPassword = false
		// See the doc comment above: every non-admin loses both local
		// credentials on linking, not just the password.
		u.TOTPSecret = ""
		u.TOTPConfirmedAt = time.Time{}
		u.TOTPLastCounter = 0
		u.RecoveryCodes = nil
		u.Passkeys = nil
		// An outstanding admin reset dies with the password it was a
		// stand-in for: Authenticate treats a live code as the
		// password, so left here it would keep a local way in open for
		// up to 24 hours after the account became SSO-only, and the
		// forced-change flag would then door an account with nothing
		// to change.
		u.ResetCodeHash = ""
		u.ResetCodeExpiresAt = time.Time{}
		u.MustChangePassword = false
	}
	// Invalidates every session issued before this point, including in
	// another process -- the account's credentials just changed
	// fundamentally, so anything holding a session from before that
	// should have to come back through the IdP. True for the admin too,
	// whose password survives: a second way into the account was just
	// attached, and a session issued before that should be re-made
	// through one of them.
	u.PasswordChangedAt = now
	s.oidcIndex[key] = userID
	if err := s.tryPersistLocked(); err != nil {
		// A link that only exists in memory must not be reported as
		// done: for everyone but the admin this also destroyed the
		// local password above, so the caller would tell its operator
		// SSO is now the only way in when a restart could revert to a
		// password nobody remembers is still live -- or, worse, leave
		// the account's SSO index entry pointing nowhere durable.
		u.OIDCIssuer, u.OIDCSubject = prevIssuer, prevSubject
		u.PasswordHash, u.HasLocalPassword = prevHash, prevHasLocalPassword
		u.PasswordChangedAt = prevPasswordChangedAt
		u.TOTPSecret = prevTOTPSecret
		u.TOTPConfirmedAt = prevTOTPConfirmedAt
		u.TOTPLastCounter = prevTOTPLastCounter
		u.RecoveryCodes = prevRecoveryCodes
		u.Passkeys = prevPasskeys
		u.ResetCodeHash, u.ResetCodeExpiresAt = prevResetHash, prevResetExpiresAt
		u.MustChangePassword = prevMustChange
		if hadIndexEntry {
			s.oidcIndex[key] = userID
		} else {
			delete(s.oidcIndex, key)
		}
		return fmt.Errorf("saving accounts: %w", err)
	}
	return nil
}

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
		// Re-checked under the write lock rather than trusted from the
		// read above: a second reset in the window between them issues a
		// new code and must kill this one, and a spend that landed first
		// must not be honoured twice.
		if !u.resetCodeLive(now) {
			return nil, ErrInvalidCredentials
		}
		// Spending the code is the write that matters here: a spend
		// that only lands in memory is undone by a restart, and the
		// code is live again for whoever saw it. Refuse the login
		// rather than honour a spend nothing recorded. A missed
		// LastLogin on an ordinary password login costs nothing, so
		// that path keeps the log-and-carry-on write below.
		prevHash, prevExpires, prevLogin := u.ResetCodeHash, u.ResetCodeExpiresAt, u.LastLogin
		u.ResetCodeHash = ""
		u.ResetCodeExpiresAt = time.Time{}
		u.LastLogin = now
		if err := s.tryPersistLocked(); err != nil {
			u.ResetCodeHash, u.ResetCodeExpiresAt, u.LastLogin = prevHash, prevExpires, prevLogin
			return nil, fmt.Errorf("saving the spent reset code: %w", err)
		}
		cp := *u
		return &cp, nil
	}
	u.LastLogin = now
	s.persistLocked()
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

	// After the hash, before the lock, like every other write here: the
	// save below is a whole-document rewrite of what this process holds.
	s.reloadIfStale()

	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[s.byName[strings.ToLower(username)]]
	if !ok {
		return ErrUserNotFound
	}
	prevHash := u.PasswordHash
	prevPasswordChangedAt := u.PasswordChangedAt
	prevHasLocalPassword := u.HasLocalPassword
	prevResetHash := u.ResetCodeHash
	prevResetExpiresAt := u.ResetCodeExpiresAt
	prevMustChange := u.MustChangePassword

	u.PasswordHash = hash
	u.PasswordChangedAt = now
	// An account that has a password has a local password, by
	// definition. Stated explicitly rather than left to be derived from
	// OIDCIssuer, so a linked account (OIDC *and* a local password)
	// isn't misread as SSO-only by recovery tooling.
	u.HasLocalPassword = true
	// Setting a password ends any outstanding admin reset: the account
	// now has a credential only its owner knows, so the code stops
	// working and the forced-change gate lifts. Done here, inside the
	// store, so every path that sets a password clears it rather than
	// each caller having to remember.
	u.ResetCodeHash = ""
	u.ResetCodeExpiresAt = time.Time{}
	u.MustChangePassword = false
	if err := s.tryPersistLocked(); err != nil {
		// A password change that only exists in memory must not be
		// reported as done: the caller would tell its operator the old
		// credential is dead, and a restart before the next good write
		// would prove that wrong.
		u.PasswordHash = prevHash
		u.PasswordChangedAt = prevPasswordChangedAt
		u.HasLocalPassword = prevHasLocalPassword
		u.ResetCodeHash = prevResetHash
		u.ResetCodeExpiresAt = prevResetExpiresAt
		u.MustChangePassword = prevMustChange
		return fmt.Errorf("saving accounts: %w", err)
	}
	return nil
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
		// in an admin-facing account list.
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

// tryPersistLocked is persistLocked's error-returning half, for the
// callers (TransferAdmin, SetPassword, DeleteUser, createLocked --
// behind Register and CreateUser --, FindOrCreateOIDCUser's new-account
// branch, LinkOIDCIdentity) that change a credential, a role, or which
// accounts exist, and so must not let the caller believe a write
// happened when it didn't -- see each one's own restore-on-error
// comment. Every other caller keeps using persistLocked below, which
// keeps the default swallow-and-log behaviour.
func (s *Store) tryPersistLocked() error {
	if s.backend == nil {
		return nil
	}
	list := make([]*User, 0, len(s.byID))
	for _, u := range s.byID {
		list = append(list, u)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Username < list[j].Username })

	data, err := json.MarshalIndent(storeFile{Users: list}, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding accounts for persistence failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), saveTimeout)
	defer cancel()
	version, conflicted, err := persist.SaveWithRetry(ctx, s.backend, data, s.version)
	if err != nil {
		return fmt.Errorf("writing accounts to %s failed: %w", s.backend.Describe(), err)
	}
	if conflicted && s.log != nil {
		// Another process wrote while this change was pending -- almost
		// always a CLI recovery command against a live server. This
		// change went on top; a concurrent change to a *different*
		// account may have been lost. Said out loud rather than
		// implied, because a whole-document store cannot merge them.
		s.log.Warn(fmt.Sprintf("accounts store was modified by another process while this change "+
			"was pending (%s); this change was applied on top", s.backend.Describe()))
	}
	s.version = version
	return nil
}

// persistLocked is the swallow-and-log default every ordinary write
// uses: the in-memory state (which every read goes through) stays
// correct either way, so a transient disk issue degrades to "won't
// survive a restart right now" rather than failing the caller outright.
// Kept by FindOrCreateOIDCUser's existing-login branch and
// Authenticate's ordinary-login branch, both of which only touch
// LastLogin -- a bookkeeping timestamp not worth failing an otherwise
// successful login over.
func (s *Store) persistLocked() {
	if err := s.tryPersistLocked(); err != nil && s.log != nil {
		s.log.Error(fmt.Sprintf("%v -- this change exists only in memory and will be lost on restart", err))
	}
}
