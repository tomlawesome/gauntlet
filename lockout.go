package gauntlet

import (
	"sync"
	"time"
)

// AccountLockouts is where a LoginLimiter keeps an account's login
// lockout so it survives a restart. *Store implements it, on the
// account's own record.
type AccountLockouts interface {
	// LoginLockedUntil returns when accountID's lockout ends, or the
	// zero time if it has none or does not exist.
	LoginLockedUntil(accountID string) time.Time
	// SetLoginLockedUntil records a lockout ending at until; the zero
	// time clears it.
	SetLoginLockedUntil(accountID string, until time.Time) error
}

// LoginLockedUntil implements AccountLockouts.
func (s *Store) LoginLockedUntil(accountID string) time.Time {
	s.reloadIfStale()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if u, ok := s.byID[accountID]; ok {
		return u.LoginLockedUntil
	}
	return time.Time{}
}

// SetLoginLockedUntil implements AccountLockouts. A lockout that cannot
// be saved is not recorded and the error is returned, like every other
// write here. It sets the lockout's end only; the count of lockouts and
// a disabled sign-in (#44) are the limiter's to write, through
// lockoutRecorder.
func (s *Store) SetLoginLockedUntil(accountID string, until time.Time) error {
	s.reloadIfStale()
	return s.mutate(func(st *storeState) error {
		u, ok := st.byID[accountID]
		if !ok {
			return ErrUserNotFound
		}
		if u.LoginLockedUntil.Equal(until) {
			return errNoChange
		}
		u.LoginLockedUntil = until
		return nil
	})
}

// UnlockLogin lifts a disabled sign-in on accountID (#44) and clears its
// lockout and its count of lockouts, in one write: afterwards the
// account signs in as one that never failed. Refused with
// ErrUserNotFound for an account that does not exist; an account with
// nothing to clear costs no write.
//
// The store has no notion of who is asking: deciding who may unlock
// whom is the caller's job.
//
// #44 follow-up: a running LoginLimiter still holds its in-memory count
// of the account's recent wrong guesses (up to one window of them), and
// may hold a decision it has yet to save; the admin unlock route should
// clear those too, through a limiter method added with it, or the
// account can stay refused until that window passes.
func (s *Store) UnlockLogin(accountID string) error {
	s.reloadIfStale()
	return s.mutate(func(st *storeState) error {
		u, ok := st.byID[accountID]
		if !ok {
			return ErrUserNotFound
		}
		if u.LoginLockedUntil.IsZero() && u.LoginLockoutCount == 0 && u.LoginDisabledAt.IsZero() {
			return errNoChange
		}
		u.LoginLockedUntil = time.Time{}
		u.LoginLockoutCount = 0
		u.LoginDisabledAt = time.Time{}
		return nil
	})
}

// lockoutState is what an account's record says about its sign-in
// limit: the three fields a LoginLimiter writes, always together.
type lockoutState struct {
	// until is User.LoginLockedUntil.
	until time.Time
	// episodes is User.LoginLockoutCount.
	episodes int
	// disabledAt is User.LoginDisabledAt.
	disabledAt time.Time
}

// equal compares two states field by field, times by instant.
func (a lockoutState) equal(b lockoutState) bool {
	return a.until.Equal(b.until) && a.episodes == b.episodes && a.disabledAt.Equal(b.disabledAt)
}

// disabled reports whether the state disables the account's sign-in.
func (a lockoutState) disabled() bool { return !a.disabledAt.IsZero() }

// lockoutRecorder is what *Store offers a LoginLimiter beyond
// AccountLockouts: the whole lockout state together with the account's
// PasswordChangedAt, in one read, and the whole state in one write.
//
// Guesses made before a password change were at the old password, so
// the limiter stops counting them (ReserveAccount). In this build only
// SetPassword and IssueResetCode move it, and they clear the lockout in
// the same write; LinkOIDCIdentity ends sessions through
// SessionsEndedAt and leaves both alone (#28). A document an older
// gauntlet or mikroview wrote may record an SSO link in
// PasswordChangedAt, so the limiter still takes a bump as a password
// change only while the record carries no lockout.
//
// Unexported, so only *Store has it. A limiter given nil or any other
// AccountLockouts keeps the count of lockouts and a disabled sign-in in
// its own memory instead (memoryLockouts), and keeps counting guesses
// made before a password change until they age out of the window, as
// before.
type lockoutRecorder interface {
	lockoutRecord(accountID string) (st lockoutState, passwordChangedAt time.Time)
	// setLockoutRecord writes st to accountID's record in one write, or
	// nothing if the record already says st.
	setLockoutRecord(accountID string, st lockoutState) error
}

// lockoutRecord implements lockoutRecorder.
func (s *Store) lockoutRecord(accountID string) (lockoutState, time.Time) {
	s.reloadIfStale()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if u, ok := s.byID[accountID]; ok {
		return lockoutState{
			until:      u.LoginLockedUntil,
			episodes:   max(u.LoginLockoutCount, 0), // a hand-edited negative count is none
			disabledAt: u.LoginDisabledAt,
		}, u.PasswordChangedAt
	}
	return lockoutState{}, time.Time{}
}

// setLockoutRecord implements lockoutRecorder. Like SetLoginLockedUntil,
// a state that cannot be saved is not recorded and the error returned.
func (s *Store) setLockoutRecord(accountID string, st lockoutState) error {
	s.reloadIfStale()
	return s.mutate(func(state *storeState) error {
		u, ok := state.byID[accountID]
		if !ok {
			return ErrUserNotFound
		}
		cur := lockoutState{until: u.LoginLockedUntil, episodes: u.LoginLockoutCount, disabledAt: u.LoginDisabledAt}
		if cur.equal(st) {
			return errNoChange
		}
		u.LoginLockedUntil = st.until
		u.LoginLockoutCount = st.episodes
		u.LoginDisabledAt = st.disabledAt
		return nil
	})
}

// passwordChangeRequirer is the one other write a LoginLimiter makes to
// an account: MustChangePassword, after a run of second-factor failures
// (SecondFactorFailed). Unexported and *Store only, like
// lockoutRecorder; a limiter given anything else has no account to set
// it on and skips it.
type passwordChangeRequirer interface {
	requirePasswordChange(accountID string) error
}

// requirePasswordChange implements passwordChangeRequirer: one write
// setting MustChangePassword, or none if it is already set.
func (s *Store) requirePasswordChange(accountID string) error {
	s.reloadIfStale()
	return s.mutate(func(st *storeState) error {
		u, ok := st.byID[accountID]
		if !ok {
			return ErrUserNotFound
		}
		if u.MustChangePassword {
			return errNoChange
		}
		u.MustChangePassword = true
		return nil
	})
}

// readLockout reads accountID's lockout from lockouts, and when the
// password last changed if lockouts can say (see lockoutRecorder).
func readLockout(lockouts AccountLockouts, accountID string) (lockedUntil, passwordChangedAt time.Time) {
	if r, ok := lockouts.(lockoutRecorder); ok {
		st, changed := r.lockoutRecord(accountID)
		return st.until, changed
	}
	return lockouts.LoginLockedUntil(accountID), time.Time{}
}

// memoryLockouts is the lockoutRecorder a LoginLimiter uses when it is
// not given the *Store: nil, or some other AccountLockouts. The count of
// lockouts and a disabled sign-in live here, in this process's memory
// only; the lockout's end goes to base when there is one (as it always
// has), and here too when there is not. It never knows when a password
// changed.
//
// Keyed by account ID, which a caller only ever takes from a real
// account, so it holds no more entries than there are accounts; an
// account whose state is all zero has none.
type memoryLockouts struct {
	mu     sync.Mutex
	states map[string]lockoutState
}

// boundLockouts is memoryLockouts with the AccountLockouts, if any, it
// stands in front of.
type boundLockouts struct {
	mem  *memoryLockouts
	base AccountLockouts // nil: the lockout's end is kept in mem too
}

func (b boundLockouts) lockoutRecord(accountID string) (lockoutState, time.Time) {
	b.mem.mu.Lock()
	st := b.mem.states[accountID]
	b.mem.mu.Unlock()
	if b.base != nil {
		st.until = b.base.LoginLockedUntil(accountID)
	}
	return st, time.Time{}
}

func (b boundLockouts) setLockoutRecord(accountID string, st lockoutState) error {
	if b.base != nil {
		if err := b.base.SetLoginLockedUntil(accountID, st.until); err != nil {
			return err
		}
	}
	b.mem.mu.Lock()
	defer b.mem.mu.Unlock()
	if st.equal(lockoutState{}) {
		delete(b.mem.states, accountID)
	} else {
		b.mem.states[accountID] = st
	}
	return nil
}
