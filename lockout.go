package gauntlet

import "time"

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
// write here.
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

// lockoutRecorder is what *Store offers a LoginLimiter beyond
// AccountLockouts: the lockout together with when the account's
// password last changed, in one read. Guesses made before a password
// change were at the old password, so the limiter stops counting them
// (ReserveAccount). Unexported, so only *Store has it: a limiter given
// any other AccountLockouts keeps counting those guesses until they
// age out of the window, as before.
type lockoutRecorder interface {
	lockoutRecord(accountID string) (lockedUntil, passwordChangedAt time.Time)
}

// lockoutRecord implements lockoutRecorder.
func (s *Store) lockoutRecord(accountID string) (lockedUntil, passwordChangedAt time.Time) {
	s.reloadIfStale()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if u, ok := s.byID[accountID]; ok {
		return u.LoginLockedUntil, u.PasswordChangedAt
	}
	return time.Time{}, time.Time{}
}

// readLockout reads accountID's lockout from lockouts, and when the
// password last changed if lockouts can say (see lockoutRecorder).
func readLockout(lockouts AccountLockouts, accountID string) (lockedUntil, passwordChangedAt time.Time) {
	if r, ok := lockouts.(lockoutRecorder); ok {
		return r.lockoutRecord(accountID)
	}
	return lockouts.LoginLockedUntil(accountID), time.Time{}
}
