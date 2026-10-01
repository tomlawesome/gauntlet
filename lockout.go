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
