package gauntlet

import (
	"fmt"
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

// SetLoginLockedUntil implements AccountLockouts. A failed save puts the
// old value back and returns the error, like every other write here.
func (s *Store) SetLoginLockedUntil(accountID string, until time.Time) error {
	s.reloadIfStale()
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[accountID]
	if !ok {
		return ErrUserNotFound
	}
	if u.LoginLockedUntil.Equal(until) {
		return nil
	}
	prev := u.LoginLockedUntil
	u.LoginLockedUntil = until
	if err := s.tryPersistLocked(); err != nil {
		u.LoginLockedUntil = prev
		return fmt.Errorf("saving accounts: %w", err)
	}
	return nil
}
