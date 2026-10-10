package gauntlet

import (
	"sync"
	"time"
)

// AccountLockouts is where a LoginLimiter keeps an account's login
// lockout so it survives a restart. *Store implements it, on the
// account's own record.
//
// It holds only the lockout's end. A host's own store that implements
// just this loses, on restart, a disabled sign-in (the account signs in
// again) and the count of lockouts (the next one is short again): the
// limiter keeps those in its memory. Implement AccountLockoutRecords
// too to keep them.
type AccountLockouts interface {
	// LoginLockedUntil returns when accountID's lockout ends, or the
	// zero time if it has none or does not exist.
	LoginLockedUntil(accountID string) time.Time
	// SetLoginLockedUntil records a lockout ending at until; the zero
	// time clears it.
	SetLoginLockedUntil(accountID string, until time.Time) error
}

// AccountLockoutRecords is an AccountLockouts that also keeps a disabled
// sign-in and the count of lockouts, so they survive a restart too. A
// LoginLimiter given one reads and writes all three through it and
// keeps none of them in its memory. *Store does not need it.
type AccountLockoutRecords interface {
	AccountLockouts
	// LoginLockoutRecord returns accountID's record, all zero if it has
	// none or does not exist.
	LoginLockoutRecord(accountID string) LoginLockoutRecord
	// SetLoginLockoutRecord saves rec as accountID's record, all three
	// fields in one write: a disable saved without its lockout, or the
	// other way round, would be read back as a state the limiter never
	// decided. An all-zero rec clears it.
	SetLoginLockoutRecord(accountID string, rec LoginLockoutRecord) error
}

// LoginLockoutRecord is what a LoginLimiter keeps on an account through
// AccountLockoutRecords: the fields *Store keeps on User as
// LoginLockedUntil, LoginLockoutCount and LoginDisabledAt.
type LoginLockoutRecord struct {
	// LockedUntil is when the lockout ends; zero for none.
	LockedUntil time.Time
	// Lockouts is the count of lockouts since the last completed
	// sign-in; each lasts longer than the one before.
	Lockouts int
	// DisabledAt is when sign-in was disabled; zero while it is not.
	DisabledAt time.Time
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

// UnlockLogin lifts a disabled sign-in on accountID (#44; it also lifts
// itself, LoginDisableDuration after it began, #70) and clears its
// lockout and its count of lockouts, in one write: afterwards the
// account signs in as one that never failed. Refused with
// ErrUserNotFound for an account that does not exist; an account with
// nothing to clear costs no write.
//
// The store has no notion of who is asking: deciding who may unlock
// whom is the caller's job.
//
// A running LoginLimiter still holds its in-memory count of the
// account's recent wrong guesses (up to one window of them), and may
// hold a decision it has yet to save; a process with a limiter calls
// LoginLimiter.UnlockLogin instead, which clears those and makes this
// same write. This method is for a caller with no limiter -- a CLI
// opening the store for one command.
//
// Lifting the admin's disable also retires the lone-admin unlock code
// (unlockcode.go), in this process at once and in another on its next
// reload.
func (s *Store) UnlockLogin(accountID string) error {
	return s.setLockoutRecord(accountID, lockoutState{})
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

// LoginDisableDuration is how long a disabled sign-in lasts (#70): the
// disable at MaxConsecutiveLoginFailures lifts itself this long after
// User.LoginDisabledAt, with no admin unlock needed. Nothing is written
// to make it lift: LoginDisabledAt and the clock are enough (see
// lapsed).
const LoginDisableDuration = 24 * time.Hour

// disabled reports whether the state records a disabled sign-in -- one
// that may since have run out (lapsed).
func (a lockoutState) disabled() bool { return !a.disabledAt.IsZero() }

// lapsed reports whether the state records a disable that has run out
// by now: LoginDisableDuration after it began.
func (a lockoutState) lapsed(now time.Time) bool {
	return a.disabled() && !loginDisabledAt(a.disabledAt, now)
}

// loginDisabledAt reports whether a sign-in disabled at disabledAt (zero
// for never) is still disabled at now.
func loginDisabledAt(disabledAt, now time.Time) bool {
	return !disabledAt.IsZero() && now.Before(disabledAt.Add(LoginDisableDuration))
}

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
// Unexported, so only *Store has it. A limiter given an
// AccountLockoutRecords uses it through recordLockouts. One given nil or
// any other AccountLockouts keeps the count of lockouts and a disabled
// sign-in in its own memory instead (memoryLockouts), so a restart loses
// both. Either way it keeps counting guesses made before a password
// change until they age out of the window, as before.
//
// reset reports that the password change was an admin's reset code, the
// account still holding it unspent: that change also lifted a disable
// (IssueResetCode), so a disable the limiter has yet to save goes too.
type lockoutRecorder interface {
	lockoutRecord(accountID string) (st lockoutState, passwordChangedAt time.Time, reset bool)
	// setLockoutRecord writes st to accountID's record in one write, or
	// nothing if the record already says st.
	setLockoutRecord(accountID string, st lockoutState) error
}

// lockoutRecord implements lockoutRecorder.
// An unspent code is taken as a reset whether or not it has expired:
// it still dates the last password change, which was the admin's.
func (s *Store) lockoutRecord(accountID string) (lockoutState, time.Time, bool) {
	s.reloadIfStale()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if u, ok := s.byID[accountID]; ok {
		return lockoutState{
			until:      u.LoginLockedUntil,
			episodes:   max(u.LoginLockoutCount, 0), // a hand-edited negative count is none
			disabledAt: u.LoginDisabledAt,
		}, u.PasswordChangedAt, u.MustChangePassword && u.ResetCodeHash != ""
	}
	return lockoutState{}, time.Time{}, false
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
	requirePasswordChange(accountID string, now time.Time) error
}

// requirePasswordChange implements passwordChangeRequirer: one write
// setting MustChangePassword and ending every session the account holds
// (SessionsEndedAt, #44), or none if the flag is already set. For an
// account with no local password it only ends the sessions.
//
// The sessions go because the change-password door asks for no current
// password while MustChangePassword is set (gate's
// handleChangePassword): that is safe only if whoever stands at the door
// has just proved the account with both factors. A session issued before
// the run of failures -- a cookie someone else may hold -- would
// otherwise reach the door and choose the new password. Ending them
// leaves a fresh, complete sign-in as the only way there (owner,
// 2026-10-02).
//
// PasswordChangedAt is left alone: the password has not changed, and
// guesses at it still count (lockoutRecorder). A flag already set needs
// nothing: every session then either predates the write that set it, and
// was ended by it, or came from a complete sign-in since.
func (s *Store) requirePasswordChange(accountID string, now time.Time) error {
	s.reloadIfStale()
	return s.mutate(func(st *storeState) error {
		u, ok := st.byID[accountID]
		if !ok {
			return ErrUserNotFound
		}
		// An account with no local password signs in through its
		// identity provider, so the thing the failures put at risk is
		// the provider identity, which this module cannot change. The
		// flag would only shut it out of everything behind a door that
		// refuses it (handleChangePassword), until an operator stepped
		// in. Its sessions still end; the flag is left alone.
		if !u.HasLocalPassword {
			u.SessionsEndedAt = now
			return nil
		}
		if u.MustChangePassword {
			return errNoChange
		}
		u.MustChangePassword = true
		u.SessionsEndedAt = now
		return nil
	})
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

func (b boundLockouts) lockoutRecord(accountID string) (lockoutState, time.Time, bool) {
	b.mem.mu.Lock()
	st := b.mem.states[accountID]
	b.mem.mu.Unlock()
	if b.base != nil {
		st.until = b.base.LoginLockedUntil(accountID)
	}
	return st, time.Time{}, false
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

// recordLockouts is a host's AccountLockoutRecords as a lockoutRecorder.
// Like boundLockouts it never knows when a password changed, so never of
// a reset either.
type recordLockouts struct{ r AccountLockoutRecords }

func (w recordLockouts) lockoutRecord(accountID string) (lockoutState, time.Time, bool) {
	rec := w.r.LoginLockoutRecord(accountID)
	return lockoutState{
		until:      rec.LockedUntil,
		episodes:   max(rec.Lockouts, 0), // a negative count is none, as on the *Store
		disabledAt: rec.DisabledAt,
	}, time.Time{}, false
}

func (w recordLockouts) setLockoutRecord(accountID string, st lockoutState) error {
	return w.r.SetLoginLockoutRecord(accountID, LoginLockoutRecord{
		LockedUntil: st.until,
		Lockouts:    st.episodes,
		DisabledAt:  st.disabledAt,
	})
}
