// Copied from mikroview's internal/auth/ratelimit.go (docs/adr/0001-
// shared-auth-module.md decision 3), then split by #19: counters for
// real accounts moved out of the capped map into their own, and a login
// lockout is kept on the account so it survives a restart.
package gauntlet

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/tomlawesome/gauntlet/internal/evict"
)

// maxLoginLimiterKeys bounds LoginLimiter's tracked-key map the same way
// every other unbounded-growth-risk map keyed on untrusted input has an
// explicit ceiling -- without it, an attacker trying many distinct
// usernames or source addresses could grow this without bound.
var maxLoginLimiterKeys = 4096

// LoginLimiter guards against brute-force login attempts with a
// sliding-window counter per key, kept in one of two places:
//
//   - Keys the caller chooses -- a source address, a username that
//     matches no account -- go in a map capped at maxLoginLimiterKeys
//     (Reserve, Release, Allow, RecordFailure). It is best effort: a
//     big enough flood of distinct keys evicts the oldest.
//   - A real account's counters are keyed by its ID (ReserveAccount,
//     ReserveRecheck). There can be no more of them than there are
//     accounts, so that map is never evicted and no flood of addresses
//     or made-up names can reset an account's count. Entries leave only
//     by expiring.
//
// A login lockout is also written to the account's record (see
// AccountLockouts), but only as it begins and as it clears, never per
// attempt: a stream of wrong guesses must not become a stream of disk
// writes.
type LoginLimiter struct {
	mu        sync.Mutex
	attempts  map[string][]time.Time
	accounts  map[string][]time.Time // bucket + account ID
	threshold int
	window    time.Duration

	// wantLockout is the lockout each account's record should carry,
	// until syncLockout has written it: the end time as one begins, the
	// zero time as one clears. At most one entry per account.
	wantLockout map[string]time.Time
	// persistMu orders syncLockout's writes, so a clear decided after a
	// lockout can never land before it. Taken without mu held.
	persistMu sync.Mutex

	log            *slog.Logger
	lastPressure   time.Time
	pressureLogged bool
}

// Account counter buckets. Login and its second-factor step share one
// budget; re-checking a signed-in caller's own password has its own, so
// a run of typos there cannot lock the single admin out of signing in.
const (
	loginBucket   = "login:"
	recheckBucket = "password-recheck:"
)

func NewLoginLimiter(threshold int, window time.Duration) *LoginLimiter {
	return &LoginLimiter{
		attempts:    make(map[string][]time.Time),
		accounts:    make(map[string][]time.Time),
		wantLockout: make(map[string]time.Time),
		threshold:   threshold,
		window:      window,
	}
}

// SetLog sets where the limiter reports eviction pressure on the capped
// map and a lockout it could not save. Call it before first use; nil
// (the default) discards both.
func (l *LoginLimiter) SetLog(log *slog.Logger) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.log = log
}

// Allow reports whether key is still under the failed-attempt
// threshold. Does not itself record an attempt.
//
// Prefer Reserve for anything guarding an expensive operation: Allow is
// a read, so check-then-act around a slow call lets a simultaneous burst
// pass the check together and consume far more than threshold attempts.
func (l *LoginLimiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.pruneLocked(key, now)) < l.threshold
}

// Reserve atomically checks the threshold and claims one attempt against
// it, returning false if key is already at the limit.
//
// This exists because Allow-then-hash-then-RecordFailure is a
// check-then-act race with a slow operation (e.g. Argon2id) sitting in
// the gap: several simultaneous attempts can all pass Allow before any
// of them reaches RecordFailure, admitting far more than threshold.
//
// Callers hold the reservation for the duration of the slow operation
// and call Release only on success, so a failure simply leaves the
// attempt counted.
func (l *LoginLimiter) Reserve(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.pruneLocked(key, now)) >= l.threshold {
		return false
	}
	if _, exists := l.attempts[key]; !exists && len(l.attempts) >= maxLoginLimiterKeys {
		l.evictOldestLocked(now)
	}
	l.attempts[key] = append(l.attempts[key], now)
	return true
}

// Release returns one reservation taken by Reserve -- called after a
// *successful* attempt, so that legitimate logins don't accumulate
// toward the threshold. Entries are interchangeable timestamps, so
// dropping the most recent is equivalent to dropping "ours".
func (l *LoginLimiter) Release(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.releaseIn(l.attempts, key, now)
}

// RecordFailure records one failed attempt for key.
func (l *LoginLimiter) RecordFailure(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, exists := l.attempts[key]; !exists && len(l.attempts) >= maxLoginLimiterKeys {
		l.evictOldestLocked(now)
	}
	l.attempts[key] = append(l.pruneLocked(key, now), now)
}

// pruneLocked drops key's attempts that have aged out of the window and
// returns what remains.
//
// It must not leave an entry behind for a key with nothing left, and
// must not create one for a key it has never seen -- see
// evictOldestLocked and maxLoginLimiterKeys: a stray empty entry per
// source address, held forever after that address's attempts have all
// aged out, is an unbounded-growth path the cap is supposed to close.
func (l *LoginLimiter) pruneLocked(key string, now time.Time) []time.Time {
	return l.pruneIn(l.attempts, key, now)
}

// pruneIn is pruneLocked for either map.
func (l *LoginLimiter) pruneIn(m map[string][]time.Time, key string, now time.Time) []time.Time {
	entries, ok := m[key]
	if !ok {
		return nil
	}
	cutoff := now.Add(-l.window)
	kept := entries[:0]
	for _, t := range entries {
		if !t.Before(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(m, key)
		return nil
	}
	m[key] = kept
	return kept
}

// evictOldestLocked makes room once the capped map is at
// maxLoginLimiterKeys: first by dropping every key whose attempts have
// all expired, and only if that is not enough by shedding the
// least-recently-active live ones -- the only case that loses a count,
// so it is logged.
//
// A batch rather than one, for internal/evict's reason: the keys are
// source addresses an attacker varies per request, so evicting exactly
// one leaves the map full and makes every subsequent request pay the
// whole scan. The account map is swept of expired entries at the same
// time, since both sweeps are the same walk.
func (l *LoginLimiter) evictOldestLocked(now time.Time) {
	for key := range l.attempts {
		l.pruneLocked(key, now)
	}
	for key := range l.accounts {
		l.pruneIn(l.accounts, key, now)
	}
	target := evict.Target(maxLoginLimiterKeys)
	if len(l.attempts) <= target {
		return
	}
	// Once per window, so a flood does not become a flood of log lines.
	if l.log != nil && (!l.pressureLogged || now.Sub(l.lastPressure) >= l.window) {
		l.log.Warn(fmt.Sprintf("login limiter: %d source addresses and unknown usernames are counting at once; "+
			"evicting the least recently active to stay under %d (accounts' own counters are unaffected)",
			len(l.attempts), maxLoginLimiterKeys))
		l.lastPressure, l.pressureLogged = now, true
	}
	evict.DownTo(l.attempts, target, func(times []time.Time) time.Time {
		if len(times) == 0 {
			return time.Time{} // shed first; pruneLocked should have removed it already
		}
		return times[len(times)-1]
	})
}

// ReserveAccount is Reserve for a real account's login, keyed by its ID
// rather than a name the caller typed: login and its second-factor step
// share this budget. See LoginLimiter for why it is kept apart from the
// capped map.
//
// lockouts is where the lockout is kept so it survives a restart --
// ordinarily the *Store the account lives in. The attempt that fills
// the window writes the lockout's end to the account, once; while one
// is in force every attempt is refused, whether or not this process saw
// the attempts that caused it. The first attempt after it ends clears
// it. nil keeps the lockout in memory only.
//
// A lockout that cannot be saved is logged, and still enforced in
// memory: the attempt it would refuse is refused either way.
func (l *LoginLimiter) ReserveAccount(lockouts AccountLockouts, accountID string, now time.Time) bool {
	var persisted time.Time
	if lockouts != nil {
		persisted = lockouts.LoginLockedUntil(accountID)
	}

	l.mu.Lock()
	if now.Before(persisted) {
		l.mu.Unlock()
		return false
	}
	key := loginBucket + accountID
	entries := l.pruneIn(l.accounts, key, now)
	if len(entries) >= l.threshold {
		l.mu.Unlock()
		return false
	}
	entries = append(entries, now)
	l.accounts[key] = entries
	sync := false
	switch {
	case len(entries) == l.threshold:
		// Refused from now until the oldest attempt in the window ages
		// out -- the moment the in-memory counter would admit one again.
		l.wantLockout[accountID] = entries[0].Add(l.window)
		sync = lockouts != nil
	case !persisted.IsZero():
		// A lockout on the record that has ended.
		l.wantLockout[accountID] = time.Time{}
		sync = lockouts != nil
	}
	l.mu.Unlock()

	if sync {
		l.syncLockout(lockouts, accountID)
	}
	return true
}

// ReleaseAccount is Release for ReserveAccount: called after a
// successful attempt. That is the account's owner signing in, so a
// lockout their own reservation recorded is cleared rather than left to
// lock them out.
func (l *LoginLimiter) ReleaseAccount(lockouts AccountLockouts, accountID string, now time.Time) {
	var persisted time.Time
	if lockouts != nil {
		persisted = lockouts.LoginLockedUntil(accountID)
	}

	l.mu.Lock()
	l.releaseIn(l.accounts, loginBucket+accountID, now)
	want, pending := l.wantLockout[accountID]
	clear := lockouts != nil && (!persisted.IsZero() || (pending && !want.IsZero()))
	if clear {
		l.wantLockout[accountID] = time.Time{}
	}
	l.mu.Unlock()

	if clear {
		l.syncLockout(lockouts, accountID)
	}
}

// ReserveRecheck is Reserve for re-checking a signed-in account's own
// password (changing it, or anything else that asks for it again). Its
// own budget, per account, memory only: a restart is not something an
// attacker holding a session can cause.
func (l *LoginLimiter) ReserveRecheck(accountID string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := recheckBucket + accountID
	entries := l.pruneIn(l.accounts, key, now)
	if len(entries) >= l.threshold {
		return false
	}
	l.accounts[key] = append(entries, now)
	return true
}

// ReleaseRecheck is Release for ReserveRecheck.
func (l *LoginLimiter) ReleaseRecheck(accountID string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.releaseIn(l.accounts, recheckBucket+accountID, now)
}

// releaseIn drops one reservation for key in m -- Release's body, for
// either map.
func (l *LoginLimiter) releaseIn(m map[string][]time.Time, key string, now time.Time) {
	if entries := l.pruneIn(m, key, now); len(entries) > 0 {
		if len(entries) == 1 {
			delete(m, key)
			return
		}
		m[key] = entries[:len(entries)-1]
	}
}

// syncLockout writes the lockout accountID's record should now carry.
// It reads wantLockout under persistMu rather than taking the value its
// caller decided on, so when a lockout and its clear race, whichever
// write goes last writes the latest decision.
func (l *LoginLimiter) syncLockout(lockouts AccountLockouts, accountID string) {
	l.persistMu.Lock()
	defer l.persistMu.Unlock()

	l.mu.Lock()
	want, ok := l.wantLockout[accountID]
	log := l.log
	l.mu.Unlock()
	if !ok {
		return
	}

	err := lockouts.SetLoginLockedUntil(accountID, want)
	if err != nil && log != nil {
		log.Error(fmt.Sprintf("login limiter: recording the login lockout on account %s: %v "+
			"(still enforced until this process restarts)", accountID, err))
	}

	l.mu.Lock()
	if cur, ok := l.wantLockout[accountID]; ok && cur.Equal(want) {
		delete(l.wantLockout, accountID)
	}
	l.mu.Unlock()
}
