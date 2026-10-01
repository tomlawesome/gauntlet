// Copied from mikroview's internal/auth/ratelimit.go (docs/adr/0001-
// shared-auth-module.md decision 3), then split by #19: counters for
// real accounts moved out of the capped map into their own, and a login
// lockout is kept on the account so it survives a restart.
package gauntlet

import (
	"errors"
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
// AccountLockouts), but only as it begins and as it clears -- and, if
// that first save failed, again at most once per lockoutRetryInterval --
// never per attempt: a stream of wrong guesses must not become a stream
// of disk writes.
type LoginLimiter struct {
	mu        sync.Mutex
	attempts  map[string][]time.Time
	accounts  map[string][]time.Time // bucket + account ID
	threshold int
	window    time.Duration

	// resetPasses are the address-limit passes AllowAfterReset has
	// handed out, keyed by resetPassKey. Bounded like the capped map:
	// one is made only for an address key that map holds, and it goes
	// once that key does or its password change leaves the window.
	resetPasses map[string]resetPass

	// wantLockout is the lockout each account's record should carry,
	// until syncLockout has written it: the end time as one begins, the
	// zero time as one clears. At most one entry per account. A lockout
	// whose save failed stays here, enforced by the in-memory counter,
	// and is saved again by a later refused attempt (ReserveAccount).
	wantLockout map[string]pendingLockout
	// persistMu orders syncLockout's writes, so a clear decided after a
	// lockout can never land before it. Taken without mu held.
	persistMu sync.Mutex

	log            *slog.Logger
	lastPressure   time.Time
	pressureLogged bool
}

// pendingLockout is one account's entry in wantLockout.
type pendingLockout struct {
	// until is the lockout's end; the zero time clears it.
	until time.Time
	// retryAt is the earliest a refused attempt may try the save again
	// if it fails: one try per lockoutRetryInterval, so a broken backend
	// is not asked to save on every guess, each holding the accounts
	// store's write lock for as long as the save takes to fail.
	retryAt time.Time
}

// lockoutRetryInterval is how often a lockout whose save failed is
// tried again, by a refused attempt on that account while the lockout
// is in force (see ReserveAccount). There is no background retry: an
// account nobody is guessing at has nothing to protect until someone
// does, and the first refused guess saves it then.
const lockoutRetryInterval = 30 * time.Second

// Account counter buckets. Login and its second-factor step share one
// budget; re-checking a signed-in caller's own password has its own, so
// a run of typos there cannot lock the single admin out of signing in.
const (
	loginBucket   = "login:"
	recheckBucket = "password-recheck:"
)

// ErrLimiterConfig is returned by NewLoginLimiter for a threshold or
// window that cannot run: threshold below one would block every login
// before a first attempt, and a non-positive window never lets a
// blocked key age out.
var ErrLimiterConfig = errors.New("gauntlet: login limiter: invalid configuration")

// NewLoginLimiter returns a LoginLimiter that allows threshold attempts
// per window, for each key or account it is asked about. It refuses a
// threshold under one or a non-positive window: either would leave
// every login refused before a first attempt is made, with nothing
// persisted or logged to say why -- see ErrLimiterConfig.
func NewLoginLimiter(threshold int, window time.Duration) (*LoginLimiter, error) {
	if threshold < 1 {
		return nil, fmt.Errorf("%w: threshold must be a whole number of one or more, got %d", ErrLimiterConfig, threshold)
	}
	if window <= 0 {
		return nil, fmt.Errorf("%w: window must be positive, got %v", ErrLimiterConfig, window)
	}
	return &LoginLimiter{
		attempts:    make(map[string][]time.Time),
		accounts:    make(map[string][]time.Time),
		resetPasses: make(map[string]resetPass),
		wantLockout: make(map[string]pendingLockout),
		threshold:   threshold,
		window:      window,
	}, nil
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
	return dropBefore(m, key, now.Add(-l.window))
}

// dropBefore drops key's attempts in m from before cutoff and returns
// what remains, leaving no entry behind for a key with nothing left
// (see pruneLocked).
func dropBefore(m map[string][]time.Time, key string, cutoff time.Time) []time.Time {
	entries, ok := m[key]
	if !ok {
		return nil
	}
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
	l.pruneResetPassesLocked(now)
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
// A password change ends the lockout: guesses at the old password stop
// counting from the moment it changed. The store clears the record in
// the same write (SetPassword, IssueResetCode); this limiter then drops
// its own count of those guesses and any lockout over them it has yet
// to save. That takes lockouts being the *Store itself (see
// lockoutRecorder). Not every PasswordChangedAt bump is a password
// change -- linking the admin to SSO bumps it and leaves the password
// working -- so one counts only while the record carries no lockout:
// the writes that change a password clear it, the link does not.
//
// A lockout that cannot be saved is logged, and still enforced in
// memory: the attempt it would refuse is refused either way. It is also
// saved again, by a refused attempt on the account while it is in
// force, at most once per lockoutRetryInterval -- so a backend that
// recovers inside the window ends up holding it, and a restart after
// that is still locked out.
func (l *LoginLimiter) ReserveAccount(lockouts AccountLockouts, accountID string, now time.Time) bool {
	var persisted, changed time.Time
	if lockouts != nil {
		persisted, changed = readLockout(lockouts, accountID)
	}
	// A change dated after now is a clock that stepped back since, or a
	// process whose clock runs ahead. Taken as it is, every guess would
	// be "before the change" on every call and the limit would be off
	// until the clock caught up; clamping it to now does the same for
	// the guesses in this second. Ignored instead, until now reaches it:
	// the limit fails closed, as gate's session check does on the same
	// skew.
	if changed.After(now) {
		changed = time.Time{}
	}
	wasPersisted := !persisted.IsZero()
	// A lockout on the record means PasswordChangedAt, whatever its
	// date, was not a password change since that lockout began: a
	// password change clears the lockout in the same write. The bump
	// was something else that ends sessions -- linking the admin to SSO
	// -- and the guesses it would drop were at a password that still
	// works. A lockout saved just after a real change, decided just
	// before it, looks the same and is honoured too: it fails closed,
	// and a second change ends it.
	if wasPersisted {
		changed = time.Time{}
	}
	// A lockout this limiter set never ends more than one window after
	// the attempt that set it (below: entries[0].Add(l.window)). One
	// further out than that is either a clock that was ahead when it was
	// written, or a window that has since been shortened -- either way
	// it is honoured for one window from now and no longer, not wiped:
	// wiping it would let a still-valid lockout through the moment the
	// window shrinks across a restart.
	clamped := wasPersisted && persisted.After(now.Add(l.window))
	if clamped {
		persisted = now.Add(l.window)
	}

	l.mu.Lock()
	// A clear whose save failed (see syncLockout): the owner signed in
	// and ended the lockout still on the record, so it is not refused
	// for; the clear is tried again below, once per lockoutRetryInterval.
	var clearRetryAt time.Time
	if p, ok := l.wantLockout[accountID]; ok && p.until.IsZero() && !p.retryAt.IsZero() {
		if wasPersisted {
			persisted, clamped, clearRetryAt = time.Time{}, false, p.retryAt
		} else {
			delete(l.wantLockout, accountID) // the record has nothing left to clear
		}
	}
	if now.Before(persisted) {
		// While a save of the clamped lockout is failing, the record
		// still reads as far off, so every guess lands here: retry it
		// once per lockoutRetryInterval, not per guess.
		if p, ok := l.wantLockout[accountID]; clamped && ok && now.Before(p.retryAt) {
			clamped = false
		}
		if clamped {
			l.wantLockout[accountID] = pendingLockout{until: persisted, retryAt: now.Add(lockoutRetryInterval)}
		}
		l.mu.Unlock()
		if clamped && lockouts != nil {
			l.syncLockout(lockouts, accountID, now)
		}
		return false
	}
	key := loginBucket + accountID
	cutoff := now.Add(-l.window)
	if changed.After(cutoff) {
		cutoff = changed // guesses at the old password do not count
	}
	entries := dropBefore(l.accounts, key, cutoff)
	if p, ok := l.wantLockout[accountID]; ok && !p.until.IsZero() && p.until.Add(-l.window).Before(changed) {
		// An unsaved lockout over guesses at the old password: dropped,
		// so no retry saves it over the change.
		delete(l.wantLockout, accountID)
	}
	if len(entries) >= l.threshold {
		// Refused by the in-memory count. If the lockout that count
		// stands for never reached the record, this is when it is tried
		// again -- see pendingLockout.retryAt.
		retry := false
		if p, ok := l.wantLockout[accountID]; ok && lockouts != nil &&
			!p.until.IsZero() && now.Before(p.until) && !now.Before(p.retryAt) {
			p.retryAt = now.Add(lockoutRetryInterval)
			l.wantLockout[accountID] = p
			retry = true
		}
		l.mu.Unlock()
		if retry {
			l.syncLockout(lockouts, accountID, now)
		}
		return false
	}
	if p, ok := l.wantLockout[accountID]; ok && !p.until.IsZero() && !now.Before(p.until) {
		// An unsaved lockout that has ended: nothing left to save.
		delete(l.wantLockout, accountID)
	}
	entries = append(entries, now)
	l.accounts[key] = entries
	sync := false
	switch {
	case len(entries) == l.threshold:
		// Refused from now until the oldest attempt in the window ages
		// out -- the moment the in-memory counter would admit one again.
		l.wantLockout[accountID] = pendingLockout{until: entries[0].Add(l.window), retryAt: now.Add(lockoutRetryInterval)}
		sync = lockouts != nil
	case wasPersisted && !now.Before(clearRetryAt):
		// A lockout on the record that has ended, or one whose clear
		// failed and is due to be tried again.
		l.wantLockout[accountID] = pendingLockout{}
		sync = lockouts != nil
	}
	l.mu.Unlock()

	if sync {
		l.syncLockout(lockouts, accountID, now)
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
	clear := lockouts != nil && (!persisted.IsZero() || (pending && !want.until.IsZero()))
	if clear {
		l.wantLockout[accountID] = pendingLockout{}
	}
	l.mu.Unlock()

	if clear {
		l.syncLockout(lockouts, accountID, now)
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
//
// A lockout that fails to save stays in wantLockout for a refused
// attempt to retry. A clear that fails while the record's lockout has
// yet to end stays too, with a retryAt: the owner has signed in, so the
// next attempt is not refused for it and tries the clear again. Any
// other failed clear is dropped: the record then holds a lockout that
// has ended, and the next attempt clears it again (ReserveAccount's
// wasPersisted case).
func (l *LoginLimiter) syncLockout(lockouts AccountLockouts, accountID string, now time.Time) {
	l.persistMu.Lock()
	defer l.persistMu.Unlock()

	l.mu.Lock()
	want, ok := l.wantLockout[accountID]
	log := l.log
	l.mu.Unlock()
	if !ok {
		return
	}

	err := lockouts.SetLoginLockedUntil(accountID, want.until)
	keep := err != nil && !want.until.IsZero() && !errors.Is(err, ErrUserNotFound)
	if err != nil && log != nil {
		if keep {
			log.Error(fmt.Sprintf("login limiter: recording the login lockout on account %s: %v "+
				"(enforced in memory meanwhile; a refused attempt will try to save it again)", accountID, err))
		} else {
			log.Error(fmt.Sprintf("login limiter: updating the login lockout on account %s: %v", accountID, err))
		}
	}

	keepClear := err != nil && want.until.IsZero() && !errors.Is(err, ErrUserNotFound) &&
		lockouts.LoginLockedUntil(accountID).After(now)

	l.mu.Lock()
	if cur, ok := l.wantLockout[accountID]; ok && cur.until.Equal(want.until) {
		switch {
		case keepClear:
			l.wantLockout[accountID] = pendingLockout{retryAt: now.Add(lockoutRetryInterval)}
		case !keep:
			delete(l.wantLockout, accountID)
		}
	}
	l.mu.Unlock()
}

// resetPass is one entry in LoginLimiter.resetPasses: the password
// change a pass was handed out for, whether an attempt holds it now,
// and whether it has been used up.
type resetPass struct {
	address   string
	changedAt time.Time
	held      bool
	ended     bool
}

func resetPassKey(addressKey, accountID string) string {
	return addressKey + "\x00" + accountID
}

// AllowAfterReset reports whether an attempt on accountID from
// addressKey may go ahead although addressKey is at its limit (Reserve
// refused it), because the account's password was reset after that
// address reached the limit (#32). It reserves nothing on addressKey;
// the account's own counter (ReserveAccount) still applies in full.
//
// A reset needs the server's command line or a code an admin issued, so
// letting that account's next sign-in past the address limit gives an
// attacker nothing they did not already have, while refusing it reads to
// the operator as the reset having failed. The pass therefore holds for
// that one account only -- other accounts tried from the address stay
// refused -- and only when at least the threshold's worth of both the
// address's attempts and the account's own in the window predate the
// change: the change ended a lockout. An account changing its own
// password while guesses at other names fill its address gets none.
//
// One attempt holds the pass at a time: AllowAfterReset hands it out
// and refuses everyone else until the attempt hands it back
// (ReleaseAfterReset) or uses it up (EndAfterReset, called once a
// session is issued or on a wrong password or code), so a burst of
// concurrent guesses gets one try, not one each. It lasts across both
// steps of a sign-in with a second factor. A later reset out of a
// lockout grants a fresh one; the window ends it anyway.
//
// The change is read from lockouts as ReserveAccount reads it, so it
// takes lockouts being the *Store itself (see lockoutRecorder), and a
// reset made by a separate process counts once the store sees it. A
// record still carrying a lockout gets no pass: a password change
// clears the lockout in the same write, so a bump without that clear --
// linking the admin to SSO -- is not a reset.
func (l *LoginLimiter) AllowAfterReset(addressKey string, lockouts AccountLockouts, accountID string, now time.Time) bool {
	if lockouts == nil {
		return false
	}
	lockedUntil, changed := readLockout(lockouts, accountID)
	if !lockedUntil.IsZero() || changed.IsZero() || changed.After(now) {
		return false
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	key := resetPassKey(addressKey, accountID)
	// Checked before the counts: the account's first attempt under the
	// pass drops its pre-change guesses (ReserveAccount), so the second
	// step of a two-factor sign-in no longer sees the lockout it ended.
	if p, ok := l.resetPasses[key]; ok && p.changedAt.Equal(changed) {
		if p.changedAt.Before(now.Add(-l.window)) {
			delete(l.resetPasses, key) // no attempt in the window predates it
			return false
		}
		if p.ended || p.held {
			return false
		}
		p.held = true
		l.resetPasses[key] = p
		return true
	}
	if countBefore(l.pruneLocked(addressKey, now), changed) < l.threshold {
		return false
	}
	cutoff := now.Add(-l.window)
	var own []time.Time
	for _, t := range l.accounts[loginBucket+accountID] {
		if !t.Before(cutoff) {
			own = append(own, t)
		}
	}
	if countBefore(own, changed) < l.threshold {
		return false
	}
	// Rare -- a full address and a reset inside one window -- so the
	// sweep runs here too, not only when the capped map is full.
	l.pruneResetPassesLocked(now)
	l.resetPasses[key] = resetPass{address: addressKey, changedAt: changed, held: true}
	return true
}

// countBefore counts the attempts in entries made before t.
func countBefore(entries []time.Time, t time.Time) int {
	n := 0
	for _, e := range entries {
		if e.Before(t) {
			n++
		}
	}
	return n
}

// ReleaseAfterReset hands back the pass AllowAfterReset gave accountID
// at addressKey, unused: the attempt holding it has finished without a
// session or a wrong guess -- the password step of a two-factor sign-in,
// a refusal by the account's own limit, a storage error. A no-op once
// EndAfterReset has used the pass up.
func (l *LoginLimiter) ReleaseAfterReset(addressKey, accountID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := resetPassKey(addressKey, accountID)
	if p, ok := l.resetPasses[key]; ok {
		p.held = false
		l.resetPasses[key] = p
	}
}

// EndAfterReset uses up the pass AllowAfterReset gave accountID at
// addressKey, if there is one: the sign-in it was for has finished, or
// a guess under it was wrong.
func (l *LoginLimiter) EndAfterReset(addressKey, accountID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := resetPassKey(addressKey, accountID)
	if p, ok := l.resetPasses[key]; ok {
		p.held, p.ended = false, true
		l.resetPasses[key] = p
	}
}

// pruneResetPassesLocked drops every pass that can no longer apply: its
// password change has left the window, so no attempt in the window can
// predate it, or its address has left the capped map.
func (l *LoginLimiter) pruneResetPassesLocked(now time.Time) {
	cutoff := now.Add(-l.window)
	for key, p := range l.resetPasses {
		if _, ok := l.attempts[p.address]; !ok || p.changedAt.Before(cutoff) {
			delete(l.resetPasses, key)
		}
	}
}
