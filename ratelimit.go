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
//
// Lockouts escalate (#44): each one on an account lasts three times the
// one before, up to maxLoginLockout, and MaxConsecutiveLoginFailures
// failures in a row disable the account's sign-in until UnlockLogin. The
// count of lockouts and the disable are written in the same write that
// starts a lockout. Both reset only on a completed sign-in (SignedIn) or
// a new password -- never on a correct password alone, nor on a lockout
// running out.
//
// A browser the account remembers (Store.KnowsBrowser) keeps a budget of
// its own when the ordinary one refuses it (ReserveKnownBrowser), so a
// stranger cannot lock the owner out by guessing wrong (#44).
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

	// wantLockout is the lockout state each account's record should
	// carry, until syncLockout has written it: a lockout as one begins
	// (with the count of lockouts, and the disable if this one reaches
	// it), a clear as one ends, a reset as the owner signs in. At most
	// one entry per account, always the latest decision. Until it is
	// saved, it is what the account's limit is decided on, in place of
	// the record (currentLocked); a decision whose save failed stays
	// here, enforced from memory, and is saved again by a later attempt
	// at most once per lockoutRetryInterval.
	wantLockout map[string]pendingLockout
	// persistMu orders syncLockout's writes, so a clear decided after a
	// lockout can never land before it. Taken without mu held.
	persistMu sync.Mutex

	// mem holds the lockout state for a limiter given nil or an
	// AccountLockouts other than the *Store (see memoryLockouts).
	mem memoryLockouts

	// secondFactor is each account's run of failed second-factor steps
	// since its last completed sign-in (SecondFactorFailed). Memory only:
	// a restart starts every run again from zero, which costs a guesser
	// nothing they could cause -- a restart is not theirs to order -- and
	// at worst lets a run that was four short start over. One entry per
	// account, gone at its next completed sign-in.
	secondFactor map[string]secondFactorRun

	log            *slog.Logger
	lastPressure   time.Time
	pressureLogged bool
}

// pendingLockout is one account's entry in wantLockout.
type pendingLockout struct {
	// state is what the record should say.
	state lockoutState
	// decidedAt is when it was decided. A password change after it
	// supersedes it: it was decided over guesses at the old password
	// (currentLocked).
	decidedAt time.Time
	// retryAt is the earliest a later attempt may try the save again
	// if it fails: one try per lockoutRetryInterval, so a broken backend
	// is not asked to save on every guess, each holding the accounts
	// store's write lock for as long as the save takes to fail.
	retryAt time.Time
}

// secondFactorRun is one account's entry in LoginLimiter.secondFactor.
type secondFactorRun struct {
	n     int       // failures in the run
	since time.Time // the run's first failure
	// required is set once MustChangePassword has been saved for this
	// run, so the failures after it cost no further store call.
	required bool
}

// MaxConsecutiveLoginFailures is how many failed sign-in attempts in a
// row, with no completed sign-in between them, disable an account's
// local sign-in (#44): wrong passwords and failed second-factor steps
// alike, since they share one count, however long apart. SP 800-63B-4
// §3.2.2 allows no more than 100; no real person needs anywhere near 50
// tries at their own credentials, and at five a window under the
// escalating lockout the fiftieth arrives only after about four days of
// lockouts. Counted as each lockout's attempts (the limiter's threshold
// times the lockouts on the record) plus those in the current window.
const MaxConsecutiveLoginFailures = 50

// maxLoginLockout caps one lockout's length: 24 hours, reached from the
// consumers' five-minute window at the seventh lockout (5, 15, 45, 135,
// 405 and 1215 minutes before it). Never less than one window, so a
// lockout always outlasts the attempts that caused it (see lockoutFor).
const maxLoginLockout = 24 * time.Hour

// secondFactorFailuresForPasswordChange is how many failed second-factor
// steps in a row, since the last completed sign-in, make the account's
// owner change their password at their next sign-in (#44): five, the
// point the consumers' first lockout starts. Each one came after the
// right password -- that is how a pending login is reached -- so a run
// of them says someone other than the owner knows it.
const secondFactorFailuresForPasswordChange = 5

// lockoutRetryInterval is how often a lockout whose save failed is
// tried again, by a refused attempt on that account while the lockout
// is in force (see ReserveAccount). There is no background retry: an
// account nobody is guessing at has nothing to protect until someone
// does, and the first refused guess saves it then.
const lockoutRetryInterval = 30 * time.Second

// Account counter buckets. Login and its second-factor step share one
// budget; re-checking a signed-in caller's own password has its own, so
// a run of typos there cannot lock the single admin out of signing in.
//
// A known browser's allowance during a lockout (ReserveKnownBrowser,
// #44) is a third, kept apart from the login budget it stands in for.
const (
	loginBucket        = "login:"
	recheckBucket      = "password-recheck:"
	knownBrowserBucket = "known:"
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
		attempts:     make(map[string][]time.Time),
		accounts:     make(map[string][]time.Time),
		resetPasses:  make(map[string]resetPass),
		wantLockout:  make(map[string]pendingLockout),
		mem:          memoryLockouts{states: make(map[string]lockoutState)},
		secondFactor: make(map[string]secondFactorRun),
		threshold:    threshold,
		window:       window,
	}, nil
}

// lockoutFor is how long an account's nth lockout lasts: one window for
// the first, three times the one before for each after it, capped at
// maxLoginLockout or one window, whichever is longer. A count under one
// -- a lockout on a record from a build that kept no count -- is a
// first lockout.
//
// Never under one window, from the attempt that starts it: so when a
// lockout ends, every attempt that caused it has aged out of the window,
// and the next lockout is counted from fresh attempts only -- never from
// ones an earlier lockout already counted.
func (l *LoginLimiter) lockoutFor(n int) time.Duration {
	limit := max(maxLoginLockout, l.window)
	d := l.window
	for i := 1; i < n; i++ {
		if d > limit/3 {
			return limit
		}
		d *= 3
	}
	return min(d, limit)
}

// consecutiveFailures is how many failed attempts in a row an account
// has: threshold for each lockout on its record, plus inWindow. It stops
// at MaxConsecutiveLoginFailures, which is all anything asks of it, so a
// hand-edited count on a record cannot overflow it.
func consecutiveFailures(episodes, threshold, inWindow int) int {
	if episodes >= MaxConsecutiveLoginFailures || (episodes > 0 && threshold >= MaxConsecutiveLoginFailures) {
		return MaxConsecutiveLoginFailures
	}
	return min(episodes*threshold+inWindow, MaxConsecutiveLoginFailures)
}

// recorder is where the limiter reads and writes accountID's lockout
// state: the *Store's own record, or this limiter's memory standing in
// for one (memoryLockouts).
func (l *LoginLimiter) recorder(lockouts AccountLockouts) lockoutRecorder {
	if r, ok := lockouts.(lockoutRecorder); ok {
		return r
	}
	return boundLockouts{mem: &l.mem, base: lockouts}
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
// the window starts a lockout and writes it to the account, once:
// its end, and the count of lockouts since the account's last completed
// sign-in, in one write. While one is in force every attempt is refused,
// whether or not this process saw the attempts that caused it. The
// first attempt after it ends clears it, keeping the count. nil, or an
// AccountLockouts other than the *Store, keeps what the record cannot
// hold in this limiter's memory only (memoryLockouts).
//
// Each lockout lasts three times as long as the one before (lockoutFor):
// with the consumers' 5 attempts per 5 minutes, 5, 15, 45, 135, 405 and
// 1215 minutes, then 24 hours each (#44). It runs from the attempt that
// starts it, so it always outlasts the window and the next lockout is
// counted from fresh attempts only. The attempt that brings the
// account's consecutive failures to MaxConsecutiveLoginFailures also
// disables its sign-in, in the same write: from then on every attempt is
// refused exactly as during a lockout, with no end, until UnlockLogin.
// The attempts are counted as they are reserved, before their outcome is
// known, as they always have been; one that turns out to succeed hands
// its count back (ReleaseAccount, SignedIn), and with it a lockout or
// disable it alone completed.
//
// A password change ends the lockout and resets the count: guesses at
// the old password stop counting from the moment it changed. The store
// clears the record in the same write (SetPassword, IssueResetCode);
// this limiter then drops its own count of those guesses and any
// decision over them it has yet to save. That takes lockouts being the
// *Store itself (see lockoutRecorder). This build moves
// PasswordChangedAt only in the writes that change a password, and those
// clear the lockout too; its SSO link ends sessions through
// SessionsEndedAt instead (#28). A document an older gauntlet or
// mikroview wrote may still hold a link's time there, with the password
// still working, so a bump counts only while the record carries no
// lockout. A disabled sign-in is not lifted by a password change.
//
// A lockout that cannot be saved is logged, and still enforced in
// memory: the attempt it would refuse is refused either way. It is also
// saved again, by a refused attempt on the account while it is in
// force, at most once per lockoutRetryInterval -- so a backend that
// recovers inside the window ends up holding it, and a restart after
// that is still locked out.
func (l *LoginLimiter) ReserveAccount(lockouts AccountLockouts, accountID string, now time.Time) bool {
	return l.ReserveAccountDecision(lockouts, accountID, now).Allowed
}

// AccountDecision is ReserveAccountDecision's answer: whether the attempt
// was admitted, and why it was refused or what it started. It only
// reports what ReserveAccount decides anyway, so a caller can record a
// sign-in attempt's outcome (#45, #53) without a second read.
type AccountDecision struct {
	// Allowed is ReserveAccount's answer.
	Allowed bool
	// Locked and Disabled say why an attempt was refused: a lockout in
	// force, or the account's sign-in disabled. Neither set with
	// Allowed false means the in-memory count refused it (see
	// ReserveAccount): a lockout cleared elsewhere while this limiter
	// still counts the attempts behind it.
	Locked   bool
	Disabled bool
	// LockedUntil is when the lockout ends: the one in force for a
	// Locked refusal, or the one this attempt started (LockoutStarted).
	// Zero otherwise.
	LockedUntil time.Time
	// LockoutStarted is set on the admitted attempt that filled the
	// window and so started a lockout. It is decided before the
	// attempt's outcome is known: one that turns out to succeed hands
	// the lockout back (SignedIn, ReleaseAccount).
	LockoutStarted bool
	// DisabledNow is set on the admitted attempt that brought the
	// account's consecutive failures to MaxConsecutiveLoginFailures,
	// disabling its sign-in, with the same caveat.
	DisabledNow bool
	// Lockouts is the account's count of lockouts since its last
	// completed sign-in, this attempt's included (User.LoginLockoutCount).
	Lockouts int
}

// ReserveAccountDecision is ReserveAccount, reporting why: see
// AccountDecision. ReserveAccount is this call's Allowed.
func (l *LoginLimiter) ReserveAccountDecision(lockouts AccountLockouts, accountID string, now time.Time) AccountDecision {
	rec := l.recorder(lockouts)
	stored, record, changed := l.readRecord(rec, accountID, now)

	l.mu.Lock()
	cur, p, pending := l.currentLocked(accountID, stored, record, changed)
	if cur.disabled() || now.Before(cur.until) {
		// Refused. A decision this limiter has yet to save is tried
		// again here, once per lockoutRetryInterval; so is a clamped
		// lockout (readRecord), which while its save fails still reads
		// as far off and lands here on every guess.
		base := stored
		if pending {
			base = p.state
		}
		sync := l.settleLocked(accountID, base, cur, p, pending, now)
		l.mu.Unlock()
		if sync {
			l.syncLockout(rec, accountID, now)
		}
		d := AccountDecision{Disabled: cur.disabled(), Lockouts: cur.episodes}
		if !d.Disabled {
			d.Locked, d.LockedUntil = true, cur.until
		}
		return d
	}
	key := loginBucket + accountID
	cutoff := now.Add(-l.window)
	if changed.After(cutoff) {
		cutoff = changed // guesses at the old password do not count
	}
	entries := dropBefore(l.accounts, key, cutoff)
	if len(entries) >= l.threshold {
		// Refused by the in-memory count. A lockout outlasts the window
		// (lockoutFor), so this is reached only when the record lost a
		// lockout this count still stands for -- cleared by another
		// process or by hand, UnlockLogin -- or in the instant a lockout
		// ends exactly one window after the attempt that started it.
		l.mu.Unlock()
		return AccountDecision{Lockouts: cur.episodes}
	}
	entries = append(entries, now)
	l.accounts[key] = entries

	next := cur
	// Not in force (checked above), so a lockout still on the record
	// has ended: this attempt clears it, keeping the count.
	next.until = time.Time{}
	if len(entries) == l.threshold {
		// Refused from now until the lockout ends.
		next.episodes = cur.episodes + 1
		next.until = now.Add(l.lockoutFor(next.episodes))
	}
	if !next.disabled() && consecutiveFailures(cur.episodes, l.threshold, len(entries)) >= MaxConsecutiveLoginFailures {
		next.disabledAt = now
	}
	sync := l.settleLocked(accountID, cur, next, p, pending, now)
	l.mu.Unlock()

	if sync {
		l.syncLockout(rec, accountID, now)
	}
	d := AccountDecision{
		Allowed:     true,
		DisabledNow: !cur.disabled() && next.disabled(),
		Lockouts:    next.episodes,
	}
	if next.episodes > cur.episodes {
		d.LockoutStarted, d.LockedUntil = true, next.until
	}
	return d
}

// readRecord reads accountID's lockout state from rec: as stored, as the
// limit is decided on (record), and the password change that guesses
// before it no longer count from (changed, zero for none). It is read
// before mu is taken, since the store has its own lock and may reload.
func (l *LoginLimiter) readRecord(rec lockoutRecorder, accountID string, now time.Time) (stored, record lockoutState, changed time.Time) {
	stored, changed = rec.lockoutRecord(accountID)
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
	// A lockout on the record means PasswordChangedAt, whatever its
	// date, was not a password change since that lockout began: a
	// password change clears the lockout in the same write. This build
	// writes PasswordChangedAt nowhere else, so for its own writes the
	// rule only matters in two cases. A document an older gauntlet or
	// mikroview linked to SSO carries the link's time there, with the
	// password still working, so the guesses it would drop still count.
	// And a lockout saved just after a real change, decided just before
	// it, is honoured too: it fails closed, and a second change ends it.
	if !stored.until.IsZero() {
		changed = time.Time{}
	}
	// A lockout this limiter set never ends more than lockoutFor its
	// count after the attempt that set it. One further out than that is
	// either a clock that was ahead when it was written, or a window
	// that has since been shortened -- either way it is honoured for
	// that long from now and no longer, not wiped: wiping it would let a
	// still-valid lockout through the moment the window shrinks across a
	// restart. The clamped end is saved back (ReserveAccount).
	record = stored
	if limit := now.Add(l.lockoutFor(stored.episodes)); stored.until.After(limit) {
		record.until = limit
	}
	return stored, record, changed
}

// currentLocked is the lockout state accountID's limit is decided on:
// the decision this limiter has yet to save, if there is one, else
// record. It reports the pending decision too.
//
// A decision made before a password change (changed, from readRecord)
// was over guesses at the old password, so the change supersedes it and
// it is dropped, and no retry saves it over the change afterwards --
// except a disable it carries that the record does not hold yet: a new
// password does not lift a disable, saved or not.
func (l *LoginLimiter) currentLocked(accountID string, stored, record lockoutState, changed time.Time) (lockoutState, pendingLockout, bool) {
	p, pending := l.wantLockout[accountID]
	if pending && !changed.IsZero() && p.decidedAt.Before(changed) {
		if p.state.disabled() && !stored.disabled() {
			p.state = lockoutState{disabledAt: p.state.disabledAt}
			l.wantLockout[accountID] = p
		} else {
			delete(l.wantLockout, accountID)
			pending = false
		}
	}
	if pending {
		return p.state, p, true
	}
	return record, pendingLockout{}, false
}

// settleLocked records next as the state accountID's record should carry,
// when it differs from cur, the state it was decided on; or, when it
// does not, readies the pending decision p for another save once its
// retryAt has passed. It reports whether syncLockout should run.
func (l *LoginLimiter) settleLocked(accountID string, cur, next lockoutState, p pendingLockout, pending bool, now time.Time) bool {
	switch {
	case !next.equal(cur):
		l.wantLockout[accountID] = pendingLockout{state: next, decidedAt: now, retryAt: now.Add(lockoutRetryInterval)}
		return true
	case pending && !now.Before(p.retryAt):
		p.retryAt = now.Add(lockoutRetryInterval)
		l.wantLockout[accountID] = p
		return true
	}
	return false
}

// ReleaseAccount is Release for ReserveAccount: called after a
// successful attempt -- the right password, before a second factor is
// asked for. It hands back the attempt's count. Its reservation was
// admitted, so a lockout or disable in force now was decided after it
// and counted it as a failure, which it was not: that lockout is undone,
// the count of lockouts back by one, and the disable lifted, rather than
// left to lock the owner out. A lockout that has ended is cleared as
// ReserveAccount clears it.
//
// It does not reset the count of lockouts: a correct password alone is
// not a completed sign-in (#44). SignedIn is.
func (l *LoginLimiter) ReleaseAccount(lockouts AccountLockouts, accountID string, now time.Time) {
	rec := l.recorder(lockouts)
	stored, record, changed := l.readRecord(rec, accountID, now)

	l.mu.Lock()
	l.releaseIn(l.accounts, loginBucket+accountID, now)
	cur, p, pending := l.currentLocked(accountID, stored, record, changed)
	next := cur
	if now.Before(cur.until) && next.episodes > 0 {
		next.episodes--
	}
	next.until = time.Time{}
	next.disabledAt = time.Time{}
	sync := l.settleLocked(accountID, cur, next, p, pending, now)
	l.mu.Unlock()

	if sync {
		l.syncLockout(rec, accountID, now)
	}
}

// SignedIn is ReleaseAccount, or ReleaseKnownBrowser, for an attempt that completed a sign-in:
// every factor the account asks for checked out, and a session is being
// issued (#44). It drops the account's whole count -- the attempts in
// the window, a known browser's (ReserveKnownBrowser), the lockouts on
// the record, the run of second-factor failures -- and anything that count decided while this attempt was in
// flight: its reservation was admitted, so no lockout or disable was in
// force when it began.
//
// One write when the record carries a lockout or a count of them, none
// otherwise, so an ordinary sign-in costs no save. Call it in place of
// ReleaseAccount or ReleaseKnownBrowser, not as well as either.
func (l *LoginLimiter) SignedIn(lockouts AccountLockouts, accountID string, now time.Time) {
	rec := l.recorder(lockouts)
	stored, record, changed := l.readRecord(rec, accountID, now)

	l.mu.Lock()
	delete(l.accounts, loginBucket+accountID)
	delete(l.accounts, knownBrowserBucket+accountID)
	delete(l.secondFactor, accountID)
	cur, p, pending := l.currentLocked(accountID, stored, record, changed)
	sync := l.settleLocked(accountID, cur, lockoutState{}, p, pending, now)
	l.mu.Unlock()

	if sync {
		l.syncLockout(rec, accountID, now)
	}
}

// UnlockLogin is Store.UnlockLogin for a process running this limiter:
// it lifts a disabled sign-in on accountID and clears its lockout and
// count of lockouts on the record, in one write, and also drops what
// this limiter holds about the account that the record does not -- its
// count of attempts in the current window, a known browser's too
// (ReserveKnownBrowser), and any lockout decision it has yet to save
// (#44). Without that, the account would stay refused
// by this process's count until the window passed, or have a disable
// that failed to save written back over the unlock by the next refused
// attempt's retry.
//
// The run of second-factor failures is kept: an unlock is not a
// completed sign-in, and the password those failures followed has not
// changed.
//
// For the *Store the write is the same one Store.UnlockLogin makes, and
// refused the same way: ErrUserNotFound for an account that does not
// exist, nothing written when there is nothing to clear. With nil or any
// other AccountLockouts, the lockout's end is cleared there and the rest
// in this limiter's memory (memoryLockouts).
//
// Taken under persistMu, so a save this limiter already had in flight
// lands before the unlock rather than after it. An attempt that read the
// record just before the unlock can still decide a lockout over the
// account's old count and save it just after: that fails closed -- the
// account is locked again, never opened wider -- and another unlock
// clears it.
//
// Deciding who may unlock whom is the caller's job, as for the store.
func (l *LoginLimiter) UnlockLogin(lockouts AccountLockouts, accountID string) error {
	rec := l.recorder(lockouts)

	l.persistMu.Lock()
	defer l.persistMu.Unlock()
	l.mu.Lock()
	delete(l.accounts, loginBucket+accountID)
	delete(l.accounts, knownBrowserBucket+accountID)
	delete(l.wantLockout, accountID)
	l.mu.Unlock()
	return rec.setLockoutRecord(accountID, lockoutState{})
}

// ReserveKnownBrowser is ReserveAccount for a browser accountID
// remembers (Store.KnowsBrowser, #44), called only once the ordinary
// path has refused the attempt -- the account locked out, or the
// address at its limit -- and only after the browser's token matched
// the account's record. It is the owner's way past a lockout a stranger
// caused: the stranger's browser never completed a sign-in there, so it
// has no token to show.
//
// The budget is the limiter's own, threshold attempts per window, per
// account, kept apart from the login budget it stands in for, and it
// does not escalate: the attempt that fills it closes it for one window
// from that attempt, as a first lockout would, whatever the account's
// count of lockouts. Its key is created only after the token matched,
// so there is at most one per account.
//
// It is no way round the disable. Refused outright while the account's
// sign-in is disabled, and every failure through it counts toward
// MaxConsecutiveLoginFailures as an ordinary one does: the attempt that
// fills the budget adds one to the account's count of lockouts -- in
// the same write a lockout would make, its end left as it was -- so
// each budget's worth of failures is counted once, and the attempt that
// brings the count to MaxConsecutiveLoginFailures disables the account
// as ReserveAccount's would. That count also lengthens the account's
// next ordinary lockout, as any lockout's worth of failures does. A
// stolen token therefore buys its holder threshold guesses per window
// during a lockout, ending at the disable, and never a session.
//
// Guesses made before a password change stop counting, as for
// ReserveAccount. The attempt hands its count back on success:
// ReleaseKnownBrowser at the password step, SignedIn when a sign-in
// completes.
func (l *LoginLimiter) ReserveKnownBrowser(lockouts AccountLockouts, accountID string, now time.Time) bool {
	return l.ReserveKnownBrowserDecision(lockouts, accountID, now).Allowed
}

// ReserveKnownBrowserDecision is ReserveKnownBrowser, reporting why, as
// ReserveAccountDecision does for ReserveAccount (#45): Disabled for a
// refusal while the account's sign-in is disabled, DisabledNow on the
// admitted attempt that disabled it, and Lockouts, the account's count
// of lockouts. The allowance filling is not a lockout of the account,
// so LockoutStarted, Locked and LockedUntil are never set.
// ReserveKnownBrowser is this call's Allowed.
func (l *LoginLimiter) ReserveKnownBrowserDecision(lockouts AccountLockouts, accountID string, now time.Time) AccountDecision {
	rec := l.recorder(lockouts)
	stored, record, changed := l.readRecord(rec, accountID, now)

	l.mu.Lock()
	cur, p, pending := l.currentLocked(accountID, stored, record, changed)
	if cur.disabled() {
		// Refused, and a disable this limiter has yet to save is tried
		// again, as ReserveAccount does while refusing.
		base := stored
		if pending {
			base = p.state
		}
		sync := l.settleLocked(accountID, base, cur, p, pending, now)
		l.mu.Unlock()
		if sync {
			l.syncLockout(rec, accountID, now)
		}
		return AccountDecision{Disabled: true, Lockouts: cur.episodes}
	}
	key := knownBrowserBucket + accountID
	entries := l.knownEntriesLocked(key, changed, now)
	if len(entries) >= l.threshold {
		l.mu.Unlock()
		return AccountDecision{Lockouts: cur.episodes}
	}
	entries = append(entries, now)
	next := cur
	if len(entries) == l.threshold {
		// Closed for one window from now: every entry ages out at once,
		// so the next fill is counted from fresh attempts only and no
		// failure is counted into two lockouts' worth.
		for i := range entries {
			entries[i] = now
		}
		next.episodes = cur.episodes + 1
	}
	l.accounts[key] = entries
	if !next.disabled() && consecutiveFailures(cur.episodes, l.threshold, len(entries)) >= MaxConsecutiveLoginFailures {
		next.disabledAt = now
	}
	sync := l.settleLocked(accountID, cur, next, p, pending, now)
	l.mu.Unlock()

	if sync {
		l.syncLockout(rec, accountID, now)
	}
	return AccountDecision{Allowed: true, DisabledNow: !cur.disabled() && next.disabled(), Lockouts: next.episodes}
}

// knownEntriesLocked is a known browser's budget for key: its attempts
// in the window, less any made before a password change (changed, zero
// for none).
func (l *LoginLimiter) knownEntriesLocked(key string, changed, now time.Time) []time.Time {
	cutoff := now.Add(-l.window)
	if changed.After(cutoff) {
		cutoff = changed
	}
	return dropBefore(l.accounts, key, cutoff)
}

// ReleaseKnownBrowser is ReleaseAccount for ReserveKnownBrowser: the
// attempt had the right password, and a second factor is still owed.
// It hands back the attempt's count. If the budget is full now, its
// filling was decided after this attempt was admitted and counted this
// attempt as a failure, which it was not: the lockout's worth it added
// to the account's count is taken back, and a disable it brought is
// lifted -- none was in force when the attempt was admitted, or it
// would have been refused. An ordinary lockout in force is left alone:
// it was there before this attempt, which only came through because of
// it.
//
// Like ReleaseAccount, it does not reset the account's count: a correct
// password alone is not a completed sign-in. SignedIn is.
func (l *LoginLimiter) ReleaseKnownBrowser(lockouts AccountLockouts, accountID string, now time.Time) {
	rec := l.recorder(lockouts)
	stored, record, changed := l.readRecord(rec, accountID, now)

	l.mu.Lock()
	key := knownBrowserBucket + accountID
	full := len(l.knownEntriesLocked(key, changed, now)) >= l.threshold
	l.releaseIn(l.accounts, key, now)
	cur, p, pending := l.currentLocked(accountID, stored, record, changed)
	next := cur
	if full {
		if next.episodes > 0 {
			next.episodes--
		}
		next.disabledAt = time.Time{}
	}
	sync := l.settleLocked(accountID, cur, next, p, pending, now)
	l.mu.Unlock()

	if sync {
		l.syncLockout(rec, accountID, now)
	}
}

// SecondFactorFailed records that a second-factor step on accountID was
// refused -- a wrong TOTP or recovery code, a passkey assertion that did
// not verify -- after the right password had brought the caller there.
// It counts toward the account's limit through the reservation the
// attempt kept, as before; this is a second count, of such failures in
// a row since the account's last completed sign-in (SignedIn).
//
// At secondFactorFailuresForPasswordChange of them someone other than
// the owner very likely knows the password, so the account is set to
// MustChangePassword (#44), in one write that also ends every session
// the account holds (SessionsEndedAt): the owner, once they next sign in
// with both factors, must replace it before going any further, and no
// session from before the run reaches the change-password door, which
// asks for no current password. That write takes
// lockouts being the *Store (passwordChangeRequirer); with any other,
// nothing is set. A password changed since the run began starts it
// again: those failures followed the old one.
//
// The run lives in this process's memory only (see
// LoginLimiter.secondFactor).
func (l *LoginLimiter) SecondFactorFailed(lockouts AccountLockouts, accountID string, now time.Time) {
	var changed time.Time
	if r, ok := lockouts.(lockoutRecorder); ok {
		_, changed = r.lockoutRecord(accountID)
	}

	l.mu.Lock()
	run := l.secondFactor[accountID]
	if run.n > 0 && !changed.After(now) && run.since.Before(changed) {
		run = secondFactorRun{}
	}
	if run.n == 0 {
		run.since = now
	}
	if run.n < secondFactorFailuresForPasswordChange {
		run.n++
	}
	l.secondFactor[accountID] = run
	due := run.n >= secondFactorFailuresForPasswordChange && !run.required
	log := l.log
	l.mu.Unlock()

	pc, ok := lockouts.(passwordChangeRequirer)
	if !due || !ok {
		return
	}
	err := pc.requirePasswordChange(accountID, now)
	if err != nil {
		// Not marked done: the next failure in the run tries again.
		if log != nil && !errors.Is(err, ErrUserNotFound) {
			log.Error(fmt.Sprintf("login limiter: requiring a password change on account %s after %d failed second-factor steps: %v "+
				"(the next failure will try again)", accountID, secondFactorFailuresForPasswordChange, err))
		}
		return
	}
	l.mu.Lock()
	if cur, ok := l.secondFactor[accountID]; ok && cur.since.Equal(run.since) {
		cur.required = true
		l.secondFactor[accountID] = cur
	}
	l.mu.Unlock()
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

// syncLockout writes the lockout state accountID's record should now
// carry, in one write. It reads wantLockout under persistMu rather than
// taking the value its caller decided on, so when a lockout and its
// clear race, whichever write goes last writes the latest decision.
//
// A decision that fails to save stays in wantLockout, with a retryAt,
// and is what the account's limit is decided on meanwhile
// (currentLocked): a lockout or disable is enforced from memory, and a
// clear or reset -- the owner signed in -- is honoured, rather than the
// record's lockout still refusing them. The next attempt on the account
// after retryAt tries the save again. An account that no longer exists
// has nothing to save to, and the decision is dropped.
//
// That pending decision lives only in this process's memory. A restart
// before a retry saves it loses it: a lockout or disable is lost with
// it (the attempts that caused it were in memory too), and a clear or
// reset leaves the new process enforcing what is still on the record --
// a lockout until it ends, or a password change clears it (#28).
// Nothing durable says the owner signed in: recording that would itself
// be a save, and saves are what failed.
func (l *LoginLimiter) syncLockout(rec lockoutRecorder, accountID string, now time.Time) {
	l.persistMu.Lock()
	defer l.persistMu.Unlock()

	l.mu.Lock()
	want, ok := l.wantLockout[accountID]
	log := l.log
	l.mu.Unlock()
	if !ok {
		return
	}

	err := rec.setLockoutRecord(accountID, want.state)
	gone := errors.Is(err, ErrUserNotFound)
	if err != nil && log != nil {
		if !gone && (want.state.disabled() || now.Before(want.state.until)) {
			log.Error(fmt.Sprintf("login limiter: recording the login lockout on account %s: %v "+
				"(enforced in memory meanwhile; a refused attempt will try to save it again)", accountID, err))
		} else {
			log.Error(fmt.Sprintf("login limiter: updating the login lockout on account %s: %v", accountID, err))
		}
	}

	l.mu.Lock()
	if cur, ok := l.wantLockout[accountID]; ok && cur.state.equal(want.state) {
		if err == nil || gone {
			delete(l.wantLockout, accountID)
		} else {
			cur.retryAt = now.Add(lockoutRetryInterval)
			l.wantLockout[accountID] = cur
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
// (ReleaseAfterReset) or uses it up (EndAfterReset: a session issued,
// the right password for an account with a second factor, or a wrong
// guess), so a burst of concurrent guesses gets one try, not one each.
// A caller with a second step carries the owner through it itself (gate
// does so in its pending login), so nobody can take the pass in
// between. A later reset out of a lockout grants a fresh one; the
// window ends it anyway.
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
	// pass drops its pre-change guesses (ReserveAccount), so an attempt
	// after a handed-back pass no longer sees the lockout it ended.
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
// session or a wrong guess -- a refusal by the account's own limit, a
// storage error. A no-op once
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
