// Copied from mikroview's internal/auth/ratelimit.go, unchanged apart
// from the import path for internal/evict (docs/adr/0001-shared-auth-
// module.md decision 3).
package gauntlet

import (
	"sync"
	"time"

	"github.com/tomlawesome/gauntlet/internal/evict"
)

// maxLoginLimiterKeys bounds LoginLimiter's tracked-key map the same way
// every other unbounded-growth-risk map keyed on untrusted input has an
// explicit ceiling -- without it, an attacker trying many distinct
// usernames or source addresses could grow this without bound.
var maxLoginLimiterKeys = 4096

// LoginLimiter guards against brute-force login attempts with a simple
// sliding-window counter per key (username or source IP).
type LoginLimiter struct {
	mu        sync.Mutex
	attempts  map[string][]time.Time
	threshold int
	window    time.Duration
}

func NewLoginLimiter(threshold int, window time.Duration) *LoginLimiter {
	return &LoginLimiter{attempts: make(map[string][]time.Time), threshold: threshold, window: window}
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
		l.evictOldestLocked()
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
	if entries := l.pruneLocked(key, now); len(entries) > 0 {
		if len(entries) == 1 {
			delete(l.attempts, key) // same reasoning as pruneLocked: no empty entries
			return
		}
		l.attempts[key] = entries[:len(entries)-1]
	}
}

// RecordFailure records one failed attempt for key.
func (l *LoginLimiter) RecordFailure(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, exists := l.attempts[key]; !exists && len(l.attempts) >= maxLoginLimiterKeys {
		l.evictOldestLocked()
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
	entries, ok := l.attempts[key]
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
		delete(l.attempts, key)
		return nil
	}
	l.attempts[key] = kept
	return kept
}

// evictOldestLocked sheds the least-recently-active keys once the
// limiter is at maxLoginLimiterKeys.
//
// A batch rather than one, for internal/evict's reason: the keys are
// source addresses an attacker varies per request, so evicting exactly
// one leaves the map full and makes every subsequent request pay the
// whole scan.
func (l *LoginLimiter) evictOldestLocked() {
	evict.DownTo(l.attempts, evict.Target(maxLoginLimiterKeys), func(times []time.Time) time.Time {
		if len(times) == 0 {
			return time.Time{} // shed first; pruneLocked should have removed it already
		}
		return times[len(times)-1]
	})
}
