package gauntlet

import (
	"sync"
	"testing"
	"time"
)

// hostLockouts is a host application's own store keeping only the
// lockout's end: a plain AccountLockouts.
type hostLockouts struct {
	mu    sync.Mutex
	until map[string]time.Time
}

func newHostLockouts() *hostLockouts {
	return &hostLockouts{until: make(map[string]time.Time)}
}

func (h *hostLockouts) LoginLockedUntil(accountID string) time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.until[accountID]
}

func (h *hostLockouts) SetLoginLockedUntil(accountID string, until time.Time) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.until[accountID] = until
	return nil
}

// hostLockoutRecords is a host store that keeps the whole record:
// an AccountLockoutRecords. It counts calls to the narrow setter, which
// the limiter should no longer need.
type hostLockoutRecords struct {
	mu          sync.Mutex
	recs        map[string]LoginLockoutRecord
	narrowSets  int
	recordSaves int
}

func newHostLockoutRecords() *hostLockoutRecords {
	return &hostLockoutRecords{recs: make(map[string]LoginLockoutRecord)}
}

func (h *hostLockoutRecords) LoginLockedUntil(accountID string) time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.recs[accountID].LockedUntil
}

func (h *hostLockoutRecords) SetLoginLockedUntil(accountID string, until time.Time) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.narrowSets++
	rec := h.recs[accountID]
	rec.LockedUntil = until
	h.recs[accountID] = rec
	return nil
}

func (h *hostLockoutRecords) LoginLockoutRecord(accountID string) LoginLockoutRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.recs[accountID]
}

func (h *hostLockoutRecords) SetLoginLockoutRecord(accountID string, rec LoginLockoutRecord) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recordSaves++
	h.recs[accountID] = rec
	return nil
}

// disableThroughHostStore drives a fresh limiter (threshold 25) to two
// lockouts, the second of which is the fiftieth failure and so disables
// sign-in, and returns a time well after both lockouts have run out.
func disableThroughHostStore(t *testing.T, lockouts AccountLockouts, id string) time.Time {
	t.Helper()
	l := mustNewLoginLimiter(t, 25, time.Minute)
	at := escalationStart
	for range 25 {
		l.ReserveAccount(lockouts, id, at)
	}
	at = at.Add(time.Minute + time.Second) // the first lockout has ended
	var d AccountDecision
	for range 25 {
		d = l.ReserveAccountDecision(lockouts, id, at)
	}
	if !d.DisabledNow || d.Lockouts != 2 {
		t.Fatalf("the fiftieth failure decided %+v, want the disable and two lockouts", d)
	}
	return at.Add(time.Hour)
}

// A host store that keeps the whole record keeps the disable and the
// count of lockouts across a restart, as the *Store does.
func TestHostLockoutRecordsSurviveRestart(t *testing.T) {
	host := newHostLockoutRecords()
	later := disableThroughHostStore(t, host, "acct")

	restarted := mustNewLoginLimiter(t, 25, time.Minute)
	d := restarted.ReserveAccountDecision(host, "acct", later)
	if d.Allowed || !d.Disabled {
		t.Errorf("after a restart the disabled account got %+v, want refused as disabled", d)
	}
	if d.Lockouts != 2 {
		t.Errorf("after a restart the count of lockouts is %d, want 2", d.Lockouts)
	}
	if host.narrowSets != 0 || host.recordSaves == 0 {
		t.Errorf("the limiter set the lockout's end alone %d times and the record %d times, want only whole-record saves",
			host.narrowSets, host.recordSaves)
	}
}

// A host store that keeps only the lockout's end loses the disable and
// the count on restart: what AccountLockoutRecords is for.
func TestHostLockoutsLoseDisableOnRestart(t *testing.T) {
	host := newHostLockouts()
	later := disableThroughHostStore(t, host, "acct")

	restarted := mustNewLoginLimiter(t, 25, time.Minute)
	d := restarted.ReserveAccountDecision(host, "acct", later)
	if !d.Allowed || d.Disabled || d.Lockouts != 0 {
		t.Errorf("after a restart a plain AccountLockouts gave %+v, want admitted with no disable or count", d)
	}
}
