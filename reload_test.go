// Ported from mikroview's internal/auth/reload_test.go. Adapted:
// OpenWithBackend -> OpenStore.

package gauntlet

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// reloadRaceBackend is a persist.Backend double for exercising
// reloadIfStale's own race directly and deterministically. Load
// snapshots the backend's current bytes immediately, then -- if gate is
// set -- blocks before returning them, so a test can force a concurrent
// in-process write to land in the gap between "the bytes were read off
// disk" and "the caller got them back".
//
// It deliberately does not implement persist.VersionReader:
// reloadIfStale falls straight through to Load rather than polling a
// cheaper version check first, the same path a real file-backed
// deployment takes.
type reloadRaceBackend struct {
	mu      sync.Mutex
	payload []byte
	version int64
	exists  bool

	// gate, if non-nil, is read from before Load returns.
	gate chan struct{}
}

func (b *reloadRaceBackend) Load(ctx context.Context) (persist.Snapshot, error) {
	b.mu.Lock()
	snap := persist.Snapshot{
		Payload: append([]byte(nil), b.payload...),
		Version: b.version,
		Exists:  b.exists,
	}
	b.mu.Unlock()
	if b.gate != nil {
		<-b.gate
	}
	return snap, nil
}

func (b *reloadRaceBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.exists && expect != b.version {
		return 0, persist.ErrConflict
	}
	b.payload = append([]byte(nil), payload...)
	b.version++
	b.exists = true
	return b.version, nil
}

func (b *reloadRaceBackend) Close() error     { return nil }
func (b *reloadRaceBackend) Describe() string { return "reload-race test backend" }

// TestReloadIfStaleDoesNotRevertAConcurrentWrite reproduces the sequence
// found in mikroview while chasing a concurrent-passkey-login race:
// reloadIfStale reads a backend snapshot without holding the store's
// write lock, and only re-checks staleness once it acquires that lock.
// A check that only bails out when the two versions matched exactly
// would fall through and apply a stale snapshot if a write had landed in
// this same process while the snapshot was being read -- silently
// reverting the write.
//
// This drives that exact sequence with a gated fake backend rather than
// real timing, so it fails every run without the fix, not just
// intermittently:
//
//  1. reloadIfStale is started in a goroutine; its Load() call reads the
//     backend's current (pre-write) bytes and then blocks on the gate.
//  2. While it's blocked, a write lands through the store's own locked
//     path -- reaching the fake backend's Save and advancing s.version
//     -- exactly like any ordinary store method would.
//  3. The gate is released, letting the blocked reloadIfStale proceed
//     with the pre-write snapshot it already captured.
//
// The write is done by hand (s.mu.Lock/mutateLocked) rather than
// through a store method, which would itself call reloadIfStale first
// and join the very reload this test is holding blocked -- deadlocking
// on the gate this goroutine hasn't released yet. Every real write
// method starts the same way, so this is the same critical section any
// of them would run, just reached directly.
//
// A store that comes out of this without the write is the bug.
func TestReloadIfStaleDoesNotRevertAConcurrentWrite(t *testing.T) {
	backend := &reloadRaceBackend{}
	s, err := OpenStore(backend, Options{})
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.Register("admin", "password123", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	backend.gate = make(chan struct{})
	reloadDone := make(chan struct{})
	go func() {
		defer close(reloadDone)
		s.reloadIfStale()
	}()

	// Give the goroutine above a moment to reach Load() and start
	// blocking on the gate before the write below runs -- a generous,
	// non-flaky margin: the goroutine has nothing else to do first.
	time.Sleep(20 * time.Millisecond)

	s.mu.Lock()
	err = s.mutateLocked(func(st *storeState) error {
		stored, ok := st.byID[u.ID]
		if !ok {
			return ErrUserNotFound
		}
		stored.TOTPSecret = "JBSWY3DPEHPK3PXP"
		return nil
	})
	s.mu.Unlock()
	if err != nil {
		t.Fatalf("the concurrent write: %v", err)
	}

	close(backend.gate)
	<-reloadDone

	// Read straight off s.byID under the store's own lock, not through
	// Get: Get calls reloadIfStale itself, and the backend's stored
	// bytes are the fresh, correct ones by now (mutateLocked above
	// wrote them) -- a second reload triggered from Get would pull
	// those in and quietly repair exactly the corruption this test
	// exists to catch, passing either way.
	s.mu.RLock()
	after, foundAfter := s.byID[u.ID]
	secret := after.TOTPSecret
	s.mu.RUnlock()
	if !foundAfter {
		t.Fatal("account vanished")
	}
	if secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("TOTPSecret after a reload raced against a concurrent write = %q, want the write to have survived (%q)",
			secret, "JBSWY3DPEHPK3PXP")
	}
}
