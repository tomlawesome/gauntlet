// Ported from mikroview's internal/auth/reload_test.go. Adapted:
// OpenWithBackend -> OpenStore.

package gauntlet

import (
	"context"
	"encoding/json"
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

	// entered, if non-nil, receives once when Load has taken its
	// snapshot and is about to wait on gate, so a test knows the read is
	// in flight without guessing at timing.
	entered chan struct{}

	// override, if non-nil, is what Load returns instead of the bytes it
	// just read: a snapshot of some other writer's document, as a second
	// process saving to the same backend would leave behind.
	override *persist.Snapshot
}

func (b *reloadRaceBackend) Load(ctx context.Context) (persist.Snapshot, error) {
	b.mu.Lock()
	snap := persist.Snapshot{
		Payload: append([]byte(nil), b.payload...),
		Version: b.version,
		Exists:  b.exists,
	}
	if b.override != nil {
		snap = *b.override
	}
	b.mu.Unlock()
	if b.entered != nil {
		select {
		case b.entered <- struct{}{}:
		default:
		}
	}
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

// ProtectedAtRest: see failingSaveBackend (testhelpers_test.go).
func (b *reloadRaceBackend) ProtectedAtRest() bool { return true }

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
// real timing. The snapshot here carries the version the reload started
// at, so it is the early return on an unchanged version that this
// covers; the re-check under the write lock is covered by the test
// after it.
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
	u, err := s.Register("admin", "password-placeholder-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	backend.gate = make(chan struct{})
	backend.entered = make(chan struct{}, 1)
	reloadDone := make(chan struct{})
	go func() {
		defer close(reloadDone)
		s.reloadIfStale()
	}()

	// Wait for the goroutine above to be inside Load(), blocked on the
	// gate, before the write below runs.
	<-backend.entered

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

// The same race as above with a snapshot that differs from the version
// the reload started at, which is what reaches the re-check made once
// the write lock is held (the early return on an unchanged version does
// not): another process saved a document, this process wrote in the
// meantime, and the other process's document -- not yet containing that
// write, and with a sequence counter no lower than this process has
// reached, so the stale-document refusal (#59) does not apply -- must
// not replace it.
func TestReloadIfStaleDoesNotRevertAWriteMadeWhileAnotherProcessesSnapshotWasRead(t *testing.T) {
	backend := &reloadRaceBackend{}
	s, err := OpenStore(backend, Options{})
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.Register("admin", "password-placeholder-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// The other process's document: this one's accounts as registered,
	// at a counter the write below will bring this process level with,
	// under a version this process has not seen.
	snap, err := backend.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var file storeFile
	if err := json.Unmarshal(snap.Payload, &file); err != nil {
		t.Fatal(err)
	}
	file.Seq++
	other, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.RLock()
	seenVersion := s.version
	s.mu.RUnlock()
	backend.override = &persist.Snapshot{Payload: other, Version: seenVersion + 5, Exists: true}

	backend.gate = make(chan struct{})
	backend.entered = make(chan struct{}, 1)
	reloadDone := make(chan struct{})
	go func() {
		defer close(reloadDone)
		s.reloadIfStale()
	}()
	<-backend.entered

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

	// Straight off s.byID, not through Get, which would reload again.
	s.mu.RLock()
	after, found := s.byID[u.ID]
	s.mu.RUnlock()
	if !found {
		t.Fatal("account vanished")
	}
	if after.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("TOTPSecret after a reload raced against a concurrent write = %q, want the write to have survived", after.TOTPSecret)
	}
}
