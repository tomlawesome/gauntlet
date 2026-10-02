// Ported from mikroview's internal/auth/stall_test.go. Adapted:
// OpenWithBackend -> OpenStore.

package gauntlet

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// stallingBackend answers normally until armed, then makes Load hang the
// way a database server does when it stops responding while its TCP
// connection stays ESTABLISHED -- a blackhole, a long lock wait, or an
// overloaded server. That case matters because it is the one many
// database drivers cannot detect: a clean disconnect returns an error
// promptly, this does not.
type stallingBackend struct {
	mu          sync.Mutex
	payload     []byte
	version     int64
	armed       bool
	inFlight    int
	maxInFlight int
	loads       int
	deadlines   int
}

func (b *stallingBackend) arm() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.armed = true
}

func (b *stallingBackend) Load(ctx context.Context) (persist.Snapshot, error) {
	b.mu.Lock()
	b.loads++
	armed := b.armed
	if armed {
		b.inFlight++
		if b.inFlight > b.maxInFlight {
			b.maxInFlight = b.inFlight
		}
		if _, ok := ctx.Deadline(); ok {
			b.deadlines++
		}
	}
	snap := persist.Snapshot{Payload: b.payload, Version: b.version, Exists: b.version != 0}
	b.mu.Unlock()

	if !armed {
		return snap, nil
	}

	<-ctx.Done() // the stall: nothing but the caller's own deadline ends this
	b.mu.Lock()
	b.inFlight--
	b.mu.Unlock()
	return persist.Snapshot{}, ctx.Err()
}

func (b *stallingBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if expect != b.version {
		return 0, persist.ErrConflict
	}
	b.payload = payload
	b.version++
	return b.version, nil
}

func (b *stallingBackend) Close() error     { return nil }
func (b *stallingBackend) Describe() string { return "stalling test backend" }

// ProtectedAtRest: see failingSaveBackend (testhelpers_test.go).
func (b *stallingBackend) ProtectedAtRest() bool { return true }

func (b *stallingBackend) stats() (maxInFlight, loads, deadlines int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.maxInFlight, b.loads, b.deadlines
}

// A stalled backend used to cost one blocked goroutine and one pooled
// connection per authenticated request, forever, in mikroview:
// reloadIfStale ran on every request via its login/session path and
// passed context.Background(). An HTTP server's write timeout does not
// rescue that -- it tears down the client connection and leaves the
// handler goroutine blocked. Login went through the same path, so an
// operator could not sign in to find out what was wrong.
//
// The claim under test is availability, not speed: every caller returns,
// only one check reaches the backend at a time, and the calls carry a
// deadline.
func TestStalledBackendDoesNotPileUpPerRequestWork(t *testing.T) {
	restore := reloadTimeout
	reloadTimeout = 150 * time.Millisecond
	t.Cleanup(func() { reloadTimeout = restore })

	b := &stallingBackend{}
	s, err := OpenStore(b, Options{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if _, err := s.Register("admin", "password123", time.Now()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	b.arm()

	const callers = 25
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			// Whatever this returns is fine. What matters is that it
			// returns at all, and that the store keeps serving from
			// memory rather than failing.
			_, _ = s.Get("nobody")
		}()
	}

	begin := time.Now()
	close(start)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("callers never returned against a stalled backend -- this is the goroutine leak the fix exists for")
	}
	elapsed := time.Since(begin)

	maxInFlight, _, deadlines := b.stats()
	if maxInFlight > 1 {
		t.Errorf("%d concurrent Loads reached the backend; want at most 1, or a stall costs one pooled connection per request", maxInFlight)
	}
	if deadlines == 0 {
		t.Error("the stalled Load carried no deadline -- it would block until the backend returned")
	}
	// Generous: the point is that 25 callers did not serialise into 25
	// consecutive timeouts, not that the constant is exact.
	if budget := 10 * reloadTimeout; elapsed > budget {
		t.Errorf("25 callers took %v against a %v timeout (budget %v) -- they are not sharing one check",
			elapsed, reloadTimeout, budget)
	}
}

// The store must still serve from memory while the backend is stalled --
// a transient backend problem must not take authentication down on a
// server that is otherwise running fine.
func TestStalledBackendStillServesFromMemory(t *testing.T) {
	restore := reloadTimeout
	reloadTimeout = 50 * time.Millisecond
	t.Cleanup(func() { reloadTimeout = restore })

	b := &stallingBackend{}
	s, err := OpenStore(b, Options{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if _, err := s.Register("admin", "password123", time.Now()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	b.arm()

	if u, ok := s.ByUsername("admin"); !ok || u.Username != "admin" {
		t.Error("the store stopped serving its in-memory accounts while the backend was stalled")
	}
	if _, err := s.Authenticate("admin", "password123", time.Now()); err != nil {
		t.Errorf("login failed against a stalled backend: %v -- the operator cannot sign in to diagnose the outage", err)
	}
}

// stallingSaveBackend is the write-side twin of stallingBackend: Load
// answers, Save hangs until the caller's own context ends it.
type stallingSaveBackend struct {
	mu      sync.Mutex
	payload []byte
	version int64
	armed   bool
}

func (b *stallingSaveBackend) Load(ctx context.Context) (persist.Snapshot, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return persist.Snapshot{Payload: b.payload, Version: b.version, Exists: b.version != 0}, nil
}

func (b *stallingSaveBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	b.mu.Lock()
	armed := b.armed
	b.mu.Unlock()
	if armed {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.payload = append([]byte(nil), payload...)
	b.version++
	return b.version, nil
}

func (b *stallingSaveBackend) Close() error     { return nil }
func (b *stallingSaveBackend) Describe() string { return "stalling-save test backend" }

// ProtectedAtRest: see failingSaveBackend (testhelpers_test.go).
func (b *stallingSaveBackend) ProtectedAtRest() bool { return true }

// TestStalledSaveReturnsAndRollsBack: a save runs under the store's
// write lock, so a backend that hangs mid-save used to hold every
// login and every signed-in request until a restart. With saveTimeout
// the write fails instead, the caller rolls its change back, and the
// store goes on serving what it has.
func TestStalledSaveReturnsAndRollsBack(t *testing.T) {
	restore := saveTimeout
	saveTimeout = 100 * time.Millisecond
	t.Cleanup(func() { saveTimeout = restore })

	b := &stallingSaveBackend{}
	s, err := OpenStore(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register("admin", "old-password", time.Now()); err != nil {
		t.Fatal(err)
	}
	tb := &stallingSaveBackend{}
	tokens, err := OpenTokenStore(tb, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for _, sb := range []*stallingSaveBackend{b, tb} {
		sb.mu.Lock()
		sb.armed = true
		sb.mu.Unlock()
	}

	done := make(chan error, 2)
	go func() { done <- s.SetPassword("admin", "new-password", time.Now()) }()
	go func() {
		_, _, err := tokens.Create("cron", TokenKindAPI, "", nil, time.Now())
		done <- err
	}()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err == nil {
				t.Error("a save against a stalled backend reported success")
			}
		case <-time.After(20 * saveTimeout):
			t.Fatal("a save against a stalled backend never returned -- the store lock is held until restart")
		}
	}

	// Rolled back: the old password still works, and a read does not
	// block behind the stalled write.
	if _, err := s.Authenticate("admin", "old-password", time.Now()); err != nil {
		t.Errorf("old password after a failed save: %v, want it still to work", err)
	}
	if n := len(tokens.List()); n != 0 {
		t.Errorf("%d tokens listed after a failed save, want 0", n)
	}
}
