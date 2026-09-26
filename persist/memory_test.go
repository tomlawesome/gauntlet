package persist

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// These are mikroview's internal/persist/contract_test.go cases, ported
// to run against Memory directly rather than through mikroview's
// multi-backend eachBackend helper -- gauntlet ships only Memory (see
// persist.go's package comment), so there is only one backend to run
// them against.

func TestMemoryLoadOfAnUnwrittenStore(t *testing.T) {
	b := NewMemory()
	snap, err := b.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if snap.Exists {
		t.Error("Exists is true for a store that was never written")
	}
	if snap.Version != 0 {
		t.Errorf("Version = %d, want 0 for a store that was never written", snap.Version)
	}
	if len(snap.Payload) != 0 {
		t.Errorf("Payload = %q, want empty", snap.Payload)
	}
}

func TestMemoryCreateThenRead(t *testing.T) {
	b := NewMemory()
	ctx := context.Background()
	v, err := b.Save(ctx, []byte(`{"hello":"world"}`), 0)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	snap, err := b.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(snap.Payload) != `{"hello":"world"}` {
		t.Errorf("Payload = %q", snap.Payload)
	}
	if !snap.Exists {
		t.Error("Exists is false after a successful create")
	}
	if snap.Version != v {
		t.Errorf("Load version %d != Save version %d", snap.Version, v)
	}
}

// Creating twice must fail. Otherwise two processes starting together
// could each believe they initialised the store.
func TestMemoryDoubleCreateIsAConflict(t *testing.T) {
	b := NewMemory()
	ctx := context.Background()
	if _, err := b.Save(ctx, []byte(`{"n":1}`), 0); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := b.Save(ctx, []byte(`{"n":2}`), 0); err != ErrConflict {
		t.Errorf("second create: got %v, want ErrConflict", err)
	}
}

func TestMemoryStaleWriteIsRefused(t *testing.T) {
	b := NewMemory()
	ctx := context.Background()
	v1, err := b.Save(ctx, []byte(`{"n":1}`), 0)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	v2, err := b.Save(ctx, []byte(`{"n":2}`), v1)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if v2 == v1 {
		t.Error("version did not advance on write")
	}
	if _, err := b.Save(ctx, []byte(`{"n":3}`), v1); err != ErrConflict {
		t.Errorf("stale write: got %v, want ErrConflict", err)
	}

	snap, _ := b.Load(ctx)
	if string(snap.Payload) != `{"n":2}` {
		t.Errorf("stale write landed: %q", snap.Payload)
	}
}

func TestMemorySuccessiveWritesChain(t *testing.T) {
	b := NewMemory()
	ctx := context.Background()
	v, err := b.Save(ctx, []byte(`{"n":0}`), 0)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for i := 1; i <= 5; i++ {
		v, err = b.Save(ctx, []byte(`{"n":`+string(rune('0'+i))+`}`), v)
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	snap, _ := b.Load(ctx)
	if string(snap.Payload) != `{"n":5}` {
		t.Errorf("final payload = %q", snap.Payload)
	}
}

// An empty document is a real, storable state -- distinct from "never
// written".
func TestMemoryEmptyPayloadIsStillAnExistingStore(t *testing.T) {
	b := NewMemory()
	ctx := context.Background()
	if _, err := b.Save(ctx, []byte(``), 0); err != nil {
		t.Fatalf("Save: %v", err)
	}
	snap, err := b.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !snap.Exists {
		t.Error("an empty document reports as never written")
	}
}

func TestMemoryDescribeIsCredentialFree(t *testing.T) {
	b := NewMemory()
	d := b.Describe()
	if d == "" {
		t.Error("Describe returned nothing")
	}
	if strings.ContainsAny(d, "{}") {
		t.Errorf("Describe looks like it leaked a document fragment: %q", d)
	}
}

// Concurrent writers may lose the compare-and-swap -- that is the
// contract, and ErrConflict says so. What they must never do is leave
// the stored document holding bytes that were never a whole payload.
func TestMemoryConcurrentWritersNeverPublishAMixedDocument(t *testing.T) {
	b := NewMemory()
	big := []byte(`{"v":"` + strings.Repeat("A", 150_000) + `"}`)
	small := []byte(`{"v":"B"}`)

	if _, err := b.Save(context.Background(), small, 0); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	for round := 0; round < 200; round++ {
		var wg sync.WaitGroup
		start := make(chan struct{})
		for _, payload := range [][]byte{big, small} {
			wg.Add(1)
			go func(payload []byte) {
				defer wg.Done()
				<-start
				snap, err := b.Load(context.Background())
				if err != nil {
					return
				}
				// ErrConflict is a correct outcome here and is
				// deliberately not asserted on.
				_, _ = b.Save(context.Background(), payload, snap.Version)
			}(payload)
		}
		close(start)
		wg.Wait()

		snap, err := b.Load(context.Background())
		if err != nil {
			t.Fatalf("round %d: settled Load: %v", round, err)
		}
		got := string(snap.Payload)
		if got != string(big) && got != string(small) {
			t.Fatalf("round %d: stored document is neither payload -- %d bytes, prefix %.80q",
				round, len(got), got)
		}
	}
}

func TestMemoryVersionReaderMatchesLoad(t *testing.T) {
	b := NewMemory()
	ctx := context.Background()

	version, exists, err := b.Version(ctx)
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if exists || version != 0 {
		t.Errorf("Version on an unwritten store = (%d, %v), want (0, false)", version, exists)
	}

	v, err := b.Save(ctx, []byte(`{"n":1}`), 0)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	version, exists, err = b.Version(ctx)
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if !exists || version != v {
		t.Errorf("Version after Save = (%d, %v), want (%d, true)", version, exists, v)
	}
}

// Load must hand back a copy: mutating the returned payload must not
// reach back into the backend's own storage.
func TestMemoryLoadReturnsACopy(t *testing.T) {
	b := NewMemory()
	ctx := context.Background()
	if _, err := b.Save(ctx, []byte(`{"n":1}`), 0); err != nil {
		t.Fatalf("Save: %v", err)
	}
	snap, err := b.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	snap.Payload[0] = 'X'

	again, err := b.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(again.Payload) != `{"n":1}` {
		t.Errorf("mutating a returned Snapshot changed the stored document: %q", again.Payload)
	}
}
