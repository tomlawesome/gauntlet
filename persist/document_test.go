package persist

import (
	"context"
	"errors"
	"testing"
)

// SaveWithRetry and LoadDocument have no dedicated test file in
// mikroview -- they are exercised there only indirectly, through each
// store's own tests. These are written directly against Memory.

func TestSaveWithRetryNilBackendIsANoop(t *testing.T) {
	version, conflicted, err := SaveWithRetry(context.Background(), nil, []byte(`{"n":1}`), 5)
	if err != nil {
		t.Fatalf("SaveWithRetry with a nil backend: %v", err)
	}
	if conflicted {
		t.Error("conflicted = true with a nil backend")
	}
	if version != 5 {
		t.Errorf("version = %d, want the current version handed back unchanged", version)
	}
}

func TestSaveWithRetrySucceedsWithoutConflict(t *testing.T) {
	b := NewMemory()
	ctx := context.Background()
	v0, err := b.Save(ctx, []byte(`{"n":0}`), 0)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	version, conflicted, err := SaveWithRetry(ctx, b, []byte(`{"n":1}`), v0)
	if err != nil {
		t.Fatalf("SaveWithRetry: %v", err)
	}
	if conflicted {
		t.Error("conflicted = true on a clean write")
	}
	snap, _ := b.Load(ctx)
	if string(snap.Payload) != `{"n":1}` {
		t.Errorf("stored payload = %q", snap.Payload)
	}
	if snap.Version != version {
		t.Errorf("returned version %d != stored version %d", version, snap.Version)
	}
}

// The documented behaviour: a conflict is resolved as last-writer-wins,
// applied on top of whatever landed -- not surfaced as a fatal error.
func TestSaveWithRetryRecoversFromAConflict(t *testing.T) {
	b := NewMemory()
	ctx := context.Background()
	v0, err := b.Save(ctx, []byte(`{"n":0}`), 0)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Someone else writes in between, so v0 is now stale.
	if _, err := b.Save(ctx, []byte(`{"n":"someone else"}`), v0); err != nil {
		t.Fatalf("interleaved write: %v", err)
	}

	version, conflicted, err := SaveWithRetry(ctx, b, []byte(`{"n":"mine"}`), v0)
	if err != nil {
		t.Fatalf("SaveWithRetry: %v", err)
	}
	if !conflicted {
		t.Error("conflicted = false, want true: the caller's version was stale")
	}
	snap, _ := b.Load(ctx)
	if string(snap.Payload) != `{"n":"mine"}` {
		t.Errorf("stored payload = %q, want the retried write to have landed", snap.Payload)
	}
	if snap.Version != version {
		t.Errorf("returned version %d != stored version %d", version, snap.Version)
	}
}

// A failure that reloading cannot fix -- the backend is simply broken --
// must be reported as an error and never silently absorbed.
func TestSaveWithRetryNonConflictErrorPropagates(t *testing.T) {
	b := &failingBackend{err: errors.New("disk on fire")}
	_, _, err := SaveWithRetry(context.Background(), b, []byte(`{}`), 1)
	if err == nil || err.Error() != "disk on fire" {
		t.Fatalf("err = %v, want the backend's own error", err)
	}
}

func TestLoadDocumentNilBackend(t *testing.T) {
	data, version, err := LoadDocument(context.Background(), nil)
	if err != nil || data != nil || version != 0 {
		t.Errorf("LoadDocument(nil) = (%v, %d, %v), want (nil, 0, nil)", data, version, err)
	}
}

func TestLoadDocumentNeverWritten(t *testing.T) {
	data, version, err := LoadDocument(context.Background(), NewMemory())
	if err != nil || data != nil || version != 0 {
		t.Errorf("LoadDocument(unwritten) = (%v, %d, %v), want (nil, 0, nil)", data, version, err)
	}
}

func TestLoadDocumentExisting(t *testing.T) {
	b := NewMemory()
	v, err := b.Save(context.Background(), []byte(`{"n":1}`), 0)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	data, version, err := LoadDocument(context.Background(), b)
	if err != nil {
		t.Fatalf("LoadDocument: %v", err)
	}
	if string(data) != `{"n":1}` || version != v {
		t.Errorf("LoadDocument = (%q, %d), want (%q, %d)", data, version, `{"n":1}`, v)
	}
}

// failingBackend always returns err from Save, never ErrConflict --
// standing in for a backend that is simply broken, so SaveWithRetry must
// not treat it as a stale write to retry.
type failingBackend struct{ err error }

func (f *failingBackend) Load(ctx context.Context) (Snapshot, error) { return Snapshot{}, f.err }
func (f *failingBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	return 0, f.err
}
func (f *failingBackend) Close() error     { return nil }
func (f *failingBackend) Describe() string { return "failing test backend" }
