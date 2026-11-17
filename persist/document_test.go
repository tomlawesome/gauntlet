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

// A conflict SaveWithRetry cannot even inspect -- reloading itself
// fails -- must surface that reload error, not the original conflict.
func TestSaveWithRetryReloadFailureAfterConflictPropagates(t *testing.T) {
	b := &conflictThenBrokenBackend{loadErr: errors.New("reload on fire")}
	_, conflicted, err := SaveWithRetry(context.Background(), b, []byte(`{}`), 1)
	if err == nil || err.Error() != "reload on fire" {
		t.Fatalf("err = %v, want the reload's own error", err)
	}
	if !conflicted {
		t.Error("conflicted = false, want true: a conflict was seen before the reload failed")
	}
}

// A conflict that reloads cleanly but whose retried Save then fails for
// an unrelated reason (not another conflict) must surface that error too.
func TestSaveWithRetryRetriedSaveFailurePropagates(t *testing.T) {
	b := &conflictThenBrokenBackend{saveErr: errors.New("retried write on fire")}
	_, conflicted, err := SaveWithRetry(context.Background(), b, []byte(`{}`), 1)
	if err == nil || err.Error() != "retried write on fire" {
		t.Fatalf("err = %v, want the retried save's own error", err)
	}
	if !conflicted {
		t.Error("conflicted = false, want true: a conflict was seen before the retried save failed")
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

// conflictThenBrokenBackend returns ErrConflict from its first Save (so
// SaveWithRetry always takes the reload-and-retry path), then breaks in
// whichever of Load or the retried Save the test configures.
type conflictThenBrokenBackend struct {
	saved   bool
	loadErr error
	saveErr error
}

func (b *conflictThenBrokenBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	if !b.saved {
		b.saved = true
		return 0, ErrConflict
	}
	if b.saveErr != nil {
		return 0, b.saveErr
	}
	return 2, nil
}

func (b *conflictThenBrokenBackend) Load(ctx context.Context) (Snapshot, error) {
	if b.loadErr != nil {
		return Snapshot{}, b.loadErr
	}
	return Snapshot{Payload: []byte(`{}`), Version: 1, Exists: true}, nil
}

func (b *conflictThenBrokenBackend) Close() error     { return nil }
func (b *conflictThenBrokenBackend) Describe() string { return "conflict-then-broken test backend" }
