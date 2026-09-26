package persist

import (
	"context"
	"sync"
)

// Memory is an in-memory Backend, for gauntlet's own tests and for an
// application's tests -- never for production use, since nothing it
// holds survives the process. Unlike mikroview's FileBackend, whose
// version has to be derived from the file's bytes because there is
// nothing cheaper to compare, Memory can simply count its own writes: a
// monotonically increasing version, starting at 1, assigned under the
// same mutex that serializes reads and writes. That also means two
// concurrent writers can never publish a mixed document -- each Save
// either replaces the stored payload whole, under the lock, or is
// refused with ErrConflict.
type Memory struct {
	mu      sync.Mutex
	payload []byte
	version int64
	exists  bool
}

// NewMemory returns an empty Memory backend, as if its document had
// never been written.
func NewMemory() *Memory {
	return &Memory{}
}

func (m *Memory) Describe() string { return "memory store" }

func (m *Memory) Close() error { return nil }

// Load returns the current document. A backend that has never been
// written to returns a zero-value Snapshot and a nil error.
func (m *Memory) Load(ctx context.Context) (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.exists {
		return Snapshot{}, nil
	}
	// Copied out so a caller mutating the returned slice cannot reach
	// back into the backend's own storage.
	payload := make([]byte, len(m.payload))
	copy(payload, m.payload)
	return Snapshot{Payload: payload, Version: m.version, Exists: true}, nil
}

// Save replaces the document if expect matches the stored version,
// returning the new version. expect == 0 means "create": it succeeds
// only if nothing is stored yet.
func (m *Memory) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.exists {
		if expect != 0 {
			return 0, ErrConflict // caller believed a document existed; it doesn't
		}
	} else {
		if expect == 0 {
			return 0, ErrConflict // caller expected to be creating it
		}
		if expect != m.version {
			return 0, ErrConflict
		}
	}

	stored := make([]byte, len(payload))
	copy(stored, payload)
	m.payload = stored
	m.exists = true
	m.version++
	return m.version, nil
}

// Version implements VersionReader. For Memory this costs nothing more
// than Load, but it exists so callers written against the interface
// exercise the same code path they use against a backend where it does.
func (m *Memory) Version(ctx context.Context) (version int64, exists bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.version, m.exists, nil
}
