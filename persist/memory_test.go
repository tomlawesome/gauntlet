package persist

import (
	"context"
	"strings"
	"testing"
)

// The contract cases ported from mikroview's
// internal/persist/contract_test.go now run against Memory through the
// persisttest suite (suite_test.go, #61). What stays here is particular
// to Memory.

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
