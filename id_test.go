package gauntlet

import "testing"

// TestNewIDShapeAndUniqueness pins newID's contract: a 32-character
// lowercase hex string, distinct across calls. The rand.Read failure
// panic has no hook to trigger it under test, so it stays unverified
// here.
func TestNewIDShapeAndUniqueness(t *testing.T) {
	const n = 1000
	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		id := newID()
		if len(id) != 32 {
			t.Fatalf("newID() = %q, length %d, want 32", id, len(id))
		}
		for _, r := range id {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
				t.Fatalf("newID() = %q contains non-lowercase-hex character %q", id, r)
			}
		}
		if seen[id] {
			t.Fatalf("newID() returned %q twice within %d calls", id, n)
		}
		seen[id] = true
	}
}
