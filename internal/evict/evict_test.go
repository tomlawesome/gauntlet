// Written for gauntlet: mikroview's internal/evict carries no test file
// of its own (checked against origin/dev, 2026-09-27), so there is
// nothing to port here. These exercise the package's exported surface
// directly.
package evict

import (
	"testing"
	"time"
)

func TestBatchIsOneEighthRoundedDown(t *testing.T) {
	cases := []struct {
		n, want int
	}{
		{0, 1},
		{1, 1},
		{7, 1},
		{8, 1},
		{16, 2},
		{4096, 512},
	}
	for _, c := range cases {
		if got := Batch(c.n); got != c.want {
			t.Errorf("Batch(%d) = %d, want %d", c.n, got, c.want)
		}
	}
}

func TestTargetIsLimitMinusOneBatch(t *testing.T) {
	cases := []struct {
		limit, want int
	}{
		{1, 1},   // Batch(1)==1, limit-1==0, clamped up to 1
		{8, 7},   // Batch(8)==1
		{16, 14}, // Batch(16)==2
		{4096, 3584},
	}
	for _, c := range cases {
		if got := Target(c.limit); got != c.want {
			t.Errorf("Target(%d) = %d, want %d", c.limit, got, c.want)
		}
	}
}

func TestDownToRemovesLeastRecentlyActiveFirst(t *testing.T) {
	now := time.Now()
	m := map[string]time.Time{
		"oldest": now,
		"middle": now.Add(time.Minute),
		"newest": now.Add(2 * time.Minute),
	}
	removed := DownTo(m, 2, func(v time.Time) time.Time { return v })
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	if len(m) != 2 {
		t.Fatalf("len(m) = %d, want 2", len(m))
	}
	if _, ok := m["oldest"]; ok {
		t.Error("expected the oldest entry to have been evicted")
	}
	if _, ok := m["newest"]; !ok {
		t.Error("expected the newest entry to remain")
	}
}

func TestDownToIsANoOpWhenAlreadyAtOrBelowTarget(t *testing.T) {
	m := map[string]time.Time{"a": time.Now()}
	if removed := DownTo(m, 5, func(v time.Time) time.Time { return v }); removed != 0 {
		t.Errorf("removed = %d, want 0", removed)
	}
	if len(m) != 1 {
		t.Errorf("len(m) = %d, want 1 -- DownTo must not touch a map already within target", len(m))
	}
}

func TestDownToClampsANegativeTargetToZero(t *testing.T) {
	m := map[string]time.Time{"a": time.Now(), "b": time.Now().Add(time.Second)}
	removed := DownTo(m, -1, func(v time.Time) time.Time { return v })
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	if len(m) != 0 {
		t.Errorf("len(m) = %d, want 0", len(m))
	}
}

func TestDownToOnEmptyMapRemovesNothing(t *testing.T) {
	m := map[string]time.Time{}
	if removed := DownTo(m, 10, func(v time.Time) time.Time { return v }); removed != 0 {
		t.Errorf("removed = %d, want 0", removed)
	}
}
