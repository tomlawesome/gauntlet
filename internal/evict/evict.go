// Copied from mikroview's internal/evict/evict.go, unchanged: this
// module's callers are LoginLimiter (ratelimit.go), the address ban
// (addressban.go) and the sign-in history's fold index (signins.go,
// #90), for the same
// reason mikroview keeps one implementation rather than several
// hand-copied ones (docs/design.md §1.1).
//
// Package evict bounds maps whose keys come from untrusted input.
//
// Several of mikroview's in-memory indexes are keyed on something an
// attacker chooses: a source MAC, a RouterOS log-prefix, a source
// address. Each is capped, and the cap is what stops the map growing
// without limit. How the cap is *enforced* turns out to matter as much
// as the cap itself.
//
// Evicting back to exactly the cap means the map is full again
// immediately, so the very next new key overflows too, and the scan
// runs again -- and again, for every subsequent event. Measured on
// internal/detect before it was fixed: 5.78 us/event with recurring
// sources against 504.96 us/event under all-distinct spoofed ones, an
// 87x slowdown that capped the detector near 2000 events/s, past which
// it silently dropped events. That is the tool failing at its one job,
// quietly, in exactly the conditions it exists for.
//
// Shedding a batch instead amortises the scan: the next n/8 new keys
// are free, so the per-event cost is the sort divided by the batch size
// rather than a whole sort. One eighth keeps the map comfortably full,
// so genuine long-lived entries are not evicted early.
//
// internal/detect solved this first and this package is that solution
// generalised, after #285 found the same eviction-to-exactly-the-cap
// pattern still live in internal/device and internal/rules. Keeping one
// implementation is the point -- the comment it replaced already
// recorded that six hand-copied versions had drifted once before.
package evict

import (
	"slices"
	"time"
)

// BatchFraction is how much of a full map to shed on overflow, as a
// divisor: 8 means one eighth.
const BatchFraction = 8

// Batch returns how many entries to shed from a map of n entries --
// always at least one, so a small map still makes progress.
func Batch(n int) int {
	if b := n / BatchFraction; b >= 1 {
		return b
	}
	return 1
}

// Target returns the size to shed a map down to once it has passed
// limit: one batch below the limit, so the next Batch(limit) new keys
// do not each trigger another shed. Callers pass this to DownTo.
func Target(limit int) int {
	if target := limit - Batch(limit); target >= 1 {
		return target
	}
	return 1
}

// DownTo removes the least-recently-active entries from m until at most
// target remain, using when to read each value's activity time. It
// returns how many were removed.
//
// The whole map is sorted once per shed rather than a single minimum
// being selected per insertion -- that is the amortisation, and it is
// why callers must pass a target *below* the cap rather than the cap
// itself. Sorting O(n log n) once every n/8 insertions costs far less
// per event than scanning O(n) on every one.
func DownTo[K comparable, V any](m map[K]V, target int, when func(V) time.Time) int {
	if target < 0 {
		target = 0
	}
	remove := len(m) - target
	if remove <= 0 {
		return 0
	}

	type entry struct {
		key  K
		when time.Time
	}
	all := make([]entry, 0, len(m))
	for k, v := range m {
		all = append(all, entry{key: k, when: when(v)})
	}
	slices.SortFunc(all, func(a, b entry) int { return a.when.Compare(b.when) })

	for i := 0; i < remove; i++ {
		delete(m, all[i].key)
	}
	return remove
}
