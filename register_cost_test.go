// Ported from mikroview's internal/auth/register_cost_test.go. Adapted:
// Open(path) -> openTestStore(t).

package gauntlet

import (
	"runtime"
	"testing"
	"time"
)

// TestClosedRegistrationDoesNotHash is the regression test for an
// unauthenticated memory-amplification DoS.
//
// HashPassword is Argon2id at 64 MiB by design. A registration endpoint
// built over this store is typically unauthenticated and, unlike login,
// has no rate limiter -- so if a request that is going to be refused
// still pays for a hash first, a ~60-byte POST costs 64 MiB and a
// handful of concurrent ones OOM-kill the container. Measured at ~1 GiB
// peak heap for 16 concurrent requests in mikroview, every one of which
// correctly returned "registration closed".
//
// Asserting allocation rather than wall-clock keeps this meaningful on
// a loaded CI machine.
//
// Run at the production cost (see TestMain): at the cheap test cost a
// hash is too small for the ceiling below to catch one.
func TestClosedRegistrationDoesNotHash(t *testing.T) {
	useProductionHashCost(t)
	s := openTestStore(t)
	if _, err := s.Register("admin", "correct horse battery staple", time.Now()); err != nil {
		t.Fatal(err)
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	const attempts = 8
	for i := 0; i < attempts; i++ {
		if _, err := s.Register("attacker", "correct horse battery staple", time.Now()); err == nil {
			t.Fatal("a second Register must be refused once an account exists")
		}
	}
	runtime.ReadMemStats(&after)

	allocated := after.TotalAlloc - before.TotalAlloc
	// One Argon2id hash is 64 MiB. Eight refused attempts must cost far
	// less than even a single hash; a generous 16 MiB ceiling catches
	// the regression without being brittle.
	const ceiling = 16 << 20
	if allocated > ceiling {
		t.Errorf("%d refused registrations allocated %d bytes (%.1f MiB); expected well under %d bytes -- "+
			"a rejected registration must not pay for an Argon2id hash",
			attempts, allocated, float64(allocated)/(1<<20), ceiling)
	}
}
