// Ported from mikroview's internal/auth/session_test.go, adapted to the
// one NewSessionStore(ttl, maxLifetime) constructor (session.go):
// mikroview's NewSessionStore(ttl) becomes NewSessionStore(ttl, 0) and
// NewSessionStoreWithMaxLifetime(ttl, max) becomes NewSessionStore(ttl,
// max). Otherwise unchanged, including the maxLifetime-ceiling cases.
package gauntlet

import (
	"strconv"
	"testing"
	"time"
)

func TestSessionCreateAndValidate(t *testing.T) {
	s := NewSessionStore(time.Hour, 0)
	now := time.Now()
	sess := s.Create("user-1", now)

	got, ok := s.Validate(sess.ID, now.Add(time.Minute))
	if !ok {
		t.Fatal("expected the freshly created session to validate")
	}
	if got.UserID != "user-1" {
		t.Errorf("UserID = %q, want %q", got.UserID, "user-1")
	}
}

func TestSessionValidateRejectsUnknownID(t *testing.T) {
	s := NewSessionStore(time.Hour, 0)
	if _, ok := s.Validate("does-not-exist", time.Now()); ok {
		t.Error("expected an unknown session ID to fail validation")
	}
}

func TestSessionExpires(t *testing.T) {
	s := NewSessionStore(time.Minute, 0)
	now := time.Now()
	sess := s.Create("user-1", now)

	if _, ok := s.Validate(sess.ID, now.Add(2*time.Minute)); ok {
		t.Error("expected the session to have expired")
	}
	// The expired lookup should have evicted it -- confirm it's really gone.
	if _, ok := s.Validate(sess.ID, now); ok {
		t.Error("expected the expired session to be evicted, not just reported expired")
	}
}

func TestSessionSlidingExpirationExtendsOnUse(t *testing.T) {
	s := NewSessionStore(time.Minute, 0)
	now := time.Now()
	sess := s.Create("user-1", now)

	// Use it right before it would have expired -- should extend, not expire.
	if _, ok := s.Validate(sess.ID, now.Add(50*time.Second)); !ok {
		t.Fatal("expected the session to still be valid just before its original expiry")
	}
	// Now well past the *original* expiry, but within a fresh TTL from the last use.
	if _, ok := s.Validate(sess.ID, now.Add(90*time.Second)); !ok {
		t.Error("expected sliding expiration to have extended the session past its original TTL")
	}
}

func TestSessionRevoke(t *testing.T) {
	s := NewSessionStore(time.Hour, 0)
	now := time.Now()
	sess := s.Create("user-1", now)

	s.Revoke(sess.ID)
	if _, ok := s.Validate(sess.ID, now); ok {
		t.Error("expected a revoked session to fail validation")
	}
}

func TestSessionRevokeAllForUser(t *testing.T) {
	s := NewSessionStore(time.Hour, 0)
	now := time.Now()
	a1 := s.Create("user-1", now)
	a2 := s.Create("user-1", now)
	b1 := s.Create("user-2", now)

	s.RevokeAllForUser("user-1")

	if _, ok := s.Validate(a1.ID, now); ok {
		t.Error("expected user-1's first session to be revoked")
	}
	if _, ok := s.Validate(a2.ID, now); ok {
		t.Error("expected user-1's second session to be revoked")
	}
	if _, ok := s.Validate(b1.ID, now); !ok {
		t.Error("expected user-2's session to be unaffected")
	}
}

// The ceiling SessionTTL does not have (#294 item 3). Without it a
// session used even once per ttl never expires, so a browser left signed
// in on a shared machine stays valid indefinitely.
func TestSessionMaxLifetimeCapsASlidingSession(t *testing.T) {
	const ttl = time.Hour
	const maxLifetime = 6 * time.Hour
	s := NewSessionStore(ttl, maxLifetime)

	start := time.Now()
	sess := s.Create("u1", start)

	// Used regularly, well inside the idle timeout every time. Under the
	// old behaviour this loop could run forever.
	for at := start.Add(30 * time.Minute); at.Before(start.Add(maxLifetime)); at = at.Add(30 * time.Minute) {
		if _, ok := s.Validate(sess.ID, at); !ok {
			t.Fatalf("session rejected at %v, still inside its %v ceiling", at.Sub(start), maxLifetime)
		}
	}

	// One step past the ceiling, still active.
	if _, ok := s.Validate(sess.ID, start.Add(maxLifetime).Add(time.Second)); ok {
		t.Error("a session older than the ceiling was accepted because it was still being used")
	}
}

// The renewed expiry must not reach past the ceiling either. Checking
// the deadline while writing an ExpiresAt beyond it would leave the
// stored session looking valid to anything reading that field.
func TestSessionRenewalNeverExceedsTheCeiling(t *testing.T) {
	const ttl = 4 * time.Hour
	const maxLifetime = 5 * time.Hour
	s := NewSessionStore(ttl, maxLifetime)

	start := time.Now()
	sess := s.Create("u1", start)

	// Renewing at +4h would normally push expiry to +8h, past the +5h
	// ceiling.
	renewed, ok := s.Validate(sess.ID, start.Add(4*time.Hour))
	if !ok {
		t.Fatal("session rejected inside its ceiling")
	}
	deadline := start.Add(maxLifetime)
	if renewed.ExpiresAt.After(deadline) {
		t.Errorf("renewed expiry %v is past the ceiling %v", renewed.ExpiresAt.Sub(start), maxLifetime)
	}
}

// Zero means no ceiling, which is what the CLI tooling and most tests
// want -- and what an operator gets if they deliberately set it to 0.
func TestSessionMaxLifetimeZeroMeansNoCeiling(t *testing.T) {
	s := NewSessionStore(time.Hour, 0)
	start := time.Now()
	sess := s.Create("u1", start)

	at := start
	for i := 0; i < 100; i++ {
		at = at.Add(30 * time.Minute)
		if _, ok := s.Validate(sess.ID, at); !ok {
			t.Fatalf("session rejected at %v with no ceiling configured", at.Sub(start))
		}
	}
}

// A negative maxLifetime is treated the same as zero: no ceiling, rather
// than a store that can never validate anything.
func TestSessionNegativeMaxLifetimeMeansNoCeiling(t *testing.T) {
	s := NewSessionStore(time.Hour, -time.Minute)
	start := time.Now()
	sess := s.Create("u1", start)

	at := start
	for i := 0; i < 100; i++ {
		at = at.Add(30 * time.Minute)
		if _, ok := s.Validate(sess.ID, at); !ok {
			t.Fatalf("session rejected at %v with a negative maxLifetime, want no ceiling", at.Sub(start))
		}
	}
}

// heldSessions is how many sessions s holds, expired or not.
func heldSessions(s *SessionStore) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// TestSessionCreateSweepsExpiredEntries: a session whose cookie is never
// presented again is only ever evicted by a sweep, so without one the
// map grows for the life of the process.
func TestSessionCreateSweepsExpiredEntries(t *testing.T) {
	const n = 1000
	s := NewSessionStore(time.Minute, 0)
	t0 := time.Now()
	for range n {
		s.Create("user-1", t0)
	}
	// Past their ttl. Each of these logins checks a few of the old
	// sessions; n of them reach every one.
	for range n {
		s.Create("user-1", t0.Add(2*time.Minute))
	}
	if got := heldSessions(s); got != n {
		t.Errorf("%d sessions held after the first %d expired, want the %d live ones", got, n, n)
	}
}

// The ceiling counts too: a session still inside its sliding ttl but
// past maxLifetime is dead to Validate, so the sweep drops it as well.
func TestSessionSweepHonoursTheCeiling(t *testing.T) {
	const n = 1000
	s := NewSessionStore(time.Hour, 10*time.Minute)
	t0 := time.Now()
	for range n {
		s.Create("user-1", t0)
	}
	for range n {
		s.Create("user-1", t0.Add(11*time.Minute))
	}
	if got := heldSessions(s); got != n {
		t.Errorf("%d sessions held after the first %d passed the ceiling, want the %d live ones", got, n, n)
	}
}

// A live session is never swept, however many times the sweep passes
// it, and a renewed one is judged by its renewed expiry.
func TestSessionSweepKeepsLiveSessions(t *testing.T) {
	s := NewSessionStore(time.Minute, 0)
	t0 := time.Now()
	kept := s.Create("user-1", t0)
	at := t0
	for range 1000 {
		at = at.Add(time.Second)
		if _, ok := s.Validate(kept.ID, at); !ok {
			t.Fatalf("live session rejected at %v", at.Sub(t0))
		}
		s.Create("user-2", at)
	}
	// The sweep trails the clock a little (see sweepBatch), so a few
	// user-2 sessions past their ttl may still be held -- but nothing
	// like the 1000 created, and the one kept alive by use is there.
	if got := heldSessions(s); got > 2*61 {
		t.Errorf("%d sessions held, want at most twice the 61 inside the last minute", got)
	}
	if _, ok := s.Validate(kept.ID, at); !ok {
		t.Error("the session kept alive by use was swept")
	}
}

// A revoked session leaves its ID in the sweep's queue; the sweep drops
// it without touching the map, and the queue does not grow without
// bound under login/logout churn.
func TestSessionSweepDropsRevokedIDs(t *testing.T) {
	s := NewSessionStore(time.Hour, 0)
	t0 := time.Now()
	for range 10000 {
		sess := s.Create("user-1", t0)
		s.Revoke(sess.ID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) != 0 || s.order.n > sweepBatch {
		t.Errorf("after 10000 login/logout pairs: %d sessions, %d queued IDs; want 0 and at most %d", len(s.sessions), s.order.n, sweepBatch)
	}
}

// TestSessionSweepWorkPerCreateIsBounded is the reason for the
// incremental sweep (#24): no single Create does more than a few
// entries' worth of sweeping, however large the store, so a big store
// cannot stall every other caller behind one login. The old sweep walked
// the whole map on the Create that doubled it -- 131072 entries in one
// call for this test -- and the count below makes that visible without
// timing anything.
func TestSessionSweepWorkPerCreateIsBounded(t *testing.T) {
	const n = 1 << 16
	s := NewSessionStore(time.Minute, 0)
	t0 := time.Now()
	for range n {
		s.Create("user-1", t0)
	}
	later := t0.Add(2 * time.Minute)
	most, total := 0, 0
	for range n {
		before := s.sweepVisits
		s.Create("user-1", later)
		visited := s.sweepVisits - before
		total += visited
		most = max(most, visited)
	}
	t.Logf("%d logins over %d expired sessions: at most %d entries checked in one Create, %d in all", n, n, most, total)
	if most > sweepBatch {
		t.Errorf("one Create checked %d entries, want at most %d", most, sweepBatch)
	}
	if got := heldSessions(s); got != n {
		t.Errorf("%d sessions held, want the %d live ones", got, n)
	}
}

// The sweep's queue keeps first-in, first-out order across its block
// boundaries, including when it empties and fills again.
func TestIDQueueIsFirstInFirstOut(t *testing.T) {
	var q idQueue
	pushed, popped := 0, 0
	for _, batch := range []int{1, idBlock - 1, idBlock, 3*idBlock + 7, 5} {
		for range batch {
			q.push(strconv.Itoa(pushed))
			pushed++
		}
		for {
			id, ok := q.pop()
			if !ok {
				break
			}
			if want := strconv.Itoa(popped); id != want {
				t.Fatalf("popped %q, want %q", id, want)
			}
			popped++
		}
	}
	if popped != pushed {
		t.Errorf("popped %d of %d pushed", popped, pushed)
	}
}

// BenchmarkSessionCreate reports, besides ns/op, the most entries one
// Create checked (max-visits/op): constant here, where the old sweep's
// was the whole map on every doubling.
func BenchmarkSessionCreate(b *testing.B) {
	s := NewSessionStore(time.Minute, 0)
	t0 := time.Now()
	for range 1 << 16 {
		s.Create("user-1", t0)
	}
	at := t0.Add(2 * time.Minute)
	most := 0
	b.ResetTimer()
	for b.Loop() {
		before := s.sweepVisits
		s.Create("user-1", at)
		most = max(most, s.sweepVisits-before)
	}
	b.ReportMetric(float64(most), "max-visits/op")
}
