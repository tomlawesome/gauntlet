// Ported from mikroview's internal/auth/session_test.go, adapted to the
// one NewSessionStore(ttl, maxLifetime) constructor (session.go):
// mikroview's NewSessionStore(ttl) becomes NewSessionStore(ttl, 0) and
// NewSessionStoreWithMaxLifetime(ttl, max) becomes NewSessionStore(ttl,
// max). Otherwise unchanged, including the maxLifetime-ceiling cases.
package gauntlet

import (
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
