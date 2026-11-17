// Tests for SessionStore.Peek and TokenStore.Peek (#104, ADR-0016),
// written from the ADR before the code: the read-only checks beside
// Validate and Authenticate. Each refusal is paired with the same
// fixture accepted before the condition, so no refusal here can pass
// against a Peek that refuses everything.
package gauntlet

import (
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// peekEpoch is a fixed clock start, advanced by hand.
var peekEpoch = time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)

// sessionFor finds id in s.ListForUser -- a read that slides nothing,
// for checking what Peek left behind.
func sessionFor(t *testing.T, s *SessionStore, userID, id string, now time.Time) Session {
	t.Helper()
	for _, sess := range s.ListForUser(userID, now) {
		if sess.ID == id {
			return sess
		}
	}
	t.Fatalf("session %s not listed for %s at %v", id, userID, now)
	return Session{}
}

func TestSessionPeekReturnsTheSessionAsCreated(t *testing.T) {
	s := NewSessionStore(10*time.Second, time.Minute)
	created := s.Create("user-1", peekEpoch)

	got, ok := s.Peek(created.ID, peekEpoch.Add(time.Second))
	if !ok {
		t.Fatal("Peek refused a fresh session")
	}
	if got.ID != created.ID || got.UserID != "user-1" {
		t.Errorf("Peek = %+v, want the session Create returned (%s, user-1)", got, created.ID)
	}
	if !got.IssuedAt.Equal(created.IssuedAt) || !got.ExpiresAt.Equal(created.ExpiresAt) || !got.LastUsedAt.Equal(created.LastUsedAt) {
		t.Errorf("Peek: IssuedAt %v ExpiresAt %v LastUsedAt %v; want as Create set them: %v %v %v",
			got.IssuedAt, got.ExpiresAt, got.LastUsedAt, created.IssuedAt, created.ExpiresAt, created.LastUsedAt)
	}
}

// Peeked every 2s for 30s with idle=10s, a session idles out exactly as
// an untouched one would: the checks are not activity (NIST SP 800-63B
// §7.2). It is then timed out for Validate too, and still resumable.
func TestSessionPeekDoesNotKeepASessionAwake(t *testing.T) {
	const idle = 10 * time.Second
	s := NewSessionStore(idle, time.Hour)
	sess := s.Create("user-1", peekEpoch)
	deadline := sess.IssuedAt.Add(idle)

	sawLive, sawDead := false, false
	for d := 2 * time.Second; d <= 30*time.Second; d += 2 * time.Second {
		now := peekEpoch.Add(d)
		_, ok := s.Peek(sess.ID, now)
		switch {
		case now.Before(deadline):
			sawLive = true
			if !ok {
				t.Fatalf("Peek at +%v refused a session idle for less than %v", d, idle)
			}
		case now.After(deadline):
			sawDead = true
			if ok {
				t.Fatalf("Peek at +%v accepted a session idle past %v: the peeks kept it awake", d, idle)
			}
		}
	}
	if !sawLive || !sawDead {
		t.Fatal("the loop did not cover both sides of the idle deadline")
	}

	end := peekEpoch.Add(30 * time.Second)
	if _, ok := s.Resumable(sess.ID, end); !ok {
		t.Error("a session that idled out under Peek is not resumable inside its ceiling")
	}
	if _, ok := s.Validate(sess.ID, end); ok {
		t.Error("Validate accepted a session the peeks should have let idle out")
	}
}

// Many peeks leave ExpiresAt and LastUsedAt where Create put them; a
// Validate afterwards still slides them, so the read-back can see a move.
func TestSessionPeekChangesNothing(t *testing.T) {
	s := NewSessionStore(10*time.Second, time.Hour)
	sess := s.Create("user-1", peekEpoch)

	for d := time.Second; d < 10*time.Second; d += time.Second {
		if _, ok := s.Peek(sess.ID, peekEpoch.Add(d)); !ok {
			t.Fatalf("Peek at +%v refused a live session", d)
		}
	}
	at := peekEpoch.Add(9 * time.Second)
	listed := sessionFor(t, s, "user-1", sess.ID, at)
	if !listed.ExpiresAt.Equal(sess.ExpiresAt) || !listed.LastUsedAt.Equal(sess.LastUsedAt) {
		t.Errorf("after peeks ListForUser shows ExpiresAt %v LastUsedAt %v, want unchanged %v %v",
			listed.ExpiresAt, listed.LastUsedAt, sess.ExpiresAt, sess.LastUsedAt)
	}
	peeked, ok := s.Peek(sess.ID, at)
	if !ok || !peeked.ExpiresAt.Equal(sess.ExpiresAt) || !peeked.LastUsedAt.Equal(sess.LastUsedAt) {
		t.Errorf("after peeks Peek shows (%v) ExpiresAt %v LastUsedAt %v, want unchanged %v %v",
			ok, peeked.ExpiresAt, peeked.LastUsedAt, sess.ExpiresAt, sess.LastUsedAt)
	}

	if _, ok := s.Validate(sess.ID, at); !ok {
		t.Fatal("Validate refused a live session")
	}
	slid, ok := s.Peek(sess.ID, at)
	if !ok {
		t.Fatal("Peek refused the session Validate just renewed")
	}
	if !slid.ExpiresAt.After(sess.ExpiresAt) || !slid.LastUsedAt.Equal(at) {
		t.Errorf("after Validate at %v: ExpiresAt %v LastUsedAt %v, want slid past %v and last used at %v",
			at, slid.ExpiresAt, slid.LastUsedAt, sess.ExpiresAt, at)
	}
	// Past the original expiry, inside the renewed one: only Validate's
	// slide can be keeping it alive.
	if _, ok := s.Peek(sess.ID, sess.ExpiresAt.Add(time.Second)); !ok {
		t.Error("Peek refused a session Validate had renewed")
	}
}

func TestSessionPeekRefuses(t *testing.T) {
	t.Run("unknown id", func(t *testing.T) {
		s := NewSessionStore(10*time.Second, time.Minute)
		live := s.Create("user-1", peekEpoch)
		if _, ok := s.Peek(live.ID, peekEpoch); !ok {
			t.Fatal("control: Peek refused a live session")
		}
		if _, ok := s.Peek("does-not-exist", peekEpoch); ok {
			t.Error("Peek accepted an unknown id")
		}
		if _, ok := s.Peek("", peekEpoch); ok {
			t.Error("Peek accepted an empty id")
		}
	})
	t.Run("revoked", func(t *testing.T) {
		s := NewSessionStore(10*time.Second, time.Minute)
		sess := s.Create("user-1", peekEpoch)
		if _, ok := s.Peek(sess.ID, peekEpoch.Add(time.Second)); !ok {
			t.Fatal("Peek refused the session before the revoke")
		}
		s.Revoke(sess.ID)
		if _, ok := s.Peek(sess.ID, peekEpoch.Add(2*time.Second)); ok {
			t.Error("Peek accepted a revoked session")
		}
	})
	t.Run("past the ceiling though used a moment ago", func(t *testing.T) {
		const ceiling = 30 * time.Second
		s := NewSessionStore(10*time.Second, ceiling)
		sess := s.Create("user-1", peekEpoch)
		for d := 5 * time.Second; d < ceiling; d += 5 * time.Second {
			if _, ok := s.Validate(sess.ID, peekEpoch.Add(d)); !ok {
				t.Fatalf("setup: Validate at +%v refused a session in use", d)
			}
		}
		lastUse := peekEpoch.Add(ceiling - time.Second)
		if _, ok := s.Validate(sess.ID, lastUse); !ok {
			t.Fatal("setup: Validate refused a session a second inside its ceiling")
		}
		if _, ok := s.Peek(sess.ID, lastUse); !ok {
			t.Fatal("Peek refused a session a second inside its ceiling")
		}
		if _, ok := s.Peek(sess.ID, peekEpoch.Add(ceiling+time.Second)); ok {
			t.Error("Peek accepted a session past its lifetime ceiling")
		}
	})
	t.Run("idle past idle with no ceiling", func(t *testing.T) {
		s := NewSessionStore(10*time.Second, 0)
		sess := s.Create("user-1", peekEpoch)
		if _, ok := s.Peek(sess.ID, peekEpoch.Add(9*time.Second)); !ok {
			t.Fatal("Peek refused a session idle for less than idle")
		}
		if _, ok := s.Peek(sess.ID, peekEpoch.Add(11*time.Second)); ok {
			t.Error("Peek accepted a session idle past idle in a store with no ceiling")
		}
	})
}

// Peek and Validate agree, state by state, at the same instant. Peek is
// asked first in every row: Validate is the one that changes things.
func TestSessionPeekAgreesWithValidate(t *testing.T) {
	const idle, ceiling = 10 * time.Second, 30 * time.Second
	cases := []struct {
		name string
		want bool
		at   func(t *testing.T) (*SessionStore, string, time.Time)
	}{
		{"live", true, func(t *testing.T) (*SessionStore, string, time.Time) {
			s := NewSessionStore(idle, ceiling)
			return s, s.Create("u", peekEpoch).ID, peekEpoch.Add(5 * time.Second)
		}},
		{"unknown", false, func(t *testing.T) (*SessionStore, string, time.Time) {
			s := NewSessionStore(idle, ceiling)
			s.Create("u", peekEpoch)
			return s, "does-not-exist", peekEpoch.Add(time.Second)
		}},
		{"revoked", false, func(t *testing.T) (*SessionStore, string, time.Time) {
			s := NewSessionStore(idle, ceiling)
			id := s.Create("u", peekEpoch).ID
			s.Revoke(id)
			return s, id, peekEpoch.Add(time.Second)
		}},
		{"idle, resumable", false, func(t *testing.T) (*SessionStore, string, time.Time) {
			s := NewSessionStore(idle, ceiling)
			return s, s.Create("u", peekEpoch).ID, peekEpoch.Add(idle + 5*time.Second)
		}},
		{"idle, no ceiling", false, func(t *testing.T) (*SessionStore, string, time.Time) {
			s := NewSessionStore(idle, 0)
			return s, s.Create("u", peekEpoch).ID, peekEpoch.Add(idle + 5*time.Second)
		}},
		{"past the ceiling", false, func(t *testing.T) (*SessionStore, string, time.Time) {
			s := NewSessionStore(idle, ceiling)
			id := s.Create("u", peekEpoch).ID
			for d := 5 * time.Second; d < ceiling; d += 5 * time.Second {
				if _, ok := s.Validate(id, peekEpoch.Add(d)); !ok {
					t.Fatalf("setup: Validate at +%v refused", d)
				}
			}
			return s, id, peekEpoch.Add(ceiling + time.Second)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, id, now := c.at(t)
			_, peeked := s.Peek(id, now)
			_, validated := s.Validate(id, now)
			if peeked != validated || peeked != c.want {
				t.Errorf("Peek = %v, Validate = %v at the same instant; want both %v", peeked, validated, c.want)
			}
		})
	}
}

func TestTokenPeekAcceptsOnlyALiveTokenOfItsKind(t *testing.T) {
	now := peekEpoch

	t.Run("live, and wrong kind", func(t *testing.T) {
		s := newTestTokenStore(t)
		raw, tok, err := s.Create("birdcage", TokenKindAPI, "", nil, now)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := s.Peek(raw, TokenKindAPI, now.Add(time.Minute))
		if !ok || got == nil || got.ID != tok.ID {
			t.Fatalf("Peek of a live API token = (%v, %v), want that token", got, ok)
		}
		if got, ok := s.Peek(raw, TokenKindIngest, now.Add(time.Minute)); ok || got != nil {
			t.Errorf("Peek as the wrong kind = (%v, %v), want (nil, false)", got, ok)
		}
	})
	t.Run("expired", func(t *testing.T) {
		s := newTestTokenStore(t)
		at := now.Add(time.Hour)
		raw, _, err := s.CreateWithExpiry("short", TokenKindAPI, "", nil, now, at)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := s.Peek(raw, TokenKindAPI, at.Add(-time.Second)); !ok {
			t.Fatal("Peek refused a token before its expiry")
		}
		if _, ok := s.Peek(raw, TokenKindAPI, at.Add(time.Second)); ok {
			t.Error("Peek accepted an expired token")
		}
	})
	t.Run("revoked", func(t *testing.T) {
		s := newTestTokenStore(t)
		raw, tok, err := s.Create("birdcage", TokenKindAPI, "", nil, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := s.Peek(raw, TokenKindAPI, now); !ok {
			t.Fatal("Peek refused the token before the revoke")
		}
		if err := s.Revoke(tok.ID); err != nil {
			t.Fatal(err)
		}
		if _, ok := s.Peek(raw, TokenKindAPI, now); ok {
			t.Error("Peek accepted a revoked token")
		}
	})
	t.Run("unknown and empty values", func(t *testing.T) {
		s := newTestTokenStore(t)
		raw, _, err := s.Create("birdcage", TokenKindAPI, "", nil, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := s.Peek(raw, TokenKindAPI, now); !ok {
			t.Fatal("control: Peek refused a live token")
		}
		for _, v := range []string{"not-a-real-token", raw + "x", ""} {
			if got, ok := s.Peek(v, TokenKindAPI, now); ok || got != nil {
				t.Errorf("Peek(%q) = (%v, %v), want (nil, false)", v, got, ok)
			}
		}
	})
	t.Run("kind not registered with this store", func(t *testing.T) {
		m := persist.NewMemory()
		withKind, err := OpenTokenStore(m, TokenOptions{Kinds: []TokenKind{TokenKindAPI, testKindOther}})
		if err != nil {
			t.Fatal(err)
		}
		raw, _, err := withKind.Create("puller", testKindOther, "", nil, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := withKind.Peek(raw, testKindOther, now); !ok {
			t.Fatal("Peek refused a token of a kind its store registers")
		}
		without, err := OpenTokenStore(m, TokenOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := without.Peek(raw, testKindOther, now); ok {
			t.Error("Peek accepted a token whose kind this store does not register")
		}
	})
	t.Run("unpersisted store", func(t *testing.T) {
		persisted := newTestTokenStore(t)
		raw, _, err := persisted.Create("birdcage", TokenKindAPI, "", nil, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := persisted.Peek(raw, TokenKindAPI, now); !ok {
			t.Fatal("control: Peek refused a live token on a persisted store")
		}
		s, err := OpenTokenStore(nil, TokenOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := s.Peek(raw, TokenKindAPI, now); ok || got != nil {
			t.Errorf("Peek on an unpersisted store = (%v, %v), want (nil, false)", got, ok)
		}
	})
}

// The token Peek returns is a copy, as Authenticate's is: changing it
// changes nothing in the store.
func TestTokenPeekReturnsACopy(t *testing.T) {
	s := newTestTokenStore(t)
	raw, tok, err := s.Create("birdcage", TokenKindAPI, "", nil, peekEpoch)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s.Peek(raw, TokenKindAPI, peekEpoch)
	if !ok {
		t.Fatal("Peek refused a live token")
	}
	got.Name = "changed"
	got.ExpiresAt = time.Time{}
	for _, l := range s.List() {
		if l.ID == tok.ID && (l.Name != "birdcage" || !l.ExpiresAt.Equal(tok.ExpiresAt)) {
			t.Errorf("listed token = %+v after editing Peek's result; want the store untouched", l)
		}
	}
}

// Peek records no use: LastUsedAt stays where it was and nothing is
// saved, across more than the hour after which Authenticate writes.
// Authenticate afterwards still records one, so the counter and the
// list can both see a use.
func TestTokenPeekRecordsNoUse(t *testing.T) {
	b := &countingBackend{Memory: persist.NewMemory()}
	s, err := OpenTokenStore(b, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	raw, tok, err := s.Create("poller", TokenKindAPI, "", nil, peekEpoch)
	if err != nil {
		t.Fatal(err)
	}
	lastUsed := func() time.Time {
		for _, l := range s.List() {
			if l.ID == tok.ID {
				return l.LastUsedAt
			}
		}
		t.Fatal("token not listed")
		return time.Time{}
	}
	before := lastUsed()
	saves := b.saves.Load()

	for d := time.Minute; d <= 3*time.Hour; d += 10 * time.Minute {
		if _, ok := s.Peek(raw, TokenKindAPI, peekEpoch.Add(d)); !ok {
			t.Fatalf("Peek at +%v refused a live token", d)
		}
	}
	if got := lastUsed(); !got.Equal(before) {
		t.Errorf("LastUsedAt = %v after peeks, want unchanged %v", got, before)
	}
	if got := b.saves.Load(); got != saves {
		t.Errorf("peeks made %d saves, want none", got-saves)
	}

	use := peekEpoch.Add(3*time.Hour + time.Minute)
	if _, ok := s.Authenticate(raw, TokenKindAPI, use); !ok {
		t.Fatal("Authenticate refused a live token")
	}
	if got := lastUsed(); !got.Equal(use) {
		t.Errorf("LastUsedAt = %v after Authenticate, want %v", got, use)
	}
	if b.saves.Load() == saves {
		t.Error("Authenticate's first recorded use made no save; the counter cannot tell")
	}
}

// A revoke made through another store on the same backend -- the CLI,
// beside the running server -- ends the token for this store's Peek:
// it reloads a stale document first, as Authenticate does.
func TestTokenPeekSeesARevokeFromAnotherStore(t *testing.T) {
	m := persist.NewMemory()
	server, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	raw, tok, err := server.Create("birdcage", TokenKindAPI, "", nil, peekEpoch)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := server.Peek(raw, TokenKindAPI, peekEpoch); !ok {
		t.Fatal("Peek refused the token before the revoke")
	}
	if err := cli.Revoke(tok.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := server.Peek(raw, TokenKindAPI, peekEpoch.Add(time.Second)); ok {
		t.Error("Peek accepted a token revoked through another store on the same backend")
	}
}
