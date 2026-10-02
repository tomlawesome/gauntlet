package gauntlet

import (
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// The store half of a person's own session list (gauntlet#48): what a
// session records about the browser that signed in, the one-way ref a
// list shows instead of the cookie, listing and ending by ref.

// What CreateFrom keeps of a client is bounded and printable whatever
// the browser sent: control and formatting characters and invalid
// UTF-8 are dropped, then each field is cut to its cap on a character
// boundary. Both reach a page and a log that show them.
func TestSessionCreateFromCleansAndCutsTheClient(t *testing.T) {
	s := NewSessionStore(time.Hour, 0)
	now := time.Now()

	cases := []struct {
		name          string
		in            SessionClient
		wantAgent     string
		wantAddress   string
		agentCapped   bool
		addressCapped bool
	}{
		{
			name:        "ordinary values are kept whole",
			in:          SessionClient{Address: "2001:db8::1", UserAgent: "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0"},
			wantAgent:   "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0",
			wantAddress: "2001:db8::1",
		},
		{
			name:        "control characters are dropped",
			in:          SessionClient{Address: "198.51.100.7\r\n", UserAgent: "Agent\x1b[31m\x00/1\x7f"},
			wantAgent:   "Agent[31m/1",
			wantAddress: "198.51.100.7",
		},
		{
			name:        "formatting characters are dropped",
			in:          SessionClient{UserAgent: "Agent\u202egnp.exe\u200b/1"},
			wantAgent:   "Agentgnp.exe/1",
			wantAddress: "",
		},
		{
			name:        "invalid UTF-8 is dropped",
			in:          SessionClient{Address: "198.51.\xff100.7", UserAgent: "A\xc3\x28gent"},
			wantAgent:   "A(gent",
			wantAddress: "198.51.100.7",
		},
		{
			name:          "long values are cut to their caps",
			in:            SessionClient{Address: strings.Repeat("a", 500), UserAgent: strings.Repeat("u", 5000)},
			wantAgent:     strings.Repeat("u", MaxSessionUserAgent),
			wantAddress:   strings.Repeat("a", MaxSessionAddress),
			agentCapped:   true,
			addressCapped: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess := s.CreateFrom("user-1", tc.in, now)
			if sess.Client.UserAgent != tc.wantAgent {
				t.Errorf("UserAgent = %q, want %q", sess.Client.UserAgent, tc.wantAgent)
			}
			if sess.Client.Address != tc.wantAddress {
				t.Errorf("Address = %q, want %q", sess.Client.Address, tc.wantAddress)
			}
			// What Validate hands back is what was stored, not only what
			// CreateFrom returned.
			got, ok := s.Validate(sess.ID, now)
			if !ok || got.Client != sess.Client {
				t.Errorf("stored client = %+v (ok %v), want %+v", got.Client, ok, sess.Client)
			}
		})
	}
}

// A multi-byte character that would straddle the cap is left out
// whole, never split into invalid UTF-8.
func TestSessionCreateFromNeverSplitsACharacter(t *testing.T) {
	s := NewSessionStore(time.Hour, 0)
	agent := strings.Repeat("u", MaxSessionUserAgent-1) + "é" // é is two bytes
	sess := s.CreateFrom("user-1", SessionClient{UserAgent: agent}, time.Now())
	if !utf8.ValidString(sess.Client.UserAgent) {
		t.Fatalf("cut agent is not valid UTF-8: %q", sess.Client.UserAgent)
	}
	if want := strings.Repeat("u", MaxSessionUserAgent-1); sess.Client.UserAgent != want {
		t.Errorf("cut agent is %d bytes, want the %d before the straddling character", len(sess.Client.UserAgent), len(want))
	}
}

// Create records no client, and is otherwise CreateFrom.
func TestSessionCreateRecordsNoClient(t *testing.T) {
	s := NewSessionStore(time.Hour, 0)
	now := time.Now()
	sess := s.Create("user-1", now)
	if sess.Client != (SessionClient{}) {
		t.Errorf("Create recorded client %+v, want none", sess.Client)
	}
	if !sess.LastUsedAt.Equal(now) {
		t.Errorf("LastUsedAt = %v, want IssuedAt %v until first use", sess.LastUsedAt, now)
	}
}

var sessionRefPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// The ref a list shows: 32 lowercase hex characters, the same every
// time for one session, different between sessions, and never the
// session ID (the cookie) or a piece of it.
func TestSessionRefIsStableOneWayAndNotTheID(t *testing.T) {
	s := NewSessionStore(time.Hour, 0)
	now := time.Now()
	a := s.Create("user-1", now)
	b := s.Create("user-1", now)

	if !sessionRefPattern.MatchString(a.Ref()) {
		t.Fatalf("Ref() = %q, want 32 lowercase hex characters", a.Ref())
	}
	if copied := (Session{ID: a.ID}); copied.Ref() != a.Ref() {
		t.Error("Ref() depends on more than the session ID")
	}
	got, _ := s.Validate(a.ID, now)
	if got.Ref() != a.Ref() {
		t.Error("Ref() changed after Validate renewed the session")
	}
	if a.Ref() == b.Ref() {
		t.Error("two sessions share a ref")
	}
	if a.Ref() == a.ID || strings.Contains(a.ID, a.Ref()) || strings.Contains(a.Ref(), a.ID) {
		t.Errorf("Ref() %q overlaps the session ID %q", a.Ref(), a.ID)
	}
}

// Validate moves LastUsedAt to the time of each use and leaves IssuedAt
// alone.
func TestSessionValidateMovesLastUsedAt(t *testing.T) {
	s := NewSessionStore(time.Hour, 0)
	t0 := time.Now()
	sess := s.Create("user-1", t0)

	t1 := t0.Add(10 * time.Minute)
	got, ok := s.Validate(sess.ID, t1)
	if !ok {
		t.Fatal("session did not validate")
	}
	if !got.LastUsedAt.Equal(t1) {
		t.Errorf("LastUsedAt = %v, want %v", got.LastUsedAt, t1)
	}
	if !got.IssuedAt.Equal(t0) {
		t.Errorf("IssuedAt moved to %v, want %v", got.IssuedAt, t0)
	}
	listed := s.ListForUser("user-1", t1)
	if len(listed) != 1 || !listed[0].LastUsedAt.Equal(t1) {
		t.Errorf("listed %+v, want one session last used at %v", listed, t1)
	}
}

// ListForUser lists only the account's own live sessions, newest
// first, and evicts the ones it finds dead (idle or past the ceiling)
// rather than listing them.
func TestSessionListForUserSkipsAndEvictsExpired(t *testing.T) {
	s := NewSessionStore(time.Hour, 3*time.Hour)
	t0 := time.Now()
	at := t0.Add(3*time.Hour + time.Minute)
	use := func(sess Session, d time.Duration) {
		t.Helper()
		if _, ok := s.Validate(sess.ID, t0.Add(d)); !ok {
			t.Fatalf("session refused at +%v", d)
		}
	}
	// old is kept in use throughout, so only the ceiling ends it; idle
	// is never used after signing in. Each use comes before the next
	// Create, whose sweep would otherwise evict old first.
	old := s.Create("user-1", t0)
	use(old, 50*time.Minute)
	idle := s.Create("user-1", t0.Add(time.Hour))
	use(old, 100*time.Minute)
	s.Create("user-2", t0.Add(2*time.Hour))
	use(old, 150*time.Minute)
	older := s.CreateFrom("user-1", SessionClient{Address: "198.51.100.1"}, at.Add(-30*time.Minute))
	newer := s.CreateFrom("user-1", SessionClient{Address: "198.51.100.2"}, at.Add(-10*time.Minute))

	got := s.ListForUser("user-1", at)
	if len(got) != 2 || got[0].ID != newer.ID || got[1].ID != older.ID {
		t.Fatalf("ListForUser = %+v, want [newer, older]", got)
	}
	if got[0].Client.Address != "198.51.100.2" {
		t.Errorf("listed client = %+v, want the recorded one", got[0].Client)
	}

	s.mu.Lock()
	_, oldHeld := s.sessions[old.ID]
	_, idleHeld := s.sessions[idle.ID]
	_, oldIndexed := s.byUser["user-1"][old.ID]
	s.mu.Unlock()
	if oldHeld || idleHeld || oldIndexed {
		t.Errorf("expired sessions still held after listing: past ceiling %v (indexed %v), idle %v", oldHeld, oldIndexed, idleHeld)
	}
	if got := s.ListForUser("nobody", at); len(got) != 0 {
		t.Errorf("an account with no sessions listed %d", len(got))
	}
}

// RevokeRef ends one session by its ref, and only within the account
// that asks: another account's ref, an unknown ref and the raw session
// ID all end nothing.
func TestSessionRevokeRefIsScopedToTheUser(t *testing.T) {
	s := NewSessionStore(time.Hour, 0)
	now := time.Now()
	mine := s.Create("user-1", now)
	keep := s.Create("user-1", now)
	theirs := s.Create("user-2", now)

	for _, ref := range []string{theirs.Ref(), "", "not-a-ref", strings.Repeat("0", 32), mine.ID} {
		if _, ok := s.RevokeRef("user-1", ref); ok {
			t.Errorf("RevokeRef(user-1, %q) reported ending a session", ref)
		}
	}
	for _, sess := range []Session{mine, keep, theirs} {
		if _, ok := s.Validate(sess.ID, now); !ok {
			t.Fatalf("session of %s ended by a refused RevokeRef", sess.UserID)
		}
	}

	ended, ok := s.RevokeRef("user-1", mine.Ref())
	if !ok || ended.ID != mine.ID {
		t.Fatalf("RevokeRef(user-1, own ref) = %+v, %v; want that session", ended, ok)
	}
	if _, ok := s.Validate(mine.ID, now); ok {
		t.Error("the session RevokeRef ended still validates")
	}
	if _, ok := s.Validate(keep.ID, now); !ok {
		t.Error("RevokeRef ended the account's other session too")
	}
	if _, ok := s.RevokeRef("user-1", mine.Ref()); ok {
		t.Error("a second RevokeRef of the same ref reported ending it again")
	}
}
