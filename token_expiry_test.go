package gauntlet

import (
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// Token expiry, the gnt_ prefix and Sweep (#74).

func TestTokenCreateDefaultsToAYearAndStartsWithThePrefix(t *testing.T) {
	s := newTestTokenStore(t)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

	raw, tok, err := s.Create("birdcage", TokenKindAPI, "", nil, now)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !strings.HasPrefix(raw, "gnt_") {
		t.Errorf("raw value %q does not start with gnt_", raw)
	}
	if want := now.Add(365 * 24 * time.Hour); !tok.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", tok.ExpiresAt, want)
	}
	if _, ok := s.Authenticate(raw, TokenKindAPI, now); !ok {
		t.Error("the new prefixed token does not authenticate")
	}
}

func TestTokenCreateWithExpiryNeverAndExplicit(t *testing.T) {
	s := newTestTokenStore(t)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

	rawNever, never, err := s.CreateWithExpiry("router", TokenKindIngest, "r1", nil, now, time.Time{})
	if err != nil {
		t.Fatalf("never: %v", err)
	}
	if !never.ExpiresAt.IsZero() {
		t.Errorf("a zero expiry stored as %v", never.ExpiresAt)
	}
	if _, ok := s.Authenticate(rawNever, TokenKindIngest, now.AddDate(20, 0, 0)); !ok {
		t.Error("a never-expiring token stopped authenticating")
	}

	at := now.Add(30 * 24 * time.Hour)
	_, dated, err := s.CreateWithExpiry("month", TokenKindAPI, "", nil, now, at)
	if err != nil {
		t.Fatalf("dated: %v", err)
	}
	if !dated.ExpiresAt.Equal(at) {
		t.Errorf("ExpiresAt = %v, want %v", dated.ExpiresAt, at)
	}
}

func TestTokenCreateWithExpiryRefusesNowOrEarlier(t *testing.T) {
	s := newTestTokenStore(t)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for _, at := range []time.Time{now, now.Add(-time.Second)} {
		if _, _, err := s.CreateWithExpiry("x", TokenKindAPI, "", nil, now, at); err != ErrTokenExpiryInvalid {
			t.Errorf("expiry %v: err = %v, want ErrTokenExpiryInvalid", at, err)
		}
	}
	if len(s.List()) != 0 {
		t.Error("a refused token was stored")
	}
}

func TestAuthenticateRefusesAnExpiredTokenLikeAnUnknownOne(t *testing.T) {
	s := newTestTokenStore(t)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	at := now.Add(time.Hour)
	raw, tok, err := s.CreateWithExpiry("short", TokenKindAPI, "", nil, now, at)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := s.Authenticate(raw, TokenKindAPI, at.Add(-time.Second)); !ok {
		t.Fatal("refused before its expiry")
	}
	for _, when := range []time.Time{at, at.Add(time.Hour)} {
		got, ok := s.Authenticate(raw, TokenKindAPI, when)
		if ok || got != nil {
			t.Errorf("at %v: (%v, %v), want (nil, false) -- the same answer as an unknown token", when, got, ok)
		}
	}
	// The refused attempts left LastUsedAt where the last good use put it.
	for _, l := range s.List() {
		if l.ID == tok.ID && !l.LastUsedAt.Equal(at.Add(-time.Second)) {
			t.Errorf("LastUsedAt = %v, want the last accepted use", l.LastUsedAt)
		}
	}
}

// A token minted before #74 had no prefix and no expiry: it is a bare
// value whose hash is stored, and must go on authenticating.
func TestAnUnprefixedTokenStillAuthenticates(t *testing.T) {
	s := newTestTokenStore(t)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	const old = "0123456789abcdef0123456789abcdef" // obviously fake, v0.2.0's 128-bit hex shape
	err := s.mutate(func(st *tokenState) error {
		tok := &Token{ID: "old", Name: "old", Kind: TokenKindAPI, HashedValue: hashTokenValue(old), CreatedAt: now.AddDate(-1, 0, 0)}
		st.byID[tok.ID] = tok
		st.byHash[tok.HashedValue] = tok.ID
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Authenticate(old, TokenKindAPI, now.AddDate(5, 0, 0)); !ok {
		t.Error("an unprefixed, never-expiring token no longer authenticates")
	}
	if _, ok := s.Authenticate("gnt_"+old, TokenKindAPI, now); ok {
		t.Error("adding the prefix to an old value authenticated it")
	}
}

func TestExpiryAndWarningSurviveAReopen(t *testing.T) {
	m := persist.NewMemory()
	s, _ := OpenTokenStore(m, TokenOptions{})
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	at := now.Add(3 * 24 * time.Hour)
	if _, _, err := s.CreateWithExpiry("soon", TokenKindAPI, "", nil, now, at); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sweep(now); err != nil {
		t.Fatal(err)
	}
	s2, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	l := s2.List()
	if len(l) != 1 || !l[0].ExpiresAt.Equal(at) || !l[0].ExpiryWarnedAt.Equal(now) {
		t.Errorf("reopened = %+v, want expiry %v and warning %v", l, at, now)
	}
}

func TestSweepRemovesOnlyTheUnused(t *testing.T) {
	s := newTestTokenStore(t)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	year := 365 * 24 * time.Hour

	create := func(name string, created time.Time) (string, string) {
		raw, tok, err := s.CreateWithExpiry(name, TokenKindAPI, "", nil, created, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		return raw, tok.ID
	}
	_, neverUsedOld := create("never-used-old", now.Add(-year-time.Hour))
	_, neverUsedNew := create("never-used-new", now.Add(-year+time.Hour))
	rawLapsed, lapsed := create("lapsed", now.Add(-3*year))
	rawRecent, recent := create("recent", now.Add(-3*year))
	if _, ok := s.Authenticate(rawLapsed, TokenKindAPI, now.Add(-year-time.Hour)); !ok {
		t.Fatal("setup: use of lapsed")
	}
	if _, ok := s.Authenticate(rawRecent, TokenKindAPI, now.Add(-time.Hour)); !ok {
		t.Fatal("setup: use of recent")
	}

	res, err := s.Sweep(now)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(res.Removed) != 2 || len(res.Expiring) != 0 {
		t.Fatalf("result = %+v, want 2 removed", res)
	}
	for _, r := range res.Removed {
		if r.HashedValue != "" {
			t.Error("a removed token's hash was handed back")
		}
	}
	present := map[string]bool{}
	for _, l := range s.List() {
		present[l.ID] = true
	}
	for id, want := range map[string]bool{neverUsedOld: false, lapsed: false, neverUsedNew: true, recent: true} {
		if present[id] != want {
			t.Errorf("token %s present = %v, want %v", id, present[id], want)
		}
	}
	// A removed token is gone for good, not merely hidden.
	if _, ok := s.Authenticate(rawLapsed, TokenKindAPI, now); ok {
		t.Error("a removed token still authenticates")
	}
	// Nothing left to do: an empty result, not an error.
	if res, err := s.Sweep(now); err != nil || len(res.Removed)+len(res.Expiring) != 0 {
		t.Errorf("second sweep = %+v, %v", res, err)
	}
}

func TestSweepWarnsOncePerToken(t *testing.T) {
	s := newTestTokenStore(t)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	week := 7 * 24 * time.Hour

	mk := func(name string, expires time.Time) {
		if _, _, err := s.CreateWithExpiry(name, TokenKindAPI, "", nil, now.Add(-time.Hour), expires); err != nil {
			t.Fatal(err)
		}
	}
	mk("edge", now.Add(week))      // exactly seven days: inside the window
	mk("soon", now.Add(time.Hour)) // expires in an hour
	mk("beyond", now.Add(week+time.Second))
	mk("never", time.Time{})

	res, err := s.Sweep(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Expiring) != 2 {
		t.Fatalf("expiring = %+v, want edge and soon", res.Expiring)
	}
	for _, e := range res.Expiring {
		if e.Name != "edge" && e.Name != "soon" {
			t.Errorf("warned about %q", e.Name)
		}
	}
	res, err = s.Sweep(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Expiring) != 0 {
		t.Errorf("second sweep warned again: %+v", res.Expiring)
	}
	// "beyond" comes inside the window a day later and is warned then.
	res, err = s.Sweep(now.Add(24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Expiring) != 1 || res.Expiring[0].Name != "beyond" {
		t.Errorf("a day later = %+v, want just beyond", res.Expiring)
	}
}

func TestSweepOfAnUnpersistedStoreDoesNothing(t *testing.T) {
	s, _ := OpenTokenStore(nil, TokenOptions{})
	res, err := s.Sweep(time.Now())
	if err != nil || len(res.Removed)+len(res.Expiring) != 0 {
		t.Errorf("Sweep = %+v, %v", res, err)
	}
}

func TestRemoveOrphansTakesOnlyTokensOfMissingAccounts(t *testing.T) {
	s := newTestTokenStore(t)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	alice := &User{ID: "user-alice", Username: "alice"}
	bob := &User{ID: "user-bob", Username: "bob"}
	aliceRaw, aliceTok, err := s.Create("alice-integration", TokenKindAPI, "", alice, now)
	if err != nil {
		t.Fatal(err)
	}
	bobRaw, _, err := s.Create("bob-integration", TokenKindAPI, "", bob, now)
	if err != nil {
		t.Fatal(err)
	}
	// Unattributed: it cannot be tied to any account, so is never an orphan.
	oldRaw, _, err := s.Create("pre-upgrade", TokenKindAPI, "", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	exists := func(id string) bool { return id == bob.ID }

	gone, err := s.RemoveOrphans(exists, now)
	if err != nil {
		t.Fatalf("RemoveOrphans: %v", err)
	}
	if len(gone) != 1 || gone[0].ID != aliceTok.ID || gone[0].CreatedByUsername != "alice" || gone[0].HashedValue != "" {
		t.Fatalf("removed = %+v, want alice's token with its hash blanked", gone)
	}
	if _, ok := s.Authenticate(aliceRaw, TokenKindAPI, now); ok {
		t.Error("the orphaned token still authenticates")
	}
	for name, raw := range map[string]string{"bob's": bobRaw, "the unattributed": oldRaw} {
		if _, ok := s.Authenticate(raw, TokenKindAPI, now); !ok {
			t.Errorf("%s token was removed", name)
		}
	}
	// Nothing left to do: no write, nothing returned.
	if gone, err := s.RemoveOrphans(exists, now); err != nil || gone != nil {
		t.Errorf("second RemoveOrphans = %+v, %v", gone, err)
	}
}
