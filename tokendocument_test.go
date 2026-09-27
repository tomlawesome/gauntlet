package gauntlet

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// TestMikroviewTokensJSONFixtureRoundTripsByteIdentical is gauntlet
// issue #4's done-when: a mikroview-shaped tokens document containing an
// "api" row, an "ingest" row and a "droplist-pull" row (mikroview's own
// third kind, #1224) loads, saves and reloads byte-identical, and only
// registered kinds authenticate.
//
// The fixture is built from gauntlet's own Token type -- field-for-
// field, JSON tag-for-tag, from mikroview's internal/auth/token.go
// (docs/design.md §1.3) -- and every raw value below is invented for
// this test, never a real credential. hashTokenValue is this package's
// own SHA-256 helper (token.go), the same one Create and Authenticate
// use, so the fixture's HashedValue fields are exactly what a real
// TokenStore would have written for these (fake) raw values.
func TestMikroviewTokensJSONFixtureRoundTripsByteIdentical(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	const (
		rawAPI      = "fixture-api-raw-token-does-not-exist"
		rawIngest   = "fixture-ingest-raw-token-does-not-exist"
		rawDroplist = "fixture-droplist-pull-raw-token-does-not-exist"
	)
	const droplistPull TokenKind = "droplist-pull"

	// Already in the CreatedAt-ascending order tryPersistLocked writes,
	// so a correct load-then-save is a no-op on the bytes.
	fixture := []*Token{
		{
			ID:          "token-id-0001",
			Name:        "birdcage",
			Kind:        TokenKindAPI,
			HashedValue: hashTokenValue(rawAPI),
			CreatedAt:   now,
		},
		{
			ID:          "token-id-0002",
			Name:        "router-1",
			Kind:        TokenKindIngest,
			Device:      "router-1",
			HashedValue: hashTokenValue(rawIngest),
			CreatedAt:   now.Add(time.Minute),
			LastUsedAt:  now.Add(2 * time.Hour),
			CreatedBy:   "user-admin",
		},
		{
			// mikroview's third kind: not one of gauntlet's default
			// Kinds, and already present in a real tokens document by
			// the time mikroview would move onto this module (#1224) --
			// this row is what proves the move drops nothing.
			ID:          "token-id-0003",
			Name:        "droplist-pull",
			Kind:        droplistPull,
			HashedValue: hashTokenValue(rawDroplist),
			CreatedAt:   now.Add(2 * time.Minute),
		},
	}

	original, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshalling fixture: %v", err)
	}

	m := persist.NewMemory()
	primeMemory(t, m, string(original))

	// Load with the default Kinds (api, ingest): the droplist-pull row
	// must be kept -- listed, not silently dropped -- but must never
	// authenticate.
	s1, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatalf("OpenTokenStore (load, default kinds): %v", err)
	}
	if got := len(s1.List()); got != len(fixture) {
		t.Fatalf("List() = %d tokens, want %d -- an unregistered kind must not be dropped", got, len(fixture))
	}

	// Save before any Authenticate call: Authenticate records
	// LastUsedAt (token.go), so exercising it here first would make the
	// round-trip compare a document this test itself had already
	// changed rather than the original fixture. This is also what
	// proves the unregistered row survives a save rather than being
	// pruned from the document.
	s1.mu.Lock()
	saveErr := s1.tryPersistLocked()
	s1.mu.Unlock()
	if saveErr != nil {
		t.Fatalf("tryPersistLocked: %v", saveErr)
	}

	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatalf("Load after save: %v", err)
	}
	if !bytes.Equal(snap.Payload, original) {
		t.Errorf("saved document differs from the original fixture:\n--- original ---\n%s\n--- saved ---\n%s",
			original, snap.Payload)
	}

	// Now exercise authentication on s1: the droplist-pull row must
	// never authenticate with the default Kinds, and the two registered
	// rows must still work.
	if _, ok := s1.Authenticate(rawDroplist, droplistPull, now); ok {
		t.Error("the droplist-pull row authenticated with the default Kinds, which do not register it")
	}
	if _, ok := s1.Authenticate(rawAPI, TokenKindAPI, now); !ok {
		t.Error("the api row failed to authenticate")
	}
	if _, ok := s1.Authenticate(rawIngest, TokenKindIngest, now); !ok {
		t.Error("the ingest row failed to authenticate")
	}

	// Reload with the default kinds again: still there, still refusing
	// to authenticate.
	s2, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatalf("OpenTokenStore (reload, default kinds): %v", err)
	}
	if got := len(s2.List()); got != len(fixture) {
		t.Fatalf("reloaded List() = %d tokens, want %d", got, len(fixture))
	}
	if _, ok := s2.Authenticate(rawDroplist, droplistPull, now); ok {
		t.Error("the droplist-pull row authenticated after a reload with the default Kinds")
	}

	// A store opened with Kinds naming the third kind -- what mikroview
	// declares as TokenKindDroplistPull and passes in Kinds
	// (docs/design.md §1.3) -- authenticates it.
	s3, err := OpenTokenStore(m, TokenOptions{Kinds: []TokenKind{TokenKindAPI, TokenKindIngest, droplistPull}})
	if err != nil {
		t.Fatalf("OpenTokenStore (reload, extended kinds): %v", err)
	}
	got, ok := s3.Authenticate(rawDroplist, droplistPull, now)
	if !ok {
		t.Fatal("the droplist-pull row did not authenticate once its kind was registered")
	}
	if got.ID != "token-id-0003" {
		t.Errorf("Authenticate returned %q, want %q", got.ID, "token-id-0003")
	}
}

// TestAnUnknownKindNeverAuthenticatesRegardlessOfWant covers the
// fail-closed list item in docs/design.md §4: a token kind this build
// has never heard of -- not in the default Kinds, and not added by any
// caller -- must not authenticate no matter what kind the caller asks
// for.
func TestAnUnknownKindNeverAuthenticatesRegardlessOfWant(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	const rawMystery = "fixture-mystery-raw-token-does-not-exist"
	const mystery TokenKind = "mystery-kind-nobody-registered"

	fixture := []*Token{{
		ID:          "token-id-mystery",
		Name:        "from-a-future-build",
		Kind:        mystery,
		HashedValue: hashTokenValue(rawMystery),
		CreatedAt:   now,
	}}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshalling fixture: %v", err)
	}

	m := persist.NewMemory()
	primeMemory(t, m, string(data))

	s, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}
	for _, want := range []TokenKind{TokenKindAPI, TokenKindIngest, mystery, TokenKind("anything-else")} {
		if _, ok := s.Authenticate(rawMystery, want, now); ok {
			t.Errorf("a token of unknown kind %q authenticated when want=%q", mystery, want)
		}
	}
	if len(s.List()) != 1 {
		t.Errorf("List() = %d, want 1 -- the unknown-kind row must still be listed and revocable", len(s.List()))
	}
}
