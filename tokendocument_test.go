package gauntlet

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// tokensFixture is a version-1 tokens document, written out by hand and
// frozen, for the same reason as accountsFixture (roundtrip_test.go): a
// renamed or dropped JSON tag on Token must fail the round trip below.
// Change it only alongside a new document version.
//
// Mikroview tokens.json-shaped: an "api" row, an "ingest" row with
// every field populated, and a "droplist-pull" row (mikroview's own
// third kind, #1224). Every raw value behind a hashedValue is invented
// for this test (the raw* constants below), never a real credential;
// each hashedValue is hashTokenValue of its raw value, exactly what a
// real TokenStore would have written for it.
const tokensFixture = `{
  "version": 1,
  "tokens": [
    {
      "id": "token-id-0001",
      "name": "birdcage",
      "kind": "api",
      "hashedValue": "4974e92fc97ec37e76aa819a8798344bec8f7f9761ae79e320466ddce1be67c2",
      "createdAt": "2026-01-02T03:04:05Z"
    },
    {
      "id": "token-id-0002",
      "name": "router-1",
      "kind": "ingest",
      "device": "router-1",
      "hashedValue": "78bfe5d78db6eb1fc4664928a6648a1a2d181ed90872f71b501d6865640afa20",
      "createdAt": "2026-01-02T03:05:05Z",
      "lastUsedAt": "2026-01-02T05:04:05Z",
      "createdBy": "user-admin",
      "createdByUsername": "admin"
    },
    {
      "id": "token-id-0003",
      "name": "droplist-pull",
      "kind": "droplist-pull",
      "hashedValue": "a61a27d3cc5217aa8c66d5b48d520ce4591320abab88927151299610166d9e94",
      "createdAt": "2026-01-02T03:06:05Z"
    }
  ]
}`

// TestMikroviewTokensJSONFixtureRoundTripsByteIdentical is gauntlet
// issue #4's done-when, held to a frozen fixture since #29: the tokens
// document above loads, saves and reloads byte-identical, and only
// registered kinds authenticate.
func TestMikroviewTokensJSONFixtureRoundTripsByteIdentical(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	const (
		rawAPI      = "fixture-api-raw-token-does-not-exist"
		rawIngest   = "fixture-ingest-raw-token-does-not-exist"
		rawDroplist = "fixture-droplist-pull-raw-token-does-not-exist"
	)
	const droplistPull TokenKind = "droplist-pull"
	const tokenCount = 3

	assertFixtureCoversEveryField(t, tokensFixture, reflect.TypeFor[Token]())
	original := []byte(tokensFixture)

	m := persist.NewMemory()
	primeMemory(t, m, tokensFixture)

	// Load with the default Kinds (api, ingest): the droplist-pull row
	// must be kept -- listed, not silently dropped -- but must never
	// authenticate.
	s1, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatalf("OpenTokenStore (load, default kinds): %v", err)
	}
	if got := len(s1.List()); got != tokenCount {
		t.Fatalf("List() = %d tokens, want %d -- an unregistered kind must not be dropped", got, tokenCount)
	}

	// Save before any Authenticate call: Authenticate records
	// LastUsedAt (token.go), so exercising it here first would make the
	// round-trip compare a document this test itself had already
	// changed rather than the original fixture. This is also what
	// proves the unregistered row survives a save rather than being
	// pruned from the document.
	if err := s1.mutate(func(*tokenState) error { return nil }); err != nil {
		t.Fatalf("mutate: %v", err)
	}

	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatalf("Load after save: %v", err)
	}
	// tokensFixture is version 1, with no seq field (#59): it loads with
	// the counter at zero and this no-op save stamps it at 1, alongside
	// the version bump to 2 -- the same "older document, stamped on its
	// next save" rule accountsFixture's own round trip exercises
	// (roundtrip_test.go).
	want := strings.Replace(string(original), `"version": 1,`, "\"version\": 2,\n  \"seq\": 1,", 1)
	if string(snap.Payload) != want {
		t.Errorf("saved document differs from the original fixture (version bumped, seq stamped at 1):\n--- want ---\n%s\n--- saved ---\n%s",
			want, snap.Payload)
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
	if got := len(s2.List()); got != tokenCount {
		t.Fatalf("reloaded List() = %d tokens, want %d", got, tokenCount)
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
