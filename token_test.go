// Ported from mikroview's internal/auth/token_test.go. Adapted:
//   - OpenTokenStore(path)/OpenTokenStoreWithBackend(b) become the one
//     OpenTokenStore(b, opts) (token.go); a persist.Memory stands in for
//     the temp-file fixtures mikroview's tests used, same convention as
//     testhelpers_test.go's openTestStore for Store.
//   - TestUnknownKindOnDiskCannotAuthenticateButStaysRevocable rewrites
//     the stored document through persist.Memory's Load/Save instead of
//     os.ReadFile/WriteFile.
//   - The three droplist-pull tests are adapted to register a
//     store-local third kind through TokenOptions.Kinds -- the mechanism
//     that replaces mikroview's hard-coded TokenKindDroplistPull (see
//     token.go's header comment) -- rather than a third exported
//     constant. The mikroview-shaped fixture with a real "droplist-pull"
//     row is the separate acceptance test in tokendocument_test.go.
package gauntlet

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// testKindOther stands in for a caller-registered third kind -- e.g.
// mikroview's TokenKindDroplistPull -- for tests that only care that
// TokenOptions.Kinds can register more than the two defaults.
const testKindOther TokenKind = "droplist-pull"

// newTestTokenStore is a persisted store over a fresh persist.Memory --
// the only shape Create accepts, since an unpersisted one refuses to
// issue tokens.
func newTestTokenStore(t *testing.T) *TokenStore {
	t.Helper()
	s, err := OpenTokenStore(persist.NewMemory(), TokenOptions{})
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}
	return s
}

func TestOpenTokenStoreNilBackendIsUsableButNotPersisted(t *testing.T) {
	s, err := OpenTokenStore(nil, TokenOptions{})
	if err != nil {
		t.Fatalf("OpenTokenStore(nil, ...): %v", err)
	}
	if s.Persisted() {
		t.Error("expected a nil backend to leave the store unpersisted")
	}
	if len(s.List()) != 0 {
		t.Errorf("expected 0 tokens, got %d", len(s.List()))
	}
}

func TestTokenCreateRefusesWhenNotPersisted(t *testing.T) {
	s, _ := OpenTokenStore(nil, TokenOptions{})
	if _, _, err := s.Create("birdcage", TokenKindAPI, "", nil, time.Now()); err != ErrTokenNotPersisted {
		t.Errorf("expected ErrTokenNotPersisted, got %v", err)
	}
}

func TestTokenCreateAndAuthenticate(t *testing.T) {
	s := newTestTokenStore(t)
	now := time.Now()

	raw, tok, err := s.Create("birdcage", TokenKindAPI, "", nil, now)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if tok.Name != "birdcage" {
		t.Errorf("Name = %q, want %q", tok.Name, "birdcage")
	}
	if tok.HashedValue == "" {
		t.Error("expected a non-empty HashedValue")
	}
	if raw == "" || raw == tok.HashedValue {
		t.Error("expected a distinct, non-empty raw value")
	}

	got, ok := s.Authenticate(raw, TokenKindAPI, now.Add(time.Minute))
	if !ok {
		t.Fatal("expected the freshly created token's raw value to authenticate")
	}
	if got.ID != tok.ID {
		t.Errorf("ID = %q, want %q", got.ID, tok.ID)
	}
	if got.LastUsedAt.IsZero() {
		t.Error("expected LastUsedAt to be recorded on successful authentication")
	}
}

// TestTokenRawValueNeverStored is the load-bearing property behind
// storing a SHA-256 hash rather than the raw bearer value: the raw
// value itself must never validate as a lookup key, and must never
// appear verbatim as HashedValue.
func TestTokenRawValueNeverStored(t *testing.T) {
	s := newTestTokenStore(t)
	raw, tok, err := s.Create("birdcage", TokenKindAPI, "", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if tok.HashedValue == raw {
		t.Fatal("expected HashedValue to differ from the raw token value")
	}
	for _, listed := range s.List() {
		if listed.HashedValue != "" {
			t.Errorf("expected List() to never expose HashedValue, got %q", listed.HashedValue)
		}
	}
}

func TestTokenAuthenticateRejectsUnknownValue(t *testing.T) {
	s := newTestTokenStore(t)
	if _, ok := s.Authenticate("not-a-real-token", TokenKindAPI, time.Now()); ok {
		t.Error("expected an unknown token value to fail authentication")
	}
	if _, ok := s.Authenticate("", TokenKindAPI, time.Now()); ok {
		t.Error("expected an empty token value to fail authentication")
	}
}

func TestTokenRevoke(t *testing.T) {
	s := newTestTokenStore(t)
	raw, tok, err := s.Create("birdcage", TokenKindAPI, "", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Revoke(tok.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, ok := s.Authenticate(raw, TokenKindAPI, time.Now()); ok {
		t.Error("expected a revoked token to fail authentication")
	}
	if len(s.List()) != 0 {
		t.Errorf("expected the token list to be empty after revoking the only token, got %d", len(s.List()))
	}
}

func TestTokenRevokeUnknownIDReturnsErrTokenNotFound(t *testing.T) {
	s := newTestTokenStore(t)
	if err := s.Revoke("does-not-exist"); err != ErrTokenNotFound {
		t.Errorf("expected ErrTokenNotFound, got %v", err)
	}
}

// TestTokenSurvivesReopen is the property that actually distinguishes
// Token from Session: it must still authenticate after the store is
// closed and reopened from the same backend, simulating a process
// restart.
func TestTokenSurvivesReopen(t *testing.T) {
	m := persist.NewMemory()
	s1, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	raw, tok, err := s1.Create("birdcage", TokenKindAPI, "", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	s2, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Authenticate(raw, TokenKindAPI, time.Now())
	if !ok {
		t.Fatal("expected the token to still authenticate after reopening the store")
	}
	if got.ID != tok.ID {
		t.Errorf("ID = %q, want %q", got.ID, tok.ID)
	}
}

func TestTokenListNeverIncludesRevokedTokens(t *testing.T) {
	s := newTestTokenStore(t)
	_, keep, err := s.Create("keep-me", TokenKindAPI, "", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, drop, err := s.Create("revoke-me", TokenKindAPI, "", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(drop.ID); err != nil {
		t.Fatal(err)
	}

	list := s.List()
	if len(list) != 1 || list[0].ID != keep.ID {
		t.Errorf("expected only %q to remain listed, got %+v", keep.Name, list)
	}
}

// A token outlives the account that made it unless something revokes
// it: the holder still has the raw value, and Authenticate only ever
// checks the token store. Reachable via admin transfer -- an admin
// issues tokens, hands over the role, and is later deleted as an
// ordinary user.
func TestRevokeAllCreatedByRemovesOnlyThatAccountsTokens(t *testing.T) {
	s := newTestTokenStore(t)
	alice := &User{ID: "user-alice", Username: "alice"}
	bob := &User{ID: "user-bob", Username: "bob"}

	aliceRaw, _, err := s.Create("alice-integration", TokenKindAPI, "", alice, time.Now())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	bobRaw, _, err := s.Create("bob-integration", TokenKindAPI, "", bob, time.Now())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if n, err := s.RevokeAllCreatedBy(alice.ID); err != nil || n != 1 {
		t.Errorf("revoked (%d, %v), want (1, nil)", n, err)
	}
	if _, ok := s.Authenticate(aliceRaw, TokenKindAPI, time.Now()); ok {
		t.Error("alice's token still authenticates after her account was deleted")
	}
	if _, ok := s.Authenticate(bobRaw, TokenKindAPI, time.Now()); !ok {
		t.Error("bob's token stopped working when alice's account was deleted")
	}
}

// Tokens written before creator attribution existed carry an empty
// CreatedBy. Matching on that would mean deleting any single account
// wiped every unattributed token in the deployment.
func TestRevokeAllCreatedByIgnoresUnattributedTokens(t *testing.T) {
	s := newTestTokenStore(t)
	raw, _, err := s.Create("pre-upgrade", TokenKindAPI, "", nil, time.Now())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if n, err := s.RevokeAllCreatedBy(""); err != nil || n != 0 {
		t.Errorf("an empty user ID revoked (%d, %v), want (0, nil)", n, err)
	}
	if n, err := s.RevokeAllCreatedBy("user-someone"); err != nil || n != 0 {
		t.Errorf("deleting an unrelated account revoked (%d, %v) unattributed tokens, want (0, nil)", n, err)
	}
	if _, ok := s.Authenticate(raw, TokenKindAPI, time.Now()); !ok {
		t.Error("an unattributed token was revoked by an unrelated account deletion")
	}
}

func TestCreatedBySurvivesAReload(t *testing.T) {
	m := persist.NewMemory()
	s1, _ := OpenTokenStore(m, TokenOptions{})
	alice := &User{ID: "user-alice", Username: "alice"}
	if _, _, err := s1.Create("integration", TokenKindAPI, "", alice, time.Now()); err != nil {
		t.Fatalf("Create: %v", err)
	}

	s2, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}
	list := s2.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 token after reload, got %d", len(list))
	}
	if list[0].CreatedBy != alice.ID || list[0].CreatedByUsername != "alice" {
		t.Errorf("creator attribution lost across a reload: %+v", list[0])
	}
}

// TestTokenKindsAreNotInterchangeable is the point of the whole kind
// field: neither credential may be presented where the other is
// expected. Both directions are asserted, because only checking the one
// that seems dangerous is how the other direction ships broken.
func TestTokenKindsAreNotInterchangeable(t *testing.T) {
	s := newTestTokenStore(t)
	now := time.Now()

	apiRaw, _, err := s.Create("birdcage", TokenKindAPI, "", nil, now)
	if err != nil {
		t.Fatalf("Create api: %v", err)
	}
	ingestRaw, _, err := s.Create("router-1", TokenKindIngest, "router-1", nil, now)
	if err != nil {
		t.Fatalf("Create ingest: %v", err)
	}

	if _, ok := s.Authenticate(ingestRaw, TokenKindAPI, now); ok {
		t.Error("an ingest token authenticated as a read-only API token")
	}
	if _, ok := s.Authenticate(apiRaw, TokenKindIngest, now); ok {
		t.Error("a read-only API token authenticated as an ingest token")
	}

	// Each still works at its own door, so the test above is proving
	// kind separation rather than that authentication is simply broken.
	if _, ok := s.Authenticate(apiRaw, TokenKindAPI, now); !ok {
		t.Error("the api token no longer authenticates as an api token")
	}
	if _, ok := s.Authenticate(ingestRaw, TokenKindIngest, now); !ok {
		t.Error("the ingest token no longer authenticates as an ingest token")
	}
}

// TestAuthenticateWrongKindDoesNotRecordUse guards a subtle one: a token
// presented at the wrong door must not look, in the token list, like it
// was legitimately used. Otherwise LastUsedAt reports activity for a
// credential that was in fact refused, which is exactly backwards for
// anyone reviewing the list after a suspected leak.
func TestAuthenticateWrongKindDoesNotRecordUse(t *testing.T) {
	s := newTestTokenStore(t)
	created := time.Now()

	ingestRaw, tok, err := s.Create("router-1", TokenKindIngest, "router-1", nil, created)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, ok := s.Authenticate(ingestRaw, TokenKindAPI, created.Add(time.Hour)); ok {
		t.Fatal("wrong-kind authentication succeeded")
	}

	for _, got := range s.List() {
		if got.ID != tok.ID {
			continue
		}
		if !got.LastUsedAt.IsZero() {
			t.Errorf("LastUsedAt = %v after a refused authentication, want zero", got.LastUsedAt)
		}
	}
}

// TestIngestTokenRequiresADevice covers both halves of the scope rule.
// An unscoped ingest token is the thing the scope exists to prevent, and
// a device on a read-only token is a scope nothing enforces -- accepting
// either quietly would leave an operator believing in a boundary that
// isn't there.
func TestIngestTokenRequiresADevice(t *testing.T) {
	s := newTestTokenStore(t)
	now := time.Now()

	if _, _, err := s.Create("unscoped", TokenKindIngest, "", nil, now); err != ErrTokenDeviceRequired {
		t.Errorf("Create ingest with no device: err = %v, want ErrTokenDeviceRequired", err)
	}
	if _, _, err := s.Create("scoped-api", TokenKindAPI, "router-1", nil, now); err != ErrTokenDeviceNotAllowed {
		t.Errorf("Create api with a device: err = %v, want ErrTokenDeviceNotAllowed", err)
	}
	if _, _, err := s.Create("nonsense", TokenKind("admin"), "", nil, now); err != ErrTokenKindInvalid {
		t.Errorf("Create with an unregistered kind: err = %v, want ErrTokenKindInvalid", err)
	}

	// Whitespace is trimmed rather than accepted as a device name, so
	// " " cannot smuggle past the required-device check.
	if _, _, err := s.Create("blank-ish", TokenKindIngest, "   ", nil, now); err != ErrTokenDeviceRequired {
		t.Errorf("Create ingest with a whitespace device: err = %v, want ErrTokenDeviceRequired", err)
	}
}

// TestValidDeviceID pins the device-scope check on its own: an IPv6
// literal with a zone (the longest real discovered id) and non-ASCII
// operator names pass; anything over MaxDeviceIDLen bytes, or carrying
// a control or formatting character, or not valid UTF-8, does not.
func TestValidDeviceID(t *testing.T) {
	for _, ok := range []string{
		"",
		"router-1",
		"192.0.2.1",
		"fe80::1ff:fe23:4567:890a%eth0",
		"büro-gateway",
		strings.Repeat("d", MaxDeviceIDLen),
	} {
		if !validDeviceID(ok) {
			t.Errorf("validDeviceID(%q) = false, want true", ok)
		}
	}
	for why, bad := range map[string]string{
		"one byte over the limit":        strings.Repeat("d", MaxDeviceIDLen+1),
		"multi-byte text over the limit": strings.Repeat("ü", MaxDeviceIDLen/2+1),
		"an ANSI escape":                 "router\x1b[2K",
		"a newline":                      "router-1\nrouter-2",
		"a DEL":                          "router\x7f",
		"a bidi override":                "router\u202e1",
		"a zero-width space":             "router\u200b1",
		"invalid UTF-8":                  "router\xff",
	} {
		if validDeviceID(bad) {
			t.Errorf("validDeviceID accepted a device id with %s: %q", why, bad)
		}
	}
}

// TestTokenNameIsBoundedLikeTheDevice: a token's name reaches the same
// token list, audit trail and log lines its device id does, so it gets
// the same cap and the same refusal of control characters.
func TestTokenNameIsBoundedLikeTheDevice(t *testing.T) {
	s := newTestTokenStore(t)
	now := time.Now()

	longest := strings.Repeat("n", MaxTokenNameLen)
	_, tok, err := s.Create("  "+longest+"  ", TokenKindAPI, "", nil, now)
	if err != nil {
		t.Fatalf("Create with a %d-character name: %v", MaxTokenNameLen, err)
	}
	if tok.Name != longest {
		t.Errorf("Name = %q, want it trimmed to the %d-character name", tok.Name, MaxTokenNameLen)
	}
	if _, _, err := s.Create("", TokenKindAPI, "", nil, now); err != nil {
		t.Errorf("Create with an empty name: %v, want it still allowed", err)
	}

	for why, bad := range map[string]string{
		"is too long":             longest + "n",
		"has a control character": "ci\x1b[2Kadmin",
		"has a bidi override":     "ci\u202egnp.exe",
	} {
		if _, _, err := s.Create(bad, TokenKindAPI, "", nil, now); err != ErrTokenNameInvalid {
			t.Errorf("Create with a name that %s: err = %v, want ErrTokenNameInvalid", why, err)
		}
	}
	if n := len(s.List()); n != 2 {
		t.Errorf("store holds %d tokens, want the 2 accepted ones", n)
	}
}

// TestUnknownKindOnDiskCannotAuthenticateButStaysRevocable covers a
// token written by some other build, or hand-edited. It must not
// authenticate -- guessing that an unrecognised kind meant a registered
// one is the wrong direction to guess in -- but it must still be visible
// and revocable, or an operator has a credential they can see the
// effects of and cannot remove.
func TestUnknownKindOnDiskCannotAuthenticateButStaysRevocable(t *testing.T) {
	m := persist.NewMemory()
	s1, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}
	raw, tok, err := s1.Create("from-the-future", TokenKindAPI, "", nil, time.Now())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rewritten := strings.Replace(string(snap.Payload), `"kind": "api"`, `"kind": "quantum"`, 1)
	if rewritten == string(snap.Payload) {
		t.Fatal("test setup: no kind field found to rewrite")
	}
	if _, err := m.Save(context.Background(), []byte(rewritten), snap.Version); err != nil {
		t.Fatalf("Save: %v", err)
	}

	s2, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, ok := s2.Authenticate(raw, TokenKindAPI, time.Now()); ok {
		t.Error("a token with an unrecognised kind authenticated as an api token")
	}
	if _, ok := s2.Authenticate(raw, TokenKindIngest, time.Now()); ok {
		t.Error("a token with an unrecognised kind authenticated as an ingest token")
	}
	if len(s2.List()) != 1 {
		t.Errorf("List() returned %d tokens, want 1 -- an operator cannot revoke what they cannot see", len(s2.List()))
	}
	if err := s2.Revoke(tok.ID); err != nil {
		t.Errorf("Revoke: %v, want nil -- an unusable token must still be removable", err)
	}
}

// TestThirdRegisteredKindLifecycle is #4's version of
// TestTokenCreateAndAuthenticate: create, authenticate, revoke, for a
// kind registered only through TokenOptions.Kinds -- the mechanism that
// replaces mikroview's hard-coded TokenKindDroplistPull.
func TestThirdRegisteredKindLifecycle(t *testing.T) {
	s, err := OpenTokenStore(persist.NewMemory(), TokenOptions{Kinds: []TokenKind{TokenKindAPI, TokenKindIngest, testKindOther}})
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}
	now := time.Now()

	raw, tok, err := s.Create("droplist-pull", testKindOther, "", nil, now)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if tok.Device != "" {
		t.Errorf("Device = %q, want empty -- this kind is not scoped to one device", tok.Device)
	}
	got, ok := s.Authenticate(raw, testKindOther, now)
	if !ok {
		t.Fatal("the registered third-kind token did not authenticate as its own kind")
	}
	if got.ID != tok.ID {
		t.Errorf("Authenticate returned %q, want %q", got.ID, tok.ID)
	}
	if err := s.Revoke(tok.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, ok := s.Authenticate(raw, testKindOther, now); ok {
		t.Error("a revoked third-kind token still authenticated")
	}
}

// TestThirdRegisteredKindIsNotInterchangeable extends
// TestTokenKindsAreNotInterchangeable to a third registered kind -- all
// six directions, since only checking the ones that seem dangerous is
// how the others ship broken.
func TestThirdRegisteredKindIsNotInterchangeable(t *testing.T) {
	s, err := OpenTokenStore(persist.NewMemory(), TokenOptions{Kinds: []TokenKind{TokenKindAPI, TokenKindIngest, testKindOther}})
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}
	now := time.Now()

	apiRaw, _, err := s.Create("birdcage", TokenKindAPI, "", nil, now)
	if err != nil {
		t.Fatalf("Create api: %v", err)
	}
	ingestRaw, _, err := s.Create("router-1", TokenKindIngest, "router-1", nil, now)
	if err != nil {
		t.Fatalf("Create ingest: %v", err)
	}
	otherRaw, _, err := s.Create("droplist-pull", testKindOther, "", nil, now)
	if err != nil {
		t.Fatalf("Create third kind: %v", err)
	}

	if _, ok := s.Authenticate(otherRaw, TokenKindAPI, now); ok {
		t.Error("the third kind authenticated as a read-only API token")
	}
	if _, ok := s.Authenticate(otherRaw, TokenKindIngest, now); ok {
		t.Error("the third kind authenticated as an ingest token")
	}
	if _, ok := s.Authenticate(apiRaw, testKindOther, now); ok {
		t.Error("a read-only API token authenticated as the third kind")
	}
	if _, ok := s.Authenticate(ingestRaw, testKindOther, now); ok {
		t.Error("an ingest token authenticated as the third kind")
	}

	if _, ok := s.Authenticate(otherRaw, testKindOther, now); !ok {
		t.Error("the third kind no longer authenticates as itself")
	}
}

// TestTokenByKindFiltersByKind covers the lookup that finds every token
// of one kind among every other kind a store holds.
func TestTokenByKindFiltersByKind(t *testing.T) {
	s := newTestTokenStore(t)
	now := time.Now()

	if _, _, err := s.Create("birdcage", TokenKindAPI, "", nil, now); err != nil {
		t.Fatalf("Create api: %v", err)
	}
	if _, _, err := s.Create("router-1", TokenKindIngest, "router-1", nil, now); err != nil {
		t.Fatalf("Create ingest: %v", err)
	}
	_, api2, err := s.Create("birdcage-2", TokenKindAPI, "", nil, now)
	if err != nil {
		t.Fatalf("Create api 2: %v", err)
	}

	got := s.ByKind(TokenKindAPI)
	if len(got) != 2 {
		t.Fatalf("ByKind(api) = %d tokens, want 2", len(got))
	}
	found := false
	for _, tok := range got {
		if tok.ID == api2.ID {
			found = true
		}
		if tok.HashedValue != "" {
			t.Error("ByKind returned a token carrying its hash -- it must never be usable to authenticate")
		}
	}
	if !found {
		t.Error("ByKind(api) did not include a token created after the first")
	}
	if len(s.ByKind(TokenKindIngest)) != 1 {
		t.Errorf("ByKind(ingest) = %d tokens, want 1", len(s.ByKind(TokenKindIngest)))
	}
}

// TestTokenCreateReportsPersistFailure: a token that cannot be saved
// must not exist in memory either, since the raw value is shown to the
// caller exactly once, here -- a restart before the next good write
// would leave that caller holding a value that authenticates against
// nothing durable.
func TestTokenCreateReportsPersistFailure(t *testing.T) {
	s, err := OpenTokenStore(failingSaveBackend{}, TokenOptions{})
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}
	raw, tok, err := s.Create("birdcage", TokenKindAPI, "", nil, time.Now())
	if err == nil {
		t.Fatal("Create against a backend that cannot save = nil error, want one")
	}
	if raw != "" || tok != nil {
		t.Errorf("Create returned (%q, %v) after a failed persist, want (\"\", nil)", raw, tok)
	}
	if len(s.List()) != 0 {
		t.Errorf("List() = %d tokens after a failed persist, want 0", len(s.List()))
	}
}

// TestTokenRevokeLeavesTheTokenWorkingWhenPersistFails: a revoke that
// cannot be saved must not remove the token from memory either, or a
// restart before the next good write would bring back a token the
// caller was told was dead.
func TestTokenRevokeLeavesTheTokenWorkingWhenPersistFails(t *testing.T) {
	// Create below persists too, so the fixture needs a backend that
	// saves once before failing, not one that fails outright.
	s, err := OpenTokenStore(&saveBudgetBackend{left: 1}, TokenOptions{})
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}
	raw, tok, err := s.Create("birdcage", TokenKindAPI, "", nil, time.Now())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.Revoke(tok.ID); err == nil {
		t.Fatal("Revoke against a backend that cannot save = nil error, want one")
	}
	if _, ok := s.Authenticate(raw, TokenKindAPI, time.Now()); !ok {
		t.Error("expected the token to still authenticate after a failed persist")
	}
}

// TestRevokeAllCreatedByLeavesTokensWorkingWhenPersistFails is the same
// rollback case for the bulk revoke a deleted account triggers: a failed
// persist must not remove any of the deleted account's tokens from
// memory, and must report zero revoked rather than the count it
// attempted.
func TestRevokeAllCreatedByLeavesTokensWorkingWhenPersistFails(t *testing.T) {
	// Create below persists too, so the fixture needs a backend that
	// saves once before failing, not one that fails outright.
	s, err := OpenTokenStore(&saveBudgetBackend{left: 1}, TokenOptions{})
	if err != nil {
		t.Fatalf("OpenTokenStore: %v", err)
	}
	alice := &User{ID: "user-alice", Username: "alice"}
	raw, _, err := s.Create("alice-integration", TokenKindAPI, "", alice, time.Now())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	n, err := s.RevokeAllCreatedBy(alice.ID)
	if err == nil {
		t.Fatal("RevokeAllCreatedBy against a backend that cannot save = nil error, want one")
	}
	if n != 0 {
		t.Errorf("revoked count = %d after a failed persist, want 0", n)
	}
	if _, ok := s.Authenticate(raw, TokenKindAPI, time.Now()); !ok {
		t.Error("expected alice's token to still authenticate after a failed persist")
	}
}

// TestTokenOrderIsDeterministicOnEqualCreatedAt: tokens created in the
// same instant (a script issuing several at once, or a clock with coarse
// resolution) must list, and persist, in one fixed order. Map iteration
// is randomised, so without a tie-breaker the order changes from call to
// call -- a list that reshuffles on refresh, and a document whose bytes
// differ on every save though nothing in it changed.
func TestTokenOrderIsDeterministicOnEqualCreatedAt(t *testing.T) {
	m := persist.NewMemory()
	s, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i := 0; i < 8; i++ {
		if _, _, err := s.Create("same-instant", TokenKindAPI, "", nil, now); err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
	}

	ids := func(list []Token) string {
		out := make([]string, len(list))
		for i, tok := range list {
			out[i] = tok.ID
		}
		if !sort.StringsAreSorted(out) {
			t.Errorf("order on equal CreatedAt is not by ID: %v", out)
		}
		return strings.Join(out, ",")
	}
	want := ids(s.List())
	for i := 0; i < 20; i++ {
		if got := ids(s.List()); got != want {
			t.Fatalf("List order changed between calls:\nfirst %s\nlater %s", want, got)
		}
		var byKind []Token
		for _, tok := range s.ByKind(TokenKindAPI) {
			byKind = append(byKind, *tok)
		}
		if got := ids(byKind); got != want {
			t.Fatalf("ByKind order differs from List:\nList   %s\nByKind %s", want, got)
		}
	}

	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var saved []Token
	if err := json.Unmarshal(snap.Payload, &saved); err != nil {
		t.Fatal(err)
	}
	if got := ids(saved); got != want {
		t.Errorf("persisted order differs from List:\nList  %s\nsaved %s", want, got)
	}
}
