package gauntlet

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// otherProcessBackend is a persist.Memory that lets a test slip another
// process's write into the one window reloadIfStale cannot close: after
// the store has reloaded and decided, just before its own Save reaches
// the document. beforeSave runs once, on the next Save, and is then
// cleared.
type otherProcessBackend struct {
	*persist.Memory
	beforeSave func()
}

func (b *otherProcessBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	if f := b.beforeSave; f != nil {
		b.beforeSave = nil
		f()
	}
	return b.Memory.Save(ctx, payload, expect)
}

// conflictingBackend is a persist.Memory that lets allow saves through
// and refuses every one after with ErrConflict, as if another process
// wrote first every single time, counting what the loop does on the
// way.
type conflictingBackend struct {
	*persist.Memory
	allow        int
	saves, loads int
}

func (b *conflictingBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	b.saves++
	if b.allow <= 0 {
		return 0, persist.ErrConflict
	}
	b.allow--
	return b.Memory.Save(ctx, payload, expect)
}

func (b *conflictingBackend) Load(ctx context.Context) (persist.Snapshot, error) {
	b.loads++
	return b.Memory.Load(ctx)
}

// storeHas reads the index directly under the store's own lock: Get and
// ByUsername reload first, and the backend's document is the fresh,
// correct one by the time a test looks, so a reload would quietly repair
// exactly the in-memory state the test is checking.
func storeHas(s *Store, username string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.byName[username]
	return ok
}

// usernamesIn decodes a saved accounts document to its usernames.
func usernamesIn(t *testing.T, m *persist.Memory) []string {
	t.Helper()
	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	st, err := decodeAccounts(snap.Payload)
	if err != nil {
		t.Fatalf("decoding the saved document: %v", err)
	}
	var names []string
	for _, u := range st.users() {
		names = append(names, u.Username)
	}
	return names
}

// TestMutateReplaysTheChangeOnAConflictingWrite: another process writes
// (here, a second Store creating carol) after this store reloaded and
// before it saved. The old SaveWithRetry saved this store's stale
// document on top, and carol was gone. The loop must instead load the
// document with carol in it, delete bob from that, and save the result:
// both changes survive, in memory and on disk.
func TestMutateReplaysTheChangeOnAConflictingWrite(t *testing.T) {
	m := persist.NewMemory()
	b := &otherProcessBackend{Memory: m}
	s, err := OpenStore(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register("alice", "password123", time.Now()); err != nil {
		t.Fatal(err)
	}
	bob, err := s.CreateUser("bob", "password456", RoleUser, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	other, err := OpenStore(m, Options{}) // the other process, on the same document
	if err != nil {
		t.Fatal(err)
	}
	b.beforeSave = func() {
		if _, err := other.CreateUser("carol", "password789", RoleUser, time.Now()); err != nil {
			t.Errorf("the other process's CreateUser: %v", err)
		}
	}

	deleted, err := s.DeleteUser(bob.ID)
	if err != nil {
		t.Fatalf("DeleteUser across a conflicting write: %v", err)
	}
	if deleted.ID != bob.ID {
		t.Errorf("DeleteUser returned %q, want bob", deleted.Username)
	}
	if storeHas(s, "bob") {
		t.Error("bob is still in memory after the replayed deletion")
	}
	if !storeHas(s, "carol") {
		t.Error("carol, written by the other process, is missing from memory: the replay did not load the fresh document")
	}
	if got := usernamesIn(t, m); strings.Join(got, ",") != "alice,carol" {
		t.Errorf("saved document holds %v, want [alice carol]", got)
	}
	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s.mu.RLock()
	version := s.version
	s.mu.RUnlock()
	if version != snap.Version {
		t.Errorf("store holds version %d after the replayed save, backend is at %d", version, snap.Version)
	}
}

// TestMutateGivesUpAfterFiveConflictsAndChangesNothing: a writer that
// never stops -- every save refused -- ends in ErrSaveConflict after
// exactly maxSaveAttempts saves, with one reload between each pair, and
// the store as it was: bob in memory, bob on disk, version unmoved.
func TestMutateGivesUpAfterFiveConflictsAndChangesNothing(t *testing.T) {
	b := &conflictingBackend{Memory: persist.NewMemory(), allow: 2} // Register and CreateUser
	s, err := OpenStore(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register("alice", "password123", time.Now()); err != nil {
		t.Fatal(err)
	}
	bob, err := s.CreateUser("bob", "password456", RoleUser, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b.saves, b.loads = 0, 0
	s.mu.RLock()
	before := s.version
	s.mu.RUnlock()

	_, err = s.DeleteUser(bob.ID)
	if !errors.Is(err, ErrSaveConflict) {
		t.Fatalf("DeleteUser against a backend that always conflicts = %v, want ErrSaveConflict", err)
	}
	if b.saves != maxSaveAttempts {
		t.Errorf("saves = %d, want %d", b.saves, maxSaveAttempts)
	}
	if b.loads != maxSaveAttempts-1 {
		t.Errorf("reloads = %d, want %d (one between each pair of attempts)", b.loads, maxSaveAttempts-1)
	}
	if !storeHas(s, "bob") {
		t.Error("bob was removed from memory by a write that was never saved")
	}
	if got := usernamesIn(t, b.Memory); strings.Join(got, ",") != "alice,bob" {
		t.Errorf("saved document holds %v, want [alice bob]", got)
	}
	s.mu.RLock()
	after := s.version
	s.mu.RUnlock()
	if after != before {
		t.Errorf("version moved from %d to %d on a write that failed", before, after)
	}
}

// TestMutateOpErrorChangesNothing: an op that changes the copy and then
// fails leaves the store untouched and never reaches the backend -- the
// copy is dropped, and there is no rollback to get wrong.
func TestMutateOpErrorChangesNothing(t *testing.T) {
	b := &conflictingBackend{Memory: persist.NewMemory(), allow: 1}
	s, err := OpenStore(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register("alice", "password123", time.Now()); err != nil {
		t.Fatal(err)
	}
	b.saves = 0

	errBoom := errors.New("boom")
	err = s.mutate(func(st *storeState) error {
		clear(st.byID)
		clear(st.byName)
		return errBoom
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("mutate = %v, want the op's own error", err)
	}
	if !storeHas(s, "alice") {
		t.Error("alice was removed from memory by an op that failed")
	}
	if b.saves != 0 {
		t.Errorf("saves = %d after a failed op, want 0", b.saves)
	}
}

// TestMutateRefusesToWriteOverADocumentItCannotApply: the fresh document
// the other process wrote fails the same check OpenStore applies (two
// admins). Where SaveWithRetry would have written this store's document
// over it, the write must fail, say why, and leave both the operator's
// document on disk and this store's memory as they were.
func TestMutateRefusesToWriteOverADocumentItCannotApply(t *testing.T) {
	m := persist.NewMemory()
	b := &otherProcessBackend{Memory: m}
	s, err := OpenStore(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register("alice", "password123", time.Now()); err != nil {
		t.Fatal(err)
	}
	bob, err := s.CreateUser("bob", "password456", RoleUser, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b.beforeSave = func() {
		snap, err := m.Load(context.Background())
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := m.Save(context.Background(), []byte(twoAdminsDocument), snap.Version); err != nil {
			t.Error(err)
		}
	}

	_, err = s.DeleteUser(bob.ID)
	if !errors.Is(err, errMultipleAdmins) {
		t.Fatalf("DeleteUser over a two-admin document = %v, want errMultipleAdmins", err)
	}
	if errors.Is(err, ErrSaveConflict) {
		t.Error("a refused document is not the same failure as a writer that never stops")
	}
	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(snap.Payload) != twoAdminsDocument {
		t.Errorf("the refused document was overwritten:\n%s", snap.Payload)
	}
	if !storeHas(s, "bob") {
		t.Error("bob was removed from memory by a write that was refused")
	}
}

// TestMutateTreatsARemovedDocumentAsEmpty: the document this store
// loaded has since been removed (a deleted file). The retried write runs
// against nothing, so a deletion finds no account, and the store is left
// as it was rather than recreating the file from memory.
func TestMutateTreatsARemovedDocumentAsEmpty(t *testing.T) {
	b := &vanishingBackend{}
	s, err := OpenStore(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register("alice", "password123", time.Now()); err != nil {
		t.Fatal(err)
	}
	bob, err := s.CreateUser("bob", "password456", RoleUser, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b.gone = true

	if _, err := s.DeleteUser(bob.ID); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("DeleteUser after the document vanished = %v, want ErrUserNotFound from the replay against an empty document", err)
	}
	if !storeHas(s, "bob") {
		t.Error("bob was removed from memory by a write that did not happen")
	}
}

// vanishingBackend holds a document until gone is set, after which it
// answers as a backend nothing has ever been written to: Load reports
// no document and Save refuses any version but 0.
type vanishingBackend struct {
	payload []byte
	version int64
	gone    bool
}

func (b *vanishingBackend) Load(ctx context.Context) (persist.Snapshot, error) {
	if b.gone || b.version == 0 {
		return persist.Snapshot{}, nil
	}
	return persist.Snapshot{Payload: b.payload, Version: b.version, Exists: true}, nil
}

func (b *vanishingBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	current := b.version
	if b.gone {
		current = 0
	}
	if expect != current {
		return 0, persist.ErrConflict
	}
	b.payload, b.version, b.gone = payload, current+1, false
	return b.version, nil
}

func (b *vanishingBackend) Close() error     { return nil }
func (b *vanishingBackend) Describe() string { return "vanishing test backend" }

// TestMutateWithoutABackendChangesMemoryOnly: a store opened with no
// backend still applies the change -- there is nothing to save and
// nothing to conflict with.
func TestMutateWithoutABackendChangesMemoryOnly(t *testing.T) {
	s, err := OpenStore(nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	err = s.mutate(func(st *storeState) error {
		st.byID["u1"] = &User{ID: "u1", Username: "alice", Role: RoleAdmin}
		st.byName["alice"] = "u1"
		return nil
	})
	if err != nil {
		t.Fatalf("mutate on an unpersisted store: %v", err)
	}
	if n := s.Count(); n != 1 {
		t.Errorf("Count() = %d after an in-memory change, want 1", n)
	}
}

// TestMutateBestEffortKeepsTheChangeInMemoryAndLogs: a bookkeeping
// write that cannot be saved is still applied in memory, where Get sees
// it, and logged -- the behaviour persistLocked gave LastLogin. An op
// that fails is dropped silently: nothing applied, nothing to log.
func TestMutateBestEffortKeepsTheChangeInMemoryAndLogs(t *testing.T) {
	var logs bytes.Buffer
	b := &conflictingBackend{Memory: persist.NewMemory(), allow: 1}
	s, err := OpenStore(b, Options{Log: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	alice, err := s.Register("alice", "password123", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	seen := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	s.mu.Lock()
	s.mutateBestEffortLocked(func(st *storeState) error {
		st.byID[alice.ID].LastLogin = seen
		return nil
	})
	s.mu.Unlock()

	if got, _ := s.Get(alice.ID); !got.LastLogin.Equal(seen) {
		t.Errorf("LastLogin = %v after a best-effort write that could not be saved, want %v kept in memory", got.LastLogin, seen)
	}
	if !strings.Contains(logs.String(), "exists only in memory") {
		t.Errorf("expected the unsaved change to be logged, got:\n%s", logs.String())
	}

	logs.Reset()
	s.mu.Lock()
	s.mutateBestEffortLocked(func(st *storeState) error {
		return ErrUserNotFound
	})
	s.mu.Unlock()
	if logs.Len() != 0 {
		t.Errorf("an op that failed was logged as an unsaved change:\n%s", logs.String())
	}
}

// TestTokenStoreReloadsOnAConflictingWrite: two TokenStores on one
// document, as a CLI and a live server would be. Before #21 the token
// store never reloaded, so the second store's Create saved its stale
// document on top and the first store's token was gone. Now the second
// store loads the fresh document, adds its token to that, and both
// tokens authenticate from a store opened afterwards.
func TestTokenStoreReloadsOnAConflictingWrite(t *testing.T) {
	m := persist.NewMemory()
	first, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}

	rawA, _, err := first.Create("a", TokenKindAPI, "", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rawB, _, err := second.Create("b", TokenKindAPI, "", nil, time.Now())
	if err != nil {
		t.Fatalf("Create on a stale store: %v", err)
	}

	if n := len(second.List()); n != 2 {
		t.Errorf("the stale store lists %d tokens after its replayed Create, want 2 (the other store's token and its own)", n)
	}
	reopened, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Authenticate(rawA, TokenKindAPI, time.Now()); !ok {
		t.Error("the first store's token was written over by the second store's Create")
	}
	if _, ok := reopened.Authenticate(rawB, TokenKindAPI, time.Now()); !ok {
		t.Error("the second store's own token was not saved")
	}
}

// TestTokenStoreGivesUpAfterFiveConflictsAndChangesNothing is the
// TokenStore half of the five-attempts bound: the token the caller was
// never handed must not be in memory either.
func TestTokenStoreGivesUpAfterFiveConflictsAndChangesNothing(t *testing.T) {
	b := &conflictingBackend{Memory: persist.NewMemory(), allow: 0}
	s, err := OpenTokenStore(b, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := s.Create("a", TokenKindAPI, "", nil, time.Now())
	if !errors.Is(err, ErrSaveConflict) {
		t.Fatalf("Create against a backend that always conflicts = %v, want ErrSaveConflict", err)
	}
	if raw != "" {
		t.Error("a raw token value was handed out for a token that was never saved")
	}
	if b.saves != maxSaveAttempts {
		t.Errorf("saves = %d, want %d", b.saves, maxSaveAttempts)
	}
	if n := len(s.List()); n != 0 {
		t.Errorf("List() = %d tokens after a write that was never saved, want 0", n)
	}
}

// TestTokenStoreBestEffortKeepsTheChangeInMemoryAndLogs is the
// TokenStore half of the best-effort contract, for the LastUsedAt bump.
func TestTokenStoreBestEffortKeepsTheChangeInMemoryAndLogs(t *testing.T) {
	var logs bytes.Buffer
	b := &conflictingBackend{Memory: persist.NewMemory(), allow: 1}
	s, err := OpenTokenStore(b, TokenOptions{Log: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	_, tok, err := s.Create("a", TokenKindAPI, "", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	seen := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	s.mu.Lock()
	s.mutateBestEffortLocked(func(st *tokenState) error {
		st.byID[tok.ID].LastUsedAt = seen
		return nil
	})
	s.mu.Unlock()

	if got := s.List(); len(got) != 1 || !got[0].LastUsedAt.Equal(seen) {
		t.Errorf("List() = %+v after a best-effort write that could not be saved, want LastUsedAt %v kept in memory", got, seen)
	}
	if !strings.Contains(logs.String(), "exists only in memory") {
		t.Errorf("expected the unsaved change to be logged, got:\n%s", logs.String())
	}
}

// TestStoreStateCloneIsDeep: the copy mutate works on must share nothing
// with the original, down to the slices inside an account, or a failed
// attempt would leave its changes behind.
func TestStoreStateCloneIsDeep(t *testing.T) {
	now := time.Now()
	orig := indexUsers(storeFile{Users: []*User{{
		ID: "u1", Username: "alice", Role: RoleAdmin,
		OIDCIssuer: "https://issuer.example", OIDCSubject: "sub",
		RecoveryCodes: []RecoveryCode{{Hash: "h1"}},
		Passkeys:      []Passkey{testPasskey(1, "YubiKey")},
		LastLogin:     now,
	}}})
	cp := orig.clone()

	cp.byID["u1"].Username = "mallory"
	cp.byID["u1"].RecoveryCodes[0].UsedAt = now
	cp.byID["u1"].Passkeys[0].ID[0] = 9
	cp.byID["u1"].Passkeys[0].Transports[0] = "usb"
	cp.byName["mallory"] = "u1"
	delete(cp.oidcIndex, oidcKey{issuer: "https://issuer.example", subject: "sub"})
	cp.lastLoginSaved["u1"] = time.Time{}

	u := orig.byID["u1"]
	if u.Username != "alice" || !u.RecoveryCodes[0].UsedAt.IsZero() || u.Passkeys[0].ID[0] != 1 || u.Passkeys[0].Transports[0] != "internal" {
		t.Errorf("changing the clone reached the original account: %+v", u)
	}
	if _, ok := orig.byName["mallory"]; ok {
		t.Error("changing the clone's name index reached the original")
	}
	if _, ok := orig.oidcIndex[oidcKey{issuer: "https://issuer.example", subject: "sub"}]; !ok {
		t.Error("changing the clone's OIDC index reached the original")
	}
	if !orig.lastLoginSaved["u1"].Equal(now) {
		t.Error("changing the clone's lastLoginSaved reached the original")
	}
}

// TestMutateNoChangeSavesNothing: an op that finds nothing to do
// returns errNoChange, which mutate answers with nil and no save -- the
// early return-before-saving the hand-written methods had.
func TestMutateNoChangeSavesNothing(t *testing.T) {
	b := &conflictingBackend{Memory: persist.NewMemory(), allow: 1}
	s, err := OpenStore(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register("alice", "password123", time.Now()); err != nil {
		t.Fatal(err)
	}
	b.saves = 0

	if err := s.mutate(func(st *storeState) error { return errNoChange }); err != nil {
		t.Fatalf("mutate with nothing to change = %v, want nil", err)
	}
	if b.saves != 0 {
		t.Errorf("saves = %d for an op with nothing to change, want 0", b.saves)
	}

	tb := &conflictingBackend{Memory: persist.NewMemory()}
	ts, err := OpenTokenStore(tb, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.mutate(func(st *tokenState) error { return errNoChange }); err != nil {
		t.Fatalf("TokenStore.mutate with nothing to change = %v, want nil", err)
	}
	if tb.saves != 0 {
		t.Errorf("saves = %d for a token op with nothing to change, want 0", tb.saves)
	}
}

// TestTokenStoreRevokeReplaysOnAConflictingWrite: the first store
// revokes its token after the second store, unseen by it, added one.
// The revoke must be replayed against the document holding both, so
// the other store's token survives and the revoked one is gone.
func TestTokenStoreRevokeReplaysOnAConflictingWrite(t *testing.T) {
	m := persist.NewMemory()
	first, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rawA, a, err := first.Create("a", TokenKindAPI, "", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rawB, _, err := second.Create("b", TokenKindAPI, "", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if err := first.Revoke(a.ID); err != nil {
		t.Fatalf("Revoke on a stale store: %v", err)
	}
	reopened, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Authenticate(rawA, TokenKindAPI, time.Now()); ok {
		t.Error("the revoked token still authenticates")
	}
	if _, ok := reopened.Authenticate(rawB, TokenKindAPI, time.Now()); !ok {
		t.Error("the other store's token was written over by the revoke")
	}
}
