package gauntlet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
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

// slowConflictingBackend answers every Save and Load after delay, and
// refuses every Save with ErrConflict -- a slow backend another process
// keeps writing to. With honourCtx it returns early when the caller's
// context ends, as a database driver does; without it, it sleeps the
// full delay regardless, as the file backends do.
type slowConflictingBackend struct {
	*persist.Memory
	delay     time.Duration
	honourCtx bool
	saves     int
}

func (b *slowConflictingBackend) wait(ctx context.Context) error {
	if !b.honourCtx {
		time.Sleep(b.delay)
		return nil
	}
	select {
	case <-time.After(b.delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *slowConflictingBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	b.saves++
	if err := b.wait(ctx); err != nil {
		return 0, err
	}
	return 0, persist.ErrConflict
}

func (b *slowConflictingBackend) Load(ctx context.Context) (persist.Snapshot, error) {
	if err := b.wait(ctx); err != nil {
		return persist.Snapshot{}, err
	}
	return b.Memory.Load(ctx)
}

// TestMutateBoundsTheWholeWriteByOneDeadline: each save and each reload
// used to get its own saveTimeout, so a slow backend that conflicted
// every time held the write lock -- and with it every read and login --
// for up to five saves and four reloads. The whole write now shares one
// deadline: it fails after far fewer attempts than maxSaveAttempts, in
// about saveTimeout, whether or not the backend honours the context.
func TestMutateBoundsTheWholeWriteByOneDeadline(t *testing.T) {
	restore := saveTimeout
	saveTimeout = 100 * time.Millisecond
	t.Cleanup(func() { saveTimeout = restore })

	for _, honourCtx := range []bool{true, false} {
		m := persist.NewMemory()
		plain, err := OpenStore(m, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := plain.Register("alice", "password123", time.Now()); err != nil {
			t.Fatal(err)
		}
		b := &slowConflictingBackend{Memory: m, delay: 60 * time.Millisecond, honourCtx: honourCtx}
		s, err := OpenStore(b, Options{})
		if err != nil {
			t.Fatal(err)
		}

		started := time.Now()
		_, err = s.CreateUser("bob", "password456", RoleUser, time.Now())
		elapsed := time.Since(started)
		if err == nil {
			t.Fatalf("honourCtx %v: a write against a backend that always conflicts succeeded", honourCtx)
		}
		if errors.Is(err, ErrSaveConflict) {
			t.Errorf("honourCtx %v: the write ran all %d attempts (%v): %v", honourCtx, maxSaveAttempts, elapsed, err)
		}
		// Unbounded, this is five saves and four reloads at 60ms each.
		// Within one 100ms deadline at most two saves fit (save, reload,
		// save -- the last one an overrun of a backend that ignores
		// ctx). The count is what is asserted, not the clock: a loaded
		// host stretches every sleep, which can only make fewer saves
		// fit, never more, where a wall-clock bound would flake.
		t.Logf("honourCtx %v: %d saves in %v: %v", honourCtx, b.saves, elapsed, err)
		if b.saves > 2 {
			t.Errorf("honourCtx %v: saves = %d, want at most 2 within one deadline", honourCtx, b.saves)
		}
		if storeHas(s, "bob") {
			t.Errorf("honourCtx %v: bob is in memory after a write that failed", honourCtx)
		}
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

// openVanishingStore opens a Store over a vanishingBackend holding
// alice (the admin) and bob, then removes the document from under it.
func openVanishingStore(t *testing.T) (*Store, *vanishingBackend, *User) {
	t.Helper()
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
	b.saves = 0
	return s, b, bob
}

// TestMutateRefusesToWriteWhenTheDocumentHasBeenRemoved: the document
// this store loaded has since been removed (a deleted file). Before,
// the retried write ran against an empty document and recreated the
// file from whatever this one write produced -- for CreateUser, a
// document holding carol and no admin, which the next OpenStore
// refuses. Now the write fails with ErrDocumentRemoved, nothing is
// recreated, and memory is left as it was.
func TestMutateRefusesToWriteWhenTheDocumentHasBeenRemoved(t *testing.T) {
	s, b, bob := openVanishingStore(t)

	if _, err := s.DeleteUser(bob.ID); !errors.Is(err, ErrDocumentRemoved) {
		t.Fatalf("DeleteUser after the document vanished = %v, want ErrDocumentRemoved", err)
	}
	if !storeHas(s, "bob") {
		t.Error("bob was removed from memory by a write that did not happen")
	}
	if _, err := s.CreateUser("carol", "password789", RoleUser, time.Now()); !errors.Is(err, ErrDocumentRemoved) {
		t.Fatalf("CreateUser after the document vanished = %v, want ErrDocumentRemoved", err)
	}
	if storeHas(s, "carol") {
		t.Error("carol is in memory after a write that was refused")
	}
	// One refused save per write, and never the second one -- with
	// version 0 -- that would create the document again.
	if !b.gone || b.saves != 2 {
		t.Errorf("the document was recreated from one write (gone %v, saves %d): the next OpenStore would refuse it", b.gone, b.saves)
	}
}

// TestFindOrCreateOIDCUserRefusesToBecomeTheAdminOfARemovedDocument:
// alice is the admin, the document vanishes, and a new SSO identity
// signs in. Replayed against an empty document, the new account would
// be the first one and so the admin -- a document in which a stranger
// holds the only admin role. The write must fail instead.
func TestFindOrCreateOIDCUserRefusesToBecomeTheAdminOfARemovedDocument(t *testing.T) {
	s, b, _ := openVanishingStore(t)

	_, _, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-1", "mallory", time.Now())
	if !errors.Is(err, ErrDocumentRemoved) {
		t.Fatalf("FindOrCreateOIDCUser after the document vanished = %v, want ErrDocumentRemoved", err)
	}
	if storeHas(s, "mallory") {
		t.Error("the SSO account is in memory after a write that was refused")
	}
	if !b.gone {
		t.Error("the document was recreated with the SSO account as its admin")
	}
}

// TestTokenStoreRefusesToWriteWhenTheDocumentHasBeenRemoved is the
// TokenStore half of the rule: a tokens document that vanished is not
// recreated holding only this write's token.
func TestTokenStoreRefusesToWriteWhenTheDocumentHasBeenRemoved(t *testing.T) {
	b := &vanishingBackend{}
	s, err := OpenTokenStore(b, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Create("a", TokenKindAPI, "", nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	b.gone = true

	raw, _, err := s.Create("b", TokenKindAPI, "", nil, time.Now())
	if !errors.Is(err, ErrDocumentRemoved) {
		t.Fatalf("Create after the document vanished = %v, want ErrDocumentRemoved", err)
	}
	if raw != "" {
		t.Error("a raw token value was handed out for a token that was never saved")
	}
	if !b.gone {
		t.Error("the tokens document was recreated holding only the new token")
	}
	if n := len(s.List()); n != 1 {
		t.Errorf("List() = %d tokens after a refused write, want the 1 still in memory", n)
	}
}

// TestMutateRefusesToSaveAStateItWouldRefuseToOpen: an op that leaves
// the accounts with no admin -- no op in this package does, so this is
// one written for the test -- is stopped at the save, before the
// backend sees a document the next OpenStore would refuse.
func TestMutateRefusesToSaveAStateItWouldRefuseToOpen(t *testing.T) {
	b := &conflictingBackend{Memory: persist.NewMemory(), allow: 2}
	s, err := OpenStore(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	alice, err := s.Register("alice", "password123", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser("bob", "password456", RoleUser, time.Now()); err != nil {
		t.Fatal(err)
	}
	b.saves = 0

	err = s.mutate(func(st *storeState) error {
		delete(st.byID, alice.ID)
		delete(st.byName, "alice")
		return nil
	})
	if !errors.Is(err, errNoAdmin) {
		t.Fatalf("mutate removing the only admin = %v, want errNoAdmin", err)
	}
	if b.saves != 0 {
		t.Errorf("saves = %d for a document with no admin, want 0", b.saves)
	}
	if !storeHas(s, "alice") {
		t.Error("alice was removed from memory by a write that was refused")
	}
	if got := usernamesIn(t, b.Memory); strings.Join(got, ",") != "alice,bob" {
		t.Errorf("saved document holds %v, want [alice bob]", got)
	}
}

// vanishingBackend holds a document until gone is set, after which it
// answers as a backend nothing has ever been written to: Load reports
// no document and Save refuses any version but 0 -- and would recreate
// the document for one, which is what the store must never ask for.
type vanishingBackend struct {
	payload []byte
	version int64
	gone    bool
	saves   int
}

func (b *vanishingBackend) Load(ctx context.Context) (persist.Snapshot, error) {
	if b.gone || b.version == 0 {
		return persist.Snapshot{}, nil
	}
	return persist.Snapshot{Payload: b.payload, Version: b.version, Exists: true}, nil
}

func (b *vanishingBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	b.saves++
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

// ProtectedAtRest: see failingSaveBackend (testhelpers_test.go).
func (b *vanishingBackend) ProtectedAtRest() bool { return true }

// removedLine is the part of the #39 log line both stores share.
const removedLine = "has been removed since this process loaded it; writes are refused until it is restored or the process restarts"

// TestStoreLogsADocumentRemovalOncePerRemoval (#39): writes against a
// removed accounts document all fail, but the operator is told once,
// at error level, what happened and what to do -- not once per write.
// A restore followed by a second removal is a new removal, logged again.
func TestStoreLogsADocumentRemovalOncePerRemoval(t *testing.T) {
	var logs bytes.Buffer
	b := &vanishingBackend{}
	s, err := OpenStore(b, Options{Log: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register("alice", "password123", time.Now()); err != nil {
		t.Fatal(err)
	}
	create := func(name string) error {
		_, err := s.CreateUser(name, "password456", RoleUser, time.Now())
		return err
	}

	b.gone = true
	for _, name := range []string{"bob", "carol"} {
		if err := create(name); !errors.Is(err, ErrDocumentRemoved) {
			t.Fatalf("CreateUser(%s) after removal = %v, want ErrDocumentRemoved", name, err)
		}
	}
	if n := strings.Count(logs.String(), removedLine); n != 1 {
		t.Fatalf("removal logged %d times over two writes, want 1; log = %q", n, logs.String())
	}
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "accounts store (vanishing test backend)") {
		t.Errorf("removal line is not an error naming the accounts store and backend: %q", logs.String())
	}

	b.gone = false // restored
	if err := create("dave"); err != nil {
		t.Fatalf("CreateUser after the restore = %v", err)
	}
	b.gone = true // removed again
	for _, name := range []string{"erin", "frank"} {
		if err := create(name); !errors.Is(err, ErrDocumentRemoved) {
			t.Fatalf("CreateUser(%s) after the second removal = %v, want ErrDocumentRemoved", name, err)
		}
	}
	if n := strings.Count(logs.String(), removedLine); n != 2 {
		t.Errorf("two removals logged %d times, want 2; log = %q", n, logs.String())
	}
}

// TestTokenStoreLogsADocumentRemovalOncePerRemoval is the TokenStore
// half of #39.
func TestTokenStoreLogsADocumentRemovalOncePerRemoval(t *testing.T) {
	var logs bytes.Buffer
	b := &vanishingBackend{}
	s, err := OpenTokenStore(b, TokenOptions{Log: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	create := func(name string) error {
		_, _, err := s.Create(name, TokenKindAPI, "", nil, time.Now())
		return err
	}
	if err := create("a"); err != nil {
		t.Fatal(err)
	}

	b.gone = true
	for _, name := range []string{"b", "c"} {
		if err := create(name); !errors.Is(err, ErrDocumentRemoved) {
			t.Fatalf("Create(%s) after removal = %v, want ErrDocumentRemoved", name, err)
		}
	}
	if n := strings.Count(logs.String(), removedLine); n != 1 {
		t.Fatalf("removal logged %d times over two writes, want 1; log = %q", n, logs.String())
	}
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "API tokens store (vanishing test backend)") {
		t.Errorf("removal line is not an error naming the tokens store and backend: %q", logs.String())
	}

	b.gone = false
	if err := create("d"); err != nil {
		t.Fatalf("Create after the restore = %v", err)
	}
	b.gone = true
	for _, name := range []string{"e", "f"} {
		if err := create(name); !errors.Is(err, ErrDocumentRemoved) {
			t.Fatalf("Create(%s) after the second removal = %v, want ErrDocumentRemoved", name, err)
		}
	}
	if n := strings.Count(logs.String(), removedLine); n != 2 {
		t.Errorf("two removals logged %d times, want 2; log = %q", n, logs.String())
	}
}

// TestBestEffortWritesStayQuietAfterARemoval: a login or token use
// whose last-seen bump cannot be saved because the document is gone
// adds nothing to the one removal line -- otherwise every sign-in for
// as long as the file stays missing logs a fresh error.
func TestBestEffortWritesStayQuietAfterARemoval(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	start := time.Now()

	ab := &vanishingBackend{}
	s, err := OpenStore(ab, Options{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	alice, err := s.Register("alice", "password123", start)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := s.AddPasskey(alice.ID, testPasskey(1, ""))
	if err != nil {
		t.Fatal(err)
	}
	tb := &vanishingBackend{}
	ts, err := OpenTokenStore(tb, TokenOptions{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := ts.Create("a", TokenKindAPI, "", nil, start)
	if err != nil {
		t.Fatal(err)
	}

	ab.gone, tb.gone = true, true
	for i := 1; i <= 3; i++ {
		now := start.Add(time.Duration(i) * 2 * time.Hour) // past each last-seen granularity
		if _, err := s.Authenticate("alice", "password123", now); err != nil {
			t.Fatalf("login %d after removal = %v", i, err)
		}
		if _, ok := ts.Authenticate(raw, TokenKindAPI, now); !ok {
			t.Fatalf("token use %d after removal refused", i)
		}
		if ok, err := s.RecordPasskeyAssertionIfFresh(alice.ID, pk.ID, 0, now); !ok || err != nil {
			t.Fatalf("passkey login %d after removal = %v, %v; want accepted", i, ok, err)
		}
	}
	if n := strings.Count(logs.String(), "level=ERROR"); n != 2 {
		t.Errorf("three logins, passkey logins and token uses after removing both files logged %d errors, want 2 (one per store); log = %q", n, logs.String())
	}
}

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
// it, and logged -- the behaviour the old persistLocked gave LastLogin. An op
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

// TestMutateInstallsTheFreshDocumentAnOpRefuses: the other process
// deletes bob and adds carol before this store's own deletion of bob
// saves. The replay finds no bob, so the write fails as it should --
// but the document it was refused against is what is out there now,
// and the store takes it: carol is in memory and the version matches
// the backend's, rather than memory still holding a bob the document
// has not had for some time.
func TestMutateInstallsTheFreshDocumentAnOpRefuses(t *testing.T) {
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
	other, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b.beforeSave = func() {
		if _, err := other.DeleteUser(bob.ID); err != nil {
			t.Errorf("the other process's DeleteUser: %v", err)
		}
		if _, err := other.CreateUser("carol", "password789", RoleUser, time.Now()); err != nil {
			t.Errorf("the other process's CreateUser: %v", err)
		}
	}

	if _, err := s.DeleteUser(bob.ID); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("DeleteUser of an account another process deleted first = %v, want ErrUserNotFound", err)
	}
	if storeHas(s, "bob") {
		t.Error("bob is still in memory after the replay found him gone")
	}
	if !storeHas(s, "carol") {
		t.Error("carol, in the document the replay was refused against, is missing from memory")
	}
	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s.mu.RLock()
	version := s.version
	s.mu.RUnlock()
	if version != snap.Version {
		t.Errorf("store holds version %d after taking the fresh document, backend is at %d", version, snap.Version)
	}
}

// TestTokenStoreReloadsBeforeAuthenticate: a token revoked through the
// CLI (a second store on the same document) stops authenticating on
// the running server at once -- with no write of the server's involved,
// since a token used in the last hour has nothing to save. Before #21
// the server kept accepting it until a restart.
func TestTokenStoreReloadsBeforeAuthenticate(t *testing.T) {
	m := persist.NewMemory()
	server, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	raw, tok, err := server.Create("a", TokenKindAPI, "", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := server.Authenticate(raw, TokenKindAPI, now); !ok {
		t.Fatal("the token does not authenticate before the revoke")
	}
	if err := cli.Revoke(tok.ID); err != nil {
		t.Fatalf("the CLI's Revoke: %v", err)
	}

	if _, ok := server.Authenticate(raw, TokenKindAPI, now.Add(time.Minute)); ok {
		t.Error("a token revoked by another process still authenticates on the running server")
	}
	if n := len(server.List()); n != 0 {
		t.Errorf("List() = %d tokens after another process revoked the only one, want 0", n)
	}
}

// TestTokenStoreReloadsOnAConflictingWrite: two TokenStores on one
// document, as a CLI and a live server would be. Before #21 the token
// store never reloaded, so the second store's Create saved its stale
// document on top and the first store's token was gone. The reload
// before the write now catches most of that; here the first store's
// Create is slipped in after that reload, so the second store's save
// is refused, and it must load the fresh document, add its token to
// that, and save -- both tokens authenticate from a store opened
// afterwards.
func TestTokenStoreReloadsOnAConflictingWrite(t *testing.T) {
	m := persist.NewMemory()
	b := &otherProcessBackend{Memory: m}
	first, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenTokenStore(b, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}

	var rawA string
	b.beforeSave = func() {
		raw, _, err := first.Create("a", TokenKindAPI, "", nil, time.Now())
		if err != nil {
			t.Errorf("the other process's Create: %v", err)
		}
		rawA = raw
	}
	rawB, _, err := second.Create("b", TokenKindAPI, "", nil, time.Now())
	if err != nil {
		t.Fatalf("Create across a conflicting write: %v", err)
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
	b := &conflictingBackend{Memory: persist.NewMemory(), allow: 1} // the first token
	s, err := OpenTokenStore(b, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Create("a", TokenKindAPI, "", nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	b.saves = 0
	raw, _, err := s.Create("b", TokenKindAPI, "", nil, time.Now())
	if !errors.Is(err, ErrSaveConflict) {
		t.Fatalf("Create against a backend that always conflicts = %v, want ErrSaveConflict", err)
	}
	if raw != "" {
		t.Error("a raw token value was handed out for a token that was never saved")
	}
	if b.saves != maxSaveAttempts {
		t.Errorf("saves = %d, want %d", b.saves, maxSaveAttempts)
	}
	if n := len(s.List()); n != 1 {
		t.Errorf("List() = %d tokens after a write that was never saved, want the 1 that was", n)
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

// timeType is skipped by the reference walk below: time.Time carries
// a *Location, shared by design and never written through.
var timeType = reflect.TypeOf(time.Time{})

// fillReferences gives every slice, map and pointer reachable from v --
// through struct fields, slice elements, map values and pointer
// targets -- a non-empty value, so a clone that shares any of them can
// be caught. An unexported reference field cannot be set from here and
// is reported, so a future one is noticed rather than silently skipped.
func fillReferences(t *testing.T, path string, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.Struct:
		if v.Type() == timeType {
			return
		}
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			name := path + "." + v.Type().Field(i).Name
			if !f.CanSet() {
				if hasReferences(f.Type()) {
					t.Errorf("%s is unexported and holds a slice, map or pointer: this test cannot fill it, so clone's handling of it is unchecked", name)
				}
				continue
			}
			fillReferences(t, name, f)
		}
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		fillReferences(t, path+"[0]", v.Index(0))
	case reflect.Map:
		v.Set(reflect.MakeMap(v.Type()))
		elem := reflect.New(v.Type().Elem()).Elem()
		fillReferences(t, path+"[key]", elem)
		v.SetMapIndex(reflect.Zero(v.Type().Key()), elem)
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fillReferences(t, "*"+path, v.Elem())
	}
}

// hasReferences reports whether typ holds a slice, map or pointer
// anywhere inside it (time.Time aside), so a struct copy of it would
// share memory with the original.
func hasReferences(typ reflect.Type) bool {
	switch typ.Kind() {
	case reflect.Slice, reflect.Map, reflect.Pointer:
		return true
	case reflect.Struct:
		if typ == timeType {
			return false
		}
		for i := 0; i < typ.NumField(); i++ {
			if hasReferences(typ.Field(i).Type) {
				return true
			}
		}
	case reflect.Array:
		return hasReferences(typ.Elem())
	}
	return false
}

// sharedReferences lists every slice, map or pointer found at the same
// place in a and b that points at the same memory.
func sharedReferences(path string, a, b reflect.Value) []string {
	var shared []string
	switch a.Kind() {
	case reflect.Struct:
		if a.Type() == timeType {
			return nil
		}
		for i := 0; i < a.NumField(); i++ {
			shared = append(shared, sharedReferences(path+"."+a.Type().Field(i).Name, a.Field(i), b.Field(i))...)
		}
	case reflect.Slice:
		if a.Len() > 0 && b.Len() > 0 && a.UnsafePointer() == b.UnsafePointer() {
			shared = append(shared, path)
		}
		for i := 0; i < min(a.Len(), b.Len()); i++ {
			shared = append(shared, sharedReferences(fmt.Sprintf("%s[%d]", path, i), a.Index(i), b.Index(i))...)
		}
	case reflect.Map:
		if !a.IsNil() && !b.IsNil() && a.UnsafePointer() == b.UnsafePointer() {
			shared = append(shared, path)
		}
		for _, key := range a.MapKeys() {
			if bv := b.MapIndex(key); bv.IsValid() {
				shared = append(shared, sharedReferences(fmt.Sprintf("%s[%v]", path, key), a.MapIndex(key), bv)...)
			}
		}
	case reflect.Pointer:
		if !a.IsNil() && !b.IsNil() {
			if a.UnsafePointer() == b.UnsafePointer() {
				shared = append(shared, path)
			} else {
				shared = append(shared, sharedReferences("*"+path, a.Elem(), b.Elem())...)
			}
		}
	}
	return shared
}

// TestCloneSharesNothingByReflection walks every field of the types the
// replay loop copies, rather than naming them by hand as
// TestStoreStateCloneIsDeep does: a slice, map or pointer added to User
// or Passkey that clone forgets fails here, and so does one added to
// RecoveryCode or Token, which have no clone of their own because a
// struct copy of them is a full copy -- true only while they hold no
// references at all.
func TestCloneSharesNothingByReflection(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(RecoveryCode{}), reflect.TypeOf(Token{})} {
		if hasReferences(typ) {
			t.Errorf("%s holds a slice, map or pointer: a struct copy of it is no longer a full copy, so User.clone or tokenState.clone must copy it by hand", typ)
		}
	}

	var u User
	fillReferences(t, "User", reflect.ValueOf(&u).Elem())
	if shared := sharedReferences("User", reflect.ValueOf(&u).Elem(), reflect.ValueOf(u.clone()).Elem()); len(shared) > 0 {
		t.Errorf("User.clone shares memory with the original at %v", shared)
	}

	var pk Passkey
	fillReferences(t, "Passkey", reflect.ValueOf(&pk).Elem())
	cp := pk.clone()
	if shared := sharedReferences("Passkey", reflect.ValueOf(&pk).Elem(), reflect.ValueOf(&cp).Elem()); len(shared) > 0 {
		t.Errorf("Passkey.clone shares memory with the original at %v", shared)
	}

	// The walk itself must see sharing when there is some, or a passing
	// run above proves nothing: a plain struct copy shares every slice.
	shallow := u
	if shared := sharedReferences("User", reflect.ValueOf(&u).Elem(), reflect.ValueOf(&shallow).Elem()); len(shared) == 0 {
		t.Error("the reference walk found nothing shared between a User and its struct copy, so it cannot catch a shallow clone")
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

// TestTokenStoreRevokeReplaysOnAConflictingWrite: the second store adds
// a token after the first store's staleness check and just before its
// revoke is saved, so the save meets a newer document. The revoke must
// be replayed against the document holding both, so the other store's
// token survives and the revoked one is gone.
func TestTokenStoreRevokeReplaysOnAConflictingWrite(t *testing.T) {
	m := persist.NewMemory()
	b := &otherProcessBackend{Memory: m}
	first, err := OpenTokenStore(b, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rawA, a, err := first.Create("a", TokenKindAPI, "", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var rawB string
	b.beforeSave = func() {
		if rawB, _, err = second.Create("b", TokenKindAPI, "", nil, time.Now()); err != nil {
			t.Errorf("the other store's Create: %v", err)
		}
	}

	if err := first.Revoke(a.ID); err != nil {
		t.Fatalf("Revoke across a conflicting write: %v", err)
	}
	if rawB == "" {
		t.Fatal("the other store wrote nothing, so the revoke met no conflict")
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
