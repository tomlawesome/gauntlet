// Package persisttest is a ready-made test suite an application runs
// against its own persist.Backend, to prove it keeps the promises
// gauntlet's stores rely on (#61).
//
// Gauntlet trusts a successful Save: it never reads a document back
// after writing it. A backend that reports "saved" when it is not,
// ignores the expected version, or answers one process from a stale
// copy breaks a store without any error, and a read-back would not
// catch it either (a caching backend answers from its cache). This is
// where it is caught: once, in the application's own tests.
//
// Call Run from a _test.go file with a function that sets up fresh,
// empty storage and returns a way to open a backend over it. Run calls
// that function once for each check, then opens as many backends over
// the storage as the check needs -- two, for the checks that stand in
// for a CLI tool and a running server sharing one store:
//
//	func TestAccountsTableKeepsTheBackendContract(t *testing.T) {
//		persisttest.Run(t, func(t testing.TB) func() persist.Backend {
//			table := newEmptyTestTable(t) // the application's own helper
//			return func() persist.Backend { return NewTableBackend(table) }
//		})
//	}
//
// Each check is its own subtest, named for the promise it tests, so a
// failure says which promise the backend broke. Run closes every
// backend it opens when the check ends, and fails the check if Close
// returns an error.
//
// The documents it writes are JSON text, as a store's are; a backend
// must hand back exactly the bytes it was given, not a reformatted
// copy. The checks are the cases of mikroview's
// internal/persist/contract_test.go, which docs/design.md B1 used to
// tell applications to port by hand, plus the two-backend and
// concurrent-writer checks.
package persisttest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/tomlawesome/gauntlet/persist"
)

// Run runs every check against backends from newStore, each check as a
// subtest of t.
//
// newStore is called once per check, with that check's subtest, and
// must set up storage holding no document yet -- a new table, file or
// key, cleaned up through t when the check ends. The function it
// returns is then called once for each backend the check opens, and
// every backend it returns must reach that same storage, as two
// processes opened against one store would.
func Run(t *testing.T, newStore func(t testing.TB) func() persist.Backend) {
	t.Helper()
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			c.run(t, newSuiteStore(t, newStore))
		})
	}
}

// check is one promise the suite tests.
type check struct {
	name string
	run  func(t testing.TB, s *suiteStore)
}

// suiteStore is one check's storage.
type suiteStore struct {
	t    testing.TB
	open func() persist.Backend
}

func newSuiteStore(t testing.TB, newStore func(t testing.TB) func() persist.Backend) *suiteStore {
	t.Helper()
	open := newStore(t)
	if open == nil {
		t.Fatal("persisttest: the store function returned no way to open a backend")
	}
	return &suiteStore{t: t, open: open}
}

// rawBackend opens a backend the caller is responsible for closing.
func (s *suiteStore) rawBackend() persist.Backend {
	s.t.Helper()
	b := s.open()
	if b == nil {
		s.t.Fatal("persisttest: opening a backend returned nil")
	}
	return b
}

// backend opens a backend that is closed when the check ends.
func (s *suiteStore) backend() persist.Backend {
	s.t.Helper()
	b := s.rawBackend()
	s.t.Cleanup(func() {
		if err := b.Close(); err != nil {
			s.t.Errorf("Close of %s after use: %v", b.Describe(), err)
		}
	})
	return b
}

// checks is the suite, in the order Run runs it.
var checks = []check{
	{"LoadOfAnUnwrittenStoreIsEmpty", checkUnwrittenLoad},
	{"SaveThenLoadReturnsTheSameBytesAndVersion", checkRoundTrip},
	{"AnEmptyDocumentStillExists", checkEmptyDocument},
	{"EachSaveReturnsTheVersionTheNextSaveNeeds", checkChain},
	{"SaveWithAStaleVersionIsAConflict", checkStaleWrite},
	{"SaveExpectingADocumentThatWasNeverWrittenIsAConflict", checkExpectOnUnwritten},
	{"CreateWhenTheDocumentExistsIsAConflict", checkDoubleCreate},
	{"ASecondBackendSeesWritesMadeThroughTheFirst", checkSecondBackend},
	{"VersionReaderAgreesWithLoad", checkVersionReader},
	{"OfTwoConcurrentWritersFromOneVersionExactlyOneWins", checkConcurrentWriters},
	{"CloseOfAnUnusedBackendSucceeds", checkCloseUnused},
}

// concurrentRounds is how many times checkConcurrentWriters races two
// writers. A backend whose compare-and-swap is not atomic lets both
// through only when they overlap, so one round proves little; this many
// gives every round a fresh chance to overlap while keeping the check
// to well under a second against a disk-backed store.
const concurrentRounds = 50

func show(snap persist.Snapshot) string {
	return fmt.Sprintf("{Exists: %v, Version: %d, Payload: %.80q (%d bytes)}",
		snap.Exists, snap.Version, snap.Payload, len(snap.Payload))
}

func save(t testing.TB, b persist.Backend, payload string, expect int64) int64 {
	t.Helper()
	v, err := b.Save(context.Background(), []byte(payload), expect)
	if err != nil {
		t.Fatalf("Save(%.40q, expect %d) through %s: %v", payload, expect, b.Describe(), err)
	}
	if v == 0 {
		t.Fatalf("Save(%.40q, expect %d) returned version 0, which means \"nothing stored\"", payload, expect)
	}
	return v
}

func load(t testing.TB, b persist.Backend) persist.Snapshot {
	t.Helper()
	snap, err := b.Load(context.Background())
	if err != nil {
		t.Fatalf("Load through %s: %v", b.Describe(), err)
	}
	return snap
}

// wantStored fails t unless snap is payload at version.
func wantStored(t testing.TB, what string, snap persist.Snapshot, payload string, version int64) {
	t.Helper()
	if !snap.Exists || !bytes.Equal(snap.Payload, []byte(payload)) || snap.Version != version {
		t.Errorf("%s: Load = %s, want {Exists: true, Version: %d, Payload: %.80q}",
			what, show(snap), version, payload)
	}
}

func wantConflict(t testing.TB, what string, err error) {
	t.Helper()
	if !errors.Is(err, persist.ErrConflict) {
		t.Errorf("%s: Save returned %v, want persist.ErrConflict", what, err)
	}
}

func checkUnwrittenLoad(t testing.TB, s *suiteStore) {
	snap, err := s.backend().Load(context.Background())
	if err != nil {
		t.Fatalf("Load of a store never written: %v, want nil -- a missing document is the normal first run", err)
	}
	if snap.Exists || snap.Version != 0 || len(snap.Payload) != 0 {
		t.Errorf("Load of a store never written = %s, want Exists false, Version 0, no payload", show(snap))
	}
}

func checkRoundTrip(t testing.TB, s *suiteStore) {
	b := s.backend()
	// Spacing, key order and non-ASCII text a JSON column would
	// normalise: the bytes must come back exactly as given.
	const doc = `{"version": 1, "zeta": [1, 2.50],  "alpha": "café – ünïcode"}`
	v := save(t, b, doc, 0)
	wantStored(t, "after create", load(t, b), doc, v)
}

// An empty document is a real stored state, distinct from "never
// written".
func checkEmptyDocument(t testing.TB, s *suiteStore) {
	b := s.backend()
	v := save(t, b, "", 0)
	snap := load(t, b)
	if !snap.Exists || snap.Version != v || len(snap.Payload) != 0 {
		t.Errorf("Load after saving an empty document = %s, want Exists true, Version %d, no payload", show(snap), v)
	}
}

func checkChain(t testing.TB, s *suiteStore) {
	b := s.backend()
	doc := `{"n":0}`
	v := save(t, b, doc, 0)
	for i := 1; i <= 5; i++ {
		doc = fmt.Sprintf(`{"n":%d}`, i)
		next := save(t, b, doc, v)
		if next == v {
			t.Fatalf("write %d returned version %d, the same as the version it replaced", i, next)
		}
		v = next
	}
	wantStored(t, "after six chained writes", load(t, b), doc, v)
}

func checkStaleWrite(t testing.TB, s *suiteStore) {
	b := s.backend()
	v1 := save(t, b, `{"n":1}`, 0)
	v2 := save(t, b, `{"n":2}`, v1)
	_, err := b.Save(context.Background(), []byte(`{"n":3}`), v1)
	wantConflict(t, "writing with the version before the latest write", err)
	wantStored(t, "after the refused stale write", load(t, b), `{"n":2}`, v2)
}

func checkExpectOnUnwritten(t testing.TB, s *suiteStore) {
	b := s.backend()
	_, err := b.Save(context.Background(), []byte(`{"n":1}`), 42)
	wantConflict(t, "writing with version 42 to a store never written", err)
	if snap := load(t, b); snap.Exists {
		t.Errorf("the refused write landed: Load = %s, want nothing stored", show(snap))
	}
}

// Two processes starting together must not both believe they created
// the store.
func checkDoubleCreate(t testing.TB, s *suiteStore) {
	b := s.backend()
	v := save(t, b, `{"n":1}`, 0)
	_, err := b.Save(context.Background(), []byte(`{"n":2}`), 0)
	wantConflict(t, "creating (version 0) when a document exists", err)
	wantStored(t, "after the refused second create", load(t, b), `{"n":1}`, v)
}

// Stands in for a CLI tool and a running server: each must see the
// other's writes, and neither may write over one it has not seen.
func checkSecondBackend(t testing.TB, s *suiteStore) {
	first, second := s.backend(), s.backend()
	// The second backend reads before the first writes, as a server
	// does at start-up, so a backend that keeps what it read is caught.
	if snap := load(t, second); snap.Exists {
		t.Fatalf("Load through the second backend before any write = %s, want nothing stored", show(snap))
	}

	v1 := save(t, first, `{"from":"first"}`, 0)
	wantStored(t, "second backend after the first wrote", load(t, second), `{"from":"first"}`, v1)

	v2 := save(t, second, `{"from":"second"}`, v1)
	wantStored(t, "first backend after the second wrote", load(t, first), `{"from":"second"}`, v2)

	_, err := first.Save(context.Background(), []byte(`{"from":"first, stale"}`), v1)
	wantConflict(t, "first backend writing with the version the second backend replaced", err)
	wantStored(t, "second backend after the first's refused write", load(t, second), `{"from":"second"}`, v2)
}

// VersionReader is optional; gauntlet falls back to Load without it.
// Where it exists, gate polls it for staleness, so it must agree with
// Load across backends.
func checkVersionReader(t testing.TB, s *suiteStore) {
	first := s.backend()
	vr, ok := first.(persist.VersionReader)
	if !ok {
		t.Skip("backend does not implement persist.VersionReader; gauntlet falls back to Load")
	}
	if v, exists, err := vr.Version(context.Background()); err != nil || exists || v != 0 {
		t.Errorf("Version of a store never written = (%d, %v, %v), want (0, false, nil)", v, exists, err)
	}
	second, ok := s.backend().(persist.VersionReader)
	if !ok {
		t.Fatal("a second backend over the same store does not implement persist.VersionReader, though the first does")
	}
	// Read through the second before the write, as checkSecondBackend
	// does, so a reader that keeps its first answer is caught.
	_, _, _ = second.Version(context.Background())

	want := save(t, first, `{"n":1}`, 0)
	for name, r := range map[string]persist.VersionReader{"first": vr, "second": second} {
		v, exists, err := r.Version(context.Background())
		if err != nil || !exists || v != want {
			t.Errorf("Version through the %s backend after a write = (%d, %v, %v), want (%d, true, nil)",
				name, v, exists, err, want)
		}
	}
}

// Of two writers saving from the same version, exactly one may win and
// the other must get ErrConflict; the stored document is then the
// winner's, whole. Each writer has its own backend, as two processes
// would, and the two documents differ in size so a write that mixed
// them would be seen.
func checkConcurrentWriters(t testing.TB, s *suiteStore) {
	backends := [2]persist.Backend{s.backend(), s.backend()}
	v := save(t, backends[0], `{"round":-1}`, 0)

	type result struct {
		version int64
		err     error
	}
	for round := 0; round < concurrentRounds; round++ {
		docs := [2]string{
			fmt.Sprintf(`{"round":%d,"writer":0,"pad":"%s"}`, round, strings.Repeat("a", 64<<10)),
			fmt.Sprintf(`{"round":%d,"writer":1}`, round),
		}
		start := make(chan struct{})
		var results [2]result
		var wg sync.WaitGroup
		for i := range backends {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				version, err := backends[i].Save(context.Background(), []byte(docs[i]), v)
				results[i] = result{version, err}
			}(i)
		}
		close(start)
		wg.Wait()

		winner := -1
		for i, r := range results {
			switch {
			case r.err == nil && winner >= 0:
				t.Fatalf("round %d: both writers saving from version %d won -- one write silently replaced the other", round, v)
			case r.err == nil:
				winner, v = i, r.version
			case !errors.Is(r.err, persist.ErrConflict):
				t.Fatalf("round %d: writer %d failed with %v, want success or persist.ErrConflict", round, i, r.err)
			}
		}
		if winner < 0 {
			t.Fatalf("round %d: neither writer saving from version %d won, want exactly one", round, v)
		}
		snap := load(t, backends[1-winner])
		if !snap.Exists || snap.Version != v || !bytes.Equal(snap.Payload, []byte(docs[winner])) {
			t.Fatalf("round %d: writer %d won at version %d, but the other backend loads %s",
				round, winner, v, show(snap))
		}
	}
}

func checkCloseUnused(t testing.TB, s *suiteStore) {
	b := s.rawBackend()
	if err := b.Close(); err != nil {
		t.Errorf("Close of a backend never used: %v", err)
	}
}
