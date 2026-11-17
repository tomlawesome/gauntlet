package persisttest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// The suite is only worth running if it fails a backend that breaks a
// promise. These tests run it against deliberately broken backends and
// pass when it fails them -- through fakeT, which records a check's
// failures instead of failing the real test -- and against correct ones
// to show it passes them (#61 acceptance).

func TestRunPassesMemory(t *testing.T) {
	Run(t, func(t testing.TB) func() persist.Backend {
		m := persist.NewMemory()
		return func() persist.Backend { return m }
	})
}

// flaw is one way a fake backend breaks the contract.
type flaw int

const (
	noFlaw flaw = iota
	// dropsWrites reports every Save as a success and stores nothing.
	dropsWrites
	// ignoresVersion writes whatever version the caller expected.
	ignoresVersion
	// cachesReads keeps the first document each backend loads and the
	// last one it wrote, and answers Load and Version from that, so a
	// second backend over the same storage never sees the first's
	// writes.
	cachesReads
	// racyCompareAndSwap checks the expected version, lets go of its
	// lock, then writes: correct alone, wrong when two writers overlap.
	racyCompareAndSwap
	// closeFails returns an error from Close.
	closeFails
	// reformatsBytes stores the document with its spaces removed, the way
	// a jsonb column normalises whitespace.
	reformatsBytes
	// emptyIsAbsent treats an empty document as no document: the version
	// moves on, but the store still reports it was never written.
	emptyIsAbsent
	// leftoverOnUnwritten answers a Load of a store never written with
	// bytes it does not have, though it says no document exists.
	leftoverOnUnwritten
)

func (f flaw) String() string {
	return [...]string{"noFlaw", "dropsWrites", "ignoresVersion", "cachesReads", "racyCompareAndSwap", "closeFails", "reformatsBytes", "emptyIsAbsent", "leftoverOnUnwritten"}[f]
}

// storage is what every fakeBackend over one store shares.
type storage struct {
	mu      sync.Mutex
	payload []byte
	version int64
	exists  bool
}

type fakeBackend struct {
	s    *storage
	flaw flaw

	mu    sync.Mutex
	cache *persist.Snapshot // cachesReads only
}

func (b *fakeBackend) Describe() string { return "fake " + b.flaw.String() }

func (b *fakeBackend) Close() error {
	if b.flaw == closeFails {
		return errors.New("fake close failure")
	}
	return nil
}

func (b *fakeBackend) Load(ctx context.Context) (persist.Snapshot, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.flaw == cachesReads && b.cache != nil {
		return *b.cache, nil
	}
	b.s.mu.Lock()
	snap := persist.Snapshot{Version: b.s.version, Exists: b.s.exists}
	if b.s.exists {
		snap.Payload = append([]byte{}, b.s.payload...)
	}
	b.s.mu.Unlock()
	if b.flaw == leftoverOnUnwritten && !snap.Exists {
		snap.Payload = []byte("leftover")
	}
	if b.flaw == cachesReads {
		b.cache = &snap
	}
	return snap, nil
}

func (b *fakeBackend) Version(ctx context.Context) (int64, bool, error) {
	snap, err := b.Load(ctx)
	return snap.Version, snap.Exists, err
}

func (b *fakeBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	s := b.s
	s.mu.Lock()
	if b.flaw != ignoresVersion && expect != s.version {
		s.mu.Unlock()
		return 0, persist.ErrConflict
	}
	if b.flaw == racyCompareAndSwap {
		// The window two writers that both passed the check above can
		// overlap in.
		s.mu.Unlock()
		time.Sleep(2 * time.Millisecond)
		s.mu.Lock()
	}
	defer s.mu.Unlock()
	next := s.version + 1
	if b.flaw == dropsWrites {
		return next, nil
	}
	s.payload, s.version, s.exists = append([]byte{}, payload...), next, true
	if b.flaw == reformatsBytes {
		s.payload = bytes.ReplaceAll(s.payload, []byte(" "), nil)
	}
	if b.flaw == emptyIsAbsent && len(payload) == 0 {
		s.exists = false
	}
	if b.flaw == cachesReads {
		b.mu.Lock()
		b.cache = &persist.Snapshot{Payload: append([]byte{}, payload...), Version: next, Exists: true}
		b.mu.Unlock()
	}
	return next, nil
}

func fakeStore(f flaw) func(testing.TB) func() persist.Backend {
	return func(testing.TB) func() persist.Backend {
		s := &storage{}
		return func() persist.Backend { return &fakeBackend{s: s, flaw: f} }
	}
}

// fakeT records what a check reports instead of failing the real test.
// Anything it does not override -- logging, TempDir -- goes to the real
// test.
type fakeT struct {
	testing.TB

	mu       sync.Mutex
	failures []string
	skipped  bool
	cleanups []func()
}

func (f *fakeT) Helper() {}

func (f *fakeT) record(msg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures = append(f.failures, msg)
}

func (f *fakeT) Error(args ...any)                 { f.record(fmt.Sprint(args...)) }
func (f *fakeT) Errorf(format string, args ...any) { f.record(fmt.Sprintf(format, args...)) }
func (f *fakeT) Fail()                             { f.record("Fail called") }
func (f *fakeT) FailNow()                          { f.Fail(); runtime.Goexit() }
func (f *fakeT) Fatal(args ...any)                 { f.Error(args...); runtime.Goexit() }
func (f *fakeT) Fatalf(format string, args ...any) { f.Errorf(format, args...); runtime.Goexit() }
func (f *fakeT) SkipNow()                          { f.skipped = true; runtime.Goexit() }
func (f *fakeT) Skip(args ...any)                  { f.SkipNow() }
func (f *fakeT) Skipf(string, ...any)              { f.SkipNow() }
func (f *fakeT) Skipped() bool                     { return f.skipped }
func (f *fakeT) Cleanup(fn func())                 { f.cleanups = append(f.cleanups, fn) }

func (f *fakeT) Failed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.failures) > 0
}

// runCheck runs one check against newStore the way Run's subtest would,
// on its own goroutine so Fatal and Skip can end it, cleanups last.
func runCheck(t *testing.T, c check, newStore func(testing.TB) func() persist.Backend) *fakeT {
	f := &fakeT{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			for i := len(f.cleanups) - 1; i >= 0; i-- {
				f.cleanups[i]()
			}
		}()
		c.run(f, newSuiteStore(f, newStore))
	}()
	<-done
	return f
}

// failingChecks runs the whole suite and returns the names of the checks
// that failed, logging what each one said.
func failingChecks(t *testing.T, newStore func(testing.TB) func() persist.Backend) []string {
	var failed []string
	for _, c := range checks {
		f := runCheck(t, c, newStore)
		if f.Failed() {
			failed = append(failed, c.name)
			t.Logf("%s: %q", c.name, f.failures)
		}
	}
	sort.Strings(failed)
	return failed
}

// The fakes are correct apart from their flaw: with none, nothing fails.
func TestSuitePassesTheFakeWithNoFlaw(t *testing.T) {
	if failed := failingChecks(t, fakeStore(noFlaw)); len(failed) != 0 {
		t.Fatalf("the suite failed a correct backend: %v", failed)
	}
}

func TestSuitePassesMemoryIncludingVersionReader(t *testing.T) {
	newStore := func(testing.TB) func() persist.Backend {
		m := persist.NewMemory()
		return func() persist.Backend { return m }
	}
	for _, c := range checks {
		f := runCheck(t, c, newStore)
		if f.Failed() || f.Skipped() {
			t.Errorf("%s against Memory: failures %q, skipped %v; want a pass", c.name, f.failures, f.Skipped())
		}
	}
}

func TestSuiteFailsEachBrokenBackend(t *testing.T) {
	const (
		roundTrip   = "SaveThenLoadReturnsTheSameBytesAndVersion"
		empty       = "AnEmptyDocumentStillExists"
		chain       = "EachSaveReturnsTheVersionTheNextSaveNeeds"
		stale       = "SaveWithAStaleVersionIsAConflict"
		unwritten   = "SaveExpectingADocumentThatWasNeverWrittenIsAConflict"
		create      = "CreateWhenTheDocumentExistsIsAConflict"
		second      = "ASecondBackendSeesWritesMadeThroughTheFirst"
		versionRead = "VersionReaderAgreesWithLoad"
		concurrent  = "OfTwoConcurrentWritersFromOneVersionExactlyOneWins"
		closeUnused = "CloseOfAnUnusedBackendSucceeds"
		load        = "LoadOfAnUnwrittenStoreIsEmpty"
	)
	cases := []struct {
		flaw flaw
		want []string // every check that must fail, and no others
	}{
		{dropsWrites, []string{roundTrip, empty, chain, stale, create, second, versionRead, concurrent}},
		{ignoresVersion, []string{stale, unwritten, create, second, concurrent}},
		{cachesReads, []string{second, versionRead, concurrent}},
		{racyCompareAndSwap, []string{concurrent}},
		{reformatsBytes, []string{roundTrip}},
		{emptyIsAbsent, []string{empty}},
		{leftoverOnUnwritten, []string{load}},
		{closeFails, []string{load, roundTrip, empty, chain, stale, unwritten, create, second, versionRead, concurrent, closeUnused}},
	}
	for _, c := range cases {
		t.Run(c.flaw.String(), func(t *testing.T) {
			want := slices.Clone(c.want)
			sort.Strings(want)
			if got := failingChecks(t, fakeStore(c.flaw)); !slices.Equal(got, want) {
				t.Errorf("failing checks = %v\nwant %v", got, want)
			}
		})
	}
}

// A store function that hands back nothing to open is the application's
// mistake, reported as such rather than as a nil-pointer panic.
func TestSuiteReportsAStoreFunctionThatOpensNothing(t *testing.T) {
	for name, newStore := range map[string]func(testing.TB) func() persist.Backend{
		"no opener":   func(testing.TB) func() persist.Backend { return nil },
		"nil backend": func(testing.TB) func() persist.Backend { return func() persist.Backend { return nil } },
	} {
		f := runCheck(t, checks[0], newStore)
		if !f.Failed() {
			t.Errorf("%s: the check passed, want it to report the store function", name)
		}
	}
}
