package gauntlet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// The sign-in history (#53, docs/adr/0006): a third sealed document,
// bounded by a row cap, folded and budgeted so a flood of attempts is a
// bounded number of rows and saves.

// signInBase is a fixed clock for history tests: the start of a
// 10-minute bucket, so bucket arithmetic in a test reads plainly.
var signInBase = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

// openTestHistory opens a history over b and closes it when the test
// ends, so no writer goroutine outlives its test.
func openTestHistory(t *testing.T, b persist.Backend, opts SignInHistoryOptions) *SignInHistory {
	t.Helper()
	h, err := OpenSignInHistory(b, opts)
	if err != nil {
		t.Fatalf("OpenSignInHistory: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

// shortenSignInIntervals sets the writer's save intervals for one test.
func shortenSignInIntervals(t *testing.T, newRows, folds time.Duration) {
	t.Helper()
	wasNew, wasFold := signInSaveInterval, signInFoldSaveInterval
	signInSaveInterval, signInFoldSaveInterval = newRows, folds
	t.Cleanup(func() { signInSaveInterval, signInFoldSaveInterval = wasNew, wasFold })
}

// failedFrom is a wrong-password event for name on account id from addr.
func failedFrom(id, name, addr string) SignInEvent {
	return SignInEvent{UserID: id, Username: name, Outcome: SignInWrongPassword, Method: SignInMethodPassword,
		Client: SessionClient{Address: addr, UserAgent: "test-agent/1.0"}}
}

// unknownFrom is a no-such-user event for a masked name.
func unknownFrom(typed, addr string) SignInEvent {
	return SignInEvent{Username: MaskUnknownUsername(typed), Outcome: SignInNoSuchUser, Method: SignInMethodPassword,
		Client: SessionClient{Address: addr}}
}

// successFrom is a completed sign-in.
func successFrom(id, name, addr string) SignInEvent {
	return SignInEvent{UserID: id, Username: name, Outcome: SignInSuccess, Method: SignInMethodPassword,
		Client: SessionClient{Address: addr}}
}

// signInCountingBackend is Memory counting saves and remembering when
// each began and what it stored.
type signInCountingBackend struct {
	*persist.Memory
	mu    sync.Mutex
	saves []time.Time
	last  []byte
}

func newSignInCountingBackend() *signInCountingBackend {
	return &signInCountingBackend{Memory: persist.NewMemory()}
}

func (b *signInCountingBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	b.mu.Lock()
	b.saves = append(b.saves, time.Now())
	b.last = append([]byte(nil), payload...)
	b.mu.Unlock()
	return b.Memory.Save(ctx, payload, expect)
}

func (b *signInCountingBackend) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.saves)
}

func (b *signInCountingBackend) times() []time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]time.Time(nil), b.saves...)
}

// waitFor polls cond until it holds or two seconds pass.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// storedSignIns decodes what b holds.
func storedSignIns(t *testing.T, b persist.Backend) signInFile {
	t.Helper()
	snap, err := b.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	var f signInFile
	if err := json.Unmarshal(snap.Payload, &f); err != nil {
		t.Fatalf("stored document: %v (%s)", err, snap.Payload)
	}
	return f
}

// One source repeating one failure within the fold span is one row
// whose count and until move; past the span it starts a new row.
func TestSignInHistoryFoldsWithinTheSpanOnly(t *testing.T) {
	h := openTestHistory(t, nil, SignInHistoryOptions{})
	ev := failedFrom("u1", "bob", "203.0.113.5")
	h.Record(ev, signInBase)
	h.Record(ev, signInBase.Add(time.Minute))
	h.Record(ev, signInBase.Add(9*time.Minute))

	rows, _ := h.List(SignInQuery{})
	if len(rows) != 1 {
		t.Fatalf("%d rows after three attempts in the span, want 1: %+v", len(rows), rows)
	}
	if r := rows[0]; r.Count != 3 || !r.At.Equal(signInBase) || !r.Until.Equal(signInBase.Add(9*time.Minute)) {
		t.Errorf("folded row = %+v, want count 3 from base to +9m", r)
	}

	h.Record(ev, signInBase.Add(10*time.Minute))
	rows, _ = h.List(SignInQuery{})
	if len(rows) != 2 || rows[0].Count != 1 {
		t.Fatalf("an attempt a span after the row began should start a new row: %+v", rows)
	}

	// A different address, outcome or method is a different row.
	h.Record(failedFrom("u1", "bob", "203.0.113.6"), signInBase.Add(10*time.Minute))
	other := ev
	other.Outcome = SignInFactorRefused
	h.Record(other, signInBase.Add(10*time.Minute))
	if total, _ := h.Summary(); total != 4 {
		t.Errorf("total = %d, want 4", total)
	}
}

// The fold keeps the row's first user agent, and an attempt that started
// a lockout is never folded into an earlier failure: the lockout is
// what the row is there to show.
func TestSignInHistoryFoldKeepsFirstAgentAndNeverFoldsALockout(t *testing.T) {
	h := openTestHistory(t, nil, SignInHistoryOptions{})
	ev := failedFrom("u1", "bob", "203.0.113.5")
	h.Record(ev, signInBase)
	second := ev
	second.Client.UserAgent = "other-agent"
	h.Record(second, signInBase.Add(time.Second))
	locking := ev
	locking.LockedUntil = signInBase.Add(time.Hour)
	h.Record(locking, signInBase.Add(2*time.Second))

	rows, _ := h.List(SignInQuery{})
	if len(rows) != 2 {
		t.Fatalf("%d rows, want the folded pair and the lockout: %+v", len(rows), rows)
	}
	if rows[1].Client.UserAgent != "test-agent/1.0" || rows[1].Count != 2 {
		t.Errorf("folded row = %+v, want the first agent and count 2", rows[1])
	}
	if !rows[0].LockedUntil.Equal(signInBase.Add(time.Hour)) || rows[0].Count != 1 {
		t.Errorf("lockout row = %+v", rows[0])
	}
}

// Failures share a budget of maxNewFailureRowsPerSpan new rows per
// 10-minute bucket; beyond it they fold into one unrecorded row that
// carries only the count and times. Successes are never budgeted.
func TestSignInHistoryBudgetsFailureRowsPerBucket(t *testing.T) {
	h := openTestHistory(t, nil, SignInHistoryOptions{})
	for i := range maxNewFailureRowsPerSpan + 250 {
		h.Record(unknownFrom(fmt.Sprintf("sprayed-name-%d", i), fmt.Sprintf("192.0.2.%d", i%250)), signInBase.Add(time.Duration(i)*time.Millisecond))
	}
	for i := range 20 {
		h.Record(successFrom(fmt.Sprintf("u%d", i), fmt.Sprintf("user%d", i), "198.51.100.7"), signInBase.Add(time.Second))
	}
	total, _ := h.Summary()
	if want := maxNewFailureRowsPerSpan + 1 + 20; total != want {
		t.Fatalf("total = %d, want %d (budget, one unrecorded row, 20 successes)", total, want)
	}
	rows, _ := h.List(SignInQuery{Outcome: SignInUnrecorded})
	if len(rows) != 1 {
		t.Fatalf("%d unrecorded rows, want 1", len(rows))
	}
	u := rows[0]
	if u.Count != 250 || u.Username != "" || u.UserID != "" || u.Method != "" || u.Client != (SessionClient{}) {
		t.Errorf("unrecorded row = %+v, want count 250 and nothing else", u)
	}

	// The next bucket has a fresh budget and its own unrecorded row.
	next := signInBase.Add(signInFoldSpan)
	for i := range maxNewFailureRowsPerSpan + 1 {
		h.Record(unknownFrom(fmt.Sprintf("next-%d", i), fmt.Sprintf("198.18.0.%d", i)), next)
	}
	rows, _ = h.List(SignInQuery{Outcome: SignInUnrecorded})
	if len(rows) != 2 || rows[0].Count != 1 {
		t.Errorf("unrecorded rows = %+v, want a second with count 1", rows)
	}
}

// The cap keeps the newest MaxRows rows; since moves with the oldest.
func TestSignInHistoryCapDropsTheOldest(t *testing.T) {
	h := openTestHistory(t, nil, SignInHistoryOptions{MaxRows: 5})
	for i := range 8 {
		h.Record(successFrom("u1", "bob", fmt.Sprintf("192.0.2.%d", i)), signInBase.Add(time.Duration(i)*time.Minute))
	}
	total, since := h.Summary()
	if total != 5 || !since.Equal(signInBase.Add(3*time.Minute)) {
		t.Errorf("Summary = %d since %s, want 5 since +3m", total, since)
	}
	rows, _ := h.List(SignInQuery{})
	if rows[0].Seq != 8 || rows[4].Seq != 4 {
		t.Errorf("rows run from seq %d to %d, want 8 to 4", rows[0].Seq, rows[4].Seq)
	}
}

// TestOpenSignInHistoryLoweredMaxRowsLogsTheDrop pins gauntlet#58 S3:
// opening over a document that already holds more rows than a newly
// lowered MaxRows drops the oldest ones in memory (saved so at the
// next save) with nothing logged, so an operator who tightens MaxRows
// gets no record that history was actually lost.
func TestOpenSignInHistoryLoweredMaxRowsLogsTheDrop(t *testing.T) {
	b := persist.NewMemory()
	h := openTestHistory(t, b, SignInHistoryOptions{MaxRows: 10})
	for i := range 8 {
		h.Record(successFrom("u1", "bob", fmt.Sprintf("192.0.2.%d", i)), signInBase.Add(time.Duration(i)*time.Minute))
	}
	if err := h.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}

	logs := &signInLogRecorder{}
	h2 := openTestHistory(t, b, SignInHistoryOptions{MaxRows: 5, Log: slog.New(logs)})
	total, _ := h2.Summary()
	if total != 5 {
		t.Fatalf("Summary total = %d, want 5", total)
	}
	if n := logs.count("MaxRows"); n != 1 {
		t.Errorf("messages mentioning MaxRows = %d, want exactly 1 logging the drop: %v", n, logs.all())
	}
}

// MaxRows: zero is the default, above the ceiling or negative refused.
func TestOpenSignInHistoryMaxRows(t *testing.T) {
	h := openTestHistory(t, nil, SignInHistoryOptions{})
	if h.maxRows != DefaultMaxSignInRows || DefaultMaxSignInRows != 10_000 || MaxSignInRows != 50_000 {
		t.Errorf("default %d (const %d), ceiling %d", h.maxRows, DefaultMaxSignInRows, MaxSignInRows)
	}
	if _, err := OpenSignInHistory(nil, SignInHistoryOptions{MaxRows: MaxSignInRows}); err != nil {
		t.Errorf("the ceiling itself refused: %v", err)
	}
	for _, n := range []int{MaxSignInRows + 1, -1} {
		if _, err := OpenSignInHistory(nil, SignInHistoryOptions{MaxRows: n}); err == nil {
			t.Errorf("MaxRows %d accepted", n)
		}
	}
}

// Seq only goes up: folds take none, and a reopened history carries on
// from the stored nextSeq.
func TestSignInHistorySeqIsMonotonicAcrossFoldsAndRestarts(t *testing.T) {
	b := persist.NewMemory()
	h := openTestHistory(t, b, SignInHistoryOptions{})
	h.Record(successFrom("u1", "bob", "192.0.2.1"), signInBase)
	h.Record(successFrom("u1", "bob", "192.0.2.1"), signInBase.Add(time.Second)) // folds
	h.Record(successFrom("u1", "bob", "192.0.2.2"), signInBase.Add(2*time.Second))
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	again := openTestHistory(t, b, SignInHistoryOptions{})
	again.Record(successFrom("u1", "bob", "192.0.2.1"), signInBase.Add(3*time.Second)) // the fold index starts fresh
	rows, _ := again.List(SignInQuery{})
	var seqs []uint64
	for _, r := range rows {
		seqs = append(seqs, r.Seq)
	}
	if fmt.Sprint(seqs) != "[3 2 1]" {
		t.Errorf("seqs = %v, want [3 2 1]", seqs)
	}
	if rows[2].Count != 2 {
		t.Errorf("first row count = %d after reopening, want 2", rows[2].Count)
	}
}

// List: newest first, filtered by account, address and outcome, paged
// by before with more, the limit defaulted and capped.
func TestSignInHistoryList(t *testing.T) {
	h := openTestHistory(t, nil, SignInHistoryOptions{})
	for i := range 300 {
		at := signInBase.Add(time.Duration(i) * signInFoldSpan) // no folding
		switch i % 3 {
		case 0:
			h.Record(successFrom("u1", "bob", "192.0.2.1"), at)
		case 1:
			h.Record(failedFrom("u2", "carol", "192.0.2.2"), at)
		default:
			h.Record(unknownFrom("someone", "192.0.2.3"), at)
		}
	}
	rows, more := h.List(SignInQuery{})
	if len(rows) != DefaultSignInListLimit || !more || rows[0].Seq != 300 {
		t.Fatalf("default page: %d rows, more %v, first seq %d", len(rows), more, rows[0].Seq)
	}
	rows, more = h.List(SignInQuery{Limit: 1000})
	if len(rows) != MaxSignInListLimit || !more {
		t.Errorf("an over-large limit gave %d rows, more %v; want %d and more", len(rows), more, MaxSignInListLimit)
	}
	rows, more = h.List(SignInQuery{Before: 11, Limit: 10})
	if len(rows) != 10 || more || rows[0].Seq != 10 || rows[9].Seq != 1 {
		t.Errorf("before 11: %d rows from %d, more %v", len(rows), rows[0].Seq, more)
	}
	rows, _ = h.List(SignInQuery{UserID: "u2", Limit: 200})
	if len(rows) != 100 {
		t.Errorf("user filter: %d rows, want 100", len(rows))
	}
	for _, r := range rows {
		if r.UserID != "u2" {
			t.Fatalf("user filter let through %+v", r)
		}
	}
	rows, _ = h.List(SignInQuery{Address: "192.0.2.3", Outcome: SignInNoSuchUser, Limit: 200})
	if len(rows) != 100 || rows[0].Username != "so•••••" {
		t.Errorf("address and outcome filter: %d rows, first %+v", len(rows), rows[0])
	}
	rows, more = h.List(SignInQuery{Address: "192.0.2.3", Outcome: SignInSuccess})
	if len(rows) != 0 || more {
		t.Errorf("no row matches both, got %d", len(rows))
	}
}

// Summary of an empty history: nothing held, since zero.
func TestSignInHistorySummaryEmpty(t *testing.T) {
	h := openTestHistory(t, nil, SignInHistoryOptions{})
	if total, since := h.Summary(); total != 0 || !since.IsZero() {
		t.Errorf("Summary = %d, %s", total, since)
	}
}

// Record cleans the client the way a session's is cleaned: control
// characters dropped, the agent and address cut.
func TestSignInHistoryCleansTheClient(t *testing.T) {
	h := openTestHistory(t, nil, SignInHistoryOptions{})
	ev := successFrom("u1", "bob", "192.0.2.1\n"+strings.Repeat("9", 100))
	ev.Client.UserAgent = "agent\x1b[31m" + strings.Repeat("a", 400)
	h.Record(ev, signInBase)
	rows, _ := h.List(SignInQuery{})
	c := rows[0].Client
	if strings.ContainsAny(c.Address+c.UserAgent, "\n\x1b") || len(c.Address) > MaxSessionAddress || len(c.UserAgent) > MaxSessionUserAgent {
		t.Errorf("client not cleaned: %+v", c)
	}
}

// A nil backend is memory only: usable, says so, nothing to flush.
func TestSignInHistoryWithoutBackendIsMemoryOnly(t *testing.T) {
	h := openTestHistory(t, nil, SignInHistoryOptions{})
	h.Record(successFrom("u1", "bob", "192.0.2.1"), signInBase)
	if h.Persisted() || !strings.Contains(h.Describe(), "memory only") {
		t.Errorf("Persisted %v, Describe %q", h.Persisted(), h.Describe())
	}
	if err := h.Flush(context.Background()); err != nil {
		t.Errorf("Flush: %v", err)
	}
	if total, _ := h.Summary(); total != 1 {
		t.Errorf("total %d", total)
	}
}

// The writer saves a new row no sooner than signInSaveInterval after
// the last save, and a count bump no sooner than signInFoldSaveInterval.
func TestSignInHistoryWriterSaveIntervals(t *testing.T) {
	shortenSignInIntervals(t, 40*time.Millisecond, 200*time.Millisecond)
	b := newSignInCountingBackend()
	h := openTestHistory(t, b, SignInHistoryOptions{})

	h.Record(successFrom("u1", "bob", "192.0.2.1"), signInBase)
	waitFor(t, "the first save", func() bool { return b.count() == 1 })
	h.Record(successFrom("u1", "bob", "192.0.2.2"), signInBase)
	waitFor(t, "the second save", func() bool { return b.count() == 2 })
	h.Record(successFrom("u1", "bob", "192.0.2.2"), signInBase.Add(time.Second)) // a fold
	waitFor(t, "the fold's save", func() bool { return b.count() == 3 })

	at := b.times()
	if gap := at[1].Sub(at[0]); gap < signInSaveInterval*9/10 {
		t.Errorf("a new row was saved %s after the last save, want at least %s", gap, signInSaveInterval)
	}
	if gap := at[2].Sub(at[1]); gap < signInFoldSaveInterval*9/10 {
		t.Errorf("a fold was saved %s after the last save, want at least %s", gap, signInFoldSaveInterval)
	}
	if f := storedSignIns(t, b); len(f.Rows) != 2 || f.Rows[1].Count != 2 || f.NextSeq != 3 {
		t.Errorf("stored = %+v", f)
	}
}

// Flush saves now; Close flushes and stops the writer; a clean history
// saves nothing.
func TestSignInHistoryFlushAndClose(t *testing.T) {
	shortenSignInIntervals(t, time.Hour, time.Hour)
	b := newSignInCountingBackend()
	h, err := OpenSignInHistory(b, SignInHistoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h.Record(successFrom("u1", "bob", "192.0.2.1"), signInBase)
	waitFor(t, "the first save", func() bool { return b.count() == 1 })
	h.Record(successFrom("u1", "bob", "192.0.2.2"), signInBase)
	if err := h.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if b.count() != 2 {
		t.Fatalf("%d saves after Flush, want 2", b.count())
	}
	if err := h.Flush(context.Background()); err != nil || b.count() != 2 {
		t.Errorf("a clean Flush saved (count %d, err %v)", b.count(), err)
	}
	h.Record(successFrom("u1", "bob", "192.0.2.3"), signInBase)
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if b.count() != 3 || len(storedSignIns(t, b).Rows) != 3 {
		t.Errorf("Close did not flush: %d saves", b.count())
	}
	select {
	case <-h.done:
	default:
		t.Error("the writer is still running after Close")
	}
	if err := h.Close(); err != nil {
		t.Errorf("a second Close: %v", err)
	}
}

// floodPace records n events from ev(i) over about wall, the simulated
// clock covering ten minutes, and returns how long it really took.
func floodPace(h *SignInHistory, n int, wall time.Duration, ev func(i int) SignInEvent) time.Duration {
	start := time.Now()
	step := 10 * time.Minute / time.Duration(n)
	for i := range n {
		if i%500 == 0 {
			if ahead := time.Duration(int64(wall)*int64(i)/int64(n)) - time.Since(start); ahead > 0 {
				time.Sleep(ahead)
			}
		}
		h.Record(ev(i), signInBase.Add(time.Duration(i)*step))
	}
	return time.Since(start)
}

// maxSavesIn is the most saves the writer may make in elapsed with
// newRows new rows to save: one per new row at most, and no more than
// one per signInSaveInterval; plus one per signInFoldSaveInterval for
// count bumps, and the first save, which waits for nothing.
func maxSavesIn(elapsed time.Duration, newRows int) int {
	byNew := min(newRows, int(elapsed/signInSaveInterval)+1)
	return byNew + int(elapsed/signInFoldSaveInterval) + 1
}

// The flood the design names: 100,000 made-up names from many addresses
// in ten minutes is at most 101 rows, and at the real intervals scaled
// down a thousandfold, about 120 saves at most.
func TestSignInHistoryDistinctNameFloodIsBounded(t *testing.T) {
	shortenSignInIntervals(t, 5*time.Millisecond, 60*time.Millisecond)
	b := newSignInCountingBackend()
	h := openTestHistory(t, b, SignInHistoryOptions{})
	elapsed := floodPace(h, 100_000, 600*time.Millisecond, func(i int) SignInEvent {
		return unknownFrom(fmt.Sprintf("spray-%06d", i), fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
	})
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	total, _ := h.Summary()
	if total > maxNewFailureRowsPerSpan+1 {
		t.Errorf("%d rows after the flood, want at most %d", total, maxNewFailureRowsPerSpan+1)
	}
	limit := maxSavesIn(elapsed, total) + 1 // + Close's flush
	if n := b.count(); n > limit || n > 125 && elapsed < 700*time.Millisecond {
		t.Errorf("%d saves in %s, want at most %d", n, elapsed, limit)
	}
	rows, _ := h.List(SignInQuery{Outcome: SignInUnrecorded})
	if len(rows) != 1 || rows[0].Count != 100_000-maxNewFailureRowsPerSpan {
		t.Errorf("unrecorded rows = %+v", rows)
	}
}

// One source hammering one name for ten minutes is one row, and the
// saves after the first are count bumps: about one a minute.
func TestSignInHistoryFoldOnlyFloodIsBounded(t *testing.T) {
	shortenSignInIntervals(t, 5*time.Millisecond, 60*time.Millisecond)
	b := newSignInCountingBackend()
	h := openTestHistory(t, b, SignInHistoryOptions{})
	ev := failedFrom("u1", "bob", "203.0.113.9")
	elapsed := floodPace(h, 50_000, 600*time.Millisecond, func(int) SignInEvent { return ev })
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	total, _ := h.Summary()
	if total > 2 {
		t.Errorf("%d rows for one repeated failure over ten minutes, want at most 2", total)
	}
	limit := maxSavesIn(elapsed, total) + 1
	if n := b.count(); n > limit || n > 13 && elapsed < 700*time.Millisecond {
		t.Errorf("%d saves in %s, want at most %d", n, elapsed, limit)
	}
}

// Another writer saved first: the save reloads, re-appends the rows this
// process added since its last save, renumbered, and saves again.
func TestSignInHistoryConflictReplaysUnsavedRows(t *testing.T) {
	shortenSignInIntervals(t, time.Hour, time.Hour)
	b := persist.NewMemory()
	first := openTestHistory(t, b, SignInHistoryOptions{})
	first.Record(successFrom("u1", "bob", "192.0.2.1"), signInBase)
	waitFor(t, "the first save", func() bool { return len(storedSignInsQuiet(b).Rows) == 1 })

	second := openTestHistory(t, b, SignInHistoryOptions{})
	second.Record(successFrom("u2", "carol", "192.0.2.2"), signInBase.Add(time.Minute))
	if err := second.Flush(context.Background()); err != nil {
		t.Fatalf("second Flush: %v", err)
	}

	first.Record(successFrom("u3", "dave", "192.0.2.3"), signInBase.Add(2*time.Minute))
	if err := first.Flush(context.Background()); err != nil {
		t.Fatalf("first Flush after the other writer: %v", err)
	}
	f := storedSignIns(t, b)
	var got []string
	for _, r := range f.Rows {
		got = append(got, fmt.Sprintf("%d:%s", r.Seq, r.Username))
	}
	if strings.Join(got, " ") != "1:bob 2:carol 3:dave" || f.NextSeq != 4 {
		t.Errorf("stored rows = %v (nextSeq %d), want bob, carol, dave numbered 1-3", got, f.NextSeq)
	}
	rows, _ := first.List(SignInQuery{})
	if len(rows) != 3 || rows[0].Seq != 3 || rows[0].Username != "dave" {
		t.Errorf("memory after the replay = %+v", rows)
	}
	// And the next save goes on from there without another conflict.
	first.Record(successFrom("u4", "erin", "192.0.2.4"), signInBase.Add(3*time.Minute))
	if err := first.Flush(context.Background()); err != nil {
		t.Fatalf("Flush after the replay: %v", err)
	}
	if f := storedSignIns(t, b); len(f.Rows) != 4 || f.Rows[3].Seq != 4 {
		t.Errorf("stored after the replay = %+v", f.Rows)
	}
}

func storedSignInsQuiet(b persist.Backend) signInFile {
	var f signInFile
	if snap, err := b.Load(context.Background()); err == nil && snap.Exists {
		_ = json.Unmarshal(snap.Payload, &f)
	}
	return f
}

// removableBackend is Memory whose document can be taken away, as an
// operator moving the file aside would.
type removableBackend struct {
	*persist.Memory
	removed atomic.Bool
}

func (b *removableBackend) Load(ctx context.Context) (persist.Snapshot, error) {
	if b.removed.Load() {
		return persist.Snapshot{}, nil
	}
	return b.Memory.Load(ctx)
}

func (b *removableBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	if b.removed.Load() {
		return 0, persist.ErrConflict
	}
	return b.Memory.Save(ctx, payload, expect)
}

// A removed document keeps the history in memory, fails each save with
// ErrDocumentRemoved and is logged once until a save succeeds.
func TestSignInHistoryRemovedDocumentLogsOnceAndKeepsMemory(t *testing.T) {
	shortenSignInIntervals(t, time.Hour, time.Hour)
	b := &removableBackend{Memory: persist.NewMemory()}
	logs := &signInLogRecorder{}
	h := openTestHistory(t, b, SignInHistoryOptions{Log: slog.New(logs)})
	h.Record(successFrom("u1", "bob", "192.0.2.1"), signInBase)
	if err := h.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	b.removed.Store(true)
	for i := range 3 {
		h.Record(successFrom("u1", "bob", fmt.Sprintf("192.0.2.%d", 10+i)), signInBase)
		if err := h.Flush(context.Background()); !errors.Is(err, ErrDocumentRemoved) {
			t.Fatalf("Flush %d: %v, want ErrDocumentRemoved", i, err)
		}
	}
	if n := logs.count("removed"); n != 1 {
		t.Errorf("%d lines about the removal, want 1: %v", n, logs.all())
	}
	if total, _ := h.Summary(); total != 4 {
		t.Errorf("memory holds %d rows, want 4", total)
	}
}

// signInLogRecorder keeps every message logged.
type signInLogRecorder struct {
	mu   sync.Mutex
	msgs []string
}

func (r *signInLogRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *signInLogRecorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, rec.Message)
	return nil
}
func (r *signInLogRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *signInLogRecorder) WithGroup(string) slog.Handler      { return r }

func (r *signInLogRecorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.msgs...)
}

func (r *signInLogRecorder) count(substr string) int {
	n := 0
	for _, m := range r.all() {
		if strings.Contains(m, substr) {
			n++
		}
	}
	return n
}

// A document newer than this build reads, a sealed envelope reaching an
// unwrapped backend, and one that does not hold together are refused.
func TestOpenSignInHistoryRefusesWhatItCannotRead(t *testing.T) {
	cases := map[string]string{
		"newer version":     `{"version":2,"nextSeq":1,"rows":[]}`,
		"sealed":            `{"sealed":"AAAA"}`,
		"rows out of order": `{"version":1,"nextSeq":3,"rows":[{"seq":2,"at":"2026-10-02T12:00:00Z","until":"2026-10-02T12:00:00Z","count":1,"outcome":"success"},{"seq":1,"at":"2026-10-02T12:00:00Z","until":"2026-10-02T12:00:00Z","count":1,"outcome":"success"}]}`,
		"seq past nextSeq":  `{"version":1,"nextSeq":1,"rows":[{"seq":1,"at":"2026-10-02T12:00:00Z","until":"2026-10-02T12:00:00Z","count":1,"outcome":"success"}]}`,
		"not json":          `{`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			m := persist.NewMemory()
			primeMemory(t, m, doc)
			if h, err := OpenSignInHistory(m, SignInHistoryOptions{}); err == nil {
				_ = h.Close()
				t.Fatal("opened")
			}
		})
	}
	m := persist.NewMemory()
	primeMemory(t, m, `{"version":2,"nextSeq":1,"rows":[]}`)
	if _, err := OpenSignInHistory(m, SignInHistoryOptions{}); !errors.Is(err, errNewerDocument) {
		t.Errorf("newer document: %v, want errNewerDocument", err)
	}
	m = persist.NewMemory()
	primeMemory(t, m, `{"sealed":"AAAA"}`)
	if _, err := OpenSignInHistory(m, SignInHistoryOptions{}); !errors.Is(err, errSealedDocument) {
		t.Errorf("sealed document: %v, want errSealedDocument", err)
	}
}

// A backend that stores plaintext is refused unless the application
// accepts it; the refusal comes before the backend is read.
func TestOpenSignInHistoryRefusesPlaintextAtRest(t *testing.T) {
	b := &plaintextBackend{inner: persist.NewMemory()}
	_, err := OpenSignInHistory(b, SignInHistoryOptions{})
	if !errors.Is(err, ErrPlaintextAtRest) || b.loads != 0 {
		t.Fatalf("err %v after %d loads, want ErrPlaintextAtRest before any", err, b.loads)
	}
	if !strings.Contains(err.Error(), "sign-in history") {
		t.Errorf("the refusal does not name the sign-in history: %v", err)
	}
	openTestHistory(t, b, SignInHistoryOptions{AllowPlaintextAtRest: true})
}

// Sealed under persist.Encrypt with its own label, the stored bytes
// carry no address, agent or name; and a history opens what it sealed.
func TestSignInHistoryOverEncryptKeepsRowsOutOfStorage(t *testing.T) {
	inner := newSignInCountingBackend()
	enc, err := persist.Encrypt(inner, testEncryptKey(), persist.EncryptOptions{Label: "signins"})
	if err != nil {
		t.Fatal(err)
	}
	h := openTestHistory(t, enc, SignInHistoryOptions{})
	ev := unknownFrom("Hunter2024-secret", "203.0.113.77")
	ev.Client.UserAgent = "Distinctive-Agent/9"
	h.Record(ev, signInBase)
	h.Record(successFrom("u1", "carolyn-the-admin", "203.0.113.78"), signInBase)
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	inner.mu.Lock()
	stored := inner.last
	inner.mu.Unlock()
	for _, secret := range []string{"203.0.113", "Distinctive-Agent", "carolyn", "Hu•", "Hunter2024"} {
		if bytes.Contains(stored, []byte(secret)) {
			t.Errorf("the stored bytes contain %q", secret)
		}
	}
	again := openTestHistory(t, enc, SignInHistoryOptions{})
	if total, _ := again.Summary(); total != 2 {
		t.Errorf("reopened over the same key: %d rows", total)
	}
}

// testdata/signins-v1.json is a version-1 document as this build writes
// it: it loads, lists as written, and saves back to the same JSON.
func TestSignInHistoryVersion1FixtureRoundTrips(t *testing.T) {
	raw, err := os.ReadFile("testdata/signins-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	m := persist.NewMemory()
	primeMemory(t, m, string(raw))
	h := openTestHistory(t, m, SignInHistoryOptions{})
	total, since := h.Summary()
	if total != 4 || !since.Equal(time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("Summary = %d since %s", total, since)
	}
	rows, _ := h.List(SignInQuery{})
	want := []SignInRow{
		{Seq: 7, At: time.Date(2026, 10, 2, 9, 30, 0, 0, time.UTC), Until: time.Date(2026, 10, 2, 9, 35, 0, 0, time.UTC), Count: 412, Outcome: SignInUnrecorded},
		{Seq: 6, At: time.Date(2026, 10, 2, 9, 20, 0, 0, time.UTC), Until: time.Date(2026, 10, 2, 9, 20, 0, 0, time.UTC), Count: 1, Username: "Hu••••••••", Outcome: SignInNoSuchUser, Method: SignInMethodPassword, Client: SessionClient{Address: "203.0.113.9"}},
		{Seq: 5, At: time.Date(2026, 10, 2, 9, 10, 0, 0, time.UTC), Until: time.Date(2026, 10, 2, 9, 14, 0, 0, time.UTC), Count: 5, UserID: "1f0c6a3e", Username: "bob", Outcome: SignInWrongPassword, Method: SignInMethodPassword, Client: SessionClient{Address: "198.51.100.4", UserAgent: "Mozilla/5.0 (X11; Linux x86_64)"}, LockedUntil: time.Date(2026, 10, 2, 9, 29, 0, 0, time.UTC), Disabled: false},
		{Seq: 3, At: time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC), Until: time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC), Count: 1, UserID: "7d2e9b10", Username: "admin", Outcome: SignInSuccess, Method: SignInMethodCode, Client: SessionClient{Address: "2001:db8::1", UserAgent: "Mozilla/5.0"}},
	}
	if fmt.Sprintf("%+v", rows) != fmt.Sprintf("%+v", want) {
		t.Errorf("rows =\n%+v\nwant\n%+v", rows, want)
	}

	// Saved back unchanged in meaning.
	h.Record(successFrom("u1", "bob", "192.0.2.1"), signInBase)
	if err := h.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := storedSignIns(t, m)
	if f.Version != 1 || f.NextSeq != 9 || len(f.Rows) != 5 || f.Rows[4].Seq != 8 {
		t.Errorf("saved document: version %d, nextSeq %d, %d rows", f.Version, f.NextSeq, len(f.Rows))
	}
	var before, after map[string]any
	_ = json.Unmarshal(raw, &before)
	reencoded, _ := json.Marshal(signInFile{Version: f.Version, NextSeq: 8, Rows: f.Rows[:4]})
	_ = json.Unmarshal(reencoded, &after)
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Errorf("the fixture's rows did not save back as they were:\n%v\n%v", before, after)
	}
}

// A slow save holds no lock Record needs: rows go on being recorded
// while one is in flight.
func TestSignInHistorySlowSaveDoesNotBlockRecord(t *testing.T) {
	b := &blockingSaveBackend{Memory: persist.NewMemory(), entered: make(chan struct{}, 1), release: make(chan struct{})}
	h := openTestHistory(t, b, SignInHistoryOptions{})
	h.Record(successFrom("u1", "bob", "192.0.2.1"), signInBase)
	select {
	case <-b.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the writer never started a save")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 100 {
			h.Record(successFrom("u1", "bob", fmt.Sprintf("192.0.2.%d", i+2)), signInBase)
			h.List(SignInQuery{})
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Record waited behind a save in flight")
	}
	close(b.release)
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if f := storedSignIns(t, b); len(f.Rows) != 101 {
		t.Errorf("%d rows stored after Close, want 101", len(f.Rows))
	}
}

// blockingSaveBackend holds every Save until release is closed, saying
// on entered when one starts.
type blockingSaveBackend struct {
	*persist.Memory
	entered chan struct{}
	release chan struct{}
}

func (b *blockingSaveBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-b.release
	return b.Memory.Save(ctx, payload, expect)
}

// Concurrent Record, List and Flush are safe (run under -race).
func TestSignInHistoryConcurrentUse(t *testing.T) {
	shortenSignInIntervals(t, time.Millisecond, 5*time.Millisecond)
	h := openTestHistory(t, persist.NewMemory(), SignInHistoryOptions{MaxRows: 500})
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 300 {
				h.Record(successFrom(fmt.Sprintf("u%d", w), "bob", fmt.Sprintf("192.0.2.%d", i)), signInBase.Add(time.Duration(i)*time.Second))
				if i%50 == 0 {
					h.List(SignInQuery{UserID: "u1"})
					h.Summary()
					_ = h.Flush(context.Background())
				}
			}
		}()
	}
	wg.Wait()
	total, _ := h.Summary()
	if total != 500 {
		t.Errorf("total = %d, want the cap of 500", total)
	}
	rows, _ := h.List(SignInQuery{Limit: MaxSignInListLimit})
	for i := 1; i < len(rows); i++ {
		if rows[i].Seq >= rows[i-1].Seq {
			t.Fatalf("seq not descending at %d: %d then %d", i, rows[i-1].Seq, rows[i].Seq)
		}
	}
}

// BenchmarkSignInHistorySave measures one save of a full history at the
// default cap, worst-case rows, sealed: the work a save does outside the
// lock.
func BenchmarkSignInHistorySave(b *testing.B) {
	enc, err := persist.Encrypt(persist.NewMemory(), testEncryptKey(), persist.EncryptOptions{Label: "signins"})
	if err != nil {
		b.Fatal(err)
	}
	h, err := OpenSignInHistory(enc, SignInHistoryOptions{})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	for i := range DefaultMaxSignInRows {
		h.Record(SignInEvent{
			UserID: "0123456789abcdef0123456789abcdef", Username: strings.Repeat("n", 64),
			Outcome: SignInWrongPassword, Method: SignInMethodPassword,
			Client:      SessionClient{Address: strings.Repeat("f", MaxSessionAddress), UserAgent: strings.Repeat("a", MaxSessionUserAgent)},
			LockedUntil: signInBase.Add(time.Hour),
		}, signInBase.Add(time.Duration(i)*signInFoldSpan))
	}
	b.ResetTimer()
	for b.Loop() {
		h.mu.Lock()
		h.foldGen++ // something to save
		h.mu.Unlock()
		if err := h.Flush(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

// The fold index is capped: past maxSignInFoldKeys, entries older than
// the span go first, then the oldest, which then no longer folds.
func TestSignInHistoryFoldIndexIsCapped(t *testing.T) {
	was := maxSignInFoldKeys
	maxSignInFoldKeys = 3
	t.Cleanup(func() { maxSignInFoldKeys = was })
	h := openTestHistory(t, nil, SignInHistoryOptions{})
	from := func(i int) SignInEvent { return successFrom("u1", "bob", fmt.Sprintf("192.0.2.%d", i)) }

	h.Record(from(0), signInBase)                                   // ages out of the span
	h.Record(from(1), signInBase.Add(signInFoldSpan))               // the oldest live entry
	h.Record(from(2), signInBase.Add(signInFoldSpan+time.Second))   // index full
	h.Record(from(3), signInBase.Add(signInFoldSpan+2*time.Second)) // drops 0, the expired one
	h.Record(from(4), signInBase.Add(signInFoldSpan+3*time.Second)) // drops 1, the oldest
	h.Record(from(1), signInBase.Add(signInFoldSpan+4*time.Second)) // no longer folds
	h.Record(from(4), signInBase.Add(signInFoldSpan+5*time.Second)) // still folds
	if total, _ := h.Summary(); total != 6 {
		t.Errorf("total = %d, want 6: key 1 evicted, key 4 folded", total)
	}
	if rows, _ := h.List(SignInQuery{Address: "192.0.2.4"}); len(rows) != 1 || rows[0].Count != 2 {
		t.Errorf("key 4 rows = %+v, want one with count 2", rows)
	}
	if len(h.fold) > maxSignInFoldKeys {
		t.Errorf("fold index holds %d keys, cap %d", len(h.fold), maxSignInFoldKeys)
	}
}
