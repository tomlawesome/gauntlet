package gauntlet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// The sign-in history (#53, docs/adr/0006): every sign-in attempt gate
// reports, kept as rows an admin can page through. A third sealed
// document beside the accounts and tokens documents, with its own
// backend and its own persist.Encrypt label ("signins"), never inside
// the accounts document: a stranger can make attempts as fast as the
// limiter lets them, and each would otherwise be a write of every
// account.
//
// Three rules, applied in Record in this order, keep a flood of attempts
// to a bounded number of rows:
//
//  1. Fold. An attempt with the same outcome, method, account (or masked
//     name, when none matched) and address as a row that began within
//     signInFoldSpan adds one to that row's count and moves its until;
//     nothing else about the row changes. The index behind this lives in
//     memory only, so folding starts afresh after a restart.
//  2. Budget. Failed attempts may start at most maxNewFailureRowsPerSpan
//     new rows per signInFoldSpan bucket (now.Truncate). Past it they
//     fold into that bucket's one SignInUnrecorded row, which carries a
//     count and times and nothing else. A success, or a password step
//     that passed, is never budgeted: only someone holding the
//     credential can make one.
//  3. Cap. At MaxRows rows the oldest goes.
//
// An attempt that started a lockout or disabled sign-in is neither
// folded nor budgeted: the lockout is what its row is there to show,
// and the limiter already bounds how often one can start.
//
// Saving is decoupled from recording. Record changes memory and nudges
// one writer goroutine, which saves the whole document no sooner than
// signInSaveInterval after its last save while a new row is unsaved, and
// no sooner than signInFoldSaveInterval while only counts have changed.
// The save copies the rows under the lock and encodes, seals and writes
// them without it, so a save in flight never holds up a sign-in.

// The flood rules' constants. Variables only so tests can shorten them.
var (
	// signInFoldSpan is how long after a row begins attempts like it
	// fold into it, and the width of the failure budget's bucket.
	signInFoldSpan = 10 * time.Minute
	// maxNewFailureRowsPerSpan is the failure budget per bucket.
	maxNewFailureRowsPerSpan = 100
	// signInSaveInterval is the least time between saves while a new
	// row is unsaved; signInFoldSaveInterval while only counts changed.
	signInSaveInterval     = 5 * time.Second
	signInFoldSaveInterval = 60 * time.Second
	// maxSignInFoldKeys caps the fold index; the oldest entry goes.
	maxSignInFoldKeys = 4096
)

const (
	// DefaultMaxSignInRows is how many rows a history keeps when
	// SignInHistoryOptions.MaxRows is zero (owner, 2026-10-02). A row
	// is about 340 bytes of JSON typically and 645 at worst, so a full
	// history is about 3.4 MB typically and 6.5 MB at worst, 8.6 MB once
	// sealed into a text column (base64).
	DefaultMaxSignInRows = 10_000
	// MaxSignInRows is the most MaxRows may be: OpenSignInHistory refuses
	// more. Each save writes the whole document, so the cap is also
	// what bounds one save.
	MaxSignInRows = 50_000

	// DefaultSignInListLimit is how many rows List returns when the
	// query sets no limit; MaxSignInListLimit is the most it returns.
	DefaultSignInListLimit = 50
	MaxSignInListLimit     = 200
)

// SignInHistoryOptions configures OpenSignInHistory.
type SignInHistoryOptions struct {
	// Log receives save failures. nil discards them.
	Log *slog.Logger
	// MaxRows is how many rows are kept, oldest dropped first: zero
	// means DefaultMaxSignInRows, and more than MaxSignInRows, or a
	// negative number, is refused.
	MaxRows int
	// AllowPlaintextAtRest accepts a backend that stores the document
	// in the clear (see ErrPlaintextAtRest): every row carries a client
	// address and browser, so the default is to refuse one, as for the
	// accounts store. Memory, the encrypting backends and a nil backend
	// need no permission.
	AllowPlaintextAtRest bool
}

// SignInRow is one row of the history: one attempt, or several alike
// folded together (Count, Until), or for SignInUnrecorded the attempts
// past a bucket's failure budget.
type SignInRow struct {
	// Seq numbers rows in the order they began, from 1; List pages by it.
	Seq uint64
	// At is when the first attempt the row stands for was made, Until
	// the last; Count how many there were.
	At, Until time.Time
	Count     int
	// UserID is the account the attempts were on, empty when the name
	// matched none; Username is then MaskUnknownUsername's form.
	UserID, Username string
	Outcome          SignInOutcome
	Method           SignInMethod
	// Client is the first attempt's address and browser, cleaned as a
	// session's is.
	Client SessionClient
	// LockedUntil and Disabled are SignInEvent's.
	LockedUntil time.Time
	Disabled    bool
}

// SignInQuery selects rows for List. Zero fields select everything.
type SignInQuery struct {
	UserID  string
	Address string
	Outcome SignInOutcome
	// Before, when not zero, returns only rows numbered below it: the
	// last Seq of one page is the next page's Before.
	Before uint64
	// Limit is at most MaxSignInListLimit; zero means
	// DefaultSignInListLimit.
	Limit int
}

// signInFile is the stored document, version 1:
// {"version":1,"nextSeq":n,"rows":[...]}, rows ascending by seq.
type signInFile struct {
	Version int             `json:"version"`
	NextSeq uint64          `json:"nextSeq"`
	Rows    []signInFileRow `json:"rows"`
}

// signInFileRow is a row as stored, with gate's API row's names.
type signInFileRow struct {
	Seq         uint64        `json:"seq"`
	At          time.Time     `json:"at"`
	Until       time.Time     `json:"until"`
	Count       int           `json:"count"`
	UserID      string        `json:"userId,omitempty"`
	Username    string        `json:"username,omitempty"`
	Outcome     SignInOutcome `json:"outcome"`
	Method      SignInMethod  `json:"method,omitempty"`
	Address     string        `json:"address,omitempty"`
	UserAgent   string        `json:"userAgent,omitempty"`
	LockedUntil time.Time     `json:"lockedUntil,omitzero"`
	Disabled    bool          `json:"disabled,omitempty"`
}

// signInState is what the document holds.
type signInState struct {
	nextSeq uint64
	rows    []SignInRow
}

func (s *signInState) clone() *signInState {
	return &signInState{nextSeq: s.nextSeq, rows: append([]SignInRow(nil), s.rows...)}
}

// row is the row numbered seq, or nil.
func (s *signInState) row(seq uint64) *SignInRow {
	i := sort.Search(len(s.rows), func(i int) bool { return s.rows[i].Seq >= seq })
	if i < len(s.rows) && s.rows[i].Seq == seq {
		return &s.rows[i]
	}
	return nil
}

// add appends r numbered from nextSeq and drops the oldest past max.
func (s *signInState) add(r SignInRow, max int) uint64 {
	r.Seq = s.nextSeq
	s.nextSeq++
	s.rows = append(s.rows, r)
	if over := len(s.rows) - max; over > 0 {
		s.rows = s.rows[over:]
	}
	return r.Seq
}

func encodeSignIns(st *signInState) ([]byte, error) {
	f := signInFile{Version: signInsDocumentVersion, NextSeq: st.nextSeq, Rows: make([]signInFileRow, len(st.rows))}
	for i, r := range st.rows {
		f.Rows[i] = signInFileRow{
			Seq: r.Seq, At: r.At, Until: r.Until, Count: r.Count,
			UserID: r.UserID, Username: r.Username, Outcome: r.Outcome, Method: r.Method,
			Address: r.Client.Address, UserAgent: r.Client.UserAgent,
			LockedUntil: r.LockedUntil, Disabled: r.Disabled,
		}
	}
	return json.Marshal(f)
}

// errSignInsMalformed is the decode error for a document whose rows do
// not hold together: out of order, numbered at or past nextSeq, or
// numbered zero.
var errSignInsMalformed = errors.New("its rows are not numbered in order below nextSeq")

func decodeSignIns(data []byte) (*signInState, error) {
	version, err := documentVersion(data)
	if err != nil {
		return nil, err
	}
	if err := checkDocumentVersion("sign-in history", version, signInsDocumentVersion); err != nil {
		return nil, err
	}
	var f signInFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	st := &signInState{nextSeq: max(f.NextSeq, 1), rows: make([]SignInRow, len(f.Rows))}
	var prev uint64
	for i, r := range f.Rows {
		if r.Seq <= prev || r.Seq >= st.nextSeq {
			return nil, errSignInsMalformed
		}
		prev = r.Seq
		st.rows[i] = SignInRow{
			Seq: r.Seq, At: r.At, Until: r.Until, Count: r.Count,
			UserID: r.UserID, Username: r.Username, Outcome: r.Outcome, Method: r.Method,
			Client:      SessionClient{Address: r.Address, UserAgent: r.UserAgent},
			LockedUntil: r.LockedUntil, Disabled: r.Disabled,
		}
	}
	return st, nil
}

// foldEntry is where attempts with one fold key go while the row they
// began is young enough.
type foldEntry struct {
	seq uint64
	at  time.Time
}

// SignInHistory is the sign-in history: see this file's header and
// docs/adr/0006. Safe for concurrent use. Open it with
// OpenSignInHistory and Close it at shutdown, which saves what is
// unsaved and stops its writer.
//
// One process writes a history's document: a running server owns it,
// as it owns its sessions. A CLI or second process opened over the same
// backend only reads. If two writers do meet, a save that finds the
// document changed reloads it and appends the rows it added since its
// last save, renumbered; count bumps it made to rows already saved are
// lost in that one case.
type SignInHistory struct {
	backend persist.Backend
	log     *slog.Logger
	maxRows int

	mu sync.Mutex
	st signInState
	// version is the backend's version of the document as last loaded
	// or saved; savedNext the nextSeq it held, so rows numbered from it
	// on are unsaved; foldGen counts count bumps, savedFoldGen the
	// count the last save included.
	version      int64
	savedNext    uint64
	foldGen      uint64
	savedFoldGen uint64
	lastSave     time.Time
	fold         map[string]foldEntry
	budgetBucket time.Time
	budgetUsed   int
	overflowAt   time.Time // the bucket overflowSeq's row stands for
	overflowSeq  uint64
	failLogged   bool
	// lastCheckedVersion is the backend version checkIfStale last read
	// and decoded, so a List or Summary call does not re-Load and
	// re-decode the same not-yet-saved version on every read while
	// nothing is dirty -- distinct from version, which only save's own
	// replay ever advances.
	lastCheckedVersion int64

	// saveSem lets one save run at a time, the writer's or Flush's.
	saveSem   chan struct{}
	nudge     chan struct{}
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// plaintextSignInsError is ErrPlaintextAtRest in the sign-in history's
// own words.
type plaintextSignInsError struct{}

func (plaintextSignInsError) Error() string {
	return "gauntlet: the sign-in history backend stores the document in the clear, every attempt's address and browser included -- wrap it in persist.Encrypt (label \"signins\"), or set SignInHistoryOptions.AllowPlaintextAtRest to accept that"
}

func (plaintextSignInsError) Is(target error) bool { return target == ErrPlaintextAtRest }

// OpenSignInHistory opens the sign-in history kept in b, and starts the
// writer that saves it. A nil b gives a history in memory only: usable,
// lost at restart, and saying so in Describe -- for tests and
// development.
//
// The same open rules as OpenStore: a document that exists but cannot
// be read or parsed is refused (persist.Open), as are one sealed by
// persist.Encrypt reaching here unwrapped, one newer than this build
// reads, and -- unless opts.AllowPlaintextAtRest -- a backend that
// stores plaintext (ErrPlaintextAtRest). A document holding more rows
// than MaxRows is cut to the newest MaxRows in memory, and saved so at
// the next save.
func OpenSignInHistory(b persist.Backend, opts SignInHistoryOptions) (*SignInHistory, error) {
	maxRows := opts.MaxRows
	if maxRows == 0 {
		maxRows = DefaultMaxSignInRows
	}
	if maxRows < 0 || maxRows > MaxSignInRows {
		return nil, fmt.Errorf("gauntlet: SignInHistoryOptions.MaxRows is %d; it must be between 1 and %d (0 for the default, %d)", opts.MaxRows, MaxSignInRows, DefaultMaxSignInRows)
	}
	if b != nil && !opts.AllowPlaintextAtRest && !protectedAtRest(b) {
		return nil, plaintextSignInsError{}
	}
	h := &SignInHistory{
		backend: b,
		log:     opts.Log,
		maxRows: maxRows,
		st:      signInState{nextSeq: 1},
		fold:    make(map[string]foldEntry),
		saveSem: make(chan struct{}, 1),
	}
	version, existed, err := persist.Open(context.Background(), b, "the sign-in history", func(data []byte) error {
		st, err := decodeSignIns(data)
		if err != nil {
			return err
		}
		h.st = *st
		return nil
	})
	if err != nil {
		return nil, err
	}
	if existed {
		h.version = version
	}
	if over := len(h.st.rows) - maxRows; over > 0 {
		h.st.rows = h.st.rows[over:]
		if opts.Log != nil {
			opts.Log.Warn(fmt.Sprintf("sign-in history: MaxRows (%d) is below the %d rows on disk; the oldest %d are dropped, saved so at the next save", maxRows, len(h.st.rows)+over, over))
		}
	}
	h.savedNext = h.st.nextSeq
	if b != nil {
		h.nudge = make(chan struct{}, 1)
		h.stop = make(chan struct{})
		h.done = make(chan struct{})
		go h.run()
	}
	return h, nil
}

// Persisted reports whether the history outlives a restart.
func (h *SignInHistory) Persisted() bool { return h.backend != nil }

// Describe names where the history is kept, for a startup line.
func (h *SignInHistory) Describe() string {
	if h.backend == nil {
		return "memory only: the sign-in history is lost at restart"
	}
	return h.backend.Describe()
}

// signInFailedOutcome reports whether o counts against the failure
// budget: anything but a sign-in or a password step that passed.
func signInFailedOutcome(o SignInOutcome) bool {
	return o != SignInSuccess && o != SignInPasswordOK
}

// startedSomething reports whether ev is the failed attempt that started
// a lockout or disabled sign-in, rather than one refused because of
// either.
func startedSomething(ev SignInEvent) bool {
	return (!ev.LockedUntil.IsZero() && ev.Outcome != SignInLocked) || (ev.Disabled && ev.Outcome != SignInDisabled)
}

// foldKey is what makes two attempts the same row: outcome, method,
// account (or the masked name, for none) and address.
func foldKey(ev SignInEvent) string {
	who := "id:" + ev.UserID
	if ev.UserID == "" {
		who = "name:" + ev.Username
	}
	return string(ev.Outcome) + "\x00" + string(ev.Method) + "\x00" + who + "\x00" + ev.Client.Address
}

// Record adds one attempt made at now, by the rules in this file's
// header. ev.Username must already be the account's username or
// MaskUnknownUsername's form; ev.Client is cleaned here as a session's
// is. It never waits for a save.
func (h *SignInHistory) Record(ev SignInEvent, now time.Time) {
	ev.Client = SessionClient{
		Address:   cleanClientText(ev.Client.Address, MaxSessionAddress),
		UserAgent: cleanClientText(ev.Client.UserAgent, MaxSessionUserAgent),
	}
	now = now.UTC()
	h.mu.Lock()
	h.recordLocked(ev, now)
	h.mu.Unlock()
	h.wake()
}

func (h *SignInHistory) recordLocked(ev SignInEvent, now time.Time) {
	special := startedSomething(ev)
	key := foldKey(ev)
	if !special {
		if e, ok := h.fold[key]; ok && now.Sub(e.at) < signInFoldSpan {
			if r := h.st.row(e.seq); r != nil {
				h.bumpLocked(r, now)
				return
			}
		}
	}
	if signInFailedOutcome(ev.Outcome) && !special {
		bucket := now.Truncate(signInFoldSpan)
		if !bucket.Equal(h.budgetBucket) {
			h.budgetBucket, h.budgetUsed = bucket, 0
		}
		if h.budgetUsed >= maxNewFailureRowsPerSpan {
			if h.overflowSeq != 0 && h.overflowAt.Equal(bucket) {
				if r := h.st.row(h.overflowSeq); r != nil {
					h.bumpLocked(r, now)
					return
				}
			}
			h.overflowAt = bucket
			h.overflowSeq = h.st.add(SignInRow{At: now, Until: now, Count: 1, Outcome: SignInUnrecorded}, h.maxRows)
			return
		}
		h.budgetUsed++
	}
	lockedUntil := ev.LockedUntil
	if !lockedUntil.IsZero() {
		lockedUntil = lockedUntil.UTC()
	}
	seq := h.st.add(SignInRow{
		At: now, Until: now, Count: 1,
		UserID: ev.UserID, Username: ev.Username, Outcome: ev.Outcome, Method: ev.Method,
		Client: ev.Client, LockedUntil: lockedUntil, Disabled: ev.Disabled,
	}, h.maxRows)
	if !special {
		h.foldLocked(key, foldEntry{seq: seq, at: now}, now)
	}
}

// bumpLocked folds one more attempt into r.
func (h *SignInHistory) bumpLocked(r *SignInRow, now time.Time) {
	r.Count++
	if now.After(r.Until) {
		r.Until = now
	}
	h.foldGen++
}

// foldLocked indexes key, keeping the index at maxSignInFoldKeys:
// entries past the span go first, then the oldest.
func (h *SignInHistory) foldLocked(key string, e foldEntry, now time.Time) {
	if _, ok := h.fold[key]; !ok && len(h.fold) >= maxSignInFoldKeys {
		var oldestKey string
		var oldest time.Time
		for k, v := range h.fold {
			if now.Sub(v.at) >= signInFoldSpan {
				delete(h.fold, k)
				continue
			}
			if oldestKey == "" || v.at.Before(oldest) {
				oldestKey, oldest = k, v.at
			}
		}
		if len(h.fold) >= maxSignInFoldKeys {
			delete(h.fold, oldestKey)
		}
	}
	h.fold[key] = e
}

// wake nudges the writer, if there is one.
func (h *SignInHistory) wake() {
	if h.nudge == nil {
		return
	}
	select {
	case h.nudge <- struct{}{}:
	default:
	}
}

// List returns the rows q selects, newest first, and whether more
// matching rows lie beyond the page.
func (h *SignInHistory) List(q SignInQuery) (rows []SignInRow, more bool) {
	h.checkIfStale()
	limit := q.Limit
	if limit <= 0 {
		limit = DefaultSignInListLimit
	}
	limit = min(limit, MaxSignInListLimit)
	h.mu.Lock()
	defer h.mu.Unlock()
	rows = make([]SignInRow, 0, min(limit, len(h.st.rows)))
	for i := len(h.st.rows) - 1; i >= 0; i-- {
		r := h.st.rows[i]
		switch {
		case q.Before != 0 && r.Seq >= q.Before,
			q.UserID != "" && r.UserID != q.UserID,
			q.Address != "" && r.Client.Address != q.Address,
			q.Outcome != "" && r.Outcome != q.Outcome:
			continue
		}
		if len(rows) == limit {
			return rows, true
		}
		rows = append(rows, r)
	}
	return rows, false
}

// Summary reports how many rows the history holds and when the oldest
// began: how full it is, and how far back it goes. since is zero when
// it holds none.
func (h *SignInHistory) Summary() (total int, since time.Time) {
	h.checkIfStale()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.st.rows) > 0 {
		since = h.st.rows[0].At
	}
	return len(h.st.rows), since
}

// Flush saves whatever is unsaved now, without waiting for the writer's
// interval: for shutdown and tests. A history in memory only has
// nothing to save.
func (h *SignInHistory) Flush(ctx context.Context) error {
	if h.backend == nil {
		return nil
	}
	return h.save(ctx)
}

// Close stops the writer and flushes once. Later calls do nothing.
// Record still works after Close, in memory only.
func (h *SignInHistory) Close() error {
	h.closeOnce.Do(func() {
		if h.stop != nil {
			close(h.stop)
			<-h.done
		}
		h.closeErr = h.Flush(context.Background())
	})
	return h.closeErr
}

// run is the writer: it saves when saveDue says so, and otherwise waits
// for that time, a nudge from Record, or Close.
func (h *SignInHistory) run() {
	defer close(h.done)
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	for {
		wait, pending := h.saveDue(time.Now())
		if pending && wait <= 0 {
			_ = h.save(context.Background())
			continue
		}
		if pending {
			timer.Reset(wait)
		}
		select {
		case <-h.stop:
			timer.Stop()
			return
		case <-h.nudge:
		case <-timer.C:
		}
		timer.Stop()
	}
}

// saveDue reports whether anything is unsaved and how long until the
// writer may save it.
func (h *SignInHistory) saveDue(now time.Time) (wait time.Duration, pending bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case h.st.nextSeq > h.savedNext:
		return h.lastSave.Add(signInSaveInterval).Sub(now), true
	case h.foldGen != h.savedFoldGen:
		return h.lastSave.Add(signInFoldSaveInterval).Sub(now), true
	}
	return 0, false
}

// dirtyLocked reports whether anything is unsaved.
func (h *SignInHistory) dirtyLocked() bool {
	return h.st.nextSeq > h.savedNext || h.foldGen != h.savedFoldGen
}

// document is the replay loop's view of the history (mutate.go). No
// check: there is no document this store would write and refuse.
func (h *SignInHistory) document() document[signInState] {
	return document[signInState]{
		backend: h.backend,
		what:    "sign-in history",
		clone:   (*signInState).clone,
		encode:  encodeSignIns,
		decode:  decodeSignIns,
	}
}

// checkIfStale is List and Summary's cheap read-time check, the kind
// the accounts and tokens stores already have (Store.reloadIfStale):
// without it, a document this store cannot apply -- most notably the
// JSON literal null -- was found and logged only at the next save,
// and save does not run at all while nothing is being recorded, so a
// file replaced while idle went unnoticed until the next sign-in.
//
// Cheap because it costs a version comparison, not a document
// transfer, when the backend is a persist.VersionReader (every backend
// this module ships is); callers without that capability are skipped
// rather than paying a full Load on every read. A version not yet seen
// by this check is read and decoded only to see whether it is one this
// store can apply -- a legitimate newer document from another writer
// decodes clean and changes nothing here; only save's own replay ever
// adopts it. Nothing in memory is overwritten either way.
func (h *SignInHistory) checkIfStale() {
	if h.backend == nil {
		return
	}
	vr, ok := h.backend.(persist.VersionReader)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), reloadTimeout)
	defer cancel()
	current, exists, err := vr.Version(ctx)
	if err != nil || !exists {
		return
	}
	h.mu.Lock()
	stale := current != h.version && current != h.lastCheckedVersion
	h.mu.Unlock()
	if !stale {
		return
	}
	_, _, loadErr := h.document().load(ctx)
	h.mu.Lock()
	h.lastCheckedVersion = current
	if loadErr != nil {
		h.logFailureLocked(loadErr)
	} else {
		h.failLogged = false
	}
	h.mu.Unlock()
}

// save writes the history. The rows are copied under mu; the encode,
// the seal and the write happen without it, so Record and List carry on
// while a save is in flight. saveSem keeps saves to one at a time, which
// is what lets the replay loop run without mu: only a save moves the
// version.
func (h *SignInHistory) save(ctx context.Context) error {
	select {
	case h.saveSem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-h.saveSem }()

	h.mu.Lock()
	if !h.dirtyLocked() {
		h.mu.Unlock()
		return nil
	}
	snap := h.st.clone()
	version, base, foldGen := h.version, h.savedNext, h.foldGen
	h.lastSave = time.Now()
	h.mu.Unlock()

	// The rows this process added since its last save, for a replay
	// against a document another writer saved in between.
	var unsaved []SignInRow
	for _, r := range snap.rows {
		if r.Seq >= base {
			unsaved = append(unsaved, r)
		}
	}
	first, replayed := true, false
	saved, savedVersion, err := h.document().replay(snap, version, func(st *signInState) error {
		if first {
			first = false // the snapshot itself: nothing to apply
			return nil
		}
		replayed = true
		for _, r := range unsaved {
			st.add(r, h.maxRows)
		}
		return nil
	})

	h.mu.Lock()
	defer h.mu.Unlock()
	if err != nil {
		h.logFailureLocked(err)
		return err
	}
	h.failLogged = false
	h.version = savedVersion
	if !replayed {
		h.savedNext, h.savedFoldGen = snap.nextSeq, foldGen
		return nil
	}
	// Another writer saved in between: what was saved is now the truth,
	// plus anything recorded here since the snapshot, renumbered after
	// it. The fold index and the overflow row named rows by their old
	// numbers, so folding starts afresh.
	for _, r := range h.st.rows {
		if r.Seq >= snap.nextSeq {
			saved.add(r, h.maxRows)
		}
	}
	h.savedNext = savedNextAfterReplay(saved, h.st.rows, snap.nextSeq)
	h.st = *saved
	h.savedFoldGen = foldGen
	h.fold = make(map[string]foldEntry)
	h.overflowSeq = 0
	return nil
}

// savedNextAfterReplay is the first number in st not saved: st holds
// the saved document plus the rows recorded since the snapshot (those
// numbered from snapNext in mem), appended after it.
func savedNextAfterReplay(st *signInState, mem []SignInRow, snapNext uint64) uint64 {
	later := uint64(0)
	for _, r := range mem {
		if r.Seq >= snapNext {
			later++
		}
	}
	return st.nextSeq - later
}

// logFailureLocked logs a failed save once until a save succeeds: the
// writer retries every interval, and a removed document fails each
// time.
func (h *SignInHistory) logFailureLocked(err error) {
	if h.failLogged || h.log == nil {
		h.failLogged = true
		return
	}
	h.failLogged = true
	if errors.Is(err, ErrDocumentRemoved) {
		h.log.Error(fmt.Sprintf("sign-in history (%s) has been removed since this process loaded it; rows are kept in memory and saves are refused until it is restored or the process restarts", h.backend.Describe()))
		return
	}
	h.log.Error(fmt.Sprintf("saving the sign-in history: %v -- rows are kept in memory and the save is retried", err))
}
