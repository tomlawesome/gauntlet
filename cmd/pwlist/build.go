package main

import (
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tomlawesome/gauntlet/blocklist"
)

const (
	// totalPrefixes is every 5-hex-digit SHA-1 prefix, 00000-FFFFF:
	// the range API serves the whole corpus as this many responses.
	totalPrefixes = 1 << 20

	defaultBaseURL     = "https://api.pwnedpasswords.com/range/"
	defaultChunkSize   = 4096 // 256 chunks over the full range
	defaultConcurrency = 32
	defaultTop         = 10000

	// The sanity bars a full run must clear before anything is
	// written. HIBP holds about a billion hashes, so seeing under half
	// that means responses went missing; and the 10,000th most
	// prevalent password has been seen far more than a thousand times,
	// so a lower count means the counts are wrong.
	defaultMinTotal = 500_000_000
	defaultMinCount = 1000

	// Per request: five attempts, backing off 250 ms doubling to 8 s
	// with jitter, on 429, 5xx and network errors. A Retry-After is
	// honoured, up to two minutes.
	maxAttempts    = 5
	minBackoff     = 250 * time.Millisecond
	maxBackoff     = 8 * time.Second
	maxRetryAfter  = 2 * time.Minute
	requestTimeout = 30 * time.Second
	// maxResponse bounds one decompressed range response. A real one
	// is about 40 KB.
	maxResponse = 4 << 20

	checkpointFormat = "gauntlet-pwlist-checkpoint/1"
	checkpointMaxAge = 24 * time.Hour
)

// entry is one hash and how many times HIBP has seen it.
type entry struct {
	Hash  string `json:"h"` // 40 uppercase hex
	Count int64  `json:"c"`
}

// worse orders entries by (count desc, hash asc): a is worse than b if
// it has fewer sightings, or as many and a later hash. A total order, so
// the top N of a corpus is one set whatever order the responses come in.
func worse(a, b entry) bool {
	if a.Count != b.Count {
		return a.Count < b.Count
	}
	return a.Hash > b.Hash
}

// topN keeps the best n entries seen: a min-heap with the worst kept
// entry at the root, so each new entry costs one comparison and, if it
// gets in, O(log n). 10,000 entries is about 300 KB.
type topN struct {
	n int
	h entryHeap
}

func (t *topN) offer(e entry) {
	if len(t.h) < t.n {
		heap.Push(&t.h, e)
		return
	}
	if worse(t.h[0], e) {
		t.h[0] = e
		heap.Fix(&t.h, 0)
	}
}

// floor is the count an entry needs to be worth offering: once the set
// is full, anything below its worst entry's count cannot get in.
func (t *topN) floor() int64 {
	if len(t.h) < t.n {
		return 0
	}
	return t.h[0].Count
}

type entryHeap []entry

func (h entryHeap) Len() int           { return len(h) }
func (h entryHeap) Less(i, j int) bool { return worse(h[i], h[j]) }
func (h entryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *entryHeap) Push(x any)        { *h = append(*h, x.(entry)) }
func (h *entryHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	*h = old[:len(old)-1]
	return e
}

// builder walks the range API and writes the top-N list. Its fields are
// set by the `build` flags; the sanity bars, the chunk size and the
// clock are fields so tests can scale them down.
type builder struct {
	baseURL     string
	client      *http.Client
	userAgent   string
	prefixes    int // walk 00000 up to this many prefixes
	fullRange   int // how many prefixes a full run walks: totalPrefixes, scaled down in tests
	chunkSize   int
	concurrency int
	top         int
	minTotal    int64
	minCount    int64
	checkpoint  string // "" for none
	out         string
	log         io.Writer
	now         func() time.Time
	sleep       func(context.Context, time.Duration) error
}

// state is a run's progress: everything a checkpoint has to carry.
type state struct {
	next  int   // the first chunk not yet done
	total int64 // non-zero-count lines seen
	top   *topN
}

func (b *builder) sample() bool { return b.prefixes < b.fullRange }

func (b *builder) run(ctx context.Context) error {
	st := b.resume()
	chunks := (b.prefixes + b.chunkSize - 1) / b.chunkSize
	for c := st.next; c < chunks; c++ {
		lo := c * b.chunkSize
		hi := min(lo+b.chunkSize, b.prefixes)
		if err := b.runChunk(ctx, lo, hi, st); err != nil {
			return fmt.Errorf("chunk %d/%d (prefixes %05X-%05X): %w", c+1, chunks, lo, hi-1, err)
		}
		st.next = c + 1
		if err := b.saveCheckpoint(st); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(b.log, "pwlist: chunk %d/%d (prefixes %05X-%05X) done: %d hashes so far, %d kept, lowest kept count %d\n",
			c+1, chunks, lo, hi-1, st.total, len(st.top.h), st.top.floor())
	}
	return b.emit(st)
}

// runChunk fetches prefixes [lo, hi) with b.concurrency requests in
// flight, merging each response into st. The first failure cancels the
// rest; st is then only partly updated, so the caller must not save it.
func (b *builder) runChunk(ctx context.Context, lo, hi int, st *state) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu       sync.Mutex // guards st and firstErr
		firstErr error
		floor    atomic.Int64
		wg       sync.WaitGroup
	)
	floor.Store(st.top.floor())
	jobs := make(chan int)
	for range b.concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				entries, n, err := b.fetch(ctx, p, floor.Load())
				mu.Lock()
				if err != nil {
					if firstErr == nil {
						firstErr = err
						cancel()
					}
				} else {
					st.total += n
					for _, e := range entries {
						st.top.offer(e)
					}
					floor.Store(st.top.floor())
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for p := lo; p < hi; p++ {
		select {
		case jobs <- p:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	return ctx.Err()
}

// permanentError is a failure no retry can fix: a 4xx other than 429,
// or a response that is not in the range API's format.
type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

// fetch gets one prefix's range, retrying transient failures, and
// returns the entries with at least floor sightings and how many
// non-zero lines it held.
func (b *builder) fetch(ctx context.Context, prefix int, floor int64) ([]entry, int64, error) {
	p := fmt.Sprintf("%05X", prefix)
	var lastErr error
	var retryAfter time.Duration
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			if err := b.sleep(ctx, backoff(attempt-1, retryAfter)); err != nil {
				return nil, 0, err
			}
		}
		var entries []entry
		var n int64
		var err error
		entries, n, retryAfter, err = b.fetchOnce(ctx, p, floor)
		if err == nil {
			return entries, n, nil
		}
		if pe := (permanentError{}); errors.As(err, &pe) || ctx.Err() != nil {
			return nil, 0, fmt.Errorf("prefix %s: %w", p, err)
		}
		lastErr = err
	}
	return nil, 0, fmt.Errorf("prefix %s: gave up after %d attempts: %w", p, maxAttempts, lastErr)
}

// backoff is the wait before retry number n (1-based): a random time
// between 250 ms and 250 ms * 2^(n-1), capped at 8 s, or the server's
// Retry-After if that is longer, capped at two minutes.
func backoff(n int, retryAfter time.Duration) time.Duration {
	ceiling := min(minBackoff<<(n-1), maxBackoff)
	d := minBackoff + time.Duration(rand.Int64N(int64(ceiling-minBackoff)+1)) //nolint:gosec // jitter, not a secret
	if retryAfter > d {
		d = min(retryAfter, maxRetryAfter)
	}
	return d
}

func (b *builder) fetchOnce(ctx context.Context, prefix string, floor int64) ([]entry, int64, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.baseURL+prefix, nil)
	if err != nil {
		return nil, 0, 0, permanentError{err}
	}
	// No Accept-Encoding of our own: net/http then asks for gzip and
	// decompresses transparently. No Add-Padding: padding lines carry
	// count 0 and would only be skipped.
	req.Header.Set("User-Agent", b.userAgent)
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, 0, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, 0, parseRetryAfter(resp.Header.Get("Retry-After"), b.now()), fmt.Errorf("HTTP %s", resp.Status)
	default:
		return nil, 0, 0, permanentError{fmt.Errorf("HTTP %s", resp.Status)}
	}

	// Read the whole body before looking at it: a response cut off
	// mid-line must count as the network error it is (and be retried),
	// not as a malformed line, which would end the run.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("read: %w", err)
	}
	if len(raw) > maxResponse {
		return nil, 0, 0, permanentError{fmt.Errorf("response larger than %d bytes", maxResponse)}
	}
	if len(raw) == 0 {
		// Every prefix holds about a thousand hashes; an empty 200 is a
		// fault somewhere on the way, worth a retry.
		return nil, 0, 0, errors.New("empty response")
	}
	var entries []entry
	var n int64
	for i, line := range strings.Split(strings.TrimRight(string(raw), "\r\n"), "\n") {
		line = strings.TrimSuffix(line, "\r")
		count, ok := parseRangeLine(line)
		if !ok {
			return nil, 0, 0, permanentError{fmt.Errorf("line %d is not `<35 uppercase hex>:<count>`: %.60q", i+1, line)}
		}
		if count == 0 {
			continue
		}
		n++
		if count >= floor {
			entries = append(entries, entry{Hash: prefix + line[:35], Count: count})
		}
	}
	return entries, n, 0, nil
}

// parseRangeLine checks a line against ^[0-9A-F]{35}:\d+$ and returns
// its count.
func parseRangeLine(line string) (int64, bool) {
	if len(line) < 37 || line[35] != ':' {
		return 0, false
	}
	if !isUpperHex(line[:35], 35) {
		return 0, false
	}
	digits := line[36:]
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, false
		}
	}
	count, err := strconv.ParseInt(digits, 10, 64)
	return count, err == nil
}

func isUpperHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// parseRetryAfter reads a Retry-After header: seconds, or an HTTP date.
func parseRetryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// checkpointFile is the on-disk progress of a run.
type checkpointFile struct {
	Format    string    `json:"format"`
	Saved     time.Time `json:"saved"`
	Prefixes  int       `json:"prefixes"`
	ChunkSize int       `json:"chunk_size"`
	Top       int       `json:"top"`
	Next      int       `json:"next_chunk"`
	Total     int64     `json:"total_hashes"`
	Entries   []entry   `json:"entries"`
}

// resume loads the checkpoint if there is a usable one, and otherwise
// starts from nothing. A checkpoint is unusable if it is older than 24
// hours (the corpus may have moved on), was saved in the future, was
// made with other settings, or does not parse; each case is logged,
// never fatal. A future save time means the clock was wrong then or is
// now, so its age is unknown: trusting it would let a checkpoint from a
// clock set ahead be resumed long after the 24 hours are up, building
// a list partly from an old copy of the corpus.
func (b *builder) resume() *state {
	fresh := &state{top: &topN{n: b.top}}
	if b.checkpoint == "" {
		return fresh
	}
	data, err := os.ReadFile(b.checkpoint)
	if errors.Is(err, os.ErrNotExist) {
		return fresh
	}
	var cp checkpointFile
	if err == nil {
		err = json.Unmarshal(data, &cp)
	}
	reason := ""
	switch {
	case err != nil:
		reason = err.Error()
	case cp.Format != checkpointFormat:
		reason = fmt.Sprintf("format %q", cp.Format)
	case cp.Saved.After(b.now()):
		reason = fmt.Sprintf("saved %s, which is in the future", cp.Saved.Format(time.RFC3339))
	case b.now().Sub(cp.Saved) > checkpointMaxAge:
		reason = fmt.Sprintf("saved %s, more than 24 hours ago", cp.Saved.Format(time.RFC3339))
	case cp.Prefixes != b.prefixes || cp.ChunkSize != b.chunkSize || cp.Top != b.top:
		reason = "made with different --prefixes, chunk size or list size"
	case cp.Next < 0 || len(cp.Entries) > b.top || cp.Total < 0:
		reason = "inconsistent contents"
	}
	if reason == "" {
		for _, e := range cp.Entries {
			if !isUpperHex(e.Hash, 40) || e.Count <= 0 {
				reason = "an entry is not a 40-hex hash with a positive count"
				break
			}
		}
	}
	if reason != "" {
		_, _ = fmt.Fprintf(b.log, "pwlist: ignoring checkpoint %s: %s; starting from the first chunk\n", b.checkpoint, reason)
		return fresh
	}
	st := &state{next: cp.Next, total: cp.Total, top: &topN{n: b.top}}
	for _, e := range cp.Entries {
		st.top.offer(e)
	}
	_, _ = fmt.Fprintf(b.log, "pwlist: resuming from checkpoint %s at chunk %d\n", b.checkpoint, cp.Next+1)
	return st
}

func (b *builder) saveCheckpoint(st *state) error {
	if b.checkpoint == "" {
		return nil
	}
	entries := slices.Clone(st.top.h)
	slices.SortFunc(entries, func(a, b entry) int { return strings.Compare(a.Hash, b.Hash) })
	data, err := json.Marshal(checkpointFile{
		Format: checkpointFormat, Saved: b.now().UTC(),
		Prefixes: b.prefixes, ChunkSize: b.chunkSize, Top: b.top,
		Next: st.next, Total: st.total, Entries: entries,
	})
	if err != nil {
		return err
	}
	if err := writeFileAtomic(b.checkpoint, data, 0o600); err != nil {
		return fmt.Errorf("save checkpoint: %w", err)
	}
	return nil
}

// emit checks the run's result against the sanity bars and writes the
// list and its checksum. Nothing is written unless every bar is met.
func (b *builder) emit(st *state) error {
	if len(st.top.h) != b.top {
		return fmt.Errorf("only %d distinct hashes seen, want %d; nothing written", len(st.top.h), b.top)
	}
	minTotal := b.minTotal
	if b.sample() {
		// A sample sees its share of the corpus; scale the bar to it.
		minTotal = b.minTotal * int64(b.prefixes) / int64(b.fullRange)
	}
	if st.total < minTotal {
		return fmt.Errorf("saw %d hashes, under the %d a run this size must see; nothing written", st.total, minTotal)
	}
	floor := st.top.floor()
	// A sample's 10,000th entry is far down the whole corpus, so its
	// count says nothing about the counts being right.
	if !b.sample() && floor < b.minCount {
		return fmt.Errorf("the 10,000th entry was seen %d times, under %d; nothing written", floor, b.minCount)
	}

	hashes := make([]string, len(st.top.h))
	for i, e := range st.top.h {
		hashes[i] = e.Hash
	}
	slices.Sort(hashes)
	note := ""
	if b.sample() {
		note = fmt.Sprintf("%d of %d prefixes; not for publication", b.prefixes, b.fullRange)
	}
	data := formatList(hashes, b.now(), floor, st.total, note)
	if !b.sample() {
		if _, err := blocklist.Parse(data); err != nil {
			return fmt.Errorf("self-check: the list written would not parse: %w", err)
		}
	}
	if err := writeFileAtomic(b.out, data, 0o644); err != nil {
		return err
	}
	if err := writeFileAtomic(b.out+".sha256", []byte(sha256Line(data, filepath.Base(b.out))), 0o644); err != nil {
		return err
	}
	if b.checkpoint != "" {
		if err := os.Remove(b.checkpoint); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove checkpoint: %w", err)
		}
	}
	_, _ = fmt.Fprintf(b.log, "pwlist: wrote %s: %d hashes from %d seen, lowest count %d\n", b.out, len(hashes), st.total, floor)
	return nil
}

// sha256Line is the checksum file for data named name, in
// `sha256sum` format: hex, two spaces, the file name, a newline.
func sha256Line(data []byte, name string) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) + "  " + name + "\n"
}

// formatList writes the list file, format gauntlet-pwned-top10k/1 (see
// blocklist.Parse): the header, then the hashes, one per line, sorted.
// Given the same hashes and time it always writes the same bytes. A
// sample run says so in a `# sample:` header, which blocklist.Parse --
// and so `sign` and every Refresher -- refuses.
func formatList(hashes []string, built time.Time, minCount, total int64, sample string) []byte {
	var b strings.Builder
	b.WriteString("# format: gauntlet-pwned-top10k/1\n")
	b.WriteString("# source: Have I Been Pwned Pwned Passwords range API (SHA-1)\n")
	_, _ = fmt.Fprintf(&b, "# built: %s\n", built.UTC().Truncate(time.Second).Format(time.RFC3339))
	_, _ = fmt.Fprintf(&b, "# count: %d\n", len(hashes))
	_, _ = fmt.Fprintf(&b, "# min-count: %d\n", minCount)
	_, _ = fmt.Fprintf(&b, "# total-hashes: %d\n", total)
	b.WriteString("# attribution: data from haveibeenpwned.com (no licence terms; attribution voluntary)\n")
	if sample != "" {
		b.WriteString("# sample: " + sample + "\n")
	}
	for _, h := range hashes {
		b.WriteString(h + "\n")
	}
	return []byte(b.String())
}

// writeFileAtomic writes data to a temporary file beside path and
// renames it into place, so a reader never sees half a file.
func writeFileAtomic(path string, data []byte, mode os.FileMode) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(mode); err == nil {
		if _, err = f.Write(data); err == nil {
			err = f.Sync()
		}
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
