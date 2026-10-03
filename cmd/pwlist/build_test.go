package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1" //nolint:gosec // synthetic corpus in HIBP's shape
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/blocklist"
)

// The corpus here is synthetic: hashes made from SHA-1 of a counter,
// counts from a formula. No real HIBP response is recorded in this
// repository (#52; the owner has not approved a recorded fixture).

var testNow = time.Date(2026, 10, 2, 4, 30, 0, 0, time.UTC)

// corpus is a fake Pwned Passwords dataset: for each prefix, its lines.
type corpus struct {
	bodies map[string]string // prefix -> response body, CRLF lines as HIBP sends them
	all    []entry           // every non-zero entry, for computing the expected top N
}

// variedCorpus is newCorpus(prefixes, 1000, variedCount), made once per
// size: building one under -race costs most of a second, and most tests
// want the same few. Corpora are never modified after they are made.
func variedCorpus(prefixes int) *corpus {
	corporaMu.Lock()
	defer corporaMu.Unlock()
	if c, ok := corpora[prefixes]; ok {
		return c
	}
	c := newCorpus(prefixes, 1000, variedCount)
	corpora[prefixes] = c
	return c
}

var (
	corporaMu sync.Mutex
	corpora   = map[int]*corpus{}
)

// newCorpus makes prefixes*per hashes, counted by count(prefix, i). A
// count of 0 is written as a padding line, which the builder must skip.
func newCorpus(prefixes, per int, count func(p, i int) int64) *corpus {
	c := &corpus{bodies: map[string]string{}}
	for p := range prefixes {
		prefix := fmt.Sprintf("%05X", p)
		var lines []string
		for i := range per {
			h := sha1.Sum([]byte(fmt.Sprintf("%d/%d", p, i))) //nolint:gosec // synthetic
			suffix := strings.ToUpper(hex.EncodeToString(h[:]))[5:]
			n := count(p, i)
			lines = append(lines, fmt.Sprintf("%s:%d", suffix, n))
			if n > 0 {
				c.all = append(c.all, entry{Hash: prefix + suffix, Count: n})
			}
		}
		slices.Sort(lines) // HIBP serves a range sorted by suffix
		c.bodies[prefix] = strings.Join(lines, "\r\n")
	}
	return c
}

// variedCount spreads counts over 1-3000 with plenty of ties, so the
// 10,000th place is decided by the (count desc, hash asc) tie-break.
func variedCount(p, i int) int64 { return int64(1 + (p*7919+i*104729)%3000) }

// expected is the list a correct build writes: the top n by (count
// desc, hash asc), by brute force, sorted by hash.
func (c *corpus) expected(n int) []string {
	all := slices.Clone(c.all)
	slices.SortFunc(all, func(a, b entry) int {
		if a.Count != b.Count {
			if a.Count > b.Count {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Hash, b.Hash)
	})
	hs := make([]string, n)
	for i := range n {
		hs[i] = all[i].Hash
	}
	slices.Sort(hs)
	return hs
}

// rangeServer serves a corpus at /range/{prefix}, gzip-compressed when
// asked, and can be told to fail a prefix a number of times.
type rangeServer struct {
	*httptest.Server
	c          *corpus
	mu         sync.Mutex
	hits       map[string]int
	failures   map[string][]int // prefix -> statuses to answer before succeeding
	retryAfter string
	override   map[string]string // prefix -> body to serve instead
	requests   []*http.Request
}

func newRangeServer(t *testing.T, c *corpus) *rangeServer {
	t.Helper()
	s := &rangeServer{c: c, hits: map[string]int{}, failures: map[string][]int{}, override: map[string]string{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

func (s *rangeServer) serve(w http.ResponseWriter, r *http.Request) {
	prefix := strings.TrimPrefix(r.URL.Path, "/range/")
	s.mu.Lock()
	s.hits[prefix]++
	s.requests = append(s.requests, r)
	if f := s.failures[prefix]; len(f) > 0 {
		s.failures[prefix] = f[1:]
		if s.retryAfter != "" {
			w.Header().Set("Retry-After", s.retryAfter)
		}
		s.mu.Unlock()
		w.WriteHeader(f[0])
		return
	}
	body, ok := s.override[prefix]
	if !ok {
		body, ok = s.c.bodies[prefix]
	}
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte(body))
		_ = gz.Close()
		return
	}
	_, _ = w.Write([]byte(body))
}

func (s *rangeServer) hitCount(prefix string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[prefix]
}

func (s *rangeServer) totalHits() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, h := range s.hits {
		n += h
	}
	return n
}

type sleeps struct {
	mu sync.Mutex
	d  []time.Duration
}

func (s *sleeps) sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	s.d = append(s.d, d)
	s.mu.Unlock()
	return ctx.Err()
}

// testBuilder walks every prefix of srv's corpus as a full run: the
// full range is scaled down to the test corpus, with sanity bars to
// match.
func testBuilder(t *testing.T, srv *rangeServer, prefixes int) (*builder, *bytes.Buffer, *sleeps) {
	t.Helper()
	dir := t.TempDir()
	var log bytes.Buffer
	sl := &sleeps{}
	return &builder{
		baseURL:     srv.URL + "/range/",
		client:      srv.Client(),
		userAgent:   "gauntlet-pwlist/test (+gitlab.tomlawson.io/ai/gauntlet)",
		prefixes:    prefixes,
		fullRange:   prefixes,
		chunkSize:   4,
		concurrency: 3,
		top:         defaultTop,
		minTotal:    1,
		minCount:    1,
		checkpoint:  filepath.Join(dir, "checkpoint.json"),
		out:         filepath.Join(dir, "top10k.txt"),
		log:         &log,
		now:         func() time.Time { return testNow },
		sleep:       sl.sleep,
	}, &log, sl
}

func body(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var hs []string
	for _, l := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if !strings.HasPrefix(l, "#") {
			hs = append(hs, l)
		}
	}
	return hs
}

func TestBuildKeepsTheTopByCountThenHash(t *testing.T) {
	t.Parallel()
	c := variedCorpus(16)
	srv := newRangeServer(t, c)
	b, log, _ := testBuilder(t, srv, 16)
	if err := b.run(context.Background()); err != nil {
		t.Fatalf("run: %v\n%s", err, log)
	}
	if got, want := body(t, b.out), c.expected(defaultTop); !slices.Equal(got, want) {
		t.Fatal("the list is not the top 10,000 by (count desc, hash asc)")
	}
	data, _ := os.ReadFile(b.out)
	l, err := blocklist.Parse(data)
	if err != nil || l.Len() != defaultTop {
		t.Fatalf("output does not parse as a list: %v", err)
	}
	// One progress line per chunk.
	if n := strings.Count(log.String(), "pwlist: chunk "); n != 4 {
		t.Fatalf("want 4 progress lines, got %d:\n%s", n, log)
	}
	if _, err := os.Stat(b.checkpoint); !os.IsNotExist(err) {
		t.Fatal("the checkpoint must be removed after a successful run")
	}
}

// Every count equal: the top N is exactly the N smallest hashes.
func TestBuildTieBreakIsHashAscending(t *testing.T) {
	t.Parallel()
	c := newCorpus(12, 1000, func(int, int) int64 { return 7 })
	srv := newRangeServer(t, c)
	b, log, _ := testBuilder(t, srv, 12)
	if err := b.run(context.Background()); err != nil {
		t.Fatalf("run: %v\n%s", err, log)
	}
	all := make([]string, len(c.all))
	for i, e := range c.all {
		all[i] = e.Hash
	}
	slices.Sort(all)
	if got := body(t, b.out); !slices.Equal(got, all[:defaultTop]) {
		t.Fatal("ties were not broken by ascending hash")
	}
}

// The golden header, and that the same corpus gives the same bytes
// whatever the concurrency.
func TestBuildOutputIsDeterministicAndInFormat(t *testing.T) {
	t.Parallel()
	c := variedCorpus(16)
	srv := newRangeServer(t, c)
	var outs [][]byte
	for _, conc := range []int{1, 7} {
		b, log, _ := testBuilder(t, srv, 16)
		b.concurrency = conc
		if err := b.run(context.Background()); err != nil {
			t.Fatalf("run: %v\n%s", err, log)
		}
		data, _ := os.ReadFile(b.out)
		outs = append(outs, data)

		sum, _ := os.ReadFile(b.out + ".sha256")
		if !strings.HasSuffix(string(sum), "  top10k.txt\n") || len(sum) != 64+2+len("top10k.txt")+1 {
			t.Fatalf("checksum file: %q", sum)
		}
	}
	if !bytes.Equal(outs[0], outs[1]) {
		t.Fatal("concurrency changed the output")
	}
	wantHeader := strings.Join([]string{
		"# format: gauntlet-pwned-top10k/1",
		"# source: Have I Been Pwned Pwned Passwords range API (SHA-1)",
		"# built: 2026-10-02T04:30:00Z",
		"# count: 10000",
		"# min-count: ",
	}, "\n")
	if !strings.HasPrefix(string(outs[0]), wantHeader) {
		t.Fatalf("header:\n%s", string(outs[0])[:400])
	}
	if !strings.Contains(string(outs[0]), "\n# total-hashes: 16000\n# attribution: data from haveibeenpwned.com (no licence terms; attribution voluntary)\n") {
		t.Fatalf("total or attribution header wrong:\n%s", string(outs[0])[:400])
	}
}

func TestBuildRequestsLikeTheDesignSays(t *testing.T) {
	t.Parallel()
	c := variedCorpus(12)
	srv := newRangeServer(t, c)
	b, log, _ := testBuilder(t, srv, 12)
	if err := b.run(context.Background()); err != nil {
		t.Fatalf("run: %v\n%s", err, log)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.requests) != 12 {
		t.Fatalf("%d requests for 12 prefixes", len(srv.requests))
	}
	for _, r := range srv.requests {
		if r.Header.Get("User-Agent") != b.userAgent {
			t.Errorf("User-Agent %q", r.Header.Get("User-Agent"))
		}
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			t.Error("gzip not requested")
		}
		if r.Header.Get("Add-Padding") != "" {
			t.Error("Add-Padding sent")
		}
	}
}

// Padding lines (count 0) are skipped, and not counted.
func TestBuildIgnoresCountZeroLines(t *testing.T) {
	t.Parallel()
	c := newCorpus(12, 1000, func(p, i int) int64 {
		if i%10 == 0 {
			return 0
		}
		return variedCount(p, i)
	})
	srv := newRangeServer(t, c)
	b, log, _ := testBuilder(t, srv, 12)
	if err := b.run(context.Background()); err != nil {
		t.Fatalf("run: %v\n%s", err, log)
	}
	data, _ := os.ReadFile(b.out)
	if !strings.Contains(string(data), "# total-hashes: 10800\n") {
		t.Fatal("count-0 lines were counted")
	}
	if !slices.Equal(body(t, b.out), c.expected(defaultTop)) {
		t.Fatal("wrong list with padding lines present")
	}
}

func TestBuildRetriesTransientFailures(t *testing.T) {
	t.Parallel()
	for _, code := range []int{429, 500, 502, 503} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			t.Parallel()
			c := variedCorpus(12)
			srv := newRangeServer(t, c)
			srv.failures["00005"] = []int{code, code, code, code} // four failures, fifth attempt succeeds
			b, log, sl := testBuilder(t, srv, 12)
			if err := b.run(context.Background()); err != nil {
				t.Fatalf("run: %v\n%s", err, log)
			}
			if srv.hitCount("00005") != 5 {
				t.Fatalf("hits = %d, want 5", srv.hitCount("00005"))
			}
			if len(sl.d) != 4 {
				t.Fatalf("sleeps = %v", sl.d)
			}
			for i, d := range sl.d {
				ceiling := min(minBackoff<<i, maxBackoff)
				if d < minBackoff || d > ceiling {
					t.Errorf("backoff %d = %v, outside [%v, %v]", i+1, d, minBackoff, ceiling)
				}
			}
		})
	}
}

func TestBuildGivesUpAfterFiveAttempts(t *testing.T) {
	t.Parallel()
	c := variedCorpus(12)
	srv := newRangeServer(t, c)
	srv.failures["00003"] = []int{503, 503, 503, 503, 503, 503}
	b, _, _ := testBuilder(t, srv, 12)
	err := b.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "gave up after 5 attempts") {
		t.Fatalf("run = %v", err)
	}
	if srv.hitCount("00003") != 5 {
		t.Fatalf("hits = %d, want 5", srv.hitCount("00003"))
	}
	if _, err := os.Stat(b.out); !os.IsNotExist(err) {
		t.Fatal("a failed run wrote output")
	}
}

func TestBuildHonoursRetryAfter(t *testing.T) {
	t.Parallel()
	for name, header := range map[string]string{
		"seconds":   "7",
		"HTTP date": testNow.Add(9 * time.Second).Format(http.TimeFormat),
		"too long":  "3600",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := variedCorpus(12)
			srv := newRangeServer(t, c)
			srv.failures["00002"] = []int{429}
			srv.retryAfter = header
			b, log, sl := testBuilder(t, srv, 12)
			if err := b.run(context.Background()); err != nil {
				t.Fatalf("run: %v\n%s", err, log)
			}
			want := map[string]time.Duration{"seconds": 7 * time.Second, "HTTP date": 9 * time.Second, "too long": maxRetryAfter}[name]
			if len(sl.d) != 1 || sl.d[0] != want {
				t.Fatalf("slept %v, want [%v]", sl.d, want)
			}
		})
	}
}

// Anything that is not a transient failure ends the run at once.
func TestBuildFailsFastOnPermanentErrors(t *testing.T) {
	t.Parallel()
	cases := map[string]func(s *rangeServer){
		"404":                func(s *rangeServer) { s.failures["00004"] = []int{404} },
		"403":                func(s *rangeServer) { s.failures["00004"] = []int{403} },
		"lowercase hex":      func(s *rangeServer) { s.override["00004"] = strings.ToLower(s.c.bodies["00004"]) },
		"no count":           func(s *rangeServer) { s.override["00004"] = "0123456789ABCDEF0123456789ABCDEF012" },
		"negative count":     func(s *rangeServer) { s.override["00004"] = "0123456789ABCDEF0123456789ABCDEF012:-1" },
		"36-char suffix":     func(s *rangeServer) { s.override["00004"] = "0123456789ABCDEF0123456789ABCDEF0123:5" },
		"count overflow":     func(s *rangeServer) { s.override["00004"] = "0123456789ABCDEF0123456789ABCDEF012:99999999999999999999" },
		"trailing junk":      func(s *rangeServer) { s.override["00004"] = "0123456789ABCDEF0123456789ABCDEF012:5 x" },
		"HTML error page":    func(s *rangeServer) { s.override["00004"] = "<html>oops</html>" },
		"wrong separator":    func(s *rangeServer) { s.override["00004"] = "0123456789ABCDEF0123456789ABCDEF012;5" },
		"empty count digits": func(s *rangeServer) { s.override["00004"] = "0123456789ABCDEF0123456789ABCDEF012:" },
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := variedCorpus(12)
			srv := newRangeServer(t, c)
			set(srv)
			b, _, sl := testBuilder(t, srv, 12)
			if err := b.run(context.Background()); err == nil {
				t.Fatal("run succeeded")
			}
			if srv.hitCount("00004") != 1 || len(sl.d) != 0 {
				t.Fatalf("retried a permanent failure: hits %d, sleeps %v", srv.hitCount("00004"), sl.d)
			}
		})
	}
}

// An empty 200 is a fault on the way, so it is retried.
func TestBuildRetriesAnEmptyResponse(t *testing.T) {
	t.Parallel()
	c := variedCorpus(12)
	srv := newRangeServer(t, c)
	srv.override["00001"] = ""
	b, _, _ := testBuilder(t, srv, 12)
	if err := b.run(context.Background()); err == nil || !strings.Contains(err.Error(), "empty response") {
		t.Fatalf("run = %v", err)
	}
	if srv.hitCount("00001") != maxAttempts {
		t.Fatalf("hits = %d", srv.hitCount("00001"))
	}
}

// A network failure -- the connection dropped part-way through a
// response -- is transient. (A connection dropped before any response
// is retried by net/http itself, for a GET, so it never reaches here.)
func TestBuildRetriesADroppedConnection(t *testing.T) {
	t.Parallel()
	c := variedCorpus(12)
	var mu sync.Mutex
	dropped := false
	srv := newRangeServer(t, c)
	inner := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		drop := !dropped && strings.HasSuffix(r.URL.Path, "/00006")
		dropped = dropped || drop
		mu.Unlock()
		if drop {
			// Promise 100,000 bytes, send three, hang up: a read
			// error part-way through a 200.
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\nABC")
				_ = buf.Flush()
				_ = conn.Close()
			}
			return
		}
		inner.ServeHTTP(w, r)
	})
	b, log, sl := testBuilder(t, srv, 12)
	if err := b.run(context.Background()); err != nil {
		t.Fatalf("run: %v\n%s", err, log)
	}
	if len(sl.d) != 1 {
		t.Fatalf("sleeps %v, want one retry", sl.d)
	}
}

// A failed run resumes from its checkpoint at the next chunk, fetching
// nothing it already had, and ends with the same list as an
// uninterrupted run.
func TestBuildResumesFromItsCheckpoint(t *testing.T) {
	t.Parallel()
	c := variedCorpus(16)
	srv := newRangeServer(t, c)
	srv.failures["0000A"] = []int{404} // chunk 3 of 4
	b, log, _ := testBuilder(t, srv, 16)
	if err := b.run(context.Background()); err == nil {
		t.Fatal("first run succeeded")
	}
	if _, err := os.Stat(b.checkpoint); err != nil {
		t.Fatalf("no checkpoint after a failed run: %v", err)
	}
	// A fresh server for the second run: requests the first run
	// cancelled may still reach the first server's counter late.
	srv2 := newRangeServer(t, c)
	b.baseURL, b.client = srv2.URL+"/range/", srv2.Client()

	log.Reset()
	if err := b.run(context.Background()); err != nil {
		t.Fatalf("resumed run: %v\n%s", err, log)
	}
	if !strings.Contains(log.String(), "resuming from checkpoint") {
		t.Fatalf("did not resume:\n%s", log)
	}
	if got := srv2.totalHits(); got != 8 {
		t.Fatalf("the resumed run made %d requests, want 8 (chunks 3 and 4)", got)
	}
	if !slices.Equal(body(t, b.out), c.expected(defaultTop)) {
		t.Fatal("the resumed run's list differs from an uninterrupted one")
	}
	data, _ := os.ReadFile(b.out)
	if !strings.Contains(string(data), "# total-hashes: 16000\n") {
		t.Fatal("the resumed run lost the checkpoint's total")
	}
}

func TestBuildIgnoresAnUnusableCheckpoint(t *testing.T) {
	t.Parallel()
	cases := map[string]func(b *builder){
		"older than 24 hours": func(b *builder) {
			later := testNow.Add(25 * time.Hour)
			b.now = func() time.Time { return later }
		},
		"saved in the future": func(b *builder) {
			earlier := testNow.Add(-time.Hour)
			b.now = func() time.Time { return earlier }
		},
		"different prefixes": func(b *builder) { b.prefixes, b.fullRange = 12, 12 },
		"corrupt": func(b *builder) {
			if err := os.WriteFile(b.checkpoint, []byte("{not json"), 0o600); err != nil {
				panic(err)
			}
		},
		"bad entry": func(b *builder) {
			data, _ := os.ReadFile(b.checkpoint)
			data = bytes.Replace(data, []byte(`"h":"`), []byte(`"h":"zz`), 1)
			if err := os.WriteFile(b.checkpoint, data, 0o600); err != nil {
				panic(err)
			}
		},
		"wrong format": func(b *builder) {
			data, _ := os.ReadFile(b.checkpoint)
			data = bytes.Replace(data, []byte(checkpointFormat), []byte("something-else/9"), 1)
			if err := os.WriteFile(b.checkpoint, data, 0o600); err != nil {
				panic(err)
			}
		},
	}
	for name, spoil := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := variedCorpus(16)
			srv := newRangeServer(t, c)
			srv.failures["0000A"] = []int{404}
			b, log, _ := testBuilder(t, srv, 16)
			if err := b.run(context.Background()); err == nil {
				t.Fatal("first run succeeded")
			}
			spoil(b)
			log.Reset()
			srv2 := newRangeServer(t, c)
			b.baseURL, b.client = srv2.URL+"/range/", srv2.Client()
			if err := b.run(context.Background()); err != nil {
				t.Fatalf("second run: %v\n%s", err, log)
			}
			if !strings.Contains(log.String(), "ignoring checkpoint") {
				t.Fatalf("checkpoint not reported as ignored:\n%s", log)
			}
			if got := srv2.totalHits(); got != b.prefixes {
				t.Fatalf("second run made %d requests, want all %d", got, b.prefixes)
			}
		})
	}
}

func TestBuildSanityBars(t *testing.T) {
	t.Parallel()
	t.Run("too few hashes seen", func(t *testing.T) {
		t.Parallel()
		srv := newRangeServer(t, variedCorpus(12))
		b, _, _ := testBuilder(t, srv, 12)
		b.minTotal = 12001
		if err := b.run(context.Background()); err == nil || !strings.Contains(err.Error(), "nothing written") {
			t.Fatalf("run = %v", err)
		}
		if _, err := os.Stat(b.out); !os.IsNotExist(err) {
			t.Fatal("output written despite the failed bar")
		}
	})
	t.Run("10,000th count too low", func(t *testing.T) {
		t.Parallel()
		srv := newRangeServer(t, variedCorpus(12))
		b, _, _ := testBuilder(t, srv, 12)
		b.minCount = 3001
		if err := b.run(context.Background()); err == nil || !strings.Contains(err.Error(), "10,000th entry") {
			t.Fatalf("run = %v", err)
		}
	})
	t.Run("fewer than 10,000 distinct", func(t *testing.T) {
		t.Parallel()
		srv := newRangeServer(t, variedCorpus(9))
		b, _, _ := testBuilder(t, srv, 9)
		if err := b.run(context.Background()); err == nil || !strings.Contains(err.Error(), "only 9000 distinct") {
			t.Fatalf("run = %v", err)
		}
	})
}

// A sample run (--prefixes below the full range) scales the total bar,
// skips the count bar, and marks its output so nothing will sign or
// accept it.
func TestBuildSampleRun(t *testing.T) {
	t.Parallel()
	srv := newRangeServer(t, variedCorpus(12))
	b, log, _ := testBuilder(t, srv, 12)
	b.fullRange = 48       // a quarter of the "full" range
	b.minTotal = 4 * 12000 // scaled to a quarter: 12000, which 12 prefixes meet
	b.minCount = 1 << 40   // ignored for a sample
	if err := b.run(context.Background()); err != nil {
		t.Fatalf("run: %v\n%s", err, log)
	}
	data, _ := os.ReadFile(b.out)
	if !strings.Contains(string(data), "\n# sample: 12 of 48 prefixes; not for publication\n") {
		t.Fatal("sample output not marked")
	}
	if _, err := blocklist.Parse(data); err == nil {
		t.Fatal("blocklist.Parse accepted a sample")
	}
	b.minTotal = 4*12000 + 4
	if err := b.run(context.Background()); err == nil {
		t.Fatal("a sample under its scaled total passed")
	}
}

func TestBuildStopsWhenCancelled(t *testing.T) {
	t.Parallel()
	srv := newRangeServer(t, variedCorpus(12))
	b, _, _ := testBuilder(t, srv, 12)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.run(ctx); err == nil {
		t.Fatal("a cancelled run succeeded")
	}
}

func TestTopNKeepsTheBest(t *testing.T) {
	t.Parallel()
	top := &topN{n: 3}
	for _, e := range []entry{
		{"B", 5}, {"A", 5}, {"C", 9}, {"D", 1}, {"E", 5}, {"0", 5},
	} {
		top.offer(e)
	}
	got := slices.Clone(top.h)
	slices.SortFunc(got, func(a, b entry) int { return strings.Compare(a.Hash, b.Hash) })
	want := []entry{{"0", 5}, {"A", 5}, {"C", 9}}
	if !slices.Equal(got, want) {
		t.Fatalf("top 3 = %v, want %v", got, want)
	}
	if top.floor() != 5 {
		t.Fatalf("floor = %d", top.floor())
	}
	if (&topN{n: 3}).floor() != 0 {
		t.Fatal("a set that is not full must take anything")
	}
}

func TestParseRetryAfter(t *testing.T) {
	t.Parallel()
	for v, want := range map[string]time.Duration{
		"":    0,
		"0":   0,
		"12":  12 * time.Second,
		"-3":  0,
		"abc": 0,
		testNow.Add(-time.Minute).Format(http.TimeFormat): 0,
		testNow.Add(time.Minute).Format(http.TimeFormat):  time.Minute,
	} {
		if got := parseRetryAfter(v, testNow); got != want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestBackoffBounds(t *testing.T) {
	t.Parallel()
	for n := 1; n <= 8; n++ {
		for range 200 {
			d := backoff(n, 0)
			if d < minBackoff || d > maxBackoff {
				t.Fatalf("backoff(%d) = %v", n, d)
			}
		}
	}
	if d := backoff(1, 30*time.Second); d != 30*time.Second {
		t.Fatalf("Retry-After 30s gave %v", d)
	}
	if d := backoff(1, time.Hour); d != maxRetryAfter {
		t.Fatalf("Retry-After 1h gave %v", d)
	}
}

func TestSleepCtx(t *testing.T) {
	t.Parallel()
	if err := sleepCtx(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepCtx(ctx, time.Hour); err == nil {
		t.Fatal("sleepCtx ignored a cancelled context")
	}
}
