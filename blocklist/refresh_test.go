package blocklist

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/internal/listsig"
)

// registry is a fake package registry: it serves whatever files the test
// put in it under /current/, and counts requests per file.
type registry struct {
	srv   *httptest.Server
	mu    sync.Mutex
	files map[string][]byte
	codes map[string]int
	hits  map[string]int
}

func newRegistry(t *testing.T) *registry {
	t.Helper()
	g := &registry{files: map[string][]byte{}, codes: map[string]int{}, hits: map[string]int{}}
	g.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/current/")
		g.mu.Lock()
		defer g.mu.Unlock()
		g.hits[name]++
		if code := g.codes[name]; code != 0 {
			w.WriteHeader(code)
			return
		}
		data, ok := g.files[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *registry) url() string { return g.srv.URL + "/current/top10k.txt" }

// publish puts a list, its checksum and its signature in the registry,
// as the CI publish job does.
func (g *registry) publish(data, sig []byte) {
	sum := sha256.Sum256(data)
	g.set("top10k.txt", data)
	g.set("top10k.txt.sig", sig)
	g.set("top10k.txt.sha256", []byte(hex.EncodeToString(sum[:])+"  top10k.txt\n"))
}

func (g *registry) set(name string, data []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.files[name] = data
}

func (g *registry) fail(name string, code int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.codes[name] = code
}

func (g *registry) hitsFor(name string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.hits[name]
}

func (g *registry) resetHits() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.hits = map[string]int{}
}

// logBuf captures a Refresher's log and counts its lines by level.
type logBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuf) count(level string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Count(b.buf.String(), "level="+level)
}

func (b *logBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type fixture struct {
	reg  *registry
	dir  string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	log  *logBuf
	now  time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv := newKey(t)
	return &fixture{
		reg:  newRegistry(t),
		dir:  filepath.Join(t.TempDir(), "blocklist"),
		pub:  pub,
		priv: priv,
		log:  &logBuf{},
		now:  testBuilt.Add(48 * time.Hour),
	}
}

// refresher builds a Refresher trusting f.pub, with embedded as the
// release's own copy.
func (f *fixture) refresher(t *testing.T, embedded *List) *Refresher {
	t.Helper()
	ring, err := listsig.NewKeyring(f.pub)
	if err != nil {
		t.Fatal(err)
	}
	return f.refresherWithKeys(t, embedded, func() (listsig.Keyring, error) { return ring, nil })
}

func (f *fixture) refresherWithKeys(t *testing.T, embedded *List, keys func() (listsig.Keyring, error)) *Refresher {
	t.Helper()
	r, err := newRefresher(RefreshConfig{
		URL:        f.reg.url(),
		Dir:        f.dir,
		HTTPClient: f.reg.srv.Client(),
		Log:        slog.New(slog.NewTextHandler(f.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}, keys, embedded, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// signedList is a list built at built from seed's hashes, signed by
// f.priv.
func (f *fixture) signedList(t *testing.T, built time.Time, seed string, extra ...string) ([]byte, []byte) {
	t.Helper()
	data := listFile(built, listHashes(seed), extra...)
	return data, sign(t, data, f.priv)
}

func TestRefreshAdoptsAVerifiedNewerList(t *testing.T) {
	f := newFixture(t)
	data, sig := f.signedList(t, testBuilt, "a")
	f.reg.publish(data, sig)

	r := f.refresher(t, &List{})
	if r.Current().Len() != 0 {
		t.Fatal("before any refresh, Current must be the embedded copy")
	}
	r.refresh(context.Background())

	if got := r.Current(); got.Len() != size || !got.Built().Equal(testBuilt) || !got.Contains("password") {
		t.Fatalf("Current after refresh: Len=%d Built=%v", got.Len(), got.Built())
	}
	if f.log.count("WARN") != 0 || f.log.count("INFO") != 1 {
		t.Fatalf("want one Info and no Warn, log:\n%s", f.log)
	}
	// Kept on disk, 0600 in a 0700 directory, byte for byte.
	p := filepath.Join(f.dir, storedPair)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if gotData, gotSig, err := decodePair(b); err != nil || !bytes.Equal(gotData, data) || !bytes.Equal(gotSig, sig) {
		t.Fatalf("not stored as published: %v", err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("%s mode %v, want 0600", storedPair, fi.Mode().Perm())
	}
	if fi, _ := os.Stat(f.dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v, want 0700", fi.Mode().Perm())
	}
	if entries, _ := os.ReadDir(f.dir); len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
}

func TestRefreshUnchangedFetchesOnlyTheChecksum(t *testing.T) {
	f := newFixture(t)
	data, sig := f.signedList(t, testBuilt, "a")
	f.reg.publish(data, sig)
	r := f.refresher(t, &List{})
	r.refresh(context.Background())
	f.reg.resetHits()

	r.refresh(context.Background())
	if f.reg.hitsFor("top10k.txt.sha256") != 1 || f.reg.hitsFor("top10k.txt") != 0 || f.reg.hitsFor("top10k.txt.sig") != 0 {
		t.Fatalf("unchanged list: hits sha256=%d txt=%d sig=%d",
			f.reg.hitsFor("top10k.txt.sha256"), f.reg.hitsFor("top10k.txt"), f.reg.hitsFor("top10k.txt.sig"))
	}
}

func TestRefreshAdoptsALaterList(t *testing.T) {
	f := newFixture(t)
	data, sig := f.signedList(t, testBuilt, "a")
	f.reg.publish(data, sig)
	r := f.refresher(t, &List{})
	r.refresh(context.Background())

	later := testBuilt.Add(24 * time.Hour)
	data2, sig2 := f.signedList(t, later, "b")
	f.reg.publish(data2, sig2)
	r.refresh(context.Background())
	if !r.Current().Built().Equal(later) || !r.Current().Contains("b-0") || r.Current().Contains("a-0") {
		t.Fatalf("the later list was not adopted: Built=%v", r.Current().Built())
	}
}

// GitHub serves a release file by redirecting to its download host; a
// list reached through https redirects is adopted like any other.
func TestRefreshFollowsHTTPSRedirects(t *testing.T) {
	f := newFixture(t)
	data, sig := f.signedList(t, testBuilt, "a")
	f.reg.publish(data, sig)
	inner := f.reg.srv.Config.Handler
	f.reg.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/download/") {
			http.Redirect(w, r, "/current/"+strings.TrimPrefix(r.URL.Path, "/download/"), http.StatusFound)
			return
		}
		inner.ServeHTTP(w, r)
	})
	r, err := newRefresher(RefreshConfig{
		URL: f.reg.srv.URL + "/download/top10k.txt", Dir: f.dir, HTTPClient: f.reg.srv.Client(),
	}, func() (listsig.Keyring, error) { return listsig.NewKeyring(f.pub) }, &List{}, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	r.refresh(context.Background())
	if r.Current().Len() != size {
		t.Fatal("a list behind a redirect was not adopted")
	}
}

// The copy in Dir survives a restart, verified again on the way in, and
// costs no network request.
func TestRestartStartsFromTheStoredCopy(t *testing.T) {
	f := newFixture(t)
	data, sig := f.signedList(t, testBuilt, "a")
	f.reg.publish(data, sig)
	f.refresher(t, &List{}).refresh(context.Background())
	f.reg.resetHits()

	r := f.refresher(t, &List{})
	if !r.Current().Built().Equal(testBuilt) || r.Current().Len() != size {
		t.Fatalf("restart did not load the stored copy: Built=%v", r.Current().Built())
	}
	if n := f.reg.hitsFor("top10k.txt.sha256") + f.reg.hitsFor("top10k.txt"); n != 0 {
		t.Fatalf("loading the stored copy made %d requests", n)
	}
}

func TestRestartIgnoresABadStoredCopy(t *testing.T) {
	writePair := func(t *testing.T, f *fixture, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(f.dir, storedPair), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// oldLayout replaces the stored copy with the two-file layout.
	oldLayout := func(t *testing.T, f *fixture, data, sig []byte) {
		t.Helper()
		if err := os.Remove(filepath.Join(f.dir, storedPair)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.dir, storedList), data, 0o600); err != nil {
			t.Fatal(err)
		}
		if sig != nil {
			if err := os.WriteFile(filepath.Join(f.dir, storedSig), sig, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := map[string]func(t *testing.T, f *fixture){
		"list altered": func(t *testing.T, f *fixture) {
			b, _ := os.ReadFile(filepath.Join(f.dir, storedPair))
			b[len(b)-2] ^= 1
			writePair(t, f, b)
		},
		"no header": func(t *testing.T, f *fixture) {
			writePair(t, f, []byte("not a stored list"))
		},
		"signature length past the end": func(t *testing.T, f *fixture) {
			writePair(t, f, fmt.Appendf(nil, "%s%d\n", pairHeader, 1<<20))
		},
		"signed by another key": func(t *testing.T, f *fixture) {
			_, other := newKey(t)
			data := listFile(testBuilt, listHashes("a"))
			writePair(t, f, encodePair(data, sign(t, data, other)))
		},
		"list unreadable": func(t *testing.T, f *fixture) {
			p := filepath.Join(f.dir, storedPair)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"old layout, signature missing": func(t *testing.T, f *fixture) {
			oldLayout(t, f, listFile(testBuilt, listHashes("a")), nil)
		},
		"old layout, list altered": func(t *testing.T, f *fixture) {
			data, sig := f.signedList(t, testBuilt, "a")
			data[len(data)-2] ^= 1
			oldLayout(t, f, data, sig)
		},
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			data, sig := f.signedList(t, testBuilt, "a")
			f.reg.publish(data, sig)
			f.refresher(t, &List{}).refresh(context.Background())
			damage(t, f)

			f.log = &logBuf{}
			embedded := &List{}
			r := f.refresher(t, embedded)
			if r.Current() != embedded {
				t.Fatal("a bad stored copy was used")
			}
			if f.log.count("WARN") != 1 {
				t.Fatalf("want one Warn, log:\n%s", f.log)
			}
		})
	}
}

// A crash while a newer list is being stored leaves the previous good
// list in use at the next start, never a list beside another list's
// signature that fails verification. The damage below is what an
// interrupted store can leave: the newer signature already in place
// under the separate signature file name, and a half-written temporary
// file.
func TestACrashWhileStoringKeepsTheGoodList(t *testing.T) {
	f := newFixture(t)
	data, sig := f.signedList(t, testBuilt, "a")
	f.reg.publish(data, sig)
	f.refresher(t, &List{}).refresh(context.Background())

	newer, newerSig := f.signedList(t, testBuilt.Add(time.Hour), "b")
	if err := os.WriteFile(filepath.Join(f.dir, storedSig), newerSig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, ".top10k.signed.12345"), newer[:len(newer)/2], 0o600); err != nil {
		t.Fatal(err)
	}

	f.log = &logBuf{}
	r := f.refresher(t, &List{})
	if !r.Current().Built().Equal(testBuilt) || r.Current().Len() != size {
		t.Fatalf("after an interrupted store the good list was lost: Built=%v, log:\n%s", r.Current().Built(), f.log)
	}
}

// A copy kept in the older two-file layout is still loaded, and the
// next list adopted replaces it with the single file.
func TestRestartReadsTheOldTwoFileLayout(t *testing.T) {
	f := newFixture(t)
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, sig := f.signedList(t, testBuilt, "a")
	for name, b := range map[string][]byte{storedList: data, storedSig: sig} {
		if err := os.WriteFile(filepath.Join(f.dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r := f.refresher(t, &List{})
	if !r.Current().Built().Equal(testBuilt) || r.Current().Len() != size {
		t.Fatalf("the old layout was not loaded: Built=%v, log:\n%s", r.Current().Built(), f.log)
	}

	data2, sig2 := f.signedList(t, testBuilt.Add(time.Hour), "b")
	f.reg.publish(data2, sig2)
	r.refresh(context.Background())
	entries, _ := os.ReadDir(f.dir)
	if len(entries) != 1 || entries[0].Name() != storedPair {
		t.Fatalf("after a store Dir holds %v, want only %s", entries, storedPair)
	}
}

// A host that boots with its clock behind still starts from the copy it
// verified and adopted earlier: the future-date check is for downloads.
func TestRestartKeepsTheStoredCopyWhenTheClockIsBehind(t *testing.T) {
	f := newFixture(t)
	data, sig := f.signedList(t, testBuilt, "a")
	f.reg.publish(data, sig)
	f.refresher(t, &List{}).refresh(context.Background())

	f.now = testBuilt.Add(-72 * time.Hour)
	f.log = &logBuf{}
	r := f.refresher(t, &List{})
	if !r.Current().Built().Equal(testBuilt) || r.Current().Len() != size {
		t.Fatalf("the stored copy was not loaded with the clock behind: Built=%v, log:\n%s", r.Current().Built(), f.log)
	}
}

// An application upgraded to a release whose embedded copy is newer
// than the one it kept on disk uses the embedded copy.
func TestRestartPrefersANewerEmbeddedCopy(t *testing.T) {
	f := newFixture(t)
	data, sig := f.signedList(t, testBuilt, "a")
	f.reg.publish(data, sig)
	f.refresher(t, &List{}).refresh(context.Background())

	newer, err := Parse(listFile(testBuilt.Add(time.Hour), listHashes("e")))
	if err != nil {
		t.Fatal(err)
	}
	if r := f.refresher(t, newer); r.Current() != newer {
		t.Fatalf("Current built %v, want the newer embedded copy", r.Current().Built())
	}
}

// Each refusal leaves Current as it was and logs exactly one Warn.
func TestRefreshRefuses(t *testing.T) {
	type setup func(t *testing.T, f *fixture)
	publishSigned := func(built time.Time, extra ...string) setup {
		return func(t *testing.T, f *fixture) {
			data, sig := f.signedList(t, built, "a", extra...)
			f.reg.publish(data, sig)
		}
	}
	cases := map[string]setup{
		"signed by an unknown key": func(t *testing.T, f *fixture) {
			_, other := newKey(t)
			data := listFile(testBuilt, listHashes("a"))
			f.reg.publish(data, sign(t, data, other))
		},
		"signature does not match": func(t *testing.T, f *fixture) {
			data, _ := f.signedList(t, testBuilt, "a")
			_, sig := f.signedList(t, testBuilt, "b")
			f.reg.publish(data, sig)
		},
		"checksum does not match": func(t *testing.T, f *fixture) {
			data, sig := f.signedList(t, testBuilt, "a")
			f.reg.publish(data, sig)
			f.reg.set("top10k.txt.sha256", []byte(strings.Repeat("ab", 32)+"  top10k.txt\n"))
		},
		"signed but malformed": func(t *testing.T, f *fixture) {
			data := []byte("# format: gauntlet-pwned-top10k/1\nnot a list\n")
			f.reg.publish(data, sign(t, data, f.priv))
		},
		"signed sample build":   publishSigned(testBuilt, "# sample: 2048 of 1048576 prefixes"),
		"built in the future":   publishSigned(testBuilt.Add(96 * time.Hour)),
		"checksum file missing": func(t *testing.T, f *fixture) { publishSigned(testBuilt)(t, f); f.reg.fail("top10k.txt.sha256", 404) },
		"list missing":          func(t *testing.T, f *fixture) { publishSigned(testBuilt)(t, f); f.reg.fail("top10k.txt", 404) },
		"signature missing":     func(t *testing.T, f *fixture) { publishSigned(testBuilt)(t, f); f.reg.fail("top10k.txt.sig", 404) },
		"registry error":        func(t *testing.T, f *fixture) { publishSigned(testBuilt)(t, f); f.reg.fail("top10k.txt.sha256", 503) },
		"checksum file not a sum": func(t *testing.T, f *fixture) {
			publishSigned(testBuilt)(t, f)
			f.reg.set("top10k.txt.sha256", []byte("hello\n"))
		},
		"checksum file not hex": func(t *testing.T, f *fixture) {
			publishSigned(testBuilt)(t, f)
			f.reg.set("top10k.txt.sha256", []byte(strings.Repeat("zz", 32)+"\n"))
		},
		"checksum file two lines": func(t *testing.T, f *fixture) {
			publishSigned(testBuilt)(t, f)
			f.reg.set("top10k.txt.sha256", []byte(strings.Repeat("ab", 32)+"\n"+strings.Repeat("ab", 32)+"\n"))
		},
		"checksum file too big": func(t *testing.T, f *fixture) {
			publishSigned(testBuilt)(t, f)
			f.reg.set("top10k.txt.sha256", []byte(strings.Repeat("a", maxSumFile+1)))
		},
		"list too big": func(t *testing.T, f *fixture) {
			big := make([]byte, maxListFile+1)
			f.reg.publish(big, sign(t, big, f.priv))
		},
		"signature file too big": func(t *testing.T, f *fixture) {
			data, _ := f.signedList(t, testBuilt, "a")
			f.reg.publish(data, bytes.Repeat([]byte("a"), listsig.MaxSignatureFile+1))
		},
		"store fails": func(t *testing.T, f *fixture) {
			publishSigned(testBuilt)(t, f)
			// Dir's place is taken by a file, so it cannot be created.
			if err := os.WriteFile(f.dir, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			embedded := &List{}
			r := f.refresher(t, embedded)
			set(t, f)
			r.refresh(context.Background())
			if r.Current() != embedded {
				t.Fatalf("Current changed to a list built %v", r.Current().Built())
			}
			if f.log.count("WARN") != 1 {
				t.Fatalf("want exactly one Warn, log:\n%s", f.log)
			}
		})
	}
}

// The size limit itself is what refuses an oversized body: the log names
// the limit, so a refusal for another reason (a bad checksum, a bad
// signature) does not satisfy this. The bodies run well past the limit,
// as a hostile host streaming without end would.
func TestRefreshRefusesABodyOverTheSizeLimit(t *testing.T) {
	cases := map[string]struct {
		limit int
		set   func(t *testing.T, f *fixture)
	}{
		"checksum file": {maxSumFile, func(t *testing.T, f *fixture) {
			data, sig := f.signedList(t, testBuilt, "a")
			f.reg.publish(data, sig)
			f.reg.set("top10k.txt.sha256", []byte(strings.Repeat("a", 10*maxSumFile)))
		}},
		"list": {maxListFile, func(t *testing.T, f *fixture) {
			big := make([]byte, 3*maxListFile)
			f.reg.publish(big, sign(t, big, f.priv))
		}},
		"signature file": {listsig.MaxSignatureFile, func(t *testing.T, f *fixture) {
			data, _ := f.signedList(t, testBuilt, "a")
			f.reg.publish(data, bytes.Repeat([]byte("a"), 10*listsig.MaxSignatureFile))
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			embedded := &List{}
			r := f.refresher(t, embedded)
			c.set(t, f)
			r.refresh(context.Background())
			if r.Current() != embedded {
				t.Fatalf("Current changed to a list built %v", r.Current().Built())
			}
			if want := fmt.Sprintf("larger than the %d-byte limit", c.limit); !strings.Contains(f.log.String(), want) {
				t.Fatalf("the refusal does not say %q, log:\n%s", want, f.log)
			}
		})
	}
}

func TestRefreshRefusesAListNoNewerThanTheCurrentOne(t *testing.T) {
	f := newFixture(t)
	current, err := Parse(listFile(testBuilt, listHashes("e")))
	if err != nil {
		t.Fatal(err)
	}
	r := f.refresher(t, current)
	for _, built := range []time.Time{testBuilt, testBuilt.Add(-time.Hour)} {
		data, sig := f.signedList(t, built, "a")
		f.reg.publish(data, sig)
		r.refresh(context.Background())
		if r.Current() != current {
			t.Fatalf("a list built %v replaced one built %v", built, testBuilt)
		}
	}
	if f.log.count("WARN") != 2 {
		t.Fatalf("want two Warns, log:\n%s", f.log)
	}
}

// With no trusted keys -- this release's state until the owner commits
// one -- nothing is ever adopted.
func TestRefreshWithNoKeysAdoptsNothing(t *testing.T) {
	f := newFixture(t)
	data, sig := f.signedList(t, testBuilt, "a")
	f.reg.publish(data, sig)
	empty := func() (listsig.Keyring, error) { return listsig.Keyring{}, nil }
	r := f.refresherWithKeys(t, &List{}, empty)
	r.refresh(context.Background())
	if r.Current().Len() != 0 || !strings.Contains(f.log.String(), "no trusted public keys") {
		t.Fatalf("adopted with no keys, or wrong reason; log:\n%s", f.log)
	}

	broken := func() (listsig.Keyring, error) { return nil, os.ErrInvalid }
	r = f.refresherWithKeys(t, &List{}, broken)
	r.refresh(context.Background())
	if r.Current().Len() != 0 {
		t.Fatal("adopted with a broken keyring")
	}
}

// The committed keys, through the exported constructor: a list signed
// by a key generated here is never adopted.
func TestNewRefresherUsesTheCommittedKeys(t *testing.T) {
	f := newFixture(t)
	data, sig := f.signedList(t, testBuilt, "a")
	f.reg.publish(data, sig)
	r, err := NewRefresher(RefreshConfig{URL: f.reg.url(), Dir: f.dir, HTTPClient: f.reg.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if r.Current() != Embedded() {
		t.Fatal("a fresh Refresher must start from the embedded copy")
	}
	r.refresh(context.Background())
	if r.Current() != Embedded() {
		t.Fatal("a list signed by an uncommitted key was adopted")
	}
}

// A signed list refused for its content is not downloaded again while
// the published checksum stays the same. A list refused for its
// signature is: re-signing the same bytes must be picked up. So is a
// checksum mismatch, which may be a read across a publish.
func TestRefusalMemory(t *testing.T) {
	t.Run("content refusal is remembered", func(t *testing.T) {
		f := newFixture(t)
		data := []byte("# format: gauntlet-pwned-top10k/1\nnot a list\n") // malformed
		f.reg.publish(data, sign(t, data, f.priv))
		r := f.refresher(t, &List{})
		r.refresh(context.Background())
		f.reg.resetHits()
		r.refresh(context.Background())
		if f.reg.hitsFor("top10k.txt") != 0 || f.log.count("WARN") != 1 {
			t.Fatalf("a refused list was fetched again (hits %d), log:\n%s", f.reg.hitsFor("top10k.txt"), f.log)
		}
		// A new list, under a new checksum, is fetched and adopted.
		data2, sig2 := f.signedList(t, testBuilt, "b")
		f.reg.publish(data2, sig2)
		r.refresh(context.Background())
		if r.Current().Len() != size {
			t.Fatal("a good list under a new checksum was not adopted")
		}
	})
	// A list refused only because it claims a build time in the future
	// is not latched by checksum: it must be re-checked against the
	// clock on every refresh, so it is adopted once the clock catches
	// up without needing a new checksum (#58, R7).
	t.Run("future build time is rechecked, not remembered", func(t *testing.T) {
		f := newFixture(t)
		built := testBuilt.Add(96 * time.Hour) // in the future relative to f.now
		data, sig := f.signedList(t, built, "a")
		f.reg.publish(data, sig)
		r := f.refresher(t, &List{})
		r.refresh(context.Background())
		if r.Current().Len() != 0 {
			t.Fatal("adopted a list dated in the future")
		}

		f.reg.resetHits()
		r.refresh(context.Background())
		if f.reg.hitsFor("top10k.txt") == 0 {
			t.Fatal("a future-dated list under the same checksum must be fetched again, not latched")
		}
		if r.Current().Len() != 0 {
			t.Fatal("adopted a still-future-dated list")
		}

		// The clock catches up: the same bytes, same checksum, are now
		// adopted without a new list being published.
		f.now = built.Add(time.Hour)
		r.refresh(context.Background())
		if r.Current().Len() != size {
			t.Fatal("a list whose build time the clock has caught up to was not adopted")
		}
	})
	t.Run("signature refusal is retried", func(t *testing.T) {
		f := newFixture(t)
		_, other := newKey(t)
		data := listFile(testBuilt, listHashes("a"))
		f.reg.publish(data, sign(t, data, other))
		r := f.refresher(t, &List{})
		r.refresh(context.Background())
		if r.Current().Len() != 0 {
			t.Fatal("adopted a list signed by an unknown key")
		}
		// The same bytes, re-signed by the trusted key.
		f.reg.publish(data, sign(t, data, f.priv))
		r.refresh(context.Background())
		if r.Current().Len() != size {
			t.Fatal("the re-signed list was not adopted")
		}
	})
	t.Run("checksum mismatch is retried", func(t *testing.T) {
		f := newFixture(t)
		d, s := f.signedList(t, testBuilt, "a")
		f.reg.publish(d, s)
		f.reg.set("top10k.txt.sha256", []byte(strings.Repeat("ab", 32)+"\n"))
		r := f.refresher(t, &List{})
		r.refresh(context.Background())
		f.reg.resetHits()
		r.refresh(context.Background())
		if f.reg.hitsFor("top10k.txt") != 1 {
			t.Fatal("a checksum mismatch must be retried next time")
		}
	})
}

func TestNewRefresherValidatesItsConfig(t *testing.T) {
	dir := t.TempDir()
	bad := map[string]RefreshConfig{
		"no dir":           {},
		"http":             {Dir: dir, URL: "http://example.invalid/top10k.txt"},
		"no host":          {Dir: dir, URL: "https:///top10k.txt"},
		"query":            {Dir: dir, URL: "https://example.invalid/top10k.txt?x=1"},
		"empty query":      {Dir: dir, URL: "https://example.invalid/top10k.txt?"},
		"fragment":         {Dir: dir, URL: "https://example.invalid/top10k.txt#x"},
		"unparseable":      {Dir: dir, URL: "https://exa mple.invalid/%zz"},
		"interval too low": {Dir: dir, Interval: 59 * time.Minute},
	}
	for name, cfg := range bad {
		if _, err := NewRefresher(cfg); err == nil {
			t.Errorf("%s: NewRefresher accepted %+v", name, cfg)
		}
	}
	r, err := NewRefresher(RefreshConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if r.url != DefaultURL || r.sumURL != DefaultURL+".sha256" || r.sigURL != DefaultURL+".sig" {
		t.Fatalf("default URLs: %s %s %s", r.url, r.sumURL, r.sigURL)
	}
	if r.interval != DefaultRefreshInterval {
		t.Fatalf("default interval %v", r.interval)
	}
	if r, err := NewRefresher(RefreshConfig{Dir: dir, Interval: MinRefreshInterval}); err != nil || r.interval != MinRefreshInterval {
		t.Fatalf("the minimum interval itself must be accepted: %v", err)
	}
}

// The default client never follows a redirect off https, and gives up
// after five.
func TestDefaultClientRedirectPolicy(t *testing.T) {
	r, err := NewRefresher(RefreshConfig{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	check := r.client.CheckRedirect
	to := func(raw string) *http.Request { u, _ := url.Parse(raw); return &http.Request{URL: u} }
	if err := check(to("http://example.invalid/x"), nil); err == nil {
		t.Error("followed a redirect to http")
	}
	if err := check(to("https://example.invalid/x"), nil); err != nil {
		t.Errorf("refused an https redirect: %v", err)
	}
	if err := check(to("https://example.invalid/x"), make([]*http.Request, 5)); err == nil {
		t.Error("followed a sixth redirect")
	}
}

func TestNextDelayStaysWithinATenth(t *testing.T) {
	r := &Refresher{interval: DefaultRefreshInterval}
	lo, hi := DefaultRefreshInterval*9/10, DefaultRefreshInterval*11/10
	for range 1000 {
		if d := r.nextDelay(); d < lo || d > hi {
			t.Fatalf("nextDelay = %v, outside [%v, %v]", d, lo, hi)
		}
	}
}

// Run checks at once, again each interval, and returns when its context
// ends.
func TestRunChecksUntilCancelled(t *testing.T) {
	f := newFixture(t)
	data, sig := f.signedList(t, testBuilt, "a")
	f.reg.publish(data, sig)
	r := f.refresher(t, &List{})
	r.interval = 10 * time.Millisecond // below the public minimum, for the test only

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	deadline := time.After(10 * time.Second)
	for f.reg.hitsFor("top10k.txt.sha256") < 3 {
		select {
		case <-deadline:
			t.Fatal("Run did not check three times")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after its context ended")
	}
	if r.Current().Len() != size {
		t.Fatal("Run did not adopt the list")
	}
}
