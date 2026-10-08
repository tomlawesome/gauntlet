package geoip

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// Fixtures are built in the test with MaxMind's own writer, the way
// mikroview's internal/geoip tests build theirs: no database file is
// committed. Lookups only ever answer for public unicast addresses, so
// the networks are public ones; the countries mapped to them are made
// up, and nothing here is any provider's data.

type layout int

const (
	nested layout = iota // MaxMind GeoLite2: country.iso_code
	flat                 // IPinfo Lite: country_code, and country is a string
)

// Addresses inside and outside the fixture's networks.
const (
	inV4  = "81.2.69.5"
	inV6  = "2a02:ff0::1"
	outV4 = "8.8.8.8"
)

// buildDB returns a database mapping the fixture's networks to iso.
func buildDB(t *testing.T, l layout, iso string) []byte {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "gauntlet-test"})
	if err != nil {
		t.Fatalf("mmdbwriter.New: %v", err)
	}
	for _, cidr := range []string{"81.2.69.0/24", "2a02:ff0::/32"} {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		var rec mmdbtype.Map
		switch l {
		case flat:
			rec = mmdbtype.Map{
				"country_code":   mmdbtype.String(iso),
				"country":        mmdbtype.String("Somewhere"),
				"continent_code": mmdbtype.String("EU"),
				"asn":            mmdbtype.String("AS64500"),
				"as_name":        mmdbtype.String("Example Networks"),
			}
		default:
			rec = mmdbtype.Map{
				"country": mmdbtype.Map{
					"iso_code": mmdbtype.String(iso),
					"names":    mmdbtype.Map{"en": mmdbtype.String("Somewhere")},
				},
			}
		}
		if err := w.Insert(network, rec); err != nil {
			t.Fatalf("Insert(%s): %v", cidr, err)
		}
	}
	var buf bytes.Buffer
	if _, err := w.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type tarMember struct {
	name string
	body []byte
	typ  byte
}

func tarGz(t *testing.T, members ...tarMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, m := range members {
		typ := m.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: m.name, Mode: 0o644, Size: int64(len(m.body)), Typeflag: typ}
		if typ != tar.TypeReg {
			hdr.Size = 0
			hdr.Linkname = "elsewhere"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write(m.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// maxmindArchive is the shape GeoLite2-Country downloads in: one
// directory holding the licence files and the database.
func maxmindArchive(t *testing.T, db []byte) []byte {
	return tarGz(t,
		tarMember{name: "GeoLite2-Country_20261002/COPYRIGHT.txt", body: []byte("test")},
		tarMember{name: "GeoLite2-Country_20261002/LICENSE.txt", body: []byte("test")},
		tarMember{name: "GeoLite2-Country_20261002/GeoLite2-Country.mmdb", body: db},
	)
}

// logBuf captures what a Manager logs, for the redaction tests.
type logBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// clock is the fake time every test runs on: nothing sleeps.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

var start = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

// fakeProvider serves both sources from one httptest server.
type fakeProvider struct {
	mu     sync.Mutex
	files  map[string][]byte // by path; missing is a 404
	etags  map[string]string
	status map[string]int // overrides the response for a path
	hits   map[string]int

	gotUser, gotPass, gotToken, gotIfNoneMatch string
}

func newFakeProvider(t *testing.T) (*fakeProvider, *httptest.Server) {
	t.Helper()
	fp := &fakeProvider{files: map[string][]byte{}, etags: map[string]string{}, status: map[string]int{}, hits: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fp.mu.Lock()
		defer fp.mu.Unlock()
		fp.hits[r.URL.Path]++
		fp.gotUser, fp.gotPass, _ = r.BasicAuth()
		fp.gotToken = r.URL.Query().Get("token")
		fp.gotIfNoneMatch = r.Header.Get("If-None-Match")
		if code, ok := fp.status[r.URL.Path]; ok {
			// A provider's error page echoing the request back is how a
			// token ends up somewhere it should not.
			http.Error(w, "error for "+r.URL.String(), code)
			return
		}
		body, ok := fp.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if et := fp.etags[r.URL.Path]; et != "" {
			if r.Header.Get("If-None-Match") == et {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", et)
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return fp, srv
}

func (fp *fakeProvider) set(path string, body []byte) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.files[path] = body
	delete(fp.status, path)
}

func (fp *fakeProvider) fail(path string, code int) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.status[path] = code
}

func (fp *fakeProvider) hitCount(path string) int {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	return fp.hits[path]
}

func (fp *fakeProvider) snapshot() (user, pass, token, ifNoneMatch string) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	return fp.gotUser, fp.gotPass, fp.gotToken, fp.gotIfNoneMatch
}

const (
	testAccount = "123456"
	testLicence = "licSECRETvalue42"
	testToken   = "sekritTOKEN42"
)

type env struct {
	m     *Manager
	fp    *fakeProvider
	srv   *httptest.Server
	logs  *logBuf
	clock *clock
	dir   string
}

// newEnv builds a Manager for src whose downloads go to a fake
// provider. The test client is the httptest server's own, since the
// default client's guard refuses 127.0.0.1 -- which is its point, and
// TestDefaultClientRefuses covers it.
func newEnv(t *testing.T, src Source) *env {
	t.Helper()
	return newEnvIn(t, src, t.TempDir())
}

func newEnvIn(t *testing.T, src Source, dir string) *env {
	t.Helper()
	return newEnvWith(t, src, "", dir)
}

func newEnvWith(t *testing.T, src Source, ed Edition, dir string) *env {
	t.Helper()
	fp, srv := newFakeProvider(t)
	logs := &logBuf{}
	c := &clock{t: start}
	m, err := New(Config{
		Source:     src,
		MaxMind:    MaxMindKey{AccountID: testAccount, LicenceKey: testLicence},
		IPinfo:     IPinfoKey{Token: testToken},
		Dir:        dir,
		Edition:    ed,
		HTTPClient: srv.Client(),
		Log:        slog.New(slog.NewTextHandler(logs, nil)),
		Now:        c.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	m.endpoint = srv.URL + "/" + string(src)
	return &env{m: m, fp: fp, srv: srv, logs: logs, clock: c, dir: dir}
}
