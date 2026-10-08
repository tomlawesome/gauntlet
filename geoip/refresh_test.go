package geoip

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func TestMaxMindArchive(t *testing.T) {
	e := newEnv(t, SourceMaxMind)
	db := buildDB(t, nested, "JP")
	e.fp.set("/maxmind", maxmindArchive(t, db))
	if wait := e.m.refresh(context.Background()); wait < 9*DefaultRefreshInterval/10 || wait > 11*DefaultRefreshInterval/10 {
		t.Errorf("wait after a good fetch = %v, want the interval give or take a tenth", wait)
	}
	if c, ok := e.m.Country(inV4); !ok || c != "JP" {
		t.Fatalf("Country = %q %v, want JP", c, ok)
	}
	user, pass, _, _ := e.fp.snapshot()
	if user != testAccount || pass != testLicence {
		t.Errorf("MaxMind saw basic auth %q:%q, want the account ID and licence key", user, pass)
	}
	st := e.m.Status()
	if !st.Loaded || !st.FetchedAt.Equal(start) || st.LastError != "" || st.Stale || st.Source != SourceMaxMind {
		t.Errorf("Status = %+v", st)
	}
	got, err := os.ReadFile(filepath.Join(e.dir, "maxmind.mmdb"))
	if err != nil || !bytes.Equal(got, db) {
		t.Errorf("the kept file is not the archive's database (err %v)", err)
	}
	for name, want := range map[string]os.FileMode{"maxmind.mmdb": 0o600, stateFileName: 0o600} {
		info, err := os.Stat(filepath.Join(e.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s mode = %v, want %v", name, info.Mode().Perm(), want)
		}
	}
	state, _ := os.ReadFile(filepath.Join(e.dir, stateFileName))
	if bytes.Contains(state, []byte(testLicence)) || bytes.Contains(state, []byte(testAccount)) {
		t.Errorf("state.json holds a key: %s", state)
	}
}

func TestDirIsCreatedPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "geoip")
	e := newEnvIn(t, SourceIPinfo, dir)
	e.fp.set("/ipinfo", buildDB(t, flat, "IS"))
	e.m.refresh(context.Background())
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("Dir mode = %v, want 0700", info.Mode().Perm())
	}
}

func TestMaxMindArchiveChecks(t *testing.T) {
	db := buildDB(t, nested, "JP")
	for _, c := range []struct {
		name    string
		archive []byte
		wantErr string
	}{
		{"two databases", tarGz(t, tarMember{name: "a/one.mmdb", body: db}, tarMember{name: "a/two.mmdb", body: db}), "more than one"},
		{"no database", tarGz(t, tarMember{name: "a/LICENSE.txt", body: []byte("x")}), "no .mmdb"},
		{"path climbing out", tarGz(t, tarMember{name: "../../etc/GeoLite2-Country.mmdb", body: db}), "unsafe path"},
		{"absolute path", tarGz(t, tarMember{name: "/tmp/GeoLite2-Country.mmdb", body: db}), "unsafe path"},
		{"symlink member", tarGz(t, tarMember{name: "a/GeoLite2-Country.mmdb", typ: tar.TypeSymlink}), "not a regular file"},
		{"not gzip", []byte("<html>"), "gzip"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := extractTarGz(bytes.NewReader(c.archive), &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("extractTarGz = %v, want an error containing %q", err, c.wantErr)
			}
		})
	}
}

func TestIPinfoBareAndGzipped(t *testing.T) {
	db := buildDB(t, flat, "IS")
	for name, body := range map[string][]byte{"bare": db, "gzip-wrapped": gz(t, db)} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, SourceIPinfo)
			e.fp.set("/ipinfo", body)
			e.m.refresh(context.Background())
			if c, ok := e.m.Country(inV4); !ok || c != "IS" {
				t.Fatalf("Country = %q %v, want IS", c, ok)
			}
			if _, _, token, _ := e.fp.snapshot(); token != testToken {
				t.Errorf("IPinfo saw token %q", token)
			}
			got, err := os.ReadFile(filepath.Join(e.dir, "ipinfo.mmdb"))
			if err != nil || !bytes.Equal(got, db) {
				t.Errorf("the kept file is not the plain database (err %v)", err)
			}
		})
	}
}

func TestNotModifiedKeepsTheFile(t *testing.T) {
	e := newEnv(t, SourceIPinfo)
	db := buildDB(t, flat, "IS")
	e.fp.set("/ipinfo", db)
	e.fp.etags["/ipinfo"] = `"v1"`
	e.m.refresh(context.Background())
	e.clock.Advance(25 * time.Hour)
	e.m.refresh(context.Background())
	if _, _, _, inm := e.fp.snapshot(); inm != `"v1"` {
		t.Errorf("If-None-Match = %q, want the ETag of the file in use", inm)
	}
	st := e.m.Status()
	if !st.Loaded || !st.FetchedAt.Equal(start.Add(25*time.Hour)) || st.LastError != "" {
		t.Errorf("after a 304: %+v, want still loaded with FetchedAt moved forward", st)
	}
	if c, _ := e.m.Country(inV4); c != "IS" {
		t.Errorf("Country after a 304 = %q", c)
	}
	got, _ := os.ReadFile(filepath.Join(e.dir, "ipinfo.mmdb"))
	if !bytes.Equal(got, db) {
		t.Error("a 304 changed the kept file")
	}
}

func TestBadDownloadNeverReplacesAGoodFile(t *testing.T) {
	e := newEnv(t, SourceIPinfo)
	good := buildDB(t, flat, "IS")
	e.fp.set("/ipinfo", good)
	e.m.refresh(context.Background())

	for name, apply := range map[string]func(){
		"an HTML portal page": func() { e.fp.set("/ipinfo", []byte("<html>log in to the hotel wifi</html>")) },
		"a truncated gzip":    func() { e.fp.set("/ipinfo", gz(t, buildDB(t, flat, "JP"))[:40]) },
		"a truncated file":    func() { e.fp.set("/ipinfo", buildDB(t, flat, "JP")[:200]) },
		"an empty body":       func() { e.fp.set("/ipinfo", nil) },
		"a server error":      func() { e.fp.fail("/ipinfo", http.StatusBadGateway) },
		"a 404":               func() { e.fp.fail("/ipinfo", http.StatusNotFound) },
	} {
		t.Run(name, func(t *testing.T) {
			apply()
			now := e.clock.Now()
			if wait := e.m.refresh(context.Background()); wait != retryAfter {
				t.Errorf("wait = %v, want %v", wait, retryAfter)
			}
			if c, _ := e.m.Country(inV4); c != "IS" {
				t.Errorf("Country = %q after a bad download, want the last good IS", c)
			}
			st := e.m.Status()
			if !st.Loaded || st.LastError == "" || !st.NextRefresh.Equal(now.Add(retryAfter)) {
				t.Errorf("Status = %+v, want loaded, an error, and a retry in an hour", st)
			}
			got, _ := os.ReadFile(filepath.Join(e.dir, "ipinfo.mmdb"))
			if !bytes.Equal(got, good) {
				t.Error("the kept file was replaced")
			}
			if left, _ := filepath.Glob(filepath.Join(e.dir, ".*")); len(left) != 0 {
				t.Errorf("temporary files left behind: %v", left)
			}
		})
	}
}

// TestRefusedKeyWaitsADay: a key the provider refuses will not start
// working on its own, so it is tried again a day later, not hourly; and
// neither the error nor the log carries it, though the provider's error
// page echoes the request back.
func TestRefusedKeyWaitsADay(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		for _, src := range []Source{SourceIPinfo, SourceMaxMind} {
			t.Run(string(src)+" "+http.StatusText(code), func(t *testing.T) {
				e := newEnv(t, src)
				e.fp.fail("/"+string(src), code)
				if wait := e.m.refresh(context.Background()); wait != refusedRetryAfter {
					t.Errorf("wait = %v, want %v", wait, refusedRetryAfter)
				}
				st := e.m.Status()
				if !st.NextRefresh.Equal(start.Add(24 * time.Hour)) {
					t.Errorf("NextRefresh = %v, want a day later", st.NextRefresh)
				}
				if !strings.Contains(st.LastError, "refused") {
					t.Errorf("LastError = %q, want it to say the key was refused", st.LastError)
				}
				logs := e.logs.String()
				for _, secret := range []string{testToken, testLicence, testAccount} {
					if strings.Contains(st.LastError, secret) || strings.Contains(logs, secret) {
						t.Errorf("a key reached the status or the log:\n%s\n%s", st.LastError, logs)
					}
				}
				if n := strings.Count(logs, "level=WARN"); n != 1 || !strings.Contains(logs, "source="+string(src)) {
					t.Errorf("want one Warn line naming the source, got:\n%s", logs)
				}
			})
		}
	}
}

// TestTransportErrorCarriesNoToken: a *url.Error prints the whole URL,
// token included. The default client's guard refusing the httptest
// server's loopback address is a real transport error.
func TestTransportErrorCarriesNoToken(t *testing.T) {
	e := newEnv(t, SourceIPinfo)
	e.m.client = newClient(guardDial)
	e.fp.set("/ipinfo", buildDB(t, flat, "IS"))
	e.m.refresh(context.Background())
	st := e.m.Status()
	if st.LastError == "" || st.Loaded {
		t.Fatalf("Status = %+v, want a refused dial", st)
	}
	if strings.Contains(st.LastError, testToken) || strings.Contains(st.LastError, "token=") {
		t.Errorf("LastError carries the query: %s", st.LastError)
	}
	if logs := e.logs.String(); strings.Contains(logs, testToken) || strings.Contains(logs, "token=") {
		t.Errorf("the log carries the query:\n%s", logs)
	}
	if e.fp.hitCount("/ipinfo") != 0 {
		t.Error("the guard let a request through to 127.0.0.1")
	}
}

func TestRedactHelpers(t *testing.T) {
	_, err := http.Get("http://127.0.0.1:1/x?token=abc123secret")
	if err == nil {
		t.Skip("something is listening on port 1")
	}
	if msg := cleanErr(err, nil); strings.Contains(msg, "abc123secret") || strings.Contains(msg, "token=") {
		t.Errorf("cleanErr kept the query: %s", msg)
	}
	if got := redact("x sek%2Fret y", []string{"sek/ret"}); strings.Contains(got, "sek") {
		t.Errorf("redact missed the URL-escaped form: %s", got)
	}
	if got := redactURL("https://u:p@h/p?token=t#f"); got != "https://h/p" {
		t.Errorf("redactURL = %q", got)
	}
}

// TestDefaultClientRefuses: the default client will not be sent to a
// private address by a redirect, nor away from https.
func TestDefaultClientRefuses(t *testing.T) {
	db := buildDB(t, flat, "IS")
	var innerHits atomic.Int32
	inner := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		innerHits.Add(1)
		_, _ = w.Write(db)
	}))
	t.Cleanup(inner.Close)

	for _, c := range []struct {
		name, location, want string
	}{
		{"redirect to 127.0.0.1", inner.URL + "/db", "non-public"},
		{"redirect to plain http", "http://example.invalid/db", "https"},
	} {
		t.Run(c.name, func(t *testing.T) {
			outer := httptest.NewTLSServer(http.RedirectHandler(c.location, http.StatusFound))
			t.Cleanup(outer.Close)
			outerAddr := outer.Listener.Addr().String()
			e := newEnv(t, SourceIPinfo)
			// The real guard, except that it lets the first hop -- the
			// test's own "provider" -- through.
			e.m.client = newClient(func(network, address string, rc syscall.RawConn) error {
				if address == outerAddr {
					return nil
				}
				return guardDial(network, address, rc)
			})
			e.m.client.Transport.(*http.Transport).TLSClientConfig = outer.Client().Transport.(*http.Transport).TLSClientConfig
			e.m.endpoint = outer.URL + "/ipinfo"
			e.m.refresh(context.Background())
			st := e.m.Status()
			if st.Loaded || !strings.Contains(st.LastError, c.want) {
				t.Errorf("Status = %+v, want a refusal mentioning %q", st, c.want)
			}
			if innerHits.Load() != 0 {
				t.Error("the redirect target was reached")
			}
		})
	}
}

func TestGuardDial(t *testing.T) {
	for _, a := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
		"::1", "::", "fd00::1", "fe80::1", "192.0.2.5", "2001:db8::1", "::ffff:127.0.0.1", "224.0.0.1", "240.0.0.1"} {
		if err := guardDial("tcp", net.JoinHostPort(a, "443"), nil); err == nil {
			t.Errorf("guardDial let %s through", a)
		}
	}
	for _, a := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if err := guardDial("tcp", net.JoinHostPort(a, "443"), nil); err != nil {
			t.Errorf("guardDial refused public %s: %v", a, err)
		}
	}
	if err := guardDial("tcp", "no-port", nil); err == nil {
		t.Error("guardDial accepted an address with no port")
	}
	if err := guardDial("tcp", "example.com:443", nil); err == nil {
		t.Error("guardDial accepted a name instead of an address")
	}
}

func TestCachedFileLoadsBeforeAnyFetch(t *testing.T) {
	dir := t.TempDir()
	fetched := start.Add(-48 * time.Hour)
	if err := os.WriteFile(filepath.Join(dir, "maxmind.mmdb"), buildDB(t, nested, "JP"), 0o600); err != nil {
		t.Fatal(err)
	}
	state, _ := json.Marshal(stateFile{Source: SourceMaxMind, FetchedAt: fetched, ETag: `"v7"`})
	if err := os.WriteFile(filepath.Join(dir, stateFileName), state, 0o600); err != nil {
		t.Fatal(err)
	}
	e := newEnvIn(t, SourceMaxMind, dir)
	if c, ok := e.m.Country(inV4); !ok || c != "JP" {
		t.Errorf("Country before any fetch = %q %v, want JP from the cached file", c, ok)
	}
	if e.fp.hitCount("/maxmind") != 0 {
		t.Error("New made a request")
	}
	if st := e.m.Status(); !st.Loaded || !st.FetchedAt.Equal(fetched) {
		t.Errorf("Status = %+v, want loaded with the kept fetch time", st)
	}
	e.fp.set("/maxmind", maxmindArchive(t, buildDB(t, nested, "JP")))
	e.fp.etags["/maxmind"] = `"v7"`
	e.m.refresh(context.Background())
	if _, _, _, inm := e.fp.snapshot(); inm != `"v7"` {
		t.Errorf("If-None-Match = %q, want the kept ETag", inm)
	}
}

func TestCachedFileOfAnotherSourceIsNotUsed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "maxmind.mmdb"), buildDB(t, nested, "JP"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := newEnvIn(t, SourceIPinfo, dir)
	if _, ok := e.m.Country(inV4); ok {
		t.Error("an ipinfo manager answered from MaxMind's file")
	}
}

func TestUnreadableCacheIsIgnored(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ipinfo.mmdb"), []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, stateFileName), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := newEnvIn(t, SourceIPinfo, dir)
	if e.m.Status().Loaded {
		t.Error("a corrupt cached file was loaded")
	}
	if !strings.Contains(e.logs.String(), "level=WARN") {
		t.Error("a corrupt cached file was not reported")
	}
	// The next good download replaces it.
	e.fp.set("/ipinfo", buildDB(t, flat, "IS"))
	e.m.refresh(context.Background())
	if c, _ := e.m.Country(inV4); c != "IS" {
		t.Errorf("Country = %q after a good download", c)
	}
}

func TestStaleWarning(t *testing.T) {
	e := newEnv(t, SourceIPinfo)
	e.fp.set("/ipinfo", buildDB(t, flat, "IS"))
	e.m.refresh(context.Background())
	e.fp.fail("/ipinfo", http.StatusBadGateway)

	e.clock.Advance(StaleAfter - time.Hour)
	e.m.refresh(context.Background())
	if e.m.Status().Stale || strings.Contains(e.logs.String(), "older than") {
		t.Error("a file younger than StaleAfter was called stale")
	}
	e.clock.Advance(2 * time.Hour)
	before := strings.Count(e.logs.String(), "older than")
	e.m.refresh(context.Background())
	if !e.m.Status().Stale {
		t.Error("Status.Stale is false past StaleAfter")
	}
	if got := strings.Count(e.logs.String(), "older than") - before; got != 1 {
		t.Errorf("%d stale warnings for one check, want 1", got)
	}
	if c, _ := e.m.Country(inV4); c != "IS" {
		t.Error("a stale file stopped answering")
	}
}

func TestRunChecksAtStartAndStops(t *testing.T) {
	e := newEnv(t, SourceIPinfo)
	e.fp.set("/ipinfo", buildDB(t, flat, "IS"))
	checked := make(chan time.Duration, 1)
	e.m.afterCheck = func(wait time.Duration) { checked <- wait }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.m.Run(ctx)
		close(done)
	}()
	if wait := <-checked; wait < 9*DefaultRefreshInterval/10 {
		t.Errorf("Run's next check in %v, want about a day", wait)
	}
	cancel()
	<-done
	if c, _ := e.m.Country(inV4); c != "IS" {
		t.Errorf("Country after Run's first check = %q", c)
	}
}

func TestCancelledCheckRecordsNothing(t *testing.T) {
	e := newEnv(t, SourceIPinfo)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.m.refresh(ctx)
	if st := e.m.Status(); st.LastError != "" || !st.NextRefresh.IsZero() {
		t.Errorf("a check cancelled by shutdown recorded %+v", st)
	}
}

func TestNextDelayIsSpread(t *testing.T) {
	e := newEnv(t, SourceIPinfo)
	for range 200 {
		d := e.m.nextDelay()
		if d < 9*DefaultRefreshInterval/10 || d > 11*DefaultRefreshInterval/10 {
			t.Fatalf("nextDelay = %v, outside the interval give or take a tenth", d)
		}
	}
}

func TestDownloadCap(t *testing.T) {
	c := &capReader{r: bytes.NewReader(make([]byte, 10)), left: 4}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(c); !errors.Is(err, errTooLarge) {
		t.Errorf("err = %v, want errTooLarge", err)
	}
	if err := copyCapped(&bytes.Buffer{}, bytes.NewReader(nil)); err == nil {
		t.Error("an empty body was accepted")
	}
}

// TestIPv4OnlyFile: a file with no IPv6 tree is adopted, and an IPv6
// address -- whose lookup in it is an error -- is simply not known.
func TestIPv4OnlyFile(t *testing.T) {
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "gauntlet-test", IPVersion: 4, RecordSize: 24})
	if err != nil {
		t.Fatal(err)
	}
	_, network, _ := net.ParseCIDR("81.2.69.0/24")
	if err := w.Insert(network, mmdbtype.Map{"country_code": mmdbtype.String("IS")}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := w.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, SourceIPinfo)
	e.fp.set("/ipinfo", buf.Bytes())
	e.m.refresh(context.Background())
	if c, ok := e.m.Country(inV4); !ok || c != "IS" {
		t.Errorf("Country(%s) = %q %v, want IS", inV4, c, ok)
	}
	if c, ok := e.m.Country(inV6); ok {
		t.Errorf("Country(%s) = %q in an IPv4-only file", inV6, c)
	}
}
