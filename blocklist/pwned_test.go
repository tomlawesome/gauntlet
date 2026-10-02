package blocklist

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// rangeAPI is a fake of HIBP's Pwned Passwords range API: it answers
// GET /range/<prefix> with body, or with status when that is set, and
// keeps a dump of every request it was sent. No real HIBP response is
// recorded in this repository (docs/testing.md); bodies here are built
// from synthetic passwords in the API's documented shape.
type rangeAPI struct {
	srv    *httptest.Server
	mu     sync.Mutex
	body   string
	status int
	delay  time.Duration
	dumps  []string
	paths  []string
}

func newRangeAPI(t *testing.T) *rangeAPI {
	t.Helper()
	a := &rangeAPI{}
	a.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dump, _ := httputil.DumpRequest(r, true)
		a.mu.Lock()
		a.dumps = append(a.dumps, string(dump))
		a.paths = append(a.paths, r.URL.Path)
		body, status, delay := a.body, a.status, a.delay
		a.mu.Unlock()
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		if body == cutShort {
			w.Header().Set("Content-Length", "4096")
			_, _ = w.Write([]byte("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n"))
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *rangeAPI) checker(t *testing.T) *PwnedChecker {
	t.Helper()
	c, err := NewPwnedChecker(PwnedConfig{URL: a.srv.URL + "/range/", HTTPClient: a.srv.Client()})
	if err != nil {
		t.Fatalf("NewPwnedChecker: %v", err)
	}
	return c
}

func (a *rangeAPI) serve(body string, status int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.body, a.status = body, status
}

// rangeBody is a range response for prefix: a run of other suffixes,
// the given extra lines, and padding entries with a count of 0, CRLF
// separated as HIBP sends them.
func rangeBody(extra ...string) string {
	lines := []string{
		"0018A45C4D1DEF81644B54AB7F969B88D65:1",
		"00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2",
		"011053FD0102E94D6AE2F8B83D76FAF94F6:1",
	}
	lines = append(lines, extra...)
	lines = append(lines, "FFF0B1B9A5D5C1F2E0F6A2C6B7E4D3C2A10:0", "FFFF6F2B8B9C2D0E4A1B3C5D7E9F1A3B5C7:0")
	return strings.Join(lines, "\r\n")
}

const pwnedTestPassword = "correct horse battery staple"

func TestPwnedSendsOnlyTheFirstFiveHexOfTheHash(t *testing.T) {
	api := newRangeAPI(t)
	api.serve(rangeBody(), 0)
	if _, err := api.checker(t).Breached(context.Background(), pwnedTestPassword); err != nil {
		t.Fatal(err)
	}
	hash := sha1Hex(pwnedTestPassword)
	if len(api.paths) != 1 || api.paths[0] != "/range/"+hash[:5] {
		t.Fatalf("requested %q, want exactly /range/%s", api.paths, hash[:5])
	}
	dump := api.dumps[0]
	for _, secret := range []string{hash, hash[5:], strings.ToLower(hash[5:]), hash[:6], pwnedTestPassword} {
		if strings.Contains(strings.ToUpper(dump), strings.ToUpper(secret)) {
			t.Errorf("the request carries more than the prefix (%q):\n%s", secret, dump)
		}
	}
	if !strings.Contains(dump, "Add-Padding: true") {
		t.Errorf("the request does not ask for padding:\n%s", dump)
	}
	if !strings.Contains(dump, "User-Agent: gauntlet") {
		t.Errorf("the request does not identify itself:\n%s", dump)
	}
}

func TestPwnedAnswers(t *testing.T) {
	suffix := sha1Hex(pwnedTestPassword)[5:]
	cases := map[string]struct {
		body string
		want bool
	}{
		"hit":                {rangeBody(suffix + ":42"), true},
		"hit, lowercase":     {rangeBody(strings.ToLower(suffix) + ":3"), true},
		"miss":               {rangeBody(), false},
		"padding is no hit":  {rangeBody(suffix + ":0"), false},
		"trailing line feed": {rangeBody(suffix+":7") + "\r\n", true},
		"empty range":        {"", false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			api := newRangeAPI(t)
			api.serve(c.body, 0)
			got, err := api.checker(t).Breached(context.Background(), pwnedTestPassword)
			if err != nil {
				t.Fatalf("Breached: %v", err)
			}
			if got != c.want {
				t.Errorf("Breached = %v, want %v", got, c.want)
			}
		})
	}
}

// cutShort tells the fake to promise a longer body than it sends, so
// the connection ends partway through reading it.
const cutShort = "\x00cut-short"

func TestPwnedFailsRatherThanGuesses(t *testing.T) {
	prefix := sha1Hex(pwnedTestPassword)[:5]
	cases := map[string]struct {
		body   string
		status int
	}{
		"server error":    {"", http.StatusInternalServerError},
		"rate limited":    {"", http.StatusTooManyRequests},
		"not found":       {"", http.StatusNotFound},
		"no colon":        {rangeBody("0018A45C4D1DEF81644B54AB7F969B88D66"), 0},
		"short suffix":    {rangeBody("0018A45C:1"), 0},
		"not hex":         {rangeBody("ZZ18A45C4D1DEF81644B54AB7F969B88D65:1"), 0},
		"count not a num": {rangeBody("0018A45C4D1DEF81644B54AB7F969B88D67:x"), 0},
		"html":            {"<html>maintenance</html>", 0},
		"too large":       {strings.Repeat(rangeBody()+"\r\n", maxRangeBody/len(rangeBody())+2), 0},
		"one huge line":   {strings.Repeat("A", 100<<10), 0},
		"cut short":       {cutShort, 0},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			api := newRangeAPI(t)
			api.serve(c.body, c.status)
			got, err := api.checker(t).Breached(context.Background(), pwnedTestPassword)
			if err == nil {
				t.Fatalf("Breached = %v with no error, want an error", got)
			}
			if strings.Contains(strings.ToUpper(err.Error()), prefix) {
				t.Errorf("the error names the hash prefix: %v", err)
			}
		})
	}
}

func TestPwnedHonoursTheDeadline(t *testing.T) {
	api := newRangeAPI(t)
	api.serve(rangeBody(), 0)
	api.mu.Lock()
	api.delay = 10 * time.Second
	api.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := api.checker(t).Breached(ctx, pwnedTestPassword)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Breached past its deadline: %v, want context.DeadlineExceeded", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("Breached took %v past a 50ms deadline", took)
	}
	if err != nil && strings.Contains(strings.ToUpper(err.Error()), sha1Hex(pwnedTestPassword)[:5]) {
		t.Errorf("the error names the hash prefix: %v", err)
	}
}

func TestNewPwnedCheckerValidatesItsConfig(t *testing.T) {
	c, err := NewPwnedChecker(PwnedConfig{})
	if err != nil {
		t.Fatalf("NewPwnedChecker with defaults: %v", err)
	}
	if c.url != DefaultPwnedURL {
		t.Errorf("default URL %q, want %q", c.url, DefaultPwnedURL)
	}
	if c.client == nil || c.client.Timeout == 0 || c.client.Timeout > 30*time.Second {
		t.Errorf("default client has no bounded timeout: %+v", c.client)
	}
	for _, bad := range []string{
		"http://api.pwnedpasswords.com/range/",
		"https://api.pwnedpasswords.com/range/?x=1",
		"https://api.pwnedpasswords.com/range/#f",
		"https:///range/",
		"://",
	} {
		if _, err := NewPwnedChecker(PwnedConfig{URL: bad}); err == nil {
			t.Errorf("NewPwnedChecker accepted %q", bad)
		}
	}
}

func TestPwnedDefaultClientFollowsHTTPSRedirectsOnly(t *testing.T) {
	c, err := NewPwnedChecker(PwnedConfig{})
	if err != nil {
		t.Fatal(err)
	}
	check := c.client.CheckRedirect
	to := func(raw string) *http.Request { u, _ := url.Parse(raw); return &http.Request{URL: u} }
	if err := check(to("http://example.invalid/range/ABCDE"), nil); err == nil {
		t.Error("followed a redirect to http")
	}
	if err := check(to("https://example.invalid/range/ABCDE"), nil); err != nil {
		t.Errorf("refused an https redirect: %v", err)
	}
}

func TestPwnedJoinsAURLWithoutATrailingSlash(t *testing.T) {
	api := newRangeAPI(t)
	api.serve(rangeBody(), 0)
	c, err := NewPwnedChecker(PwnedConfig{URL: api.srv.URL + "/range", HTTPClient: api.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Breached(context.Background(), pwnedTestPassword); err != nil {
		t.Fatal(err)
	}
	if want := "/range/" + sha1Hex(pwnedTestPassword)[:5]; api.paths[0] != want {
		t.Errorf("requested %q, want %q", api.paths[0], want)
	}
}

func TestRefresherContainsAsItsCurrentList(t *testing.T) {
	f := newFixture(t)
	embedded, err := Parse(listFile(testBuilt, listHashes("a")))
	if err != nil {
		t.Fatal(err)
	}
	r := f.refresher(t, embedded)
	if !r.Contains("password") {
		t.Error(`Refresher.Contains("password") = false with "password" on its current list`)
	}
	if r.Contains(fmt.Sprintf("not-on-%s", "the-list")) {
		t.Error("Refresher.Contains is true for a password not on the list")
	}
}
