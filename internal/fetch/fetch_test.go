package fetch

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func request(t *testing.T, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("NewRequest(%q): %v", target, err)
	}
	return req
}

func via(t *testing.T, n int) []*http.Request {
	t.Helper()
	out := make([]*http.Request, n)
	for i := range out {
		out[i] = request(t, "https://example.test/hop")
	}
	return out
}

func TestHTTPSRedirectsOnlyAllowsHTTPSUpToFiveRedirects(t *testing.T) {
	// via holds the earlier requests, so len(via) 0..4 means the first to
	// fifth redirect.
	for n := 0; n <= 4; n++ {
		if err := HTTPSRedirectsOnly(request(t, "https://example.test/next"), via(t, n)); err != nil {
			t.Errorf("len(via)=%d: https redirect refused: %v", n, err)
		}
	}
}

func TestHTTPSRedirectsOnlyRefusesSixthRedirect(t *testing.T) {
	err := HTTPSRedirectsOnly(request(t, "https://example.test/next"), via(t, 5))
	if err == nil {
		t.Fatal("sixth redirect (len(via)=5) was allowed")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "redirect") {
		t.Errorf("error does not mention redirects: %q", err)
	}
	// Beyond the limit stays refused.
	if err := HTTPSRedirectsOnly(request(t, "https://example.test/next"), via(t, 9)); err == nil {
		t.Error("len(via)=9 was allowed")
	}
}

func TestHTTPSRedirectsOnlyRefusesHTTPTarget(t *testing.T) {
	for n := 0; n <= 5; n++ {
		err := HTTPSRedirectsOnly(request(t, "http://example.test/next"), via(t, n))
		if err == nil {
			t.Errorf("len(via)=%d: http redirect was allowed", n)
			continue
		}
		// At the hop limit either reason is a fair one to give, so only
		// the cases below it must name the scheme rule.
		if n < 5 && !strings.Contains(strings.ToLower(err.Error()), "https") {
			t.Errorf("len(via)=%d: error does not mention https: %q", n, err)
		}
	}
}

func TestHTTPSRedirectsOnlyRefusesOtherSchemes(t *testing.T) {
	for _, target := range []string{"ftp://example.test/x", "file:///etc/passwd"} {
		req := request(t, target)
		if err := HTTPSRedirectsOnly(req, via(t, 1)); err == nil {
			t.Errorf("%s redirect was allowed", target)
		}
	}
}

func TestJitterStaysWithinTenPercent(t *testing.T) {
	for _, interval := range []time.Duration{time.Hour, 24 * time.Hour, 30 * 24 * time.Hour} {
		lo, hi := interval-interval/10, interval+interval/10
		seen := map[time.Duration]bool{}
		for i := 0; i < 1000; i++ {
			d := Jitter(interval)
			if d < lo || d > hi {
				t.Fatalf("Jitter(%v) = %v, outside [%v, %v]", interval, d, lo, hi)
			}
			seen[d] = true
		}
		if len(seen) < 2 {
			t.Errorf("Jitter(%v) returned the same value 1000 times", interval)
		}
	}
}

func TestRedirectToHTTPIsRefusedEndToEnd(t *testing.T) {
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainHits.Add(1)
	}))
	defer plain.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/plain", http.StatusFound)
	}))
	defer srv.Close()

	client := srv.Client()
	client.CheckRedirect = HTTPSRedirectsOnly
	resp, err := client.Get(srv.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("redirect to an http:// URL was followed")
	}
	var ue *url.Error
	if !errors.As(err, &ue) {
		t.Fatalf("error is %T, want it to wrap *url.Error: %v", err, err)
	}
	if n := plainHits.Load(); n != 0 {
		t.Errorf("the http:// target was contacted %d time(s)", n)
	}
}

func TestHTTPSRedirectsFollowedEndToEnd(t *testing.T) {
	dst := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer dst.Close()
	src := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dst.URL, http.StatusFound)
	}))
	defer src.Close()

	// Both servers use the same httptest certificate, so one client trusts both.
	client := src.Client()
	client.CheckRedirect = HTTPSRedirectsOnly
	resp, err := client.Get(src.URL)
	if err != nil {
		t.Fatalf("https to https redirect failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d, want 200", resp.StatusCode)
	}
}

func TestRedirectLoopStopsEndToEnd(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"x", http.StatusFound)
	}))
	defer srv.Close()

	client := srv.Client()
	client.CheckRedirect = HTTPSRedirectsOnly
	resp, err := client.Get(srv.URL + "/")
	if resp != nil {
		resp.Body.Close()
	}
	var ue *url.Error
	if !errors.As(err, &ue) {
		t.Fatalf("endless redirects: error is %v, want *url.Error", err)
	}
}
