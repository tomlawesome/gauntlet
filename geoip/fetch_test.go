package geoip

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A caller's HTTPClient may have no timeout of its own, and the
// refresher must not hang on a provider that stops answering, whether
// before the headers or partway through the body. download bounds the
// whole exchange itself; fetchTimeout is shortened here so the test
// does not wait the real two minutes.
func TestDownloadIsBoundedWithAClientThatHasNoTimeout(t *testing.T) {
	saved := fetchTimeout
	fetchTimeout = 200 * time.Millisecond
	t.Cleanup(func() { fetchTimeout = saved })

	for _, c := range []struct {
		name        string
		sendHeaders bool
	}{
		{"no headers", false},
		{"stalled body", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			release := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if c.sendHeaders {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte{0x1f})
					w.(http.Flusher).Flush()
				}
				select {
				case <-r.Context().Done():
				case <-release:
				}
			}))
			// Cleanups run last-registered first: free the handler, then
			// close the server, which waits for it.
			t.Cleanup(srv.Close)
			t.Cleanup(func() { close(release) })

			m, err := New(Config{
				Source:     SourceIPinfo,
				IPinfo:     IPinfoKey{Token: testToken},
				Dir:        t.TempDir(),
				HTTPClient: &http.Client{},
				Log:        slog.New(slog.DiscardHandler),
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(func() { _ = m.Close() })

			done := make(chan error, 1)
			go func() {
				_, err := m.download(context.Background(), request{url: srv.URL}, io.Discard)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("download from a provider that never finishes succeeded, want an error")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("download did not return: a client without a timeout hung it")
			}
		})
	}
}
