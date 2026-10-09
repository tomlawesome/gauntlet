package geoip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/tomlawesome/gauntlet/internal/atomicfile"
	"github.com/tomlawesome/gauntlet/internal/fetch"
)

const (
	// retryAfter is how soon a failed check is tried again: sooner than
	// a day, so a brief outage does not cost a day's freshness.
	retryAfter = time.Hour
	// refusedRetryAfter is the wait after the provider refuses the key
	// (401 or 403). A refused key will not start working on its own, so
	// it is not sent hourly.
	refusedRetryAfter = 24 * time.Hour
	// stateFileName is the small document beside the kept file.
	stateFileName = "state.json"
)

// probeV4 and probeV6 are documentation addresses (RFC 5737, RFC 3849).
// A download is adopted only once a lookup of them succeeds -- found or
// not, but without an error -- so a file that opens but cannot be
// searched never replaces a working one.
var (
	probeV4 = netip.MustParseAddr("192.0.2.1")
	probeV6 = netip.MustParseAddr("2001:db8::1")
)

// Run checks for a new file at once and then every interval, give or
// take a tenth, until ctx is done, and returns when it is. A failed
// check is retried after an hour, or after a day when the provider
// refused the key. Failures are logged and kept in Status, never
// returned: a Manager that cannot reach its provider keeps answering
// from the file it has.
func (m *Manager) Run(ctx context.Context) {
	if m == nil {
		return
	}
	for {
		wait := m.refresh(ctx)
		if ctx.Err() != nil {
			return
		}
		if m.afterCheck != nil {
			m.afterCheck(wait)
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// nextDelay is the interval moved by up to a tenth either way, so many
// processes started together do not all download together
// (internal/fetch, shared with blocklist).
func (m *Manager) nextDelay() time.Duration {
	return fetch.Jitter(m.interval)
}

// refresh runs one check and returns how long until the next. A check
// cut short by ctx records nothing.
func (m *Manager) refresh(ctx context.Context) time.Duration {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	err := m.fetch(ctx)
	if ctx.Err() != nil {
		return 0
	}
	var refused errRefused
	wait := m.nextDelay()
	switch {
	case errors.As(err, &refused):
		wait = refusedRetryAfter
	case err != nil:
		wait = retryAfter
	}
	now := m.now()
	m.mu.Lock()
	m.nextRefresh = now.Add(wait)
	m.lastError = ""
	if err != nil {
		m.lastError = err.Error()
	}
	loaded, age := m.reader != nil, now.Sub(m.fetchedAt)
	m.mu.Unlock()

	if err != nil {
		m.log.Warn("geoip: country file check failed; keeping the file in use",
			"source", m.source, "loaded", loaded, "retry_in", wait, "err", err.Error())
	}
	if loaded && age > StaleAfter {
		m.log.Warn("geoip: the country file in use is older than StaleAfter; still answering from it, but newer address assignments may be missing",
			"source", m.source, "age", age.Round(time.Hour), "stale_after", StaleAfter)
	}
	return wait
}

// errRefused marks a check the provider refused the key for. Its
// message is fixed and names no key.
type errRefused struct{ status errStatus }

func (e errRefused) Error() string {
	return fmt.Sprintf("the provider refused the key (%v); check it -- next try in a day", e.status)
}

// fetch downloads the source's file and, when a new one arrives and
// passes adopt's checks, puts it in use. Every failure leaves the file
// in use as it was.
func (m *Manager) fetch(ctx context.Context) error {
	m.mu.RLock()
	req := request{url: m.endpoint, user: m.user, pass: m.pass, tarGz: m.source == SourceMaxMind}
	if m.reader != nil {
		// Conditional only while a file is in use: a 304 answered
		// with nothing loaded would leave nothing to keep.
		req.etag, req.modified = m.etag, m.lastModified
	}
	m.mu.RUnlock()
	if m.token != "" {
		req.url += "?" + url.Values{"token": {m.token}}.Encode()
	}

	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", m.dir, err)
	}
	tmp, err := os.CreateTemp(m.dir, "."+string(m.source)+".mmdb.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // a no-op once renamed into place
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	// The download is renamed over the kept file, so it takes that
	// file's owner and group first, as atomicfile.WriteFile does (#80).
	if err := atomicfile.KeepOwner(tmp, m.cacheFile()); err != nil {
		_ = tmp.Close()
		return err
	}
	res, err := m.download(ctx, req, tmp)
	if cerr := tmp.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if res.refused {
		var status errStatus
		errors.As(err, &status)
		return errRefused{status}
	}
	if err != nil {
		return err
	}
	if res.notModified {
		// Unchanged: confirmed current, so the fetch time moves on.
		m.mu.Lock()
		m.fetchedAt = m.now()
		m.mu.Unlock()
		m.saveState()
		return nil
	}
	return m.adopt(tmpName, res)
}

// adopt opens a downloaded file and puts it in use if it is a database
// a lookup succeeds in. Only then is it renamed over the kept file and
// swapped in; the reader it replaces is closed after the swap, which is
// safe because lookups hold the read lock for the whole lookup.
func (m *Manager) adopt(tmpName string, res response) error {
	r, err := maxminddb.Open(tmpName)
	if err != nil {
		return fmt.Errorf("the download is not a readable country file: %w", err)
	}
	if err := probe(r); err != nil {
		_ = r.Close()
		return fmt.Errorf("the download is not a usable country file: %w", err)
	}
	if err := m.checkEdition(r); err != nil {
		_ = r.Close()
		return fmt.Errorf("the download is not a city file: %w", err)
	}
	if err := os.Rename(tmpName, m.cacheFile()); err != nil {
		_ = r.Close()
		return fmt.Errorf("keep the new file in %s: %w", m.dir, err)
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return r.Close()
	}
	old := m.reader
	m.reader = r
	m.fetchedAt = m.now()
	m.etag, m.lastModified = res.etag, res.lastModified
	m.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	m.saveState()
	m.log.Info("geoip: adopted a new country file", "source", m.source, "built", r.Metadata.BuildTime())
	return nil
}

// probe is the check a file must pass before it is used: a search tree
// with something in it, and a lookup that does not fail.
func probe(r *maxminddb.Reader) error {
	if r.Metadata.NodeCount == 0 {
		return errors.New("it is empty")
	}
	if err := r.Lookup(probeV4).Err(); err != nil {
		return err
	}
	if r.Metadata.IPVersion == 6 {
		return r.Lookup(probeV6).Err()
	}
	return nil
}

// checkEdition is the second check for EditionCity: the file must say
// it is a City database, so a Country file served at the City URL never
// replaces one that locates. Any type is accepted for EditionCountry,
// as before editions existed.
func (m *Manager) checkEdition(r *maxminddb.Reader) error {
	if m.edition == EditionCity && !strings.Contains(r.Metadata.DatabaseType, "City") {
		return fmt.Errorf("its database type is %q", r.Metadata.DatabaseType)
	}
	return nil
}

// cacheFile is where the source's file is kept: <Source>.mmdb, or
// maxmind-city.mmdb for the City file, so switching editions never
// loads the other edition's file.
func (m *Manager) cacheFile() string {
	if m.edition == EditionCity {
		return filepath.Join(m.dir, string(m.source)+"-city.mmdb")
	}
	return filepath.Join(m.dir, string(m.source)+".mmdb")
}

// stateFile is what a restart needs to make a conditional request and
// to report the file's age honestly. It is the provider's public data's
// bookkeeping, not the application's state, and holds no key.
type stateFile struct {
	Source Source `json:"source"`
	// Edition is the kept file's edition; a document written before
	// editions existed has none and is about the Country file.
	Edition      Edition   `json:"edition,omitempty"`
	FetchedAt    time.Time `json:"fetchedAt"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"lastModified,omitempty"`
}

// edition is the document's edition, EditionCountry when it predates
// editions.
func (st stateFile) edition() Edition {
	if st.Edition == "" {
		return EditionCountry
	}
	return st.Edition
}

// loadCache puts the kept file in use, if there is one and it passes
// the same checks as a download. A missing file is the normal first
// start and is silent; any other failure is one Warn line and an empty
// Manager, never a failed New. The state document is used only when it
// is about this source; otherwise the file's own modification time
// stands in for the fetch time.
func (m *Manager) loadCache() {
	p := m.cacheFile()
	info, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	var r *maxminddb.Reader
	if err == nil {
		r, err = maxminddb.Open(p)
	}
	if err == nil {
		if err = probe(r); err == nil {
			err = m.checkEdition(r)
		}
		if err != nil {
			_ = r.Close()
		}
	}
	if err != nil {
		m.log.Warn("geoip: ignoring the kept country file until a download replaces it",
			"source", m.source, "file", p, "err", err.Error())
		return
	}
	m.reader = r
	m.fetchedAt = info.ModTime()
	var st stateFile
	// #nosec G304 -- the application's own Dir.
	if data, err := os.ReadFile(filepath.Join(m.dir, stateFileName)); err == nil {
		if err := json.Unmarshal(data, &st); err != nil {
			m.log.Warn("geoip: ignoring an unreadable state.json", "file", filepath.Join(m.dir, stateFileName), "err", err.Error())
		} else if st.Source == m.source && st.edition() == m.edition && !st.FetchedAt.IsZero() {
			m.fetchedAt, m.etag, m.lastModified = st.FetchedAt, st.ETag, st.LastModified
		}
	}
	m.log.Info("geoip: loaded the kept country file", "source", m.source, "fetched", m.fetchedAt)
}

// saveState writes the state document. A failure is logged and
// otherwise ignored: its only cost is a full download after a restart.
func (m *Manager) saveState() {
	m.mu.RLock()
	st := stateFile{Source: m.source, Edition: m.edition, FetchedAt: m.fetchedAt, ETag: m.etag, LastModified: m.lastModified}
	m.mu.RUnlock()
	data, err := json.MarshalIndent(st, "", "  ")
	if err == nil {
		err = writeFileAtomic(m.dir, stateFileName, data)
	}
	if err != nil {
		m.log.Warn("geoip: could not write state.json", "dir", m.dir, "err", err.Error())
	}
}

// writeFileAtomic writes name in dir crash-safely, 0600, keeping an
// existing file's owner and group, as blocklist's and persist's writes
// do (atomicfile.WriteFile, #80).
func writeFileAtomic(dir, name string, data []byte) error {
	return atomicfile.WriteFile(filepath.Join(dir, name), data, 0o600)
}
