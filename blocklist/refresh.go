package blocklist

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tomlawesome/gauntlet/internal/listsig"
)

// DefaultURL is where applications fetch the newest list: the
// `pwned-top10k-current` release on gauntlet's public GitHub mirror.
// The scheduled CI pipeline publishes each list to the GitLab project's
// package registry first, then copies the same signed files here,
// because the GitLab project is private (owner, 2026-10-02, on #52).
// The checksum and signature sit beside it at the same URL plus
// ".sha256" and ".sig". Each run also has its own release,
// pwned-top10k-<YYYY.MM.DD>, which is never rewritten.
const DefaultURL = "https://github.com/tomlawesome/gauntlet/releases/download/pwned-top10k-current/top10k.txt"

const (
	// DefaultRefreshInterval is how often a Refresher checks for a
	// new list when RefreshConfig.Interval is zero. The published list
	// changes at most once per scheduled CI run, and between runs the
	// live HIBP check covers new breaches, so checking more often than
	// daily only costs the download host.
	DefaultRefreshInterval = 24 * time.Hour
	// MinRefreshInterval is the shortest RefreshConfig.Interval
	// NewRefresher accepts.
	MinRefreshInterval = time.Hour
)

// Fetch limits. The checksum is fetched first and is tiny, so an
// unchanged list costs one small request per interval. A real list is
// about 410 KB; anything over a mebibyte is not one.
const (
	maxSumFile   = 256
	maxListFile  = 1 << 20
	sumTimeout   = 10 * time.Second
	listTimeout  = 60 * time.Second
	sigTimeout   = 10 * time.Second
	futureMargin = 24 * time.Hour
)

// File names the accepted copy is kept under, in RefreshConfig.Dir.
const (
	storedList = "top10k.txt"
	storedSig  = "top10k.txt.sig"
)

// RefreshConfig configures NewRefresher.
type RefreshConfig struct {
	// URL is the list's https URL; its checksum and signature are
	// fetched from URL+".sha256" and URL+".sig". Empty means
	// DefaultURL. It must not carry a query or fragment, since the
	// other two URLs are made by appending to it.
	URL string
	// Dir is the directory the accepted list is kept in, so a restart
	// starts from it rather than the older embedded copy. Required. It
	// is created (0700) if missing; the files in it are written 0600,
	// each by writing a temporary file and renaming it into place.
	// What is read back from it is verified again, exactly as a
	// download is.
	Dir string
	// HTTPClient makes the requests. nil uses a client with a two-minute
	// overall timeout that follows https redirects only (GitHub serves
	// release files by redirecting to its download host). Each
	// request also has its own deadline: 10 s for the checksum and the
	// signature, 60 s for the list.
	HTTPClient *http.Client
	// Interval is the time between checks; Run checks once at start and
	// then every Interval, give or take a tenth so that many processes
	// started together do not check together. Zero means
	// DefaultRefreshInterval; anything else below MinRefreshInterval
	// is an error.
	Interval time.Duration
	// Log receives one Warn line for each refresh that fails or
	// refuses a list, and one Info line for each list adopted. nil
	// discards both.
	Log *slog.Logger
}

// A Refresher keeps the newest trustworthy list available through
// Current. It is opt-in: nothing in gauntlet creates one, so an
// application that does not makes no network request for this list.
//
// A list is adopted only when all of these hold:
//   - its SHA-256 matches the published ".sha256";
//   - its ".sig" verifies against a key compiled into this release
//     (blocklist/keys/*.pub) -- with no key there, nothing is ever
//     adopted;
//   - Parse accepts it: format v1, exactly 10,000 strictly ascending
//     hashes;
//   - it was built no more than 24 hours in the future, and later than
//     the list in use, which starts as the newer of the embedded copy
//     and the copy in Dir. A list older than the one compiled into
//     this release is therefore never used.
//
// Any failure -- the network, the download host, a refused file, the disk --
// logs one Warn and leaves Current as it was. A list whose signature
// verified but whose content was refused -- malformed, dated in the
// future, or not newer -- is not downloaded again until the published
// checksum changes, since signing the same bytes again cannot change
// that verdict; a list refused for its signature is fetched again next
// time, so a re-signed copy is picked up.
type Refresher struct {
	url, sumURL, sigURL string
	dir                 string
	client              *http.Client
	interval            time.Duration
	log                 *slog.Logger

	// Seams for tests: the trusted keys, the clock, and the embedded
	// copy this release carries.
	keys     func() (listsig.Keyring, error)
	now      func() time.Time
	embedded *List

	current atomic.Pointer[List]

	mu         sync.Mutex // one refresh at a time; guards refused
	refused    [sha256.Size]byte
	hasRefused bool
}

// NewRefresher validates cfg and loads the copy kept in cfg.Dir, if
// there is one and it verifies; it makes no network request. Current
// is usable as soon as it returns. Call Run, usually in its own
// goroutine, to start checking for new lists.
func NewRefresher(cfg RefreshConfig) (*Refresher, error) {
	return newRefresher(cfg, trustedKeys, Embedded(), time.Now)
}

func newRefresher(cfg RefreshConfig, keys func() (listsig.Keyring, error), embedded *List, now func() time.Time) (*Refresher, error) {
	if cfg.Dir == "" {
		return nil, errors.New("blocklist: RefreshConfig.Dir is required")
	}
	raw := cfg.URL
	if raw == "" {
		raw = DefaultURL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("blocklist: RefreshConfig.URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return nil, fmt.Errorf("blocklist: RefreshConfig.URL must be an https URL with no query or fragment: %q", raw)
	}
	interval := cfg.Interval
	switch {
	case interval == 0:
		interval = DefaultRefreshInterval
	case interval < MinRefreshInterval:
		return nil, fmt.Errorf("blocklist: RefreshConfig.Interval %v is below the %v minimum", interval, MinRefreshInterval)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 2 * time.Minute,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if req.URL.Scheme != "https" {
					return errors.New("blocklist: refused a redirect away from https")
				}
				if len(via) >= 5 {
					return errors.New("blocklist: too many redirects")
				}
				return nil
			},
		}
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	r := &Refresher{
		url: raw, sumURL: raw + ".sha256", sigURL: raw + ".sig",
		dir:      cfg.Dir,
		client:   client,
		interval: interval,
		log:      log,
		keys:     keys,
		now:      now,
		embedded: embedded,
	}
	r.current.Store(embedded)
	r.loadStored()
	return r, nil
}

// Current returns the list in use: the newest one adopted, or the copy
// kept in Dir, or the embedded copy. It is never nil, and is safe to
// call from any goroutine at any time.
func (r *Refresher) Current() *List {
	return r.current.Load()
}

// Run checks for a new list at once and then every interval until ctx
// is done, and returns when it is. Failures are logged, never returned:
// a refresher that cannot reach the download host keeps the list it has.
func (r *Refresher) Run(ctx context.Context) {
	for {
		r.refresh(ctx)
		t := time.NewTimer(r.nextDelay())
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// nextDelay is the interval moved by up to a tenth either way.
func (r *Refresher) nextDelay() time.Duration {
	tenth := int64(r.interval / 10)
	return r.interval + time.Duration(rand.Int64N(2*tenth+1)-tenth) //nolint:gosec // spreading load, not a secret
}

// loadStored adopts the copy kept in Dir when it verifies and is newer
// than the embedded one. A missing copy is the normal first start and
// is silent; one that does not verify is reported once and ignored --
// the next successful refresh overwrites it.
func (r *Refresher) loadStored() {
	data, err := os.ReadFile(filepath.Join(r.dir, storedList))
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	var l *List
	if err == nil {
		var sig []byte
		sig, err = os.ReadFile(filepath.Join(r.dir, storedSig))
		if err == nil {
			l, err = r.check(data, sig)
		}
	}
	if err != nil {
		r.log.Warn("blocklist: ignoring the stored common-password list; using the embedded copy until a refresh succeeds",
			"dir", r.dir, "err", err)
		return
	}
	if !l.Built().After(r.embedded.Built()) {
		return
	}
	r.current.Store(l)
}

// refresh runs one check, logging its failure.
func (r *Refresher) refresh(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.refreshLocked(ctx); err != nil {
		r.log.Warn("blocklist: common-password list refresh failed; keeping the current list",
			"url", r.url, "current_built", r.Current().Built(), "err", err)
	}
}

func (r *Refresher) refreshLocked(ctx context.Context) error {
	sumFile, err := r.get(ctx, r.sumURL, maxSumFile, sumTimeout)
	if err != nil {
		return err
	}
	want, err := parseSum(sumFile)
	if err != nil {
		return err
	}
	cur := r.Current()
	if want == cur.sum || (r.hasRefused && want == r.refused) {
		return nil
	}
	data, err := r.get(ctx, r.url, maxListFile, listTimeout)
	if err != nil {
		return err
	}
	if sha256.Sum256(data) != want {
		// Not remembered: the list and its checksum may simply have
		// been read either side of a publish.
		return errors.New("the list does not match the published SHA-256")
	}
	sig, err := r.get(ctx, r.sigURL, listsig.MaxSignatureFile, sigTimeout)
	if err != nil {
		return err
	}
	l, err := r.check(data, sig)
	if err == nil && !l.Built().After(cur.Built()) {
		err = contentError{fmt.Errorf("the published list (built %s) is not newer than the one in use (built %s)",
			l.Built().Format(time.RFC3339), cur.Built().Format(time.RFC3339))}
	}
	if err != nil {
		var ce contentError
		if errors.As(err, &ce) {
			r.refused, r.hasRefused = want, true
		}
		return err
	}
	if err := r.store(data, sig); err != nil {
		return fmt.Errorf("keep the new list in %s: %w", r.dir, err)
	}
	r.current.Store(l)
	r.log.Info("blocklist: adopted a new common-password list", "built", l.Built())
	return nil
}

// check is every content test a list must pass, for a download and for
// the copy in Dir alike. The signature comes first, so nothing parses
// bytes nobody trusted.
func (r *Refresher) check(data, sig []byte) (*List, error) {
	ring, err := r.keys()
	if err != nil {
		return nil, fmt.Errorf("trusted keys: %w", err)
	}
	if err := listsig.Verify(data, sig, ring); err != nil {
		return nil, err
	}
	l, err := Parse(data)
	if err != nil {
		return nil, contentError{err}
	}
	if l.Built().After(r.now().Add(futureMargin)) {
		return nil, contentError{fmt.Errorf("the list claims to be built at %s, in the future", l.Built().Format(time.RFC3339))}
	}
	return l, nil
}

// contentError marks a refusal of a correctly signed list for what it
// says, which no re-signing changes.
type contentError struct{ err error }

func (e contentError) Error() string { return e.err.Error() }
func (e contentError) Unwrap() error { return e.err }

// get fetches u with its own deadline, refusing any status but 200 and
// any body over limit bytes.
func (r *Refresher) get(ctx context.Context, u string, limit int64, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "gauntlet-blocklist")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", u, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("GET %s: larger than the %d-byte limit", u, limit)
	}
	return body, nil
}

// parseSum reads a `sha256sum` line: 64 hex characters, optionally
// followed by whitespace and a file name, on one line.
func parseSum(b []byte) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	line := bytes.TrimSuffix(b, []byte("\n"))
	if bytes.ContainsAny(line, "\r\n") {
		return sum, errors.New("the published SHA-256 file is not one line")
	}
	field := line
	if i := bytes.IndexAny(line, " \t"); i >= 0 {
		field = line[:i]
	}
	if len(field) != 2*sha256.Size {
		return sum, errors.New("the published SHA-256 file does not start with 64 hex characters")
	}
	if _, err := hex.Decode(sum[:], field); err != nil {
		return sum, fmt.Errorf("the published SHA-256 file: %w", err)
	}
	return sum, nil
}

// store keeps data and sig in Dir. Each file is written to a temporary
// file in the same directory, synced, and renamed over the old one, so
// a reader -- this process after a restart -- never sees half a file.
// The pair is not replaced as one: a crash between the two renames
// leaves a new signature beside the old list, which fails verification
// at the next start; that start falls back to the embedded copy and
// its first refresh writes the pair again. The signature is renamed
// first so that a list file is never newer than the signature for it.
func (r *Refresher) store(data, sig []byte) error {
	if err := os.MkdirAll(r.dir, 0o700); err != nil {
		return err
	}
	if err := writeFileAtomic(r.dir, storedSig, sig); err != nil {
		return err
	}
	return writeFileAtomic(r.dir, storedList, data)
}

func writeFileAtomic(dir, name string, data []byte) (err error) {
	f, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(0o600); err == nil {
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
	return os.Rename(tmp, filepath.Join(dir, name))
}
