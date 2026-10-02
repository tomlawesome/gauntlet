package blocklist

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // HIBP's range API is keyed on SHA-1; a lookup key, not a password hash.
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultPwnedURL is Have I Been Pwned's Pwned Passwords range API. A
// PwnedChecker appends the first five hex characters of a password's
// SHA-1 to it. The API needs no key and places no licence terms on its
// data (#43).
const DefaultPwnedURL = "https://api.pwnedpasswords.com/range/"

// maxRangeBody bounds a range response. A padded range holds 800 to
// 1,000 lines of about 40 bytes; anything near this is not one.
const maxRangeBody = 512 << 10

// defaultPwnedClientTimeout is the default client's ceiling on one
// request, for a caller that gives Breached a context with no deadline.
// gauntlet's own Store gives it a shorter one (see gauntlet.Options).
const defaultPwnedClientTimeout = 10 * time.Second

// pwnedUserAgent identifies gauntlet's requests to HIBP, which asks
// every client to send one.
const pwnedUserAgent = "gauntlet-password-check"

// PwnedConfig configures NewPwnedChecker.
type PwnedConfig struct {
	// URL is the range API's https base URL; the five-character prefix
	// is appended as one more path segment. Empty means DefaultPwnedURL.
	// It must not carry a query or fragment.
	URL string
	// HTTPClient makes the requests. nil uses a client with a 10 s
	// overall timeout that follows https redirects only. Breached also
	// stops at its context's deadline, whichever comes first.
	HTTPClient *http.Client
}

// A PwnedChecker asks Have I Been Pwned's Pwned Passwords range API
// whether a password has appeared in a known breach, by k-anonymity:
// only the first five hex characters of the password's SHA-1 leave the
// process, and the rest of the hash is compared, here, against the few
// hundred suffixes HIBP returns for that prefix. Every request asks for
// padding (the Add-Padding header), so the response's size does not
// tell an observer of the encrypted connection how many real suffixes
// the prefix has; padding entries carry a count of 0 and are ignored.
//
// It is opt-in: nothing in gauntlet creates one. An application that
// wants the live check builds one and passes it as
// gauntlet.Options.BreachCheck, which is what makes the outbound call
// its own decision. Safe for concurrent use.
type PwnedChecker struct {
	url    string
	base   *url.URL
	client *http.Client
}

// NewPwnedChecker validates cfg. It makes no request.
func NewPwnedChecker(cfg PwnedConfig) (*PwnedChecker, error) {
	raw := cfg.URL
	if raw == "" {
		raw = DefaultPwnedURL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("blocklist: PwnedConfig.URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return nil, fmt.Errorf("blocklist: PwnedConfig.URL must be an https URL with no query or fragment: %q", raw)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultPwnedClientTimeout, CheckRedirect: httpsRedirectsOnly}
	}
	return &PwnedChecker{url: raw, base: u, client: client}, nil
}

// Breached reports whether password appears in Pwned Passwords. An
// error means the answer is unknown -- HIBP unreachable, slow past
// ctx's deadline, or answering with anything but a well-formed range
// -- never that the password is clean; the caller decides what an
// unknown answer means. The error never carries the hash prefix or the
// URL, so it is safe to log.
func (c *PwnedChecker) Breached(ctx context.Context, password string) (bool, error) {
	sum := sha1.Sum([]byte(password)) //nolint:gosec // see the import.
	hash := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := hash[:5], hash[5:]

	req := (&http.Request{
		Method: http.MethodGet,
		URL:    c.base.JoinPath(prefix),
		Header: http.Header{"Add-Padding": {"true"}, "User-Agent": {pwnedUserAgent}},
		Host:   c.base.Host,
	}).WithContext(ctx)

	resp, err := c.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("blocklist: Pwned Passwords unreachable: %w", withoutURL(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("blocklist: Pwned Passwords answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRangeBody+1))
	if err != nil {
		return false, fmt.Errorf("blocklist: Pwned Passwords: reading the response: %w", withoutURL(err))
	}
	if len(body) > maxRangeBody {
		return false, fmt.Errorf("blocklist: Pwned Passwords: response over %d bytes", maxRangeBody)
	}
	return findSuffix(body, suffix)
}

// findSuffix reads a range response -- "SUFFIX:COUNT" lines, CRLF or LF
// separated, 35 hex characters before the colon -- and reports whether
// suffix is in it with a count above zero. A malformed line fails the
// whole response rather than being skipped: a response that is not a
// range (a maintenance page, a proxy's error) must not read as clean.
func findSuffix(body []byte, suffix string) (bool, error) {
	found := false
	sc := bufio.NewScanner(bytes.NewReader(body))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSuffix(sc.Text(), "\r")
		if line == "" {
			continue
		}
		s, count, ok := strings.Cut(line, ":")
		if !ok || len(s) != 2*sha1.Size-5 || !isHex(s) {
			return false, fmt.Errorf("blocklist: Pwned Passwords: line %d is not a range entry", n)
		}
		c, err := strconv.ParseUint(count, 10, 64)
		if err != nil {
			return false, fmt.Errorf("blocklist: Pwned Passwords: line %d has no count", n)
		}
		if c > 0 && strings.EqualFold(s, suffix) {
			found = true
		}
	}
	if err := sc.Err(); err != nil {
		return false, fmt.Errorf("blocklist: Pwned Passwords: %w", err)
	}
	return found, nil
}

// withoutURL unwraps a *url.Error, which quotes the request's URL and
// with it the hash prefix, to what went wrong.
func withoutURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'A' || c > 'F') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Contains reports whether password is on the list in use (Current),
// so a Refresher can be given wherever a list is expected --
// gauntlet.Options.PasswordBlocklist in particular -- and every check
// sees the newest list it has adopted.
func (r *Refresher) Contains(password string) bool {
	return r.Current().Contains(password)
}
