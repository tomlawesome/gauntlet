package geoip

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"syscall"
	"time"
)

// The download locations. Constants, not configuration: an operator
// choosing a source trusts gauntlet's vetting of where it is fetched
// from, and no request URL is built from free text -- only a validated
// key is added (New).
const (
	// maxmindURL takes HTTP basic auth (account ID : licence key) and
	// answers with a redirect to a signed storage URL; Go's client
	// drops the Authorization header on that hop to another host, as
	// it should. The body is a .tar.gz holding one .mmdb.
	maxmindURL = "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz"
	// maxmindCityURL is GeoLite2-City (EditionCity): the same account,
	// key, basic auth, redirect and archive shape.
	maxmindCityURL = "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"
	// ipinfoURL takes ?token=. The token rides in the URL, so every
	// string made from a request to it goes through cleanErr and
	// redact. The body is a bare .mmdb, possibly gzip-wrapped.
	ipinfoURL = "https://ipinfo.io/data/ipinfo_lite.mmdb"
)

// fetchTimeout bounds a whole download: headers, body and extraction,
// whichever client made the request. A var only so a test can shorten it.
var fetchTimeout = 2 * time.Minute

const (
	// maxFileBytes caps both what is read off the wire and what one
	// decompressed database may grow to. Both sources' files are well
	// under it; it bounds a hostile or broken download.
	maxFileBytes = 128 << 20
	// maxTarEntries bounds how many headers a MaxMind archive may walk.
	// A real one has three (COPYRIGHT.txt, LICENSE.txt, the .mmdb).
	maxTarEntries = 64
	userAgent     = "gauntlet-geoip"
)

// newClient is the default client: mikroview's guarded fetch client
// with blocklist's https-only redirect policy and two-minute timeout.
// control runs in Dialer.Control -- after DNS, immediately before the
// connection is made -- so it sees the address actually dialled, for
// the first request and every redirect alike. Proxy is deliberately
// unset: through a proxy, the guard would see only the proxy's address.
func newClient(control func(network, address string, c syscall.RawConn) error) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: control}
	return &http.Client{
		Timeout:       fetchTimeout,
		CheckRedirect: httpsRedirectsOnly,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
			ForceAttemptHTTP2:     true,
		},
	}
}

// httpsRedirectsOnly follows up to five redirects, each to https.
func httpsRedirectsOnly(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return errors.New("geoip: refused a redirect away from https")
	}
	if len(via) >= 5 {
		return errors.New("geoip: too many redirects")
	}
	return nil
}

// guardDial refuses a connection to any address that is not public
// unicast, so a download -- or a redirect from one -- can never be
// pointed at the operator's own network.
func guardDial(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("geoip: refusing to dial unparsable address %q", host)
	}
	addr = addr.Unmap()
	if !isPublicUnicast(addr) {
		return fmt.Errorf("geoip: refusing to dial non-public address %s", addr)
	}
	return nil
}

// isPublicUnicast is stricter than any one net/netip predicate: Go's
// miss carrier-grade NAT (100.64.0.0/10), 192.0.0.0/24, 198.18.0.0/15,
// the documentation ranges and the rest of 0.0.0.0/8, so the reserved
// lists backstop them. It decides both what is looked up and what is
// dialled.
func isPublicUnicast(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() ||
		addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsPrivate() || addr.IsInterfaceLocalMulticast() {
		return false
	}
	list := reservedV4
	if addr.Is6() {
		list = reservedV6
	}
	host := netip.PrefixFrom(addr.WithZone(""), addr.BitLen())
	for _, r := range list {
		if r.Overlaps(host) {
			return false
		}
	}
	return true
}

var reservedV4 = mustPrefixes(
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
)

var reservedV6 = mustPrefixes(
	"::1/128",
	"::/128",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
	"2001:db8::/32",
)

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

// request is one download.
type request struct {
	url      string
	user     string // basic auth; empty for none
	pass     string
	etag     string // conditional: If-None-Match
	modified string // conditional: If-Modified-Since
	tarGz    bool   // MaxMind's archive; otherwise a maybe-gzipped .mmdb
}

// response is what a download produced.
type response struct {
	notModified  bool
	refused      bool // 401 or 403: the provider refused the key
	etag         string
	lastModified string
}

// errStatus is an unexpected HTTP status. It carries only the code: a
// provider's error page can echo the request back, token included, so
// the body is never read.
type errStatus int

func (e errStatus) Error() string { return fmt.Sprintf("unexpected status %d", int(e)) }

// download fetches req and writes the extracted .mmdb bytes to dst.
// Every error it returns has been through cleanErr or redact.
func (m *Manager) download(ctx context.Context, req request, dst io.Writer) (response, error) {
	// Bounded here, not only by the default client's Timeout: a caller's
	// HTTPClient may have none, and a provider that stops answering --
	// before the headers or partway through the body -- would otherwise
	// hang the refresher for good. The request carries ctx, so this also
	// cuts off the body read inside extraction.
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	hr, err := http.NewRequestWithContext(ctx, http.MethodGet, req.url, nil)
	if err != nil {
		return response{}, errors.New(cleanErr(err, m.secrets))
	}
	hr.Header.Set("User-Agent", userAgent)
	if req.user != "" {
		hr.SetBasicAuth(req.user, req.pass)
	}
	if req.etag != "" {
		hr.Header.Set("If-None-Match", req.etag)
	}
	if req.modified != "" {
		hr.Header.Set("If-Modified-Since", req.modified)
	}
	resp, err := m.client.Do(hr)
	if err != nil {
		return response{}, errors.New(cleanErr(err, m.secrets))
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return response{notModified: true, etag: req.etag, lastModified: req.modified}, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return response{refused: true}, errStatus(resp.StatusCode)
	default:
		return response{}, errStatus(resp.StatusCode)
	}

	body := &capReader{r: resp.Body, left: maxFileBytes}
	if req.tarGz {
		err = extractTarGz(body, dst)
	} else {
		err = extractMaybeGzip(body, dst)
	}
	if err != nil {
		return response{}, errors.New(redact(err.Error(), m.secrets))
	}
	return response{etag: resp.Header.Get("ETag"), lastModified: resp.Header.Get("Last-Modified")}, nil
}

// capReader fails, rather than silently truncating, once more than left
// bytes have been read: a truncated file that happened to open would be
// worse than a refused one.
type capReader struct {
	r    io.Reader
	left int64
}

var errTooLarge = fmt.Errorf("download exceeds the %d MiB cap", maxFileBytes>>20)

func (c *capReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		var one [1]byte
		if n, _ := c.r.Read(one[:]); n > 0 {
			return 0, errTooLarge
		}
		return 0, io.EOF
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

// copyCapped copies at most maxFileBytes from src and fails if src has
// more, so a decompression bomb stops at the cap.
func copyCapped(dst io.Writer, src io.Reader) error {
	n, err := io.CopyN(dst, src, maxFileBytes+1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if n > maxFileBytes {
		return errTooLarge
	}
	if n == 0 {
		return errors.New("empty download")
	}
	return nil
}

// extractMaybeGzip copies a bare .mmdb, or one gzip-wrapped -- told
// apart by the gzip magic bytes, so a source that starts or stops
// compressing keeps working.
func extractMaybeGzip(body io.Reader, dst io.Writer) error {
	br := bufio.NewReader(body)
	magic, _ := br.Peek(2)
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return fmt.Errorf("gzip: %w", err)
		}
		defer func() { _ = zr.Close() }()
		return copyCapped(dst, zr)
	}
	return copyCapped(dst, br)
}

// extractTarGz copies the archive's single .mmdb member to dst. The
// member's name is never used as a path -- the file is kept under this
// package's own fixed name -- but a name that is absolute or climbs out
// with ".." marks an archive nobody should trust, and is refused.
func extractTarGz(body io.Reader, dst io.Writer) error {
	zr, err := gzip.NewReader(body)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer func() { _ = zr.Close() }()
	tr := tar.NewReader(zr)
	found := false
	for i := 0; ; i++ {
		if i >= maxTarEntries {
			return fmt.Errorf("archive has more than %d entries", maxTarEntries)
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		name := hdr.Name
		if path.IsAbs(name) || strings.Contains(name, `\`) || strings.Contains("/"+name+"/", "/../") {
			return fmt.Errorf("archive member %q has an unsafe path", name)
		}
		if !strings.HasSuffix(strings.ToLower(name), ".mmdb") {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("archive member %q is not a regular file", name)
		}
		if found {
			return errors.New("archive holds more than one .mmdb file")
		}
		if hdr.Size > maxFileBytes {
			return errTooLarge
		}
		if err := copyCapped(dst, tr); err != nil {
			return err
		}
		found = true
	}
	if !found {
		return errors.New("archive holds no .mmdb file")
	}
	return nil
}

// redactURL drops the query, user information and fragment -- where a
// token or credential can sit.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[unparsable URL]"
	}
	u.RawQuery = ""
	u.ForceQuery = false
	u.User = nil
	u.Fragment = ""
	return u.String()
}

// cleanErr renders a client error without the request URL's query. A
// *url.Error prints the full URL -- IPinfo's token included -- so it is
// rebuilt around the redacted URL rather than printed as it is.
func cleanErr(err error, secrets []string) string {
	msg := err.Error()
	var ue *url.Error
	if errors.As(err, &ue) {
		inner := "request failed"
		if ue.Err != nil {
			inner = ue.Err.Error()
		}
		msg = fmt.Sprintf("%s %s: %s", ue.Op, redactURL(ue.URL), inner)
	}
	return redact(msg, secrets)
}

// redact is the second line behind cleanErr: whatever path a message
// took, no key survives in it, plain or URL-escaped.
func redact(msg string, secrets []string) string {
	for _, s := range secrets {
		if s == "" {
			continue
		}
		msg = strings.ReplaceAll(msg, s, "[redacted]")
		if esc := url.QueryEscape(s); esc != s {
			msg = strings.ReplaceAll(msg, esc, "[redacted]")
		}
	}
	return msg
}
