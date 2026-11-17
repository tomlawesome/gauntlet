// Package blocklist is gauntlet's common-password list: the SHA-1
// hashes of the 10,000 most prevalent passwords in Have I Been Pwned's
// Pwned Passwords corpus (#43, #52, ADR-0007).
//
// It is a fallback for applications that cannot reach the live HIBP
// check, and a floor under those that can. The hashes are only ever
// compared against a new password; they are never credentials and
// nothing here stores or logs a password.
//
// Nothing in this package touches the network unless the application
// asks it to. Embedded returns the copy compiled into this release.
// A Refresher, opt-in, fetches the newest published copy, accepts it
// only when its signature, checksum and format all check out and it is
// newer than what the application already has, and keeps it on disk so
// a restart does not fall back to an older list.
//
// The list itself is built by cmd/pwlist in a monthly CI pipeline,
// signed, and published to the GitLab package registry and then to
// releases on the public GitHub mirror, which is where a Refresher
// fetches it (DefaultURL); ADR-0007 has the whole path. The data is from haveibeenpwned.com, which places no
// licence terms on the Pwned Passwords API; the attribution is voluntary
// and carried in every copy's header.
package blocklist

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // HIBP's corpus is SHA-1; this is a lookup key, not a password hash.
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// formatLine is the first line of every list file, naming its version. A
// file that does not start with it is refused, so a later format can
// never be misread as this one.
const formatLine = "# format: gauntlet-pwned-top10k/1"

// size is how many hashes a list holds: exactly this many, no more and
// no fewer. ASVS 5.0 V6.2.4 asks for at least the top 3,000; the owner
// chose 10,000 on #43.
const size = 10000

// List is an immutable, sorted set of password SHA-1 hashes. The zero
// value and a nil *List are empty lists: Contains reports false for
// every password.
type List struct {
	hashes [][sha1.Size]byte // ascending
	built  time.Time
	sum    [sha256.Size]byte // SHA-256 of the file Parse read
}

// Contains reports whether password is on the list: whether the SHA-1
// of its exact bytes is one of the list's hashes. The comparison is
// exact, as HIBP's is -- "Password" and "password" are different
// entries -- so a caller that wants a case-insensitive check asks
// about each spelling it cares about.
func (l *List) Contains(password string) bool {
	if l == nil || len(l.hashes) == 0 {
		return false
	}
	h := sha1.Sum([]byte(password)) //nolint:gosec // see the import.
	_, found := slices.BinarySearchFunc(l.hashes, h, func(a, b [sha1.Size]byte) int {
		return bytes.Compare(a[:], b[:])
	})
	return found
}

// Built is when the list was built, from its `# built:` header. It is
// the zero time for an empty list, so any real list is newer.
func (l *List) Built() time.Time {
	if l == nil {
		return time.Time{}
	}
	return l.built
}

// Len is how many hashes the list holds: 10,000 for any list Parse
// accepted, 0 for an empty one.
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	return len(l.hashes)
}

// Parse reads a list file in format `gauntlet-pwned-top10k/1`:
//
//	# format: gauntlet-pwned-top10k/1
//	# source: ...
//	# built: <RFC 3339, UTC>
//	# count: 10000
//	# min-count: ... (and other `# key: value` lines)
//	<40 uppercase hex characters>   x 10,000, strictly ascending
//
// It is strict, because the file comes from the network: lines end in
// a single "\n" (no "\r", and the last line too); the format line comes
// first; every header is `# key: value` with no key twice; `built` and
// `count` are required and `count` is 10000; the body is exactly
// 10,000 hashes in strictly ascending order with no blank or comment
// line among them. A file carrying a `# sample:` header -- the partial
// list a CI test run produces -- is refused, so a sample can never be
// mistaken for a real list. Header keys this version does not know are
// ignored.
//
// Parse checks the format only. It does not check a signature: a copy
// fetched from anywhere goes through a Refresher, which does.
func Parse(data []byte) (*List, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, errors.New("blocklist: empty, or the last line is not terminated")
	}
	if bytes.IndexByte(data, '\r') >= 0 {
		return nil, errors.New("blocklist: carriage return in the file; lines end in \\n only")
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	if lines[0] != formatLine {
		return nil, fmt.Errorf("blocklist: first line is not %q", formatLine)
	}

	headers := make(map[string]string)
	i := 1
	for ; i < len(lines) && strings.HasPrefix(lines[i], "#"); i++ {
		key, value, ok := strings.Cut(strings.TrimPrefix(lines[i], "# "), ": ")
		if !strings.HasPrefix(lines[i], "# ") || !ok || key == "" || strings.ContainsAny(key, " :") {
			return nil, fmt.Errorf("blocklist: line %d is not a `# key: value` header", i+1)
		}
		if _, dup := headers[key]; dup || key == "format" {
			return nil, fmt.Errorf("blocklist: header %q appears twice", key)
		}
		headers[key] = value
	}
	if _, ok := headers["sample"]; ok {
		return nil, errors.New("blocklist: this is a sample build (`# sample:` header), not a list for use")
	}
	built, err := time.Parse(time.RFC3339, headers["built"])
	if err != nil {
		return nil, fmt.Errorf("blocklist: `# built:` header missing or not RFC 3339: %q", headers["built"])
	}
	if headers["count"] != strconv.Itoa(size) {
		return nil, fmt.Errorf("blocklist: `# count:` is %q, want %d", headers["count"], size)
	}

	body := lines[i:]
	if len(body) != size {
		return nil, fmt.Errorf("blocklist: %d hashes, want exactly %d", len(body), size)
	}
	l := &List{hashes: make([][sha1.Size]byte, size), built: built.UTC(), sum: sha256.Sum256(data)}
	for j, line := range body {
		if !isUpperHex(line, 2*sha1.Size) {
			return nil, fmt.Errorf("blocklist: line %d is not 40 uppercase hex characters", i+j+1)
		}
		if _, err := hex.Decode(l.hashes[j][:], []byte(line)); err != nil {
			return nil, fmt.Errorf("blocklist: line %d: %w", i+j+1, err)
		}
		if j > 0 && bytes.Compare(l.hashes[j-1][:], l.hashes[j][:]) >= 0 {
			return nil, fmt.Errorf("blocklist: line %d is not above the line before it; hashes must be strictly ascending", i+j+1)
		}
	}
	return l, nil
}

func isUpperHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// The copy compiled into this release: blocklist/embedded/top10k.txt
// and its signature, the exact files the pipeline published, placed
// there by scripts/update-blocklist.sh as a release step.
//
// A tree without the real list carries embedded/PLACEHOLDER instead,
// as it did before the first signed CI run; see Embedded.
//
//go:embed embedded
var embeddedFS embed.FS

const (
	embeddedList        = "embedded/top10k.txt"
	embeddedSig         = "embedded/top10k.txt.sig"
	embeddedPlaceholder = "embedded/PLACEHOLDER"
)

// Embedded returns the list compiled into this release of gauntlet.
// It never touches the network or the disk, and never returns nil.
//
// Until the first signed CI run publishes a real list, the release
// carries a placeholder (blocklist/embedded/PLACEHOLDER) instead, and
// Embedded returns an empty list: Contains is false for every
// password, Len is 0 and Built is the zero time, so any list a
// Refresher fetches is newer. The first real list arrives with the
// first signed run, through scripts/update-blocklist.sh; from then on
// the placeholder is gone and a release refuses to tag without a list
// built within the last 90 days (scripts/blocklist-age-check.sh).
//
// The embedded copy's signature is not checked here, at run time: it
// was checked when it was committed, and a test (TestEmbeddedCopy)
// checks it against the committed public keys on every pipeline. A
// copy that fails to parse is a broken build, not a condition an
// application can recover from, so Embedded panics on it -- that
// same test makes sure no such build is ever tagged.
func Embedded() *List {
	return embedded()
}

var embedded = sync.OnceValue(func() *List {
	l, err := loadEmbedded(embeddedFS)
	if err != nil {
		panic(err)
	}
	return l
})

// loadEmbedded reads the embedded copy from fsys. Exactly one of
// top10k.txt and PLACEHOLDER must be present: both, or neither, is a
// mistake in the release (the update script removes the placeholder as
// it adds the list), and an empty list must never be the silent result
// of a deleted file.
func loadEmbedded(fsys fs.FS) (*List, error) {
	data, listErr := fs.ReadFile(fsys, embeddedList)
	_, placeholderErr := fs.Stat(fsys, embeddedPlaceholder)
	hasList, hasPlaceholder := listErr == nil, placeholderErr == nil
	switch {
	case hasList && hasPlaceholder:
		return nil, fmt.Errorf("blocklist: both %s and %s are present; remove the placeholder", embeddedList, embeddedPlaceholder)
	case hasPlaceholder:
		return &List{}, nil
	case !hasList:
		return nil, fmt.Errorf("blocklist: neither %s nor %s is present", embeddedList, embeddedPlaceholder)
	}
	l, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("blocklist: embedded copy: %w", err)
	}
	return l, nil
}
