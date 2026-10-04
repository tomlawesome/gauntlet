package geoip

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/tomlawesome/gauntlet"
)

// Source names the provider a Manager downloads from. The operator
// chooses one; there is no default.
type Source string

const (
	// SourceMaxMind is MaxMind GeoLite2-Country. It needs a MaxMind
	// account ID and licence key (Config.MaxMind).
	SourceMaxMind Source = "maxmind"
	// SourceIPinfo is IPinfo Lite. It needs an IPinfo token
	// (Config.IPinfo).
	SourceIPinfo Source = "ipinfo"
)

// Edition names which of a source's files a Manager keeps: the country
// file every source has, or MaxMind's larger city file, which also
// carries a location for each address (#55).
type Edition string

const (
	// EditionCountry is the default: GeoLite2-Country, or IPinfo Lite.
	// Country answers; Locate never does.
	EditionCountry Edition = "country"
	// EditionCity is GeoLite2-City: MaxMind only, since IPinfo Lite has
	// no coordinates. Country answers from it exactly as from the
	// Country file, and Locate answers too, which impossible travel
	// needs (gate.Config.Locate).
	EditionCity Edition = "city"
)

// MaxMindKey is what MaxMind's download needs: the account ID and a
// licence key made for it on maxmind.com.
type MaxMindKey struct {
	AccountID  string
	LicenceKey string
}

// IPinfoKey is what IPinfo's download needs: the account's token.
type IPinfoKey struct {
	Token string
}

const (
	// DefaultRefreshInterval is how often a Manager checks for a new
	// file when Config.Interval is zero. Both providers publish at most
	// daily, and the check is a conditional request where the provider
	// answers one.
	DefaultRefreshInterval = 24 * time.Hour
	// MinRefreshInterval is the shortest Config.Interval New accepts.
	MinRefreshInterval = time.Hour
	// StaleAfter is the age past which the file in use is reported as
	// stale: still used -- an address's country rarely moves -- but
	// each check logs one Warn line and Status says so, so a download
	// failing for weeks is said out loud.
	StaleAfter = 45 * 24 * time.Hour
)

// Config configures New.
type Config struct {
	// Source is the provider to download from. Required.
	Source Source
	// MaxMind is the key for SourceMaxMind, IPinfo the one for
	// SourceIPinfo; the one for the source not chosen is ignored. The
	// application keeps them (a configuration file, a mounted secret
	// file, its own sealed settings); gauntlet never stores them.
	MaxMind MaxMindKey
	IPinfo  IPinfoKey
	// Edition is which file to keep. "" means EditionCountry;
	// EditionCity needs SourceMaxMind. The City file is kept as
	// maxmind-city.mmdb, beside rather than over a Country file, and
	// only the configured edition's file is ever loaded: delete the
	// other edition's file when switching.
	Edition Edition
	// Dir is where the last good file is kept, as <Source>.mmdb (the
	// City file as maxmind-city.mmdb) beside
	// a small state.json, so a restart answers from it before any
	// download. Required. It is created (0700) if missing; files are
	// written 0600 to a temporary file and renamed into place. The file
	// is the provider's public data, not the application's state: leave
	// it out of backups.
	Dir string
	// HTTPClient makes the downloads. nil uses a client with a
	// two-minute overall timeout that follows https redirects only and
	// refuses to connect to a private, loopback, link-local,
	// unspecified or reserved address, redirects included.
	HTTPClient *http.Client
	// Interval is the time between checks; Run checks once at start and
	// then every Interval, give or take a tenth. Zero means
	// DefaultRefreshInterval; anything else below MinRefreshInterval is
	// an error. A failed check is retried after an hour instead, or a
	// day when the provider refused the key.
	Interval time.Duration
	// Log receives one Warn line for each failed check and each check
	// of a stale file, and one Info line for each file adopted. nil
	// discards them. No line carries a key.
	Log *slog.Logger
	// Now is the clock. nil means time.Now.
	Now func() time.Time
}

// Status is a Manager's state, for an application's health or settings
// page. It never carries a key.
type Status struct {
	Source Source `json:"source"`
	// Edition is the configured edition, EditionCountry when none was.
	Edition Edition `json:"edition"`
	// Loaded is whether a file is in use, so Country can answer.
	Loaded bool `json:"loaded"`
	// Locates is whether the file in use carries locations, so Locate
	// can answer: a City file is loaded.
	Locates bool `json:"locates"`
	// FetchedAt is when the file in use was downloaded or last
	// confirmed current by the provider; zero when none is loaded.
	FetchedAt time.Time `json:"fetchedAt,omitzero"`
	// NextRefresh is when Run checks next; zero before its first check.
	NextRefresh time.Time `json:"nextRefresh,omitzero"`
	// LastError is why the last check failed, "" when it succeeded.
	LastError string `json:"lastError,omitempty"`
	// Stale is whether the file in use is older than StaleAfter.
	Stale bool `json:"stale"`
}

// A Manager keeps one source's country file current and answers lookups
// from it. Its methods are safe for concurrent use, and a nil *Manager
// answers every lookup with "not known".
type Manager struct {
	source   Source
	edition  Edition
	endpoint string // the download URL, without credentials
	user     string // MaxMind basic auth
	pass     string
	token    string   // IPinfo, sent as ?token=
	secrets  []string // redacted from every message
	dir      string
	client   *http.Client
	interval time.Duration
	log      *slog.Logger
	now      func() time.Time
	// afterCheck, when set, is told the wait after each of Run's
	// checks. A seam for tests.
	afterCheck func(time.Duration)

	refreshMu sync.Mutex // one check at a time

	mu           sync.RWMutex // guards everything below
	reader       *maxminddb.Reader
	fetchedAt    time.Time
	etag         string
	lastModified string
	nextRefresh  time.Time
	lastError    string
	closed       bool
}

// New validates cfg and loads the file kept in cfg.Dir, if there is one
// and it opens; it makes no network request. Country answers from that
// file as soon as New returns. Call Run, usually in its own goroutine,
// to keep the file current, and Close once Run has returned.
func New(cfg Config) (*Manager, error) {
	m := &Manager{source: cfg.Source, edition: cfg.Edition}
	switch m.edition {
	case "":
		m.edition = EditionCountry
	case EditionCountry, EditionCity:
	default:
		return nil, fmt.Errorf("geoip: Config.Edition must be %q or %q", EditionCountry, EditionCity)
	}
	switch cfg.Source {
	case SourceMaxMind:
		if err := validateKey("MaxMind.AccountID", cfg.MaxMind.AccountID); err != nil {
			return nil, err
		}
		// A colon would end the account ID early inside HTTP basic auth.
		if strings.Contains(cfg.MaxMind.AccountID, ":") {
			return nil, errors.New("geoip: Config.MaxMind.AccountID contains a colon")
		}
		if err := validateKey("MaxMind.LicenceKey", cfg.MaxMind.LicenceKey); err != nil {
			return nil, err
		}
		m.endpoint = maxmindURL
		if m.edition == EditionCity {
			m.endpoint = maxmindCityURL
		}
		m.user, m.pass = cfg.MaxMind.AccountID, cfg.MaxMind.LicenceKey
	case SourceIPinfo:
		if m.edition == EditionCity {
			return nil, errors.New("geoip: Config.Edition city needs SourceMaxMind: IPinfo Lite has no coordinates")
		}
		if err := validateKey("IPinfo.Token", cfg.IPinfo.Token); err != nil {
			return nil, err
		}
		m.endpoint = ipinfoURL
		m.token = cfg.IPinfo.Token
	default:
		// Not quoted: a key pasted into the wrong field must not end
		// up in a log through this message.
		return nil, fmt.Errorf("geoip: Config.Source must be %q or %q", SourceMaxMind, SourceIPinfo)
	}
	// Both sources' keys, whichever is in use: neither may surface.
	m.secrets = []string{cfg.MaxMind.LicenceKey, cfg.MaxMind.AccountID, cfg.IPinfo.Token}
	if cfg.Dir == "" {
		return nil, errors.New("geoip: Config.Dir is required")
	}
	m.dir = cfg.Dir
	m.interval = cfg.Interval
	switch {
	case m.interval == 0:
		m.interval = DefaultRefreshInterval
	case m.interval < MinRefreshInterval:
		return nil, fmt.Errorf("geoip: Config.Interval %v is below the %v minimum", cfg.Interval, MinRefreshInterval)
	}
	m.client = cfg.HTTPClient
	if m.client == nil {
		m.client = newClient(guardDial)
	}
	m.log = cfg.Log
	if m.log == nil {
		m.log = slog.New(slog.DiscardHandler)
	}
	m.now = cfg.Now
	if m.now == nil {
		m.now = time.Now
	}
	m.loadCache()
	return m, nil
}

// maxKeyLen is far above any real key (IPinfo tokens are about 14
// characters, MaxMind licence keys 40); mikroview's limit.
const maxKeyLen = 256

// validateKey is mikroview's validateField. Its messages never repeat
// the value.
func validateKey(field, v string) error {
	switch {
	case v == "":
		return fmt.Errorf("geoip: Config.%s is empty", field)
	case len(v) > maxKeyLen:
		return fmt.Errorf("geoip: Config.%s is longer than %d characters", field, maxKeyLen)
	}
	for _, r := range v {
		if unicode.IsSpace(r) || !unicode.IsPrint(r) || r > unicode.MaxASCII {
			return fmt.Errorf("geoip: Config.%s contains whitespace or characters no key uses", field)
		}
	}
	return nil
}

// Country returns the ISO 3166-1 alpha-2 code, upper case, of the
// country address is in, and whether one is known. It is not known --
// never an error -- for an address that does not parse or is not public
// unicast, before a file is loaded, and for an address the file has no
// country for. Its signature is gate.Config.Country's.
func (m *Manager) Country(address string) (code string, ok bool) {
	ip, ok := lookupAddr(address)
	if !ok || m == nil {
		return "", false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.reader == nil {
		return "", false
	}
	code = countryFrom(m.reader.Lookup(ip))
	return code, code != ""
}

// Locate returns the point an address is likely near and the radius
// around it, and whether one is known. It is not known for the same
// addresses Country is not known for, for any address when the file in
// use carries no locations (EditionCountry, or a record without all
// three of latitude, longitude and accuracy radius), and always under
// SourceIPinfo. Its signature is gate.Config.Locate's.
func (m *Manager) Locate(address string) (gauntlet.Location, bool) {
	ip, ok := lookupAddr(address)
	if !ok || m == nil || m.edition != EditionCity {
		return gauntlet.Location{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.reader == nil {
		return gauntlet.Location{}, false
	}
	return locationFrom(m.reader.Lookup(ip))
}

// lookupAddr parses address and reports whether it is worth looking up:
// only a public unicast address has a country. An IPv4-mapped IPv6
// address is the IPv4 host it carries, and a zone is dropped.
func lookupAddr(address string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return netip.Addr{}, false
	}
	ip = ip.Unmap().WithZone("")
	return ip, isPublicUnicast(ip)
}

// Status reports the Manager's state. A nil Manager reports nothing
// loaded.
func (m *Manager) Status() Status {
	if m == nil {
		return Status{}
	}
	now := m.now()
	m.mu.RLock()
	defer m.mu.RUnlock()
	st := Status{
		Source:      m.source,
		Edition:     m.edition,
		Loaded:      m.reader != nil,
		NextRefresh: m.nextRefresh,
		LastError:   m.lastError,
	}
	if st.Loaded {
		st.FetchedAt = m.fetchedAt
		// adopt and loadCache accept only a City-typed file for
		// EditionCity, so a loaded City manager's file carries them.
		st.Locates = m.edition == EditionCity
		st.Stale = now.Sub(m.fetchedAt) > StaleAfter
	}
	return st
}

// Close releases the file in use; Country then reports nothing known.
// Call it after Run has returned. Closing twice, or a nil Manager, is
// harmless.
func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	if m.reader == nil {
		return nil
	}
	err := m.reader.Close()
	m.reader = nil
	return err
}
