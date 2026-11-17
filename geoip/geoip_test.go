package geoip

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/oschwald/maxminddb-golang/v2"
	"net/netip"
)

func TestNewValidatesConfig(t *testing.T) {
	good := func() Config {
		return Config{
			Source:  SourceMaxMind,
			MaxMind: MaxMindKey{AccountID: testAccount, LicenceKey: testLicence},
			Dir:     t.TempDir(),
		}
	}
	for _, c := range []struct {
		name   string
		change func(*Config)
		want   string // in the error; "" means New must succeed
		secret string // must not appear in the error
	}{
		{"maxmind", func(*Config) {}, "", ""},
		{"ipinfo", func(c *Config) {
			c.Source, c.MaxMind, c.IPinfo = SourceIPinfo, MaxMindKey{}, IPinfoKey{Token: testToken}
		}, "", ""},
		{"interval at the minimum", func(c *Config) { c.Interval = MinRefreshInterval }, "", ""},
		{"no source", func(c *Config) { c.Source = "" }, "Source", ""},
		{"unknown source", func(c *Config) { c.Source = "dbip" }, "Source", ""},
		{"source holding a key by mistake", func(c *Config) { c.Source = Source(testLicence) }, "Source", testLicence},
		{"empty account ID", func(c *Config) { c.MaxMind.AccountID = "" }, "AccountID is empty", ""},
		{"empty licence key", func(c *Config) { c.MaxMind.LicenceKey = "" }, "LicenceKey is empty", ""},
		{"colon in the account ID", func(c *Config) { c.MaxMind.AccountID = "12:34" }, "colon", "12:34"},
		{"space in the licence key", func(c *Config) { c.MaxMind.LicenceKey = "lic SECRET" }, "whitespace", "lic SECRET"},
		{"tab in the licence key", func(c *Config) { c.MaxMind.LicenceKey = "lic\tSECRET" }, "whitespace", "lic\tSECRET"},
		{"non-ASCII licence key", func(c *Config) { c.MaxMind.LicenceKey = "lïcSECRET" }, "whitespace", "lïcSECRET"},
		{"overlong licence key", func(c *Config) { c.MaxMind.LicenceKey = strings.Repeat("k", 257) }, "longer than", strings.Repeat("k", 257)},
		{"ipinfo with no token", func(c *Config) { c.Source = SourceIPinfo }, "Token is empty", ""},
		{"ipinfo token with a newline", func(c *Config) { c.Source, c.IPinfo.Token = SourceIPinfo, "tok\nSECRET" }, "whitespace", "tok\nSECRET"},
		{"no Dir", func(c *Config) { c.Dir = "" }, "Dir is required", ""},
		{"interval below the minimum", func(c *Config) { c.Interval = 30 * time.Minute }, "below", ""},
		{"negative interval", func(c *Config) { c.Interval = -time.Hour }, "below", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := good()
			c.change(&cfg)
			m, err := New(cfg)
			if c.want == "" {
				if err != nil {
					t.Fatalf("New = %v, want success", err)
				}
				_ = m.Close()
				return
			}
			if err == nil {
				_ = m.Close()
				t.Fatalf("New succeeded, want an error containing %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("New = %q, want it to contain %q", err, c.want)
			}
			if c.secret != "" && strings.Contains(err.Error(), c.secret) {
				t.Errorf("the error repeats the value: %q", err)
			}
		})
	}
}

func TestNewDefaults(t *testing.T) {
	m, err := New(Config{Source: SourceIPinfo, IPinfo: IPinfoKey{Token: testToken}, Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	if m.interval != DefaultRefreshInterval {
		t.Errorf("interval = %v, want %v", m.interval, DefaultRefreshInterval)
	}
	if m.endpoint != ipinfoURL {
		t.Errorf("endpoint = %q, want %q", m.endpoint, ipinfoURL)
	}
	if m.client == nil || m.client.Timeout != 2*time.Minute || m.client.CheckRedirect == nil {
		t.Errorf("default client = %+v, want a two-minute timeout and a redirect policy", m.client)
	}
	if st := m.Status(); st.Source != SourceIPinfo || st.Loaded {
		t.Errorf("Status of a fresh manager = %+v", st)
	}
}

func TestDecodesBothRecordLayouts(t *testing.T) {
	for _, c := range []struct {
		name string
		l    layout
	}{
		{"nested (MaxMind GeoLite2)", nested},
		{"flat (IPinfo Lite)", flat},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, err := maxminddb.OpenBytes(buildDB(t, c.l, "nz"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()
			if got := countryFrom(r.Lookup(netip.MustParseAddr(inV4))); got != "NZ" {
				t.Errorf("countryFrom = %q, want NZ, upper-cased", got)
			}
			if got := countryFrom(r.Lookup(netip.MustParseAddr(outV4))); got != "" {
				t.Errorf("countryFrom on a miss = %q, want empty", got)
			}
		})
	}
}

// TestOnlyTwoLetterCodes: whatever a file holds, the caller gets an
// upper-case ISO 3166-1 alpha-2 code or nothing.
func TestOnlyTwoLetterCodes(t *testing.T) {
	for _, iso := range []string{"GBR", "G", "", "1A", "G-", "Ü"} {
		for _, l := range []layout{nested, flat} {
			r, err := maxminddb.OpenBytes(buildDB(t, l, iso))
			if err != nil {
				t.Fatal(err)
			}
			if got := countryFrom(r.Lookup(netip.MustParseAddr(inV4))); got != "" {
				t.Errorf("layout %d, code %q: countryFrom = %q, want not known", l, iso, got)
			}
			_ = r.Close()
		}
	}
}

// The file answers "IS" for every address, so a non-public address comes
// back empty only because Country refused it before reading the file.
func TestLookupOnlyPublicUnicast(t *testing.T) {
	e := newEnv(t, SourceIPinfo)
	e.fp.set("/ipinfo", buildCoveringDB(t, "gauntlet-test", func() mmdbtype.Map {
		return mmdbtype.Map{"country_code": mmdbtype.String("IS"), "country": mmdbtype.String("Somewhere")}
	}))
	e.m.refresh(context.Background())
	for _, c := range []struct {
		addr string
		want string
	}{
		{inV4, "IS"},
		{"::ffff:" + inV4, "IS"},
		{inV6, "IS"},
		{outV4, "IS"},
		{"10.0.0.1", ""},
		{"172.16.5.4", ""},
		{"192.168.1.1", ""},
		{"127.0.0.1", ""},
		{"::ffff:127.0.0.1", ""},
		{"::ffff:192.168.1.1", ""},
		{"::1", ""},
		{"::", ""},
		{"0.0.0.0", ""},
		{"169.254.169.254", ""},
		{"fe80::1", ""},
		{"fe80::1%eth0", ""},
		{"fd00::1", ""},
		{"100.64.0.1", ""},
		{"192.0.2.1", ""},
		{"2001:db8::1", ""},
		{"224.0.0.1", ""},
		{"255.255.255.255", ""},
		{"not-an-address", ""},
		{inV4 + ":443", ""},
		{"", ""},
	} {
		got, ok := e.m.Country(c.addr)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("Country(%q) = %q %v, want %q", c.addr, got, ok, c.want)
		}
	}
}

func TestNotKnownWithoutAFile(t *testing.T) {
	e := newEnv(t, SourceMaxMind)
	if _, ok := e.m.Country(inV4); ok {
		t.Error("Country answered with no file loaded")
	}
	var nilManager *Manager
	if _, ok := nilManager.Country(inV4); ok {
		t.Error("a nil Manager answered")
	}
	if err := nilManager.Close(); err != nil {
		t.Errorf("Close on a nil Manager = %v", err)
	}
	if st := nilManager.Status(); st.Loaded {
		t.Error("a nil Manager reports a loaded file")
	}
}

func TestCloseStopsAnswering(t *testing.T) {
	e := newEnv(t, SourceIPinfo)
	e.fp.set("/ipinfo", buildDB(t, flat, "IS"))
	e.m.refresh(context.Background())
	if _, ok := e.m.Country(inV4); !ok {
		t.Fatal("setup: no answer before Close")
	}
	if err := e.m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.m.Country(inV4); ok {
		t.Error("Country answered after Close")
	}
	if err := e.m.Close(); err != nil {
		t.Errorf("a second Close = %v", err)
	}
	// A refresh finishing after Close must not leave a file open.
	e.m.refresh(context.Background())
	if _, ok := e.m.Country(inV4); ok {
		t.Error("a refresh after Close loaded a file")
	}
}
