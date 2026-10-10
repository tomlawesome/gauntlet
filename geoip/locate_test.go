package geoip

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/tomlawesome/gauntlet"
)

// The City fixture's point: made up, like its country.
const (
	fixtureLat    = 51.5
	fixtureLon    = -0.12
	fixtureRadius = 20
)

// buildCityDB is a GeoLite2-City-shaped file: the nested country plus a
// location map, typed as a City database.
func buildCityDB(t *testing.T, iso string) []byte {
	t.Helper()
	return buildTypedDB(t, "GeoLite2-City", func() mmdbtype.Map {
		return mmdbtype.Map{
			"country": mmdbtype.Map{"iso_code": mmdbtype.String(iso)},
			"location": mmdbtype.Map{
				"latitude":        mmdbtype.Float64(fixtureLat),
				"longitude":       mmdbtype.Float64(fixtureLon),
				"accuracy_radius": mmdbtype.Uint16(fixtureRadius),
			},
		}
	})
}

// buildTypedDB maps the fixture's networks to rec() in a file whose
// metadata names dbType.
func buildTypedDB(t *testing.T, dbType string, rec func() mmdbtype.Map) []byte {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: dbType})
	if err != nil {
		t.Fatalf("mmdbwriter.New: %v", err)
	}
	for _, cidr := range []string{"81.2.69.0/24", "2a02:ff0::/32"} {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Insert(network, rec()); err != nil {
			t.Fatalf("Insert(%s): %v", cidr, err)
		}
	}
	var buf bytes.Buffer
	if _, err := w.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// cityArchive is the shape GeoLite2-City downloads in.
func cityArchive(t *testing.T, db []byte) []byte {
	return tarGz(t,
		tarMember{name: "GeoLite2-City_20261002/COPYRIGHT.txt", body: []byte("test")},
		tarMember{name: "GeoLite2-City_20261002/GeoLite2-City.mmdb", body: db},
	)
}

func TestNewRefusesCityUnderIPinfo(t *testing.T) {
	_, err := New(Config{Source: SourceIPinfo, IPinfo: IPinfoKey{Token: testToken}, Dir: t.TempDir(), Edition: EditionCity})
	if err == nil || !strings.Contains(err.Error(), "IPinfo Lite has no coordinates") {
		t.Fatalf("New(IPinfo, City) = %v, want a refusal naming the missing coordinates", err)
	}
	_, err = New(Config{Source: SourceMaxMind, MaxMind: MaxMindKey{AccountID: testAccount, LicenceKey: testLicence}, Dir: t.TempDir(), Edition: "region"})
	if err == nil || !strings.Contains(err.Error(), "Edition") {
		t.Fatalf("New with an unknown edition = %v, want a refusal", err)
	}
}

func TestEditionEndpoints(t *testing.T) {
	for _, c := range []struct {
		ed       Edition
		endpoint string
		want     Edition
	}{
		{"", maxmindURL, EditionCountry},
		{EditionCountry, maxmindURL, EditionCountry},
		{EditionCity, maxmindCityURL, EditionCity},
	} {
		m, err := New(Config{Source: SourceMaxMind, MaxMind: MaxMindKey{AccountID: testAccount, LicenceKey: testLicence}, Dir: t.TempDir(), Edition: c.ed})
		if err != nil {
			t.Fatal(err)
		}
		if m.endpoint != c.endpoint {
			t.Errorf("edition %q: endpoint = %q, want %q", c.ed, m.endpoint, c.endpoint)
		}
		if st := m.Status(); st.Edition != c.want || st.Locates {
			t.Errorf("edition %q: Status = %+v, want edition %q and nothing located yet", c.ed, st, c.want)
		}
		_ = m.Close()
	}
	if !strings.Contains(maxmindCityURL, "/GeoLite2-City/download?suffix=tar.gz") {
		t.Errorf("maxmindCityURL = %q", maxmindCityURL)
	}
}

func newCityEnv(t *testing.T, dir string) *env {
	t.Helper()
	e := newEnvWith(t, SourceMaxMind, EditionCity, dir)
	e.m.endpoint = e.srv.URL + "/maxmind-city"
	return e
}

func TestCityDownloadLocates(t *testing.T) {
	e := newCityEnv(t, t.TempDir())
	db := buildCityDB(t, "GB")
	e.fp.set("/maxmind-city", cityArchive(t, db))
	e.m.refresh(context.Background())
	if st := e.m.Status(); !st.Loaded || st.LastError != "" || st.Edition != EditionCity || !st.Locates {
		t.Fatalf("Status = %+v, want the City file loaded and locating", st)
	}
	got, err := os.ReadFile(filepath.Join(e.dir, "maxmind-city.mmdb"))
	if err != nil || !bytes.Equal(got, db) {
		t.Errorf("the City file is not kept as maxmind-city.mmdb (err %v)", err)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "maxmind.mmdb")); err == nil {
		t.Error("the City download was kept under the Country file's name")
	}
	state, _ := os.ReadFile(filepath.Join(e.dir, stateFileName))
	var st stateFile
	if err := json.Unmarshal(state, &st); err != nil || st.Edition != EditionCity {
		t.Errorf("state.json = %s, want edition city", state)
	}
	for _, addr := range []string{inV4, inV6} {
		loc, ok := e.m.Locate(addr)
		want := gauntlet.Location{Latitude: fixtureLat, Longitude: fixtureLon, RadiusKm: fixtureRadius}
		if !ok || loc != want {
			t.Errorf("Locate(%s) = %+v %v, want %+v", addr, loc, ok, want)
		}
	}
	if c, ok := e.m.Country(inV4); !ok || c != "GB" {
		t.Errorf("Country from the City file = %q %v, want GB", c, ok)
	}
	for _, addr := range []string{outV4, "10.0.0.1", "192.0.2.1", "not-an-address"} {
		if _, ok := e.m.Locate(addr); ok {
			t.Errorf("Locate(%s) answered", addr)
		}
	}
}

// The file locates every address, so a non-public one is refused by
// Locate itself and not by missing from the file.
func TestLocateOnlyPublicUnicast(t *testing.T) {
	e := newCityEnv(t, t.TempDir())
	db := buildCoveringDB(t, "GeoLite2-City", func() mmdbtype.Map {
		return mmdbtype.Map{
			"country": mmdbtype.Map{"iso_code": mmdbtype.String("GB")},
			"location": mmdbtype.Map{
				"latitude":        mmdbtype.Float64(fixtureLat),
				"longitude":       mmdbtype.Float64(fixtureLon),
				"accuracy_radius": mmdbtype.Uint16(fixtureRadius),
			},
		}
	})
	e.fp.set("/maxmind-city", cityArchive(t, db))
	e.m.refresh(context.Background())
	want := gauntlet.Location{Latitude: fixtureLat, Longitude: fixtureLon, RadiusKm: fixtureRadius}
	for _, addr := range []string{inV4, outV4, "::ffff:" + outV4, inV6} {
		if loc, ok := e.m.Locate(addr); !ok || loc != want {
			t.Fatalf("setup: Locate(%s) = %+v %v, want %+v", addr, loc, ok, want)
		}
	}
	for _, addr := range []string{
		"10.0.0.1", "172.16.5.4", "192.168.1.1", "127.0.0.1", "::ffff:127.0.0.1",
		"::1", "::", "0.0.0.0", "169.254.169.254", "fe80::1", "fd00::1", "100.64.0.1",
		"192.0.2.1", "2001:db8::1", "224.0.0.1", "255.255.255.255", "not-an-address", "",
	} {
		if loc, ok := e.m.Locate(addr); ok {
			t.Errorf("Locate(%q) = %+v, want refused", addr, loc)
		}
	}
}

func TestLocateNotOkWithoutLocations(t *testing.T) {
	// Country edition: the Country file has no location.
	e := newEnv(t, SourceMaxMind)
	e.fp.set("/maxmind", maxmindArchive(t, buildDB(t, nested, "JP")))
	e.m.refresh(context.Background())
	if _, ok := e.m.Country(inV4); !ok {
		t.Fatal("setup: no country")
	}
	if loc, ok := e.m.Locate(inV4); ok {
		t.Errorf("Locate from a Country file = %+v, want not ok", loc)
	}
	if st := e.m.Status(); st.Locates {
		t.Error("Status.Locates for a Country file")
	}
	// IPinfo: never, even from a file that happened to carry locations.
	ip := newEnv(t, SourceIPinfo)
	ip.fp.set("/ipinfo", buildCityDB(t, "IS"))
	ip.m.refresh(context.Background())
	if _, ok := ip.m.Country(inV4); !ok {
		t.Fatal("setup: no IPinfo country")
	}
	if _, ok := ip.m.Locate(inV4); ok {
		t.Error("Locate answered under IPinfo")
	}
	// A record missing any of the three never answers.
	partial := newCityEnv(t, t.TempDir())
	partial.fp.set("/maxmind-city", cityArchive(t, buildTypedDB(t, "GeoLite2-City", func() mmdbtype.Map {
		return mmdbtype.Map{
			"country":  mmdbtype.Map{"iso_code": mmdbtype.String("GB")},
			"location": mmdbtype.Map{"latitude": mmdbtype.Float64(1), "longitude": mmdbtype.Float64(2)},
		}
	})))
	partial.m.refresh(context.Background())
	if !partial.m.Status().Loaded {
		t.Fatal("setup: partial City file not loaded")
	}
	if loc, ok := partial.m.Locate(inV4); ok {
		t.Errorf("Locate with no accuracy radius = %+v, want not ok", loc)
	}
	var nilManager *Manager
	if _, ok := nilManager.Locate(inV4); ok {
		t.Error("a nil Manager located")
	}
}

func TestCityRefusesACountryFile(t *testing.T) {
	e := newCityEnv(t, t.TempDir())
	e.fp.set("/maxmind-city", cityArchive(t, buildCityDB(t, "GB")))
	e.m.refresh(context.Background())
	if _, ok := e.m.Locate(inV4); !ok {
		t.Fatal("setup: the City file did not load")
	}
	e.fp.set("/maxmind-city", cityArchive(t, buildTypedDB(t, "GeoLite2-Country", func() mmdbtype.Map {
		return mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String("FR")}}
	})))
	e.m.refresh(context.Background())
	st := e.m.Status()
	if !strings.Contains(st.LastError, "not a city file") {
		t.Errorf("LastError = %q, want the download refused as not a city file", st.LastError)
	}
	if c, _ := e.m.Country(inV4); c != "GB" {
		t.Errorf("Country = %q after a refused download, want the file in use kept (GB)", c)
	}
	if _, ok := e.m.Locate(inV4); !ok {
		t.Error("Locate stopped answering after a refused download")
	}
}

func TestKeptFileOfTheOtherEditionIsNotLoaded(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "maxmind.mmdb"), buildDB(t, nested, "JP"), 0o600); err != nil {
		t.Fatal(err)
	}
	city := newCityEnv(t, dir)
	if city.m.Status().Loaded {
		t.Error("a City manager loaded the kept Country file")
	}
	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, "maxmind-city.mmdb"), buildCityDB(t, "GB"), 0o600); err != nil {
		t.Fatal(err)
	}
	country := newEnvIn(t, SourceMaxMind, dir2)
	if country.m.Status().Loaded {
		t.Error("a Country manager loaded the kept City file")
	}
	// A kept City file loads for a City manager, and answers at once.
	reload := newCityEnv(t, dir2)
	if st := reload.m.Status(); !st.Loaded || !st.Locates {
		t.Errorf("Status of a City manager over its kept file = %+v", st)
	}
	if _, ok := reload.m.Locate(inV4); !ok {
		t.Error("the kept City file does not locate")
	}
	// A kept file under the City name that is not a City file is not used.
	dir3 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir3, "maxmind-city.mmdb"), buildDB(t, nested, "JP"), 0o600); err != nil {
		t.Fatal(err)
	}
	if newCityEnv(t, dir3).m.Status().Loaded {
		t.Error("a Country file kept under the City name was loaded")
	}
}
