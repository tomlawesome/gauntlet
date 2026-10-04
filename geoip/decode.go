package geoip

import (
	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/tomlawesome/gauntlet"
)

// The two sources use two record layouts:
//
//   - MaxMind GeoLite2: nested, {"country": {"iso_code": "GB", ...}}.
//   - IPinfo Lite: flat, {"country_code": "GB", "country": "United
//     Kingdom", "asn": ..., ...}. "country" is a string here, not a map.
//
// Read by path rather than decoded into one struct, as mikroview does:
// a struct with a nested Country field fails to decode IPinfo's string
// "country" at all, and a struct per source would make a source that
// changed layout read as "not known" for every address. Trying the flat
// path first and the nested one second tolerates either layout from
// either source. Only the country is read, and from a City file the
// location (locationFrom).

// countryFrom returns the upper-case ISO 3166-1 alpha-2 code in a
// lookup result, in either layout, or "" when the address is not in the
// file or its record holds no such code.
func countryFrom(res maxminddb.Result) string {
	if !res.Found() {
		return ""
	}
	var code string
	if err := res.DecodePath(&code, "country_code"); err == nil {
		if c := alpha2(code); c != "" {
			return c
		}
	}
	code = ""
	if err := res.DecodePath(&code, "country", "iso_code"); err == nil {
		return alpha2(code)
	}
	return ""
}

// alpha2 is code upper-cased when it is two ASCII letters, else "":
// whatever a file holds, a caller only ever sees a code the API's
// pattern (^[A-Z]{2}$) allows.
func alpha2(code string) string {
	if len(code) != 2 {
		return ""
	}
	var b [2]byte
	for i := range 2 {
		c := code[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		default:
			return ""
		}
		b[i] = c
	}
	if b[0] == code[0] && b[1] == code[1] {
		return code
	}
	return string(b[:])
}

// locationFrom returns a lookup result's location -- MaxMind's
// location.latitude, location.longitude and location.accuracy_radius --
// and whether all three decoded. A Country file's records, and any
// record missing one of them, answer not ok: a point with no radius, or
// a radius with half a point, is not a location.
func locationFrom(res maxminddb.Result) (gauntlet.Location, bool) {
	if !res.Found() {
		return gauntlet.Location{}, false
	}
	// Pointers, so a path the record lacks -- which DecodePath answers
	// without an error -- is told apart from a real zero.
	var lat, lon *float64
	var radius *uint16
	if res.DecodePath(&lat, "location", "latitude") != nil ||
		res.DecodePath(&lon, "location", "longitude") != nil ||
		res.DecodePath(&radius, "location", "accuracy_radius") != nil ||
		lat == nil || lon == nil || radius == nil {
		return gauntlet.Location{}, false
	}
	return gauntlet.Location{Latitude: *lat, Longitude: *lon, RadiusKm: int(*radius)}, true
}
