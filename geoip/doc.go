// Package geoip looks up the country a public IP address is in, so a
// sign-in can be recorded with where it came from (#54,
// docs/adr/0008-sign-in-country.md). The application passes
// (*Manager).Country as gate.Config.Country.
//
// The lookup is local. The operator chooses one source -- MaxMind
// GeoLite2-Country or IPinfo Lite, each needing a free account -- and a
// Manager downloads that provider's country file to Config.Dir, keeps
// it current, and answers from it. No address is ever sent anywhere.
// There is no default source and no fallback from one to the other.
//
// With Config.Edition set to EditionCity (MaxMind only), the Manager
// keeps GeoLite2-City instead, and (*Manager).Locate also answers a
// point and radius for an address; the application passes it as
// gate.Config.Locate so impossible travel can be judged (#55). IPinfo
// Lite has no coordinates, so impossible travel is unavailable under it.
//
// It is a leaf, like passkey: it imports
// github.com/oschwald/maxminddb-golang/v2 (and the root package, for
// gauntlet.Location), and neither gate nor the root package imports it, so an application that never imports this package
// never compiles the reader in.
//
// The keys are the application's: they arrive in Config as plain
// strings, and nothing here stores them. Where they are used, sent or
// could be echoed back -- fetch.go -- they are kept out of every error,
// log line and Status.
//
// Every failure degrades rather than errors: until a file is loaded, and
// for any address that is not public or not in the file, Country
// reports "not known"; a failed refresh keeps the last good file.
//
// Ported from mikroview's internal/geoip (read at mikroview gitlab/dev
// 2b2089de: the download client and its guard, the archive handling,
// redaction, the two record layouts, the cache) with the refresh shape
// of gauntlet's blocklist.Refresher. Mikroview's key store, its third
// keyless source and its precedence between sources are left behind
// (ADR-0008).
package geoip
