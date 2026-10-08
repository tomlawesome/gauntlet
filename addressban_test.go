package gauntlet

import (
	"fmt"
	"testing"
	"time"
)

// The address ban (#70): AddressBanFailures failed sign-in attempts from
// one address ban it for AddressBanDuration. Addresses here are from the
// documentation ranges (RFC 5737, RFC 3849).

var banStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// failN records n failures from address at at, returning whether any of
// them started a ban.
func failN(l *LoginLimiter, address string, n int, at time.Time) (started int) {
	for range n {
		if l.RecordAddressFailure(address, at) {
			started++
		}
	}
	return started
}

func TestAddressBanGroup(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.7":                    "192.0.2.7", // IPv4 by the full address
		"192.0.2.8":                    "192.0.2.8",
		"2001:db8:1:2::1":              "2001:db8:1:2::/64", // IPv6 by /64
		"2001:db8:1:2:ffff:ffff::9":    "2001:db8:1:2::/64",
		"2001:DB8:1:2:0:0:0:5":         "2001:db8:1:2::/64", // spelling does not matter
		"2001:db8:1:3::1":              "2001:db8:1:3::/64", // another /64
		"fe80::1%eth0":                 "fe80::/64",         // the zone is not part of it
		"::ffff:192.0.2.7":             "192.0.2.7",         // an IPv4 address in IPv6 dress
		"not-an-address":               "not-an-address",    // unparsable: itself
		"192.0.2.7:443":                "192.0.2.7:443",
		"[2001:db8::1]:443":            "[2001:db8::1]:443",
		"":                             "",
		"2001:db8:1:2::1/64":           "2001:db8:1:2::1/64",
		"2001:db8:1:2:3:4:5:6:7":       "2001:db8:1:2:3:4:5:6:7",
		"unknown, 192.0.2.7 (a proxy)": "unknown, 192.0.2.7 (a proxy)",
	} {
		if got := AddressBanGroup(in); got != want {
			t.Errorf("AddressBanGroup(%q) = %q, want %q", in, got, want)
		}
	}
}

// The hundredth failure bans, the ninety-ninth does not, and the ban is
// reported started exactly once.
func TestTheHundredthFailureBansTheAddress(t *testing.T) {
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	const addr = "192.0.2.7"
	if n := failN(l, addr, AddressBanFailures-1, banStart); n != 0 {
		t.Fatalf("%d failures started a ban", AddressBanFailures-1)
	}
	if _, banned := l.AddressBanned(addr, banStart); banned {
		t.Fatal("99 failures banned the address")
	}
	if !l.RecordAddressFailure(addr, banStart) {
		t.Fatal("the hundredth failure did not start a ban")
	}
	until, banned := l.AddressBanned(addr, banStart)
	if !banned || !until.Equal(banStart.Add(AddressBanDuration)) {
		t.Fatalf("AddressBanned = %v, %v; want a ban until %v", until, banned, banStart.Add(AddressBanDuration))
	}
	// Further failures change nothing: one ban, flat, not extended.
	if n := failN(l, addr, 50, banStart.Add(time.Hour)); n != 0 {
		t.Errorf("failures during a ban started %d more", n)
	}
	if u, _ := l.AddressBanned(addr, banStart.Add(time.Hour)); !u.Equal(until) {
		t.Errorf("failures during the ban moved its end to %v, want %v", u, until)
	}
	if _, banned := l.AddressBanned("192.0.2.8", banStart); banned {
		t.Error("another address was banned too")
	}
}

// The ban lasts 24 hours from the hundredth failure, then the address is
// free and its count starts again from nothing.
func TestAnAddressBanExpiresAndTheCountRestarts(t *testing.T) {
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	const addr = "192.0.2.7"
	failN(l, addr, AddressBanFailures, banStart)
	end := banStart.Add(AddressBanDuration)
	if _, banned := l.AddressBanned(addr, end.Add(-time.Second)); !banned {
		t.Fatal("the ban ended early")
	}
	if _, banned := l.AddressBanned(addr, end); banned {
		t.Fatal("the ban was still in force 24 hours on")
	}
	if len(l.addresses) != 0 {
		t.Errorf("an ended ban left %d entries behind", len(l.addresses))
	}
	if n := failN(l, addr, AddressBanFailures-1, end); n != 0 {
		t.Fatal("99 failures after the ban started another: the old count was not dropped")
	}
	if !l.RecordAddressFailure(addr, end) {
		t.Error("100 failures after a ban ended did not ban again")
	}
}

// Failures count over a rolling 24 hours: each stops counting 24 hours
// after it, so slow guessing never reaches the ban but a burst across
// the midpoint does.
func TestAddressFailuresCountOverARollingDay(t *testing.T) {
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	const addr = "192.0.2.7"
	failN(l, addr, AddressBanFailures-1, banStart)
	// The 99 have aged out when the next arrives, so it is the first.
	if l.RecordAddressFailure(addr, banStart.Add(AddressBanDuration+time.Second)) {
		t.Error("a failure 24 hours after 99 others banned the address: they should have aged out")
	}
	// But 50 and 50 inside the day do.
	l2 := mustNewLoginLimiter(t, 5, 5*time.Minute)
	failN(l2, addr, 50, banStart)
	if n := failN(l2, addr, 50, banStart.Add(AddressBanDuration-time.Second)); n != 1 {
		t.Errorf("50 failures, then 50 just inside the day, started %d bans, want 1", n)
	}
	// And one failure an hour for ever never does.
	l3 := mustNewLoginLimiter(t, 5, 5*time.Minute)
	for i := range 24 * 10 {
		if l3.RecordAddressFailure(addr, banStart.Add(time.Duration(i)*time.Hour)) {
			t.Fatalf("one failure an hour banned the address at hour %d", i)
		}
	}
	if got := len(l3.addresses[addr].failures); got > 25 {
		t.Errorf("the count holds %d failures, want only those in the last day", got)
	}
}

// IPv6 addresses in one /64 are one address for the ban; another /64, and
// an IPv4 address, are not.
func TestIPv6AddressesInOneSlash64ShareABan(t *testing.T) {
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	started := 0
	for i := range AddressBanFailures {
		if l.RecordAddressFailure(fmt.Sprintf("2001:db8:1:2:%x::%x", i, i), banStart) {
			started++
		}
	}
	if started != 1 {
		t.Fatalf("100 failures from one /64 started %d bans, want 1", started)
	}
	for _, addr := range []string{"2001:db8:1:2::1", "2001:db8:1:2:dead:beef:0:1", "2001:DB8:1:2::ffff"} {
		if _, banned := l.AddressBanned(addr, banStart); !banned {
			t.Errorf("%s, in the banned /64, was not banned", addr)
		}
	}
	for _, addr := range []string{"2001:db8:1:3::1", "2001:db8:2:2::1", "192.0.2.1"} {
		if _, banned := l.AddressBanned(addr, banStart); banned {
			t.Errorf("%s, outside the banned /64, was banned", addr)
		}
	}
}

// An unparsable address is its own group, and no address at all is
// neither counted nor banned.
func TestUnparsableAndEmptyAddresses(t *testing.T) {
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	failN(l, "a-proxy-name", AddressBanFailures, banStart)
	if _, banned := l.AddressBanned("a-proxy-name", banStart); !banned {
		t.Error("an unparsable address was not banned as itself")
	}
	if _, banned := l.AddressBanned("another-name", banStart); banned {
		t.Error("another unparsable address was banned with it")
	}
	if n := failN(l, "", 10*AddressBanFailures, banStart); n != 0 {
		t.Error("the empty address was banned")
	}
	if _, banned := l.AddressBanned("", banStart); banned || len(l.addresses) != 1 {
		t.Errorf("the empty address left state: banned %v, %d entries", banned, len(l.addresses))
	}
}

func withAddressCap(t *testing.T, n int) {
	t.Helper()
	old := maxAddressBanKeys
	maxAddressBanKeys = n
	t.Cleanup(func() { maxAddressBanKeys = old })
}

// A flood of distinct addresses -- one failure each, far more than the
// map holds -- never evicts a live ban: counts go first. The map stays
// bounded.
func TestAFloodOfAddressesDoesNotEvictABan(t *testing.T) {
	withAddressCap(t, 64)
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	const banned = "192.0.2.7"
	failN(l, banned, AddressBanFailures, banStart)
	for i := range 20 * maxAddressBanKeys {
		at := banStart.Add(time.Duration(i) * time.Second)
		l.RecordAddressFailure(fmt.Sprintf("198.51.%d.%d", i/250, i%250), at)
		if i%97 == 0 {
			if _, ok := l.AddressBanned(banned, at); !ok {
				t.Fatalf("the ban was evicted after %d flood addresses", i+1)
			}
		}
		if len(l.addresses) > maxAddressBanKeys {
			t.Fatalf("the map holds %d entries, over its cap of %d", len(l.addresses), maxAddressBanKeys)
		}
	}
	if _, ok := l.AddressBanned(banned, banStart.Add(time.Hour)); !ok {
		t.Error("the ban did not survive the flood")
	}
}

// Expired entries go before anything live: a map full of counts that
// have aged out makes room without shedding a live count or ban.
func TestExpiredAddressEntriesAreDroppedBeforeLiveOnes(t *testing.T) {
	withAddressCap(t, 16)
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	for i := range 15 {
		l.RecordAddressFailure(fmt.Sprintf("198.51.100.%d", i), banStart)
	}
	failN(l, "192.0.2.7", AddressBanFailures, banStart.Add(time.Hour)) // 16th entry: a ban
	later := banStart.Add(AddressBanDuration + 30*time.Minute)         // the 15 counts have aged out, the ban has not
	l.RecordAddressFailure("203.0.113.1", later)
	if len(l.addresses) != 2 {
		t.Errorf("after the sweep the map holds %d entries, want the live ban and the new count", len(l.addresses))
	}
	if _, ok := l.AddressBanned("192.0.2.7", later); !ok {
		t.Error("the sweep dropped a live ban")
	}
}

// Only when bans alone fill the map is one shed, the oldest first: the
// guarantee is the map's, as for the attempts map.
func TestBansAreShedOnlyWhenBansAloneFillTheMap(t *testing.T) {
	withAddressCap(t, 8)
	l := mustNewLoginLimiter(t, 5, 5*time.Minute)
	for i := range 8 {
		failN(l, fmt.Sprintf("198.51.100.%d", i), AddressBanFailures, banStart.Add(time.Duration(i)*time.Minute))
	}
	l.RecordAddressFailure("203.0.113.1", banStart.Add(time.Hour)) // a ninth address
	if len(l.addresses) > maxAddressBanKeys {
		t.Fatalf("the map holds %d entries, over its cap of %d", len(l.addresses), maxAddressBanKeys)
	}
	now := banStart.Add(time.Hour)
	if _, ok := l.AddressBanned("198.51.100.0", now); ok {
		t.Error("the oldest ban was kept while the map was full of bans")
	}
	if _, ok := l.AddressBanned("198.51.100.7", now); !ok {
		t.Error("the newest ban was shed")
	}
}
