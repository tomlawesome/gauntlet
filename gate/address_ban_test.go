package gate

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
)

// The address ban (#70) through the login route: AddressBanFailures
// failed sign-ins from one address ban it for 24 hours, whatever names
// they tried; a known browser passes it. Addresses are from the
// documentation ranges.

// banFixture is escalationFixture with the address under the test's
// control: from(n) is called per request and names the client address.
func banFixture(t *testing.T, from func(n int64) string) (*Gate, *httptest.Server, *escalationClock, *auditRecorder) {
	t.Helper()
	g, ts, clock := escalationFixture(t)
	g.deps.Limiter = mustNewLoginLimiter(t, 5, 5*time.Minute)
	var n atomic.Int64
	g.cfg.ClientIP = func(*http.Request) string { return from(n.Add(1)) }
	audit, _, _ := recordSignIns(g)
	return g, ts, clock, audit
}

// guess is one wrong password at a name no account has, so only the
// address is being tried. The name is new each time, so no per-name
// limit applies.
func guess(t *testing.T, ts *httptest.Server, i int) loginResult {
	t.Helper()
	return tryLogin(t, ts, fmt.Sprintf("nobody-%d", i), "wrong-password-placeholder")
}

// failFromOneAddress makes n wrong guesses in different names from the
// address from() names, moving the clock a window on after each five so
// the per-address limit (5 a window) never refuses one: it is the ban
// being tried, not that limit.
func failFromOneAddress(t *testing.T, ts *httptest.Server, clock *escalationClock, start, n int) {
	t.Helper()
	for i := start; i < start+n; i++ {
		if r := guess(t, ts, i); r.status != http.StatusUnauthorized {
			t.Fatalf("guess %d: status %d, want 401 (%s)", i, r.status, r.body)
		}
		if (i+1)%5 == 0 {
			clock.set(clock.now().Add(6 * time.Minute))
		}
	}
}

func TestAHundredFailuresFromOneAddressBanItForADay(t *testing.T) {
	_, ts, clock, audit := banFixture(t, func(int64) string { return "192.0.2.50" })
	failFromOneAddress(t, ts, clock, 0, gauntlet.AddressBanFailures-1)
	if n := len(auditEntries(audit, "address.banned")); n != 0 {
		t.Fatalf("%d address.banned records after 99 failures", n)
	}
	// The hundredth is answered as any wrong guess is, and starts the ban.
	banned := clock.now()
	if r := guess(t, ts, 1000); r.status != http.StatusUnauthorized {
		t.Fatalf("the hundredth failure: status %d, want 401", r.status)
	}
	records := auditEntries(audit, "address.banned")
	if len(records) != 1 {
		t.Fatalf("%d address.banned records after the hundredth failure, want 1", len(records))
	}
	if r := records[0]; r.Target != "192.0.2.50" || r.Actor != "unknown" ||
		!strings.HasPrefix(r.Detail, "until="+banned.Add(gauntlet.AddressBanDuration).UTC().Format(time.RFC3339)+" after 100 failed sign-ins in 24h0m0s") ||
		!strings.HasSuffix(r.Detail, `from="192.0.2.50"`) {
		t.Errorf("address.banned = %+v", r)
	}

	// From now on every attempt from the address is refused: the same
	// answer the per-address limit gives, even the right password, and
	// no more records.
	want := tryLogin(t, ts, "someone", "wrong-password-placeholder")
	if want.status != http.StatusTooManyRequests {
		t.Fatalf("an attempt from a banned address: status %d, want 429", want.status)
	}
	if r := tryLogin(t, ts, totpBobUsername, totpBobPassword); r != want {
		t.Errorf("the right password from a banned address got %+v, want exactly %+v", r, want)
	}
	for range 20 {
		_ = tryLogin(t, ts, "someone", "wrong-password-placeholder")
	}
	if n := len(auditEntries(audit, "address.banned")); n != 1 {
		t.Errorf("%d address.banned records after refused attempts, want still 1", n)
	}

	// It ends 24 hours after it began, and not before.
	clock.set(banned.Add(gauntlet.AddressBanDuration - time.Second))
	if r := tryLogin(t, ts, totpBobUsername, totpBobPassword); r.status != http.StatusTooManyRequests {
		t.Errorf("a second before the ban ends: status %d, want 429", r.status)
	}
	clock.set(banned.Add(gauntlet.AddressBanDuration))
	if r := tryLogin(t, ts, totpBobUsername, totpBobPassword); r.status != http.StatusOK {
		t.Errorf("when the ban ends: status %d, want 200", r.status)
	}
}

// A different /64 is a different address; the same /64 is not.
func TestTheBanCoversAnIPv6SlashSixtyFour(t *testing.T) {
	var addr atomic.Value
	addr.Store("")
	g, ts, clock, _ := banFixture(t, func(int64) string { return addr.Load().(string) })
	// One /64, a different address every time. Ninety-nine of the
	// failures go straight to the limiter (the first test counts them
	// through the route, and a wrong guess costs a password hash); the
	// hundredth comes through the route.
	for i := range gauntlet.AddressBanFailures - 1 {
		g.deps.Limiter.RecordAddressFailure(fmt.Sprintf("2001:db8:1:2:%x::%x", i, i), clock.now())
	}
	addr.Store("2001:db8:1:2:ffff::1")
	if r := guess(t, ts, 1); r.status != http.StatusUnauthorized {
		t.Fatalf("the hundredth guess: status %d, want 401", r.status)
	}
	addr.Store("2001:db8:1:2:abcd::1")
	if r := tryLogin(t, ts, totpBobUsername, totpBobPassword); r.status != http.StatusTooManyRequests {
		t.Errorf("a new address in the banned /64: status %d, want 429", r.status)
	}
	addr.Store("2001:db8:1:3::1")
	if r := tryLogin(t, ts, totpBobUsername, totpBobPassword); r.status != http.StatusOK {
		t.Errorf("an address in another /64: status %d, want 200", r.status)
	}
}

// A browser the account remembers is not refused by the ban: behind a
// reverse proxy that hides visitor addresses, one attacker's ban is
// everyone's, and the owner must still get in. A browser that is not
// known, or is known to another account, is refused.
func TestAKnownBrowserPassesTheAddressBan(t *testing.T) {
	g, ts, clock, _ := banFixture(t, func(int64) string { return "192.0.2.60" })
	bob := loggedInClient(t, ts, totpBobUsername, totpBobPassword)
	clock.set(clock.now().Add(10 * time.Minute)) // the sign-in's attempt has aged out

	for range gauntlet.AddressBanFailures {
		g.deps.Limiter.RecordAddressFailure("192.0.2.60", clock.now())
	}
	if _, banned := g.deps.Limiter.AddressBanned("192.0.2.60", clock.now()); !banned {
		t.Fatal("test setup: the address was not banned")
	}
	if r := tryLogin(t, ts, totpBobUsername, totpBobPassword); r.status != http.StatusTooManyRequests {
		t.Fatalf("an unknown browser from the banned address: status %d, want 429", r.status)
	}
	if status := signInFrom(t, bob, ts, totpBobUsername, totpBobPassword); status != http.StatusOK {
		t.Errorf("bob's known browser from the banned address: status %d, want 200", status)
	}
	// Bob's token is for bob: it does not carry another account's name
	// past the ban.
	if status := signInFrom(t, bob, ts, "admin", "password-placeholder-1"); status != http.StatusTooManyRequests {
		t.Errorf("bob's browser naming another account: status %d, want 429", status)
	}
	// Nor an unknown name.
	if status := signInFrom(t, bob, ts, "nobody-at-all", "wrong-password-placeholder"); status != http.StatusTooManyRequests {
		t.Errorf("bob's browser naming no account: status %d, want 429", status)
	}
}
