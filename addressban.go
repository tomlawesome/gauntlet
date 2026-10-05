package gauntlet

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/tomlawesome/gauntlet/internal/evict"
)

// The address ban (#70): fail2ban-style source-address ban beside a
// capped account lockout (OWASP Authentication Cheat Sheet; Auth0
// brute-force protection). The account lockout stops guessing at one
// account from anywhere; this stops one source guessing at anything.
// After AddressBanFailures failed sign-in attempts from one address, in
// any names, within AddressBanDuration, the address is refused for
// AddressBanDuration. It is flat, not escalating: the account's lockout
// is the escalating part, and it is capped; this is where the long
// penalty falls, on the attacker rather than on the owner.
//
// Separate from the per-address limit (Reserve on an "ip:" key), which
// keeps its threshold and window as they were: that is a short brake,
// this is the ban a persistent guesser reaches.
//
// Counts and bans live in this limiter's memory only (the capped map's
// rules, below), so a restart clears them. That costs a guesser nothing
// they could cause: a restart is not theirs to order.

const (
	// AddressBanFailures is how many failed sign-in attempts from one
	// address ban it. NIST SP 800-63B-4 §3.2.2 allows 100 consecutive
	// failures per account before disabling; this is gauntlet's own use
	// of that figure, per address: only deliberate guessing reaches it,
	// where the account's limit counts five at a time.
	AddressBanFailures = 100
	// AddressBanDuration is how long a banned address is refused, and
	// the span failures count over: the 100 failures must fall within
	// one 24-hour period, a rolling one -- each failure counts for the
	// 24 hours after it.
	AddressBanDuration = 24 * time.Hour
)

// maxAddressBanKeys bounds the address map the way maxLoginLimiterKeys
// bounds the attempts map: the keys come from untrusted input, so there
// is a ceiling. The same rules apply (evictAddressesLocked): expired
// entries are dropped first, and only if that is not enough are the
// least recently active shed. A live ban is worth more than a count, so
// counts go before bans, and a ban goes only when bans alone fill the
// map -- which takes AddressBanFailures failures from that many
// addresses. A flood of single failures from distinct addresses
// therefore evicts other counts, as it does in the attempts map (best
// effort), but never a ban.
var maxAddressBanKeys = 4096

// addressRecord is one address group's entry in LoginLimiter.addresses:
// either a count (failures, bannedUntil zero) or a ban (bannedUntil set,
// failures empty).
type addressRecord struct {
	// failures are the times of its failed attempts in the last
	// AddressBanDuration, oldest first. At most AddressBanFailures-1:
	// the one that makes AddressBanFailures starts a ban and the slice
	// is dropped with it. A plain list of times is the simplest
	// structure that gives an exact rolling window, and the cap makes
	// it small: 100 times is under 3 KiB, and 4096 addresses at most
	// about 10 MiB.
	failures []time.Time
	// bannedUntil is when the ban ends; zero for none. A ban that has
	// ended is dropped when it is next looked at.
	bannedUntil time.Time
}

// banned reports whether r is a ban still in force at now.
func (r addressRecord) banned(now time.Time) bool { return now.Before(r.bannedUntil) }

// lastActive is when r was last written: the end of its ban less the ban's
// length, or its latest failure.
func (r addressRecord) lastActive() time.Time {
	if !r.bannedUntil.IsZero() {
		return r.bannedUntil.Add(-AddressBanDuration)
	}
	if len(r.failures) == 0 {
		return time.Time{}
	}
	return r.failures[len(r.failures)-1]
}

// AddressBanGroup is the key an address is counted and banned under:
// an IPv4 address as itself, an IPv6 address by its /64 (its network
// prefix, written as 2001:db8:1:2::/64), because one machine or one
// customer holds a whole /64 and varying the low bits would otherwise
// make every attempt a new address. An IPv4-mapped IPv6 address is the
// IPv4 one, and a zone is dropped. What does not parse as an address --
// the string ClientIP returned is the application's, and may be a name
// or carry a port -- is its own group, as typed. The empty string means
// no address was resolved and is never counted or banned (see
// RecordAddressFailure).
func AddressBanGroup(address string) string {
	a, err := netip.ParseAddr(address)
	if err != nil {
		return address
	}
	a = a.WithZone("").Unmap()
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return p.String()
		}
	}
	return a.String()
}

// AddressBanned reports whether address is banned at now, and until
// when. address is the string the application's ClientIP gave; it is
// grouped as AddressBanGroup says. Read-only apart from dropping a ban
// that has ended. Checked before any credential is, and refused as the
// per-address limit refuses (gate's 429): the caller decides whether a
// known browser passes it (gate does: a reverse proxy that hides
// visitor addresses must not lock the owner out).
func (l *LoginLimiter) AddressBanned(address string, now time.Time) (until time.Time, banned bool) {
	key := AddressBanGroup(address)
	if key == "" {
		return time.Time{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, ok := l.addresses[key]
	if !ok {
		return time.Time{}, false
	}
	if rec.banned(now) {
		return rec.bannedUntil, true
	}
	if !rec.bannedUntil.IsZero() {
		delete(l.addresses, key) // the ban has ended; what is left is nothing
	}
	return time.Time{}, false
}

// RecordAddressFailure counts one failed sign-in attempt from address
// -- a wrong password or code, in any name, an unknown name included --
// and reports whether it was the AddressBanFailures'th within
// AddressBanDuration, which bans the address for AddressBanDuration
// from now: true exactly once per ban, so the caller records the ban
// starting once. A failure from an address already banned counts for
// nothing and neither extends the ban nor starts another: a ban is one
// flat 24 hours.
//
// Call it once per failed attempt the limiter admitted (a refusal
// checked no credential), for a success never. The empty address is
// ignored: no address was resolved, and counting it would make every
// such request one address.
//
// The count is the failures themselves, so the 24 hours roll: a
// failure stops counting 24 hours after it. When the ban starts the
// count is dropped, so the first failure after the ban ends is the
// first of a fresh count.
func (l *LoginLimiter) RecordAddressFailure(address string, now time.Time) (banStarted bool) {
	key := AddressBanGroup(address)
	if key == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, exists := l.addresses[key]
	if rec.banned(now) {
		return false
	}
	// Either no entry, a count, or a ban that has ended: start from the
	// failures still inside the window.
	cutoff := now.Add(-AddressBanDuration)
	kept := rec.failures[:0]
	for _, t := range rec.failures {
		if !t.Before(cutoff) {
			kept = append(kept, t)
		}
	}
	if !exists && len(l.addresses) >= maxAddressBanKeys {
		l.evictAddressesLocked(now)
	}
	kept = append(kept, now)
	if len(kept) >= AddressBanFailures {
		l.addresses[key] = addressRecord{bannedUntil: now.Add(AddressBanDuration)}
		return true
	}
	l.addresses[key] = addressRecord{failures: kept}
	return false
}

// evictAddressesLocked makes room once the address map is at
// maxAddressBanKeys, by the rules evictOldestLocked follows for the
// attempts map: every entry that has expired goes first -- a ban that
// has ended, a count whose failures have all aged out -- and only if
// that is not enough, a batch (internal/evict) of the least recently
// active live ones, down to evict.Target. Counts are shed before bans,
// so a flood of addresses cannot lift one; bans are shed, soonest-
// started first, only when they alone are over the target. Shedding a
// live entry is the one case that loses state, so it is logged, once
// per window.
func (l *LoginLimiter) evictAddressesLocked(now time.Time) {
	cutoff := now.Add(-AddressBanDuration)
	for key, rec := range l.addresses {
		if rec.banned(now) {
			continue
		}
		if len(rec.failures) == 0 || rec.failures[len(rec.failures)-1].Before(cutoff) {
			delete(l.addresses, key)
		}
	}
	target := evict.Target(maxAddressBanKeys)
	if len(l.addresses) <= target {
		return
	}
	if l.log != nil && (!l.addressPressureLogged || now.Sub(l.lastAddressPressure) >= l.window) {
		l.log.Warn(fmt.Sprintf("login limiter: %d source addresses are counting failed sign-ins or banned at once; "+
			"evicting the least recently active counts, then bans, to stay under %d",
			len(l.addresses), maxAddressBanKeys))
		l.lastAddressPressure, l.addressPressureLogged = now, true
	}
	counts := make(map[string]addressRecord, len(l.addresses))
	for key, rec := range l.addresses {
		if !rec.banned(now) {
			counts[key] = rec
		}
	}
	room := target - (len(l.addresses) - len(counts)) // what the counts may keep once the bans are seated
	evict.DownTo(counts, max(room, 0), addressRecord.lastActive)
	for key, rec := range l.addresses {
		if rec.banned(now) {
			continue
		}
		if _, kept := counts[key]; !kept {
			delete(l.addresses, key)
		}
	}
	evict.DownTo(l.addresses, target, addressRecord.lastActive)
}
