package gauntlet

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
)

// Unusual sign-ins (#55, docs/design.md). A completed sign-in -- every
// credential passed, no session yet -- is judged against what the
// account remembers of the sign-ins before it: its known browsers
// (#44), the countries it signs in from, and where its latest located
// sign-in came from. Each signal is raised only against something
// remembered (the baseline rule): an account that remembers nothing of
// a kind remembers this sign-in and raises nothing, which covers a new
// account, every account after the upgrade, and the first sign-in after
// a reset code or sign out everywhere. gate decides what a raised
// signal does; this file only judges and remembers.

// SignInSignals is the set of unusual-sign-in signals a sign-in raised.
// A bit set rather than a slice so SessionClient, which carries one,
// stays comparable. Shown, stored and audited by name, always in one
// fixed order: new-browser, new-country, impossible-travel.
type SignInSignals uint8

const (
	// SignalNewBrowser ("new-browser"): the account remembers at least
	// one live browser and the browser signing in carries none of their
	// tokens.
	SignalNewBrowser SignInSignals = 1 << iota
	// SignalNewCountry ("new-country"): the sign-in's country is known,
	// the account remembers at least one country seen within
	// SeenCountryLifetime, and this is not one of them.
	SignalNewCountry
	// SignalImpossibleTravel ("impossible-travel"): the sign-in is
	// located, the account has a LastPlace, and getting from there to
	// here in the time between them is faster than
	// ImpossibleTravelSpeedKmh, after both accuracy radii are allowed
	// for.
	SignalImpossibleTravel
)

// signInSignalNames is the fixed order and spelling of the signals.
var signInSignalNames = [...]struct {
	bit  SignInSignals
	name string
}{
	{SignalNewBrowser, "new-browser"},
	{SignalNewCountry, "new-country"},
	{SignalImpossibleTravel, "impossible-travel"},
}

// Has reports whether s holds every signal in f; false when f is empty.
func (s SignInSignals) Has(f SignInSignals) bool {
	return f != 0 && s&f == f
}

// Names returns the names of the signals s holds, in the fixed order,
// or nil for none. Bits that name no signal are ignored.
func (s SignInSignals) Names() []string {
	var names []string
	for _, n := range signInSignalNames {
		if s&n.bit != 0 {
			names = append(names, n.name)
		}
	}
	return names
}

// String is the names joined by ",", "" for none: the form the audit
// detail and the sign-in history's fold key use.
func (s SignInSignals) String() string {
	return strings.Join(s.Names(), ",")
}

// MarshalJSON writes the names as a JSON array, [] for none.
func (s SignInSignals) MarshalJSON() ([]byte, error) {
	names := s.Names()
	if names == nil {
		names = []string{}
	}
	return json.Marshal(names)
}

// UnmarshalJSON reads a JSON array of names. An unknown name is an
// error, so a document a newer build wrote with a signal this one does
// not know is not quietly read as fewer signals. null leaves s as it
// was, as encoding/json does for other types.
func (s *SignInSignals) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	var names []string
	if err := json.Unmarshal(data, &names); err != nil {
		return err
	}
	var out SignInSignals
	for _, name := range names {
		bit, ok := ParseSignInSignal(name)
		if !ok {
			return fmt.Errorf("gauntlet: unknown sign-in signal %q", name)
		}
		out |= bit
	}
	*s = out
	return nil
}

// ParseSignInSignal returns the signal one name stands for, and whether
// it names one.
func ParseSignInSignal(name string) (SignInSignals, bool) {
	for _, n := range signInSignalNames {
		if n.name == name {
			return n.bit, true
		}
	}
	return 0, false
}

// MaxSeenCountries is how many countries an account remembers at once
// (User.SeenCountries). A fourth evicts the one seen longest ago.
const MaxSeenCountries = 3

// SeenCountryLifetime is how long a country stays remembered after the
// latest completed sign-in from it. An entry this old or older no longer
// counts and is dropped at the next write that remembers a country.
const SeenCountryLifetime = 90 * 24 * time.Hour

// SignInAllowanceLifetime is how long an administrator's allowance of
// an account's next sign-in (#81, Store.AllowNextSignIn) lasts.
const SignInAllowanceLifetime = 10 * time.Minute

// ImpossibleTravelSpeedKmh is the speed past which getting from the
// account's last located sign-in to this one is judged impossible.
const ImpossibleTravelSpeedKmh = 800.0

// earthRadiusKm is the mean radius distanceKm uses.
const earthRadiusKm = 6371.0

// SeenCountry is one country an account signs in from: only the code
// and when it was last seen, so the record is "where this account signs
// in from", not a travel log.
type SeenCountry struct {
	// Code is the ISO 3166-1 alpha-2 code gate.Config.Country answered.
	Code string `json:"code"`
	// LastAt is the latest completed sign-in from it.
	LastAt time.Time `json:"lastAt"`
}

// live reports whether c still counts at now.
func (c SeenCountry) live(now time.Time) bool {
	return now.Sub(c.LastAt) < SeenCountryLifetime
}

// Location is a point and how far around it an address is likely to
// be, as a city-level lookup gives it (geoip's EditionCity). It is what
// impossible travel compares (#55); a sign-in's country is enough for
// everything else.
type Location struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	// RadiusKm is the lookup's accuracy radius: the address is likely
	// within this many kilometres of the point.
	RadiusKm int `json:"radiusKm"`
}

// LastPlace is where an account's latest located sign-in came from: one
// point, not a trail.
type LastPlace struct {
	// Country is the sign-in's country, "" if it was not known.
	Country string `json:"country,omitempty"`
	Location
	// At is when that sign-in completed.
	At time.Time `json:"at"`
}

// SignInJudgement is what JudgeSignIn found.
type SignInJudgement struct {
	Signals SignInSignals
	// PreviousCountry is LastPlace.Country when SignalImpossibleTravel
	// is set, "" otherwise.
	PreviousCountry string
}

// distanceKm is the great-circle (haversine) distance between two
// points, on a sphere of earthRadiusKm.
func distanceKm(a, b Location) float64 {
	rad := func(deg float64) float64 { return deg * math.Pi / 180 }
	dLat := rad(b.Latitude - a.Latitude)
	dLon := rad(b.Longitude - a.Longitude)
	h := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(rad(a.Latitude))*math.Cos(rad(b.Latitude))*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * earthRadiusKm * math.Asin(math.Sqrt(min(1, h)))
}

// impossibleTravel reports whether getting from prev to next by now is
// faster than ImpossibleTravelSpeedKmh. The distance counted is the
// great-circle distance less both accuracy radii, so two lookups that
// may be the same place never raise it. A negative elapsed time -- a
// clock stepped back -- never raises it; no time at all with any net
// distance does.
func impossibleTravel(prev LastPlace, next Location, now time.Time) bool {
	elapsed := now.Sub(prev.At)
	if elapsed < 0 {
		return false
	}
	net := distanceKm(prev.Location, next) - float64(prev.RadiusKm) - float64(next.RadiusKm)
	if net <= 0 {
		return false
	}
	if elapsed == 0 {
		return true
	}
	return net/elapsed.Hours() > ImpossibleTravelSpeedKmh
}

// JudgeSignIn judges a completed sign-in on accountID against what the
// account remembers, by the baseline rule above. tokens are the
// known-browser tokens the browser carries (nil for none); country is
// "" when unknown; loc is nil when unknown. Read-only: it never writes,
// and an unknown account raises nothing. Each carried token is compared
// in constant time against every remembered browser, as KnowsBrowser
// does.
func (s *Store) JudgeSignIn(accountID string, tokens []string, country string, loc *Location, now time.Time) SignInJudgement {
	var hashes [][]byte
	for _, t := range tokens {
		if wellFormedKnownBrowserToken(t) {
			hashes = append(hashes, []byte(knownBrowserHash(t)))
		}
	}

	s.reloadIfStale()
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[accountID]
	if !ok {
		return SignInJudgement{}
	}
	var j SignInJudgement

	remembersBrowser, carriesOne := false, false
	for _, b := range u.KnownBrowsers {
		if !b.live(now) {
			continue
		}
		remembersBrowser = true
		for _, h := range hashes {
			if subtle.ConstantTimeCompare([]byte(b.Hash), h) == 1 {
				carriesOne = true
			}
		}
	}
	if remembersBrowser && !carriesOne {
		j.Signals |= SignalNewBrowser
	}

	if country != "" {
		remembersCountry, seen := false, false
		for _, c := range u.SeenCountries {
			if !c.live(now) {
				continue
			}
			remembersCountry = true
			if c.Code == country {
				seen = true
			}
		}
		if remembersCountry && !seen {
			j.Signals |= SignalNewCountry
		}
	}

	if loc != nil && u.LastPlace != nil && impossibleTravel(*u.LastPlace, *loc, now) {
		j.Signals |= SignalImpossibleTravel
		j.PreviousCountry = u.LastPlace.Country
	}
	return j
}

// RememberSignIn remembers a completed sign-in on accountID in one
// write, and returns the browser's fresh known-browser token:
//
//   - the browser, as RememberBrowser describes (replacing is the token
//     it carried for this account, "" for none);
//   - with a non-empty country: entries SeenCountryLifetime old or older
//     are dropped, a country already remembered has its LastAt moved to
//     now, a new one is added, and past MaxSeenCountries the one seen
//     longest ago goes. A blank country changes nothing;
//   - with a location: LastPlace becomes {country, loc, now}. Without
//     one it is left as it was, so a later located sign-in is compared
//     against the last located one, and the longer gap only lowers the
//     speed.
//
// The same write spends an administrator's allowance of the account's
// next sign-in (#81, User.SignInAllowedUntil), whatever browser the
// sign-in came from and whether or not the policy would have stopped it.
//
// Called at every session issue, whatever gate's policy, so turning a
// signal on later starts from a baseline. A failed write is the
// caller's to log. Refused with ErrUserNotFound for an account that
// does not exist.
func (s *Store) RememberSignIn(accountID, replacing, country string, loc *Location, now time.Time) (string, error) {
	token := newKnownBrowserToken()
	entry := KnownBrowser{Hash: knownBrowserHash(token), IssuedAt: now}
	var replaced string
	if replacing != "" {
		replaced = knownBrowserHash(replacing)
	}

	s.reloadIfStale()
	err := s.mutate(func(st *storeState) error {
		u, ok := st.byID[accountID]
		if !ok {
			return ErrUserNotFound
		}
		kept := make([]KnownBrowser, 0, len(u.KnownBrowsers)+1)
		fresh := entry
		for _, b := range u.KnownBrowsers {
			if !b.live(now) {
				continue
			}
			if b.Hash == replaced {
				// The browser brought its token back: it is one the
				// account really uses, not a passing sign-in.
				fresh.Confirmed = true
				continue
			}
			kept = append(kept, b)
		}
		if len(kept)+1 > MaxKnownBrowsers {
			// Unconfirmed entries go first, oldest first, then confirmed
			// ones, so a run of sign-ins that never bring their cookie
			// back cannot push out the browsers the owner uses every
			// day. The new entry is never the one evicted: it must be on
			// the record for its cookie to come back at all.
			slices.SortStableFunc(kept, func(a, b KnownBrowser) int {
				if a.Confirmed != b.Confirmed {
					if a.Confirmed {
						return 1
					}
					return -1
				}
				return a.IssuedAt.Compare(b.IssuedAt)
			})
			kept = kept[len(kept)+1-MaxKnownBrowsers:]
		}
		u.KnownBrowsers = append(kept, fresh)

		if country != "" {
			u.SeenCountries = rememberCountry(u.SeenCountries, country, now)
		}
		if loc != nil {
			u.LastPlace = &LastPlace{Country: country, Location: *loc, At: now}
		}
		// The next completed sign-in is the one an allowance was for.
		u.SignInAllowedUntil = time.Time{}
		return nil
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// AllowNextSignIn records an administrator's allowance of accountID's
// next sign-in (#81): User.SignInAllowedUntil becomes now plus
// SignInAllowanceLifetime, replacing any earlier window. Until then a
// sign-in gate's unusual-sign-in policy would hold or refuse completes
// instead. It changes nothing else: no credential, session, lockout or
// disable. The copy returned has its credentials blanked, as
// IssueResetCode's has. Refused with ErrNotPersisted when the store has
// no backend -- an allowance reported as made must survive a restart,
// as a reset code must -- and with ErrUserNotFound for an account that
// does not exist.
func (s *Store) AllowNextSignIn(accountID string, now time.Time) (*User, error) {
	if !s.Persisted() {
		return nil, ErrNotPersisted
	}
	s.reloadIfStale()
	var allowed User
	err := s.mutate(func(st *storeState) error {
		u, ok := st.byID[accountID]
		if !ok {
			return ErrUserNotFound
		}
		u.SignInAllowedUntil = now.Add(SignInAllowanceLifetime)
		allowed = *u
		return nil
	})
	if err != nil {
		return nil, err
	}
	allowed.blankCredentials()
	return &allowed, nil
}

// rememberCountry is RememberSignIn's rule for the countries.
func rememberCountry(seen []SeenCountry, country string, now time.Time) []SeenCountry {
	kept := make([]SeenCountry, 0, len(seen)+1)
	found := false
	for _, c := range seen {
		if !c.live(now) {
			continue
		}
		if c.Code == country {
			c.LastAt, found = now, true
		}
		kept = append(kept, c)
	}
	if !found {
		kept = append(kept, SeenCountry{Code: country, LastAt: now})
	}
	if len(kept) > MaxSeenCountries {
		slices.SortStableFunc(kept, func(a, b SeenCountry) int { return a.LastAt.Compare(b.LastAt) })
		kept = kept[len(kept)-MaxSeenCountries:]
	}
	return kept
}
