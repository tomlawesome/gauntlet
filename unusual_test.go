package gauntlet

import (
	"encoding/json"
	"errors"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// Unusual sign-ins (#55): the signals, what an account remembers, and
// the judgement over them.

func TestSignInSignalsNamesAndOrder(t *testing.T) {
	all := SignalImpossibleTravel | SignalNewBrowser | SignalNewCountry
	if got := all.Names(); !slices.Equal(got, []string{"new-browser", "new-country", "impossible-travel"}) {
		t.Errorf("Names() = %q, want the fixed order", got)
	}
	if got := all.String(); got != "new-browser,new-country,impossible-travel" {
		t.Errorf("String() = %q", got)
	}
	var none SignInSignals
	if none.Names() != nil || none.String() != "" {
		t.Errorf("no signals: Names %q, String %q, want nil and empty", none.Names(), none.String())
	}
	if got := (SignalNewCountry | SignalImpossibleTravel).String(); got != "new-country,impossible-travel" {
		t.Errorf("String() = %q", got)
	}
	if !all.Has(SignalNewCountry) || SignalNewBrowser.Has(SignalNewCountry) || none.Has(SignalNewBrowser) {
		t.Error("Has answers wrongly")
	}
	if !all.Has(SignalNewBrowser|SignalNewCountry) || SignalNewBrowser.Has(SignalNewBrowser|SignalNewCountry) {
		t.Error("Has of several bits wants all of them")
	}
	if none.Has(0) {
		t.Error("Has(0) is true")
	}
	for _, name := range []string{"new-browser", "new-country", "impossible-travel"} {
		bit, ok := ParseSignInSignal(name)
		if !ok || bit.String() != name {
			t.Errorf("ParseSignInSignal(%q) = %v %v", name, bit, ok)
		}
	}
	for _, name := range []string{"", "New-Browser", "new_browser", "new-browser,new-country"} {
		if _, ok := ParseSignInSignal(name); ok {
			t.Errorf("ParseSignInSignal(%q) accepted", name)
		}
	}
}

func TestSignInSignalsJSON(t *testing.T) {
	for _, c := range []struct {
		s    SignInSignals
		json string
	}{
		{0, `[]`},
		{SignalNewCountry, `["new-country"]`},
		{SignalImpossibleTravel | SignalNewBrowser, `["new-browser","impossible-travel"]`},
	} {
		got, err := json.Marshal(c.s)
		if err != nil || string(got) != c.json {
			t.Errorf("Marshal(%v) = %s %v, want %s", c.s, got, err, c.json)
		}
		var back SignInSignals
		if err := json.Unmarshal(got, &back); err != nil || back != c.s {
			t.Errorf("Unmarshal(%s) = %v %v, want %v", got, back, err, c.s)
		}
	}
	var s SignInSignals
	if err := json.Unmarshal([]byte(`["new-browser","teleport"]`), &s); err == nil {
		t.Error("an unknown name was accepted")
	}
	if err := json.Unmarshal([]byte(`"new-browser"`), &s); err == nil {
		t.Error("a bare string was accepted")
	}
	s = SignalNewBrowser
	if err := json.Unmarshal([]byte(`null`), &s); err != nil || s != SignalNewBrowser {
		t.Errorf("null = %v %v, want left as it was", s, err)
	}
	// In a struct, as the history row and session carry it.
	type row struct {
		Unusual SignInSignals `json:"unusual,omitzero"`
	}
	if b, _ := json.Marshal(row{}); string(b) != `{}` {
		t.Errorf("an empty set in a row = %s, want omitted", b)
	}
	if b, _ := json.Marshal(row{SignalNewCountry}); string(b) != `{"unusual":["new-country"]}` {
		t.Errorf("a set in a row = %s", b)
	}
}

// pointAt is a location east of (0,0) along the equator, km away.
func pointAt(km float64, radius int) Location {
	return Location{Latitude: 0, Longitude: km / (math.Pi * earthRadiusKm / 180), RadiusKm: radius}
}

func TestDistanceKm(t *testing.T) {
	london := Location{Latitude: 51.5074, Longitude: -0.1278}
	paris := Location{Latitude: 48.8566, Longitude: 2.3522}
	if d := distanceKm(london, paris); d < 340 || d > 347 {
		t.Errorf("London to Paris = %.1f km, want about 343.5", d)
	}
	if d := distanceKm(london, london); d != 0 {
		t.Errorf("a point to itself = %v", d)
	}
	if d := distanceKm(Location{}, pointAt(1000, 0)); math.Abs(d-1000) > 0.01 {
		t.Errorf("pointAt(1000) is %.3f km away", d)
	}
	antipode := distanceKm(Location{Latitude: 0, Longitude: 0}, Location{Latitude: 0, Longitude: 180})
	if math.Abs(antipode-math.Pi*earthRadiusKm) > 0.01 {
		t.Errorf("antipodes = %.1f km", antipode)
	}
}

func TestImpossibleTravel(t *testing.T) {
	at := escalationStart
	prev := LastPlace{Country: "GB", Location: pointAt(0, 0), At: at}
	for _, c := range []struct {
		name string
		next Location
		now  time.Time
		want bool
	}{
		{"1,000 km in an hour", pointAt(1000, 0), at.Add(time.Hour), true},
		{"600 km in an hour", pointAt(600, 0), at.Add(time.Hour), false},
		{"1,000 km apart, radius 300 km: 700 km net in an hour", pointAt(1000, 300), at.Add(time.Hour), false},
		{"1,200 km apart, radius 100 km: 1,100 km net in an hour", pointAt(1200, 100), at.Add(time.Hour), true},
		{"overlapping radii, no time at all", pointAt(100, 100), at, false},
		{"radii exactly touching, no time at all", pointAt(200, 200), at, false},
		{"zero elapsed with distance", pointAt(5, 0), at, true},
		{"a clock stepped back", pointAt(10000, 0), at.Add(-time.Minute), false},
		{"2,000 km in ten minutes", pointAt(2000, 20), at.Add(10 * time.Minute), true},
		{"2,000 km in three hours", pointAt(2000, 20), at.Add(3 * time.Hour), false},
	} {
		if got := impossibleTravel(prev, c.next, c.now); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	// The previous place's radius counts too.
	wide := prev
	wide.RadiusKm = 500
	if impossibleTravel(wide, pointAt(1000, 0), at.Add(time.Hour)) {
		t.Error("the previous radius was not subtracted")
	}
}

// openJudgeStore is a store with alice and a counting backend.
func openJudgeStore(t *testing.T) (*Store, string, *countingBackend) {
	t.Helper()
	b := &countingBackend{Memory: persist.NewMemory()}
	s, id := openLockoutStore(t, b)
	return s, id, b
}

func mustRememberSignIn(t *testing.T, s *Store, id, replacing, country string, loc *Location, at time.Time) string {
	t.Helper()
	token, err := s.RememberSignIn(id, replacing, country, loc, at)
	if err != nil {
		t.Fatalf("RememberSignIn: %v", err)
	}
	return token
}

func TestJudgeSignInBaseline(t *testing.T) {
	s, id, b := openJudgeStore(t)
	at := escalationStart
	before := b.saves.Load()
	// Nothing remembered: nothing is new, wherever it comes from.
	j := s.JudgeSignIn(id, []string{newKnownBrowserToken()}, "FR", &Location{Latitude: 10, Longitude: 10}, at)
	if j.Signals != 0 || j.PreviousCountry != "" {
		t.Errorf("judgement with nothing remembered = %+v, want nothing raised", j)
	}
	if got := s.JudgeSignIn("no-such-id", nil, "FR", nil, at); got.Signals != 0 {
		t.Errorf("an unknown account = %+v", got)
	}
	if b.saves.Load() != before {
		t.Error("JudgeSignIn wrote")
	}
}

func TestJudgeSignInNewBrowser(t *testing.T) {
	s, id, b := openJudgeStore(t)
	at := escalationStart
	other, err := s.CreateUser("bob", "password-placeholder-2", RoleUser, at)
	if err != nil {
		t.Fatal(err)
	}
	expired := mustRememberSignIn(t, s, id, "", "", nil, at.Add(-KnownBrowserLifetime))
	token := mustRememberSignIn(t, s, id, "", "", nil, at)
	bobToken := mustRememberSignIn(t, s, other.ID, "", "", nil, at)
	now := at.Add(time.Hour)
	before := b.saves.Load()
	for _, c := range []struct {
		name   string
		tokens []string
		want   bool
	}{
		{"the live token", []string{token}, false},
		{"the live token among others", []string{newKnownBrowserToken(), bobToken, token}, false},
		{"no cookie", nil, true},
		{"a forged token", []string{newKnownBrowserToken()}, true},
		{"an expired token", []string{expired}, true},
		{"another account's token", []string{bobToken}, true},
		{"junk", []string{"not-a-token"}, true},
	} {
		j := s.JudgeSignIn(id, c.tokens, "", nil, now)
		if j.Signals.Has(SignalNewBrowser) != c.want || j.Signals&^SignalNewBrowser != 0 {
			t.Errorf("%s: signals %v, want new-browser %v alone", c.name, j.Signals, c.want)
		}
	}
	if b.saves.Load() != before {
		t.Error("JudgeSignIn wrote")
	}
	// Every remembered browser expired: nothing to compare with.
	if j := s.JudgeSignIn(id, nil, "", nil, at.Add(KnownBrowserLifetime+time.Hour)); j.Signals != 0 {
		t.Errorf("with every browser expired = %v, want nothing", j.Signals)
	}
}

func TestJudgeSignInNewCountry(t *testing.T) {
	s, id, _ := openJudgeStore(t)
	at := escalationStart
	token := mustRememberSignIn(t, s, id, "", "GB", nil, at)
	now := at.Add(time.Hour)
	for _, c := range []struct {
		country string
		want    bool
	}{
		{"GB", false},
		{"FR", true},
		{"", false},
	} {
		j := s.JudgeSignIn(id, []string{token}, c.country, nil, now)
		if j.Signals.Has(SignalNewCountry) != c.want || j.Signals&^SignalNewCountry != 0 {
			t.Errorf("country %q: %v, want new-country %v alone", c.country, j.Signals, c.want)
		}
	}
	// GB seen exactly 90 days ago has expired: with nothing else
	// remembered, nothing is new; beside a live FR it is.
	later := at.Add(SeenCountryLifetime)
	if j := s.JudgeSignIn(id, nil, "DE", nil, later); j.Signals.Has(SignalNewCountry) {
		t.Error("an account whose only country expired raised new-country")
	}
	mustRememberSignIn(t, s, id, token, "FR", nil, at.Add(time.Hour))
	if j := s.JudgeSignIn(id, nil, "GB", nil, later); !j.Signals.Has(SignalNewCountry) {
		t.Error("a country seen 90 days ago is not new beside a live one")
	}
}

func TestJudgeSignInImpossibleTravel(t *testing.T) {
	s, id, _ := openJudgeStore(t)
	at := escalationStart
	// Remembered without a location: no last place, never raised.
	token := mustRememberSignIn(t, s, id, "", "GB", nil, at)
	far := pointAt(2000, 20)
	if j := s.JudgeSignIn(id, []string{token}, "GB", &far, at.Add(10*time.Minute)); j.Signals != 0 || j.PreviousCountry != "" {
		t.Errorf("no last place: %+v", j)
	}
	home := pointAt(0, 10)
	token = mustRememberSignIn(t, s, id, token, "GB", &home, at)
	j := s.JudgeSignIn(id, []string{token}, "GB", &far, at.Add(10*time.Minute))
	if j.Signals != SignalImpossibleTravel || j.PreviousCountry != "GB" {
		t.Errorf("2,000 km in ten minutes = %+v, want impossible-travel with GB", j)
	}
	if j := s.JudgeSignIn(id, []string{token}, "GB", &far, at.Add(5*time.Hour)); j.Signals != 0 || j.PreviousCountry != "" {
		t.Errorf("2,000 km in five hours = %+v, want nothing and no previous country", j)
	}
	if j := s.JudgeSignIn(id, []string{token}, "GB", nil, at.Add(10*time.Minute)); j.Signals != 0 {
		t.Errorf("no location now = %v", j.Signals)
	}
}

func TestRememberSignIn(t *testing.T) {
	s, id, b := openJudgeStore(t)
	at := escalationStart
	before := b.saves.Load()
	loc := Location{Latitude: 1, Longitude: 2, RadiusKm: 3}
	token := mustRememberSignIn(t, s, id, "", "GB", &loc, at)
	if b.saves.Load() != before+1 {
		t.Errorf("RememberSignIn made %d writes, want 1", b.saves.Load()-before)
	}
	u := mustGet(t, s, id)
	if len(u.KnownBrowsers) != 1 || !s.KnowsBrowser(id, token, at) {
		t.Error("the browser was not remembered")
	}
	if !slices.Equal(u.SeenCountries, []SeenCountry{{Code: "GB", LastAt: at}}) {
		t.Errorf("SeenCountries = %+v", u.SeenCountries)
	}
	if u.LastPlace == nil || *u.LastPlace != (LastPlace{Country: "GB", Location: loc, At: at}) {
		t.Errorf("LastPlace = %+v", u.LastPlace)
	}

	// A known country only moves; no location keeps the last place.
	token = mustRememberSignIn(t, s, id, token, "GB", nil, at.Add(time.Hour))
	u = mustGet(t, s, id)
	if !slices.Equal(u.SeenCountries, []SeenCountry{{Code: "GB", LastAt: at.Add(time.Hour)}}) {
		t.Errorf("a known country = %+v, want its LastAt moved", u.SeenCountries)
	}
	if u.LastPlace == nil || !u.LastPlace.At.Equal(at) {
		t.Errorf("a sign-in without a location changed LastPlace: %+v", u.LastPlace)
	}

	// The fourth evicts the oldest.
	for i, c := range []string{"FR", "DE", "ES"} {
		token = mustRememberSignIn(t, s, id, token, c, nil, at.Add(time.Duration(2+i)*time.Hour))
	}
	u = mustGet(t, s, id)
	var codes []string
	for _, c := range u.SeenCountries {
		codes = append(codes, c.Code)
	}
	if !slices.Equal(codes, []string{"FR", "DE", "ES"}) {
		t.Errorf("after four countries = %q, want GB evicted", codes)
	}

	// A blank country changes nothing about the countries.
	token = mustRememberSignIn(t, s, id, token, "", nil, at.Add(SeenCountryLifetime+10*time.Hour))
	if got := mustGet(t, s, id).SeenCountries; len(got) != 3 {
		t.Errorf("a blank country changed the countries: %+v", got)
	}

	// A 90-day-old entry is dropped at the next write with a country.
	late := at.Add(2*time.Hour + SeenCountryLifetime)
	newLoc := Location{Latitude: 5, Longitude: 6, RadiusKm: 7}
	mustRememberSignIn(t, s, id, token, "IT", &newLoc, late)
	u = mustGet(t, s, id)
	codes = codes[:0]
	for _, c := range u.SeenCountries {
		codes = append(codes, c.Code)
	}
	if !slices.Equal(codes, []string{"DE", "ES", "IT"}) {
		t.Errorf("after FR aged 90 days = %q, want FR dropped and IT added", codes)
	}
	if u.LastPlace == nil || *u.LastPlace != (LastPlace{Country: "IT", Location: newLoc, At: late}) {
		t.Errorf("LastPlace = %+v, want replaced", u.LastPlace)
	}

	if _, err := s.RememberSignIn("no-such-id", "", "GB", nil, at); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("an unknown account: %v", err)
	}
	// RememberBrowser leaves countries and place alone.
	before = b.saves.Load()
	mustRemember(t, s, id, "", late.Add(time.Hour))
	if b.saves.Load() != before+1 {
		t.Error("RememberBrowser made more than one write")
	}
	if got := mustGet(t, s, id); len(got.SeenCountries) != 3 || got.LastPlace == nil || !got.LastPlace.At.Equal(late) {
		t.Errorf("RememberBrowser changed what the account remembers: %+v %+v", got.SeenCountries, got.LastPlace)
	}
}

func TestClearsForgetCountriesAndPlace(t *testing.T) {
	s, id, b := openJudgeStore(t)
	at := escalationStart
	loc := Location{Latitude: 1, Longitude: 2, RadiusKm: 3}
	mustRememberSignIn(t, s, id, "", "GB", &loc, at)
	if err := s.ClearKnownBrowsers(id); err != nil {
		t.Fatal(err)
	}
	if u := mustGet(t, s, id); u.KnownBrowsers != nil || u.SeenCountries != nil || u.LastPlace != nil {
		t.Errorf("ClearKnownBrowsers left %+v %+v %+v", u.KnownBrowsers, u.SeenCountries, u.LastPlace)
	}
	before := b.saves.Load()
	if err := s.ClearKnownBrowsers(id); err != nil || b.saves.Load() != before {
		t.Errorf("clearing nothing: %v, %d writes", err, b.saves.Load()-before)
	}
	// A country alone, with no browser, is still something to clear.
	if _, err := s.RememberSignIn(id, "", "GB", nil, at); err != nil {
		t.Fatal(err)
	}
	if err := s.mutate(func(st *storeState) error { st.byID[id].KnownBrowsers = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	before = b.saves.Load()
	if err := s.ClearKnownBrowsers(id); err != nil || b.saves.Load() != before+1 || mustGet(t, s, id).SeenCountries != nil {
		t.Error("ClearKnownBrowsers did not clear a country remembered without a browser")
	}

	mustRememberSignIn(t, s, id, "", "GB", &loc, at)
	if _, _, err := s.IssueResetCode(id, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if u := mustGet(t, s, id); u.KnownBrowsers != nil || u.SeenCountries != nil || u.LastPlace != nil {
		t.Errorf("IssueResetCode left %+v %+v %+v", u.KnownBrowsers, u.SeenCountries, u.LastPlace)
	}
}

func TestDeleteUserLeavesNothingRemembered(t *testing.T) {
	s, _, _ := openJudgeStore(t)
	at := escalationStart
	bob, err := s.CreateUser("bob", "password-placeholder-2", RoleUser, at)
	if err != nil {
		t.Fatal(err)
	}
	loc := Location{Latitude: 1, Longitude: 2, RadiusKm: 3}
	mustRememberSignIn(t, s, bob.ID, "", "GB", &loc, at)
	if _, err := s.DeleteUser(bob.ID); err != nil {
		t.Fatal(err)
	}
	if j := s.JudgeSignIn(bob.ID, nil, "FR", &loc, at.Add(time.Minute)); j.Signals != 0 {
		t.Errorf("a deleted account judged %v", j.Signals)
	}
	if _, ok := s.Get(bob.ID); ok {
		t.Error("the record survived")
	}
}

// clone, what mutate changes and may throw away, shares neither the
// countries nor the place with the record.
func TestCloneCopiesCountriesAndPlace(t *testing.T) {
	u := &User{
		SeenCountries: []SeenCountry{{Code: "GB", LastAt: escalationStart}},
		LastPlace:     &LastPlace{Country: "GB", At: escalationStart},
	}
	cp := u.clone()
	cp.SeenCountries[0].Code = "XX"
	cp.LastPlace.Country = "XX"
	if u.SeenCountries[0].Code != "GB" || u.LastPlace.Country != "GB" {
		t.Error("changing a clone changed the original")
	}
}

func TestSessionClientCarriesUnusual(t *testing.T) {
	ss := NewSessionStore(MaxSessionIdle, MaxSessionLifetime)
	sess := ss.CreateFrom("u1", SessionClient{Address: "192.0.2.1", Country: "GB", Unusual: SignalNewCountry}, escalationStart)
	if sess.Client.Unusual != SignalNewCountry {
		t.Errorf("CreateFrom dropped the signals: %+v", sess.Client)
	}
	// Still comparable: a slice field would make this not compile.
	if sess.Client != (SessionClient{Address: "192.0.2.1", Country: "GB", Unusual: SignalNewCountry}) {
		t.Errorf("Client = %+v", sess.Client)
	}
}
