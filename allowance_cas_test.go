package gauntlet

import (
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// #103 R1: a one-time allowance is spent at most once. The store judges
// an allowance live from what it holds, then spends it in a later write;
// RememberAllowedSignIn makes the spend conditional, in the one locked
// write that remembers the sign-in, so a sign-in whose allowance is
// already spent (here or in another process) completes nothing.

var allowanceHere = &Location{Latitude: 51.5074, Longitude: -0.1278, RadiusKm: 20}

// remembered is what an account remembers about its sign-ins.
type remembered struct {
	browsers  []KnownBrowser
	countries []SeenCountry
	place     *LastPlace
}

func rememberedBy(t *testing.T, s *Store, id string) remembered {
	t.Helper()
	u := mustGet(t, s, id)
	r := remembered{browsers: slices.Clone(u.KnownBrowsers), countries: slices.Clone(u.SeenCountries)}
	if u.LastPlace != nil {
		p := *u.LastPlace
		r.place = &p
	}
	return r
}

func requireNothingWritten(t *testing.T, s *Store, id string, before remembered) {
	t.Helper()
	after := rememberedBy(t, s, id)
	if !reflect.DeepEqual(before.browsers, after.browsers) {
		t.Errorf("known browsers changed: %+v -> %+v", before.browsers, after.browsers)
	}
	if !reflect.DeepEqual(before.countries, after.countries) {
		t.Errorf("seen countries changed: %+v -> %+v", before.countries, after.countries)
	}
	if !reflect.DeepEqual(before.place, after.place) {
		t.Errorf("last place changed: %+v -> %+v", before.place, after.place)
	}
}

func requireNotAllowed(t *testing.T, token string, err error) {
	t.Helper()
	if !errors.Is(err, ErrSignInNotAllowed) {
		t.Errorf("RememberAllowedSignIn error = %v, want ErrSignInNotAllowed", err)
	}
	if token != "" {
		t.Errorf("RememberAllowedSignIn token = %q, want none", token)
	}
}

// A live allowance: the sign-in is remembered exactly as RememberSignIn
// would, and the allowance is spent in the same write.
func TestRememberAllowedSignInSpendsALiveAllowance(t *testing.T) {
	at := escalationStart
	now := at.Add(time.Minute)

	s, id, _ := openJudgeStore(t)
	if _, err := s.AllowNextSignIn(id, at); err != nil {
		t.Fatal(err)
	}
	token, err := s.RememberAllowedSignIn(id, "", "GB", allowanceHere, now)
	if err != nil {
		t.Fatalf("RememberAllowedSignIn: %v", err)
	}
	if token == "" {
		t.Fatal("RememberAllowedSignIn returned no browser token")
	}
	got := mustGet(t, s, id)
	if !got.SignInAllowedUntil.IsZero() {
		t.Errorf("after the allowed sign-in the window ends %v, want none", got.SignInAllowedUntil)
	}

	// The same sign-in remembered by RememberSignIn on another account.
	ref, refID, _ := openJudgeStore(t)
	refToken := mustRememberSignIn(t, ref, refID, "", "GB", allowanceHere, now)
	want := mustGet(t, ref, refID)

	if len(got.KnownBrowsers) != len(want.KnownBrowsers) || len(got.KnownBrowsers) != 1 {
		t.Fatalf("known browsers = %+v, want one like RememberSignIn's %+v", got.KnownBrowsers, want.KnownBrowsers)
	}
	if got.KnownBrowsers[0].Hash != knownBrowserHash(token) {
		t.Errorf("the remembered browser is not the returned token's")
	}
	if !got.KnownBrowsers[0].IssuedAt.Equal(want.KnownBrowsers[0].IssuedAt) ||
		got.KnownBrowsers[0].Confirmed != want.KnownBrowsers[0].Confirmed {
		t.Errorf("known browser = %+v, RememberSignIn wrote %+v", got.KnownBrowsers[0], want.KnownBrowsers[0])
	}
	if want.KnownBrowsers[0].Hash != knownBrowserHash(refToken) {
		t.Fatal("control: RememberSignIn's token does not match its stored hash")
	}
	if !s.KnowsBrowser(id, token, now) {
		t.Error("the account does not know the browser it just let in")
	}
	if !reflect.DeepEqual(got.SeenCountries, want.SeenCountries) {
		t.Errorf("seen countries = %+v, RememberSignIn wrote %+v", got.SeenCountries, want.SeenCountries)
	}
	if !reflect.DeepEqual(got.LastPlace, want.LastPlace) {
		t.Errorf("last place = %+v, RememberSignIn wrote %+v", got.LastPlace, want.LastPlace)
	}
}

// Without a live allowance nothing is written and the sign-in is not
// allowed: never made, already spent, or expired.
func TestRememberAllowedSignInWithoutALiveAllowance(t *testing.T) {
	at := escalationStart
	cases := []struct {
		name  string
		setup func(t *testing.T, s *Store, id string)
		now   time.Time
	}{
		{"never made", func(*testing.T, *Store, string) {}, at.Add(time.Minute)},
		{"already spent by a first allowed sign-in", func(t *testing.T, s *Store, id string) {
			if _, err := s.AllowNextSignIn(id, at); err != nil {
				t.Fatal(err)
			}
			if _, err := s.RememberAllowedSignIn(id, "", "GB", allowanceHere, at.Add(time.Minute)); err != nil {
				t.Fatalf("the first allowed sign-in: %v", err)
			}
		}, at.Add(2 * time.Minute)},
		{"already spent by an ordinary sign-in", func(t *testing.T, s *Store, id string) {
			if _, err := s.AllowNextSignIn(id, at); err != nil {
				t.Fatal(err)
			}
			mustRememberSignIn(t, s, id, "", "GB", allowanceHere, at.Add(time.Minute))
		}, at.Add(2 * time.Minute)},
		{"expired", func(t *testing.T, s *Store, id string) {
			if _, err := s.AllowNextSignIn(id, at); err != nil {
				t.Fatal(err)
			}
		}, at.Add(SignInAllowanceLifetime + time.Second)},
		{"expired this instant", func(t *testing.T, s *Store, id string) {
			if _, err := s.AllowNextSignIn(id, at); err != nil {
				t.Fatal(err)
			}
		}, at.Add(SignInAllowanceLifetime)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, id, b := openJudgeStore(t)
			// Something already remembered, so a stray write shows.
			mustRememberSignIn(t, s, id, "", "GB", allowanceHere, at.Add(-time.Hour))
			c.setup(t, s, id)
			before := rememberedBy(t, s, id)
			saves := b.saves.Load()

			token, err := s.RememberAllowedSignIn(id, "", "FR", &Location{Latitude: 48.8566, Longitude: 2.3522, RadiusKm: 20}, c.now)
			requireNotAllowed(t, token, err)
			requireNothingWritten(t, s, id, before)
			if n := b.saves.Load() - saves; n != 0 {
				t.Errorf("a refused RememberAllowedSignIn made %d writes, want none", n)
			}
		})
	}
}

func TestRememberAllowedSignInUnknownAccount(t *testing.T) {
	s, _, _ := openJudgeStore(t)
	token, err := s.RememberAllowedSignIn("no-such-id", "", "GB", allowanceHere, escalationStart)
	if !errors.Is(err, ErrUserNotFound) {
		t.Errorf("unknown account: %v, want ErrUserNotFound", err)
	}
	if token != "" {
		t.Errorf("unknown account token = %q, want none", token)
	}
}

// Many sign-ins race on one live allowance: exactly one spends it.
func TestRememberAllowedSignInSpendsAtMostOnceConcurrently(t *testing.T) {
	const n = 8
	at := escalationStart
	now := at.Add(time.Minute)
	s, id, _ := openJudgeStore(t)
	if _, err := s.AllowNextSignIn(id, at); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	tokens := make([]string, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			tokens[i], errs[i] = s.RememberAllowedSignIn(id, "", "GB", allowanceHere, now)
		}()
	}
	close(start)
	wg.Wait()

	won := 0
	for i := range n {
		switch {
		case errs[i] == nil:
			won++
			if tokens[i] == "" {
				t.Errorf("caller %d succeeded with no token", i)
			}
		case errors.Is(errs[i], ErrSignInNotAllowed):
			if tokens[i] != "" {
				t.Errorf("caller %d was refused but got token %q", i, tokens[i])
			}
		default:
			t.Errorf("caller %d: %v, want nil or ErrSignInNotAllowed", i, errs[i])
		}
	}
	if won != 1 {
		t.Errorf("%d of %d concurrent sign-ins spent the one allowance, want exactly 1", won, n)
	}
	u := mustGet(t, s, id)
	if !u.SignInAllowedUntil.IsZero() {
		t.Errorf("after the race the window ends %v, want none", u.SignInAllowedUntil)
	}
	if len(u.KnownBrowsers) != 1 {
		t.Errorf("%d browsers remembered after the race, want only the winner's", len(u.KnownBrowsers))
	}
}

// Two stores on one document (two processes): A judged the allowance
// live, B spends it first, then A's allowed sign-in is refused.
func TestRememberAllowedSignInRefusedWhenAnotherProcessSpentIt(t *testing.T) {
	at := escalationStart
	now := at.Add(time.Minute)
	spenders := []struct {
		name  string
		spend func(t *testing.T, b *Store, id string)
	}{
		{"by an ordinary sign-in", func(t *testing.T, b *Store, id string) {
			mustRememberSignIn(t, b, id, "", "GB", allowanceHere, now)
		}},
		{"by an allowed sign-in", func(t *testing.T, b *Store, id string) {
			if _, err := b.RememberAllowedSignIn(id, "", "GB", allowanceHere, now); err != nil {
				t.Fatalf("the other process's allowed sign-in: %v", err)
			}
		}},
	}
	for _, sp := range spenders {
		t.Run(sp.name+", after A judged", func(t *testing.T) {
			m := persist.NewMemory()
			a, id := openLockoutStore(t, m)
			if _, err := a.AllowNextSignIn(id, at); err != nil {
				t.Fatal(err)
			}
			b, err := OpenStore(m, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if u := mustGet(t, a, id); !u.SignInAllowanceLive(now) {
				t.Fatalf("A does not see a live allowance: %v", u.SignInAllowedUntil)
			}
			sp.spend(t, b, id)

			token, err := a.RememberAllowedSignIn(id, "", "FR", &Location{Latitude: 48.8566, Longitude: 2.3522, RadiusKm: 20}, now)
			requireNotAllowed(t, token, err)
			for _, c := range mustGet(t, a, id).SeenCountries {
				if c.Code == "FR" {
					t.Errorf("A remembered France though its allowance was spent: %+v", c)
				}
			}
			if u := mustGet(t, a, id); len(u.KnownBrowsers) != 1 {
				t.Errorf("%d browsers remembered, want only the other process's", len(u.KnownBrowsers))
			}
		})

		// The window itself: A has decided to spend, and the other
		// process spends just before A's save reaches the document.
		t.Run(sp.name+", in the window before A's save", func(t *testing.T) {
			m := persist.NewMemory()
			backend := &otherProcessBackend{Memory: m}
			a, id := openLockoutStore(t, backend)
			if _, err := a.AllowNextSignIn(id, at); err != nil {
				t.Fatal(err)
			}
			b, err := OpenStore(m, Options{})
			if err != nil {
				t.Fatal(err)
			}
			backend.beforeSave = func() { sp.spend(t, b, id) }

			token, err := a.RememberAllowedSignIn(id, "", "FR", &Location{Latitude: 48.8566, Longitude: 2.3522, RadiusKm: 20}, now)
			if backend.beforeSave != nil {
				t.Fatal("A saved nothing, so the other process never spent the allowance under it")
			}
			requireNotAllowed(t, token, err)
			u := mustGet(t, a, id)
			if !u.SignInAllowedUntil.IsZero() {
				t.Errorf("the window ends %v, want none", u.SignInAllowedUntil)
			}
			for _, c := range u.SeenCountries {
				if c.Code == "FR" {
					t.Errorf("A remembered France though its allowance was spent: %+v", c)
				}
			}
			if len(u.KnownBrowsers) != 1 {
				t.Errorf("%d browsers remembered, want only the other process's", len(u.KnownBrowsers))
			}
		})
	}
}
