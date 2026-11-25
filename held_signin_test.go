package gauntlet

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// The held sign-in on the account record (#107): the latest sign-in the
// unusual-sign-in policy held, kept until the account completes a
// sign-in or is allowed one.

var heldAt = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

func sampleHold(at time.Time) HeldSignIn {
	return HeldSignIn{At: at, Outcome: SignInRefused, UserAgent: "Firefox/131.0 (test)", Country: "FR"}
}

func mustHold(t *testing.T, s *Store, id string, h HeldSignIn) {
	t.Helper()
	if err := s.HoldSignIn(id, h); err != nil {
		t.Fatalf("HoldSignIn: %v", err)
	}
}

func requireHeld(t *testing.T, s *Store, id string, want HeldSignIn) {
	t.Helper()
	got := mustGet(t, s, id).HeldSignIn
	if got == nil {
		t.Fatalf("HeldSignIn is nil, want %+v", want)
	}
	if !got.At.Equal(want.At) || got.Outcome != want.Outcome || got.UserAgent != want.UserAgent || got.Country != want.Country {
		t.Errorf("HeldSignIn = %+v, want %+v", *got, want)
	}
}

func requireNotHeld(t *testing.T, s *Store, id, after string) {
	t.Helper()
	if got := mustGet(t, s, id).HeldSignIn; got != nil {
		t.Errorf("HeldSignIn is still %+v after %s", *got, after)
	}
}

func TestHoldSignInRecordsTheHold(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	if mustGet(t, s, id).HeldSignIn != nil {
		t.Fatal("a new account holds a sign-in")
	}
	mustHold(t, s, id, sampleHold(heldAt))
	requireHeld(t, s, id, sampleHold(heldAt))

	// Store.List does not blank it.
	var listed *User
	for _, u := range s.List() {
		if u.ID == id {
			c := u
			listed = &c
		}
	}
	if listed == nil || listed.HeldSignIn == nil || listed.HeldSignIn.Outcome != SignInRefused {
		t.Errorf("Store.List's copy = %+v, want the hold", listed)
	}

	if err := s.HoldSignIn("no-such-id", sampleHold(heldAt)); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("unknown account: %v, want ErrUserNotFound", err)
	}
}

func TestHoldSignInKeepsOnlyTheLatest(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	mustHold(t, s, id, sampleHold(heldAt))
	later := HeldSignIn{At: heldAt.Add(time.Hour), Outcome: SignInConfirmSent} // no agent, no country
	mustHold(t, s, id, later)
	requireHeld(t, s, id, later)
}

func TestHeldSignInSurvivesAReopen(t *testing.T) {
	m := persist.NewMemory()
	s, id := openLockoutStore(t, m)
	h := HeldSignIn{At: heldAt, Outcome: SignInEscapeIssued, UserAgent: "Firefox/131.0 (test)", Country: "GB"}
	mustHold(t, s, id, h)

	reopened, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	requireHeld(t, reopened, id, h)
}

func TestHeldSignInIsOmittedFromTheDocumentWhenNil(t *testing.T) {
	m := persist.NewMemory()
	_, _ = openLockoutStore(t, m)
	snap, err := m.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(snap.Payload), "heldSignIn") {
		t.Errorf("a document with no hold names heldSignIn:\n%s", snap.Payload)
	}
}

func TestSignInCompletionsClearTheHold(t *testing.T) {
	at := escalationStart
	for name, step := range map[string]func(t *testing.T, s *Store, id string){
		"RememberSignIn": func(t *testing.T, s *Store, id string) {
			mustRememberSignIn(t, s, id, "", "GB", nil, at)
		},
		"RememberSignIn from a browser the account knows": func(t *testing.T, s *Store, id string) {
			token := mustRememberSignIn(t, s, id, "", "GB", nil, at)
			mustHold(t, s, id, sampleHold(heldAt))
			mustRememberSignIn(t, s, id, token, "GB", nil, at.Add(time.Minute))
		},
		"RememberAllowedSignIn": func(t *testing.T, s *Store, id string) {
			// Only a live allowance lets this sign-in through, and granting
			// one clears the hold itself, so hold again after it.
			if _, err := s.AllowNextSignIn(id, at); err != nil {
				t.Fatal(err)
			}
			mustHold(t, s, id, sampleHold(heldAt))
			if _, err := s.RememberAllowedSignIn(id, "", "FR", nil, at); err != nil {
				t.Fatal(err)
			}
		},
		"AllowNextSignIn": func(t *testing.T, s *Store, id string) {
			if _, err := s.AllowNextSignIn(id, at); err != nil {
				t.Fatal(err)
			}
		},
		"ClearKnownBrowsers with nothing else to clear": func(t *testing.T, s *Store, id string) {
			if err := s.ClearKnownBrowsers(id); err != nil {
				t.Fatal(err)
			}
		},
		"IssueResetCode": func(t *testing.T, s *Store, id string) {
			if _, _, err := s.IssueResetCode(id, at); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, id := openLockoutStore(t, persist.NewMemory())
			mustHold(t, s, id, sampleHold(heldAt))
			step(t, s, id)
			requireNotHeld(t, s, id, name)
		})
	}
}

// ClearKnownBrowsers on an account that does remember browsers clears
// the hold in the same write.
func TestClearKnownBrowsersClearsTheHoldAlongsideTheBrowsers(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	mustRememberSignIn(t, s, id, "", "GB", nil, escalationStart)
	mustHold(t, s, id, sampleHold(heldAt))
	if err := s.ClearKnownBrowsers(id); err != nil {
		t.Fatal(err)
	}
	requireNotHeld(t, s, id, "ClearKnownBrowsers")
}

// An unlock, and a lockout lapsing, leave the hold: it has no expiry.
func TestUnlockLoginAndTimeLeaveTheHold(t *testing.T) {
	s, id := openLockoutStore(t, persist.NewMemory())
	mustHold(t, s, id, sampleHold(heldAt))
	if err := s.SetLoginLockedUntil(id, heldAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.UnlockLogin(id); err != nil {
		t.Fatal(err)
	}
	requireHeld(t, s, id, sampleHold(heldAt))

	// Nothing reads the clock: a hold from long ago still stands.
	old := sampleHold(time.Now().Add(-365 * 24 * time.Hour))
	mustHold(t, s, id, old)
	requireHeld(t, s, id, old)
}

// The document version (#107): 10 -> 11, no migration.
func TestAccountsDocumentVersion11(t *testing.T) {
	// A version-10 document has no heldSignIn and reads it as nil.
	m := persist.NewMemory()
	overwrite(t, m, `{"version":10,"users":[`+
		`{"id":"u1","username":"alice","passwordHash":"$argon2id$fake","role":"admin","createdAt":"2026-01-01T00:00:00Z"}]}`)
	s, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatalf("a version-10 document: %v", err)
	}
	if u := mustGet(t, s, "u1"); u.HeldSignIn != nil {
		t.Errorf("a version-10 account reads HeldSignIn = %+v, want nil", *u.HeldSignIn)
	}

	// A write by this build stamps version 11.
	mustHold(t, s, "u1", sampleHold(heldAt))
	snap, err := m.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(snap.Payload), "{\n  \"version\": 11,") {
		t.Errorf("the saved document is not version 11:\n%s", snap.Payload)
	}
	if !strings.Contains(string(snap.Payload), `"heldSignIn"`) {
		t.Errorf("the saved document lacks heldSignIn:\n%s", snap.Payload)
	}

	// A version-11 document with a hold loads it.
	m2 := persist.NewMemory()
	overwrite(t, m2, `{"version":11,"users":[`+
		`{"id":"u1","username":"alice","passwordHash":"$argon2id$fake","role":"admin","createdAt":"2026-01-01T00:00:00Z",`+
		`"heldSignIn":{"at":"2026-03-04T05:06:07Z","outcome":"confirm_sent","userAgent":"UA","country":"DE"}}]}`)
	s2, err := OpenStore(m2, Options{})
	if err != nil {
		t.Fatalf("a version-11 document: %v", err)
	}
	requireHeld(t, s2, "u1", HeldSignIn{At: heldAt, Outcome: SignInConfirmSent, UserAgent: "UA", Country: "DE"})

	// One version ahead of this build is still refused, naming both.
	m3 := persist.NewMemory()
	overwrite(t, m3, `{"version":12,"users":[`+
		`{"id":"u1","username":"alice","passwordHash":"$argon2id$fake","role":"admin","createdAt":"2026-01-01T00:00:00Z"}]}`)
	_, err = OpenStore(m3, Options{})
	assertNamesBothVersions(t, err, 12, 11)
}
