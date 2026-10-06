package gauntlet

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// Several admins (#67, ADR-0010): any number may hold the role, and the
// last one cannot be deleted or demoted. #75: SetRole moves an account
// among admin, user and viewer.

// storeWithTwoAdmins is openTestStore with "alice" (the first admin,
// registered) and "bob" (a second admin made with CreateUser), plus
// "carol", a plain user.
func storeWithTwoAdmins(t *testing.T) (s *Store, alice, bob, carol *User) {
	t.Helper()
	s = openTestStore(t)
	var err error
	if alice, err = s.Register("alice", "correct-horse-battery-staple", time.Now()); err != nil {
		t.Fatal(err)
	}
	if bob, err = s.CreateUser("bob", "correct-horse-battery-staple", RoleAdmin, time.Now()); err != nil {
		t.Fatalf("CreateUser(admin): %v", err)
	}
	if carol, err = s.CreateUser("carol", "correct-horse-battery-staple", RoleUser, time.Now()); err != nil {
		t.Fatal(err)
	}
	return s, alice, bob, carol
}

func TestCreateUserMakesAnotherAdmin(t *testing.T) {
	s, _, bob, _ := storeWithTwoAdmins(t)
	if bob.Role != RoleAdmin {
		t.Fatalf("CreateUser(admin) made role %q", bob.Role)
	}
	admins := s.Admins()
	if len(admins) != 2 || admins[0].Username != "alice" || admins[1].Username != "bob" {
		t.Fatalf("Admins() = %+v, want alice and bob", admins)
	}
	for _, a := range admins {
		if a.PasswordHash != "" {
			t.Errorf("Admins() leaked %s's password hash", a.Username)
		}
	}
}

func TestTwoAdminsSurviveAReopen(t *testing.T) {
	m := persist.NewMemory()
	s, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register("alice", "correct-horse-battery-staple", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser("bob", "correct-horse-battery-staple", RoleAdmin, time.Now()); err != nil {
		t.Fatal(err)
	}
	again, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatalf("reopening a two-admin store: %v", err)
	}
	if n := len(again.Admins()); n != 2 {
		t.Errorf("reopened store has %d admins, want 2", n)
	}
}

// A version-8 document (one admin, the shape before #67) loads
// unchanged and is saved back as version 9.
func TestVersion8DocumentLoadsAndGainsVersion9(t *testing.T) {
	m := persist.NewMemory()
	primeMemory(t, m, `{"version":8,"seq":5,"users":[`+
		`{"id":"u1","username":"alice","passwordHash":"$argon2id$fake","role":"admin","hasLocalPassword":true,"createdAt":"2026-01-01T00:00:00Z"}]}`)
	s, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatalf("OpenStore refused a version-8 document: %v", err)
	}
	if a := s.Admin(); a == nil || a.Username != "alice" {
		t.Fatalf("Admin() = %+v, want alice", a)
	}
	if _, err := s.CreateUser("bob", "correct-horse-battery-staple", RoleAdmin, time.Now()); err != nil {
		t.Fatal(err)
	}
	if n := len(s.Admins()); n != 2 {
		t.Errorf("%d admins, want 2", n)
	}
}

func TestCreateUserRefusesAnUnknownRoleStill(t *testing.T) {
	s := openTestStoreWithAdmin(t)
	if _, err := s.CreateUser("x", "correct-horse-battery-staple", Role("owner"), time.Now()); !errors.Is(err, ErrInvalidRole) {
		t.Errorf("err = %v, want ErrInvalidRole", err)
	}
}

func TestDeleteUserRefusesTheLastAdminButNotAnother(t *testing.T) {
	s, alice, bob, _ := storeWithTwoAdmins(t)

	if _, err := s.DeleteUser(bob.ID); err != nil {
		t.Fatalf("deleting one of two admins: %v", err)
	}
	_, err := s.DeleteUser(alice.ID)
	if err != ErrCannotDeleteAdmin {
		t.Fatalf("deleting the last admin = %v, want ErrCannotDeleteAdmin itself", err)
	}
	if !errors.Is(err, ErrLastAdmin) {
		t.Errorf("errors.Is(%v, ErrLastAdmin) = false", err)
	}
	if s.Admin() == nil {
		t.Error("the last admin is gone after a refused delete")
	}
}

func TestSetRoleGrantsAndRecords(t *testing.T) {
	s, _, _, carol := storeWithTwoAdmins(t)
	now := time.Now().UTC().Truncate(time.Second)

	got, from, err := s.SetRole(carol.ID, RoleAdmin, now)
	if err != nil {
		t.Fatal(err)
	}
	if from != RoleUser || got.Role != RoleAdmin || !got.RoleChangedAt.Equal(now) {
		t.Errorf("SetRole = %+v from %q, want admin changed at %v from user", got, from, now)
	}
	if !got.SessionsEndedAt.IsZero() {
		t.Error("a grant ended the account's sessions; only a downgrade does")
	}
	if got.PasswordHash != "" {
		t.Error("SetRole returned the password hash")
	}
	if u, _ := s.ByUsername("carol"); u.Role != RoleAdmin {
		t.Errorf("stored role = %q, want admin", u.Role)
	}
}

func TestSetRoleDowngradeEndsSessionsAndUpgradeDoesNot(t *testing.T) {
	s, _, bob, carol := storeWithTwoAdmins(t)
	now := time.Now().UTC().Truncate(time.Second)

	// admin -> viewer and user -> viewer are downgrades.
	got, _, err := s.SetRole(bob.ID, RoleViewer, now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.SessionsEndedAt.Equal(now) {
		t.Errorf("SessionsEndedAt after admin->viewer = %v, want %v", got.SessionsEndedAt, now)
	}
	got, _, err = s.SetRole(carol.ID, RoleViewer, now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.SessionsEndedAt.Equal(now) {
		t.Errorf("SessionsEndedAt after user->viewer = %v, want %v", got.SessionsEndedAt, now)
	}
	// viewer -> user is an upgrade: the zero value stays on a fresh account.
	later := now.Add(time.Hour)
	got, _, err = s.SetRole(carol.ID, RoleUser, later)
	if err != nil {
		t.Fatal(err)
	}
	if !got.SessionsEndedAt.Equal(now) || !got.RoleChangedAt.Equal(later) {
		t.Errorf("an upgrade moved SessionsEndedAt to %v (want %v) or missed RoleChangedAt %v", got.SessionsEndedAt, now, got.RoleChangedAt)
	}
}

func TestSetRoleRefusals(t *testing.T) {
	s, alice, bob, carol := storeWithTwoAdmins(t)
	now := time.Now()

	if _, _, err := s.SetRole("no-such-id", RoleUser, now); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("unknown id: %v, want ErrUserNotFound", err)
	}
	if _, _, err := s.SetRole(carol.ID, Role("owner"), now); !errors.Is(err, ErrInvalidRole) {
		t.Errorf("unknown role: %v, want ErrInvalidRole", err)
	}
	if _, _, err := s.SetRole(carol.ID, RoleUser, now); !errors.Is(err, ErrRoleUnchanged) {
		t.Errorf("same role: %v, want ErrRoleUnchanged", err)
	}
	// Two admins: either may demote the other, once.
	if _, _, err := s.SetRole(bob.ID, RoleUser, now); err != nil {
		t.Fatalf("demoting one of two admins: %v", err)
	}
	if _, _, err := s.SetRole(alice.ID, RoleUser, now); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("demoting the last admin: %v, want ErrLastAdmin", err)
	}
	if _, _, err := s.SetRole(alice.ID, RoleViewer, now); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("demoting the last admin to viewer: %v, want ErrLastAdmin", err)
	}
	if a := s.Admin(); a == nil || a.ID != alice.ID {
		t.Errorf("Admin() = %+v, want alice still", a)
	}
}

// An admin may demote themselves while another admin remains.
func TestSetRoleSelfDemoteNeedsAnotherAdmin(t *testing.T) {
	s, alice, _, _ := storeWithTwoAdmins(t)
	if _, _, err := s.SetRole(alice.ID, RoleUser, time.Now()); err != nil {
		t.Fatalf("self-demote with another admin: %v", err)
	}
	if a := s.Admin(); a == nil || a.Username != "bob" {
		t.Errorf("Admin() = %+v, want bob", a)
	}
}

// TestConcurrentDemotesLeaveExactlyOneAdmin is the check-then-act race
// TransferAdmin's comment names: every admin demoted at once, from
// several goroutines, must end with one admin and never none -- and
// the loser must be told ErrLastAdmin.
func TestConcurrentDemotesLeaveExactlyOneAdmin(t *testing.T) {
	s, alice, bob, _ := storeWithTwoAdmins(t)
	dave, err := s.CreateUser("dave", "correct-horse-battery-staple", RoleAdmin, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{alice.ID, bob.ID, dave.ID}

	var wg sync.WaitGroup
	start := make(chan struct{})
	var mu sync.Mutex
	var okCount int
	for i := range 3 * 4 {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			<-start
			_, _, err := s.SetRole(id, RoleUser, time.Now())
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				okCount++
			case errors.Is(err, ErrLastAdmin), errors.Is(err, ErrRoleUnchanged):
				// refused, as it should be
			default:
				t.Errorf("SetRole: unexpected error %v", err)
			}
		}(ids[i%3])
	}
	close(start)
	wg.Wait()

	if okCount != 2 {
		t.Errorf("%d demotes succeeded, want exactly 2 of 3 admins", okCount)
	}
	if n := len(s.Admins()); n != 1 {
		t.Fatalf("%d admins after concurrent demotes, want exactly 1", n)
	}
}

// Deleting and demoting at once must not empty the deployment either.
func TestConcurrentDeleteAndDemoteLeaveAnAdmin(t *testing.T) {
	for range 20 {
		s, alice, bob, _ := storeWithTwoAdmins(t)
		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(2)
		go func() { defer wg.Done(); <-start; _, _ = s.DeleteUser(alice.ID) }()
		go func() { defer wg.Done(); <-start; _, _, _ = s.SetRole(bob.ID, RoleUser, time.Now()) }()
		close(start)
		wg.Wait()
		if len(s.Admins()) != 1 {
			t.Fatalf("%d admins after a concurrent delete and demote, want 1", len(s.Admins()))
		}
	}
}

func TestHasLocalAdminWithSeveralAdmins(t *testing.T) {
	s, alice, bob, _ := storeWithTwoAdmins(t)
	// Both admins have local passwords.
	if !s.HasLocalAdmin() {
		t.Fatal("two admins with passwords: HasLocalAdmin = false")
	}
	// Link SSO on both: each keeps its password.
	if err := s.LinkOIDCIdentity(alice.ID, "https://idp.example", "sub-a", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkOIDCIdentity(bob.ID, "https://idp.example", "sub-b", time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice", "bob"} {
		u, _ := s.ByUsername(name)
		if !u.LocalPassword() {
			t.Errorf("%s lost the local password on an SSO link", name)
		}
	}
	if !s.HasLocalAdmin() {
		t.Error("HasLocalAdmin = false after both admins linked SSO")
	}
}

// With one SSO-only admin and one with a password, a local way in exists.
func TestHasLocalAdminCountsAnyAdmin(t *testing.T) {
	s := openTestStoreWithAdmin(t) // setup-admin keeps a password
	if _, _, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-c", "carol", time.Now()); err != nil {
		t.Fatal(err)
	}
	carol, _ := s.ByUsername("carol")
	if _, _, err := s.SetRole(carol.ID, RoleAdmin, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !s.HasLocalAdmin() {
		t.Error("an admin with a password exists but HasLocalAdmin = false")
	}
	// Demoting the one with the password, which used to leave only the
	// SSO-only admin, is now refused (TestLastLocalAdminCannotBeDemotedOrDeleted).
	setup, _ := s.ByUsername("setup-admin")
	if _, _, err := s.SetRole(setup.ID, RoleUser, time.Now()); !errors.Is(err, ErrLastLocalAdmin) {
		t.Fatalf("demoting the last admin with a password = %v, want ErrLastLocalAdmin", err)
	}
	if !s.HasLocalAdmin() {
		t.Error("a refused demotion lost the local way in")
	}
}

// Every admin keeps a local password (owner decision on #79): while the
// other admins sign in only through SSO, the last admin with a password
// can be neither demoted nor deleted. The SSO-only admin itself may go,
// and once another admin has a password, so may the first.
func TestLastLocalAdminCannotBeDemotedOrDeleted(t *testing.T) {
	s := openTestStoreWithAdmin(t) // setup-admin keeps a password
	if _, _, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-c", "carol", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-d", "dave", time.Now()); err != nil {
		t.Fatal(err)
	}
	carol, _ := s.ByUsername("carol")
	dave, _ := s.ByUsername("dave")
	for _, id := range []string{carol.ID, dave.ID} {
		if _, _, err := s.SetRole(id, RoleAdmin, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	setup, _ := s.ByUsername("setup-admin")

	for _, role := range []Role{RoleUser, RoleViewer} {
		if _, _, err := s.SetRole(setup.ID, role, time.Now()); err != ErrLastLocalAdmin {
			t.Errorf("demoting the last admin with a password to %s = %v, want ErrLastLocalAdmin", role, err)
		}
	}
	if _, err := s.DeleteUser(setup.ID); err != ErrLastLocalAdmin {
		t.Errorf("deleting the last admin with a password = %v, want ErrLastLocalAdmin", err)
	}
	if u, ok := s.Get(setup.ID); !ok || u.Role != RoleAdmin {
		t.Fatalf("setup-admin after the refusals = %+v, want an admin still", u)
	}

	// An SSO-only admin is no one's local way in.
	if _, _, err := s.SetRole(carol.ID, RoleUser, time.Now()); err != nil {
		t.Errorf("demoting an SSO-only admin: %v", err)
	}
	if _, err := s.DeleteUser(carol.ID); err != nil {
		t.Errorf("deleting an SSO-only (now plain) account: %v", err)
	}

	// Once dave has a password, setup-admin is no longer the last.
	if err := s.SetPassword("dave", "correct-horse-battery-staple", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteUser(setup.ID); err != nil {
		t.Errorf("deleting setup-admin once another admin has a password: %v", err)
	}
}

func TestTransferAdminEndsTheOldAdminsSessions(t *testing.T) {
	s, _, _ := storeWithAdminAndUser(t)
	now := time.Now().UTC().Truncate(time.Second)
	from, _, err := s.TransferAdmin("second", now)
	if err != nil {
		t.Fatal(err)
	}
	if !from.SessionsEndedAt.Equal(now) {
		t.Errorf("old admin's SessionsEndedAt = %v, want %v", from.SessionsEndedAt, now)
	}
}

func TestTransferAdminRefusesAnSSOOnlyTargetFromTheLastLocalAdmin(t *testing.T) {
	s := openTestStoreWithAdmin(t) // setup-admin keeps a password
	if _, _, err := s.FindOrCreateOIDCUser("https://idp.example", "sub-c", "carol", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.TransferAdmin("carol", time.Now()); err != ErrLastLocalAdmin {
		t.Fatalf("transferring the only admin role to an SSO-only account = %v, want ErrLastLocalAdmin", err)
	}
	setup, _ := s.ByUsername("setup-admin")
	if setup.Role != RoleAdmin {
		t.Fatalf("setup-admin after the refusal = %s, want admin still", setup.Role)
	}
	// With a password of her own, carol is a local way in and the
	// transfer goes through.
	if err := s.SetPassword("carol", "correct-horse-battery-staple", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.TransferAdmin("carol", time.Now()); err != nil {
		t.Fatalf("transferring to an account with a password: %v", err)
	}
}
