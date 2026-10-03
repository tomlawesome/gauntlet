// Ported from mikroview's internal/auth/transfer_test.go. Adapted:
// Open(path) -> openTestStore(t); OpenWithBackend -> OpenStore.

package gauntlet

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

func storeWithAdminAndUser(t *testing.T) (*Store, *User, *User) {
	t.Helper()
	s := openTestStore(t)
	admin, err := s.Register("admin", "correct-horse-battery-staple", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	user, err := s.CreateUser("second", "correct-horse-battery-staple", RoleUser, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return s, admin, user
}

func TestCreateUserCannotMintASecondAdmin(t *testing.T) {
	s, _, _ := storeWithAdminAndUser(t)
	if _, err := s.CreateUser("other", "correct-horse-battery-staple", RoleAdmin, time.Now()); !errors.Is(err, ErrSingleAdmin) {
		t.Errorf("a second admin was created (err=%v) -- the single-admin invariant is the whole model", err)
	}
}

func TestTransferAdminMovesTheRole(t *testing.T) {
	s, admin, user := storeWithAdminAndUser(t)

	from, to, err := s.TransferAdmin("second", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if from.ID != admin.ID || to.ID != user.ID {
		t.Errorf("transfer reported the wrong accounts: from=%s to=%s", from.Username, to.Username)
	}

	got := s.Admin()
	if got == nil || got.Username != "second" {
		t.Fatalf("admin is %v, want second", got)
	}
	old, ok := s.ByUsername("admin")
	if !ok {
		t.Fatal("previous admin vanished")
	}
	if old.Role != RoleUser {
		t.Errorf("previous admin still has role %q -- there are now two admins", old.Role)
	}
}

// TestExactlyOneAdminUnderConcurrentTransfers is the TOCTOU case. Two
// simultaneous transfers must not produce zero admins or two.
func TestExactlyOneAdminUnderConcurrentTransfers(t *testing.T) {
	s, _, _ := storeWithAdminAndUser(t)
	if _, err := s.CreateUser("third", "correct-horse-battery-staple", RoleUser, time.Now()); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, target := range []string{"second", "third", "second", "third"} {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			<-start
			_, _, _ = s.TransferAdmin(u, time.Now())
		}(target)
	}
	close(start)
	wg.Wait()

	admins := 0
	for _, u := range s.List() {
		if u.Role == RoleAdmin {
			admins++
		}
	}
	if admins != 1 {
		t.Errorf("after concurrent transfers there are %d admins, want exactly 1", admins)
	}
}

func TestTransferRejections(t *testing.T) {
	s, _, _ := storeWithAdminAndUser(t)

	if _, _, err := s.TransferAdmin("admin", time.Now()); !errors.Is(err, ErrTransferToSelf) {
		t.Errorf("transfer to the current admin returned %v, want ErrTransferToSelf", err)
	}
	if _, _, err := s.TransferAdmin("nobody", time.Now()); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("transfer to an unknown account returned %v, want ErrUserNotFound", err)
	}

	empty := openTestStore(t)
	if _, _, err := empty.TransferAdmin("anyone", time.Now()); !errors.Is(err, ErrNoAdmin) {
		t.Errorf("transfer with no admin returned %v, want ErrNoAdmin", err)
	}
}

// TestTransferAdminLeavesRolesUnchangedWhenPersistFails: a transfer that
// cannot be saved must not move the admin role in memory either, or a
// restart before the next good write would leave the deployment with
// the wrong admin -- or, briefly, two.
func TestTransferAdminLeavesRolesUnchangedWhenPersistFails(t *testing.T) {
	// Register and CreateUser below each persist too (createAccount
	// persists as well), so the fixture needs a backend that saves
	// twice before failing, not one that fails outright.
	s, err := OpenStore(&saveBudgetBackend{left: 2}, Options{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	admin, err := s.Register("admin", "correct-horse-battery-staple", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser("second", "correct-horse-battery-staple", RoleUser, time.Now()); err != nil {
		t.Fatal(err)
	}

	if _, _, err := s.TransferAdmin("second", time.Now()); err == nil {
		t.Fatal("TransferAdmin against a backend that cannot save = nil error, want one")
	}

	got := s.Admin()
	if got == nil || got.ID != admin.ID {
		t.Errorf("admin after a failed transfer = %v, want the original admin still in place", got)
	}
	second, ok := s.ByUsername("second")
	if !ok || second.Role != RoleUser {
		t.Errorf("second's role after a failed transfer = %v, want RoleUser unchanged", second)
	}
	// RoleChangedAt is what ends sessions issued before a role change,
	// so a stray update here would log both accounts out for nothing.
	if !got.RoleChangedAt.Equal(admin.RoleChangedAt) || !second.RoleChangedAt.IsZero() {
		t.Errorf("RoleChangedAt after a failed transfer = admin %v, second %v; want both untouched",
			got.RoleChangedAt, second.RoleChangedAt)
	}
}

func TestTransferSurvivesReload(t *testing.T) {
	m := persist.NewMemory()
	s, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register("admin", "correct-horse-battery-staple", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser("second", "correct-horse-battery-staple", RoleUser, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.TransferAdmin("second", time.Now()); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := reopened.Admin()
	if got == nil || got.Username != "second" {
		t.Errorf("after reload the admin is %v, want second -- the transfer wasn't persisted", got)
	}
}
