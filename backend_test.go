// Ported from mikroview's internal/auth/backend_test.go. Adapted:
// mikroview's eachAuthBackend runs the same assertions against its file
// and Postgres backends, neither of which exists in this module --
// gauntlet ships only persist.Memory (an application supplies its own
// persist.Backend; see persist/persist.go). These assertions are what
// matters for *any* persist.Backend implementation, so they still earn
// their keep run against the one backend gauntlet itself ships.

package gauntlet

import (
	"context"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

func TestBackendRegisterAndAuthenticate(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.Register("alice", "password123", time.Now()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := s.Authenticate("alice", "password123", time.Now()); err != nil {
		t.Errorf("Authenticate: %v", err)
	}
	if _, err := s.Authenticate("alice", "wrong", time.Now()); err != ErrInvalidCredentials {
		t.Errorf("wrong password: got %v", err)
	}
}

// The whole point of persistence: a second Store opened against the same
// backend sees what the first wrote. This is also the cross-process case
// a CLI recovery command relies on.
func TestBackendSurvivesReopen(t *testing.T) {
	m := persist.NewMemory()
	first, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if _, err := first.Register("alice", "password123", time.Now()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := first.CreateUser("bob", "password456", RoleUser, time.Now()); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	second, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if second.Count() != 2 {
		t.Fatalf("reopened store has %d accounts, want 2", second.Count())
	}
	admin := second.Admin()
	if admin == nil || admin.Username != "alice" {
		t.Errorf("admin did not survive: %+v", admin)
	}
	if _, err := second.Authenticate("bob", "password456", time.Now()); err != nil {
		t.Errorf("bob's password did not survive: %v", err)
	}
}

// A second Store standing in for a CLI command: it writes, and the
// first (standing in for the running server) must pick the change up
// without being restarted.
func TestBackendPicksUpAnotherProcessesWrite(t *testing.T) {
	m := persist.NewMemory()
	server, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if _, err := server.Register("alice", "password123", time.Now()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	cli, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if err := cli.SetPassword("alice", "newpassword999", time.Now()); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	// The running server must see it -- Authenticate reloads first.
	if _, err := server.Authenticate("alice", "newpassword999", time.Now()); err != nil {
		t.Errorf("the running store did not pick up the other process's change: %v", err)
	}
	if _, err := server.Authenticate("alice", "password123", time.Now()); err == nil {
		t.Error("the old password still works on the running store")
	}
}

// An unreadable document must not read as an absent one -- that turns a
// corrupted accounts store into a fresh install, silently reopening
// registration. An application refuses to start on this error.
func TestBackendCorruptDocumentIsAnError(t *testing.T) {
	m := persist.NewMemory()
	s, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if _, err := s.Register("alice", "password123", time.Now()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Corrupt it through the backend, the way a bad disk or a truncated
	// write would.
	snap, err := s.backend.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := s.backend.Save(context.Background(), []byte("{not json"), snap.Version); err != nil {
		t.Fatalf("corrupting: %v", err)
	}

	reopened, err := OpenStore(s.backend, Options{})
	if err == nil {
		t.Error("a corrupt accounts document opened cleanly -- it would present as a fresh install")
	}
	if reopened != nil && reopened.Count() != 0 {
		t.Errorf("expected an empty store alongside the error, got %d accounts", reopened.Count())
	}
}
