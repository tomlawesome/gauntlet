package gauntlet

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// twoAdminsDocument is an accounts document no code path in this package
// can write: CreateUser refuses a second admin and TransferAdmin swaps
// the role in one save. Only a hand edit, or a writer outside this
// package, produces it.
const twoAdminsDocument = `{"users":[` +
	`{"id":"u1","username":"alice","passwordHash":"$argon2id$fake","role":"admin","createdAt":"2026-01-01T00:00:00Z"},` +
	`{"id":"u2","username":"bob","passwordHash":"$argon2id$fake","role":"admin","createdAt":"2026-01-01T00:00:00Z"}]}`

// TestOpenRefusesADocumentWithTwoAdmins: a document holding more than
// one admin is refused at startup like one that will not parse -- the
// same "not a fresh install, restore from backup" error -- instead of
// loading a deployment the rest of the package assumes cannot exist
// (TransferAdmin would demote whichever admin it met first).
func TestOpenRefusesADocumentWithTwoAdmins(t *testing.T) {
	m := persist.NewMemory()
	primeMemory(t, m, twoAdminsDocument)

	s, err := OpenStore(m, Options{})
	if err == nil {
		t.Fatalf("OpenStore accepted a document with two admins (admin: %+v)", s.Admin())
	}
	var startup *persist.StartupError
	if !errors.As(err, &startup) {
		t.Fatalf("expected a *persist.StartupError, got %T: %v", err, err)
	}
	if !errors.Is(err, errMultipleAdmins) {
		t.Errorf("expected the error to name the admin count, got: %v", err)
	}
}

// noAdminDocument is an accounts document no code path in this package
// can write either: DeleteUser refuses to remove the admin account, so
// an existing deployment can never be emptied of one from underneath
// it. Only a hand edit, or a foreign writer, produces it.
const noAdminDocument = `{"users":[` +
	`{"id":"u1","username":"alice","passwordHash":"$argon2id$fake","role":"user","createdAt":"2026-01-01T00:00:00Z"},` +
	`{"id":"u2","username":"bob","passwordHash":"$argon2id$fake","role":"user","createdAt":"2026-01-01T00:00:00Z"}]}`

// TestOpenRefusesADocumentWithNoAdmin: a document holding accounts but
// no admin is refused at startup the same way as one with two, rather
// than loaded as a fresh install -- it is not one, and nothing in this
// package can ever grant admin back once it loads (Register is closed
// as soon as Count()>0, CreateUser refuses RoleAdmin, and TransferAdmin
// needs a current admin to transfer from).
func TestOpenRefusesADocumentWithNoAdmin(t *testing.T) {
	m := persist.NewMemory()
	primeMemory(t, m, noAdminDocument)

	s, err := OpenStore(m, Options{})
	if err == nil {
		t.Fatalf("OpenStore accepted a document with no admin (count: %d)", s.Count())
	}
	var startup *persist.StartupError
	if !errors.As(err, &startup) {
		t.Fatalf("expected a *persist.StartupError, got %T: %v", err, err)
	}
	if !errors.Is(err, errNoAdmin) {
		t.Errorf("expected the error to name the missing admin, got: %v", err)
	}
}

// TestReloadIfStaleIgnoresADocumentWithNoAdmin: the same document
// written under a running server is not applied, for the same reason as
// the two-admin case -- the server keeps serving what it holds, logs
// the refusal once, and does not re-log on every request while the
// document stays as it is.
func TestReloadIfStaleIgnoresADocumentWithNoAdmin(t *testing.T) {
	var logs bytes.Buffer
	m := persist.NewMemory()
	// OnSetupCode keeps the empty store's setup-code line out of logs:
	// this test counts lines about the refused document, nothing else.
	s, err := OpenStore(m, Options{Log: slog.New(slog.NewTextHandler(&logs, nil)), OnSetupCode: SetupCodeFunc(func(string) {})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register("alice", "password123", time.Now()); err != nil {
		t.Fatal(err)
	}

	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Save(context.Background(), []byte(noAdminDocument), snap.Version); err != nil {
		t.Fatal(err)
	}

	for range 3 { // each read runs reloadIfStale
		if u, ok := s.ByUsername("bob"); ok {
			t.Fatalf("a document with no admin was applied: bob loaded as %+v", u)
		}
	}
	if a := s.Admin(); a == nil || a.Username != "alice" {
		t.Fatalf("expected alice to remain the only admin, got %+v", a)
	}
	if n := strings.Count(logs.String(), "admin"); n != 1 {
		t.Errorf("expected exactly one log line about the refused document, got %d:\n%s", n, logs.String())
	}
}

// TestReloadIfStaleIgnoresADocumentWithTwoAdmins: the same document
// written under a running server is not applied. The server keeps
// serving what it holds, says so in the log once, and does not re-log
// on every request while the document stays as it is.
func TestReloadIfStaleIgnoresADocumentWithTwoAdmins(t *testing.T) {
	var logs bytes.Buffer
	m := persist.NewMemory()
	// OnSetupCode keeps the empty store's setup-code line out of logs:
	// this test counts lines about the refused document, nothing else.
	s, err := OpenStore(m, Options{Log: slog.New(slog.NewTextHandler(&logs, nil)), OnSetupCode: SetupCodeFunc(func(string) {})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register("alice", "password123", time.Now()); err != nil {
		t.Fatal(err)
	}

	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Save(context.Background(), []byte(twoAdminsDocument), snap.Version); err != nil {
		t.Fatal(err)
	}

	for range 3 { // each read runs reloadIfStale
		if u, ok := s.ByUsername("bob"); ok {
			t.Fatalf("a document with two admins was applied: bob loaded as %+v", u)
		}
	}
	if a := s.Admin(); a == nil || a.Username != "alice" {
		t.Fatalf("expected alice to remain the only admin, got %+v", a)
	}
	if n := strings.Count(logs.String(), "admin"); n != 1 {
		t.Errorf("expected exactly one log line about the refused document, got %d:\n%s", n, logs.String())
	}
}

// TestRegisterStaysClosedWhileATwoAdminDocumentIsRefused: this Store
// opens on an empty backend, so it has no admin of its own -- Count()
// stays 0 even after the two-admin document is refused. Register must
// not read that 0 as "registration is open": doing so would create a
// new admin and save it over the operator's restored document on the
// next conflict-retry.
func TestRegisterStaysClosedWhileATwoAdminDocumentIsRefused(t *testing.T) {
	m := persist.NewMemory()
	s, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	primeMemory(t, m, twoAdminsDocument)

	if _, err := s.Register("carol", "password123", time.Now()); !errors.Is(err, ErrRegistrationClosed) {
		t.Fatalf("expected ErrRegistrationClosed, got %v", err)
	}

	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(snap.Payload) != twoAdminsDocument {
		t.Fatalf("the refused document was overwritten:\n%s", snap.Payload)
	}
	if n := s.Count(); n != 0 {
		t.Errorf("expected this store's own view to stay empty, got %d", n)
	}
}

// TestRegisterReopensOnceTheRefusedDocumentIsReplaced: an operator who
// sees the previous test's refusal fixes it by replacing the bad
// document on disk, not by restarting the process. The next reload must
// apply that replacement and let registration proceed again -- a
// refusal only holds while the refused document is still the one on
// disk.
func TestRegisterReopensOnceTheRefusedDocumentIsReplaced(t *testing.T) {
	m := persist.NewMemory()
	s, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	primeMemory(t, m, twoAdminsDocument)

	if _, err := s.Register("carol", "password123", time.Now()); !errors.Is(err, ErrRegistrationClosed) {
		t.Fatalf("expected ErrRegistrationClosed, got %v", err)
	}

	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Save(context.Background(), []byte(`{"users":[]}`), snap.Version); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Register("carol", "password123", time.Now()); err != nil {
		t.Fatalf("expected Register to succeed once the refused document was replaced, got %v", err)
	}
}
