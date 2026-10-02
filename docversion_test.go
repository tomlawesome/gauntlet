package gauntlet

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// The stored-document version (#29). Both documents carry a top-level
// version; one written by a newer build is refused rather than loaded,
// because an older build that loaded it would drop every field it does
// not know on its next save -- after a rollback, a newer build's TOTP
// secrets or passkeys, gone without a word.

// newerAccountsDocument is an accounts document from a build one format
// version ahead of this one (this build writes version 4, #44),
// otherwise valid: one admin, one user.
const newerAccountsDocument = `{"version":5,"users":[` +
	`{"id":"u1","username":"alice","passwordHash":"$argon2id$fake","role":"admin","createdAt":"2026-01-01T00:00:00Z"},` +
	`{"id":"u2","username":"bob","passwordHash":"$argon2id$fake","role":"user","createdAt":"2026-01-01T00:00:00Z"}]}`

// newerTokensDocument is the same for tokens: one token, in a document
// one format version ahead.
const newerTokensDocument = `{"version":2,"tokens":[` +
	`{"id":"t-newer","name":"from-a-newer-build","kind":"api","hashedValue":"fixture-hash","createdAt":"2026-01-01T00:00:00Z"}]}`

// assertNamesBothVersions fails unless err names the document's version
// and the one this build reads, so an operator can tell from the
// message alone which build wrote the file.
func assertNamesBothVersions(t *testing.T, err error, got, known int) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error naming the document version, got nil")
	}
	msg := err.Error()
	for _, want := range []string{"version " + strconv.Itoa(got), "version " + strconv.Itoa(known)} {
		if !strings.Contains(msg, want) {
			t.Errorf("error does not say %q: %v", want, err)
		}
	}
}

// TestOpenRefusesANewerAccountsDocument: at startup, a newer document is
// refused like an unparseable one -- a *persist.StartupError, so the
// app does not start on it -- and the error says which version it is
// and which this build reads. A newer document whose users no longer
// parse as this build's is still reported as newer, not as garbage.
func TestOpenRefusesANewerAccountsDocument(t *testing.T) {
	for name, doc := range map[string]string{
		"same shape":      newerAccountsDocument,
		"different shape": `{"version":5,"users":{"alice":{"role":"admin"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			m := persist.NewMemory()
			primeMemory(t, m, doc)

			s, err := OpenStore(m, Options{})
			if err == nil {
				t.Fatalf("OpenStore accepted a newer document (count: %d)", s.Count())
			}
			var startup *persist.StartupError
			if !errors.As(err, &startup) {
				t.Fatalf("expected a *persist.StartupError, got %T: %v", err, err)
			}
			assertNamesBothVersions(t, err, 5, 4)
		})
	}
}

// TestOpenTokenStoreRefusesANewerTokensDocument is the same for tokens.
func TestOpenTokenStoreRefusesANewerTokensDocument(t *testing.T) {
	m := persist.NewMemory()
	primeMemory(t, m, newerTokensDocument)

	s, err := OpenTokenStore(m, TokenOptions{})
	if err == nil {
		t.Fatalf("OpenTokenStore accepted a newer document (%d tokens)", len(s.List()))
	}
	var startup *persist.StartupError
	if !errors.As(err, &startup) {
		t.Fatalf("expected a *persist.StartupError, got %T: %v", err, err)
	}
	assertNamesBothVersions(t, err, 2, 1)
}

// TestReloadIfStaleRefusesANewerAccountsDocument: a newer document
// written under a running server -- the newer build started alongside
// an older one, or a rollback that left the newer file in place -- is
// not applied, is logged once with both versions, and a later write
// does not save over it.
func TestReloadIfStaleRefusesANewerAccountsDocument(t *testing.T) {
	var logs bytes.Buffer
	m := persist.NewMemory()
	s, err := OpenStore(m, Options{Log: slog.New(slog.NewTextHandler(&logs, nil))})
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
	if _, err := m.Save(context.Background(), []byte(newerAccountsDocument), snap.Version); err != nil {
		t.Fatal(err)
	}

	for range 3 { // each read runs reloadIfStale
		if u, ok := s.ByUsername("bob"); ok {
			t.Fatalf("a newer document was applied: bob loaded as %+v", u)
		}
	}
	if n := strings.Count(logs.String(), "version 5"); n != 1 {
		t.Errorf("expected exactly one log line about the newer document, got %d:\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "version 4") {
		t.Errorf("the log line does not name the version this build reads:\n%s", logs.String())
	}

	_, err = s.CreateUser("carol", "password456", RoleUser, time.Now())
	assertNamesBothVersions(t, err, 5, 4)
	assertPayload(t, m, newerAccountsDocument)
}

// TestTokenStoreReloadRefusesANewerTokensDocument is the same for
// tokens.
func TestTokenStoreReloadRefusesANewerTokensDocument(t *testing.T) {
	var logs bytes.Buffer
	m := persist.NewMemory()
	s, err := OpenTokenStore(m, TokenOptions{Log: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Create("first", TokenKindAPI, "", nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Save(context.Background(), []byte(newerTokensDocument), snap.Version); err != nil {
		t.Fatal(err)
	}

	for range 3 { // each read runs reloadIfStale
		for _, tok := range s.List() {
			if tok.ID == "t-newer" {
				t.Fatal("a newer tokens document was applied")
			}
		}
	}
	if n := strings.Count(logs.String(), "version 2"); n != 1 {
		t.Errorf("expected exactly one log line about the newer document, got %d:\n%s", n, logs.String())
	}

	_, _, err = s.Create("second", TokenKindAPI, "", nil, time.Now())
	assertNamesBothVersions(t, err, 2, 1)
	assertPayload(t, m, newerTokensDocument)
}

// TestMutateRefusesToWriteOverANewerAccountsDocument: a newer document
// that lands between this store's last read and its save is met by the
// save's conflict, and refused there -- the write fails rather than
// replaying onto it and saving it back without the fields this build
// does not know.
func TestMutateRefusesToWriteOverANewerAccountsDocument(t *testing.T) {
	m := persist.NewMemory()
	b := &otherProcessBackend{Memory: m}
	s, err := OpenStore(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register("alice", "password123", time.Now()); err != nil {
		t.Fatal(err)
	}
	b.beforeSave = func() { overwrite(t, m, newerAccountsDocument) }

	_, err = s.CreateUser("carol", "password456", RoleUser, time.Now())
	assertNamesBothVersions(t, err, 5, 4)
	assertPayload(t, m, newerAccountsDocument)
}

// TestTokenStoreRefusesToWriteOverANewerTokensDocument is the same for
// tokens.
func TestTokenStoreRefusesToWriteOverANewerTokensDocument(t *testing.T) {
	m := persist.NewMemory()
	b := &otherProcessBackend{Memory: m}
	s, err := OpenTokenStore(b, TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Create("first", TokenKindAPI, "", nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	b.beforeSave = func() { overwrite(t, m, newerTokensDocument) }

	_, _, err = s.Create("second", TokenKindAPI, "", nil, time.Now())
	assertNamesBothVersions(t, err, 2, 1)
	assertPayload(t, m, newerTokensDocument)
}

// TestAV010AccountsDocumentLoadsAndGainsAVersion: v0.1.0 wrote no
// version. Such a document opens as version 1, unchanged, and the next
// save writes it as this build's version, 4.
func TestAV010AccountsDocumentLoadsAndGainsAVersion(t *testing.T) {
	m := persist.NewMemory()
	primeMemory(t, m, `{"users":[`+
		`{"id":"u1","username":"alice","passwordHash":"$argon2id$fake","role":"admin","createdAt":"2026-01-01T00:00:00Z"}]}`)

	s, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatalf("OpenStore refused a v0.1.0 document: %v", err)
	}
	if a := s.Admin(); a == nil || a.Username != "alice" {
		t.Fatalf("expected alice as admin, got %+v", a)
	}
	if err := s.mutate(func(*storeState) error { return nil }); err != nil {
		t.Fatal(err)
	}
	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(snap.Payload), "{\n  \"version\": 4,\n  \"users\": [") {
		t.Errorf("the saved accounts document does not carry version 4:\n%s", snap.Payload)
	}
}

// TestAV010TokensDocumentLoadsAndIsWrapped: v0.1.0 wrote the tokens
// document as a bare array. It opens as version 1, unchanged, and the
// next save writes it as an object with a version and a tokens list.
func TestAV010TokensDocumentLoadsAndIsWrapped(t *testing.T) {
	m := persist.NewMemory()
	primeMemory(t, m, `[{"id":"t1","name":"old","kind":"api","hashedValue":"fixture-hash","createdAt":"2026-01-01T00:00:00Z"}]`)

	s, err := OpenTokenStore(m, TokenOptions{})
	if err != nil {
		t.Fatalf("OpenTokenStore refused a v0.1.0 document: %v", err)
	}
	if got := s.List(); len(got) != 1 || got[0].ID != "t1" {
		t.Fatalf("List() = %+v, want the one v0.1.0 token", got)
	}
	if err := s.mutate(func(*tokenState) error { return nil }); err != nil {
		t.Fatal(err)
	}
	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(snap.Payload), "{\n  \"version\": 1,\n  \"tokens\": [\n    {\n      \"id\": \"t1\",") {
		t.Errorf("the saved document is not version 1 wrapping the token:\n%s", snap.Payload)
	}
}

// overwrite saves doc over whatever m holds, as another process would.
func overwrite(t *testing.T, m *persist.Memory, doc string) {
	t.Helper()
	snap, err := m.Load(context.Background())
	if err != nil {
		t.Error(err)
		return
	}
	if _, err := m.Save(context.Background(), []byte(doc), snap.Version); err != nil {
		t.Error(err)
	}
}

// assertPayload fails unless m still holds exactly want.
func assertPayload(t *testing.T, m *persist.Memory, want string) {
	t.Helper()
	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(snap.Payload) != want {
		t.Errorf("the newer document was overwritten:\n%s", snap.Payload)
	}
}
