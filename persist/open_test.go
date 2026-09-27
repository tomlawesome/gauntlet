package persist

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Ported from mikroview's internal/persist/open_test.go, against Memory
// for everything except the Load-failure case: gauntlet ships no file
// backend, so there is no filesystem-permissions trick to force Load
// itself to fail, as mikroview's TestOpenLoadFailureFailsClosed does.
// TestOpenLoadFailureFailsClosed here instead reuses failingBackend
// (document_test.go), which returns an arbitrary error from Load
// directly.

// TestOpenAbsentDocumentIsFreshStart pins the "never written" half of
// Open's policy: no document at all is a normal first boot, not a
// failure, and decode must never be called against bytes that don't
// exist.
func TestOpenAbsentDocumentIsFreshStart(t *testing.T) {
	b := NewMemory()
	called := false
	version, existed, err := Open(context.Background(), b, "the test store", func(data []byte) error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("Open on a never-written document returned an error: %v", err)
	}
	if existed {
		t.Error("existed=true for a never-written document")
	}
	if version != 0 {
		t.Errorf("version = %d, want 0 for a never-written document", version)
	}
	if called {
		t.Error("decode was called for a document that doesn't exist")
	}
}

// TestOpenDecodeFailureFailsClosed is Open's core contract: a document
// that exists but cannot be decoded produces a *StartupError, not a
// partially-applied decode plus a nil error.
func TestOpenDecodeFailureFailsClosed(t *testing.T) {
	b := NewMemory()
	if _, err := b.Save(context.Background(), []byte("not valid json"), 0); err != nil {
		t.Fatalf("Save: %v", err)
	}

	var decodeCalledWith []byte
	_, existed, err := Open(context.Background(), b, "the test store", func(data []byte) error {
		decodeCalledWith = data
		return errors.New("boom: invalid syntax")
	})
	if err == nil {
		t.Fatal("Open returned a nil error for a decode failure, want fail-closed")
	}
	if existed {
		t.Error("existed=true on a decode failure, want false")
	}
	if string(decodeCalledWith) != "not valid json" {
		t.Errorf("decode was called with %q, want the stored bytes", decodeCalledWith)
	}

	var startupErr *StartupError
	if !errors.As(err, &startupErr) {
		t.Fatalf("err is not a *StartupError: %v (%T)", err, err)
	}
	if startupErr.Store != "the test store" {
		t.Errorf("StartupError.Store = %q, want %q", startupErr.Store, "the test store")
	}
	if startupErr.Location != b.Describe() {
		t.Errorf("StartupError.Location = %q, want %q", startupErr.Location, b.Describe())
	}
	if !errors.Is(err, startupErr.Err) {
		t.Error("StartupError does not unwrap to the decode error")
	}
}

// TestOpenLoadFailureFailsClosed covers Open's other fail-closed path:
// the backend's Load itself errors (a read failure, not a decode
// failure). Open must report a *StartupError and must never call decode
// against a document it couldn't even read.
func TestOpenLoadFailureFailsClosed(t *testing.T) {
	b := &failingBackend{err: errors.New("disk on fire")}

	called := false
	_, existed, err := Open(context.Background(), b, "the test store", func(data []byte) error {
		called = true
		return nil
	})
	if err == nil {
		t.Fatal("Open returned a nil error for a Load failure, want fail-closed")
	}
	if existed {
		t.Error("existed=true on a Load failure, want false")
	}
	if called {
		t.Error("decode was called for a document that could not even be loaded")
	}

	var startupErr *StartupError
	if !errors.As(err, &startupErr) {
		t.Fatalf("err is not a *StartupError: %v (%T)", err, err)
	}
	if startupErr.Store != "the test store" {
		t.Errorf("StartupError.Store = %q, want %q", startupErr.Store, "the test store")
	}
	if startupErr.Location != b.Describe() {
		t.Errorf("StartupError.Location = %q, want %q", startupErr.Location, b.Describe())
	}
	if !errors.Is(err, startupErr.Err) {
		t.Error("StartupError does not unwrap to the Load error")
	}
}

// TestStartupErrorMessageNamesStoreLocationCauseAndRemedy is the message
// an operator actually reads: it has to identify the store, where its
// document lives, what went wrong, and what to do about it.
func TestStartupErrorMessageNamesStoreLocationCauseAndRemedy(t *testing.T) {
	cause := errors.New("unexpected end of JSON input")
	e := &StartupError{Store: "the accounts store", Location: "memory store", Err: cause}
	msg := e.Error()

	for _, want := range []string{
		"the accounts store",
		"memory store",
		"unexpected end of JSON input",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q does not contain %q", msg, want)
		}
	}
	lower := strings.ToLower(msg)
	if !strings.Contains(lower, "restore") && !strings.Contains(lower, "backup") {
		t.Errorf("message %q does not mention restoring from a backup", msg)
	}
	if !strings.Contains(lower, "move") {
		t.Errorf("message %q does not mention moving the document aside to start fresh", msg)
	}
	if !strings.Contains(lower, "not a fresh install") && !strings.Contains(lower, "not a fresh") {
		t.Errorf("message %q does not say this is not a fresh install", msg)
	}
}

// TestOpenDecodeFailureLeavesTheDocumentUnchanged: Open only ever reads.
// A failed Open must never be the thing that leaves a store's document
// any different from how it found it.
func TestOpenDecodeFailureLeavesTheDocumentUnchanged(t *testing.T) {
	b := NewMemory()
	if _, err := b.Save(context.Background(), []byte("not valid json"), 0); err != nil {
		t.Fatalf("Save: %v", err)
	}
	before, err := b.Load(context.Background())
	if err != nil {
		t.Fatalf("Load before Open: %v", err)
	}

	_, _, err = Open(context.Background(), b, "the test store", func(data []byte) error {
		return errors.New("boom")
	})
	if err == nil {
		t.Fatal("expected Open to fail on a corrupt document")
	}

	after, err := b.Load(context.Background())
	if err != nil {
		t.Fatalf("Load after Open: %v", err)
	}
	if string(after.Payload) != string(before.Payload) {
		t.Errorf("the document changed across a failed Open: before %q, after %q", before.Payload, after.Payload)
	}
	if after.Version != before.Version {
		t.Errorf("the document's version changed across a failed Open: before %d, after %d", before.Version, after.Version)
	}
}

// TestOpenSuccessfulDecodePassesThroughTheVersion covers Open's normal
// path: an existing, well-formed document decodes cleanly and reports
// the version it was stored at.
func TestOpenSuccessfulDecodePassesThroughTheVersion(t *testing.T) {
	b := NewMemory()
	v, err := b.Save(context.Background(), []byte(`{"n":1}`), 0)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	var decoded string
	version, existed, err := Open(context.Background(), b, "the test store", func(data []byte) error {
		decoded = string(data)
		return nil
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !existed {
		t.Error("existed = false, want true")
	}
	if version != v {
		t.Errorf("version = %d, want %d", version, v)
	}
	if decoded != `{"n":1}` {
		t.Errorf("decode saw %q", decoded)
	}
}
