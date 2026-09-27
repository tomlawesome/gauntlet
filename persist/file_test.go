package persist

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Direct tests of the unexported fileBackend -- exercised only through
// EncryptedFileBackend elsewhere in this package's public tests, but its
// own conflict, error and atomic-write paths need covering in their own
// right (issue #18 ported this from mikroview's internal/persist.FileBackend
// verbatim; these pin the behaviour that porting must not change).

func TestFileBackendRoundTripAndClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	b := newFileBackend(path)
	if err := b.Close(); err != nil {
		t.Errorf("Close on an unused backend: %v", err)
	}

	v, err := b.Save(context.Background(), []byte(`{"n":1}`), 0)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	snap, err := b.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(snap.Payload) != `{"n":1}` || snap.Version != v || !snap.Exists {
		t.Errorf("Load = %+v, want payload {\"n\":1}, version %d, exists true", snap, v)
	}
	if err := b.Close(); err != nil {
		t.Errorf("Close after use: %v", err)
	}
}

func TestFileBackendSaveWithoutPathErrors(t *testing.T) {
	b := newFileBackend("")
	if _, err := b.Save(context.Background(), []byte(`{}`), 0); err == nil {
		t.Fatal("Save with no path configured succeeded, want an error")
	}
}

func TestFileBackendDoubleCreateIsConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	b := newFileBackend(path)
	if _, err := b.Save(context.Background(), []byte(`{"n":1}`), 0); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := b.Save(context.Background(), []byte(`{"n":2}`), 0); err != ErrConflict {
		t.Errorf("second create: got %v, want ErrConflict", err)
	}
}

func TestFileBackendStaleWriteIsConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	b := newFileBackend(path)
	v1, err := b.Save(context.Background(), []byte(`{"n":1}`), 0)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := b.Save(context.Background(), []byte(`{"n":2}`), v1); err != nil {
		t.Fatalf("update: %v", err)
	}
	if _, err := b.Save(context.Background(), []byte(`{"n":3}`), v1); err != ErrConflict {
		t.Errorf("stale write: got %v, want ErrConflict", err)
	}
}

func TestFileBackendExpectNonzeroButFileMissingIsConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	b := newFileBackend(path)
	if _, err := b.Save(context.Background(), []byte(`{"n":1}`), 12345); err != ErrConflict {
		t.Errorf("write against a nonexistent file expecting version 12345: got %v, want ErrConflict", err)
	}
}

func TestFileBackendSaveExistingFileUnreadableErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission bits behave differently on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	path := filepath.Join(t.TempDir(), "store.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	b := newFileBackend(path)
	if _, err := b.Save(context.Background(), []byte(`{"n":1}`), 999); err == nil {
		t.Fatal("Save against a permission-denied existing file succeeded, want an error")
	}
}

func TestFileBackendSaveWriteFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("write-permission bits behave differently on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")
	if err := os.Chmod(dir, 0o500); err != nil { // read+execute, no write
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	b := newFileBackend(path)
	if _, err := b.Save(context.Background(), []byte(`{"n":1}`), 0); err == nil {
		t.Fatal("Save into a read-only directory succeeded, want the underlying write error")
	}
}

func TestFileBackendLoadUnreadableFileErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission bits behave differently on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	path := filepath.Join(t.TempDir(), "store.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	b := newFileBackend(path)
	if _, err := b.Load(context.Background()); err == nil {
		t.Fatal("Load of a permission-denied file succeeded, want an error")
	}
}

func TestFileBackendMkdirFailureIsError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory-as-file collision behaves differently on windows")
	}
	base := t.TempDir()
	blocker := filepath.Join(base, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	// blocker is a plain file, so a directory cannot be created under it.
	path := filepath.Join(blocker, "sub", "store.json")
	b := newFileBackend(path)
	if _, err := b.Save(context.Background(), []byte(`{}`), 0); err == nil {
		t.Fatal("Save under a path whose parent is a file succeeded, want an error")
	}
}

// The three tests below call writeFileAtomic directly rather than
// through fileBackend.Save, so each forces one of its own failure
// branches without also having to get past Save's pre-write checks
// first (which, for two of these shapes, would themselves refuse the
// write before writeFileAtomic ever ran).

func TestWriteFileAtomicMkdirFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory-as-file collision behaves differently on windows")
	}
	base := t.TempDir()
	blocker := filepath.Join(base, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocker, "sub", "store.json")
	if err := writeFileAtomic(path, []byte("x"), 0o600); err == nil {
		t.Fatal("writeFileAtomic under a path whose parent is a file succeeded, want an error")
	}
}

func TestWriteFileAtomicCreateTempFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("write-permission bits behave differently on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil { // read+execute, no write
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	path := filepath.Join(dir, "store.json")
	if err := writeFileAtomic(path, []byte("x"), 0o600); err == nil {
		t.Fatal("writeFileAtomic in a read-only directory succeeded, want an error")
	}
}

func TestWriteFileAtomicRenameFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("rename-onto-a-directory behaves differently on windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")
	// A directory sitting at the destination path can never be replaced
	// by rename()ing a plain file over it.
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("x"), 0o600); err == nil {
		t.Fatal("writeFileAtomic onto an existing directory succeeded, want an error")
	}
}

func TestContentVersionNeverReturnsZero(t *testing.T) {
	// A vanishingly unlikely FNV-1a collision with 0 is handled
	// explicitly (contentVersion's comment); this just pins that the
	// function never hands back 0 for real input, which Save and Load
	// depend on to distinguish "no document" from "a document".
	if v := contentVersion([]byte("")); v == 0 {
		t.Error("contentVersion(\"\") == 0, want a nonzero sentinel-safe value")
	}
	if v := contentVersion([]byte("some content")); v == 0 {
		t.Error("contentVersion(...) == 0 for nonempty input")
	}
}
