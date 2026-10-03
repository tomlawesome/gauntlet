package persist

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
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

// Save holds path+".lock" for its whole read-compare-write, so a
// concurrent Save (here, another goroutine, but flock does not
// distinguish that from another process) must wait for it rather than
// running in between the read and the rename.
func TestFileBackendSaveWaitsForTheLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	b := newFileBackend(path)
	v1, err := b.Save(context.Background(), []byte(`{"n":1}`), 0)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	held, err := lockFile(path + ".lock")
	if err != nil {
		t.Fatalf("lockFile: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := b.Save(context.Background(), []byte(`{"n":2}`), v1); err != nil {
			t.Errorf("Save while lock was held then released: %v", err)
		}
	}()

	select {
	case <-done:
		t.Fatal("Save returned before the held lock was released")
	case <-time.After(100 * time.Millisecond):
	}

	if err := held.unlock(); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Save did not return after the lock was released")
	}
}

// Without the lock, two processes (simulated here as goroutines against
// the same fileBackend) can each Load, both pass the version compare in
// Save, and both rename -- the later one silently discards the earlier
// write. With the lock, at most one Save against any given expect value
// can ever succeed.
func TestFileBackendConcurrentSavesNeverBothWinTheSameVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	b := newFileBackend(path)
	if _, err := b.Save(context.Background(), []byte(`{"n":0}`), 0); err != nil {
		t.Fatalf("create: %v", err)
	}

	const goroutines = 8
	const iterations = 50

	var mu sync.Mutex
	winsByExpect := make(map[int64]int)

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				snap, err := b.Load(context.Background())
				if err != nil {
					t.Errorf("Load: %v", err)
					return
				}
				payload := []byte(fmt.Sprintf(`{"g":%d,"i":%d}`, g, i))
				if _, err := b.Save(context.Background(), payload, snap.Version); err == nil {
					mu.Lock()
					winsByExpect[snap.Version]++
					mu.Unlock()
				} else if err != ErrConflict {
					t.Errorf("Save: unexpected error %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	for expect, wins := range winsByExpect {
		if wins > 1 {
			t.Fatalf("expect version %d won %d saves, want at most 1 -- a later rename silently discarded an earlier write", expect, wins)
		}
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
	// The lock file exists before the directory is made read-only, so
	// Save gets past taking the lock and fails where this test means it
	// to: creating the temp file for the write itself.
	if err := os.WriteFile(path+".lock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil { // read+execute, no write
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	b := newFileBackend(path)
	_, err := b.Save(context.Background(), []byte(`{"n":1}`), 0)
	if err == nil {
		t.Fatal("Save into a read-only directory succeeded, want the underlying write error")
	}
	if !strings.Contains(err.Error(), ".tmp-") {
		t.Fatalf("Save failed before reaching the write: %v", err)
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

// Save takes the sidecar lock before anything else, so a lock file it
// cannot open is a Save that fails before the version check, not one
// that quietly runs unlocked.
func TestFileBackendSaveFailsWhenTheLockFileCannotBeOpened(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	if err := os.Mkdir(path+".lock", 0o700); err != nil { // a directory cannot be opened O_RDWR
		t.Fatal(err)
	}
	b := newFileBackend(path)
	if _, err := b.Save(context.Background(), []byte(`{"n":1}`), 0); err == nil {
		t.Fatal("Save with an unopenable lock file succeeded, want an error")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("Save wrote the document without holding the lock: stat err = %v", err)
	}
}

// Backend.Describe goes into logs and StartupError.Location, so it must
// stay a short, single-line label: the file backends name their path
// and nothing else, and no backend may echo the document it holds or,
// for EncryptedFileBackend, its key in any common encoding. Each backend
// is described after a save, so a Describe that reached for state would
// have something to leak.
func TestEveryBackendDescribeIsShortAndCarriesNoSecrets(t *testing.T) {
	const marker = "describe-test-payload-marker"
	payload := []byte(`{"secret":"` + marker + `"}`)
	key := []byte("describe-test-key-bytes-not-real-0123456789")
	path := filepath.Join(t.TempDir(), "store.json")
	sealedPath := filepath.Join(t.TempDir(), "sealed.json")

	encrypted, err := NewEncryptedFileBackend(sealedPath, key)
	if err != nil {
		t.Fatalf("NewEncryptedFileBackend: %v", err)
	}
	cases := []struct {
		name     string
		b        Backend
		wantPath string // "" for a backend with no path
	}{
		{"Memory", NewMemory(), ""},
		{"fileBackend", newFileBackend(path), path},
		{"EncryptedFileBackend", encrypted, sealedPath},
	}
	leaks := []string{
		marker,
		string(key),
		hex.EncodeToString(key),
		base64.StdEncoding.EncodeToString(key),
		base64.RawURLEncoding.EncodeToString(key),
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.b.Save(context.Background(), payload, 0); err != nil {
				t.Fatalf("Save: %v", err)
			}
			got := c.b.Describe()
			if got == "" {
				t.Fatal("Describe returned nothing")
			}
			if limit := len(c.wantPath) + 32; len(got) > limit {
				t.Errorf("Describe() is %d bytes, want at most %d: %q", len(got), limit, got)
			}
			if strings.ContainsAny(got, "\r\n") {
				t.Errorf("Describe() spans lines: %q", got)
			}
			if c.wantPath != "" && !strings.Contains(got, c.wantPath) {
				t.Errorf("Describe() = %q, want it to name %q", got, c.wantPath)
			}
			for _, leak := range leaks {
				if strings.Contains(got, leak) {
					t.Errorf("Describe() = %q leaks %q", got, leak)
				}
			}
		})
	}
}
