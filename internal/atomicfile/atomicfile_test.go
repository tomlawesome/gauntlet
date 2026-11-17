package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// These call WriteFile directly, so each forces one of its own failure
// branches (moved here from persist's tests with the writer, #80).

func TestWriteFileMkdirFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory-as-file collision behaves differently on windows")
	}
	base := t.TempDir()
	blocker := filepath.Join(base, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocker, "sub", "store.json")
	if err := WriteFile(path, []byte("x"), 0o600); err == nil {
		t.Fatal("WriteFile under a path whose parent is a file succeeded, want an error")
	}
}

func TestWriteFileCreateTempFailure(t *testing.T) {
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
	if err := WriteFile(path, []byte("x"), 0o600); err == nil {
		t.Fatal("WriteFile in a read-only directory succeeded, want an error")
	}
}

func TestWriteFileRenameFailure(t *testing.T) {
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
	if err := WriteFile(path, []byte("x"), 0o600); err == nil {
		t.Fatal("WriteFile onto an existing directory succeeded, want an error")
	}
}

func TestWriteFileReportsAParentThatIsNotADirectory(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "store")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The store's directory would have to be created inside a regular
	// file: MkdirAll refuses, and the save reports that instead of
	// pretending to have written anything.
	if err := WriteFile(filepath.Join(blocker, "store.json"), []byte("{}"), 0o600); err == nil {
		t.Fatal("a save under a regular file succeeded")
	}
}

func TestWriteFileReportsADirectoryItCannotWriteIn(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere, so the refusal cannot be produced")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	// The temp file cannot be created, so nothing is renamed and the
	// error comes back to the caller.
	if err := WriteFile(filepath.Join(dir, "store.json"), []byte("{}"), 0o600); err == nil {
		t.Fatal("a save into a read-only directory succeeded")
	}
}

func TestWriteFileReportsARenameItCannotMake(t *testing.T) {
	dir := t.TempDir()
	// A non-empty directory already sits where the store should go: the
	// temp file is written, the rename over it is refused, and the error
	// comes back instead of a store that silently went nowhere.
	target := filepath.Join(dir, "store.json")
	if err := os.MkdirAll(filepath.Join(target, "inside"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(target, []byte("{}"), 0o600); err == nil {
		t.Fatal("renaming the store over a non-empty directory succeeded")
	}
	left, _ := filepath.Glob(filepath.Join(dir, "store.json.tmp-*"))
	if len(left) != 0 {
		t.Fatalf("temp files left behind after the refused rename: %v", left)
	}
}

func TestWriteFileReportsAStoreItCannotStat(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can stat anything, so the refusal cannot be produced")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	// The directory exists but cannot be searched: whether a store is
	// already there is unknown, which is an error, not a fresh install.
	if err := WriteFile(filepath.Join(dir, "store.json"), []byte("{}"), 0o600); err == nil {
		t.Fatal("a save into an unsearchable directory succeeded")
	}
}
