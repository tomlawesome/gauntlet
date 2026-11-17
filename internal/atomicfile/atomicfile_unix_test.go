//go:build unix

package atomicfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tomlawesome/gauntlet/internal/testutil"
)

// A rewrite keeps the file's owner and group -- the rename puts a fresh
// inode in its place, owned by the writer -- and always sets perm.
func TestWriteFileKeepsOwnerAndGroupAndSetsTheMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kept")
	if err := WriteFile(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if !testutil.GiveAway(t, path) {
		t.Log("cannot give the file away as this user: only checking that an unchanged owner is kept")
	}
	wasUID, wasGID := testutil.OwnerOf(t, path)

	if err := WriteFile(path, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if uid, gid := testutil.OwnerOf(t, path); uid != wasUID || gid != wasGID {
		t.Errorf("owner after a rewrite = %d:%d, want the original %d:%d", uid, gid, wasUID, wasGID)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode after a rewrite = %v, want 0600", info.Mode().Perm())
	}
	if got, _ := os.ReadFile(path); string(got) != "two" {
		t.Errorf("contents = %q, want two", got)
	}
}

func TestKeepOwner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kept")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	testutil.GiveAway(t, path)
	wantUID, wantGID := testutil.OwnerOf(t, path)
	f, err := os.CreateTemp(dir, "tmp-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := KeepOwner(f, path); err != nil {
		t.Fatalf("KeepOwner: %v", err)
	}
	if uid, gid := testutil.OwnerOf(t, f.Name()); uid != wantUID || gid != wantGID {
		t.Errorf("temp file owner = %d:%d, want %d:%d", uid, gid, wantUID, wantGID)
	}
	if err := KeepOwner(f, filepath.Join(dir, "missing")); err != nil {
		t.Errorf("KeepOwner with nothing to copy from: %v", err)
	}
	if err := KeepOwner(f, filepath.Join(path, "under-a-file")); err == nil {
		t.Error("KeepOwner over a path it cannot stat succeeded")
	}
}
