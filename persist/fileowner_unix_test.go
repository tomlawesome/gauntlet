//go:build unix

package persist

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A store shared between a server and an app's CLI (persist.go's Backend
// doc) must come out of a Save still owned, grouped and moded as it went
// in: the rename puts a fresh inode in its place, and a CLI run with sudo
// would otherwise leave the server unable to read its own store.
func TestFileBackendSaveKeepsTheReplacedFilesModeOwnerAndGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	b := newFileBackend(path)
	v, err := b.Save(context.Background(), []byte(`{"n":1}`), 0)
	if err != nil {
		t.Fatalf("first Save: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := b.Save(context.Background(), []byte(`{"n":2}`), v); err != nil {
		t.Fatalf("second Save: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := after.Mode().Perm(); got != 0o640 {
		t.Errorf("mode after Save = %#o, want the original 0640", got)
	}
	was := before.Sys().(*syscall.Stat_t)
	now := after.Sys().(*syscall.Stat_t)
	if now.Uid != was.Uid || now.Gid != was.Gid {
		t.Errorf("owner after Save = %d:%d, want the original %d:%d", now.Uid, now.Gid, was.Uid, was.Gid)
	}
}

// A store this package creates still gets 0600: only a file that already
// exists lends the replacement its mode.
func TestFileBackendSaveCreatesANewFile0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	if _, err := newFileBackend(path).Save(context.Background(), []byte(`{}`), 0); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode of a new store = %#o, want 0600", got)
	}
}
