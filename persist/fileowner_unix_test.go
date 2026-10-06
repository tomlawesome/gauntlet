//go:build unix

package persist

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// giveAway moves path to an owner or group other than this process's
// where it can, so the owner checks below can tell "kept the original"
// from "the writer's own": as root, to an arbitrary uid and gid; as
// anyone else, to a supplementary group if there is one. Otherwise the
// file stays the writer's own and the checks can only show that copying
// an unchanged owner does not fail.
func giveAway(t *testing.T, path string) {
	t.Helper()
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 4242, 4243); err != nil {
			t.Fatal(err)
		}
		return
	}
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range groups {
		if g != os.Getegid() {
			if err := os.Chown(path, -1, g); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
}

func ownerOf(t *testing.T, path string) (uid, gid uint32) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return st.Uid, st.Gid
}

// A store shared between a server and an app's CLI (persist.go's Backend
// doc) must come out of a Save still owned and grouped as it went in:
// the rename puts a fresh inode in its place, and a CLI run with sudo
// would otherwise leave the server unable to read its own store. Its
// mode, though, is always put back to 0600.
func TestFileBackendSaveKeepsOwnerAndGroupAndResetsMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	b := newFileBackend(path)
	v, err := b.Save(context.Background(), []byte(`{"n":1}`), 0)
	if err != nil {
		t.Fatalf("first Save: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	giveAway(t, path)
	wasUID, wasGID := ownerOf(t, path)

	if _, err := b.Save(context.Background(), []byte(`{"n":2}`), v); err != nil {
		t.Fatalf("second Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode after Save = %#o, want 0600", got)
	}
	if uid, gid := ownerOf(t, path); uid != wasUID || gid != wasGID {
		t.Errorf("owner after Save = %d:%d, want the original %d:%d", uid, gid, wasUID, wasGID)
	}
}

// The sidecar lock is created by whichever writer first finds it
// missing. Made by a CLI run with sudo and left root-owned 0600, the
// server could never open it again, so it takes the store's owner and
// group like the store's own replacement does.
func TestLockFileCreatedBesideAStoreTakesItsOwnerAndGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	giveAway(t, path)
	wantUID, wantGID := ownerOf(t, path)

	lock, err := lockFile(context.Background(), path+".lock")
	if err != nil {
		t.Fatalf("lockFile: %v", err)
	}
	defer func() { _ = lock.unlock() }()
	if uid, gid := ownerOf(t, path+".lock"); uid != wantUID || gid != wantGID {
		t.Errorf("lock file owner = %d:%d, want the store's %d:%d", uid, gid, wantUID, wantGID)
	}
}

// A store this package creates still gets 0600.
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
