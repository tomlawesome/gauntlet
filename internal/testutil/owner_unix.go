//go:build unix

package testutil

import (
	"os"
	"syscall"
	"testing"
)

// GiveAway moves path to an owner or group other than this process's
// where it can, so a test can tell "a rewrite kept the file's owner"
// from "the writer's own": as root, to an arbitrary uid and gid; as
// anyone else, to a supplementary group if there is one. Otherwise the
// file stays the writer's own and the test can only show that keeping
// an unchanged owner does not fail; it reports which it managed.
func GiveAway(t *testing.T, path string) (moved bool) {
	t.Helper()
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 4242, 4243); err != nil {
			t.Fatal(err)
		}
		return true
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
			return true
		}
	}
	return false
}

// OwnerOf is path's uid and gid.
func OwnerOf(t *testing.T, path string) (uid, gid uint32) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return st.Uid, st.Gid
}
