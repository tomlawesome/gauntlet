//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tomlawesome/gauntlet/internal/testutil"
)

// #90 item 15: a rebuild run by another user (a CLI with sudo) keeps the
// owner and group of the list and checksum it replaces, as the other
// atomic writers do: the rename puts a fresh inode in place, and a list the
// server cannot read or replace is worse than a stale one.
func TestBuildKeepsTheExistingFilesOwners(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "top10k.txt")
	buildInto(t, out)

	type owner struct{ uid, gid uint32 }
	want := map[string]owner{}
	moved := true
	for _, p := range []string{out, out + ".sha256"} {
		if !testutil.GiveAway(t, p) {
			moved = false
		}
		uid, gid := testutil.OwnerOf(t, p)
		want[p] = owner{uid, gid}
	}
	if !moved {
		t.Skip("cannot give the files away as this user (not root, no supplementary group): the owner check would prove nothing")
	}

	before, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	buildInto(t, out)
	after, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the rebuild wrote a different list from the same corpus: test setup is unsound")
	}
	for p, w := range want {
		if uid, gid := testutil.OwnerOf(t, p); uid != w.uid || gid != w.gid {
			t.Errorf("%s owner = %d:%d after a rebuild, want the original %d:%d", filepath.Base(p), uid, gid, w.uid, w.gid)
		}
	}
}
