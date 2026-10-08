//go:build unix

package geoip

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/internal/testutil"
)

// A refresh keeps the kept country file's and state.json's owner and
// group, as persist's store writes do (#80): the rename puts a fresh
// inode in place, and a refresh run by another user (a CLI with sudo)
// would otherwise leave files the server cannot read or replace.
func TestRefreshKeepsTheFilesOwners(t *testing.T) {
	e := newEnv(t, SourceIPinfo)
	e.fp.set("/ipinfo", buildDB(t, flat, "IS"))
	e.m.refresh(context.Background())
	db, state := filepath.Join(e.dir, "ipinfo.mmdb"), filepath.Join(e.dir, stateFileName)
	type owner struct{ uid, gid uint32 }
	want := map[string]owner{}
	for _, p := range []string{db, state} {
		if !testutil.GiveAway(t, p) {
			t.Log("cannot give the files away as this user: only checking that an unchanged owner is kept")
		}
		uid, gid := testutil.OwnerOf(t, p)
		want[p] = owner{uid, gid}
	}

	e.clock.Advance(25 * time.Hour)
	e.fp.set("/ipinfo", buildDB(t, flat, "JP"))
	e.m.refresh(context.Background())
	if c, _ := e.m.Country(inV4); c != "JP" {
		t.Fatalf("Country = %q after the refresh, want the new file's JP", c)
	}
	for p, w := range want {
		if uid, gid := testutil.OwnerOf(t, p); uid != w.uid || gid != w.gid {
			t.Errorf("%s owner = %d:%d after a refresh, want the original %d:%d", filepath.Base(p), uid, gid, w.uid, w.gid)
		}
	}
}
