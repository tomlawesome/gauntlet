//go:build unix

package blocklist

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/internal/testutil"
)

// Storing a newer list keeps the stored copy's owner and group, as
// persist's store writes do (#80): the rename puts a fresh inode in
// place, and a refresh run by another user would otherwise leave a file
// the server cannot read or replace.
func TestStoringKeepsTheStoredCopysOwner(t *testing.T) {
	f := newFixture(t)
	data, sig := f.signedList(t, testBuilt, "a")
	f.reg.publish(data, sig)
	r := f.refresher(t, &List{})
	r.refresh(context.Background())
	p := filepath.Join(f.dir, storedPair)
	if !testutil.GiveAway(t, p) {
		t.Log("cannot give the file away as this user: only checking that an unchanged owner is kept")
	}
	wantUID, wantGID := testutil.OwnerOf(t, p)

	later := testBuilt.Add(24 * time.Hour)
	data2, sig2 := f.signedList(t, later, "b")
	f.reg.publish(data2, sig2)
	r.refresh(context.Background())
	if !r.Current().Built().Equal(later) {
		t.Fatalf("the later list was not adopted: Built=%v", r.Current().Built())
	}
	if uid, gid := testutil.OwnerOf(t, p); uid != wantUID || gid != wantGID {
		t.Errorf("%s owner = %d:%d after a refresh, want the original %d:%d", storedPair, uid, gid, wantUID, wantGID)
	}
}
