package gauntlet

import (
	"os"
	"testing"

	"github.com/tomlawesome/gauntlet/internal/hashcost"
)

// TestMain runs this package's tests with cheap password hashes
// (internal/hashcost): the production cost is ~150 real Argon2id
// hashes across the suite for nothing the tests check. A test that is
// about the cost itself calls useProductionHashCost.
func TestMain(m *testing.M) {
	hashcost.Use(true)
	// dummyHash was made at the production cost as the package loaded;
	// an unknown-username login verifies against it, so remake it cheap.
	dummyHash = mustHashPassword("not-a-real-password-used-only-for-timing")
	os.Exit(m.Run())
}

// useProductionHashCost makes the rest of t hash at the production
// cost, for a test about the cost itself.
func useProductionHashCost(t *testing.T) {
	t.Helper()
	was := hashcost.Use(false)
	t.Cleanup(func() { hashcost.Use(was) })
}
