package gate

import (
	"os"
	"testing"

	"github.com/tomlawesome/gauntlet/internal/hashcost"
)

// TestMain runs gate's tests with cheap password hashes
// (internal/hashcost): every fixture account hashes a password, and
// nothing here is about the Argon2id cost.
func TestMain(m *testing.M) {
	hashcost.Use(true)
	os.Exit(m.Run())
}
