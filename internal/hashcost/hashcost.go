// Package hashcost lets this module's own tests make password hashes
// cheaply. A production Argon2id hash costs 64 MiB and three passes by
// design (gauntlet's password.go), which is most of the root package's
// and gate's test time once every fixture account hashes a password.
//
// Only HashPassword reads it, and only for new hashes: a hash records
// its own cost, so one made cheaply verifies cheaply and one made at the
// production cost verifies at that cost, whatever this says. It is in
// internal/ so nothing outside this module can reach it, and Use refuses
// to switch to the cheap cost outside a test binary, so no production
// build can end up with it.
package hashcost

import (
	"sync/atomic"
	"testing"
)

// The cheap cost: the least Argon2id accepts with one thread, near
// enough. VerifyPassword's lower bound (8 KiB per thread) admits it.
const (
	Memory  uint32 = 64 // KiB
	Time    uint32 = 1
	Threads uint8  = 1
)

var cheap atomic.Bool

// Use switches new password hashes in this process to the cheap cost
// (on) or back to the production cost (off), and reports the setting it
// replaced so a test can put it back. Switching on panics outside a
// test binary.
func Use(on bool) (was bool) {
	if on && !testing.Testing() {
		panic("hashcost: the cheap password-hash cost is for this module's tests only")
	}
	return cheap.Swap(on)
}

// Cheap reports whether new password hashes use the cheap cost. False
// unless a test switched it on.
func Cheap() bool { return cheap.Load() }
