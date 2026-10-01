package gauntlet

import (
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// The tests in this file are the invariant half of #21: a write whose
// save is refused because another process wrote first is replayed
// against the fresh document, and every check that protects an
// invariant has to be made again against that document, not carried
// over from the one this process decided on. Each test slips the other
// process's write in just before this store's save (otherProcessBackend,
// mutate_test.go) and changes exactly the fact the check decides on.

// openRacingStores opens a store over an otherProcessBackend and a
// second store on the same document, after setup has run on the first:
// the second is the other process, and has seen everything setup did.
func openRacingStores(t *testing.T, setup func(s *Store)) (s *Store, b *otherProcessBackend, other *Store) {
	t.Helper()
	m := persist.NewMemory()
	b = &otherProcessBackend{Memory: m}
	s, err := OpenStore(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if setup != nil {
		setup(s)
	}
	other, err = OpenStore(m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return s, b, other
}

// TestGenerateRecoveryCodesIfAbsentRedecidesOnReplay: another process
// mints alice's recovery codes after this one checked and found none.
// The replay must find that set and report alreadyIssued, leaving the
// codes the other process showed its user working -- not replace them
// with a set nobody will ever see.
func TestGenerateRecoveryCodesIfAbsentRedecidesOnReplay(t *testing.T) {
	now := time.Now()
	var aliceID string
	s, b, other := openRacingStores(t, func(s *Store) {
		alice, err := s.Register("alice", "password123", now)
		if err != nil {
			t.Fatal(err)
		}
		aliceID = alice.ID
	})

	var otherCodes []string
	b.beforeSave = func() {
		codes, already, err := other.GenerateRecoveryCodesIfAbsent(aliceID, now)
		if err != nil || already {
			t.Errorf("the other process's GenerateRecoveryCodesIfAbsent = %v, %v", already, err)
		}
		otherCodes = codes
	}

	codes, already, err := s.GenerateRecoveryCodesIfAbsent(aliceID, now)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodesIfAbsent across a conflicting write: %v", err)
	}
	if !already || codes != nil {
		t.Fatalf("GenerateRecoveryCodesIfAbsent = %d codes, alreadyIssued %v; want none and true -- the other process issued a set first", len(codes), already)
	}
	if len(otherCodes) == 0 {
		t.Fatal("the other process minted nothing")
	}
	reopened, err := OpenStore(b.Memory, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := reopened.BurnRecoveryCode(aliceID, otherCodes[0], now); err != nil || !ok {
		t.Errorf("a code the other process showed its user no longer works (ok %v, err %v): its set was replaced", ok, err)
	}
}
