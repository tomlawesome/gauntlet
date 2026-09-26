package gauntlet

import "time"

// RecoveryCode is the stored shape of one single-use fallback code, from
// mikroview's internal/auth/recoverycodes.go. Only the type is here for
// G2: a whole-document Store must round-trip every field the store
// persists (docs/design.md Summary), so User.RecoveryCodes has to
// compile and (un)marshal correctly even before this package generates,
// hashes or redeems a code itself. Generation (GenerateRecoveryCodes),
// hashing and single-use redemption (BurnRecoveryCode) are a later slice
// (G4).
type RecoveryCode struct {
	Hash   string    `json:"hash"`
	UsedAt time.Time `json:"usedAt,omitzero"`
}
