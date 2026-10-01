package gauntlet

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

var errTestBackendUnavailable = errors.New("backend unavailable")

// openTestStore returns a Store over a fresh persist.Memory backend.
// Every ported mikroview test that opened a temp-file store
// (filepath.Join(t.TempDir(), "users.json") + Open(path)) now opens one
// of these instead: gauntlet ships no file backend (persist.Backend is
// the seam applications implement; see persist/persist.go), only
// persist.Memory, for tests.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(persist.NewMemory(), Options{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	return s
}

// openTestStoreWithAdmin is openTestStore plus the first admin,
// "setup-admin", for tests about accounts that come after it -- SSO
// provisioning in particular, which never creates the first account
// (ErrSetupRequired).
func openTestStoreWithAdmin(t *testing.T) *Store {
	t.Helper()
	s := openTestStore(t)
	if _, err := s.Register("setup-admin", "setup-admin-password", time.Now()); err != nil {
		t.Fatalf("registering the first admin: %v", err)
	}
	return s
}

// primeMemory writes data as m's initial document, as if an external
// process -- or a hand-edited file -- had put it there before a Store
// first opens against it. Mirrors mikroview's os.WriteFile-before-Open
// fixtures.
func primeMemory(t *testing.T, m *persist.Memory, data string) {
	t.Helper()
	if _, err := m.Save(context.Background(), []byte(data), 0); err != nil {
		t.Fatalf("priming memory backend: %v", err)
	}
}

// failingSaveBackend lets OpenStore/Register succeed (nothing stored
// yet) but fails every Save -- for the rollback tests that need a
// backend which can never durably record the change a scoped call is
// about to make.
type failingSaveBackend struct{}

func (failingSaveBackend) Load(ctx context.Context) (persist.Snapshot, error) {
	return persist.Snapshot{}, nil
}
func (failingSaveBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	return 0, errTestBackendUnavailable
}
func (failingSaveBackend) Close() error     { return nil }
func (failingSaveBackend) Describe() string { return "failing test backend" }

// saveBudgetBackend allows a fixed number of Saves and then fails every
// one after, for the rollback cases where the change under test has to
// land on a store that already holds something.
type saveBudgetBackend struct{ left int }

func (b *saveBudgetBackend) Load(ctx context.Context) (persist.Snapshot, error) {
	return persist.Snapshot{}, nil
}
func (b *saveBudgetBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	if b.left <= 0 {
		return 0, errTestBackendUnavailable
	}
	b.left--
	return expect + 1, nil
}
func (b *saveBudgetBackend) Close() error     { return nil }
func (b *saveBudgetBackend) Describe() string { return "save-budget test backend" }

// setSecondFactorForTest sets userID's TOTP, recovery-code and passkey
// fields directly and persists them. This package doesn't yet implement
// the methods that generate these (SetPendingTOTPSecret,
// GenerateRecoveryCodes, AddPasskey -- a later slice), but
// LinkOIDCIdentity's clearing behaviour is in scope now and needs a
// fixture that already holds every kind of second factor, the same way
// mikroview's own enrolEverySecondFactor does through its real
// enrolment methods.
func setSecondFactorForTest(t *testing.T, s *Store, userID string, now time.Time) {
	t.Helper()
	err := s.mutate(func(st *storeState) error {
		u, ok := st.byID[userID]
		if !ok {
			return ErrUserNotFound
		}
		u.TOTPSecret = testTOTPSecret
		u.TOTPConfirmedAt = now
		u.TOTPLastCounter = 42
		u.RecoveryCodes = []RecoveryCode{{Hash: "fake-recovery-hash-1"}, {Hash: "fake-recovery-hash-2"}}
		u.Passkeys = []Passkey{{ID: []byte("test-credential-1"), PublicKey: []byte("test-public-key-1"), Name: "YubiKey", CreatedAt: now}}
		return nil
	})
	if err != nil {
		t.Fatalf("setSecondFactorForTest: persisting fixture for %q: %v", userID, err)
	}
}

// testTOTPSecret is opaque to the store, same as mikroview's own
// constant of the same name -- the shape here only has to look like the
// base32 a caller would actually store.
const testTOTPSecret = "JBSWY3DPEHPK3PXP"

// setTOTPForTest already exists in store_test.go (added alongside G2's
// TestUnconfirmedTOTPSecretIsNotAnActiveFactor, ahead of this slice) --
// reused here rather than redeclared.

// testPasskey builds a fixture Passkey with a distinct credential ID --
// id is folded into ID and PublicKey so every fixture in a test is
// trivially distinguishable in a failure message.
func testPasskey(id byte, name string) Passkey {
	return Passkey{
		ID:         []byte{id},
		PublicKey:  []byte{id, id, id},
		Transports: []string{"internal"},
		Flags: PasskeyFlags{
			UserPresent:    true,
			UserVerified:   true,
			BackupEligible: true,
			BackupState:    true,
		},
		RPID: "gauntlet.example",
		Name: name,
	}
}
