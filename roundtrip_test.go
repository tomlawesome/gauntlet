package gauntlet

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// TestMikroviewUsersJSONFixtureRoundTripsByteIdentical is gauntlet issue
// #3's (G2) and #5's (G4) done-when: a mikroview users.json-shaped
// fixture, built here rather than copied from mikroview, with every field
// populated including every second-factor kind, loads, saves and reloads
// byte-identical.
//
// The fixture is built from gauntlet's own User/RecoveryCode/Passkey
// types -- copied field-for-field, JSON tag-for-tag, from mikroview's
// internal/auth/store.go:81 (docs/design.md §1.3) -- never from real
// user data. It covers every field category a whole-document store must
// round-trip without dropping anything, per the design's Summary: an
// admin with every second-factor field populated (TOTP, two recovery
// codes, a passkey, and an outstanding admin-issued reset code -- data
// shape only; a real account would not carry all of these live at
// once), a plain local user, an SSO-linked account with no local
// password, and a roleless legacy account (loads as-is; see
// TestOpenLeavesAnEmptyRoleFailingClosed). Every password/code hash
// below is produced by this package's own HashPassword on a fixed test
// string -- a real Argon2id hash, but of a value invented for this
// test, never a secret from anywhere real.
func TestMikroviewUsersJSONFixtureRoundTripsByteIdentical(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	adminHash, err := HashPassword("fixture-admin-password-does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	bobHash, err := HashPassword("fixture-bob-password-does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	// Stands in for unmatchablePasswordHash's output on an SSO-only
	// account -- a real hash of a value nobody will ever type.
	ssoHash, err := HashPassword(newID())
	if err != nil {
		t.Fatal(err)
	}
	// Stands in for IssueResetCode's ResetCodeHash -- a real Argon2id
	// hash of a fixture code nobody will ever type.
	resetHash, err := HashPassword("FIXTURERESETCODE0000")
	if err != nil {
		t.Fatal(err)
	}

	// fixture.Users is already in the username-sorted order
	// tryPersistLocked writes ("admin" < "bob" < "carol@example.com" <
	// "legacy"), so a correct load-then-save is a no-op on the bytes.
	fixture := storeFile{
		Users: []*User{
			{
				ID:                 "admin-id-0001",
				Username:           "admin",
				PasswordHash:       adminHash,
				Role:               RoleAdmin,
				CreatedAt:          now,
				LastLogin:          now.Add(time.Hour),
				PasswordChangedAt:  now,
				HasLocalPassword:   true,
				ResetCodeHash:      resetHash,
				ResetCodeExpiresAt: now.Add(ResetCodeTTL),
				MustChangePassword: true,
				TOTPSecret:         "JBSWY3DPEHPK3PXP",
				TOTPConfirmedAt:    now,
				TOTPLastCounter:    99,
				RecoveryCodes: []RecoveryCode{
					{Hash: "fixture-recovery-hash-a"},
					{Hash: "fixture-recovery-hash-b", UsedAt: now},
				},
				Passkeys: []Passkey{
					{
						ID:         []byte("fixture-credential-id"),
						PublicKey:  []byte("fixture-public-key-bytes"),
						SignCount:  7,
						Transports: []string{"usb", "nfc"},
						Flags: PasskeyFlags{
							UserPresent:    true,
							UserVerified:   true,
							BackupEligible: true,
							BackupState:    false,
						},
						RPID:       "example.test",
						Name:       "YubiKey",
						CreatedAt:  now,
						LastUsedAt: now.Add(2 * time.Hour),
					},
				},
			},
			{
				ID:               "bob-id-0002",
				Username:         "bob",
				PasswordHash:     bobHash,
				Role:             RoleUser,
				CreatedAt:        now,
				HasLocalPassword: true,
			},
			{
				ID:               "sso-id-0003",
				Username:         "carol@example.com",
				PasswordHash:     ssoHash,
				Role:             RoleViewer,
				CreatedAt:        now,
				LastLogin:        now,
				OIDCIssuer:       "https://idp.example",
				OIDCSubject:      "sub-carol",
				HasLocalPassword: false,
			},
			{
				ID:           "roleless-id-0004",
				Username:     "legacy",
				PasswordHash: bobHash,
				// Role deliberately empty: a hand-edited or pre-roles
				// document, which must load as-is and fail closed.
				CreatedAt: now,
			},
		},
	}

	original, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshalling fixture: %v", err)
	}

	m := persist.NewMemory()
	primeMemory(t, m, string(original))

	// Load.
	s1, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatalf("OpenStore (load): %v", err)
	}
	if s1.Count() != len(fixture.Users) {
		t.Fatalf("Count() = %d, want %d", s1.Count(), len(fixture.Users))
	}

	// Save: the same whole-document rewrite every real mutation goes
	// through (tryPersistLocked), with no data actually changed here.
	s1.mu.Lock()
	saveErr := s1.tryPersistLocked()
	s1.mu.Unlock()
	if saveErr != nil {
		t.Fatalf("tryPersistLocked: %v", saveErr)
	}

	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatalf("Load after save: %v", err)
	}
	if !bytes.Equal(snap.Payload, original) {
		t.Errorf("saved document differs from the original fixture:\n--- original ---\n%s\n--- saved ---\n%s",
			original, snap.Payload)
	}

	// Reload: a second Store opened fresh against the now-saved document
	// must see the identical set of accounts, field for field.
	s2, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatalf("OpenStore (reload): %v", err)
	}
	if s2.Count() != len(fixture.Users) {
		t.Fatalf("reloaded Count() = %d, want %d", s2.Count(), len(fixture.Users))
	}
	for _, want := range fixture.Users {
		got, ok := s2.Get(want.ID)
		if !ok {
			t.Errorf("reloaded store is missing user %q", want.ID)
			continue
		}
		if !reflect.DeepEqual(*got, *want) {
			t.Errorf("reloaded user %q differs:\ngot  %+v\nwant %+v", want.ID, *got, *want)
		}
	}
}
