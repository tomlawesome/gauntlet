package gauntlet

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/tomlawesome/gauntlet/persist"
)

// accountsFixture is a version-1 accounts document, written out by hand
// and frozen: it is the stored format as birdcage and mikroview hold it
// on disk, not what this build's structs happen to produce. A renamed
// or dropped JSON tag changes what loading it and saving it back
// writes, so TestMikroviewUsersJSONFixtureRoundTripsByteIdentical fails
// -- which a fixture marshalled from the structs themselves, as this
// one was before #29, could never do. Change it only alongside a change
// to the stored format (see docversion.go).
//
// Mikroview users.json-shaped, plus gauntlet's own sessionsEndedAt and
// loginLockedUntil, never real user data: an admin with every field
// populated, including every second-factor kind (TOTP, two
// recovery codes, a passkey, an outstanding reset code, a lockout --
// data shape only; a real account would not carry all of these live at
// once), a plain local user, an SSO-linked account with no local
// password, and a roleless legacy account (loads as-is; see
// TestOpenLeavesAnEmptyRoleFailingClosed). The hashes are placeholders,
// not hashes of anything: nothing here authenticates. Users are in the
// username order a save writes them in.
const accountsFixture = `{
  "version": 1,
  "users": [
    {
      "id": "admin-id-0001",
      "username": "admin",
      "passwordHash": "$argon2id$fixture-admin-password-hash",
      "role": "admin",
      "createdAt": "2026-01-02T03:04:05Z",
      "lastLogin": "2026-01-02T04:04:05Z",
      "passwordChangedAt": "2026-01-02T03:04:05Z",
      "sessionsEndedAt": "2026-01-02T03:06:05Z",
      "hasLocalPassword": true,
      "roleChangedAt": "2026-01-02T03:05:05Z",
      "resetCodeHash": "$argon2id$fixture-reset-code-hash",
      "resetCodeExpiresAt": "2026-01-03T03:04:05Z",
      "mustChangePassword": true,
      "loginLockedUntil": "2026-01-02T03:19:05Z",
      "totpSecret": "JBSWY3DPEHPK3PXP",
      "totpConfirmedAt": "2026-01-02T03:04:05Z",
      "totpLastCounter": 99,
      "recoveryCodes": [
        {
          "hash": "fixture-recovery-hash-a"
        },
        {
          "hash": "fixture-recovery-hash-b",
          "usedAt": "2026-01-02T03:04:05Z"
        }
      ],
      "passkeys": [
        {
          "id": "Zml4dHVyZS1jcmVkZW50aWFsLWlk",
          "publicKey": "Zml4dHVyZS1wdWJsaWMta2V5LWJ5dGVz",
          "signCount": 7,
          "transports": [
            "usb",
            "nfc"
          ],
          "flags": {
            "userPresent": true,
            "userVerified": true,
            "backupEligible": true,
            "backupState": true
          },
          "rpId": "example.test",
          "name": "YubiKey",
          "createdAt": "2026-01-02T03:04:05Z",
          "lastUsedAt": "2026-01-02T05:04:05Z"
        }
      ]
    },
    {
      "id": "bob-id-0002",
      "username": "bob",
      "passwordHash": "$argon2id$fixture-bob-password-hash",
      "role": "user",
      "createdAt": "2026-01-02T03:04:05Z",
      "hasLocalPassword": true
    },
    {
      "id": "sso-id-0003",
      "username": "carol@example.com",
      "passwordHash": "$argon2id$fixture-unmatchable-hash",
      "role": "viewer",
      "createdAt": "2026-01-02T03:04:05Z",
      "lastLogin": "2026-01-02T03:04:05Z",
      "oidcIssuer": "https://idp.example",
      "oidcSubject": "sub-carol",
      "hasLocalPassword": false
    },
    {
      "id": "roleless-id-0004",
      "username": "legacy",
      "passwordHash": "$argon2id$fixture-bob-password-hash",
      "role": "",
      "createdAt": "2026-01-02T03:04:05Z",
      "hasLocalPassword": false
    }
  ]
}`

// TestMikroviewUsersJSONFixtureRoundTripsByteIdentical is gauntlet issue
// #3's (G2) and #5's (G4) done-when, held to a frozen fixture since #29:
// the accounts document above loads, saves and reloads byte-identical,
// so no field is dropped or renamed on the way through.
func TestMikroviewUsersJSONFixtureRoundTripsByteIdentical(t *testing.T) {
	assertFixtureCoversEveryField(t, accountsFixture,
		reflect.TypeFor[storeFile](), reflect.TypeFor[User](), reflect.TypeFor[RecoveryCode](),
		reflect.TypeFor[Passkey](), reflect.TypeFor[PasskeyFlags]())

	m := persist.NewMemory()
	primeMemory(t, m, accountsFixture)

	s1, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatalf("OpenStore (load): %v", err)
	}
	if s1.Count() != 4 {
		t.Fatalf("Count() = %d, want 4", s1.Count())
	}

	// Save: the same whole-document rewrite every real mutation goes
	// through (mutate), with no data actually changed here.
	if err := s1.mutate(func(*storeState) error { return nil }); err != nil {
		t.Fatalf("mutate: %v", err)
	}
	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatalf("Load after save: %v", err)
	}
	if string(snap.Payload) != accountsFixture {
		t.Errorf("saved document differs from the frozen fixture:\n--- fixture ---\n%s\n--- saved ---\n%s",
			accountsFixture, snap.Payload)
	}

	// Reload: a second Store opened fresh against the saved document
	// saves it back unchanged too.
	s2, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatalf("OpenStore (reload): %v", err)
	}
	resaved, err := encodeAccounts(&s2.storeState)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resaved, snap.Payload) {
		t.Errorf("reloaded document differs from the saved one:\n--- saved ---\n%s\n--- reloaded ---\n%s",
			snap.Payload, resaved)
	}
}

// assertFixtureCoversEveryField fails unless every JSON field of every
// type given appears somewhere in fixture -- so a field added to User
// or Token without being added to its frozen fixture is caught here,
// rather than going unchecked by the round trip.
func assertFixtureCoversEveryField(t *testing.T, fixture string, types ...reflect.Type) {
	t.Helper()
	var doc any
	if err := json.Unmarshal([]byte(fixture), &doc); err != nil {
		t.Fatalf("fixture does not parse: %v", err)
	}
	seen := map[string]bool{}
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, child := range v {
				seen[k] = true
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(doc)

	var missing []string
	for _, typ := range types {
		for f := range typ.Fields() {
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if !f.IsExported() || name == "" || name == "-" {
				continue
			}
			if !seen[name] {
				missing = append(missing, typ.Name()+"."+f.Name+" ("+name+")")
			}
		}
	}
	slices.Sort(missing)
	if len(missing) > 0 {
		t.Errorf("the frozen fixture does not populate: %s", strings.Join(missing, ", "))
	}
}
