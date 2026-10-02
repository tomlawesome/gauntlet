package gauntlet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/tomlawesome/gauntlet/persist"
)

// accountsFixture is a version-4 accounts document, written out by hand
// and frozen: it is the stored format as birdcage and mikroview hold it
// on disk, not what this build's structs happen to produce. A renamed
// or dropped JSON tag changes what loading it and saving it back
// writes, so TestMikroviewUsersJSONFixtureRoundTripsByteIdentical fails
// -- which a fixture marshalled from the structs themselves, as this
// one was before #29, could never do. Change it only alongside a new
// document version (see docversion.go).
//
// Mikroview users.json-shaped, plus gauntlet's own sessionsEndedAt,
// loginLockedUntil, loginLockoutCount, loginDisabledAt and
// knownBrowsers, never real user data: an admin with every field
// populated, including every second-factor kind (TOTP, two recovery
// codes, a passkey, an outstanding reset code, a lockout, a count of
// lockouts, a disabled sign-in, a remembered browser --
// data shape only; a real account would not carry all of these live at
// once), a plain local user, an SSO-linked account with no local
// password, and a roleless legacy account (loads as-is; see
// TestOpenLeavesAnEmptyRoleFailingClosed). The hashes are placeholders,
// not hashes of anything: nothing here authenticates. Users are in the
// username order a save writes them in.
const accountsFixture = `{
  "version": 4,
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
      "loginLockoutCount": 2,
      "loginDisabledAt": "2026-01-02T03:20:05Z",
      "knownBrowsers": [
        {
          "hash": "fixture-known-browser-hash",
          "issuedAt": "2026-01-02T04:04:05Z"
        }
      ],
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
		reflect.TypeFor[Passkey](), reflect.TypeFor[PasskeyFlags](), reflect.TypeFor[KnownBrowser]())

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

// lockoutLines are the fields accounts version 3 (#44) added, as the
// every-field fixture spells them.
const lockoutLines = "      \"loginLockoutCount\": 2,\n" +
	"      \"loginDisabledAt\": \"2026-01-02T03:20:05Z\",\n"

// knownBrowserLines is the field accounts version 4 (#44) added, as the
// every-field fixture spells it.
const knownBrowserLines = "      \"knownBrowsers\": [\n" +
	"        {\n" +
	"          \"hash\": \"fixture-known-browser-hash\",\n" +
	"          \"issuedAt\": \"2026-01-02T04:04:05Z\"\n" +
	"        }\n" +
	"      ],\n"

// fixtureAtVersion is the every-field fixture without the given lines
// and with its version set to version: an older document, as the build
// that wrote it would have.
func fixtureAtVersion(t *testing.T, version int, without ...string) string {
	t.Helper()
	doc := accountsFixture
	for _, line := range without {
		if !strings.Contains(doc, line) {
			t.Fatalf("the every-field fixture no longer has the line this test removes: %q", line)
		}
		doc = strings.Replace(doc, line, "", 1)
	}
	const current = `"version": 4,`
	if !strings.Contains(doc, current) {
		t.Fatal("the every-field fixture is no longer at version 4")
	}
	return strings.Replace(doc, current, `"version": `+strconv.Itoa(version)+`,`, 1)
}

// openSaveAndCompare opens doc, saves it with no change, and fails
// unless what is saved is exactly want.
func openSaveAndCompare(t *testing.T, doc, want string) *Store {
	t.Helper()
	m := persist.NewMemory()
	primeMemory(t, m, doc)
	s, err := OpenStore(m, Options{})
	if err != nil {
		t.Fatalf("OpenStore refused an older document: %v", err)
	}
	if err := s.mutate(func(*storeState) error { return nil }); err != nil {
		t.Fatalf("mutate: %v", err)
	}
	snap, err := m.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(snap.Payload) != want {
		t.Errorf("a saved older document differs from the fixture at version 4 without the fields it lacked:\n--- want ---\n%s\n--- saved ---\n%s",
			want, snap.Payload)
	}
	return s
}

// TestAVersion1AccountsDocumentOpensAndSavesAsVersion4: version 2
// (#28) only added sessionsEndedAt, version 3 (#44) only
// loginLockoutCount and loginDisabledAt, and version 4 (#44) only
// knownBrowsers, none of which a version-1 document -- gauntlet
// v0.2.0's, or mikroview's -- carries, and all of which read correctly
// as zero, so no migration code exists. The every-field fixture without
// them, at version 1, opens with them zero and the session cutoff at
// passwordChangedAt, and its next save writes exactly the fixture
// without them, now at version 4.
func TestAVersion1AccountsDocumentOpensAndSavesAsVersion4(t *testing.T) {
	const sessionsLine = "      \"sessionsEndedAt\": \"2026-01-02T03:06:05Z\",\n"
	v1 := fixtureAtVersion(t, 1, sessionsLine, lockoutLines, knownBrowserLines)
	want := fixtureAtVersion(t, 4, sessionsLine, lockoutLines, knownBrowserLines)

	s := openSaveAndCompare(t, v1, want)
	admin, ok := s.Get("admin-id-0001")
	if !ok {
		t.Fatal("the admin did not load")
	}
	if !admin.SessionsEndedAt.IsZero() {
		t.Errorf("SessionsEndedAt = %v from a document without it, want zero", admin.SessionsEndedAt)
	}
	if !admin.SessionCutoff().Equal(admin.PasswordChangedAt) {
		t.Errorf("SessionCutoff() = %v, want passwordChangedAt %v", admin.SessionCutoff(), admin.PasswordChangedAt)
	}
	if admin.LoginLockoutCount != 0 || !admin.LoginDisabledAt.IsZero() {
		t.Errorf("lockout count %d, disabled at %v from a document without them, want zero",
			admin.LoginLockoutCount, admin.LoginDisabledAt)
	}
}

// TestAVersion2AccountsDocumentOpensAndSavesAsVersion4: version 3 (#44)
// added loginLockoutCount and loginDisabledAt, which a version-2
// document does not carry and which read correctly as zero -- no
// lockouts counted, sign-in not disabled: no build that wrote version 2
// counted either. The every-field fixture without them (or version 4's
// knownBrowsers), at version 2, opens with both zero, its lockout still
// in force, and saves back as exactly the fixture without them at
// version 4.
func TestAVersion2AccountsDocumentOpensAndSavesAsVersion4(t *testing.T) {
	v2 := fixtureAtVersion(t, 2, lockoutLines, knownBrowserLines)
	want := fixtureAtVersion(t, 4, lockoutLines, knownBrowserLines)

	s := openSaveAndCompare(t, v2, want)
	admin, ok := s.Get("admin-id-0001")
	if !ok {
		t.Fatal("the admin did not load")
	}
	if admin.LoginLockoutCount != 0 || !admin.LoginDisabledAt.IsZero() {
		t.Errorf("lockout count %d, disabled at %v from a version-2 document, want zero",
			admin.LoginLockoutCount, admin.LoginDisabledAt)
	}
	if admin.LoginLockedUntil.IsZero() {
		t.Error("the version-2 document's lockout did not load")
	}
}

// TestAVersion3AccountsDocumentOpensAndSavesAsVersion4: version 4 (#44)
// added knownBrowsers, which a version-3 document does not carry and
// which reads correctly as none remembered: no browser carries a token
// a build without the field issued. The every-field fixture without it,
// at version 3, opens with no browser remembered and everything else
// intact, and saves back as exactly the fixture without it at version 4
// -- after which a build reading only up to version 3 refuses it
// (errNewerDocument).
func TestAVersion3AccountsDocumentOpensAndSavesAsVersion4(t *testing.T) {
	v3 := fixtureAtVersion(t, 3, knownBrowserLines)
	want := fixtureAtVersion(t, 4, knownBrowserLines)

	s := openSaveAndCompare(t, v3, want)
	admin, ok := s.Get("admin-id-0001")
	if !ok {
		t.Fatal("the admin did not load")
	}
	if len(admin.KnownBrowsers) != 0 {
		t.Errorf("KnownBrowsers = %+v from a version-3 document, want none", admin.KnownBrowsers)
	}
	if admin.LoginLockoutCount != 2 || admin.LoginDisabledAt.IsZero() {
		t.Error("the version-3 document's lockout fields did not load")
	}
	if err := checkDocumentVersion("accounts", accountsDocumentVersion, 3); !errors.Is(err, errNewerDocument) {
		t.Errorf("a version-3 build reading what this one saves: %v, want errNewerDocument", err)
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
