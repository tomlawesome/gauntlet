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

// accountsFixture is a version-8 accounts document, written out by hand
// and frozen: it is the stored format as birdcage and mikroview hold it
// on disk, not what this build's structs happen to produce. A renamed
// or dropped JSON tag changes what loading it and saving it back
// writes, so TestMikroviewUsersJSONFixtureRoundTripsByteIdentical fails
// -- which a fixture marshalled from the structs themselves, as this
// one was before #29, could never do. Change it only alongside a new
// document version (see docversion.go).
//
// Its seq (#59) is 1, as if this were a document already saved once --
// a no-op save (below) bumps it to 2, since the counter goes up on
// every save, changed or not; bumpedSeq below is that one step.
//
// Mikroview users.json-shaped, plus gauntlet's own sessionsEndedAt,
// loginLockedUntil, loginLockoutCount, loginDisabledAt, knownBrowsers,
// breachCheckPending, totpPendingSince, heldEnrolment, seenCountries
// and lastPlace, never real
// user data: an admin with every field populated, including every
// second-factor kind (TOTP, two recovery codes, a passkey, an
// outstanding reset code, a lockout, a count of lockouts, a disabled
// sign-in, a remembered browser, a breach check still to make, an
// enrolment on hold, a remembered country and last place --
// data shape only; a real account would not carry all of these live at
// once), a plain local user, an SSO-linked account with no local
// password, and a roleless legacy account (loads as-is; see
// TestOpenLeavesAnEmptyRoleFailingClosed). The hashes are placeholders,
// not hashes of anything: nothing here authenticates. Users are in the
// username order a save writes them in.
const accountsFixture = `{
  "version": 8,
  "seq": 1,
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
      "breachCheckPending": true,
      "loginLockedUntil": "2026-01-02T03:19:05Z",
      "loginLockoutCount": 2,
      "loginDisabledAt": "2026-01-02T03:20:05Z",
      "knownBrowsers": [
        {
          "hash": "fixture-known-browser-hash",
          "issuedAt": "2026-01-02T04:04:05Z"
        }
      ],
      "seenCountries": [
        {
          "code": "GB",
          "lastAt": "2026-01-02T04:04:05Z"
        }
      ],
      "lastPlace": {
        "country": "GB",
        "latitude": 51.5,
        "longitude": -0.12,
        "radiusKm": 20,
        "at": "2026-01-02T04:04:05Z"
      },
      "totpSecret": "JBSWY3DPEHPK3PXP",
      "totpConfirmedAt": "2026-01-02T03:04:05Z",
      "totpLastCounter": 99,
      "totpPendingSince": "2026-01-02T03:03:05Z",
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
      ],
      "heldEnrolment": {
        "kind": "passkey",
        "passkey": {
          "id": "Zml4dHVyZS1oZWxkLWNyZWRlbnRpYWw=",
          "publicKey": "Zml4dHVyZS1oZWxkLXB1YmxpYy1rZXk=",
          "signCount": 0,
          "flags": {
            "userPresent": true,
            "userVerified": true,
            "backupEligible": false,
            "backupState": false
          },
          "rpId": "example.test",
          "name": "Spare key",
          "createdAt": "2026-01-02T05:10:05Z"
        },
        "recoveryCodes": [
          {
            "hash": "fixture-held-recovery-hash"
          }
        ],
        "heldUntil": "2026-01-02T05:20:05Z"
      }
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
		reflect.TypeFor[Passkey](), reflect.TypeFor[PasskeyFlags](), reflect.TypeFor[KnownBrowser](),
		reflect.TypeFor[HeldEnrolment](), reflect.TypeFor[SeenCountry](), reflect.TypeFor[LastPlace](),
		reflect.TypeFor[Location]())

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
	// The sequence counter (#59) goes up by one on every save, changed
	// or not, so the saved document is the fixture with seq advanced
	// one step, not byte-identical to it.
	want := bumpedSeq(t, accountsFixture)
	if string(snap.Payload) != want {
		t.Errorf("saved document differs from the frozen fixture (with seq advanced one save):\n--- want ---\n%s\n--- saved ---\n%s",
			want, snap.Payload)
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

// breachLines is the field accounts version 5 (#43) added, as the
// every-field fixture spells it.
const breachLines = "      \"breachCheckPending\": true,\n"

// seqLine is the top-level counter accounts version 6 (#59) added, as
// the every-field fixture spells it. Unlike lockoutLines and the other
// per-field lines above, this one sits outside "users" (fixtureAtVersion
// finds it the same way regardless).
const seqLine = "  \"seq\": 1,\n"

// holdLines are the fields accounts version 7 (#58) added, as the
// every-field fixture spells them: totpPendingLine inside the admin's
// TOTP fields, heldLines closing its record (with the comma that ends
// the passkeys before it).
const totpPendingLine = "      \"totpPendingSince\": \"2026-01-02T03:03:05Z\",\n"

const heldLines = ",\n" +
	"      \"heldEnrolment\": {\n" +
	"        \"kind\": \"passkey\",\n" +
	"        \"passkey\": {\n" +
	"          \"id\": \"Zml4dHVyZS1oZWxkLWNyZWRlbnRpYWw=\",\n" +
	"          \"publicKey\": \"Zml4dHVyZS1oZWxkLXB1YmxpYy1rZXk=\",\n" +
	"          \"signCount\": 0,\n" +
	"          \"flags\": {\n" +
	"            \"userPresent\": true,\n" +
	"            \"userVerified\": true,\n" +
	"            \"backupEligible\": false,\n" +
	"            \"backupState\": false\n" +
	"          },\n" +
	"          \"rpId\": \"example.test\",\n" +
	"          \"name\": \"Spare key\",\n" +
	"          \"createdAt\": \"2026-01-02T05:10:05Z\"\n" +
	"        },\n" +
	"        \"recoveryCodes\": [\n" +
	"          {\n" +
	"            \"hash\": \"fixture-held-recovery-hash\"\n" +
	"          }\n" +
	"        ],\n" +
	"        \"heldUntil\": \"2026-01-02T05:20:05Z\"\n" +
	"      }"

// unusualLines are the fields accounts version 8 (#55) added, as the
// every-field fixture spells them.
const unusualLines = "      \"seenCountries\": [\n" +
	"        {\n" +
	"          \"code\": \"GB\",\n" +
	"          \"lastAt\": \"2026-01-02T04:04:05Z\"\n" +
	"        }\n" +
	"      ],\n" +
	"      \"lastPlace\": {\n" +
	"        \"country\": \"GB\",\n" +
	"        \"latitude\": 51.5,\n" +
	"        \"longitude\": -0.12,\n" +
	"        \"radiusKm\": 20,\n" +
	"        \"at\": \"2026-01-02T04:04:05Z\"\n" +
	"      },\n"

// bumpedSeq returns doc with its "seq" advanced by one -- what one more
// no-op save produces, since the counter #59 added goes up on every
// save, changed or not. A document with no "seq" field at all (one
// fixtureAtVersion built below version 6, where the field does not
// exist yet) reads as zero and is stamped at 1 on that save instead.
func bumpedSeq(t *testing.T, doc string) string {
	t.Helper()
	const marker = `"seq": `
	if i := strings.Index(doc, marker); i >= 0 {
		numStart := i + len(marker)
		numEnd := numStart + strings.IndexByte(doc[numStart:], ',')
		n, err := strconv.Atoi(doc[numStart:numEnd])
		if err != nil {
			t.Fatalf("fixture seq is not a number: %v", err)
		}
		return doc[:numStart] + strconv.Itoa(n+1) + doc[numEnd:]
	}
	const versionMarker = `"version": `
	vi := strings.Index(doc, versionMarker)
	if vi < 0 {
		t.Fatal("fixture has no version field to stamp a seq line after")
	}
	lineEnd := strings.IndexByte(doc[vi:], '\n') + vi + 1
	return doc[:lineEnd] + seqLine + doc[lineEnd:]
}

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
	const current = `"version": 8,`
	if !strings.Contains(doc, current) {
		t.Fatal("the every-field fixture is no longer at version 8")
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
		t.Errorf("a saved older document differs from the fixture at version 8 without the fields it lacked:\n--- want ---\n%s\n--- saved ---\n%s",
			want, snap.Payload)
	}
	return s
}

// TestAVersion1AccountsDocumentOpensAndSavesAsVersion8: version 2
// (#28) only added sessionsEndedAt, version 3 (#44) only
// loginLockoutCount and loginDisabledAt, version 4 (#44) only
// knownBrowsers, version 5 (#43) only breachCheckPending, version 6
// (#59) only the top-level seq, and version 7 (#58) only
// totpPendingSince and heldEnrolment, none of which a version-1 document --
// gauntlet v0.2.0's, or mikroview's -- carries, and all of which read
// correctly as zero, so no migration code exists. The every-field
// fixture without them, at version 1, opens with them zero and the
// session cutoff at passwordChangedAt, and its next save writes exactly
// the fixture without the others, now at version 8 and seq 1 (stamped
// from zero).
func TestAVersion1AccountsDocumentOpensAndSavesAsVersion8(t *testing.T) {
	const sessionsLine = "      \"sessionsEndedAt\": \"2026-01-02T03:06:05Z\",\n"
	v1 := fixtureAtVersion(t, 1, sessionsLine, lockoutLines, knownBrowserLines, breachLines, seqLine, totpPendingLine, heldLines, unusualLines)
	want := fixtureAtVersion(t, 8, sessionsLine, lockoutLines, knownBrowserLines, breachLines, totpPendingLine, heldLines, unusualLines)

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

// TestAVersion2AccountsDocumentOpensAndSavesAsVersion8: version 3 (#44)
// added loginLockoutCount and loginDisabledAt, which a version-2
// document does not carry and which read correctly as zero -- no
// lockouts counted, sign-in not disabled: no build that wrote version 2
// counted either. The every-field fixture without them (or the later
// versions' knownBrowsers, breachCheckPending and seq), at version 2,
// opens with both zero, its lockout still in force, and saves back as
// exactly the fixture without the others at version 8, seq stamped at 1.
func TestAVersion2AccountsDocumentOpensAndSavesAsVersion8(t *testing.T) {
	v2 := fixtureAtVersion(t, 2, lockoutLines, knownBrowserLines, breachLines, seqLine, totpPendingLine, heldLines, unusualLines)
	want := fixtureAtVersion(t, 8, lockoutLines, knownBrowserLines, breachLines, totpPendingLine, heldLines, unusualLines)

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

// TestAVersion3AccountsDocumentOpensAndSavesAsVersion8: version 4 (#44)
// added knownBrowsers, which a version-3 document does not carry and
// which reads correctly as none remembered: no browser carries a token
// a build without the field issued. The every-field fixture without it
// (or version 5's breachCheckPending and version 6's seq), at version 3,
// opens with no browser remembered and everything else intact, and
// saves back as exactly the fixture without the others at version 8,
// seq stamped at 1 -- after which a build reading only up to version 3
// refuses it (errNewerDocument).
func TestAVersion3AccountsDocumentOpensAndSavesAsVersion8(t *testing.T) {
	v3 := fixtureAtVersion(t, 3, knownBrowserLines, breachLines, seqLine, totpPendingLine, heldLines, unusualLines)
	want := fixtureAtVersion(t, 8, knownBrowserLines, breachLines, totpPendingLine, heldLines, unusualLines)

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

// TestAVersion4AccountsDocumentOpensAndSavesAsVersion8: version 5 (#43)
// added breachCheckPending, which a version-4 document does not carry
// and which reads correctly as false -- no breach check owed: no build
// that wrote version 4 accepted a password HIBP had not answered for.
// The every-field fixture without it (or version 6's seq), at version 4,
// opens with no recheck pending and everything else intact, and saves
// back as exactly the fixture without them at version 8, seq stamped at
// 1 -- after which a build reading only up to version 4 refuses it
// (errNewerDocument), rather than drop a recheck that is owed. A
// version-6 document with the mark set opens with it set and round-trips
// (TestMikroviewUsersJSONFixtureRoundTripsByteIdentical, on the
// every-field fixture).
func TestAVersion4AccountsDocumentOpensAndSavesAsVersion8(t *testing.T) {
	v4 := fixtureAtVersion(t, 4, breachLines, seqLine, totpPendingLine, heldLines, unusualLines)
	want := fixtureAtVersion(t, 8, breachLines, totpPendingLine, heldLines, unusualLines)

	s := openSaveAndCompare(t, v4, want)
	admin, ok := s.Get("admin-id-0001")
	if !ok {
		t.Fatal("the admin did not load")
	}
	if admin.BreachCheckPending {
		t.Error("BreachCheckPending is set from a version-4 document, want false")
	}
	if len(admin.KnownBrowsers) != 1 || !admin.MustChangePassword {
		t.Error("the version-4 document's other fields did not load")
	}
	if err := checkDocumentVersion("accounts", accountsDocumentVersion, 4); !errors.Is(err, errNewerDocument) {
		t.Errorf("a version-4 build reading what this one saves: %v, want errNewerDocument", err)
	}

	v8 := openSaveAndCompare(t, accountsFixture, bumpedSeq(t, accountsFixture))
	if admin, _ := v8.Get("admin-id-0001"); !admin.BreachCheckPending {
		t.Error("BreachCheckPending did not load from a version-8 document")
	}
}

// TestAVersion5AccountsDocumentOpensAndSavesAsVersion8 is #59's own
// migration step: version 6 added the top-level seq counter, which a
// version-5 document -- the one the build immediately before this one
// writes -- does not carry, and which reads correctly as zero (no save
// has happened under this process's watch yet). The every-field fixture
// without it (or version 7's fields) opens with every other field intact
// and saves back as exactly the fixture without version 7's fields, seq
// stamped at 1 -- an older document loading
// with the counter at zero and being stamped on its next save, as
// docs/design.md §4 describes.
func TestAVersion5AccountsDocumentOpensAndSavesAsVersion8(t *testing.T) {
	v5 := fixtureAtVersion(t, 5, seqLine, totpPendingLine, heldLines, unusualLines)
	want := fixtureAtVersion(t, 8, totpPendingLine, heldLines, unusualLines)

	s := openSaveAndCompare(t, v5, want)
	admin, ok := s.Get("admin-id-0001")
	if !ok {
		t.Fatal("the admin did not load")
	}
	if !admin.BreachCheckPending || len(admin.KnownBrowsers) != 1 {
		t.Error("the version-5 document's fields did not load")
	}
}

// TestAVersion6AccountsDocumentOpensAndSavesAsVersion8 is #58's own
// migration step: version 7 added totpPendingSince and heldEnrolment,
// which a version-6 document does not carry and which read correctly as
// zero and nil -- nothing on hold. The every-field fixture without them
// opens with every other field intact and saves back as exactly the
// fixture without them at version 7 -- after which a build reading only
// up to version 6 refuses it (errNewerDocument), rather than drop an
// enrolment on hold.
func TestAVersion6AccountsDocumentOpensAndSavesAsVersion8(t *testing.T) {
	v6 := fixtureAtVersion(t, 6, totpPendingLine, heldLines, unusualLines)
	want := bumpedSeq(t, fixtureAtVersion(t, 8, totpPendingLine, heldLines, unusualLines))

	s := openSaveAndCompare(t, v6, want)
	admin, ok := s.Get("admin-id-0001")
	if !ok {
		t.Fatal("the admin did not load")
	}
	if admin.HeldEnrolment != nil || !admin.TOTPPendingSince.IsZero() {
		t.Errorf("a version-6 document loaded a hold %+v and pending-since %v, want neither", admin.HeldEnrolment, admin.TOTPPendingSince)
	}
	if len(admin.Passkeys) != 1 || !admin.BreachCheckPending {
		t.Error("the version-6 document's other fields did not load")
	}
	if err := checkDocumentVersion("accounts", accountsDocumentVersion, 6); !errors.Is(err, errNewerDocument) {
		t.Errorf("a version-6 build reading what this one saves: %v, want errNewerDocument", err)
	}

	v8 := openSaveAndCompare(t, accountsFixture, bumpedSeq(t, accountsFixture))
	admin, _ = v8.Get("admin-id-0001")
	if admin.HeldEnrolment == nil || admin.HeldEnrolment.Passkey == nil || admin.HeldEnrolment.Passkey.Name != "Spare key" {
		t.Errorf("the version-7 hold did not load: %+v", admin.HeldEnrolment)
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

// TestAVersion7AccountsDocumentOpensAndSavesAsVersion8 is #55's own
// migration step: version 8 added seenCountries and lastPlace, which a
// version-7 document does not carry and which read correctly as nothing
// remembered -- so the first sign-in after the upgrade sets a baseline
// and raises nothing. The every-field fixture without them opens with
// every other field intact and saves back as exactly the fixture
// without them at version 8 -- after which a build reading only up to
// version 7 refuses it (errNewerDocument), rather than drop what the
// account remembers.
func TestAVersion7AccountsDocumentOpensAndSavesAsVersion8(t *testing.T) {
	v7 := fixtureAtVersion(t, 7, unusualLines)
	want := bumpedSeq(t, fixtureAtVersion(t, 8, unusualLines))

	s := openSaveAndCompare(t, v7, want)
	admin, ok := s.Get("admin-id-0001")
	if !ok {
		t.Fatal("the admin did not load")
	}
	if admin.SeenCountries != nil || admin.LastPlace != nil {
		t.Errorf("a version-7 document loaded countries %+v and place %+v, want neither", admin.SeenCountries, admin.LastPlace)
	}
	if len(admin.KnownBrowsers) != 1 || admin.HeldEnrolment == nil {
		t.Error("the version-7 document's other fields did not load")
	}
	if err := checkDocumentVersion("accounts", accountsDocumentVersion, 7); !errors.Is(err, errNewerDocument) {
		t.Errorf("a version-7 build reading what this one saves: %v, want errNewerDocument", err)
	}

	v8 := openSaveAndCompare(t, accountsFixture, bumpedSeq(t, accountsFixture))
	admin, _ = v8.Get("admin-id-0001")
	want8 := LastPlace{Country: "GB", Location: Location{Latitude: 51.5, Longitude: -0.12, RadiusKm: 20}, At: admin.KnownBrowsers[0].IssuedAt}
	if len(admin.SeenCountries) != 1 || admin.SeenCountries[0].Code != "GB" || admin.LastPlace == nil || *admin.LastPlace != want8 {
		t.Errorf("the version-8 countries and place did not load: %+v %+v", admin.SeenCountries, admin.LastPlace)
	}
}
