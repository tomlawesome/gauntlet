package persist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Encrypted over Memory (#50): the same guarantees
// encrypted_file_test.go pins for the file, now for any backend, plus
// the two things only the generic wrapper does -- store a text-safe
// envelope, and seal a plaintext document in place when told to.

func encryptedMemory(t *testing.T, seed byte, opts EncryptOptions) (*Encrypted, *Memory) {
	t.Helper()
	inner := NewMemory()
	if opts.Label == "" {
		opts.Label = "accounts"
	}
	b, err := Encrypt(inner, testKey(seed), opts)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return b, inner
}

func TestEncryptRefusesShortKeyNilBackendAndEmptyLabel(t *testing.T) {
	if _, err := Encrypt(NewMemory(), testKey(0x01)[:MinKeyBytes-1], EncryptOptions{Label: "accounts"}); err == nil {
		t.Error("Encrypt accepted a key shorter than MinKeyBytes, want a refusal")
	}
	if _, err := Encrypt(nil, testKey(0x01), EncryptOptions{Label: "accounts"}); err == nil {
		t.Error("Encrypt accepted a nil backend, want a refusal")
	}
	if _, err := Encrypt(NewMemory(), testKey(0x01), EncryptOptions{}); err == nil {
		t.Error("Encrypt accepted an empty label, want a refusal")
	}
}

// The inner backend must hold valid JSON with no trace of the
// plaintext: that is what lets mikroview's `payload text` column and
// birdcage's planned one carry the envelope.
func TestEncryptedSaveThenLoadRoundTripsThroughATextEnvelope(t *testing.T) {
	b, inner := encryptedMemory(t, 0x01, EncryptOptions{})
	ctx := context.Background()

	plaintext := []byte(`{"version":3,"users":[{"username":"tom","totpSecret":"JBSWY3DPEHPK3PXP"}]}`)
	v, err := b.Save(ctx, plaintext, 0)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	stored, err := inner.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(stored.Payload) {
		t.Errorf("stored payload is not valid JSON: %q", stored.Payload)
	}
	for _, marker := range []string{"tom", "JBSWY3DPEHPK3PXP", "users", "version"} {
		if bytes.Contains(stored.Payload, []byte(marker)) {
			t.Errorf("stored bytes contain plaintext marker %q -- the document is not actually encrypted", marker)
		}
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal(stored.Payload, &env); err != nil || len(env) != 1 || env["sealed"] == nil {
		t.Errorf("stored payload = %q, want a JSON object with the one member \"sealed\"", stored.Payload)
	}
	if stored.Version != v {
		t.Errorf("Save returned version %d, inner backend holds %d", v, stored.Version)
	}

	snap, err := b.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(snap.Payload, plaintext) || !snap.Exists || snap.Version != v {
		t.Errorf("Load = (%q, %d, %v), want (%q, %d, true)", snap.Payload, snap.Version, snap.Exists, plaintext, v)
	}
}

func TestEncryptedLoadOfNeverWrittenBackendIsNotAnError(t *testing.T) {
	b, _ := encryptedMemory(t, 0x01, EncryptOptions{})
	snap, err := b.Load(context.Background())
	if err != nil || snap.Exists {
		t.Errorf("Load of an unwritten backend = (%v, exists=%v), want (nil, false)", err, snap.Exists)
	}
}

func TestEncryptedTwoSavesOfSamePlaintextDiffer(t *testing.T) {
	b, inner := encryptedMemory(t, 0x01, EncryptOptions{})
	ctx := context.Background()
	v1, err := b.Save(ctx, []byte(`{"n":1}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := inner.Load(ctx)
	if _, err := b.Save(ctx, []byte(`{"n":1}`), v1); err != nil {
		t.Fatal(err)
	}
	second, _ := inner.Load(ctx)
	if bytes.Equal(first.Payload, second.Payload) {
		t.Error("two saves of the same plaintext produced identical ciphertext -- salt/nonce are not fresh")
	}
}

func TestEncryptedWrongKeyFailsToOpen(t *testing.T) {
	ctx := context.Background()
	inner := NewMemory()
	writer, err := Encrypt(inner, testKey(0x01), EncryptOptions{Label: "accounts"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Save(ctx, []byte(`{"n":1}`), 0); err != nil {
		t.Fatal(err)
	}
	reader, err := Encrypt(inner, testKey(0x02), EncryptOptions{Label: "accounts"})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := reader.Load(ctx)
	if err == nil {
		t.Fatal("Load under the wrong key succeeded, want a failure")
	}
	if snap.Exists || snap.Payload != nil {
		t.Error("a failed Load handed back a snapshot; nothing must come out of a document that did not open")
	}
	if !strings.Contains(err.Error(), inner.Describe()) {
		t.Errorf("error %q does not name the store (%q)", err, inner.Describe())
	}
}

// The label is authenticated: the same bytes under another store's
// label must not open, so a tokens document copied into the accounts
// row is refused rather than parsed.
func TestEncryptedDocumentUnderAnotherLabelFailsToOpen(t *testing.T) {
	ctx := context.Background()
	inner := NewMemory()
	writer, err := Encrypt(inner, testKey(0x01), EncryptOptions{Label: "tokens"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Save(ctx, []byte(`{"n":1}`), 0); err != nil {
		t.Fatal(err)
	}
	reader, err := Encrypt(inner, testKey(0x01), EncryptOptions{Label: "accounts"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Load(ctx); err == nil {
		t.Fatal("Load under another label succeeded, want the AAD check to refuse it")
	}
}

// Every way the stored envelope can be damaged is refused, and none of
// them is mistaken for a plaintext document to migrate -- even with
// MigratePlaintext on, damaged ciphertext must never be sealed over as
// if it were the document.
func TestEncryptedTamperedEnvelopeFailsToOpenAndIsNeverMigrated(t *testing.T) {
	ctx := context.Background()
	for _, migrate := range []bool{false, true} {
		b, inner := encryptedMemory(t, 0x01, EncryptOptions{MigratePlaintext: migrate})
		if _, err := b.Save(ctx, []byte(`{"n":1}`), 0); err != nil {
			t.Fatal(err)
		}
		good, _ := inner.Load(ctx)
		var env textEnvelope
		if err := json.Unmarshal(good.Payload, &env); err != nil {
			t.Fatal(err)
		}

		flipped := append([]byte(nil), env.Sealed...)
		flipped[len(flipped)-1] ^= 0x01
		flippedJSON, _ := json.Marshal(textEnvelope{Sealed: flipped})
		truncated, _ := json.Marshal(textEnvelope{Sealed: env.Sealed[:sealHeaderBytes+2]})
		noMagic, _ := json.Marshal(textEnvelope{Sealed: bytes.Repeat([]byte{0xAA}, len(env.Sealed))})

		cases := map[string][]byte{
			"flipped ciphertext byte": flippedJSON,
			"truncated envelope":      truncated,
			"envelope without magic":  noMagic,
			"base64 that is not":      []byte(`{"sealed":"not base64!"}`),
			"sealed member not text":  []byte(`{"sealed":42}`),
		}
		for name, raw := range cases {
			// Memory's version is a write count, so replacing the
			// payload moves it on; v is stale and expect = current.
			cur, _ := inner.Load(ctx)
			if _, err := inner.Save(ctx, raw, cur.Version); err != nil {
				t.Fatal(err)
			}
			if _, err := b.Load(ctx); err == nil {
				t.Errorf("migrate=%v: Load of a %s succeeded, want a failure", migrate, name)
			}
			after, _ := inner.Load(ctx)
			if !bytes.Equal(after.Payload, raw) {
				t.Errorf("migrate=%v: Load of a %s rewrote the stored document; damaged ciphertext must never be sealed over", migrate, name)
			}
		}
	}
}

// By default a plaintext document in the inner backend is refused like
// any other document that is not the wrapper's own ciphertext: anyone
// who can write the backend could otherwise replace the sealed
// document with one of their own and have it accepted.
func TestEncryptedPlaintextDocumentIsRefusedByDefault(t *testing.T) {
	ctx := context.Background()
	inner := NewMemory()
	plaintext := []byte(`{"version":3,"users":[]}`)
	if _, err := inner.Save(ctx, plaintext, 0); err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt(inner, testKey(0x01), EncryptOptions{Label: "accounts"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Load(ctx); err == nil {
		t.Fatal("Load of a plaintext document succeeded without MigratePlaintext, want a refusal")
	}
	after, _ := inner.Load(ctx)
	if !bytes.Equal(after.Payload, plaintext) {
		t.Error("a refused plaintext document was rewritten; without MigratePlaintext nothing may be written")
	}

	// Through Open it is the same fail-closed *StartupError a wrong key
	// gives, and the caller's decode never runs.
	decodeCalled := false
	_, _, err = Open(ctx, b, "the accounts store", func([]byte) error { decodeCalled = true; return nil })
	var startupErr *StartupError
	if !errors.As(err, &startupErr) {
		t.Fatalf("Open = %v (%T), want a *StartupError", err, err)
	}
	if decodeCalled {
		t.Error("decode was called against a document that was refused")
	}
}

// With MigratePlaintext on, the first Load seals the document in place:
// the inner backend holds ciphertext from then on, the version moves
// to the sealed document's, and the plaintext comes back unchanged.
func TestEncryptedMigratePlaintextSealsInPlaceOnFirstLoad(t *testing.T) {
	ctx := context.Background()
	inner := NewMemory()
	plaintext := []byte("{\n  \"version\": 3,\n  \"users\": [{\"username\": \"tom\", \"totpSecret\": \"JBSWY3DPEHPK3PXP\"}]\n}")
	v0, err := inner.Save(ctx, plaintext, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt(inner, testKey(0x01), EncryptOptions{Label: "accounts", MigratePlaintext: true})
	if err != nil {
		t.Fatal(err)
	}

	snap, err := b.Load(ctx)
	if err != nil {
		t.Fatalf("Load of a plaintext document with MigratePlaintext: %v", err)
	}
	if !bytes.Equal(snap.Payload, plaintext) {
		t.Errorf("Load = %q, want the plaintext unchanged", snap.Payload)
	}
	if snap.Version == v0 {
		t.Error("Load returned the plaintext document's version, want the sealed document's, which a later Save must expect")
	}

	stored, _ := inner.Load(ctx)
	if bytes.Contains(stored.Payload, []byte("JBSWY3DPEHPK3PXP")) {
		t.Error("the inner backend still holds the TOTP secret in the clear after the first Load")
	}
	if stored.Version != snap.Version {
		t.Errorf("Load returned version %d, inner backend holds %d", snap.Version, stored.Version)
	}

	// The returned version is usable: a Save with it is not a conflict,
	// and a second Load opens the sealed document without migrating.
	if _, err := b.Save(ctx, []byte(`{"version":3,"users":[]}`), snap.Version); err != nil {
		t.Errorf("Save with the version Load returned: %v", err)
	}
	if snap, err := b.Load(ctx); err != nil || string(snap.Payload) != `{"version":3,"users":[]}` {
		t.Errorf("second Load = (%q, %v)", snap.Payload, err)
	}

	// A sealed document is unaffected by the option, so leaving it on
	// costs nothing once the upgrade has happened.
	strict, _ := Encrypt(inner, testKey(0x01), EncryptOptions{Label: "accounts"})
	if _, err := strict.Load(ctx); err != nil {
		t.Errorf("Load of the migrated document without MigratePlaintext: %v", err)
	}
}

// Two processes upgrading the same plaintext document at once: the
// second one's in-place save conflicts, and it loads what the first
// wrote instead of failing or writing over it.
func TestEncryptedMigratePlaintextLoadsTheOtherWriterOnConflict(t *testing.T) {
	ctx := context.Background()
	inner := NewMemory()
	plaintext := []byte(`{"version":3,"users":[]}`)
	v0, err := inner.Save(ctx, plaintext, 0)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := Encrypt(inner, testKey(0x01), EncryptOptions{Label: "accounts"})
	racing := &saveInterposer{Memory: inner, before: func() {
		// The other process seals the document first.
		if _, err := other.Save(ctx, []byte(`{"version":3,"users":[],"by":"other"}`), v0); err != nil {
			t.Fatal(err)
		}
	}}
	b, err := Encrypt(racing, testKey(0x01), EncryptOptions{Label: "accounts", MigratePlaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := b.Load(ctx)
	if err != nil {
		t.Fatalf("Load whose in-place seal conflicted: %v", err)
	}
	if string(snap.Payload) != `{"version":3,"users":[],"by":"other"}` {
		t.Errorf("Load = %q, want the document the other writer sealed", snap.Payload)
	}
	if racing.saves != 1 {
		t.Errorf("the migrating Load wrote %d times, want 1 (the refused in-place seal)", racing.saves)
	}
}

// An in-place seal that fails for any reason other than a conflict is
// an error, not a silent fall-through to plaintext: the option promises
// the document is sealed once Load returns.
func TestEncryptedMigratePlaintextReportsAFailedSeal(t *testing.T) {
	ctx := context.Background()
	inner := NewMemory()
	if _, err := inner.Save(ctx, []byte(`{"version":3,"users":[]}`), 0); err != nil {
		t.Fatal(err)
	}
	broken := &saveInterposer{Memory: inner, err: errors.New("disk on fire")}
	b, err := Encrypt(broken, testKey(0x01), EncryptOptions{Label: "accounts", MigratePlaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Load(ctx); err == nil || !strings.Contains(err.Error(), "disk on fire") {
		t.Fatalf("Load = %v, want the save's own error", err)
	}
}

// The file backend's binary envelope opens through the generic wrapper
// too, so a document moved from a file into a database row under the
// same label and key keeps working.
func TestEncryptedOpensTheBinaryEnvelope(t *testing.T) {
	ctx := context.Background()
	inner := NewMemory()
	sealed, err := sealDocument(testKey(0x01), []byte("accounts"), []byte(`{"n":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inner.Save(ctx, sealed, 0); err != nil {
		t.Fatal(err)
	}
	b, _ := Encrypt(inner, testKey(0x01), EncryptOptions{Label: "accounts"})
	snap, err := b.Load(ctx)
	if err != nil || string(snap.Payload) != `{"n":1}` {
		t.Errorf("Load of a binary envelope = (%q, %v)", snap.Payload, err)
	}
}

func TestEncryptedVersionAndConflictAreTheInnerBackends(t *testing.T) {
	ctx := context.Background()
	b, inner := encryptedMemory(t, 0x01, EncryptOptions{})
	if _, exists, err := b.Version(ctx); err != nil || exists {
		t.Errorf("Version of an unwritten backend = (exists=%v, %v)", exists, err)
	}
	v, err := b.Save(ctx, []byte(`{"n":1}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	got, exists, err := b.Version(ctx)
	if err != nil || !exists || got != v {
		t.Errorf("Version = (%d, %v, %v), want (%d, true, nil)", got, exists, err, v)
	}
	if _, err := b.Save(ctx, []byte(`{"n":2}`), 0); !errors.Is(err, ErrConflict) {
		t.Errorf("second create = %v, want ErrConflict", err)
	}
	// Version never decrypts, so a document sealed under another key
	// still reports its version -- what lets a running server see that
	// a document it cannot open has changed.
	otherKey, _ := Encrypt(inner, testKey(0x02), EncryptOptions{Label: "accounts"})
	if got, exists, err := otherKey.Version(ctx); err != nil || !exists || got != v {
		t.Errorf("Version under another key = (%d, %v, %v), want (%d, true, nil)", got, exists, err, v)
	}
	// Without an inner VersionReader, Version falls back to Load.
	plain := &noVersionBackend{Memory: inner}
	viaLoad, _ := Encrypt(plain, testKey(0x01), EncryptOptions{Label: "accounts"})
	if got, exists, err := viaLoad.Version(ctx); err != nil || !exists || got != v {
		t.Errorf("Version via Load = (%d, %v, %v), want (%d, true, nil)", got, exists, err, v)
	}
}

func TestEncryptedDescribeCloseAndAtRest(t *testing.T) {
	b, inner := encryptedMemory(t, 0x01, EncryptOptions{})
	if b.Describe() != inner.Describe() {
		t.Errorf("Describe = %q, want the inner backend's %q", b.Describe(), inner.Describe())
	}
	if bytes.Contains([]byte(b.Describe()), testKey(0x01)) {
		t.Error("Describe leaked the key")
	}
	if err := b.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	var atRest AtRest = b
	if !atRest.ProtectedAtRest() {
		t.Error("Encrypted.ProtectedAtRest() = false")
	}
	if !NewMemory().ProtectedAtRest() {
		t.Error("Memory.ProtectedAtRest() = false; it has no storage to copy")
	}
	fileBacked, err := NewEncryptedFileBackend(t.TempDir()+"/store.json", testKey(0x01))
	if err != nil {
		t.Fatal(err)
	}
	if !fileBacked.ProtectedAtRest() {
		t.Error("EncryptedFileBackend.ProtectedAtRest() = false")
	}
}

// saveInterposer is Memory with a hook before each Save, for racing
// another writer in, and an optional error in place of the save.
type saveInterposer struct {
	*Memory
	before func()
	err    error
	saves  int
}

func (s *saveInterposer) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	s.saves++
	if s.before != nil {
		s.before()
	}
	if s.err != nil {
		return 0, s.err
	}
	return s.Memory.Save(ctx, payload, expect)
}

// noVersionBackend hides Memory's Version method, standing in for a
// backend without the VersionReader capability.
type noVersionBackend struct{ *Memory }

func (b *noVersionBackend) Version() {} // the wrong signature, so it is not a VersionReader
