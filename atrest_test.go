package gauntlet

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet/persist"
)

// Secrets at rest on every backend (#50): the accounts store refuses a
// backend that keeps the document in the clear unless the application
// says it accepts that, and over persist.Encrypt the backend never sees
// a TOTP secret or a passkey public key, while the store's own answers
// -- Get, List, code verification -- are unchanged.

// plaintextBackend is Memory hidden behind a type without
// ProtectedAtRest: what an application's own database table looks like
// to the store before it is wrapped. It counts Loads so a test can show
// the refusal happens before the backend is touched.
type plaintextBackend struct {
	inner *persist.Memory
	loads int
}

func (b *plaintextBackend) Load(ctx context.Context) (persist.Snapshot, error) {
	b.loads++
	return b.inner.Load(ctx)
}

func (b *plaintextBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	return b.inner.Save(ctx, payload, expect)
}

func (b *plaintextBackend) Close() error     { return nil }
func (b *plaintextBackend) Describe() string { return "plaintext test backend" }

func testEncryptKey() []byte { return bytes.Repeat([]byte{0x42}, persist.MinKeyBytes) }

func encryptedMemoryBackend(t *testing.T, inner *persist.Memory, migrate bool) *persist.Encrypted {
	t.Helper()
	b, err := persist.Encrypt(inner, testEncryptKey(), persist.EncryptOptions{Label: "accounts", MigratePlaintext: migrate})
	if err != nil {
		t.Fatalf("persist.Encrypt: %v", err)
	}
	return b
}

// No key configured: the store refuses to open rather than keep the
// TOTP secrets in the clear with a warning nobody reads. The tokens
// store, whose document holds only hashes of random values, has no
// such check.
func TestOpenStoreRefusesABackendThatStoresPlaintextAtRest(t *testing.T) {
	b := &plaintextBackend{inner: persist.NewMemory()}
	s, err := OpenStore(b, Options{})
	if !errors.Is(err, ErrPlaintextAtRest) {
		t.Fatalf("OpenStore over a plaintext backend = (%v, %v), want ErrPlaintextAtRest", s, err)
	}
	if s != nil {
		t.Error("OpenStore handed back a store it refused to open")
	}
	if b.loads != 0 {
		t.Errorf("the backend was read %d times before the refusal; the decision needs nothing from it", b.loads)
	}
	if _, err := OpenTokenStore(b, TokenOptions{}); err != nil {
		t.Errorf("OpenTokenStore over a plaintext backend: %v, want it accepted (the tokens document holds no secret)", err)
	}
}

func TestOpenStoreAcceptsPlaintextAtRestOnlyWhenTold(t *testing.T) {
	b := &plaintextBackend{inner: persist.NewMemory()}
	s, err := OpenStore(b, Options{AllowPlaintextAtRest: true})
	if err != nil {
		t.Fatalf("OpenStore with AllowPlaintextAtRest: %v", err)
	}
	if _, err := s.Register("admin", "admin-password", time.Now()); err != nil {
		t.Errorf("Register over the accepted backend: %v", err)
	}

	// The backends that are fine without being told: none (nothing is
	// stored), Memory (nothing survives the process) and Encrypt.
	if _, err := OpenStore(nil, Options{}); err != nil {
		t.Errorf("OpenStore(nil): %v", err)
	}
	if _, err := OpenStore(persist.NewMemory(), Options{}); err != nil {
		t.Errorf("OpenStore(Memory): %v", err)
	}
	if _, err := OpenStore(encryptedMemoryBackend(t, persist.NewMemory(), false), Options{}); err != nil {
		t.Errorf("OpenStore(Encrypt(Memory)): %v", err)
	}
}

// Over persist.Encrypt the stored bytes carry neither the TOTP secret
// nor the passkey public key, List still blanks both on the copies it
// hands out, and the store itself still has the secret: a code
// verifies, before and after reopening under the same key.
func TestStoreOverEncryptedBackendKeepsSecretsOutOfStorageAndOutOfList(t *testing.T) {
	inner := persist.NewMemory()
	s, err := OpenStore(encryptedMemoryBackend(t, inner, false), Options{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	admin, err := s.Register("admin", "admin-password", now)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	const secret = "JBSWY3DPEHPK3PXP"
	if err := s.SetPendingTOTPSecret(admin.ID, secret); err != nil {
		t.Fatalf("SetPendingTOTPSecret: %v", err)
	}
	if err := s.ConfirmTOTP(admin.ID, now, 0); err != nil {
		t.Fatalf("ConfirmTOTP: %v", err)
	}
	publicKey := []byte("public-key-bytes-that-must-not-be-stored-in-the-clear")
	if _, err := s.AddPasskey(admin.ID, Passkey{ID: []byte("credential-id"), PublicKey: publicKey, RPID: "example.test", Name: "key", CreatedAt: now}); err != nil {
		t.Fatalf("AddPasskey: %v", err)
	}

	stored, err := inner.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for name, marker := range map[string][]byte{
		"TOTP secret":            []byte(secret),
		"passkey public key":     []byte(base64.StdEncoding.EncodeToString(publicKey)),
		"raw passkey public key": publicKey,
		"username":               []byte("admin"),
		"field name":             []byte("passwordHash"),
	} {
		if bytes.Contains(stored.Payload, marker) {
			t.Errorf("the backend holds the %s in the clear", name)
		}
	}

	for _, u := range s.List() {
		if u.TOTPSecret != "" || u.Passkeys != nil {
			t.Errorf("List exposes TOTPSecret=%q Passkeys=%v", u.TOTPSecret, u.Passkeys)
		}
		if !u.HasActiveTOTP() || u.PasskeyCount() != 1 {
			t.Errorf("List copy answers HasActiveTOTP=%v PasskeyCount=%d, want true and 1", u.HasActiveTOTP(), u.PasskeyCount())
		}
	}

	codeFor := func(at time.Time) string {
		raw, err := DecodeTOTPSecret(secret)
		if err != nil {
			t.Fatal(err)
		}
		return GenerateTOTPCode(raw, uint64(at.Unix())/30)
	}
	later := now.Add(10 * time.Minute)
	if ok, err := s.VerifyAndRecordTOTP(admin.ID, codeFor(later), later); err != nil || !ok {
		t.Errorf("VerifyAndRecordTOTP = (%v, %v), want (true, nil)", ok, err)
	}

	// A new process under the same key reads everything back.
	reopened, err := OpenStore(encryptedMemoryBackend(t, inner, false), Options{})
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	got, ok := reopened.Get(admin.ID)
	if !ok || got.TOTPSecret != secret || got.PasskeyCount() != 1 || !bytes.Equal(got.Passkeys[0].PublicKey, publicKey) {
		t.Fatalf("reopened Get = %+v, %v", got, ok)
	}
	later = later.Add(10 * time.Minute)
	if ok, err := reopened.VerifyAndRecordTOTP(admin.ID, codeFor(later), later); err != nil || !ok {
		t.Errorf("VerifyAndRecordTOTP after reopening = (%v, %v), want (true, nil)", ok, err)
	}
}

// The upgrade path for an application that already has a plaintext
// accounts document in its database: wrapped with MigratePlaintext,
// OpenStore reads it, seals it in place, and from then on the store
// works exactly as over a document that was always sealed -- writes
// succeed, a strict reopen (no MigratePlaintext) opens it, and the
// secrets came through. Without MigratePlaintext the same document is
// refused, fail-closed, as a *persist.StartupError.
func TestOpenStoreUpgradesAPlaintextDocumentWhenTold(t *testing.T) {
	inner := persist.NewMemory()
	primeMemory(t, inner, accountsFixture)

	_, err := OpenStore(encryptedMemoryBackend(t, inner, false), Options{})
	var startupErr *persist.StartupError
	if !errors.As(err, &startupErr) {
		t.Fatalf("OpenStore over a plaintext document without MigratePlaintext = %v (%T), want a *persist.StartupError", err, err)
	}
	if stored, _ := inner.Load(context.Background()); string(stored.Payload) != accountsFixture {
		t.Fatal("the refused document was rewritten")
	}

	s, err := OpenStore(encryptedMemoryBackend(t, inner, true), Options{})
	if err != nil {
		t.Fatalf("OpenStore over a plaintext document with MigratePlaintext: %v", err)
	}
	admin, ok := s.Get("admin-id-0001")
	if !ok || admin.TOTPSecret != "JBSWY3DPEHPK3PXP" || admin.PasskeyCount() != 1 {
		t.Fatalf("Get after the upgrade = %+v, %v; the document's secrets did not come through", admin, ok)
	}
	stored, _ := inner.Load(context.Background())
	if bytes.Contains(stored.Payload, []byte("JBSWY3DPEHPK3PXP")) || bytes.Contains(stored.Payload, []byte("admin")) {
		t.Error("the backend still holds the document in the clear after OpenStore")
	}

	// The version the store holds is the sealed document's: a write is
	// not a conflict.
	if _, err := s.CreateUser("carol", "carol-password", RoleUser, time.Now()); err != nil {
		t.Errorf("CreateUser after the upgrade: %v", err)
	}

	strict, err := OpenStore(encryptedMemoryBackend(t, inner, false), Options{})
	if err != nil {
		t.Fatalf("strict reopen after the upgrade: %v", err)
	}
	if _, ok := strict.ByUsername("carol"); !ok {
		t.Error("the write after the upgrade did not reach the backend")
	}
	if admin, ok := strict.Get("admin-id-0001"); !ok || admin.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Error("the TOTP secret did not survive the upgrade and a strict reopen")
	}
}

// A sealed document that reaches the store unwrapped -- the application
// dropped persist.Encrypt from a backend whose document it had already
// sealed -- is refused at open, not read as an empty store that the
// first write would then seal over with a plaintext document of none.
func TestStoresRefuseASealedDocumentReadWithoutEncrypt(t *testing.T) {
	inner := persist.NewMemory()
	if _, err := encryptedMemoryBackend(t, inner, false).Save(context.Background(), []byte(accountsFixture), 0); err != nil {
		t.Fatal(err)
	}
	unwrapped := &plaintextBackend{inner: inner}

	_, err := OpenStore(unwrapped, Options{AllowPlaintextAtRest: true})
	var startupErr *persist.StartupError
	if !errors.As(err, &startupErr) || !errors.Is(err, errSealedDocument) {
		t.Errorf("OpenStore over a sealed document without Encrypt = %v, want a *persist.StartupError wrapping errSealedDocument", err)
	}
	_, err = OpenTokenStore(unwrapped, TokenOptions{})
	if !errors.As(err, &startupErr) || !errors.Is(err, errSealedDocument) {
		t.Errorf("OpenTokenStore over a sealed document without Encrypt = %v, want a *persist.StartupError wrapping errSealedDocument", err)
	}
	if stored, _ := inner.Load(context.Background()); bytes.Contains(stored.Payload, []byte("admin")) {
		t.Error("the sealed document was written over")
	}
}
