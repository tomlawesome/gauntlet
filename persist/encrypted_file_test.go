package persist

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testKey returns a MinKeyBytes-length key filled with seed, distinct
// keys coming from distinct seeds. Mirrors mikroview's own
// internal/persist/encrypted_test.go helper (contract_test.go's
// eachBackend does the same with a repeated byte), kept here in the
// same shape (persist/open_test.go's, per issue #18) rather than
// imported.
func testKey(seed byte) []byte {
	return bytes.Repeat([]byte{seed}, MinKeyBytes)
}

func TestNewEncryptedFileBackendRefusesShortKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	if _, err := NewEncryptedFileBackend(path, testKey(0x01)[:MinKeyBytes-1]); err == nil {
		t.Fatal("NewEncryptedFileBackend accepted a key shorter than MinKeyBytes, want a refusal")
	}
}

func TestNewEncryptedFileBackendRefusesEmptyPath(t *testing.T) {
	if _, err := NewEncryptedFileBackend("", testKey(0x01)); err == nil {
		t.Fatal("NewEncryptedFileBackend accepted an empty path, want a refusal")
	}
	if _, err := newEncryptedFileBackendForPath("", "logical", testKey(0x01)); err == nil {
		t.Fatal("newEncryptedFileBackendForPath accepted an empty path, want a refusal")
	}
}

func TestEncryptedFileBackendSaveThenLoadRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	b, err := NewEncryptedFileBackend(path, testKey(0x01))
	if err != nil {
		t.Fatalf("NewEncryptedFileBackend: %v", err)
	}

	plaintext := []byte(`{"accounts":[{"username":"tom","role":"admin"}]}`)
	if _, err := b.Save(context.Background(), plaintext, 0); err != nil {
		t.Fatalf("Save: %v", err)
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"tom", "admin", "accounts"} {
		if bytes.Contains(onDisk, []byte(marker)) {
			t.Errorf("on-disk bytes contain plaintext marker %q -- the file is not actually encrypted", marker)
		}
	}

	snap, err := b.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(snap.Payload) != string(plaintext) {
		t.Errorf("Load = %q, want %q", snap.Payload, plaintext)
	}
	if !snap.Exists {
		t.Error("Exists is false after a successful Save")
	}
}

// Both saves go through the same backend (same path, same key, same AAD)
// so the only thing that can make the ciphertext differ is a fresh
// salt/nonce -- using two different paths here would confound the
// result, since different AAD alone changes the GCM tag regardless of
// whether the salt or nonce were reused.
func TestEncryptedFileBackendTwoSavesOfSamePlaintextDiffer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	key := testKey(0x01)
	b, err := NewEncryptedFileBackend(path, key)
	if err != nil {
		t.Fatalf("NewEncryptedFileBackend: %v", err)
	}

	plaintext := []byte(`{"n":1}`)
	v1, err := b.Save(context.Background(), plaintext, 0)
	if err != nil {
		t.Fatalf("Save 1: %v", err)
	}
	on1, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := b.Save(context.Background(), plaintext, v1); err != nil {
		t.Fatalf("Save 2: %v", err)
	}
	on2, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(on1, on2) {
		t.Error("two saves of the same plaintext under the same path and key produced identical ciphertext -- salt/nonce are not fresh")
	}
}

func TestEncryptedFileBackendWrongKeyFailsToOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	writer, err := NewEncryptedFileBackend(path, testKey(0x01))
	if err != nil {
		t.Fatalf("NewEncryptedFileBackend: %v", err)
	}
	if _, err := writer.Save(context.Background(), []byte(`{"n":1}`), 0); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reader, err := NewEncryptedFileBackend(path, testKey(0x02))
	if err != nil {
		t.Fatalf("NewEncryptedFileBackend: %v", err)
	}
	if _, err := reader.Load(context.Background()); err == nil {
		t.Fatal("Load with the wrong key succeeded, want a clean failure")
	}
}

func TestEncryptedFileBackendFlippedByteFailsToOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	b, err := NewEncryptedFileBackend(path, testKey(0x01))
	if err != nil {
		t.Fatalf("NewEncryptedFileBackend: %v", err)
	}
	if _, err := b.Save(context.Background(), []byte(`{"n":1}`), 0); err != nil {
		t.Fatalf("Save: %v", err)
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte{}, onDisk...)
	tampered[len(tampered)-1] ^= 0x01 // flip one bit in the GCM tag/ciphertext tail
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := b.Load(context.Background()); err == nil {
		t.Fatal("Load of a document with one flipped byte succeeded, want a clean failure")
	}
}

func TestEncryptedFileBackendDocumentCopiedToAnotherPathFailsToOpen(t *testing.T) {
	key := testKey(0x01)
	srcPath := filepath.Join(t.TempDir(), "accounts.json")
	dstPath := filepath.Join(t.TempDir(), "accounts.json")

	writer, err := NewEncryptedFileBackend(srcPath, key)
	if err != nil {
		t.Fatalf("NewEncryptedFileBackend: %v", err)
	}
	if _, err := writer.Save(context.Background(), []byte(`{"n":1}`), 0); err != nil {
		t.Fatalf("Save: %v", err)
	}

	onDisk, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dstPath, onDisk, 0o600); err != nil {
		t.Fatal(err)
	}

	// dstPath differs from srcPath as a string (different temp dirs),
	// so the AAD bound at Save time (srcPath) does not match the AAD
	// the reader at dstPath will check against.
	reader, err := NewEncryptedFileBackend(dstPath, key)
	if err != nil {
		t.Fatalf("NewEncryptedFileBackend: %v", err)
	}
	_, err = reader.Load(context.Background())
	if err == nil {
		t.Fatal("Load of a document copied to a different logical path succeeded, want the AAD check to refuse it")
	}
	// The operator's most likely mistake is a moved file, and the advice
	// that follows this error (restore a backup) does not help with that,
	// so the message has to name it.
	if !strings.Contains(err.Error(), "moved") {
		t.Fatalf("refusal does not tell the operator the file may have been moved: %v", err)
	}
}

// TestEncryptedFileBackendPersistOpenFailsClosedOnTamper pins the
// end-to-end contract from the caller's point of view: a store that
// funnels its backend through persist.Open (as every real store does)
// gets a *StartupError on a tampered document, never a silent fresh
// start.
func TestEncryptedFileBackendPersistOpenFailsClosedOnTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	b, err := NewEncryptedFileBackend(path, testKey(0x01))
	if err != nil {
		t.Fatalf("NewEncryptedFileBackend: %v", err)
	}
	if _, err := b.Save(context.Background(), []byte(`{"n":1}`), 0); err != nil {
		t.Fatalf("Save: %v", err)
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte{}, onDisk...)
	tampered[len(tampered)-1] ^= 0x01
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	var decodeCalled bool
	_, _, err = Open(context.Background(), b, "the test store", func(data []byte) error {
		decodeCalled = true
		return nil
	})
	if err == nil {
		t.Fatal("persist.Open over a tampered document returned nil, want a fail-closed error")
	}
	if decodeCalled {
		t.Error("decode was called against a document that never successfully decrypted")
	}
	var startupErr *StartupError
	if !errors.As(err, &startupErr) {
		t.Fatalf("err is not a *StartupError: %v (%T)", err, err)
	}
}

func TestEncryptedFileBackendDescribeNeverLeaksAKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	key := testKey(0x01)
	b, err := NewEncryptedFileBackend(path, key)
	if err != nil {
		t.Fatalf("NewEncryptedFileBackend: %v", err)
	}
	got := b.Describe()
	if !strings.Contains(got, path) {
		t.Errorf("Describe() = %q, want it to name the path", got)
	}
	if bytes.Contains([]byte(got), key) {
		t.Error("Describe() leaked the raw key bytes")
	}
}

func TestEncryptedFileBackendVersionPropagatesLoadError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	path := filepath.Join(t.TempDir(), "store.json")
	if err := os.WriteFile(path, []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	b, err := NewEncryptedFileBackend(path, testKey(0x01))
	if err != nil {
		t.Fatalf("NewEncryptedFileBackend: %v", err)
	}
	if _, _, err := b.Version(context.Background()); err == nil {
		t.Fatal("Version over a permission-denied file succeeded, want an error")
	}
}

// The three malformed-envelope shapes openSealed distinguishes
// internally, each forced directly by writing the raw bytes rather than
// through Save, so each branch is proven independently instead of only
// ever being reached via a full valid-then-tampered document.
func TestEncryptedFileBackendMalformedEnvelopesFailToOpen(t *testing.T) {
	cases := map[string][]byte{
		"too short":   []byte("MVS1"),
		"wrong magic": bytes.Repeat([]byte{0xAA}, sealHeaderBytes+20),
		"unsupported version": append(
			append([]byte(sealMagic), 0x09),
			bytes.Repeat([]byte{0}, saltBytes+20)...,
		),
		"truncated after header": append([]byte(sealMagic), append([]byte{sealVersion}, bytes.Repeat([]byte{0}, saltBytes+2)...)...),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "store.json")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			b, err := NewEncryptedFileBackend(path, testKey(0x01))
			if err != nil {
				t.Fatalf("NewEncryptedFileBackend: %v", err)
			}
			if _, err := b.Load(context.Background()); err == nil {
				t.Fatalf("Load of a %s envelope succeeded, want a clean failure", name)
			}
		})
	}
}

func TestEncryptedFileBackendVersionWorksWithoutDecrypting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	if err := os.WriteFile(path, []byte("not a sealed document"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := NewEncryptedFileBackend(path, testKey(0x01))
	if err != nil {
		t.Fatalf("NewEncryptedFileBackend: %v", err)
	}

	version, exists, err := b.Version(context.Background())
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if !exists {
		t.Error("Version reports exists=false for a file that is present")
	}
	if version == 0 {
		t.Error("Version reports 0 for a file that exists")
	}
}
