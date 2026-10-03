package persist

import (
	"context"
	"testing"
)

// testdata/mikroview-encrypted-fixture-v1.bin was written by mikroview's
// REAL internal/persist.EncryptedFileBackend, not by this port, so this
// test proves gauntlet's version reads mikroview's actual on-disk
// scheme rather than merely agreeing with itself.
//
// Generated at mikroview gitlab/dev commit
// bb29f23eb5e9918fdd888a6d34640eb5b228a129, from a disposable checkout
// (mkdir /tmp/mv-src && git -C ~/projects/mikroview archive gitlab/dev |
// tar -x -C /tmp/mv-src) with a throwaway
// internal/persist/zz_gauntlet_fixture_test.go added there (not
// committed anywhere, and the checkout was deleted after). That test
// called mikroview's NewEncryptedFileBackendForPath with a
// retention.Key built from fixtureKeyMaterial below (via
// retention.NewKeyFromMaterial) and the AAD/logical path
// fixtureLogicalPath, saved fixturePlaintext, and the resulting file
// was copied here unmodified.
const (
	fixtureKeyMaterial = "gauntlet-test-fixture-key-not-secret-0123456789"
	fixtureLogicalPath = "gauntlet/persist/testdata/mikroview-encrypted-fixture-v1.bin"
	fixturePlaintext   = `{"fixture":"gauntlet issue #18 cross-app compatibility","accounts":[{"username":"fixture-user","role":"admin"}]}`
	fixtureFile        = "testdata/mikroview-encrypted-fixture-v1.bin"
)

func TestEncryptedFileBackendOpensMikroviewFixture(t *testing.T) {
	b, err := newEncryptedFileBackendForPath(fixtureFile, fixtureLogicalPath, []byte(fixtureKeyMaterial))
	if err != nil {
		t.Fatalf("newEncryptedFileBackendForPath: %v", err)
	}

	snap, err := b.Load(context.Background())
	if err != nil {
		t.Fatalf("Load of mikroview's fixture failed: %v", err)
	}
	if !snap.Exists {
		t.Fatal("fixture file reports as not existing")
	}
	if string(snap.Payload) != fixturePlaintext {
		t.Errorf("Load = %q, want %q", snap.Payload, fixturePlaintext)
	}
}

// TestEncryptedFileBackendFixtureWrongLogicalPathFails pins that the
// fixture's AAD binding is real, not incidental: opening the same bytes
// under any other logical path must fail the same way a same-app AAD
// mismatch does (TestEncryptedFileBackendDocumentCopiedToAnotherPathFailsToOpen).
func TestEncryptedFileBackendFixtureWrongLogicalPathFails(t *testing.T) {
	b, err := newEncryptedFileBackendForPath(fixtureFile, fixtureLogicalPath+"-different", []byte(fixtureKeyMaterial))
	if err != nil {
		t.Fatalf("newEncryptedFileBackendForPath: %v", err)
	}
	if _, err := b.Load(context.Background()); err == nil {
		t.Fatal("Load succeeded under the wrong logical path, want the AAD check to refuse it")
	}
}
