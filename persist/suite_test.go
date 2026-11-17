package persist_test

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/tomlawesome/gauntlet/persist"
	"github.com/tomlawesome/gauntlet/persist/persisttest"
)

// Gauntlet's own backends run the same suite an application runs
// against its own (#61). These replace the per-backend copies of
// mikroview's contract cases that memory_test.go, file_test.go and
// encrypted_file_test.go used to carry; what stays in those files is
// what is particular to each backend.

func TestMemoryKeepsTheBackendContract(t *testing.T) {
	persisttest.Run(t, func(t testing.TB) func() persist.Backend {
		// Memory is its own storage: every backend "over the same
		// store" is the same value.
		m := persist.NewMemory()
		return func() persist.Backend { return m }
	})
}

func TestFileBackendKeepsTheBackendContract(t *testing.T) {
	persisttest.Run(t, func(t testing.TB) func() persist.Backend {
		path := filepath.Join(t.TempDir(), "store.json")
		return func() persist.Backend { return persist.NewFileBackendForTest(path) }
	})
}

func TestEncryptedFileBackendKeepsTheBackendContract(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, persist.MinKeyBytes)
	persisttest.Run(t, func(t testing.TB) func() persist.Backend {
		path := filepath.Join(t.TempDir(), "store.json")
		return func() persist.Backend {
			b, err := persist.NewEncryptedFileBackend(path, key)
			if err != nil {
				t.Fatalf("NewEncryptedFileBackend: %v", err)
			}
			return b
		}
	})
}

// The shape an application's own backend takes: its storage wrapped in
// Encrypt (#50).
func TestEncryptOverMemoryKeepsTheBackendContract(t *testing.T) {
	key := bytes.Repeat([]byte{0x02}, persist.MinKeyBytes)
	persisttest.Run(t, func(t testing.TB) func() persist.Backend {
		table := persist.NewMemory()
		return func() persist.Backend {
			b, err := persist.Encrypt(table, key, persist.EncryptOptions{Label: "accounts"})
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			return b
		}
	})
}
