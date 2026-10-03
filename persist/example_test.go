// Runnable usage examples for godoc. A database Backend is each
// application's own code (see persist.go's package doc); the first
// example shows the version/conflict contract every implementer must
// honour, the second how an application wraps its backend so the
// document is sealed before the backend stores it (#50).
package persist_test

import (
	"context"
	"fmt"

	"github.com/tomlawesome/gauntlet/persist"
)

// ExampleNewMemory saves a document, then shows that saving again with
// the version the caller already used -- rather than the one Save just
// returned -- is reported as persist.ErrConflict.
func ExampleNewMemory() {
	ctx := context.Background()
	backend := persist.NewMemory()

	snap, err := backend.Load(ctx)
	if err != nil {
		fmt.Println("load:", err)
		return
	}
	fmt.Println("existed:", snap.Exists)

	version, err := backend.Save(ctx, []byte(`{"accounts":[]}`), snap.Version)
	if err != nil {
		fmt.Println("save:", err)
		return
	}
	fmt.Println("version:", version)

	_, err = backend.Save(ctx, []byte(`{"accounts":[]}`), snap.Version) // stale: snap.Version is now out of date
	fmt.Println("stale save:", err == persist.ErrConflict)

	// Output:
	// existed: false
	// version: 1
	// stale save: true
}

// ExampleEncrypt wraps a backend -- here Memory, in an application its
// own database table -- so everything the backend stores is ciphertext
// under the application's key, and shows the stored form.
func ExampleEncrypt() {
	ctx := context.Background()
	key := make([]byte, persist.MinKeyBytes) // the application reads this from its key file
	table := persist.NewMemory()

	backend, err := persist.Encrypt(table, key, persist.EncryptOptions{Label: "accounts"})
	if err != nil {
		fmt.Println("encrypt:", err)
		return
	}
	if _, err := backend.Save(ctx, []byte(`{"version":3,"users":[]}`), 0); err != nil {
		fmt.Println("save:", err)
		return
	}

	stored, _ := table.Load(ctx)
	fmt.Println("stored starts with:", string(stored.Payload[:10]))
	opened, _ := backend.Load(ctx)
	fmt.Println("opened:", string(opened.Payload))

	// Output:
	// stored starts with: {"sealed":
	// opened: {"version":3,"users":[]}
}
