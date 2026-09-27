// Runnable usage example for godoc. persist.Memory is the only Backend
// this module ships (a real one -- file, database table -- is each
// application's own code; see persist.go's package doc). The example
// exists to show the version/conflict contract every Backend implementer
// must honour, not just NewMemory's signature.
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
