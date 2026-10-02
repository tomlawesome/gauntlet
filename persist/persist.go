// Package persist is the storage boundary gauntlet's stores sit on:
// accounts and sessions, tokens, and (later) any other whole-document
// state the module keeps.
//
// Each store keeps its whole dataset in memory and serves reads from
// there; persistence is a whole-document snapshot, written after each
// change. That shape, and every type in this file, is copied
// method-for-method from mikroview's internal/persist (persist.go,
// document.go, open.go) so mikroview's existing backends -- a JSON file,
// an encrypted file, Postgres, a write-behind wrapper -- satisfy this
// interface with no adapter when mikroview moves onto gauntlet
// (ADR-0005, birdcage #8; see docs/adr/0001-shared-auth-module.md). The
// one thing that does not carry across the package boundary is the
// sentinel ErrConflict below: mikroview's internal/persist will assign
// its own ErrConflict = gpersist.ErrConflict when it moves, rather than
// gauntlet importing mikroview's error value.
//
// This package ships the interface, a Memory backend for tests
// (memory.go), the Encrypt wrapper that seals a document before any
// backend stores it (encrypted.go, #50, docs/adr/0005) and the
// encrypted file backend built on it (encrypted_file.go, #18). A
// database backend is each application's own code, deliberately kept
// out of the module (birdcage ADR-0005 decision 2: "the module never
// owns a database"), and the application wraps it in Encrypt.
package persist

import (
	"context"
	"errors"
)

// ErrConflict is returned by Save when the stored version is not the one
// the caller expected -- someone else wrote in between.
//
// This is not an error condition to bubble up to a user. It means
// "reload and try again": the caller's in-memory copy is stale. Callers
// must not treat it as fatal.
var ErrConflict = errors.New("persist: store was modified by someone else")

// Snapshot is one store's persisted document plus the token needed to
// write it back safely.
type Snapshot struct {
	// Payload is the store's serialized state, exactly as the store
	// marshalled it -- this package never inspects or rewrites it.
	Payload []byte
	// Version is what Save must be given to accept the next write. Zero
	// means "nothing stored yet", which is the value to pass when
	// creating a store's first document.
	Version int64
	// Exists distinguishes "stored, and happens to be empty" from "never
	// stored".
	Exists bool
}

// Backend is where one store's document lives.
//
// Implementations must be safe for concurrent use: a CLI tool and a
// running server can be separate processes against the same backend,
// which is the whole reason Save takes a version rather than just
// writing.
type Backend interface {
	// Load reads the current document. A store that has never been
	// written returns a zero-value Snapshot and a nil error -- a missing
	// document is the normal first-run case, not a failure.
	Load(ctx context.Context) (Snapshot, error)

	// Save writes payload if the stored version still matches expect,
	// returning the new version. It returns ErrConflict if it does not.
	//
	// expect == 0 means "create": it succeeds only if nothing is stored,
	// so two processes racing to create the same store can't both win.
	Save(ctx context.Context, payload []byte, expect int64) (int64, error)

	// Close releases whatever the backend holds. Safe to call on a
	// backend that was never used.
	Close() error

	// Describe returns a short, credential-free description for logs,
	// e.g. "memory store" or "postgres store 'accounts'". Never includes
	// a DSN or password.
	Describe() string
}

// VersionReader is an optional Backend capability: reporting the stored
// version without transferring the document.
//
// It exists for a caller that polls for staleness far more often than
// the document actually changes -- gate checks this on every
// authenticated request in mikroview's model, so a live server would
// otherwise pull the whole accounts document over the wire per request
// just to compare an integer. Callers must treat its absence as normal
// and fall back to Load.
//
// exists is false when nothing has been stored yet, matching
// Snapshot.Exists.
type VersionReader interface {
	Version(ctx context.Context) (version int64, exists bool, err error)
}
