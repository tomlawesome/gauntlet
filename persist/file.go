package persist

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
)

// fileBackend is a Backend over one JSON (or any) document in a single
// file, atomically replaced on write. It is not exported: gauntlet
// offers no unencrypted file mode (docs/security-by-design.md), only
// EncryptedFileBackend, which wraps this for the actual bytes-on-disk
// handling. Ported from mikroview's internal/persist.FileBackend
// (issue #18), including the file mode and the write-temp-then-rename
// dance, so wrapping it in encryption is not itself a behaviour change.
//
// Save also maintains a sidecar lock file alongside path, named path
// with ".lock" appended -- worth knowing if the store is ever backed up
// or moved by hand. It holds no data of its own, but deleting it while a
// writer holds it is not harmless: a second writer can then take its own
// lock on a fresh inode at the same name and overlap with the first,
// defeating the compare-and-swap below.
type fileBackend struct {
	path string
}

func newFileBackend(path string) *fileBackend { return &fileBackend{path: path} }

func (b *fileBackend) Describe() string { return "file " + b.path }

func (b *fileBackend) Close() error { return nil }

// Load reads the file. A missing file is the normal first-run case and
// returns a zero Snapshot with a nil error; an unreadable one is a real
// error, because treating it as absent is how a corrupt document
// silently becomes a fresh install.
func (b *fileBackend) Load(ctx context.Context) (Snapshot, error) {
	data, err := os.ReadFile(b.path)
	if err != nil {
		if os.IsNotExist(err) {
			return Snapshot{}, nil
		}
		return Snapshot{}, err
	}
	return Snapshot{Payload: data, Version: contentVersion(data), Exists: true}, nil
}

// contentVersion derives a store's version from its bytes rather than
// from the file's modification time, whose granularity is coarser than
// the interval between two quick writes and would let a stale
// compare-and-swap through. FNV-1a, not a cryptographic hash: this
// guards against accidental overwrite between cooperating processes,
// not against an attacker who can already write the file.
func contentVersion(data []byte) int64 {
	h := fnv.New64a()
	_, _ = h.Write(data)
	v := int64(h.Sum64() & 0x7fffffffffffffff)
	if v == 0 {
		// 0 means "nothing stored" to Save; never hand it back for a
		// file that does exist.
		return 1
	}
	return v
}

// writeFileAtomic replaces path's contents crash-safely: a temp file is
// written in path's own directory, fsynced, renamed over path, and the
// directory is fsynced after the rename.
//
// perm applies only to a file being created. The rename puts a new inode
// at path, owned by whoever wrote it, so when path already exists the
// temp file first takes on its mode, owner and group. Otherwise one save
// from an app's CLI run with sudo leaves a store the server sharing it
// (persist.go's Backend doc) can no longer read or replace, and every
// save after that fails.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	existing, err := os.Stat(path)
	switch {
	case err == nil:
		perm = existing.Mode().Perm()
	case os.IsNotExist(err):
		existing = nil
	default:
		return err
	}
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	// Best effort on both counts: the function is already returning the
	// real error from whichever step failed, and there is nothing more
	// useful to do with a failure to close or remove a temp file we are
	// abandoning anyway.
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(tmp)
	}
	if err := f.Chmod(perm); err != nil {
		cleanup()
		return err
	}
	if existing != nil {
		if err := copyOwner(f, existing); err != nil {
			cleanup()
			return err
		}
	}
	if _, err := f.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if d, err := os.Open(dir); err == nil {
		// Best effort: some filesystems refuse to sync a directory, and
		// a failure here costs durability of the rename, not
		// correctness of the bytes.
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Save atomically replaces the file. expect is checked against
// contentVersion of the file's current bytes, so a write that would
// clobber someone else's change is refused rather than silently
// winning. expect == 0 additionally requires that no file exists yet.
func (b *fileBackend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	if b.path == "" {
		return 0, fmt.Errorf("persist: no file path configured")
	}
	dir := filepath.Dir(b.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}

	// The read-compare-write below has to run as one unit across
	// processes, not just goroutines in this one: a CLI tool and a
	// running server (persist.go's Backend doc) can each read the same
	// current version, both pass the compare, and both rename -- the
	// later rename wins and the earlier write is gone with no error to
	// anyone. A sidecar lock file, not a lock on b.path itself, because
	// b.path is replaced wholesale by rename below, so a lock tied to its
	// inode would not be seen by the next writer that opens the new one.
	lock, err := lockFile(ctx, b.path+".lock")
	if err != nil {
		return 0, err
	}
	defer func() { _ = lock.unlock() }()

	current, readErr := os.ReadFile(b.path)
	switch {
	case os.IsNotExist(readErr):
		if expect != 0 {
			// Caller believed a document existed. It doesn't -- someone
			// removed it underneath them.
			return 0, ErrConflict
		}
	case readErr != nil:
		return 0, readErr
	default:
		if expect == 0 {
			return 0, ErrConflict // caller expected to be creating it
		}
		if contentVersion(current) != expect {
			return 0, ErrConflict
		}
	}

	// 0600: every document this package writes may hold secrets --
	// password hashes, tokens, or (through EncryptedFileBackend)
	// ciphertext keyed material is bound to.
	//
	// The temp file's name is unique per writer (os.CreateTemp), not a
	// fixed shared name written with O_TRUNC -- two writers racing on a
	// shared temp name can otherwise both land in the same file and
	// whichever renames second publishes a byte mixture of both
	// payloads, which is settled corruption rather than a transient
	// (mikroview's TestContractConcurrentWritersNeverPublishAMixedDocument;
	// here, persisttest's concurrent-writers check).
	if err := writeFileAtomic(b.path, payload, 0o600); err != nil {
		return 0, err
	}

	return contentVersion(payload), nil
}
