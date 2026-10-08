// Package atomicfile is the one crash-safe file writer this module's
// file-keeping packages share: persist's file backend, blocklist's
// stored list and geoip's country file and state. Each used to carry its
// own copy, and only persist's kept a replaced file's owner (#79, #80).
package atomicfile

import (
	"os"
	"path/filepath"
)

// WriteFile replaces path's contents crash-safely: a temp file is
// written in path's own directory, fsynced, renamed over path, and the
// directory is fsynced after the rename. The directory is created 0700
// if missing.
//
// The rename puts a new inode at path, owned by whoever wrote it, so
// when path already exists the temp file first takes on its owner and
// group (CopyOwner). Otherwise one write from a tool run with sudo
// leaves a file the server sharing it can no longer read or replace,
// and every write after that fails. The mode is always perm, not the
// old file's: a file loosened by hand is tightened again on the next
// write rather than kept as it was found.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	existing, err := os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
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
		if err := CopyOwner(f, existing); err != nil {
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

// KeepOwner gives f, a file about to be renamed over path, path's owner
// and group, when path exists: for a writer that fills its own temp
// file (geoip's download) rather than handing WriteFile the bytes.
func KeepOwner(f *os.File, path string) error {
	existing, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return CopyOwner(f, existing)
}
