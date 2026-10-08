//go:build unix

package persist

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// copyOwner gives f the owner and group of the file described by was,
// which f is about to replace by rename. Permission denied is not an
// error: only root may give a file away, and a writer that is not root
// but may replace the store is in practice its owner already, so the
// chown it was refused would have changed nothing that matters. Any
// other failure is real and fails the write.
func copyOwner(f *os.File, was fs.FileInfo) error {
	st, ok := was.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if err := f.Chown(int(st.Uid), int(st.Gid)); err != nil && !errors.Is(err, fs.ErrPermission) {
		return err
	}
	return nil
}
