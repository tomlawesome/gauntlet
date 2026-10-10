//go:build !unix

package atomicfile

import (
	"io/fs"
	"os"
)

// CopyOwner is the non-unix stand-in for owner_unix.go: there is no
// uid/gid pair to carry over, so there is nothing to do.
func CopyOwner(f *os.File, was fs.FileInfo) error { return nil }
