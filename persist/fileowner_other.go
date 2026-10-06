//go:build !unix

package persist

import (
	"io/fs"
	"os"
)

// copyOwner is the non-unix stand-in for fileowner_unix.go: there is no
// uid/gid pair to carry over, so there is nothing to do.
func copyOwner(f *os.File, was fs.FileInfo) error { return nil }
