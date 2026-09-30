//go:build unix

package persist

import (
	"os"
	"syscall"
)

// fileLock is an exclusive advisory lock on a sidecar file, held for the
// life of one fileBackend.Save call.
type fileLock struct {
	f *os.File
}

// lockFile opens (creating if needed) the file at path and blocks until
// it holds an exclusive flock on it. flock locks are per open file
// description, not per process, so two separate os.OpenFile handles --
// whether in the same process or two different ones -- block each other
// on the same path.
func lockFile(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &fileLock{f: f}, nil
}

// unlock releases the lock by closing the file handle: an flock lives on
// the open file description, and this is the only handle to it, so
// closing releases the lock without a separate LOCK_UN call.
func (l *fileLock) unlock() error {
	return l.f.Close()
}
