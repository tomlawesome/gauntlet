//go:build unix

package persist

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"syscall"
)

// fileLock is an exclusive advisory lock on a sidecar file, held for the
// life of one fileBackend.Save call.
type fileLock struct {
	f *os.File
}

// lockFile opens (creating if needed) the file at path and waits until it
// holds an exclusive flock on it or ctx is done, whichever comes first.
// flock locks are per open file description, not per process, so two
// separate os.OpenFile handles -- whether in the same process or two
// different ones -- block each other on the same path.
//
// syscall.Flock has no deadline parameter, so the blocking call runs in
// its own goroutine; lockFile itself waits on that goroutine or on
// ctx.Done. If ctx wins, the goroutine is left to finish on its own --
// when the lock call eventually returns, it closes the file at once, so
// an abandoned lock is not held forever and the handle never leaks; the
// caller gets ctx.Err() without waiting for that to happen.
//
// A lock file this call creates takes the owner and group of the store
// it guards (path without ".lock"), when that exists, for the same
// reason writeFileAtomic keeps the store's: created root-owned 0600 by
// an app's CLI run with sudo, it could never be opened again by the
// server sharing the store, and every save there would fail.
func lockFile(ctx context.Context, path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	switch {
	case err == nil:
		if err := ownLikeStore(f, strings.TrimSuffix(path, ".lock")); err != nil {
			_ = f.Close()
			return nil, err
		}
	case errors.Is(err, fs.ErrExist):
		f, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if errors.Is(err, fs.ErrPermission) {
			// A lock made before this check existed, by a CLI run with
			// sudo, belongs to root and nothing this process can do
			// repairs it: say what to do rather than fail every save
			// with a bare "permission denied".
			return nil, fmt.Errorf("persist: cannot open the lock file %s (%w): it belongs to another user, probably after a CLI run with sudo -- give it to the user this server runs as, or delete it while the server is stopped", path, err)
		}
		if err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	acquired := make(chan error, 1)
	go func() { acquired <- syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }()

	select {
	case err := <-acquired:
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		return &fileLock{f: f}, nil
	case <-ctx.Done():
		go func() {
			<-acquired // locked or failed, the handle is no longer needed
			_ = f.Close()
		}()
		return nil, ctx.Err()
	}
}

// ownLikeStore gives a just-created lock file the owner and group of the
// store at store, if there is one yet; a first save has nothing to copy
// and leaves the lock as its writer made it.
func ownLikeStore(f *os.File, store string) error {
	info, err := os.Stat(store)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return copyOwner(f, info)
}

// unlock releases the lock by closing the file handle: an flock lives on
// the open file description, and this is the only handle to it, so
// closing releases the lock without a separate LOCK_UN call.
func (l *fileLock) unlock() error {
	return l.f.Close()
}
