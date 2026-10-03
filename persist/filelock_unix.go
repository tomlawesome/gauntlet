//go:build unix

package persist

import (
	"context"
	"os"
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
// when it eventually acquires the lock, it closes the file at once so the
// abandoned lock is not held forever, but the caller gets ctx.Err()
// without waiting for that to happen.
func lockFile(ctx context.Context, path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
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
			if err := <-acquired; err == nil {
				_ = f.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// unlock releases the lock by closing the file handle: an flock lives on
// the open file description, and this is the only handle to it, so
// closing releases the lock without a separate LOCK_UN call.
func (l *fileLock) unlock() error {
	return l.f.Close()
}
