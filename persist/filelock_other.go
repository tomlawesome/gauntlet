//go:build !unix

package persist

import "fmt"

// fileLock is the non-unix stand-in: see filelock_unix.go. There is no
// portable advisory-lock primitive in the stdlib outside unix, and
// fileBackend.Save's cross-process safety depends on actually holding
// one, so this fails loudly rather than silently running unlocked.
type fileLock struct{}

func lockFile(path string) (*fileLock, error) {
	return nil, fmt.Errorf("persist: the file backend needs an advisory file lock, which this platform build does not provide")
}

func (l *fileLock) unlock() error { return nil }
