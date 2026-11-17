package persist

// NewFileBackendForTest exposes the unexported plain file backend to
// this package's external tests, so suite_test.go can run the
// persisttest suite against it: persisttest imports persist, so only
// the external test package can import persisttest.
var NewFileBackendForTest = func(path string) Backend { return newFileBackend(path) }
