//go:build !(linux || darwin || freebsd || openbsd || netbsd)

package lockfile

// fileLock is a no-op where flock(2) is unavailable (development builds).
type fileLock struct{}

func acquire(string, string, string) (*fileLock, error) { return &fileLock{}, nil }

func (*fileLock) release() {}
