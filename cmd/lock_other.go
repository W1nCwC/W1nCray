//go:build !(linux || darwin || freebsd || openbsd || netbsd)

package cmd

// instanceLock is a no-op where flock(2) is unavailable (development builds).
type instanceLock struct{}

func acquireInstanceLock(string) (*instanceLock, error) { return &instanceLock{}, nil }

func (*instanceLock) release() {}
