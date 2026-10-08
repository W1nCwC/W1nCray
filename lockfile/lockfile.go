// Package lockfile implements the single-instance lock the W1nCray programs
// take per configuration file: an exclusive flock(2) on a lock file next to
// config.yml, released by the kernel when the process exits, however it exits.
//
// The agent and the Xray kernel use different lock files
// (<config>.lock and <config>.xray.lock), so the two programs can run side by
// side against the same configuration.
package lockfile

// Lock is a held single-instance lock.
type Lock struct {
	f *fileLock
}

// Acquire takes the exclusive lock of lockPath and writes this process's pid
// into it. program and configPath only shape the error message (the lock file
// is what is actually locked).
func Acquire(lockPath, program, configPath string) (*Lock, error) {
	f, err := acquire(lockPath, program, configPath)
	if err != nil {
		return nil, err
	}
	return &Lock{f: f}, nil
}

// Release drops the lock. It is safe to call on a nil lock.
func (l *Lock) Release() {
	if l == nil || l.f == nil {
		return
	}
	l.f.release()
	l.f = nil
}
