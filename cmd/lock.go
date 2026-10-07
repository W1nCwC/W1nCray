package cmd

import "github.com/W1nCwC/W1nCray/lockfile"

// instanceLock is the agent's single-instance lock: <config>.lock. The Xray
// kernel uses <config>.xray.lock, so the two programs can run side by side
// against the same configuration.
type instanceLock struct{ l *lockfile.Lock }

// acquireInstanceLock takes the agent's lock of a config file.
func acquireInstanceLock(configPath string) (*instanceLock, error) {
	l, err := lockfile.Acquire(configPath+".lock", "W1nCray", configPath)
	if err != nil {
		return nil, err
	}
	return &instanceLock{l: l}, nil
}

func (l *instanceLock) release() {
	if l == nil {
		return
	}
	l.l.Release()
}
