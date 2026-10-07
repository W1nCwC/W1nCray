//go:build linux || darwin || freebsd || openbsd || netbsd

package lockfile

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// fileLock is a held flock(2).
type fileLock struct{ f *os.File }

func acquire(lockPath, program, configPath string) (*fileLock, error) {
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		b := make([]byte, 32)
		n, _ := f.ReadAt(b, 0)
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			pid := strings.TrimSpace(string(b[:n]))
			if _, perr := strconv.Atoi(pid); perr != nil {
				pid = "?"
			}
			return nil, fmt.Errorf("已有 %s 实例在使用 %s 运行（PID %s）。请先停止它", program, configPath, pid)
		}
		return nil, fmt.Errorf("lock %s: %w", lockPath, err)
	}
	f.Truncate(0)
	f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	return &fileLock{f: f}, nil
}

func (l *fileLock) release() {
	if l == nil || l.f == nil {
		return
	}
	syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	l.f.Close()
}
