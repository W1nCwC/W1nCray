//go:build linux || darwin || freebsd || openbsd || netbsd

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// instanceLock guarantees a single running instance per config file: the
// panel keeps one WebSocket per node and a second process would keep kicking
// the first one off. flock(2) is released by the kernel when the process
// exits, however it exits.
type instanceLock struct{ f *os.File }

func acquireInstanceLock(configPath string) (*instanceLock, error) {
	path := configPath + ".lock"
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", path, err)
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
			return nil, fmt.Errorf("已有 W1nCray 实例在使用 %s 运行（PID %s）。请先停止它（W1nCray stop）或查看日志（W1nCray log）", configPath, pid)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	f.Truncate(0)
	f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	return &instanceLock{f: f}, nil
}

func (l *instanceLock) release() {
	if l != nil && l.f != nil {
		syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
		l.f.Close()
	}
}
