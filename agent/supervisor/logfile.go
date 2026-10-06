package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// logFile is an append-only, size-rotated log file (mode 0600). It is the
// stdout/stderr sink of a supervised process.
//
// Write never fails: if the process's output pipe stopped being drained, the
// child would get EPIPE/SIGPIPE and die, so a full disk or a failed rotation
// must not turn into a dead proxy. Failures are counted in dropped instead.
type logFile struct {
	path string
	max  int64
	keep int // rotated files kept; <=0 keeps none (the file is truncated on rotation)

	mu      sync.Mutex
	f       *os.File
	size    int64
	closed  bool
	dropped int64
}

func openLog(path string, max int64, keep int) (*logFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("log: %w", err)
	}
	l := &logFile{path: path, max: max, keep: keep}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *logFile) open() error {
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("log: %w", err)
	}
	// An existing file may predate the 0600 rule.
	_ = os.Chmod(l.path, 0o600)
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("log: %w", err)
	}
	l.f, l.size = f, fi.Size()
	return nil
}

// Write implements io.Writer. It always reports success. A chunk that does not
// fit in the current file is split so that no file ever exceeds max bytes.
func (l *logFile) Write(p []byte) (int, error) {
	total := len(p)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return total, nil
	}
	for len(p) > 0 {
		if l.f != nil && l.size >= l.max {
			l.rotate()
		}
		if l.f == nil {
			if err := l.open(); err != nil {
				l.dropped += int64(len(p))
				return total, nil
			}
		}
		room := l.max - l.size
		if room <= 0 || room > int64(len(p)) {
			room = int64(len(p))
		}
		n, err := l.f.Write(p[:room])
		l.size += int64(n)
		if err != nil {
			l.dropped += int64(len(p))
			return total, nil
		}
		p = p[n:]
	}
	return total, nil
}

// rotate shifts path -> path.1 -> path.2 ... and reopens. Must hold l.mu.
func (l *logFile) rotate() {
	_ = l.f.Close()
	l.f = nil
	if l.keep <= 0 {
		_ = os.Remove(l.path)
	} else {
		_ = os.Remove(fmt.Sprintf("%s.%d", l.path, l.keep))
		for i := l.keep - 1; i >= 1; i-- {
			_ = os.Rename(fmt.Sprintf("%s.%d", l.path, i), fmt.Sprintf("%s.%d", l.path, i+1))
		}
		_ = os.Rename(l.path, l.path+".1")
	}
	if err := l.open(); err != nil {
		l.f = nil
	}
}

// Close flushes nothing (writes are unbuffered) and stops accepting data.
func (l *logFile) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.f != nil {
		err := l.f.Close()
		l.f = nil
		return err
	}
	return nil
}
