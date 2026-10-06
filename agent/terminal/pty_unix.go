//go:build unix && (amd64 || 386 || arm || arm64 || mips || mipsle || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x || loong64)

package terminal

import (
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/creack/pty"
)

// Supported reports whether this build carries a PTY implementation AND this
// machine can actually create one. The runtime probe is what keeps a kernel
// without devpts (some OpenWrt builds) from promising a terminal it cannot
// deliver.
//
// "Compiles" is not "works": the release build matrix asserts that a binary for
// every listed platform builds, and this probe decides at runtime whether the
// machine really gets the capability (design section 6.8).
func Supported() bool {
	f, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// ptyProcess is the platform part of a session: the PTY master, the child and
// the calls that end it.
type ptyProcess interface {
	read(p []byte) (int, error)
	write(p []byte) (int, error)
	resize(cols, rows uint16) error
	pid() int
	signalTerm() error
	signalKill() error
	// wait blocks until the child is reaped. It must be called exactly once.
	wait() error
	// close releases the PTY master. It is called after wait returned.
	close() error
}

// realPTY is the creack/pty backed implementation.
type realPTY struct {
	cmd    *exec.Cmd
	master *os.File
	once   sync.Once
}

var _ ptyProcess = (*realPTY)(nil)

// startPTY starts shell under a fresh pseudo-terminal. shell is a single
// program path: it is started as an argv array (no "-c", no command string),
// so nothing the panel sent can become a command line.
func startPTY(shell string, env []string, cols, rows uint16) (ptyProcess, error) {
	cmd := exec.Command(shell)
	cmd.Env = env
	// The PTY is a tty; -i keeps the shell interactive without reading a
	// profile the operator did not ask for.
	cmd.Args = []string{shell, "-i"}
	master, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: rows, Cols: cols})
	if err != nil {
		return nil, err
	}
	return &realPTY{cmd: cmd, master: master}, nil
}

func (p *realPTY) read(b []byte) (int, error)  { return p.master.Read(b) }
func (p *realPTY) write(b []byte) (int, error) { return p.master.Write(b) }

func (p *realPTY) resize(cols, rows uint16) error {
	return pty.Setsize(p.master, &pty.Winsize{Rows: rows, Cols: cols})
}

func (p *realPTY) pid() int {
	if p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

// signalTerm asks the whole process group to stop. pty.StartWithSize sets
// Setsid, so the child is the leader of a new group whose pgid equals its pid:
// signalling -pid reaches the shell and everything it started.
func (p *realPTY) signalTerm() error {
	pid := p.pid()
	if pid <= 0 {
		return nil
	}
	if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil {
		// The group may be gone already, or the platform may refuse a group
		// signal: fall back to the process itself.
		if p.cmd != nil && p.cmd.Process != nil {
			return p.cmd.Process.Signal(syscall.SIGTERM)
		}
	}
	return nil
}

func (p *realPTY) signalKill() error {
	pid := p.pid()
	if pid <= 0 {
		return nil
	}
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
		if p.cmd != nil && p.cmd.Process != nil {
			return p.cmd.Process.Kill()
		}
	}
	return nil
}

func (p *realPTY) wait() error {
	if p.cmd == nil {
		return nil
	}
	return p.cmd.Wait()
}

func (p *realPTY) close() error {
	var err error
	p.once.Do(func() {
		if p.master != nil {
			err = p.master.Close()
		}
	})
	return err
}
