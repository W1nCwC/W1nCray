//go:build unix

package supervisor

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
)

// setProcAttr makes the child the leader of a new process group so the whole
// tree can be signalled at once and does not receive the agent's terminal
// signals.
func setProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// termProc asks the process group to stop (SIGTERM).
func termProc(p *os.Process) error { return syscall.Kill(-p.Pid, syscall.SIGTERM) }

// killProc kills the process group (SIGKILL).
func killProc(p *os.Process) error { return syscall.Kill(-p.Pid, syscall.SIGKILL) }

// sweepGroup kills anything still in the group of a process that has exited.
// A pgid stays reserved while any member lives, so this cannot hit an
// unrelated group unless the whole group vanished and the id was recycled
// within microseconds, which we accept.
func sweepGroup(pid int) { _ = syscall.Kill(-pid, syscall.SIGKILL) }

// signalPID signals the group of pid if it leads one, else the process alone.
func signalPID(pid int, kill bool) error {
	sig := syscall.SIGTERM
	if kill {
		sig = syscall.SIGKILL
	}
	if pg, err := syscall.Getpgid(pid); err == nil && pg == pid {
		return syscall.Kill(-pid, sig)
	}
	return syscall.Kill(pid, sig)
}

// pidAlive reports whether a live process has this pid. A zombie (exited but
// not yet reaped, for example an orphan under an init that does not reap) does
// not count as alive.
func pidAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	if err != nil && !errors.Is(err, syscall.EPERM) {
		return false
	}
	return !isZombie(pid)
}

func isZombie(pid int) bool {
	if runtime.GOOS != "linux" {
		return false
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	// "pid (comm) S ...": comm may contain spaces and parentheses, so look
	// for the last ')'.
	i := bytes.LastIndexByte(b, ')')
	return i >= 0 && i+2 < len(b) && b[i+2] == 'Z'
}
