//go:build windows

package supervisor

import (
	"os"
	"os/exec"
)

// Windows has no process groups or SIGTERM for console-less children: every
// "graceful" step falls back to Kill, and descendants of the child are not
// tracked (documented limitation).
func setProcAttr(cmd *exec.Cmd) {}

func termProc(p *os.Process) error { return p.Kill() }

func killProc(p *os.Process) error { return p.Kill() }

func sweepGroup(pid int) {}

func signalPID(pid int, kill bool) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	defer p.Release()
	return p.Kill()
}

func pidAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// FindProcess opens a handle on Windows, so success means the pid exists.
	p.Release()
	return true
}
