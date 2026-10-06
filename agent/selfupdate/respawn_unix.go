//go:build unix

package selfupdate

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// Supported reports whether this build can replace its own executable and
// respawn it. It is the platform half of the upgrade capability; Ready adds
// the install-method half (a service manager that runs this executable).
func Supported() bool { return true }

// respawn starts the helper in its own session (setsid) so it is not killed by
// the terminal or process group of the agent that is exiting, with stdio
// detached and an argv array (never a shell).
func respawn(exe string, argv []string, h HelperOptions, log driver.Logger) error {
	if h.StateDir == "" {
		return fmt.Errorf("selfupdate: no state directory for the respawn helper")
	}
	args := append([]string{HelperCommand}, HelperArgv(exe, argv, h)...)
	cmd := exec.Command(exe, args...)
	cmd.Env = os.Environ()
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("selfupdate: starting the respawn helper: %w", err)
	}
	if log != nil {
		log.Infof("selfupdate: respawn helper started (pid %d)", cmd.Process.Pid)
	}
	return cmd.Process.Release()
}

// processAlive reports whether pid exists (signal 0).
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}
