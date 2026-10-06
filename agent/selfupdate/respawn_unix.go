//go:build unix

package selfupdate

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// systemdRunTimeout bounds the systemd-run call: the agent is about to exit and
// must not be held up by a misbehaving bus. --no-block means systemd-run
// returns as soon as the transient unit is enqueued, so this is generous.
const systemdRunTimeout = 15 * time.Second

// Supported reports whether this build can replace its own executable and
// respawn it. It is the platform half of the upgrade capability; Ready adds
// the install-method half (a service manager that runs this executable).
func Supported() bool { return true }

// respawn starts the watchdog from the known-good copy of the previous binary.
//
// On systemd the watchdog is started as its own transient unit through
// systemd-run. That is not cosmetic: the default KillMode=control-group makes
// systemd kill every process of the service's cgroup when the service stops or
// restarts, which is exactly what happens right after a self-update, so a
// watchdog merely detached with setsid would be killed with the agent it is
// supposed to watch. Without systemd (OpenRC, procd, no service manager) the
// process is detached into its own session instead. A failed systemd-run is
// logged and falls back to that, so a broken systemd-run never fails an update.
func respawn(watchdogExe string, h HelperOptions, log driver.Logger) error {
	if h.StateDir == "" {
		return fmt.Errorf("selfupdate: no state directory for the watchdog")
	}
	args := WatchdogArgs(h)
	if systemdRunAvailable() {
		unit := systemdUnitName(time.Now())
		if err := runSystemdRun(unit, watchdogExe, args, log); err == nil {
			return nil
		} else if log != nil {
			log.Warnf("selfupdate: systemd-run could not start the watchdog (%v); falling back to setsid", err)
		}
	}
	return runSetsid(watchdogExe, args, log)
}

// lookSystemdRun is exec.LookPath; a variable so tests can force the fallback.
var lookSystemdRun = exec.LookPath

// systemdRunAvailable reports whether the watchdog can be started through
// systemd-run on this machine.
func systemdRunAvailable() bool {
	_, err := os.Stat("/run/systemd/system")
	return useSystemdRun(os.Getenv("INVOCATION_ID"), err == nil, lookSystemdRun)
}

// runSystemdRun starts the watchdog in its own transient unit and waits only
// for systemd-run to enqueue it (--no-block).
func runSystemdRun(unit, watchdogExe string, args []string, log driver.Logger) error {
	argv := SystemdRunArgv(unit, watchdogExe, args)
	ctx, cancel := context.WithTimeout(context.Background(), systemdRunTimeout)
	defer cancel()
	//nolint:noshell -- systemd-run with an argv array, never a shell.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = os.Environ()
	cmd.Stdin = nil
	cmd.Stdout = nil
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("systemd-run: %w: %s", err, msg)
		}
		return fmt.Errorf("systemd-run: %w", err)
	}
	if log != nil {
		log.Infof("selfupdate: watchdog started as the transient unit %s", unit)
	}
	return nil
}

// runSetsid starts the watchdog in its own session, with stdio detached and an
// argv array (never a shell). The service manager's own restart is then the
// only guarantee that the watchdog survives a stop of the service.
func runSetsid(watchdogExe string, args []string, log driver.Logger) error {
	//nolint:noshell -- watchdogExe is the verified copy of this agent's own
	// executable and the arguments are an argv array, never a shell string.
	cmd := exec.Command(watchdogExe, args...)
	cmd.Env = os.Environ()
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("selfupdate: starting the watchdog: %w", err)
	}
	if log != nil {
		log.Infof("selfupdate: watchdog started (pid %d)", cmd.Process.Pid)
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
