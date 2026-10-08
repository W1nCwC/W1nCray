package selfupdate

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// The service names the installer writes. They mirror xraysvc.ServiceName and
// the agent's own unit name; the strings are duplicated here because the
// watchdog must not drag the kernel-install tree (agent/xraysvc) into its
// dependency set.
const (
	agentServiceName = "W1nCray"
	xrayServiceName  = "W1nCray-xray"
)

// serviceCommandTimeout bounds one service-manager call. The rollback runs on a
// detached context (the watchdog may be shutting down), but a hung
// service-manager call must not hold it forever.
const serviceCommandTimeout = 20 * time.Second

// serviceExists reports whether an absolute path exists. It is a variable so
// the backend detection is testable without the machine's real init system.
var serviceExists = func(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// runServiceCommand runs one service-manager command. It is a variable so a
// test can observe the rollback's service calls without a service manager.
var runServiceCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	//nolint:noshell -- a fixed service-manager command with an argv array,
	// never a shell string.
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// stopXrayCommand returns the argv that stops the W1nCray-xray service on this
// machine, or nil when no service manager owns it. It is pure: the platform
// facts are passed in, so systemd, OpenRC, procd and the no-manager fallback
// are all testable.
//
// The order matches xraysvc.newBackend: systemd, then OpenRC, then procd.
func stopXrayCommand(exists func(string) bool) []string {
	switch {
	case exists("/run/systemd/system"):
		return []string{"systemctl", "stop", xrayServiceName}
	case exists("/sbin/openrc-run"):
		return []string{"rc-service", xrayServiceName, "stop"}
	case exists("/sbin/procd") && exists("/etc/rc.common"):
		return []string{"/etc/init.d/" + xrayServiceName, "stop"}
	default:
		return nil
	}
}

// restartAgentCommand returns the commands that bring the restored agent
// binary back, or nil when no service manager owns it. unit is the systemd unit
// name the watchdog detected ("" falls back to the conventional name).
func restartAgentCommand(unit string, exists func(string) bool) [][]string {
	if unit == "" {
		unit = agentServiceName + ".service"
	}
	switch {
	case exists("/run/systemd/system"):
		return [][]string{
			{"systemctl", "reset-failed", unit},
			{"systemctl", "restart", unit},
		}
	case exists("/sbin/openrc-run"):
		return [][]string{{"rc-service", agentServiceName, "restart"}}
	case exists("/sbin/procd") && exists("/etc/rc.common"):
		return [][]string{{"/etc/init.d/" + agentServiceName, "restart"}}
	default:
		return nil
	}
}

// stopXrayService stops the W1nCray-xray service before a rollback (R1-16). A
// rollback can restore an in-process-Xray 0.5.x agent, which must not find the
// 0.6 service already holding the node ports. It is best effort: every failure
// is logged, never returned, because the rollback itself must still happen.
func stopXrayService(log driver.Logger) {
	argv := stopXrayCommand(serviceExists)
	if len(argv) == 0 {
		if log != nil {
			log.Infof("selfupdate: no service manager owns %s; nothing to stop before the rollback", xrayServiceName)
		}
		return
	}
	runService(argv, log)
}

// restartService brings the restored binary back after a rollback. On systemd
// the unit is reset and restarted; OpenRC and procd get their own restart so
// the restored file is what runs even when the manager already respawned the
// failed one while the rollback ran. A failure is only logged: the service
// manager may already be bringing the restored binary back, and a rollback that
// succeeded must not be reported as failed because the manager was unavailable.
func restartService(h HelperOptions, log driver.Logger) {
	cmds := restartAgentCommand(h.Unit, serviceExists)
	if len(cmds) == 0 {
		if log != nil {
			log.Warnf("selfupdate: no service manager was found (checked systemd, OpenRC, procd); the restored %s must be started by hand",
				h.ExePath)
		}
		return
	}
	for _, argv := range cmds {
		runService(argv, log)
	}
}

// runService runs one best-effort service-manager command and logs the result.
func runService(argv []string, log driver.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), serviceCommandTimeout)
	defer cancel()
	out, err := runServiceCommand(ctx, argv[0], argv[1:]...)
	if err != nil {
		if log != nil {
			log.Warnf("selfupdate: %s failed: %v: %s", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
		}
		return
	}
	if log != nil {
		log.Infof("selfupdate: %s", strings.Join(argv, " "))
	}
}
