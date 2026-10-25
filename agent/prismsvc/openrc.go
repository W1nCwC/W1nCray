package prismsvc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// openrcScriptPath is the init script of the service.
const openrcScriptPath = "etc/init.d/" + ServiceName

// openrcSoftlevel exists only while OpenRC is the running init system; an
// installed but idle OpenRC (a container image, say) has no such file.
const openrcSoftlevel = "run/openrc/softlevel"

// openrcScript renders the OpenRC init script with supervise-daemon as the
// supervisor, like xraysvc does for the Xray kernel. The kernel restores its
// configuration from its state directory at boot, so the script does not
// depend on the agent.
func openrcScript(bin string) string {
	sockDir := filepath.Dir(SocketPath())
	stateDir := KernelStateDir()

	return fmt.Sprintf(`#!/sbin/openrc-run
# W1nCray Prism kernel (OpenRC)

name="%s"
description="W1nCray Prism kernel"

supervisor="supervise-daemon"
command="%s"
command_args="run --socket unix:%s --state %s"

# Restart after a crash, forever, %d s apart.
respawn_delay=%d
respawn_max=0
retry="TERM/10/KILL/5"

rc_ulimit="-n 1048576"

output_log="/var/log/%s.log"
error_log="/var/log/%s.log"

depend() {
	need localmount
	after net firewall
	use dns
}

start_pre() {
	[ -x "$command" ] || { eerror "$command is not executable"; return 1; }
	# systemd creates these with RuntimeDirectory= / StateDirectory=.
	checkpath -d -m 0700 -o root:root %s
	checkpath -d -m 0700 -o root:root %s
	# Keep the log from growing without bound.
	if [ -f "$output_log" ] && [ "$(wc -c <"$output_log")" -gt 10485760 ]; then
		: >"$output_log"
	fi
	return 0
}
`, ServiceName, bin, SocketPath(), stateDir, restartDelaySeconds, restartDelaySeconds, ServiceName, ServiceName, sockDir, stateDir)
}

func (m *Manager) rcService(ctx context.Context, args ...string) error {
	full := append([]string{ServiceName}, args...)
	out, err := m.o.Runner.Run(ctx, "rc-service", full...)
	if err != nil {
		return fmt.Errorf("rc-service %s: %w: %s", strings.Join(full, " "), err, oneLine(out))
	}
	return nil
}

// openrcState reads the service state from `rc-service <name> status`: exit 0
// is running, "crashed" in the output is failed, anything else stopped.
func (m *Manager) openrcState(ctx context.Context) string {
	out, err := m.o.Runner.Run(ctx, "rc-service", ServiceName, "status")
	if err == nil {
		return StateRunning
	}
	if strings.Contains(string(out), "crashed") {
		return StateFailed
	}
	return StateStopped
}

// ensureOpenRC writes the init script, enables it at boot and makes sure the
// service runs the installed binary. The logic mirrors ensureSystemd.
func (m *Manager) ensureOpenRC(ctx context.Context, cur driver.Installed) error {
	path := resolve(m.o.Root, openrcScriptPath)
	want := openrcScript(cur.Path)
	old, _ := os.ReadFile(path)
	changed := string(old) != want
	if changed {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := writeAtomic(path, []byte(want), 0o755); err != nil {
			return err
		}
	}
	// rc-update is not repeated on every pass (the controller calls Ensure
	// often): only for a new script, or once per process.
	if changed || !m.enabled {
		out, err := m.o.Runner.Run(ctx, "rc-update", "add", ServiceName, "default")
		if err != nil {
			return fmt.Errorf("启用 %s 服务: rc-update add %s default: %w: %s", ServiceName, ServiceName, err, oneLine(out))
		}
		m.enabled = true
	}

	active := m.openrcState(ctx) == StateRunning
	switch {
	case changed && active:
		m.logf("prismsvc: 服务定义已变化，重启 %s", ServiceName)
		m.recoverOrphan(ctx)
		if err := m.rcService(ctx, "restart"); err != nil {
			return err
		}
	case active && m.healthy(ctx) && !m.versionDiffers(ctx, cur.Version):
		return nil
	case active:
		m.recoverOrphan(ctx)
		if err := m.rcService(ctx, "restart"); err != nil {
			return err
		}
	default:
		m.logf("prismsvc: 启动 %s %s", ServiceName, cur.Version)
		m.recoverOrphan(ctx)
		if err := m.rcService(ctx, "start"); err != nil {
			return err
		}
	}

	return m.waitHealthy(ctx)
}

// recoverOrphan ends a kernel an earlier agent run left under its own
// supervisor, once, before OpenRC takes the kernel over. A failure is logged:
// the start then fails on its own if the socket is really still taken.
func (m *Manager) recoverOrphan(ctx context.Context) {
	if m.migrated || m.o.RecoverOrphan == nil {
		return
	}
	if err := m.o.RecoverOrphan(ctx, agentProcID); err != nil {
		m.logf("prismsvc: 清理旧的 agent 子进程失败: %v", err)
		return
	}
	m.migrated = true
}

// removeOpenRC stops the service, drops it from the default runlevel and
// deletes the init script.
func (m *Manager) removeOpenRC(ctx context.Context) error {
	if !exists(m.o.Root, openrcScriptPath) {
		return nil
	}
	if err := m.rcService(ctx, "stop"); err != nil {
		return err
	}
	if out, err := m.o.Runner.Run(ctx, "rc-update", "del", ServiceName, "default"); err != nil {
		// Not being in the runlevel is the goal; log anything else.
		m.logf("prismsvc: rc-update del %s default: %v: %s", ServiceName, err, oneLine(out))
	}
	m.enabled = false
	if err := os.Remove(resolve(m.o.Root, openrcScriptPath)); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}
