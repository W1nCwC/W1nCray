package prismsvc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/prismapi"
)

const systemdUnitPath = "etc/systemd/system/" + ServiceName + ".service"

// agentProcID is the supervisor id of the kernel in the fallback backend.
const agentProcID = "prism"

// restartDelaySeconds is the pause systemd waits before it starts the kernel
// again after a crash.
const restartDelaySeconds = 5

// systemdUnit renders the unit. The runtime and state directories are their
// own (not the Xray kernel's): stopping one service removes its RuntimeDirectory,
// which must never take the other kernel's socket with it.
func systemdUnit(bin string) string {
	return fmt.Sprintf(`[Unit]
Description=W1nCray Prism kernel
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=%s run --socket unix:%s --state %s
Restart=always
RestartSec=%d
LimitNOFILE=1048576
RuntimeDirectory=%s
RuntimeDirectoryMode=0700
StateDirectory=%s
StateDirectoryMode=0700

[Install]
WantedBy=multi-user.target
`, bin, SocketPath(), KernelStateDir(), restartDelaySeconds, prismapi.RuntimeDirName, prismapi.StateDirName)
}

func (m *Manager) systemctl(ctx context.Context, args ...string) error {
	out, err := m.o.Runner.Run(ctx, "systemctl", args...)
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, oneLine(out))
	}
	return nil
}

func oneLine(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// ensureSystemd writes the unit and makes sure the service runs the installed
// binary.
func (m *Manager) ensureSystemd(ctx context.Context, cur driver.Installed) error {
	path := resolve(m.o.Root, systemdUnitPath)
	want := systemdUnit(cur.Path)
	old, _ := os.ReadFile(path)
	changed := string(old) != want
	if changed {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := writeAtomic(path, []byte(want), 0o644); err != nil {
			return err
		}
		if err := m.systemctl(ctx, "daemon-reload"); err != nil {
			return err
		}
	}
	if err := m.systemctl(ctx, "enable", ServiceName); err != nil {
		return fmt.Errorf("启用 %s 服务: %w", ServiceName, err)
	}

	active := m.isActive(ctx)
	// A changed unit points the service at another binary: only a restart
	// replaces a process that systemd already calls active.
	switch {
	case changed && active:
		m.logf("prismsvc: 服务定义已变化，重启 %s", ServiceName)
		if err := m.systemctl(ctx, "restart", ServiceName); err != nil {
			return err
		}
	case active && m.healthy(ctx) && !m.versionDiffers(ctx, cur.Version):
		return nil
	case active:
		if err := m.systemctl(ctx, "restart", ServiceName); err != nil {
			return err
		}
	default:
		m.logf("prismsvc: 启动 %s %s", ServiceName, cur.Version)
		if err := m.systemctl(ctx, "start", ServiceName); err != nil {
			return err
		}
	}

	return m.waitHealthy(ctx)
}

func (m *Manager) isActive(ctx context.Context) bool {
	out, _ := m.o.Runner.Run(ctx, "systemctl", "is-active", ServiceName)
	switch strings.TrimSpace(string(out)) {
	case "active", "activating":
		return true
	}
	return false
}

func (m *Manager) healthy(ctx context.Context) bool {
	if m.o.Status == nil {
		return true
	}
	sctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err := m.o.Status(sctx)
	return err == nil
}

// versionDiffers reports that the running kernel reports another version than
// the installed one (an upgrade whose binary path did not change).
func (m *Manager) versionDiffers(ctx context.Context, installed string) bool {
	if m.o.Status == nil || installed == "" {
		return false
	}
	sctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	st, err := m.o.Status(sctx)

	return err == nil && st.Version != "" && st.Version != installed
}

// ensureAgent runs the kernel as a child of the agent's supervisor.
func (m *Manager) ensureAgent(ctx context.Context, cur driver.Installed) error {
	if m.o.Sup.Status(agentProcID).Running && m.versionDiffers(ctx, cur.Version) {
		m.logf("prismsvc: 内核版本已变化，重启 %s", ServiceName)
		if err := m.o.Sup.Stop(ctx, agentProcID); err != nil {
			return err
		}
	}
	spec := driver.ProcSpec{
		ID:   agentProcID,
		Path: cur.Path,
		Args: []string{"run", "--socket", "unix:" + SocketPath(), "--state", KernelStateDir()},
		Restart: driver.RestartPolicy{
			Always: true,
		},
	}
	if m.o.StateDir != "" {
		spec.LogFile = filepath.Join(m.o.StateDir, "log", "W1nCray-prism.log")
	}
	if err := os.MkdirAll(filepath.Dir(SocketPath()), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(KernelStateDir(), 0o700); err != nil {
		return err
	}
	if err := m.o.Sup.Start(ctx, spec); err != nil {
		return fmt.Errorf("agent supervisor 启动 %s: %w", ServiceName, err)
	}

	return m.waitHealthy(ctx)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
