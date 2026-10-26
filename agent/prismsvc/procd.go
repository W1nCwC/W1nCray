package prismsvc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/driver"
	"github.com/W1nCwC/W1nCray/agent/xraysvc"
)

// procdScriptPath is the init script of the service (OpenWrt).
const procdScriptPath = "etc/init.d/" + ServiceName

// procdSysupgradePath is OpenWrt's list of extra files sysupgrade keeps.
const procdSysupgradePath = "etc/sysupgrade.conf"

// procdFramework marks a procd machine that has OpenWrt's init framework; a
// procd without it cannot run an init script of this kind.
const procdFramework = "etc/rc.common"

// procdScript renders the procd init script. The kernel restores its
// configuration from its state directory at boot, so the script does not depend
// on the agent. The command line is the same as the systemd and OpenRC ones.
func procdScript(bin string) string {
	sockDir := filepath.Dir(SocketPath())
	stateDir := KernelStateDir()

	return fmt.Sprintf(`#!/bin/sh /etc/rc.common
# W1nCray Prism kernel (procd)

USE_PROCD=1
START=95
STOP=10

start_service() {
	[ -x "%s" ] || { echo "%s is not executable" >&2; return 1; }
	# systemd creates these with RuntimeDirectory= / StateDirectory=.
	mkdir -p "%s" "%s"
	chmod 0700 "%s" "%s"
	procd_open_instance
	procd_set_param command "%s" run --socket unix:%s --state %s
	# Restart after a crash, forever, %d s apart (threshold, timeout, retry).
	procd_set_param respawn 3600 %d 0
	procd_set_param limits nofile=1048576
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_close_instance
}
`, bin, bin, sockDir, stateDir, sockDir, stateDir, bin, SocketPath(), stateDir, restartDelaySeconds, restartDelaySeconds)
}

// procdScriptFile is the script's host path under the manager's root.
func (m *Manager) procdScriptFile() string { return resolve(m.o.Root, procdScriptPath) }

// procdInitEntry is the sysupgrade.conf line of the init script: the real host
// path, without the test root prefix.
func (m *Manager) procdInitEntry() string {
	if m.o.Root == "" {
		return "/" + procdScriptPath
	}
	return m.procdScriptFile()
}

// procdKernelBase derives the kernel base directory from a kernel binary path
// (<base>/kernels/<name>/<version>/<binary>); "" when the path does not have
// that shape (nothing is then added to sysupgrade.conf).
func procdKernelBase(bin string) string {
	if bin == "" {
		return ""
	}
	kernels := filepath.Dir(filepath.Dir(filepath.Dir(bin)))
	if filepath.Base(kernels) != "kernels" {
		return ""
	}
	return filepath.Dir(kernels)
}

// procdCall runs the init script with a verb (the script is run by its path,
// like xraysvc does).
func (m *Manager) procdCall(ctx context.Context, verb string) error {
	script := m.procdScriptFile()
	out, err := m.o.Runner.Run(ctx, script, verb)
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", script, verb, err, oneLine(out))
	}
	return nil
}

// procdState reads the service state from the script's `running` command (exit
// 0 is running). `status` is not used: it reports "running" for a dead
// instance on OpenWrt <= 23.05 (install.sh does the same).
func (m *Manager) procdState(ctx context.Context) string {
	if _, err := m.o.Runner.Run(ctx, m.procdScriptFile(), "running"); err == nil {
		return StateRunning
	}
	return StateStopped
}

// ensureProcd is ensureOpenRC for OpenWrt: the same flow, procd as supervisor.
// OpenWrt's sysupgrade keeps only /etc/config and the listed paths, so the init
// script and the kernel directory (which holds the binary) are listed in
// /etc/sysupgrade.conf. The kernel's runtime and state directories live under
// /run and /var/lib (volatile on OpenWrt), so they are not listed.
func (m *Manager) ensureProcd(ctx context.Context, cur driver.Installed) error {
	return m.ensureScripted(ctx, cur, scriptedInit{
		script: procdScript(cur.Path),
		path:   procdScriptPath,
		write: func() error {
			entries := []string{m.procdInitEntry()}
			if base := procdKernelBase(cur.Path); base != "" {
				entries = append(entries, base)
			}
			return xraysvc.EnsureSysupgrade(resolve(m.o.Root, procdSysupgradePath), entries...)
		},
		enable: func(ctx context.Context) error {
			if err := m.procdCall(ctx, "enable"); err != nil {
				return fmt.Errorf("启用 %s 服务: %w", ServiceName, err)
			}
			return nil
		},
		state: m.procdState,
		call:  m.procdCall,
	})
}

// removeProcd stops the service, takes it out of the boot sequence, deletes the
// init script and its sysupgrade.conf line (the kernel directory line stays:
// the installed kernel files and the Xray kernel share it).
func (m *Manager) removeProcd(ctx context.Context) error {
	if !exists(m.o.Root, procdScriptPath) {
		return nil
	}
	if err := m.procdCall(ctx, "stop"); err != nil {
		return err
	}
	if err := m.procdCall(ctx, "disable"); err != nil {
		// Not being enabled is the goal; log anything else.
		m.logf("prismsvc: %s disable: %s", ServiceName, strings.TrimSpace(err.Error()))
	}
	m.enabled = false
	if err := os.Remove(m.procdScriptFile()); err != nil && !os.IsNotExist(err) {
		return err
	}

	return xraysvc.DropSysupgrade(resolve(m.o.Root, procdSysupgradePath), m.procdInitEntry())
}
