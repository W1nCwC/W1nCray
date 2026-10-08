package xraysvc

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/xrayapi"
)

// restartDelaySeconds is the pause every service backend waits before it starts
// the Xray kernel again after a crash. All three service definitions render it
// from here so that a kernel crash interrupts the same number of seconds on
// systemd, OpenRC and procd machines (T1 measured OpenRC/procd at 10 s versus
// systemd's 5 s).
//
// Each backend spells the pause differently:
//
//   - systemd: RestartSec=<pause> is the delay before Restart=always starts the
//     unit again.
//   - OpenRC supervise-daemon: respawn_delay=<pause> is the delay between
//     restarts; respawn_max=0 means the restarts are unlimited.
//   - procd: respawn <threshold> <timeout> <retry>; threshold is the window
//     after which the retry counter resets (3600 s), timeout is the delay
//     before the process is restarted (the pause) and retry=0 means unlimited
//     retries.
//
// Only the pause is shared: the procd threshold and the unlimited-retry
// semantics of both respawn settings stay exactly as they were.
const restartDelaySeconds = 5

// systemdUnit renders the systemd unit of the Xray kernel. The ExecStart names
// the kernel binary of the current version and the "run -c" subcommand
// explicitly, so the unit never depends on the program's default action.
//
// RuntimeDirectory=W1nCray makes systemd create /run/W1nCray (mode 0755) before
// the service starts and remove it after it stops; that is where the kernel
// publishes its status socket, away from the etc_t configuration directory
// (agent/selinux explains why a socket under /etc/W1nCray cannot be created by
// this service's domain).
func systemdUnit(bin, configPath, configDir string) string {
	return fmt.Sprintf(`[Unit]
Description=W1nCray Xray kernel
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=%s
ExecStart=%s run -c %s
Restart=always
RestartSec=%s
LimitNOFILE=1048576
Environment=XRAY_LOCATION_ASSET=%s
RuntimeDirectory=%s
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
`, configDir, bin, configPath, strconv.Itoa(restartDelaySeconds), configDir, xrayapi.RuntimeDirName)
}

// openrcScript renders the OpenRC init script (Alpine), with supervise-daemon
// as the supervisor, exactly like install.sh's OpenRC backend.
func openrcScript(bin, configPath, configDir string) string {
	return fmt.Sprintf(`#!/sbin/openrc-run
# W1nCray Xray kernel (OpenRC)

name="%s"
description="W1nCray Xray kernel"

supervisor="supervise-daemon"
command="%s"
command_args="run -c %s"
directory="%s"

# Restart after a crash, forever, %s s apart.
respawn_delay=%s
respawn_max=0

rc_ulimit="-n 1048576"

output_log="/var/log/%s.log"
error_log="/var/log/%s.log"

supervise_daemon_args="--env XRAY_LOCATION_ASSET=%s"

depend() {
	need localmount
	after net firewall
	use dns
}

start_pre() {
	# The status socket lives in the runtime directory; systemd creates it with
	# RuntimeDirectory=, OpenRC has to do it here.
	mkdir -p /run/%s
	# Keep the log from growing without bound.
	if [ -f "$output_log" ] && [ "$(wc -c <"$output_log")" -gt 10485760 ]; then
		: >"$output_log"
	fi
	return 0
}
`, ServiceName, bin, configPath, configDir, strconv.Itoa(restartDelaySeconds), strconv.Itoa(restartDelaySeconds), ServiceName, ServiceName, configDir, xrayapi.RuntimeDirName)
}

// procdScript renders the procd init script (OpenWrt), exactly like
// install.sh's procd backend. memLimit is the extra environment ("" or
// "GOMEMLIMIT=...MiB") small routers need.
func procdScript(bin, configPath, configDir, memLimit string) string {
	env := "XRAY_LOCATION_ASSET=" + configDir
	if memLimit != "" {
		env += " " + memLimit
	}
	return fmt.Sprintf(`#!/bin/sh /etc/rc.common
# W1nCray Xray kernel (procd)

USE_PROCD=1
START=99
STOP=10

start_service() {
	# The status socket lives in the runtime directory; procd has no equivalent
	# of systemd's RuntimeDirectory=, so create it here.
	mkdir -p /run/%s
	procd_open_instance
	procd_set_param command "%s" run -c "%s"
	procd_set_param env %s
	procd_set_param limits nofile="1048576 1048576"
	# Restart after a crash, forever, %s s apart (threshold, timeout, retry).
	procd_set_param respawn 3600 %s 0
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_set_param term_timeout 10
	procd_close_instance
}
`, xrayapi.RuntimeDirName, bin, configPath, env, strconv.Itoa(restartDelaySeconds), strconv.Itoa(restartDelaySeconds))
}

// gomemLimit returns the GOMEMLIMIT setting for a router with less than 1 GiB
// of RAM (40% of MemTotal, like install.sh) and "" when it is not needed or
// /proc/meminfo cannot be read.
func gomemLimit(root string) string {
	path := "/proc/meminfo"
	if root != "" {
		path = filepath.Join(root, "proc", "meminfo")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(key) != "MemTotal" {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			return ""
		}
		kb, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil || kb <= 0 {
			return ""
		}
		mb := kb / 1024
		if mb >= 1024 {
			return ""
		}
		return fmt.Sprintf("GOMEMLIMIT=%dMiB", mb*40/100)
	}
	return ""
}

// ensureSysupgrade adds entries to /etc/sysupgrade.conf, one per line, without
// duplicating a line that is already there. The file's other content is kept.
func ensureSysupgrade(path string, entries ...string) error {
	content, _ := os.ReadFile(path)
	lines, trailing := splitLines(string(content))
	have := map[string]bool{}
	for _, l := range lines {
		have[l] = true
	}
	changed := false
	for _, e := range entries {
		if e == "" || have[e] {
			continue
		}
		lines = append(lines, e)
		have[e] = true
		changed = true
	}
	if !changed && !trailing {
		return nil
	}
	_, err := writeIfChanged(path, joinLines(lines), 0o644)
	return err
}

// dropSysupgrade removes exact lines from /etc/sysupgrade.conf.
func dropSysupgrade(path string, entries ...string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	drop := map[string]bool{}
	for _, e := range entries {
		drop[e] = true
	}
	lines, _ := splitLines(string(content))
	out := lines[:0]
	for _, l := range lines {
		if !drop[l] {
			out = append(out, l)
		}
	}
	if len(out) == len(lines) {
		return nil
	}
	_, err = writeIfChanged(path, joinLines(out), 0o644)
	return err
}

// splitLines splits content into lines and reports whether it ended with a
// newline (so an empty file and a file with a single empty line differ).
func splitLines(content string) (lines []string, trailing bool) {
	if content == "" {
		return nil, true
	}
	trailing = strings.HasSuffix(content, "\n")
	content = strings.TrimSuffix(content, "\n")
	if content == "" {
		return nil, trailing
	}
	return strings.Split(content, "\n"), trailing
}

// joinLines renders lines with one trailing newline.
func joinLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}
