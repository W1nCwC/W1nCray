//go:build linux

package selfupdate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// serviceUnits are the init files install.sh writes for this program. A
// self-update is only allowed when one of them runs exactly this executable:
// that is what makes "the new process cannot start" recoverable, because
// Restart=always / respawn / supervise-daemon bring the binary back.
var serviceUnits = []string{
	"/etc/systemd/system/W1nCray.service",
	"/lib/systemd/system/W1nCray.service",
	"/usr/lib/systemd/system/W1nCray.service",
	"/etc/init.d/W1nCray",
}

// Ready reports why this executable cannot self-update in place: the platform
// must support the swap (Supported), the executable must be a replaceable
// regular file in a writable directory, and a service manager must be
// configured to run it. It is the honest gate of the "upgrade" capability
// (protocol ruling 11, PLAN v9 ruling 3).
func Ready(exePath string) error {
	if !Supported() {
		return ErrNotSupported
	}
	if exePath == "" {
		return errors.New("selfupdate: no executable path")
	}
	resolved, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("selfupdate: resolving %s: %w", exePath, err)
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("selfupdate: %s is not a regular file", resolved)
	}
	if err := writableDir(filepath.Dir(resolved)); err != nil {
		return err
	}
	if !unitRuns(resolved) {
		return fmt.Errorf("selfupdate: no service unit runs %s (checked %s); run the agent from its installed service before updating it in place",
			resolved, strings.Join(serviceUnits, ", "))
	}
	return nil
}

// writableDir reports whether a file can be created in dir (the swap needs a
// temporary file next to the executable so both renames stay on one
// filesystem).
func writableDir(dir string) error {
	f, err := os.CreateTemp(dir, ".w1ncray-write-test-*")
	if err != nil {
		return fmt.Errorf("selfupdate: %s is not writable: %w", dir, err)
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

// unitRuns reports whether an init file starts exe.
func unitRuns(exe string) bool {
	for _, path := range serviceUnits {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if unitMentions(string(b), exe) {
			return true
		}
	}
	return false
}

// serviceUnitFor returns the systemd unit name that runs exe (for example
// "W1nCray.service"), or "" when no systemd unit does. Only systemd is
// restarted explicitly after a rollback: OpenRC and procd bring the restored
// binary back with their own respawn, and "systemctl restart" would only fail
// there.
func serviceUnitFor(exe string) string {
	if exe == "" {
		return ""
	}
	for _, path := range serviceUnits {
		if !strings.HasSuffix(path, ".service") {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if unitMentions(string(b), exe) {
			return filepath.Base(path)
		}
	}
	return ""
}

// unitMentions reports whether an init file starts exe: systemd's
// "ExecStart=<exe> ...", OpenRC's command="<exe>" and procd's
// procd_set_param command "<exe>" all put the path in a token of a line that
// also names the command.
func unitMentions(text, exe string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "ExecStart") && !strings.Contains(line, "command") {
			continue
		}
		for _, tok := range strings.FieldsFunc(line, func(r rune) bool {
			return r == ' ' || r == '\t' || r == '"' || r == '\'' || r == '='
		}) {
			if tok == exe {
				return true
			}
		}
	}
	return false
}
