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

// deletedSuffix is what the kernel appends to the /proc/self/exe target once
// the running image has been unlinked. A rollback that raced this process's
// start leaves exactly that behind, and it must not cost the machine its
// upgrade capability for good (D-M7).
const deletedSuffix = " (deleted)"

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
	if err != nil && strings.HasSuffix(exePath, deletedSuffix) {
		// /proc/self/exe reports "<path> (deleted)" after a rollback unlinked
		// the running image. The install path itself is usually fine again by
		// then, so retry without the marker before refusing.
		if r2, err2 := filepath.EvalSymlinks(strings.TrimSuffix(exePath, deletedSuffix)); err2 == nil {
			resolved, err = r2, nil
		}
	}
	if err != nil {
		return fmt.Errorf("selfupdate: resolving %s: %w (the running image was replaced or removed; reinstall the agent, or point the service at %s)",
			exePath, err, strings.Join(serviceUnits, ", "))
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

// ServiceExecutable returns the executable a service manager runs for this
// agent, derived from the init files in serviceUnits, or "" when none is found.
//
// It is the fallback target when /proc/self/exe no longer resolves (the running
// image was unlinked by a rollback that raced this process's start). The
// install path is still the file that has to be swapped, so targeting it is
// what lets the panel self_update this machine back into a consistent state
// instead of losing the capability for good (D-M7).
func ServiceExecutable() string {
	for _, path := range serviceUnits {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if exe := commandExecutable(string(b)); exe != "" {
			return exe
		}
	}
	return ""
}

// commandExecutable extracts the executable an init file starts: the first
// absolute-path token on an ExecStart/command line that exists and is
// executable. systemd's "ExecStart=<exe> ...", OpenRC's command="<exe>" and
// procd's procd_set_param command "<exe>" all put it there, ahead of any option
// such as "-c /etc/W1nCray/config.yml" (which exists too, but is not
// executable).
func commandExecutable(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "ExecStart") && !strings.Contains(line, "command") {
			continue
		}
		for _, tok := range splitCommandLine(line) {
			if !strings.HasPrefix(tok, "/") {
				continue
			}
			fi, err := os.Stat(tok)
			if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
				continue
			}
			return tok
		}
	}
	return ""
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
		for _, tok := range splitCommandLine(line) {
			if tok == exe {
				return true
			}
		}
	}
	return false
}

// splitCommandLine tokenizes an init-file line: whitespace, quotes and '=' all
// separate the tokens, so "ExecStart=/usr/bin/W1nCray" and
// `command="/usr/bin/W1nCray"` both yield the path.
func splitCommandLine(line string) []string {
	return strings.FieldsFunc(line, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '"' || r == '\'' || r == '='
	})
}
