package selfupdate

import (
	"path/filepath"
	"strings"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// AgentIdentity reports whether pid is a W1nCray agent process, that is,
// whether it runs one of the executables a self-update may legitimately install
// or start. It is deliberately conservative: when the executable of pid cannot
// be determined, the answer is "no".
type AgentIdentity func(pid int) bool

// agentIdentity builds the identity check for this updater. Every pid the
// watchdog reads from the single-instance lock or from the ready marker goes
// through it before it is treated as an agent or signalled.
func (u *Updater) agentIdentity(log driver.Logger) AgentIdentity {
	if log == nil {
		log = nopLog{}
	}
	return func(pid int) bool { return u.isAgentPID(pid, log) }
}

// isAgentPID verifies that pid runs one of the executables this updater knows
// about: the install path, the backup next to it, the watchdog copy and the
// staged directory of the pending version. A pid the kernel has reused for an
// unrelated program (sshd, dropbear, any service) fails this check, which is
// what keeps a rollback from killing it.
//
// The kernel's own view of the process is the only accepted evidence. The
// process name (comm) is not, because any program can carry the agent's name.
func (u *Updater) isAgentPID(pid int, log driver.Logger) bool {
	if pid <= 0 {
		return false
	}
	exe, ok := processExecutable(pid)
	if !ok || exe == "" {
		log.Warnf("selfupdate: cannot verify the executable of pid %d; treating it as not the agent", pid)
		return false
	}
	files, dirs := u.agentExecutablePaths()
	for _, f := range files {
		if sameExecutable(exe, f) {
			return true
		}
	}
	for _, d := range dirs {
		if executableInDir(exe, d) {
			return true
		}
	}
	log.Warnf("selfupdate: pid %d is not a W1nCray agent (running %q); ignoring it", pid, exe)
	return false
}

// agentExecutablePaths returns the files an agent may be running from while a
// self-update is pending and the directories whose contents are agent binaries.
// The old binary is included because the process that committed the update
// keeps running from exe.old until it exits. The watchdog directory is used
// rather than WatchdogPath() because the watchdog's own Updater does not know
// the version it was copied from, so only the directory is stable there.
func (u *Updater) agentExecutablePaths() (files, dirs []string) {
	files = []string{u.exe, u.OldPath()}
	dirs = []string{u.watchdogDir()}
	if p, ok := u.Pending(); ok {
		// Stage extracts the verified binary into the version directory under
		// the name the manifest chose, so the directory is the stable part.
		dirs = append(dirs, u.stagedVersionDir(p.Version))
	}
	return files, dirs
}

// stagedVersionDir is <StateDir>/update/staged/<version>, the directory Stage
// extracts a version into.
func (u *Updater) stagedVersionDir(version string) string {
	if version == "" {
		return ""
	}
	return filepath.Join(u.dir, "staged", version)
}

// sameExecutable reports whether two paths name the same file.
func sameExecutable(a, b string) bool {
	a, b = resolvePath(a), resolvePath(b)
	return a != "" && a == b
}

// executableInDir reports whether exe is a file inside dir (the staged version
// directory and the watchdog directory hold the binary under a chosen name).
func executableInDir(exe, dir string) bool {
	exe, dir = resolvePath(exe), resolvePath(dir)
	if exe == "" || dir == "" {
		return false
	}
	if !strings.HasSuffix(dir, string(filepath.Separator)) {
		dir += string(filepath.Separator)
	}
	return strings.HasPrefix(exe, dir)
}

// resolvePath resolves symlinks when it can and cleans the path otherwise.
// /proc/<pid>/exe reports the real path, while the updater's own paths may be
// reached through a symlink (for example /usr/local/bin/W1nCray), so both sides
// are normalised before they are compared.
func resolvePath(p string) string {
	if p == "" {
		return ""
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return filepath.Clean(r)
	}
	return filepath.Clean(p)
}
