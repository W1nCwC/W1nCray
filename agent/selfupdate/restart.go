package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// HelperOptions is what the detached watchdog needs. Respawn passes it on the
// watchdog's command line; ParseHelperArgs reads it back.
type HelperOptions struct {
	// ParentPID is the agent that committed the update and is about to exit.
	// The watchdog waits for it so it never mistakes it for the new process.
	ParentPID int
	// ExePath is the executable the update replaced: the new, unproven one.
	// It is what the watchdog rolls back over when the new one cannot run.
	ExePath string
	// StateDir holds update/pending.json, which the rollback needs.
	StateDir string
	// LockPath is the single-instance lock (<config>.lock) that records the
	// pid of the running agent. It is how the watchdog tells "the new version
	// is up" from "the service manager is restarting a broken binary".
	LockPath string
	// Unit is the service unit to restart after a rollback (systemd only, ""
	// otherwise). The manager's own respawn is the fallback.
	Unit string
	// Argv is the agent's own argument list, without the program name. The
	// watchdog does not start the agent itself any more; the field is kept so
	// the helper's command line stays a faithful record of what was replaced.
	Argv []string

	// Attempts is how many agent restarts the watchdog tolerates before it
	// rolls back; AliveWindow how long it tolerates no live agent; Deadline is
	// the total budget; PollInterval how often it probes.
	Attempts     int
	AliveWindow  time.Duration
	Deadline     time.Duration
	PollInterval time.Duration
}

// Respawn starts the detached watchdog. It is a variable so tests can observe
// the spawn; production code never changes it. respawn is platform specific
// and returns ErrNotSupported where a process cannot detach itself.
var Respawn = respawn

// RespawnHelper starts the watchdog for this updater. It is called after
// Commit, just before the process exits, and runs the known-good copy Commit
// left in update/watchdog, never the new binary, which is the thing that may
// not be able to run.
func (u *Updater) RespawnHelper() error {
	copyPath := u.WatchdogPath()
	if _, err := os.Stat(copyPath); err != nil {
		return fmt.Errorf("selfupdate: the watchdog copy %s is missing: %w", copyPath, err)
	}
	h := HelperOptions{
		ParentPID:    os.Getpid(),
		ExePath:      u.exe,
		StateDir:     u.stateDir,
		LockPath:     u.lockPath,
		Unit:         serviceUnitFor(u.exe),
		Argv:         os.Args[1:],
		Attempts:     u.attempts,
		AliveWindow:  u.aliveWindow,
		Deadline:     u.deadline,
		PollInterval: u.pollInterval,
	}
	return Respawn(copyPath, h, u.log)
}

// HelperCommand is the hidden subcommand the watchdog runs under. It is a
// watchdog, not a respawner: it never starts the agent, it only decides whether
// the service manager's restarts are making progress and rolls the update back
// when they are not.
const HelperCommand = "__watchdog"

// ParseHelperArgs parses the watchdog's argv (everything after HelperCommand):
//
//	-parent PID -state DIR -exe EXE [-lock FILE] [-unit UNIT]
//	[-attempts N] [-window D] [-deadline D] [-poll 2s] -- <agent argv...>
//
// A missing -window or -deadline falls back to DefaultWatchdogWindows(GOARCH):
// 60 s / 3 min on amd64 and arm64, 180 s / 8 min on the slower targets.
func ParseHelperArgs(args []string) (HelperOptions, error) {
	var (
		h   HelperOptions
		err error
	)
	for i := 0; i < len(args); {
		a := args[i]
		if a == "--" {
			i++
			h.Argv = append([]string(nil), args[i:]...)
			return h, nil
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			return h, fmt.Errorf("selfupdate: unexpected argument %q", a)
		}
		key := strings.TrimLeft(a, "-")
		val := ""
		if eq := strings.IndexByte(key, '='); eq >= 0 {
			key, val = key[:eq], key[eq+1:]
			i++
		} else {
			if i+1 >= len(args) {
				return h, fmt.Errorf("selfupdate: %s needs a value", a)
			}
			val = args[i+1]
			i += 2
		}
		switch key {
		case "parent":
			h.ParentPID, err = strconv.Atoi(val)
		case "state":
			h.StateDir = val
		case "exe":
			h.ExePath = val
		case "lock":
			h.LockPath = val
		case "unit":
			h.Unit = val
		case "attempts":
			h.Attempts, err = strconv.Atoi(val)
		case "window":
			h.AliveWindow, err = time.ParseDuration(val)
		case "deadline":
			h.Deadline, err = time.ParseDuration(val)
		case "poll":
			h.PollInterval, err = time.ParseDuration(val)
		default:
			return h, fmt.Errorf("selfupdate: unknown helper option %q", a)
		}
		if err != nil {
			return h, fmt.Errorf("selfupdate: %s: %w", a, err)
		}
	}
	h.Argv = nil
	return h, nil
}

// HelperArgv builds the watchdog's argument list (without the subcommand) for
// Respawn implementations and tests.
func HelperArgv(exe string, argv []string, h HelperOptions) []string {
	args := []string{
		"-parent", strconv.Itoa(h.ParentPID),
		"-state", h.StateDir,
		"-exe", exe,
		"-attempts", strconv.Itoa(h.Attempts),
		"-window", h.AliveWindow.String(),
		"-deadline", h.Deadline.String(),
		"-poll", h.PollInterval.String(),
	}
	if h.LockPath != "" {
		args = append(args, "-lock", h.LockPath)
	}
	if h.Unit != "" {
		args = append(args, "-unit", h.Unit)
	}
	args = append(args, "--")
	return append(args, argv...)
}

// WatchdogArgs is the watchdog's own argument list: the hidden subcommand
// followed by HelperArgv. The program name is not part of it.
func WatchdogArgs(h HelperOptions) []string {
	return append([]string{HelperCommand}, HelperArgv(h.ExePath, h.Argv, h)...)
}

// SystemdRunArgv is the argv that starts the watchdog as its own transient
// unit through systemd-run. It is an argv array, never a shell command string:
// the executable path and every argument stay one element each.
func SystemdRunArgv(unit, watchdogExe string, args []string) []string {
	argv := []string{
		"systemd-run",
		"--quiet",
		"--collect",
		"--no-block",
		"--unit=" + unit,
		"--",
		watchdogExe,
	}
	return append(argv, args...)
}

// systemdUnitName is the transient unit name of a watchdog started at t. The
// unit name makes the watchdog's cgroup independent of the service's, which is
// what keeps KillMode=control-group from killing it with the service.
func systemdUnitName(t time.Time) string {
	return fmt.Sprintf("w1ncray-selfupdate-%d", t.Unix())
}

// useSystemdRun decides whether the watchdog can be started through
// systemd-run. A systemd-managed invocation (INVOCATION_ID set, or
// /run/systemd/system present) and a usable systemd-run binary are both
// required; anything else means the caller has to fall back to a detached
// session (setsid), where the service's cgroup may still kill the watchdog.
func useSystemdRun(invocationID string, systemdDir bool, lookPath func(string) (string, error)) bool {
	if invocationID == "" && !systemdDir {
		return false
	}
	if lookPath == nil {
		return false
	}
	_, err := lookPath("systemd-run")
	return err == nil
}

// AgentProbe reports the pid of the agent that currently holds the
// single-instance lock and whether that process is alive.
type AgentProbe func() (pid int, alive bool)

// RunHelper is the watchdog's main loop: wait for the agent that committed the
// update to exit, then watch the new version until it confirms the update,
// until the service manager is clearly not making progress (roll back), or
// until the deadline (report stalled, keep the update). It is what makes a
// version that cannot start recoverable.
func RunHelper(ctx context.Context, h HelperOptions, log driver.Logger) error {
	up, err := New(Options{ExePath: h.ExePath, StateDir: h.StateDir, LockPath: h.LockPath, Log: log})
	if err != nil {
		return err
	}
	return runWatchdog(ctx, h, up.agentProbe(), time.Now, time.Sleep, log)
}

// agentProbe is the production liveness probe. The authoritative signal is the
// ready marker the new process writes at start-up (D-M7): it carries the
// version and the pid, so the watchdog can tell "the new version is really
// running" from "the service manager has not started it yet" and from a stale
// single-instance lock holding the pid of the process that just exited. The
// lock stays as the fallback for a process that started before the marker
// existed or could not write it.
//
// A live pid is not enough: the pid has to be running an agent executable.
// The lock file and the ready marker are both on-disk records that outlive the
// process they name, and the kernel hands a freed pid to whatever is started
// next, so a stale record can point at an unrelated program (F3b). A pid that
// fails the identity check is reported as "no agent", never as a live one.
func (u *Updater) agentProbe() AgentProbe {
	isAgent := u.agentIdentity(u.log)
	return func() (int, bool) {
		if m, ok := u.ReadyMarker(); ok {
			if p, pending := u.Pending(); pending && m.Version == p.Version && processAlive(m.PID) && isAgent(m.PID) {
				return m.PID, true
			}
			// A marker whose version does not match the pending update is
			// stale (an older process left it behind) or carries no version
			// at all: never treat it as the new version.
		}
		pid := lockPID(u.lockPath)
		if pid <= 0 || !processAlive(pid) || !isAgent(pid) {
			return 0, false
		}
		return pid, true
	}
}

// runWatchdog is the decision loop with the clock, the sleep and the liveness
// probe injected, so every rule is testable without a service manager.
func runWatchdog(ctx context.Context, h HelperOptions, probe AgentProbe, now func() time.Time, sleep func(time.Duration), log driver.Logger) error {
	if h.ExePath == "" || h.StateDir == "" {
		return errors.New("selfupdate: the watchdog needs -exe and -state")
	}
	aliveDefault, deadlineDefault := DefaultWatchdogWindows(runtime.GOARCH)
	if h.Attempts <= 0 {
		h.Attempts = DefaultAttempts
	}
	if h.AliveWindow <= 0 {
		h.AliveWindow = aliveDefault
	}
	if h.Deadline <= 0 {
		h.Deadline = deadlineDefault
	}
	// The deadline must leave room for the no-live-agent window: a deadline
	// that expires first would turn every slow start into a "stalled, kept"
	// update and the machine would never be rolled back to a working binary.
	if h.Deadline <= h.AliveWindow {
		h.Deadline = h.AliveWindow + DefaultPollInterval*15
	}
	if h.PollInterval <= 0 {
		h.PollInterval = DefaultPollInterval
	}
	if log == nil {
		log = nopLog{}
	}
	if now == nil {
		now = time.Now
	}
	if sleep == nil {
		sleep = time.Sleep
	}
	up, err := New(Options{ExePath: h.ExePath, StateDir: h.StateDir, Log: log})
	if err != nil {
		return err
	}

	// The agent that committed the update still holds the lock and is still
	// alive; wait for it before counting anything.
	if h.ParentPID > 0 {
		waitForExit(ctx, h.ParentPID, parentWaitTimeout)
	}
	// Nothing pending any more: a previous watchdog (or a manual rollback)
	// already finished this update.
	pending, ok := up.Pending()
	if !ok {
		return up.CleanupWatchdog()
	}

	// Without a lock path there is no liveness signal. Rolling back on a
	// missing probe would undo a perfectly good update, so the watchdog only
	// reports the update as stalled in that case.
	haveProbe := probe != nil && h.LockPath != ""
	if !haveProbe {
		log.Warnf("selfupdate: the watchdog has no single-instance lock path; it cannot tell whether an agent is alive and will not roll back on its own")
	}

	deadline := now().Add(h.Deadline)
	var (
		lastPID   int
		restarts  int
		deadSince time.Time
	)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		// The new process reached the panel and confirmed: the update is good.
		if p, ok := up.Pending(); !ok {
			log.Infof("selfupdate: the new version confirmed the update; the watchdog stops")
			return up.CleanupWatchdog()
		} else {
			pending = p
		}
		if haveProbe {
			pid, alive := probe()
			switch {
			case alive:
				deadSince = time.Time{}
				if pid != lastPID {
					if lastPID != 0 {
						restarts++
					}
					lastPID = pid
					log.Infof("selfupdate: agent pid %d observed (%d restart(s))", pid, restarts)
				}
			case deadSince.IsZero():
				deadSince = now()
			}
			if restarts >= h.Attempts {
				reason := fmt.Sprintf("the new version restarted %d time(s) without confirming the update", restarts)
				return rollbackAndRestart(up, h, reason, log)
			}
			if !deadSince.IsZero() && now().Sub(deadSince) >= h.AliveWindow {
				// Probe once more before acting. A start that is merely slow
				// is exactly what this window exists for, and the previous
				// probe may have run microseconds before the new process took
				// the lock or wrote its ready marker. Rolling back under a
				// live process is what leaves "the running executable is not
				// the installed file" behind (D-M7).
				if pid, alive := probe(); alive {
					deadSince = time.Time{}
					lastPID = pid
					log.Infof("selfupdate: agent pid %d appeared while the watchdog was deciding; keeping version %s",
						pid, pending.Version)
				} else {
					reason := fmt.Sprintf("no agent was alive for %s after the update", h.AliveWindow)
					return rollbackAndRestart(up, h, reason, log)
				}
			}
		}
		if !now().Before(deadline) {
			// An agent that is alive and stable but never confirmed is a panel
			// problem, not a broken binary (protocol ruling 11): keep the
			// update, keep the backup, and let the new process report
			// self_update.stalled.
			log.Warnf("selfupdate: version %s was not confirmed within %s; not rolling back (a panel outage is not a broken binary)",
				pending.Version, h.Deadline)
			return nil
		}
		sleep(h.PollInterval)
	}
}

// rollbackAndRestart restores the previous binary, records why, and asks the
// service manager to bring it back.
//
// It never restores the file under a process that is still running: the new
// version is stopped by pid first, because renaming the executable away under a
// live process is exactly what leaves "the running executable is not the
// installed file" behind (D-M7). Before restarting the agent it stops the
// W1nCray-xray service, so a rollback to the in-process-Xray 0.5.x agent never
// finds the 0.6 service holding the node ports (R1-16).
//
// The pid is verified to be an agent before any signal is sent: the watchdog
// runs as root and a stale lock or ready marker can name a pid the kernel has
// since reused for an unrelated process (F3b).
func rollbackAndRestart(up *Updater, h HelperOptions, reason string, log driver.Logger) error {
	isAgent := up.agentIdentity(log)
	newPID := liveAgentPID(up, h, log)
	if newPID > 0 {
		log.Warnf("selfupdate: %s; stopping agent pid %d before the rollback", reason, newPID)
		stopAgentProcess(newPID, isAgent, log)
	}
	stopXrayService(log)
	if err := up.Rollback(reason); err != nil {
		return fmt.Errorf("selfupdate: %s; the rollback failed too: %w", reason, err)
	}
	// The service manager may have brought the new binary back while the
	// rollback ran (its respawn does not know about the swap). Stop it once
	// more so the next start picks the restored file. stopAgentProcess verifies
	// the pid again, so a process that already exited is not signalled.
	if newPID > 0 && processAlive(newPID) {
		log.Warnf("selfupdate: agent pid %d came back during the rollback; stopping it again", newPID)
		stopAgentProcess(newPID, isAgent, log)
	}
	log.Warnf("selfupdate: %s; restored %s", reason, up.ExePath())
	restartService(h, log)
	return nil
}

// liveAgentPID is the pid of the process running the new version right now: the
// ready marker when its version matches the pending update, else the
// single-instance lock. It is the process a rollback has to stop first.
//
// It only returns a pid that is both alive and verified to be running an agent
// executable (F3b). A pid the kernel has reused for an unrelated process is
// reported as 0 ("no agent"), so the rollback never signals it.
func liveAgentPID(up *Updater, h HelperOptions, log driver.Logger) int {
	isAgent := up.agentIdentity(log)
	if m, ok := up.ReadyMarker(); ok {
		if p, pending := up.Pending(); pending && m.Version == p.Version && processAlive(m.PID) && isAgent(m.PID) {
			return m.PID
		}
	}
	if pid := lockPID(h.LockPath); pid > 0 && processAlive(pid) && isAgent(pid) {
		return pid
	}
	return 0
}

// lockPID reads the pid the single-instance lock records. cmd/lock_flock.go
// writes "<pid>\n" and the kernel releases the flock when the process exits, so
// a dead pid here means "no agent". A missing or malformed file means the same.
func lockPID(path string) int {
	if path == "" {
		return 0
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0
	}
	return pid
}

// waitForExit blocks until pid is gone or timeout elapses.
func waitForExit(ctx context.Context, pid int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return
		}
		if !processAlive(pid) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}
