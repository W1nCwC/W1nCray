package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/W1nCwC/W1nCray/agent/driver"
)

// HelperOptions is what the detached respawn helper needs. Respawn passes it on
// the helper's command line; ParseHelperArgs reads it back.
type HelperOptions struct {
	// ParentPID is the agent that committed the update and is about to exit.
	// The helper waits for it so the single-instance lock is free.
	ParentPID int
	// ExePath is the executable to run (the new one, then the restored old one).
	ExePath string
	// StateDir holds update/pending.json, which the rollback needs.
	StateDir string
	// Argv is the agent's own argument list, without the program name.
	Argv []string

	Attempts    int
	RetryDelay  time.Duration
	AliveWindow time.Duration
}

// startFunc runs the agent once and reports whether it stayed alive for the
// window. It is injected so the retry/rollback watchdog is testable without
// spawning anything.
type startFunc func(exe string, argv []string, window time.Duration) error

// Respawn starts the detached helper. It is a variable so tests can observe
// the spawn; production code never changes it. respawn is platform specific
// and returns ErrNotSupported where a process cannot detach itself.
var Respawn = respawn

// RespawnHelper starts the respawn helper for this updater's executable. It is
// called after Commit, just before the process exits.
func (u *Updater) RespawnHelper() error {
	return Respawn(u.exe, os.Args[1:], HelperOptions{
		ParentPID:   os.Getpid(),
		StateDir:    u.stateDir,
		Attempts:    u.attempts,
		RetryDelay:  u.retryDelay,
		AliveWindow: u.aliveWindow,
	}, u.log)
}

// HelperCommand is the hidden subcommand the helper runs under.
const HelperCommand = "__respawn"

// ParseHelperArgs parses the helper's argv (everything after HelperCommand):
//
//	-parent PID -state DIR -exe EXE [-attempts N] [-retry 5s] [-window 10s] -- <agent argv...>
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
		case "attempts":
			h.Attempts, err = strconv.Atoi(val)
		case "retry":
			h.RetryDelay, err = time.ParseDuration(val)
		case "window":
			h.AliveWindow, err = time.ParseDuration(val)
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

// HelperArgv builds the helper's argument list (without the subcommand) for
// Respawn implementations and tests.
func HelperArgv(exe string, argv []string, h HelperOptions) []string {
	args := []string{
		"-parent", strconv.Itoa(h.ParentPID),
		"-state", h.StateDir,
		"-exe", exe,
		"-attempts", strconv.Itoa(h.Attempts),
		"-retry", h.RetryDelay.String(),
		"-window", h.AliveWindow.String(),
		"--",
	}
	return append(args, argv...)
}

// RunHelper is the helper's main loop: wait for the old agent to exit, run the
// new binary up to Attempts times, and when it never stays alive restore
// exe.old and run that instead (writing rollback.json). It is what makes a
// version that cannot start recoverable.
func RunHelper(ctx context.Context, h HelperOptions, log driver.Logger) error {
	return runHelper(ctx, h, startWindow, time.Sleep, log)
}

func runHelper(ctx context.Context, h HelperOptions, start startFunc, sleep func(time.Duration), log driver.Logger) error {
	if h.ExePath == "" || h.StateDir == "" {
		return errors.New("selfupdate: the respawn helper needs -exe and -state")
	}
	if h.Attempts <= 0 {
		h.Attempts = DefaultAttempts
	}
	if h.RetryDelay <= 0 {
		h.RetryDelay = DefaultRetryDelay
	}
	if h.AliveWindow <= 0 {
		h.AliveWindow = DefaultAliveWindow
	}
	if log == nil {
		log = nopLog{}
	}
	up, err := New(Options{ExePath: h.ExePath, StateDir: h.StateDir, Log: log})
	if err != nil {
		return err
	}
	// The old process holds the single-instance lock; it is released by the
	// kernel when it exits, so wait for it before starting anything.
	if h.ParentPID > 0 {
		waitForExit(ctx, h.ParentPID, parentWaitTimeout)
	}
	var last error
	for attempt := 1; attempt <= h.Attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := start(h.ExePath, h.Argv, h.AliveWindow); err == nil {
			log.Infof("selfupdate: the new version stayed alive for %s", h.AliveWindow)
			return nil
		} else {
			last = err
		}
		log.Warnf("selfupdate: start attempt %d/%d failed: %v", attempt, h.Attempts, err)
		if attempt < h.Attempts {
			sleep(h.RetryDelay)
		}
	}
	reason := fmt.Sprintf("the new version did not stay alive after %d attempts: %v", h.Attempts, last)
	if err := up.Rollback(reason); err != nil {
		return fmt.Errorf("selfupdate: %s; the rollback failed too: %w", reason, err)
	}
	// The restored binary must come back up. If it does not either, the
	// operator has to intervene (documented in docs/AGENT.md).
	return start(h.ExePath, h.Argv, h.AliveWindow)
}

// startWindow runs exe once and reports nil only when it is still alive after
// window. Any exit inside the window (clean or not) counts as a failure: an
// agent that exits is not serving.
func startWindow(exe string, argv []string, window time.Duration) error {
	//nolint:noshell -- exe is this agent's own executable (os.Executable or the
	// binary a committed update put in place) and the arguments are an argv
	// array, never a shell or a command string.
	cmd := exec.Command(exe, argv...)
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(window)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("exited within %s: %w", window, err)
		}
		return fmt.Errorf("exited cleanly within %s", window)
	case <-timer.C:
		return nil
	}
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
