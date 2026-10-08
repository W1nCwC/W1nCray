//go:build unix

package selfupdate

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSelfUpdateSleeperProcess is not a test: it is the stand-in for a healthy
// new agent process that is still running when the watchdog decides to roll
// back. It is exactly the D-M7 state the watchdog must never create: the
// install path renamed out from under a live process.
func TestSelfUpdateSleeperProcess(t *testing.T) {
	if os.Getenv("W1NCRAY_SELFUPDATE_SLEEP") == "" {
		return
	}
	time.Sleep(2 * time.Minute)
}

// TestRollbackStopsTheNewProcessBeforeRestoringTheBinary is the D-M7 rollback
// regression test: the new version is alive (its ready marker names a real
// process) when the watchdog rolls back, so the watchdog must stop that process
// before it restores the previous binary. It failed before the fix, leaving the
// process running from an unlinked image.
//
// F3b: the stand-in agent really runs from the install path (ExePath), so the
// identity check recognizes it; the pid a rollback signals is never assumed to
// be the agent any more.
func TestRollbackStopsTheNewProcessBeforeRestoringTheBinary(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "W1nCray")
	staged := filepath.Join(dir, "staged")
	if err := copyFile(self, exe, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(self, staged, 0o755); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	up, err := New(Options{
		ExePath: exe, StateDir: state, Log: nopLog{}, Ready: func(string) error { return nil },
		AgentVersion: "0.5.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := up.Commit(Staged{Version: "0.6.0", Path: staged, SHA256: sha(mustRead(t, staged))}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	oldSum := sha(mustRead(t, up.OldPath()))

	cmd := startFakeAgent(t, exe)
	pid := cmd.Process.Pid
	if !processAlive(pid) {
		t.Fatal("the stand-in process is not alive")
	}

	// The authoritative marker names that process with the pending version.
	if err := writeJSONAtomic(up.readyPath(), &ReadyMarker{Version: "0.6.0", PID: pid, At: time.Now()}, 0o600); err != nil {
		t.Fatal(err)
	}

	oldRun, oldExists := runServiceCommand, serviceExists
	t.Cleanup(func() { runServiceCommand, serviceExists = oldRun, oldExists })
	serviceExists = func(string) bool { return false }
	runServiceCommand = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }

	h := watchdogBudget(exe, state)
	if err := rollbackAndRestart(up, h, "test rollback", nopLog{}); err != nil {
		t.Fatalf("rollbackAndRestart: %v", err)
	}
	if processAlive(pid) {
		t.Error("the new process is still running after the rollback: the running executable is no longer the installed file")
	}
	if got := sha(mustRead(t, exe)); got != oldSum {
		t.Errorf("exe was not restored to the previous binary")
	}
}
