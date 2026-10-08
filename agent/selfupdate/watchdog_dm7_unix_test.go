//go:build unix

package selfupdate

import (
	"context"
	"os"
	"os/exec"
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
func TestRollbackStopsTheNewProcessBeforeRestoringTheBinary(t *testing.T) {
	up, exe, state := watchdogFixture(t)

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-test.run=TestSelfUpdateSleeperProcess")
	cmd.Env = append(os.Environ(), "W1NCRAY_SELFUPDATE_SLEEP=1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the stand-in new agent: %v", err)
	}
	reaped := make(chan struct{})
	go func() { _ = cmd.Wait(); close(reaped) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-reaped:
		case <-time.After(10 * time.Second):
		}
	})
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
	if got := readFile(t, exe); got != "OLD-BINARY" {
		t.Errorf("exe = %q, want the previous binary restored", got)
	}
}
