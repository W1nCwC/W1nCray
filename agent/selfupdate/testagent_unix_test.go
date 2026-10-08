//go:build unix

package selfupdate

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// startFakeAgent starts a process that runs from exe, a copy of this test
// binary: /proc/<pid>/exe then reports exe, exactly like a real agent started
// by the service manager from the install path. The child is the
// TestSelfUpdateSleeperProcess stand-in, which stays alive until it is killed.
func startFakeAgent(t *testing.T, exe string) *exec.Cmd {
	t.Helper()
	//nolint:noshell -- exe is a copy of this test binary, run with an argv
	// array, never a shell.
	cmd := exec.Command(exe, "-test.run=TestSelfUpdateSleeperProcess")
	cmd.Env = append(os.Environ(), "W1NCRAY_SELFUPDATE_SLEEP=1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the stand-in agent %s: %v", exe, err)
	}
	reapInCleanup(t, cmd)
	return cmd
}

// startUnrelatedProcess starts a process that is definitely not the agent: a
// plain sleep(1). It is the "the kernel handed this pid to something else"
// case a stale single-instance lock or ready marker can point at.
func startUnrelatedProcess(t *testing.T) *exec.Cmd {
	t.Helper()
	path, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("no sleep(1) on this host: %v", err)
	}
	//nolint:noshell -- an argv array, never a shell.
	cmd := exec.Command(path, "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the unrelated process: %v", err)
	}
	reapInCleanup(t, cmd)
	return cmd
}

// reapInCleanup reaps cmd in the background and kills it when the test ends.
// The tests assert that the process is still alive after the code under test
// ran, so the cleanup is the test's own and never the watchdog's.
func reapInCleanup(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	reaped := make(chan struct{})
	go func() { _ = cmd.Wait(); close(reaped) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-reaped:
		case <-time.After(10 * time.Second):
		}
	})
}
