//go:build linux

package selfupdate

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// stubNoServiceManager keeps the rollback's service commands off the test host
// and records nothing: these tests are about which pid gets signalled.
func stubNoServiceManager(t *testing.T) {
	t.Helper()
	oldRun, oldExists := runServiceCommand, serviceExists
	t.Cleanup(func() { runServiceCommand, serviceExists = oldRun, oldExists })
	serviceExists = func(string) bool { return false }
	runServiceCommand = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
}

// TestUnrelatedProcessInTheLockIsNotAnAgentAndIsNotStopped is the F3b
// regression test for the pid-reuse hole: the single-instance lock and the
// ready marker can both name a pid the kernel has since handed to an unrelated
// program (sshd, dropbear, any service). The watchdog runs as root and used to
// SIGTERM/SIGKILL that pid. Identity is now verified against the executables an
// agent may run from, so the unrelated process must be left alone and the
// watchdog must fall back to "no agent".
func TestUnrelatedProcessInTheLockIsNotAnAgentAndIsNotStopped(t *testing.T) {
	up, exe, state := watchdogFixture(t)
	lock := filepath.Join(state, "config.yml.lock")
	up.lockPath = lock
	unrelated := startUnrelatedProcess(t)
	pid := unrelated.Process.Pid
	if !processAlive(pid) {
		t.Fatal("the unrelated process is not alive")
	}
	writeFile(t, lock, strconv.Itoa(pid)+"\n")
	marker := &ReadyMarker{Version: "0.6.0", PID: pid, At: time.Now()}
	if err := writeJSONAtomic(up.readyPath(), marker, 0o600); err != nil {
		t.Fatal(err)
	}

	// (a) The ready marker names a live pid that is not the agent.
	if got, alive := up.agentProbe()(); alive {
		t.Errorf("the ready marker's unrelated pid %d was reported as the agent (pid %d)", pid, got)
	}
	// (b) The single-instance lock names it, with no marker at all.
	if err := os.Remove(up.readyPath()); err != nil {
		t.Fatal(err)
	}
	if got, alive := up.agentProbe()(); alive {
		t.Errorf("the lock's unrelated pid %d was reported as the agent (pid %d)", pid, got)
	}
	// (c) A rollback must not signal it, and must treat the update as having no
	// live agent at all.
	if err := writeJSONAtomic(up.readyPath(), marker, 0o600); err != nil {
		t.Fatal(err)
	}
	stubNoServiceManager(t)
	h := watchdogBudget(exe, state)
	if err := rollbackAndRestart(up, h, "test rollback", nopLog{}); err != nil {
		t.Fatalf("rollbackAndRestart: %v", err)
	}
	if !processAlive(pid) {
		t.Errorf("the watchdog killed the unrelated process (pid %d)", pid)
	}
	if got := readFile(t, exe); got != "OLD-BINARY" {
		t.Errorf("exe = %q, want the previous binary restored (an unrelated pid is not an agent)", got)
	}
	if _, ok := up.TakeRollback(); !ok {
		t.Error("the rollback must be recorded")
	}
}

// TestWatchdogTreatsAnUnrelatedPidAsNoAgent pins the watchdog's decision: a
// lock/ready marker naming a live unrelated process is not an agent, so the
// update is rolled back by the "no agent was alive" rule instead of being kept
// alive by a pid the kernel reused.
func TestWatchdogTreatsAnUnrelatedPidAsNoAgent(t *testing.T) {
	up, exe, state := watchdogFixture(t)
	lock := filepath.Join(state, "config.yml.lock")
	up.lockPath = lock
	unrelated := startUnrelatedProcess(t)
	pid := unrelated.Process.Pid
	writeFile(t, lock, strconv.Itoa(pid)+"\n")
	if err := writeJSONAtomic(up.readyPath(), &ReadyMarker{Version: "0.6.0", PID: pid, At: time.Now()}, 0o600); err != nil {
		t.Fatal(err)
	}
	stubNoServiceManager(t)

	clock := &fakeClock{t: time.Unix(1000, 0)}
	h := watchdogBudget(exe, state)
	if err := runWatchdog(context.Background(), h, up.agentProbe(), clock.now, clock.sleep, nopLog{}); err != nil {
		t.Fatalf("runWatchdog: %v", err)
	}
	if got := readFile(t, exe); got != "OLD-BINARY" {
		t.Errorf("exe = %q, want the previous binary: a pid the kernel reused is not an agent", got)
	}
	rb, ok := up.TakeRollback()
	if !ok || !strings.Contains(rb.Reason, "alive") {
		t.Fatalf("rollback marker = %+v (ok=%v), want the no-agent-alive rule", rb, ok)
	}
	if !processAlive(pid) {
		t.Errorf("the watchdog killed the unrelated process (pid %d)", pid)
	}
}

// TestRealAgentProcessIsRecognizedAndStopped is the positive half of F3b: a
// process really running from the install path (ExePath) is still recognized
// as the agent and is stopped before the rollback restores the previous
// binary, so verifying identity does not switch the D-M7 fix off.
func TestRealAgentProcessIsRecognizedAndStopped(t *testing.T) {
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
	lock := filepath.Join(dir, "config.yml.lock")
	up, err := New(Options{
		ExePath: exe, StateDir: state, LockPath: lock, Log: nopLog{},
		Ready: func(string) error { return nil }, AgentVersion: "0.5.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := up.Commit(Staged{Version: "0.6.0", Path: staged, SHA256: sha(mustRead(t, staged))}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	oldSum := sha(mustRead(t, up.OldPath()))

	agent := startFakeAgent(t, exe)
	pid := agent.Process.Pid
	if err := writeJSONAtomic(up.readyPath(), &ReadyMarker{Version: "0.6.0", PID: pid, At: time.Now()}, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, alive := up.agentProbe()(); !alive || got != pid {
		t.Fatalf("the process running from %s was not recognized as the agent: pid=%d alive=%v", exe, got, alive)
	}
	stubNoServiceManager(t)
	h := watchdogBudget(exe, state)
	if err := rollbackAndRestart(up, h, "test rollback", nopLog{}); err != nil {
		t.Fatalf("rollbackAndRestart: %v", err)
	}
	if processAlive(pid) {
		t.Error("the agent process was not stopped before the rollback")
	}
	if got := sha(mustRead(t, exe)); got != oldSum {
		t.Error("the previous binary was not restored")
	}
}

// TestReadyMarkerIsTheAuthoritativeLivenessSignal pins the D-M7 liveness
// contract: the ready marker (version + pid) decides, and the single-instance
// lock is only the fallback. A marker for another version is stale and must
// never be mistaken for the pending one.
//
// F3b moved it to Linux: the live pid has to be a process whose executable the
// kernel really reports as an agent path, which needs /proc (the test already
// skipped on Windows, where the watchdog never runs).
func TestReadyMarkerIsTheAuthoritativeLivenessSignal(t *testing.T) {
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
	lock := filepath.Join(dir, "config.yml.lock")
	up, err := New(Options{
		ExePath: exe, StateDir: state, LockPath: lock, Log: nopLog{},
		Ready: func(string) error { return nil }, AgentVersion: "0.5.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := up.Commit(Staged{Version: "0.6.0", Path: staged, SHA256: sha(mustRead(t, staged))}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	probe := up.agentProbe()
	dead := 1 << 30

	// The real agent process: /proc/<pid>/exe reports exe.
	agent := startFakeAgent(t, exe)
	agentPID := agent.Process.Pid

	writeFile(t, lock, strconv.Itoa(dead)+"\n")
	if _, alive := probe(); alive {
		t.Fatal("a lock holding a dead pid must not be reported alive")
	}

	// The lock names a live agent process: the lock alone is still a liveness
	// signal while the new process has not written its marker yet.
	writeFile(t, lock, strconv.Itoa(agentPID)+"\n")
	if _, alive := probe(); !alive {
		t.Fatal("a live agent pid in the lock must be reported alive")
	}

	// A marker for another version is stale: it must not be mistaken for the
	// pending one, and the lock fallback must keep working.
	if err := writeJSONAtomic(up.readyPath(), &ReadyMarker{Version: "0.5.0", PID: agentPID}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, alive := probe(); !alive {
		t.Fatal("the lock fallback must still work with a stale ready marker")
	}

	// The marker for the pending version is authoritative, even with no lock.
	if err := writeJSONAtomic(up.readyPath(), &ReadyMarker{Version: "0.6.0", PID: agentPID}, 0o600); err != nil {
		t.Fatal(err)
	}
	writeFile(t, lock, strconv.Itoa(dead)+"\n")
	pid, alive := probe()
	if !alive || pid != agentPID {
		t.Fatalf("the ready marker must be authoritative: pid=%d alive=%v", pid, alive)
	}

	// A marker whose process is gone proves nothing.
	if err := writeJSONAtomic(up.readyPath(), &ReadyMarker{Version: "0.6.0", PID: dead}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, alive := probe(); alive {
		t.Fatal("a marker whose pid is dead must not be reported alive")
	}
}
