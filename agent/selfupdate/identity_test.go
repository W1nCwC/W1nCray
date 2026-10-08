package selfupdate

import (
	"path/filepath"
	"reflect"
	"testing"
)

// TestAgentExecutablePaths covers the known-agent set F3b compares a live pid
// against: the install path, the backup next to it, the watchdog copy
// directory and the staged directory of the pending version.
func TestAgentExecutablePaths(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "W1nCray")
	state := filepath.Join(dir, "state")
	up, err := New(Options{ExePath: exe, StateDir: state, Ready: func(string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	files, dirs := up.agentExecutablePaths()
	if want := []string{exe, exe + ".old"}; !reflect.DeepEqual(files, want) {
		t.Errorf("files = %v, want %v", files, want)
	}
	if want := []string{filepath.Join(state, "update", "watchdog")}; !reflect.DeepEqual(dirs, want) {
		t.Errorf("dirs = %v, want %v", dirs, want)
	}

	// A pending update adds the staged directory of that version.
	if err := writeJSONAtomic(up.pendingPath(), &Pending{Version: "0.6.0", ExePath: exe, OldPath: exe + ".old"}, 0o600); err != nil {
		t.Fatal(err)
	}
	_, dirs = up.agentExecutablePaths()
	want := []string{
		filepath.Join(state, "update", "watchdog"),
		filepath.Join(state, "update", "staged", "0.6.0"),
	}
	if !reflect.DeepEqual(dirs, want) {
		t.Errorf("dirs with a pending update = %v, want %v", dirs, want)
	}
}

// TestExecutableIdentityMatching pins the comparison itself: the exact paths
// match, a binary inside the watchdog/staged directories matches, and anything
// else (a name that only looks like the install path, or an unrelated program)
// does not.
func TestExecutableIdentityMatching(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "W1nCray")
	old := exe + ".old"
	if !sameExecutable(exe, exe) || !sameExecutable(old, old) {
		t.Error("a path must match itself")
	}
	if sameExecutable(old, exe) {
		t.Error("the backup must not match the install path")
	}
	if sameExecutable(exe+"-other", exe) {
		t.Error("a name that only starts with the install path must not match")
	}
	if sameExecutable("/usr/sbin/sshd", exe) {
		t.Error("an unrelated program must not match")
	}

	watch := filepath.Join(dir, "state", "update", "watchdog")
	if !executableInDir(filepath.Join(watch, "W1nCray-0.5.0"), watch) {
		t.Error("the watchdog copy must match its directory")
	}
	if executableInDir(filepath.Join(dir, "state", "update", "watchdog-other", "W1nCray"), watch) {
		t.Error("a sibling directory must not match")
	}
	if executableInDir("/usr/sbin/sshd", watch) {
		t.Error("an unrelated program must not match a directory")
	}
}

// TestUnknownProcessIsNotAnAgent keeps the conservative rule honest: a pid the
// platform cannot inspect, or one that does not exist, is never an agent.
func TestUnknownProcessIsNotAnAgent(t *testing.T) {
	up, _, _ := watchdogFixture(t)
	if up.isAgentPID(0, nopLog{}) {
		t.Error("pid 0 must never be an agent")
	}
	if up.isAgentPID(1<<30, nopLog{}) {
		t.Error("a pid that cannot be inspected must not be an agent")
	}
}
